#!/usr/bin/env python3
"""Mock RFC 9447 Token Authority for the akamu tkauth-01 demo.

Implements two endpoints:
  GET  /jwks                            — JWKS with the demo ML-DSA-65 signing key
  POST /at/account/{id}/token           — SPNEGO-authenticated token issuance

The SPNEGO context accepts any principal from the demo KDC (set KRB5_CONFIG and
KRB5_KTNAME before launching).  After successful auth it issues a compact JWT
signed with ML-DSA-65 via the synta Python library.

The JWT carries a RFC 8226 JWTClaimConstraints DER blob (atc.tkvalue) with
permittedValues constraining the "dns" claim to the configured --domain and the
"sub" claim to the authenticated Kerberos principal.  Both are also present as
top-level JWT claims so akamu's check_jwt_claim_constraints passes.

Usage:
    KRB5_CONFIG=/tmp/kdc/krb5.conf \\
    KRB5_KTNAME=/tmp/kdc/idp.keytab \\
    python3 mock_idp.py --port 9447 --domain demo.test
"""

import argparse
import base64
import http.server
import json
import os
import re
import sys
import time
import uuid
from typing import List, Optional, Tuple

import gssapi
import synta

# ── Helpers ───────────────────────────────────────────────────────────────────

def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


# ── RFC 8226 JWTClaimConstraints DER encoder ──────────────────────────────────

def _encode_tlv(tag: int, body: bytes) -> bytes:
    """Minimal DER TLV encoder (length < 65536 bytes)."""
    if len(body) < 0x80:
        return bytes([tag, len(body)]) + body
    if len(body) < 0x100:
        return bytes([tag, 0x81, len(body)]) + body
    return bytes([tag, 0x82, len(body) >> 8, len(body) & 0xff]) + body


def encode_jcc_der(
    must_include: List[str],
    permitted_values: List[Tuple[str, List[str]]],
    must_exclude: Optional[List[str]] = None,
) -> bytes:
    """Encode an EnhancedJWTClaimConstraints DER blob per RFC 9118.

      EnhancedJWTClaimConstraints ::= SEQUENCE {
          mustInclude     [0] JWTClaimNames         OPTIONAL,
          permittedValues [1] JWTClaimValuesList    OPTIONAL,
          mustExclude     [2] JWTClaimNames         OPTIONAL
      }
      JWTClaimNames       ::= SEQUENCE OF IA5String
      JWTClaimValuesList  ::= SEQUENCE OF JWTClaimPermittedValues
      JWTClaimPermittedValues ::= SEQUENCE {
          claim  IA5String,
          values SEQUENCE OF UTF8String
      }

    `must_include` — claim names that MUST be present in the JWT.
    `permitted_values` — (claim, [value, ...]) pairs restricting allowed values.
    `must_exclude` — claim names that MUST NOT be present in the JWT.
    """
    body = b""

    if must_include:
        names_der  = b"".join(_encode_tlv(0x16, n.encode()) for n in must_include)
        names_seq  = _encode_tlv(0x30, names_der)             # SEQUENCE OF IA5String
        body      += _encode_tlv(0xa0, names_seq)             # [0] EXPLICIT

    if permitted_values:
        jcpv_ders = b""
        for claim, values in permitted_values:
            claim_der  = _encode_tlv(0x16, claim.encode())    # IA5String
            vals_inner = b"".join(_encode_tlv(0x0c, v.encode()) for v in values)
            vals_seq   = _encode_tlv(0x30, vals_inner)
            jcpv_ders += _encode_tlv(0x30, claim_der + vals_seq)
        perm_list  = _encode_tlv(0x30, jcpv_ders)            # inner SEQUENCE OF
        body      += _encode_tlv(0xa1, perm_list)             # [1] EXPLICIT

    if must_exclude:
        names_der  = b"".join(_encode_tlv(0x16, n.encode()) for n in must_exclude)
        names_seq  = _encode_tlv(0x30, names_der)             # SEQUENCE OF IA5String
        body      += _encode_tlv(0xa2, names_seq)             # [2] EXPLICIT

    return _encode_tlv(0x30, body)                            # outer SEQUENCE


# ── ML-DSA-65 JWT builder ─────────────────────────────────────────────────────

class MlDsa65Signer:
    """Generates a fresh ML-DSA-65 key pair and signs compact JWTs."""

    ML_DSA_65_PUB_LEN = 1952    # FIPS 204
    SPKI_HEADER_LEN   = 22      # fixed DER header before raw key bytes

    def __init__(self):
        self.kid = str(uuid.uuid4())
        self._private_key = synta.PrivateKey.generate_ml_dsa("ML-DSA-65")
        spki_der = self._private_key.public_key.to_der()
        self._raw_pub = spki_der[self.SPKI_HEADER_LEN:]
        if len(self._raw_pub) != self.ML_DSA_65_PUB_LEN:
            raise RuntimeError(
                f"ML-DSA-65 public key length mismatch: {len(self._raw_pub)}"
            )

    def jwks(self) -> dict:
        return {
            "keys": [{
                "kty": "AKP",
                "alg": "ML-DSA-65",
                "kid": self.kid,
                "pub": b64url_encode(self._raw_pub),
            }]
        }

    def sign(self, claims: dict) -> str:
        header = json.dumps({"alg": "ML-DSA-65", "kid": self.kid},
                            separators=(",", ":"), sort_keys=True)
        payload = json.dumps(claims, separators=(",", ":"), sort_keys=True)
        signing_input = b64url_encode(header.encode()) + "." + b64url_encode(payload.encode())
        raw_sig = self._private_key.sign(signing_input.encode())
        return signing_input + "." + b64url_encode(raw_sig)


# ── SPNEGO helper ─────────────────────────────────────────────────────────────

def load_server_creds(keytab_path: str) -> gssapi.Credentials:
    """Acquire acceptor credentials from the given keytab."""
    return gssapi.Credentials(
        name=None,
        usage="accept",
        store={"keytab": keytab_path},
    )


def accept_spnego(token_b64: str, server_creds: gssapi.Credentials):
    """Validate one SPNEGO token.  Returns (principal_str, out_token_b64_or_None).

    Raises ValueError on auth failure.
    out_token is non-empty when the server wants to send a mutual-auth token
    back in the WWW-Authenticate header.
    """
    raw = base64.b64decode(token_b64)
    ctx = gssapi.SecurityContext(creds=server_creds, usage="accept")
    try:
        out_raw = ctx.step(raw)
    except gssapi.exceptions.GSSError as e:
        raise ValueError(f"SPNEGO validation failed: {e}") from e
    if not ctx.complete:
        raise ValueError("SPNEGO required additional round-trips (unexpected for Kerberos)")
    principal = str(ctx.initiator_name)
    out_b64 = base64.b64encode(out_raw).decode() if out_raw else None
    return principal, out_b64


# ── HTTP request handler ──────────────────────────────────────────────────────

class IdpHandler(http.server.BaseHTTPRequestHandler):
    signer: MlDsa65Signer          # set on the class before serving
    server_creds: gssapi.Credentials
    domain: str

    def log_message(self, fmt, *args):
        print(f"[mock_idp] {self.address_string()} {fmt % args}", file=sys.stderr)

    # ── GET /jwks ─────────────────────────────────────────────────────────────

    def do_GET(self):
        if self.path != "/jwks":
            self._respond(404, {"error": "not found"})
            return
        body = json.dumps(self.signer.jwks()).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    # ── POST /at/account/{id}/token ───────────────────────────────────────────

    def do_POST(self):
        if not re.fullmatch(r"/at/account/\w+/token", self.path):
            self._respond(404, {"error": "not found"})
            return

        auth_header = self.headers.get("Authorization", "")
        if not auth_header.lower().startswith("negotiate "):
            self._challenge_spnego()
            return

        token_b64 = auth_header.split(" ", 1)[1].strip()
        try:
            principal, out_b64 = accept_spnego(token_b64, self.server_creds)
        except ValueError as e:
            self.log_message("SPNEGO error: %s", e)
            self._respond(403, {"error": "authentication failed"})
            return

        length = int(self.headers.get("Content-Length", 0))
        body_bytes = self.rfile.read(length)
        try:
            req = json.loads(body_bytes)
            atc_req = req["atc"]
            fingerprint = atc_req["fingerprint"]
        except (json.JSONDecodeError, KeyError) as e:
            self._respond(400, {"error": f"malformed request: {e}"})
            return

        # Generate a JWTClaimConstraints DER blob (RFC 8226):
        #   mustInclude     — "sub" must be present in the JWT (principal mandate)
        #   permittedValues — dns constrained to the configured domain;
        #                     sub constrained to the authenticated principal
        #                     (single permitted value → SAN injection at finalize time)
        jcc_der   = encode_jcc_der(
            must_include     = ["sub"],
            permitted_values = [
                ("dns", [self.domain]),
                ("sub", [principal]),
            ],
        )
        tkvalue_b64 = b64url_encode(jcc_der)

        now = int(time.time())
        claims = {
            "iss": "mock-idp@" + os.environ.get("KRB5_REALM", "DEMO.TEST"),
            # Top-level claims mirror permittedValues so akamu's
            # check_jwt_claim_constraints can verify them.
            "sub": principal,
            "dns": self.domain,
            "iat": now,
            "exp": now + 300,
            "jti": str(uuid.uuid4()),
            "atc": {
                "tktype":      "EnhancedJWTClaimConstraints",
                "tkvalue":     tkvalue_b64,
                "fingerprint": fingerprint,
                "ca":          False,
            },
        }
        jwt_str = self.signer.sign(claims)
        resp_body = json.dumps({"token": jwt_str}).encode()

        extra_headers = {}
        if out_b64:
            extra_headers["WWW-Authenticate"] = f"Negotiate {out_b64}"

        self._respond(200, None, body=resp_body,
                      content_type="application/json", extra=extra_headers)
        self.log_message("issued ML-DSA-65 JWT for %s (dns=%s)", principal, self.domain)

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _challenge_spnego(self):
        self.send_response(401)
        self.send_header("WWW-Authenticate", "Negotiate")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _respond(self, status, obj, body=None, content_type="application/json", extra=None):
        if body is None:
            body = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)


# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(description="Mock RFC 9447 Token Authority")
    ap.add_argument("--port", type=int, default=9447)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--domain", required=True,
                    help="DNS name the IdP will certify (e.g. demo.test)")
    ap.add_argument("--idp-keytab", required=True,
                    help="Keytab for HTTP/localhost@REALM")
    args = ap.parse_args()

    signer = MlDsa65Signer()
    try:
        server_creds = load_server_creds(args.idp_keytab)
    except gssapi.exceptions.GSSError as e:
        print(f"[mock_idp] Failed to load keytab {args.idp_keytab}: {e}", file=sys.stderr)
        sys.exit(1)

    IdpHandler.signer       = signer
    IdpHandler.server_creds = server_creds
    IdpHandler.domain       = args.domain

    jwks_json = json.dumps(signer.jwks(), indent=2)
    print(f"[mock_idp] ML-DSA-65 kid: {signer.kid}", file=sys.stderr)
    print(f"[mock_idp] Listening on {args.host}:{args.port}", file=sys.stderr)
    print(f"[mock_idp] JWKS:\n{jwks_json}", file=sys.stderr)
    print("[mock_idp] READY", file=sys.stderr, flush=True)

    server = http.server.HTTPServer((args.host, args.port), IdpHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
