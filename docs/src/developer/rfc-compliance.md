# RFC Compliance Internals

This chapter documents how specific RFC requirements are implemented in code: EAB (RFC 8555 §7.3.4), JWS algorithm support (RFC 8555 §6.2), ML-DSA JWS (draft-ietf-cose-dilithium-11), DER structures, the pre-issuance linting step, supported challenge types, ACME STAR (RFC 8739), Renewal Info / ARI (RFC 9773), and IP identifier support (RFC 8738).

## JWS algorithm support (RFC 8555 §6.2)

All ACME POST requests are signed with JWS flattened JSON serialization (RFC 7515 §7.2.6). The server accepts the following `alg` values in the JWS protected header:

| `alg` | Key type | Curve / variant |
|---|---|---|
| `RS256` | RSA | SHA-256 |
| `RS384` | RSA | SHA-384 |
| `RS512` | RSA | SHA-512 |
| `PS256` | RSA-PSS | SHA-256 |
| `PS384` | RSA-PSS | SHA-384 |
| `PS512` | RSA-PSS | SHA-512 |
| `ES256` | EC | P-256 |
| `ES384` | EC | P-384 |
| `ES512` | EC | P-521 |
| `EdDSA` | OKP | Ed25519 or Ed448 |
| `ML-DSA-44` | AKP | FIPS 204 ML-DSA-44 |
| `ML-DSA-65` | AKP | FIPS 204 ML-DSA-65 |
| `ML-DSA-87` | AKP | FIPS 204 ML-DSA-87 |

Any other `alg` value returns `JoseError::UnsupportedAlgorithm`. ECDSA signatures use IEEE P1363 encoding (raw `r||s`) on the wire; the server converts them to DER before passing to the OpenSSL backend. ML-DSA is handled separately — see the next section.

The JWK thumbprint computation (RFC 7638) supports key types `RSA`, `EC`, `OKP`, and `AKP` (ML-DSA). The canonical JSON fields and their order per key type are implemented in `crates/akamu-jose/src/jwk.rs`.

## ML-DSA JWS verification (draft-ietf-cose-dilithium-11)

### Signature format

ML-DSA signatures in JOSE are raw bytes per FIPS 204 §7.2. They are **not** DER-wrapped. The server checks the signature length before verification:

| Algorithm | Expected signature length |
|---|---|
| ML-DSA-44 | 2420 bytes |
| ML-DSA-65 | 3309 bytes |
| ML-DSA-87 | 4627 bytes |

A length mismatch causes an immediate `badSignatureAlgorithm` error. This prevents attempting to pass malformed input to the OpenSSL backend.

### Verification call

Per draft-ietf-cose-dilithium-11 §4, the signing context must be an empty byte string. The server calls:

```rust
BackendPublicKey::verify_ml_dsa_with_context(
    message_bytes,
    signature_bytes,
    &[],   // empty context
)
```

This is dispatched from the JWS verification path in `crates/akamu-jose/src/jws.rs` after the `ML-DSA-*` algorithm is detected in the JWS protected header `alg` field.

### JWK thumbprint for `AKP` keys

Per draft-ietf-cose-dilithium-11 §6, the canonical JSON for the thumbprint hash is:

```json
{"alg":"ML-DSA-65","kty":"AKP","pub":"<base64url-public-key>"}
```

Members in lexicographic order: `alg`, `kty`, `pub`. The SHA-256 of the UTF-8 encoding of this JSON string is base64url-encoded to produce the thumbprint. The `pub` field contains the raw public key bytes (no DER wrapping).

## Supported challenge types

The `src/validation/mod.rs` dispatch table recognises the following challenge types:

| Challenge type | Identifier types | Specification |
|---|---|---|
| `http-01` | `dns`, `ip` | RFC 8555 §8.3 |
| `dns-01` | `dns` | RFC 8555 §8.4 |
| `tls-alpn-01` | `dns`, `ip` | RFC 8737 / RFC 8738 §4 |
| `dns-persist-01` | `dns` | draft-ietf-acme-dns-persist |
| `onion-csr-01` | `dns` (`.onion` only) | RFC 9799 §3.2 |

Any unrecognised challenge type returns `AcmeError::IncorrectResponse("unsupported challenge type: …")`.

### dns-persist-01 (draft-ietf-acme-dns-persist)

The `dns-persist-01` challenge uses a long-lived TXT record that the client pre-provisions and keeps in DNS. Because the record persists across issuance cycles, the server performs an extra safety check at validation time: it queries the account status from the database and rejects the challenge with `unauthorized` if the account is not in the `valid` state. This prevents a deactivated or revoked account from continuing to use a stale TXT record.

The challenge is only offered when the operator has configured at least one `dns_persist_issuer_domains` entry. The server validates the TXT record content against the issuer domain list. A separate per-challenge DNS resolver address (`dns_persist01_resolver_addr`) can be configured independently of the general DNS resolver.

### onion-csr-01 (RFC 9799)

The `onion-csr-01` challenge is offered exclusively for `.onion` identifiers (Tor v3 hidden services). The client submits a PKCS#10 CSR containing:

1. The `.onion` domain in a SAN `dNSName`.
2. The `cabf-onion-csr-nonce` extension (OID `2.23.140.41`) whose value is the key authorization string (`token.thumbprint`).
3. A signature by both the CSR key and the hidden-service Ed25519 key derived from the v3 `.onion` address.

The server-side validation in `src/validation/onion_csr_01.rs`:

1. Decodes the 32-byte Ed25519 public key from the `.onion` label (base32, 56 chars, version byte `0x03`).
2. Parses the DER CSR and verifies its self-signature.
3. Extracts the `cabf-onion-csr-nonce` extension and compares its value to the key authorization.
4. Verifies the hidden-service Ed25519 signature over the `CertificationRequestInfo` DER.
5. Confirms the CSR SAN contains the `.onion` domain.

RFC 9799 §2 prohibits v2 `.onion` addresses (16-character label); the server enforces this in both the new-order and pre-authorization paths.

### IP identifiers (RFC 8738)

The server accepts `"type": "ip"` identifiers in new-order requests (RFC 8738). IP identifiers support two challenge types:

- `http-01` — standard HTTP challenge, connecting directly to the IP address.
- `tls-alpn-01` — per RFC 8738 §4, the TLS SNI is the reverse-DNS form of the IP address (`arpa.` suffix), and the acmeIdentifier extension carries an `iPAddress` GeneralName rather than a `dNSName`.

`dns-01` is not offered for IP identifiers (no DNS name to validate against).

## ACME STAR — short-term auto-renewal (RFC 8739)

The ACME STAR protocol (RFC 8739) is implemented across several files:

- **New order** (`src/routes/order.rs`): accepts the `auto-renewal` object in the new-order payload (§3.1.1), stores `start-date`, `end-date`, `lifetime`, `lifetime-adjust`, and `allow-certificate-get` on the order row.
- **Finalize** (`src/routes/finalize.rs`): issues the first STAR certificate; the background reissuance task (`src/star.rs`) issues renewals automatically until `end-date` is reached or the order is canceled.
- **STAR certificate URL** (`src/routes/star_cert.rs`): serves the most recent certificate at `GET /acme/cert/star/{order_id}` (unauthenticated when `allow_certificate_get` is set; authenticated POST-as-GET always allowed for the order owner). The response includes `Cert-Not-Before` and `Cert-Not-After` headers per RFC 8739 §3.3.
- **Cancellation**: a `POST /acme/order/{id}` with `{"status":"canceled"}` sets `star_canceled_at`; subsequent certificate GET requests return `autoRenewalCanceled`.

The server-level `star_allow_certificate_get` config flag gates unauthenticated certificate retrieval globally (RFC 8739 §3.1.3).

## Renewal Info / ARI (RFC 9773)

The `GET /acme/renewal-info/{cert_id}` endpoint is implemented in `src/routes/renewal_info.rs`. The `cert_id` path parameter is `base64url(AKI) "." base64url(serial)` per RFC 9773 §4.1.

The handler:

1. Validates the AKI component against the CA's key identifier; returns 404 if the AKI does not match this CA.
2. Looks up the certificate by `cert_id` in the database.
3. Returns a `suggestedWindow` object with `start` and `end` timestamps. If explicit window fields are set in the database (operator override), they are used directly. Otherwise the default is: start at two-thirds of the certificate lifetime, end one day before expiry.
4. Includes an `explanationURL` field if `ari_explanation_url` is configured.
5. Sets the `Retry-After` response header to `ari_retry_after_secs` (RFC 9773 §4.3).

The response content type is `application/json` (not the ACME JWS envelope — ARI responses are plain JSON per RFC 9773).

Per-CA ARI is also available at `/acme/{ca_id}/renewal-info/{cert_id}`.

## DER structures

### Serial number encoding

Leaf certificate serials are 16 random bytes from `getrandom`. The high bit of the first byte is cleared (bitwise AND with `0x7f`) to ensure the value is a non-negative DER INTEGER per RFC 5280 §4.1.2.2.

In `src/ca/revoke.rs`, `encode_integer_der(n: u64)` handles DER INTEGER encoding for the CRL Number extension. It:

1. Converts the `u64` to 8 big-endian bytes.
2. Strips leading zero bytes (keeping at least one).
3. Prepends `0x00` if the high bit of the first remaining byte is set (two's complement positive padding).
4. Prepends the DER INTEGER tag `0x02` and the length byte.

```
n=127 → 02 01 7f
n=128 → 02 02 00 80   (zero-pad because high bit set)
n=256 → 02 02 01 00
```

### CSR extensions: manual DER walking

The `extensionRequest` attribute (OID `1.2.840.113549.1.9.14`) inside a PKCS#10 CSR is nested in a `SET OF ANY`, which `synta`'s high-level decoder does not unwrap automatically. `src/ca/csr.rs` walks the attribute bytes manually using `read_tlv`, `decode_length`, and `strip_sequence` helpers to locate and extract the extension list. This is deliberate: the alternative of using a fully-general ASN.1 parser for this path would add complexity with no benefit.

## EAB implementation walkthrough

See [EAB Internals](eab.md) for the database schema, `insert_if_absent`, and the two-step verification pipeline (`parse_eab_kid` + `verify_eab_jws`). The summary below focuses on the JWS wire format.

### EAB JWS structure

The EAB JWS is a JWS Flattened JSON Serialization with three fields:

```json
{
  "protected": "<base64url(JSON protected header)>",
  "payload":   "<base64url(JSON public JWK of the account key)>",
  "signature": "<base64url(HMAC-SHA256/384/512 over 'protected.payload')>"
}
```

The protected header must contain:

```json
{ "alg": "HS256", "kid": "<eab-key-id>", "url": "<new-account endpoint URL>" }
```

The signing input is the ASCII concatenation `"{protected}.{payload}"` (the two base64url strings joined by a period), matching the JWS compact serialization format. The HMAC is computed over this string using the raw HMAC key bytes (after base64url-decoding `hmac_key_b64u` from the database).

The payload must be the canonical JSON representation of the account's public JWK. The server verifies this by computing the RFC 7638 thumbprint of the payload JWK and comparing it with the thumbprint of the outer JWS's account key. This prevents a client from using someone else's EAB credential to create an account under a different key.

### Algorithm-to-hash mapping

| EAB `alg` | HMAC hash function |
|---|---|
| `HS256` | SHA-256 |
| `HS384` | SHA-384 |
| `HS512` | SHA-512 |

Any other `alg` value returns `AcmeError::BadRequest("EAB: unsupported algorithm …")`.

### EAB HMAC verification: constant-time comparison

`default_hmac_provider().hmac_verify(hash_alg, hmac_key, message, signature)` uses OpenSSL's `HMAC_CTX` and a constant-time byte comparison. The OpenSSL backend returns `false` rather than an early exit if the MAC does not match, preventing timing side-channels.

## Pre-issuance linting

After signing each certificate, `ca::issue::issue_with_params` runs `synta_x509_verification` policy checks before returning the `IssuedCert`:

1. The DER-encoded certificate is decoded again by `synta::Decoder`.
2. A `PolicyDefinition` is constructed for end-entity certificate validation.
3. The CA's public key is used as the trust anchor for the signature check.
4. `verify(leaf, &[], &policy, RevocationChecks::default())` is called.

If linting fails, `AcmeError::Builder` is returned and the certificate is not stored or delivered to the client. This satisfies CA/B Forum BR §4.3.1.2 (pre-issuance linting).

The checks include:

- X.509 version = v3 (tag `A2 03 02 01 02`).
- Serial number: ≤ 20 octets, positive (high bit not set without `0x00` prefix).
- `BasicConstraints: cA=FALSE` on the end-entity certificate.
- `AuthorityKeyIdentifier` extension present.
- SPKI algorithm on the WebPKI allowlist.
- RSA modulus ≥ 2048 bits; EC key on a named curve.
- CA signature cryptographically valid over the certificate body.

## `AcmeError` type strings

Every ACME-level error maps to a URN in the `urn:ietf:params:acme:error:` namespace. The mapping is defined in `src/error.rs` and is tested exhaustively — see `developer/error-handling.md` for the full table and HTTP status mapping.

The EAB-specific path uses two types:

| Condition | Error variant | ACME type | HTTP |
|---|---|---|---|
| EAB required but absent | `AcmeError::ExternalAccountRequired` | `externalAccountRequired` | 403 |
| Unknown `kid`, used `kid`, MAC fail | `AcmeError::Unauthorized(msg)` | `unauthorized` | 401 |
| Unsupported EAB `alg` | `AcmeError::BadRequest(msg)` | (maps to `serverInternal`) | 400 |
