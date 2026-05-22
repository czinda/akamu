# ACME Protocol Reference

This page is the protocol-level API reference for clients interacting with Akāmu: which JWS algorithms the server accepts, which challenge types are offered and for which identifier types, the wire format for EAB credentials, and the endpoint contract for ARI and ACME STAR.

For implementation notes — how the server verifies these on the wire, DER encoding helpers, and pre-issuance linting — see [RFC Compliance Internals](../developer/rfc-compliance.md).

## JWS algorithm support (RFC 8555 §6.2)

All ACME POST requests must be signed with JWS flattened JSON serialization (RFC 7515 §7.2.6). The server accepts the following `alg` values in the JWS protected header:

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

Any other `alg` value returns `badSignatureAlgorithm` (HTTP 400). ECDSA signatures use IEEE P1363 encoding (raw `r||s`).

### ML-DSA signature wire format (RFC 9964)

ML-DSA signatures in JOSE are raw bytes per FIPS 204 §7.2 — **not** DER-wrapped. The server checks the signature length before verification:

| Algorithm | Expected signature length |
|---|---|
| `ML-DSA-44` | 2420 bytes |
| `ML-DSA-65` | 3309 bytes |
| `ML-DSA-87` | 4627 bytes |

A length mismatch causes an immediate `badSignatureAlgorithm` error. The signing context must be an empty byte string per RFC 9964 §4.

### JWK thumbprint for AKP keys (ML-DSA)

Per RFC 9964 §6, the canonical JSON for computing the RFC 7638 thumbprint of an ML-DSA public key is:

```json
{"alg":"ML-DSA-65","kty":"AKP","pub":"<base64url-public-key>"}
```

Members in lexicographic order: `alg`, `kty`, `pub`. The `pub` field contains the raw public key bytes (no DER wrapping).

## Supported challenge types

The server offers the following challenge types per identifier type:

| Challenge type | Identifier types | Specification |
|---|---|---|
| `http-01` | `dns`, `ip` | RFC 8555 §8.3 |
| `dns-01` | `dns` | RFC 8555 §8.4 |
| `tls-alpn-01` | `dns`, `ip` | RFC 8737 / RFC 8738 §4 |
| `dns-persist-01` | `dns` | draft-ietf-acme-dns-persist |
| `onion-csr-01` | `dns` (`.onion` only) | RFC 9799 §3.2 |

`dns-persist-01` is only offered when the server is configured with at least one `dns_persist_issuer_domains` entry.

`onion-csr-01` is offered exclusively for `.onion` (Tor v3 hidden service) identifiers. The server rejects v2 `.onion` addresses.

### IP identifiers (RFC 8738)

`"type": "ip"` identifiers in new-order requests are accepted per RFC 8738. Two challenge types are offered for IP identifiers:

- `http-01` — standard HTTP challenge connecting to the IP address directly.
- `tls-alpn-01` — per RFC 8738 §4, the TLS SNI is the reverse-DNS form of the IP (`arpa.` suffix), and the `acmeIdentifier` extension carries an `iPAddress` GeneralName rather than `dNSName`.

`dns-01` is not offered for IP identifiers.

## EAB JWS wire format (RFC 8555 §7.3.4)

When External Account Binding is required, the `externalAccountBinding` field of the `newAccount` payload must be a JWS Flattened JSON Serialization:

```json
{
  "protected": "<base64url(JSON protected header)>",
  "payload":   "<base64url(JSON public JWK of the account key)>",
  "signature": "<base64url(HMAC over 'protected.payload')>"
}
```

The protected header must contain:

```json
{ "alg": "HS256", "kid": "<eab-key-id>", "url": "<new-account endpoint URL>" }
```

The signing input is the ASCII concatenation `"{protected}.{payload}"`. The payload must be the canonical JSON representation of the account's public JWK. The server verifies the payload JWK thumbprint matches the outer account key.

### EAB algorithm support

| EAB `alg` | HMAC hash function |
|---|---|
| `HS256` | SHA-256 |
| `HS384` | SHA-384 |
| `HS512` | SHA-512 |

Any other `alg` value returns `badRequest` (HTTP 400).

## Renewal Information / ARI (RFC 9773)

**Endpoint:** `GET /acme/renewal-info/{cert_id}`  
Per-CA variant: `GET /acme/{ca_id}/renewal-info/{cert_id}`

The `cert_id` path parameter is `base64url(AKI) "." base64url(serial)` per RFC 9773 §4.1. The server returns 404 if the AKI does not match this CA's key identifier.

The response is plain JSON (not wrapped in a JWS envelope) with content type `application/json`:

```json
{
  "suggestedWindow": {
    "start": "<RFC 3339 timestamp>",
    "end":   "<RFC 3339 timestamp>"
  },
  "explanationURL": "<url>"   // present only when configured
}
```

The default window starts at two-thirds of the certificate lifetime and ends one day before expiry. Operators can override this per-certificate via the admin API. The `Retry-After` response header is set per RFC 9773 §4.3.

## ACME STAR — short-term auto-renewal (RFC 8739)

STAR certificates are issued and renewed automatically by the server. The `auto-renewal` object in the new-order payload accepts:

| Field | Meaning |
|---|---|
| `start-date` | ISO 8601 date when auto-renewal begins |
| `end-date` | ISO 8601 date when auto-renewal stops |
| `lifetime` | Per-certificate validity duration (seconds) |
| `lifetime-adjust` | Optional clock-skew window (seconds) |
| `allow-certificate-get` | `true` to allow unauthenticated certificate retrieval |

The current STAR certificate is available at:

```
GET /acme/cert/star/{order_id}
```

Unauthenticated access is gated on both the `allow-certificate-get` order field and the server-level `star_allow_certificate_get` config flag. The response includes `Cert-Not-Before` and `Cert-Not-After` headers (RFC 8739 §3.3).

To cancel a STAR order, POST `{"status":"canceled"}` to `POST /acme/order/{id}`. Subsequent certificate requests return `autoRenewalCanceled`.
