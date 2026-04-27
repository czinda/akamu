# RFC Compliance Internals

This chapter documents how specific RFC requirements are implemented in code: EAB (RFC 8555 §7.3.4), ML-DSA JWS (draft-ietf-cose-dilithium-11), DER structures, and the pre-issuance linting step.

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

This is dispatched from the JWS verification path in `src/jose/jws.rs` after the `ML-DSA-*` algorithm is detected in the JWS protected header `alg` field.

### JWK thumbprint for `AKP` keys

Per draft-ietf-cose-dilithium-11 §6, the canonical JSON for the thumbprint hash is:

```json
{"alg":"ML-DSA-65","kty":"AKP","pub":"<base64url-public-key>"}
```

Members in lexicographic order: `alg`, `kty`, `pub`. The SHA-256 of the UTF-8 encoding of this JSON string is base64url-encoded to produce the thumbprint. The `pub` field contains the raw public key bytes (no DER wrapping).

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

### EAB HMAC verification: constant-time comparison

`default_hmac_provider().hmac_verify(hash_alg, hmac_key, message, signature)` uses OpenSSL's `HMAC_CTX` and a constant-time byte comparison. The OpenSSL backend returns `false` rather than an early exit if the MAC does not match, preventing timing side-channels.

### CSR extensions: manual DER walking

The `extensionRequest` attribute (OID `1.2.840.113549.1.9.14`) inside a PKCS#10 CSR is nested in a `SET OF ANY`, which `synta`'s high-level decoder does not unwrap automatically. `src/ca/csr.rs` walks the attribute bytes manually using `read_tlv`, `decode_length`, and `strip_sequence` helpers to locate and extract the extension list. This is deliberate: the alternative of using a fully-general ASN.1 parser for this path would add complexity with no benefit.

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
