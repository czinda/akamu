# RFC Compliance Internals

This chapter documents *how* specific RFC requirements are implemented in code. For the protocol-facing view — which algorithms are accepted, which challenge types are offered, error codes, and wire formats — see [ACME Protocol Reference](../client/protocol.md).

Topics covered here: JWS algorithm dispatch and ML-DSA verification internals, challenge validation code paths, DER encoding helpers, EAB constant-time HMAC verification, pre-issuance linting, ACME STAR and ARI source layout, and RFC 9115 CSR template validation.

## JWS algorithm dispatch

All ACME POST requests are verified through the JWS path in `crates/akamu-jose/src/jws.rs`. The accepted `alg` values are listed in [ACME Protocol Reference § JWS algorithm support](../client/protocol.md#jws-algorithm-support-rfc-8555-62). Any other `alg` returns `JoseError::UnsupportedAlgorithm`.

ECDSA signatures arrive as IEEE P1363 encoding (raw `r||s`) on the wire; the server converts them to DER before passing to the OpenSSL backend.

The JWK thumbprint computation (RFC 7638) supports key types `RSA`, `EC`, `OKP`, and `AKP` (ML-DSA). The canonical JSON fields and their order per key type are implemented in `crates/akamu-jose/src/jwk.rs`.

### ML-DSA JWS verification internals (RFC 9964)

After detecting an `ML-DSA-*` algorithm in the protected header `alg` field, the server checks the raw signature length (see [protocol reference](../client/protocol.md#ml-dsa-signature-wire-format-rfc-9964) for the byte counts). A length mismatch causes an immediate `badSignatureAlgorithm` error without attempting the verify call — this prevents malformed input from reaching the OpenSSL backend.

Per RFC 9964 §4, the signing context must be an empty byte string. The server calls:

```rust
BackendPublicKey::verify_ml_dsa_with_context(
    message_bytes,
    signature_bytes,
    &[],   // empty context
)
```

This is dispatched from `crates/akamu-jose/src/jws.rs` after the algorithm is detected.

## Challenge validation code paths

The `src/validation/mod.rs` dispatch table routes each challenge type to its validator. The supported types and identifier constraints are listed in [ACME Protocol Reference § Supported challenge types](../client/protocol.md#supported-challenge-types).

Any unrecognised challenge type returns `AcmeError::IncorrectResponse("unsupported challenge type: …")`.

### dns-persist-01 safety check

Beyond the standard TXT record content check, the server performs an extra safety step at validation time: it queries the account status from the database and rejects with `unauthorized` if the account is not in the `valid` state. This prevents a deactivated or revoked account from continuing to use a stale persistent TXT record that was provisioned before deactivation.

The separate per-challenge DNS resolver (`dns_persist01_resolver_addr`) is configured independently of the general resolver.

### onion-csr-01 validation steps (RFC 9799)

`src/validation/onion_csr_01.rs` performs the following checks on the client-submitted CSR:

1. Decodes the 32-byte Ed25519 public key from the `.onion` label (base32, 56 chars, version byte `0x03`).
2. Parses the DER CSR and verifies its self-signature.
3. Extracts the `cabf-onion-csr-nonce` extension (OID `2.23.140.41`) and compares its value to the key authorization.
4. Verifies the hidden-service Ed25519 signature over the `CertificationRequestInfo` DER.
5. Confirms the CSR SAN contains the `.onion` domain.

RFC 9799 §2 prohibits v2 `.onion` addresses (16-character label); this is enforced in both the new-order and pre-authorization paths.

### tls-alpn-01 SNI encoding for IP identifiers (RFC 8738 §4)

For IP identifier challenges, the TLS SNI is the reverse-DNS form of the IP address (`arpa.` suffix), and the `acmeIdentifier` extension carries an `iPAddress` GeneralName rather than a `dNSName`. The SAN type switch is performed in `src/validation/tls_alpn_01.rs`.

## ACME STAR implementation (RFC 8739)

The STAR protocol spans several source files:

- **`src/routes/order.rs`**: accepts the `auto-renewal` object in the new-order payload (§3.1.1), stores `start-date`, `end-date`, `lifetime`, `lifetime-adjust`, and `allow-certificate-get` on the order row.
- **`src/routes/finalize.rs`**: issues the first STAR certificate.
- **`src/star.rs`**: background reissuance task that issues renewals automatically until `end-date` is reached or the order is canceled.
- **`src/routes/star_cert.rs`**: serves the most recent certificate; includes `Cert-Not-Before` and `Cert-Not-After` headers per RFC 8739 §3.3.

The server-level `star_allow_certificate_get` config flag gates unauthenticated certificate retrieval globally (RFC 8739 §3.1.3).

For the endpoint URLs and request/response shape, see [ACME Protocol Reference § ACME STAR](../client/protocol.md#acme-star--short-term-auto-renewal-rfc-8739).

## Renewal Info / ARI implementation (RFC 9773)

The endpoint is implemented in `src/routes/renewal_info.rs`. The handler:

1. Validates the AKI component against the CA's key identifier; returns 404 on mismatch.
2. Looks up the certificate by `cert_id` in the database.
3. Computes the `suggestedWindow`: if explicit window fields are set in the database (operator override), uses them; otherwise defaults to start at two-thirds of the certificate lifetime, end one day before expiry.
4. Includes `explanationURL` if `ari_explanation_url` is configured.
5. Sets `Retry-After` to `ari_retry_after_secs` (RFC 9773 §4.3).

For the `cert_id` format and response shape, see [ACME Protocol Reference § Renewal Information / ARI](../client/protocol.md#renewal-information--ari-rfc-9773).

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

## EAB implementation internals

See [EAB Internals](eab.md) for the database schema, `insert_if_absent`, and the two-step verification pipeline (`parse_eab_kid` + `verify_eab_jws`). For the EAB JWS wire format and algorithm table, see [ACME Protocol Reference § EAB JWS wire format](../client/protocol.md#eab-jws-wire-format-rfc-8555-734).

### EAB HMAC verification: constant-time comparison

`default_hmac_provider().hmac_verify(hash_alg, hmac_key, message, signature)` uses OpenSSL's `HMAC_CTX` and a constant-time byte comparison. The OpenSSL backend returns `false` rather than an early exit if the MAC does not match, preventing timing side-channels.

### EAB error mapping

| Condition | Error variant | ACME type | HTTP |
|---|---|---|---|
| EAB required but absent | `AcmeError::ExternalAccountRequired` | `externalAccountRequired` | 403 |
| Unknown `kid`, used `kid`, MAC fail | `AcmeError::Unauthorized(msg)` | `unauthorized` | 401 |
| Unsupported EAB `alg` | `AcmeError::BadRequest(msg)` | (maps to `serverInternal`) | 400 |

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

## RFC 9115 — CSR template validation

The CSR template validation in `src/routes/finalize.rs` enforces the RFC 9115 §4 constraints on delegation-order CSRs. When an order has a non-null `delegation_id`, `finalize` loads the delegation's `csr_template` from the database and passes it to `validate_csr_against_template`.

### Template semantics

Each field in the CSR template carries a JSON value whose type determines the constraint:

| JSON value type | Constraint |
|-----------------|-----------|
| `{}` (empty object) | MandatoryWildcard — the field MUST appear in the CSR |
| `null` | OptionalWildcard — the field MAY appear; its content is not checked |
| `"<literal>"` (string) | Literal — the field MUST appear with this exact value |
| absent | Forbidden — the field MUST NOT appear in the CSR |

### Validated fields

| Template field | CSR check |
|---------------|-----------|
| `keyTypes` | At least one entry in the array must match the CSR's SPKI algorithm and curve |
| `subject.commonName` | MandatoryWildcard (`{}`) → must be present; Literal → must equal the string |
| `subject.organization` | Same semantics as `commonName` |
| `extensions.subjectAltName` | MandatoryWildcard → must be present; the SAN values themselves are constrained by the order identifiers (existing RFC 8555 check), not the template |
| `extensions.keyUsage` | Array of allowed key usage bit names; the CSR's requested KeyUsage must be a subset |
| `extensions.extendedKeyUsage` | Array of allowed EKU OIDs; the CSR's requested EKU must be a subset |

A CSR that violates any constraint is rejected with `AcmeError::BadCSR` → HTTP 400 `urn:ietf:params:acme:error:badCSR`.

### Template validation at Admin API write time

`POST /admin/delegations` and `PUT /admin/delegations/{id}` both parse the `csr_template` JSON against the schema and reject malformed templates before they reach the database. This keeps the finalize-time validation path clean — by the time a CSR is checked against a template, the template is guaranteed to be structurally valid.

## `AcmeError` type strings

Every ACME-level error maps to a URN in the `urn:ietf:params:acme:error:` namespace. The mapping is defined in `src/error.rs` and is tested exhaustively — see [Error Reference](../developer/error-handling.md) for the full table and HTTP status mapping.
