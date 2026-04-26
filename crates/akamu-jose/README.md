# akamu-jose

JWK/JWS primitives for the Akamu ACME server (RFC 7515 / RFC 7638).

This crate provides the cryptographic building blocks used by both the Akamu
server and the `akamu-client` library.  It has no dependency on axum, sqlx,
or any other server-specific crate.

## What this crate provides

- **`JwkPublic`** — JSON Web Key (public half only).  Parses, serialises, and
  computes RFC 7638 thumbprints for EC (P-256/P-384/P-521), RSA, OKP
  (Ed25519/Ed448), and ML-DSA (AKP) keys.  Converts any supported key to
  DER-encoded SubjectPublicKeyInfo.
- **`JwsFlattened`** — JWS flattened JSON serialisation (RFC 7515 §7.2.6).
  Signs and verifies ACME-style JWS objects.
- **`JwsProtectedHeader`** — decoded protected header (alg, nonce, url, key
  reference).
- **`JwsKeyRef`** — `Jwk` variant for new-account requests; `Kid` variant for
  signed requests authenticated by account URL.
- **`JoseError`** — unified error type covering bad input, crypto failures,
  unsupported algorithms, base64 decode errors, and JSON errors.

## Supported algorithms

| Family | JWS `alg` values |
|--------|-----------------|
| ECDSA  | ES256, ES384, ES512 |
| RSA-PSS | PS256, PS384, PS512 |
| EdDSA  | EdDSA (Ed25519 and Ed448) |
| ML-DSA (post-quantum) | ML-DSA-44, ML-DSA-65, ML-DSA-87 |

ML-DSA support follows draft-ietf-cose-dilithium-11.  The JWK key type for
ML-DSA keys is `"AKP"` with an `"alg"` member (`"ML-DSA-44"`, `"ML-DSA-65"`,
or `"ML-DSA-87"`) and a `"pub"` member containing the raw public key bytes
(base64url, no padding).

ECDSA signatures are encoded as IEEE P1363 (raw r||s) in JWS, as required by
RFC 7518.  The crate converts to/from ASN.1 DER internally when calling the
OpenSSL backend.

## Usage example

```rust
use akamu_jose::{JwkPublic, JwsFlattened, JwsKeyRef};
use synta_certificate::BackendPrivateKey;

// Generate an EC P-256 account key.
let key = BackendPrivateKey::generate_ec("P-256").unwrap();

// Derive the public JWK from the backend key.
let pub_key = key.public_key().unwrap();
let jwk = JwkPublic::from_public_key(&pub_key).unwrap();

// Print the RFC 7638 thumbprint.
println!("thumbprint: {}", jwk.thumbprint().unwrap());

// Sign a new-account JWS (jwk key reference, real payload).
let jws = JwsFlattened::sign(
    &key,
    "ES256",
    "nonce-from-server",
    "https://acme.example.com/acme/new-account",
    JwsKeyRef::Jwk { jwk },
    Some(br#"{"termsOfServiceAgreed":true}"#),
)
.unwrap();

// Verify the signature (server-side equivalent).
let spki_der = pub_key.spki_der().to_vec();
jws.verify(&spki_der).unwrap();
```

For POST-as-GET requests, pass `None` as the payload; the crate produces an
empty payload string as required by RFC 8555 §6.3.

## Dependency note — PQC support

This crate depends on `synta-certificate` with the `pqc` feature.  ML-DSA and
other post-quantum primitives are provided via `native-ossl`, which is
published on crates.io.  No git fork or `[patch.crates-io]` block is required.

## License

GPL-3.0-or-later
