# akamu-jose — JWK/JWS Primitives

`akamu-jose` is a standalone Rust crate that provides RFC 7517 JWK key handling and RFC 7515 JWS signing and verification. It supports both classical and post-quantum algorithms and has **no HTTP, database, or server dependencies**.

## What it provides

- Parsing RFC 7517 public keys from JSON (`JwkPublic`)
- Computing RFC 7638 JWK thumbprints
- Converting public keys to SPKI DER for use with `synta-certificate`
- Signing and verifying RFC 7515 JWS flattened serialization (`JwsFlattened`)
- Decoding JWS protected headers (`JwsProtectedHeader`)
- All classical algorithms: ES256/ES384/ES512, PS256/PS384/PS512, EdDSA
- Post-quantum algorithms: ML-DSA-44, ML-DSA-65, ML-DSA-87 (RFC 9964)

## What it does NOT provide

- HTTP requests of any kind
- ACME protocol logic
- Database access
- Certificate issuance or CSR handling

For those, use [akamu-client](client-library.md).

## JwkPublic

`JwkPublic` represents an RFC 7517 public key. It can be constructed from a JSON JWK, from a `synta-certificate` `BackendPublicKey`, or converted to SPKI DER.

### Parsing a JWK

```rust
use akamu_jose::JwkPublic;

let json = r#"{"kty":"EC","crv":"P-256","x":"...","y":"..."}"#;
let jwk: JwkPublic = serde_json::from_str(json)?;
```

### Computing a thumbprint

The thumbprint is a SHA-256 digest of the canonical JWK representation (RFC 7638). It is used in ACME key authorizations.

```rust
let thumb = jwk.thumbprint()?;  // returns String (base64url, no padding)
```

### Converting to SPKI DER

`to_spki_der` is needed when you want to pass the public key to `synta-certificate` for signature verification or certificate issuance.

```rust
let spki_der: Vec<u8> = jwk.to_spki_der()?;
```

### Constructing from a public key

If you have a `BackendPublicKey` from `synta-certificate`, convert it to a `JwkPublic`:

```rust
let jwk = JwkPublic::from_public_key(&backend_public_key)?;
```

## JwsFlattened

`JwsFlattened` is the RFC 7515 flattened JSON serialization. It is the format used by all ACME POST requests.

### Signing

`JwsFlattened::sign` takes a protected header (already base64url-encoded JSON), a payload (already base64url-encoded), and a `BackendPrivateKey`.

```rust
use akamu_jose::{JwsFlattened, JwsProtectedHeader, JwsKeyRef};

// Sign with ES256 (P-256 key)
let protected_b64 = base64url_encode(&serde_json::to_vec(&header)?);
let payload_b64   = base64url_encode(payload_json.as_bytes());

let jws = JwsFlattened::sign(&protected_b64, &payload_b64, &private_key)?;
```

For ML-DSA-87, the call is identical — the algorithm is determined by the key type, not by a separate parameter:

```rust
// private_key is a BackendPrivateKey for an ML-DSA-87 key
let jws = JwsFlattened::sign(&protected_b64, &payload_b64, &private_key)?;
```

ML-DSA signatures are produced over the raw signing input using an empty context string as required by RFC 9964 §4.

### Verifying

`verify` checks the signature against a provided SPKI DER:

```rust
let spki_der = jwk.to_spki_der()?;
jws.verify(&spki_der)?;   // returns Ok(()) or Err(JoseError)
```

### Decoding header and payload

```rust
let header: JwsProtectedHeader = jws.decode_header()?;
let payload_bytes: Vec<u8> = jws.decode_payload()?;
```

## JwsProtectedHeader

The decoded ACME JWS protected header. Fields:

| Field | Type | Meaning |
|---|---|---|
| `alg` | `String` | Algorithm string (e.g. `"ES256"`, `"ML-DSA-87"`) |
| `nonce` | `String` | ACME anti-replay nonce |
| `url` | `String` | Target URL (must match the request URL) |
| `key_ref` | `JwsKeyRef` | Key identification: embedded JWK or account kid |

## JwsKeyRef

`JwsKeyRef` indicates how the signing key is identified in the JWS header.

```rust
pub enum JwsKeyRef {
    Jwk { jwk: JwkPublic },  // embedded public key (first request; new-account, key-change)
    Kid { kid: String },      // account URL (all subsequent requests)
}
```

Use `Jwk` when the request is made before an account exists (new-account) or for key-change operations where the new key must be embedded. Use `Kid` for all other ACME requests once an account URL is known.

## Algorithm support

| Family | alg string | JWK kty / crv | Notes |
|---|---|---|---|
| ECDSA | `ES256` | `EC` / `P-256` | SHA-256 |
| ECDSA | `ES384` | `EC` / `P-384` | SHA-384 |
| ECDSA | `ES512` | `EC` / `P-521` | SHA-512 |
| RSASSA-PSS | `PS256` | `RSA` | SHA-256 / MGF1-SHA-256 |
| RSASSA-PSS | `PS384` | `RSA` | SHA-384 / MGF1-SHA-384 |
| RSASSA-PSS | `PS512` | `RSA` | SHA-512 / MGF1-SHA-512 |
| EdDSA | `EdDSA` | `OKP` / `Ed25519` or `Ed448` | RFC 8037 |
| ML-DSA | `ML-DSA-44` | `LWE` | RFC 9964 |
| ML-DSA | `ML-DSA-65` | `LWE` | RFC 9964 |
| ML-DSA | `ML-DSA-87` | `LWE` | RFC 9964 |

## JoseError

```rust
pub enum JoseError {
    BadRequest(String),           // malformed input (missing field, wrong format)
    Crypto(String),               // signature failure or key operation error
    UnsupportedAlgorithm(String), // alg string not recognized
    Base64(String),               // base64url decode failure
    Json(String),                 // JSON parse failure
}
```

When `akamu-jose` is used inside the server, `From<JoseError> for AcmeError` converts these automatically:

- `BadRequest` → `AcmeError::BadRequest`
- `Crypto` → `AcmeError::Crypto`
- `UnsupportedAlgorithm` → `AcmeError::BadSignatureAlgorithm`

## Full example: generate P-256 key, compute thumbprint, sign a JWS

```rust
use akamu_jose::{JwkPublic, JwsFlattened};
use synta_certificate::BackendPrivateKey;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

fn base64url(data: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(data)
}

// 1. Generate a P-256 private key via synta-certificate
let private_key = BackendPrivateKey::generate("ec:P-256")?;
let public_key  = private_key.to_public_key()?;

// 2. Wrap as JwkPublic and compute the thumbprint
let jwk   = JwkPublic::from_public_key(&public_key)?;
let thumb = jwk.thumbprint()?;
println!("Thumbprint: {thumb}");

// 3. Build an ACME-style protected header (illustrative; real code uses serde)
let header_json = serde_json::json!({
    "alg":   "ES256",
    "nonce": "some-nonce",
    "url":   "https://acme.example.com/acme/new-account",
    "jwk":   serde_json::to_value(&jwk)?,
});
let protected_b64 = base64url(&serde_json::to_vec(&header_json)?);

// 4. Encode the payload
let payload_json  = serde_json::json!({"termsOfServiceAgreed": true});
let payload_b64   = base64url(&serde_json::to_vec(&payload_json)?);

// 5. Sign
let jws = JwsFlattened::sign(&protected_b64, &payload_b64, &private_key)?;

// 6. Verify round-trip
let spki_der = jwk.to_spki_der()?;
jws.verify(&spki_der)?;
println!("Signature verified");
```
