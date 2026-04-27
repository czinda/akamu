# TLS Layer

This chapter documents the internal implementation of Akāmu's native TLS server, covering the crypto backend selection, certificate loading, composite ML-DSA scheme wiring, and the connection acceptance loop.

## Module layout

```
src/tls/
  mod.rs       TLS module re-exports; build_rustls_server_config entry point
  init.rs      tls::init::load_or_generate — certificate bootstrap
  loader.rs    PEM loading helpers (pem_to_der, BackendPrivateKey::from_pem)
  schemes.rs   Composite ML-DSA+classical code points (COMPOSITE_SCHEMES)
  verifier.rs  SyntaClientCertVerifier — rustls ClientCertVerifier impl
```

TLS is optional. When `config.tls.enabled` is `false`, the server uses a plain `axum::serve` call and the entire `src/tls/` subsystem is never entered.

## Crypto provider: `ring`

The rustls `ServerConfig` is constructed with the `ring` default provider:

```rust
let provider = Arc::new(rustls::crypto::ring::default_provider());
let builder = rustls::ServerConfig::builder_with_provider(provider)
    .with_protocol_versions(&versions)?;
```

`ring` handles all classical TLS signature schemes (ECDSA, RSA-PSS, RSA-PKCS1, EdDSA) for both server certificate verification and client certificate `CertificateVerify` in TLS 1.2.

Composite ML-DSA+classical `CertificateVerify` messages in TLS 1.3 are routed away from ring to the `native-ossl` OpenSSL backend (see [Composite scheme verification](#composite-scheme-verification-native-ossl) below).

## `tls::init::load_or_generate` (`src/tls/init.rs`)

Called once at startup when `config.tls.enabled` is `true`. It mirrors the logic of `ca::init::load_or_generate`:

| `cert_file` exists | `key_file` exists | Action |
|---|---|---|
| No | No | Generate server key + CA-signed cert; write both files |
| Yes | Yes | Return immediately — caller has supplied its own cert |
| Yes | No (or No/Yes) | Return `Err` — partial state rejected |

When generating:

1. `ca::init::generate_backend_key(&tls.bootstrap_key_type)` generates a fresh server key.
2. `ca::issue::sign_server_cert(&tls.server_name, &server_key, ca)` produces a CA-signed certificate DER.
3. `synta_certificate::der_to_pem("CERTIFICATE", &cert_der)` converts to PEM.
4. The PEM chain written to `cert_file` is `leaf cert + CA cert` (PEM-concatenated) so TLS clients see a complete chain without needing the CA cert separately.
5. `server_key.to_pem(None)` serialises the private key PEM.

The function signature is:

```rust
pub fn load_or_generate(tls: &TlsConfig, ca: &CaState) -> Result<(), String>
```

## PEM loading (`src/tls/loader.rs`)

All PEM-to-DER conversion uses `synta_certificate::pem_to_der` — the same helper used throughout the server and CA subsystems. This avoids a second PEM parser dependency.

### `load_server_cert_chain`

```rust
pub fn load_server_cert_chain(path: &str) -> Result<Vec<CertificateDer<'static>>, String>
```

Reads the file, calls `pem_to_der`, and maps each DER blob to `rustls::pki_types::CertificateDer`. Returns an error if the file contains no PEM blocks.

### `load_server_private_key`

```rust
pub fn load_server_private_key(path: &str) -> Result<PrivateKeyDer<'static>, String>
```

Reads the PEM file and calls `BackendPrivateKey::from_pem(&pem, None)` to parse it — the same `synta_certificate` primitive used to load the CA key. The resulting `BackendPrivateKey` is then serialised to PKCS#8 DER via `.to_der()` and wrapped in `rustls::pki_types::PrivateKeyDer::Pkcs8`. This accepts both unencrypted PKCS#8 (`-----BEGIN PRIVATE KEY-----`) and SEC1 EC keys (`-----BEGIN EC PRIVATE KEY-----`).

### `load_ca_certs`

```rust
pub fn load_ca_certs(ca_files: &[String]) -> Result<Vec<Vec<u8>>, String>
```

Iterates the configured CA PEM files, calls `pem_to_der` for each, and returns a flat `Vec` of DER blobs for the `SyntaClientCertVerifier` trust store.

## `SyntaClientCertVerifier` (`src/tls/verifier.rs`)

Implements `rustls::server::danger::ClientCertVerifier` using `synta-x509-verification` for chain validation. Trust anchors are parsed once at startup via `OwnedStore::try_new` and reused across all connections with no DER re-parsing per handshake.

### Construction

```rust
let verifier = SyntaClientCertVerifier::new(&ca_ders, client_auth_config)?;
```

`OwnedStore::try_new` parses each CA DER blob into an owned in-process trust store. The DN hints (`root_hint_subjects`) are also pre-computed once by parsing the subject Name from each CA DER using `synta::Decoder`.

### `verify_client_cert`

On each TLS handshake, rustls calls this method. It:

1. Clones the DER bytes out of the short-lived `CertificateDer` borrows into owned `Vec<u8>` allocations.
2. Parses the leaf and each intermediate via `synta::Decoder::decode::<Certificate>()`.
3. Builds a `PolicyDefinition` from the configured profile, depth, minimum RSA modulus, and algorithm sets.
4. Calls `self.owned_store.verify(...)` — no re-parsing of trust anchors.

Algorithm sets are chosen based on `allow_post_quantum`:

| `allow_post_quantum` | SPKI algorithms | Signature algorithms |
|---|---|---|
| `false` | `WEBPKI_PERMITTED_SPKI_ALGORITHMS` | `WEBPKI_PERMITTED_SIGNATURE_ALGORITHMS` |
| `true` | `WEBPKI_PERMITTED_SPKI_ALGORITHMS_WITH_PQ` | `WEBPKI_PERMITTED_SIGNATURE_ALGORITHMS_WITH_PQ` |

### `verify_tls12_signature`

All TLS 1.2 `CertificateVerify` schemes delegate to the `ring` provider:

```rust
rustls::crypto::verify_tls12_signature(
    message, cert, dss,
    &rustls::crypto::ring::default_provider().signature_verification_algorithms,
)
```

Composite ML-DSA schemes are TLS 1.3 only and never appear here.

### `verify_tls13_signature`

TLS 1.3 `CertificateVerify` dispatch:

```rust
if crate::tls::schemes::is_composite(dss.scheme) {
    verify_composite_tls13_signature(message, cert, dss)
} else {
    rustls::crypto::verify_tls13_signature(
        message, cert, dss,
        &rustls::crypto::ring::default_provider().signature_verification_algorithms,
    )
}
```

Classical schemes go to `ring`; composite ML-DSA schemes go to the native-ossl path.

## Composite scheme code points (`src/tls/schemes.rs`)

```rust
pub const MLDSA44_ECDSA_P256_SHA256:     u16 = 0x0901;
pub const MLDSA44_RSA2048_PKCS15_SHA256: u16 = 0x0902;
// … 12 entries total
pub const MLDSA87_ED448_SHA512:          u16 = 0x090C;
```

These are taken from the provisional IANA allocations in draft-ietf-lamps-pq-composite-sigs. They are advertised as `SignatureScheme::Unknown(code)` values because rustls does not have built-in named variants for these provisional code points.

`COMPOSITE_SCHEMES` is a `&[SignatureScheme]` slice of all 12 entries, returned by `supported_verify_schemes` when `allow_post_quantum = true`.

`is_composite(scheme: SignatureScheme) -> bool` checks whether a scheme's code point is in `COMPOSITE_SCHEMES`:

```rust
pub fn is_composite(scheme: SignatureScheme) -> bool {
    if let SignatureScheme::Unknown(code) = scheme {
        COMPOSITE_SCHEMES.contains(&SignatureScheme::Unknown(code))
    } else {
        false
    }
}
```

## Composite scheme verification (`native-ossl`)

When `is_composite` returns `true`, verification is routed to:

```rust
fn verify_composite_tls13_signature(
    message: &[u8],
    cert: &CertificateDer<'_>,
    dss: &DigitallySignedStruct,
) -> Result<HandshakeSignatureValid, TlsError>
```

This function:

1. Extracts the composite SubjectPublicKeyInfo DER from the raw certificate bytes using `synta_certificate::cert_byte_ranges` to get the exact SPKI TLV byte range — avoiding a full certificate re-parse.
2. Calls `verify_composite_via_openssl(dss.scheme, message, spki_der, dss.signature())`.

`verify_composite_via_openssl` uses `native-ossl`:

```rust
use native_ossl::pkey::{Pkey, Public, SignInit, Verifier};

let pkey = Pkey::<Public>::from_der(spki_der)?;
let digest = composite_digest(scheme)?;
let mut verifier = Verifier::new(&pkey, &SignInit { digest: Some(&digest), params: None })?;
verifier.update(message)?;
verifier.verify(sig_bytes)?
```

`Pkey::<Public>::from_der` loads the composite SubjectPublicKeyInfo DER via OpenSSL's `d2i_PUBKEY`, which understands both the classical and ML-DSA components of the composite key. `Verifier::verify` dispatches to the OpenSSL provider, which applies "and" semantics — both the classical and ML-DSA components must verify.

`composite_digest` maps each code point to the correct hash algorithm name for `native_ossl::digest::DigestAlg::fetch`:

| Code point | Hash |
|---|---|
| `0x0901` MLDSA44_ECDSA_P256_SHA256 | `SHA2-256` |
| `0x0904` MLDSA44_ED25519_SHA512 | `SHA2-512` |
| `0x0907` MLDSA65_RSA3072_PKCS15_SHA384 | `SHA2-384` |
| `0x090A` MLDSA87_ECDSA_P384_SHA512 | `SHA2-512` |
| … | … |

## TLS connection acceptance loop (`src/main.rs`)

When `config.tls.enabled` is `true`, the server does **not** use `axum::serve`. Instead it runs a manual accept loop:

```rust
let server_cfg = akamu::tls::build_rustls_server_config(&config.tls)?;
server_cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_cfg));

loop {
    let (stream, _) = listener.accept().await?;
    let acceptor = acceptor.clone();
    let router = router.clone();
    tokio::spawn(async move {
        let tls = match acceptor.accept(stream).await { Ok(s) => s, Err(e) => { ... return; } };
        let io = hyper_util::rt::TokioIo::new(tls);
        // route request through tower::ServiceExt::oneshot
        hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
            .serve_connection(io, svc)
            .await
    });
}
```

Each accepted TCP connection is handed to `tokio_rustls::TlsAcceptor::accept`, which completes the TLS handshake (including client certificate verification if `client_auth` is configured). TLS handshake failures log a warning via `tracing::warn!` and the task returns without serving any HTTP.

For the plain HTTP path, `axum::serve(listener, router).await` is used without modification.

ALPN protocols `["h2", "http/1.1"]` are negotiated; hyper's `auto::Builder` handles both HTTP/1.1 and HTTP/2.

The remote client IP address is available via `hyper::Request` header inspection (`X-Forwarded-For`, `X-Real-IP`) from an upstream proxy, or directly from the `std::net::SocketAddr` returned by `listener.accept()`. Because `axum::serve` is not used in the TLS path, axum's `ConnectInfo` extractor is not available in TLS-enabled mode; handlers relying on the client IP must inspect headers.

## `build_rustls_server_config` (`src/tls/mod.rs`)

The central assembly function:

```rust
pub fn build_rustls_server_config(
    tls: &crate::config::TlsConfig,
) -> Result<rustls::ServerConfig, String>
```

1. Calls `loader::load_server_cert_chain` and `loader::load_server_private_key`.
2. Builds the provider: `Arc::new(rustls::crypto::ring::default_provider())`.
3. Filters `tls.protocols` to `&rustls::version::TLS12` and/or `&rustls::version::TLS13`. Returns `Err` if the resulting list is empty.
4. If `tls.client_auth` is present: builds `SyntaClientCertVerifier` and calls `.with_client_cert_verifier(verifier)`.
5. If absent: calls `.with_no_client_auth()`.
6. Calls `.with_single_cert(certs, key)` to install the server certificate and key.
