# TLS Layer

This chapter documents the internal implementation of Akāmu's native TLS server, covering the crypto backend selection, certificate loading, composite ML-DSA scheme wiring, and the connection acceptance loop.

## Module layout

```
src/tls/
  mod.rs              TLS module re-exports; build_rustls_server_config entry point;
                      leaf_cert_der helper
  init.rs             tls::init::load_or_generate — certificate bootstrap
  loader.rs           PEM loading helpers (cert chain, private key, CA trust store)
  schemes.rs          Composite ML-DSA+classical code points (COMPOSITE_SCHEMES)
  verifier.rs         SyntaChainVerifier (CertChainVerifier for rustls-native-ossl) and
                      SyntaClientCertVerifier (rustls ClientCertVerifier wrapper)
  channel_binding.rs  RFC 5929 tls-server-end-point channel binding computation
```

TLS is optional. When `config.tls.enabled` is `false`, the server uses a plain `axum::serve` call and the entire `src/tls/` subsystem is never entered.

## Crypto provider: `rustls-native-ossl`

The rustls `ServerConfig` is constructed with the `rustls-native-ossl` default provider, which delegates all cryptographic operations to the system OpenSSL library:

```rust
let provider = Arc::new(rustls_native_ossl::default_provider());
let builder = rustls::ServerConfig::builder_with_provider(provider)
    .with_protocol_versions(&versions)?;
```

`rustls-native-ossl` handles all classical TLS signature schemes (ECDSA, RSA-PSS, RSA-PKCS1, EdDSA) for both server certificate verification and client certificate `CertificateVerify` in TLS 1.2.

Composite ML-DSA+classical `CertificateVerify` messages in TLS 1.3 are routed through the same `native-ossl` OpenSSL backend via a dedicated dispatch path (see [Composite scheme verification](#composite-scheme-verification-native-ossl) below).

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
3. `server_key.to_pem(None)` serialises the private key PEM; written to `key_file` first via `crate::util::write_key_file`.
4. `synta_certificate::der_to_pem("CERTIFICATE", &cert_der)` converts the certificate to PEM.
5. The PEM chain written to `cert_file` is `leaf cert + CA cert` (PEM-concatenated) so TLS clients see a complete chain without needing the CA cert separately.

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

## Client certificate verification (`src/tls/verifier.rs`)

Client certificate chain validation uses a two-layer architecture built on `rustls-native-ossl`:

1. **`SyntaChainVerifier`** (private) — implements the `rustls_native_ossl::cert_verifier::CertChainVerifier` trait, providing pluggable chain validation backed by `synta-x509-verification`.
2. **`SyntaClientCertVerifier`** (public) — wraps an `OsslClientCertVerifier` (which carries the `SyntaChainVerifier`) and adds configurable `client_auth_mandatory`, composite ML-DSA TLS 1.3 `CertificateVerify` routing, and `allow_post_quantum` scheme advertising.

Trust anchors are parsed once at startup via `OwnedStore::try_new` and reused across all connections with no DER re-parsing per handshake.

### `SyntaChainVerifier`

Implements `CertChainVerifier` from `rustls-native-ossl`. The framework passes native-ossl `X509` types directly; the verifier converts them back to DER and runs synta policy validation:

1. Calls `end_entity.to_der()` and each `intermediate.to_der()` to obtain raw DER bytes from the `X509` objects.
2. Parses the leaf and each intermediate via `synta::Decoder::decode::<Certificate>()`.
3. Builds a `PolicyDefinition` via `PolicyDefinition::new_client(OpensslSignatureVerifier, validation_time)`, then applies the configured profile, depth, minimum RSA modulus, and algorithm sets.
4. Calls `self.owned_store.verify(&leaf_vc, &inter_vcs, &policy, RevocationChecks::default())` — no re-parsing of trust anchors.

Algorithm sets are chosen based on `allow_post_quantum`:

| `allow_post_quantum` | SPKI algorithms | Signature algorithms |
|---|---|---|
| `false` | `WEBPKI_PERMITTED_SPKI_ALGORITHMS` | `WEBPKI_PERMITTED_SIGNATURE_ALGORITHMS` |
| `true` | `WEBPKI_PERMITTED_SPKI_ALGORITHMS_WITH_PQ` | `WEBPKI_PERMITTED_SIGNATURE_ALGORITHMS_WITH_PQ` |

### `SyntaClientCertVerifier` — construction

```rust
let verifier = SyntaClientCertVerifier::new(&ca_ders, client_auth_config)?;
```

Construction proceeds in three steps:

1. **DN hints**: each CA DER is parsed with `synta::Decoder` to extract the subject `Name`, pre-computing the `root_hint_subjects` list sent to clients in the `CertificateRequest` message.
2. **Trust store**: `OwnedStore::try_new` parses each CA DER blob into an owned in-process trust store, shared via `Arc`.
3. **Two-layer assembly**: a `SyntaChainVerifier` is created with the `OwnedStore`, profile, chain-depth, RSA-modulus, and PQ settings. It is then wrapped in `OsslClientCertVerifier::builder_with_verifier(synta_verifier).with_root_hint_subjects(root_hints).build()`. The resulting `OsslClientCertVerifier` is stored as the `inner` field of `SyntaClientCertVerifier`.

A `rustls::crypto::CryptoProvider` (`Arc<rustls_native_ossl::default_provider()>`) is also built once and stored in the `provider` field for TLS 1.2/1.3 `CertificateVerify` signature verification.

### `verify_client_cert`

On each TLS handshake, rustls calls this method. `SyntaClientCertVerifier` delegates directly to `self.inner.verify_client_cert(end_entity, intermediates, now)`, which invokes the `SyntaChainVerifier::verify_chain` callback described above.

### `verify_tls12_signature`

All TLS 1.2 `CertificateVerify` schemes delegate to the `rustls-native-ossl` provider via
the `provider` field cached at construction time — no new `default_provider()` call per
handshake:

```rust
rustls::crypto::verify_tls12_signature(
    message, cert, dss,
    &self.provider.signature_verification_algorithms,
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
        &self.provider.signature_verification_algorithms,
    )
}
```

Classical schemes go to `rustls-native-ossl`; composite ML-DSA schemes go to the
native-ossl EVP path.  The `provider` is stored as `Arc<rustls::crypto::CryptoProvider>`
in the verifier struct (built once at `SyntaClientCertVerifier::new`), so a single
`rustls_native_ossl::default_provider()` call is shared across every connection.

## Composite scheme code points (`src/tls/schemes.rs`)

```rust
pub const MLDSA44_ECDSA_P256_SHA256:     u16 = 0x0901;
pub const MLDSA44_RSA2048_PKCS15_SHA256: u16 = 0x0902;
// … 11 entries total
pub const MLDSA87_ED448_SHAKE256:        u16 = 0x090C;
```

These are provisional code points from draft-reddy-tls-composite-mldsa (all TBD pending IANA
allocation). The X.509 OIDs for the same algorithm combinations are defined in the companion
draft-ietf-lamps-pq-composite-sigs. They are advertised as `SignatureScheme::Unknown(code)`
values because rustls does not have built-in named variants for these provisional code points.

`COMPOSITE_SCHEMES` is a `&[SignatureScheme]` slice of all 11 entries, returned by `supported_verify_schemes` when `allow_post_quantum = true`.

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

| Code point | Constant | Hash |
|---|---|---|
| `0x0901` | MLDSA44_ECDSA_P256_SHA256 | `SHA2-256` |
| `0x0902` | MLDSA44_RSA2048_PKCS15_SHA256 | `SHA2-256` |
| `0x0903` | MLDSA44_RSA2048_PSS_SHA256 | `SHA2-256` |
| `0x0904` | MLDSA44_ED25519_SHA512 | `SHA2-512` |
| `0x0905` | MLDSA65_ECDSA_P256_SHA512 | `SHA2-512` |
| `0x0906` | MLDSA65_ECDSA_P384_SHA512 | `SHA2-512` |
| `0x0907` | MLDSA65_RSA3072_PKCS15_SHA512 | `SHA2-512` |
| `0x0908` | MLDSA65_RSA3072_PSS_SHA512 | `SHA2-512` |
| `0x0909` | MLDSA65_ED25519_SHA512 | `SHA2-512` |
| `0x090A` | MLDSA87_ECDSA_P384_SHA512 | `SHA2-512` |
| `0x090C` | MLDSA87_ED448_SHAKE256 | `SHAKE256` |

## Channel binding (`src/tls/channel_binding.rs`)

Implements RFC 5929 §4 `tls-server-end-point` channel binding, used by the GSSAPI
authentication layer to bind Kerberos tokens to the TLS session.

### `TlsServerEndpointBinding`

```rust
#[derive(Clone)]
pub struct TlsServerEndpointBinding(pub Vec<u8>);
```

A typed request extension injected per-connection.  Contains the raw binding bytes
(the hash of the leaf certificate DER per RFC 5929 §4).  Absent when the server
certificate uses an algorithm with no defined hash (ML-DSA pure or composite, Ed448,
or any unrecognised algorithm) — in those cases the field is not inserted and the
GSSAPI layer passes `None` channel bindings.

### `tls_server_endpoint_binding`

```rust
pub fn tls_server_endpoint_binding(cert_der: &[u8]) -> Option<Vec<u8>>
```

Parses the leaf certificate DER with `synta::Decoder`, extracts the signature
algorithm OID, and selects the appropriate hash:

| Signature algorithm | Hash used |
|---|---|
| ecdsa-with-SHA256 / sha256WithRSAEncryption | SHA-256 |
| md5WithRSAEncryption / sha1WithRSAEncryption | SHA-256 (RFC 5929 §4 override) |
| id-RSASSA-PSS with SHA-1 or SHA-256 params | SHA-256 (SHA-1 overridden) |
| id-RSASSA-PSS with SHA-384 params | SHA-384 |
| id-RSASSA-PSS with SHA-512 params | SHA-512 |
| ecdsa-with-SHA384 / sha384WithRSAEncryption | SHA-384 |
| ecdsa-with-SHA512 / sha512WithRSAEncryption / id-Ed25519 | SHA-512 |
| ML-DSA pure (FIPS 204), Composite ML-DSA, id-Ed448 | `None` — no canonical hash |

Returns `None` for unsupported algorithms; the caller logs an informational message
and disables GSSAPI channel bindings for that server certificate.

## TLS connection acceptance loop (`src/main.rs`)

When `config.tls.enabled` is `true`, the server does **not** use `axum::serve`. Instead it runs a manual accept loop:

```rust
let mut server_cfg = akamu::tls::build_rustls_server_config(&config.tls)?;
server_cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_cfg));

// Pre-compute RFC 5929 tls-server-end-point channel binding once at startup.
let tls_channel_binding: Option<Arc<Vec<u8>>> = { ... };

loop {
    tokio::select! {
        _ = &mut shutdown => { break; }
        result = listener.accept() => {
            let (stream, peer_addr) = result?;
            let acceptor = acceptor.clone();
            let router = router.clone();
            let tls_channel_binding = tls_channel_binding.clone();
            tokio::spawn(async move {
                let tls = match acceptor.accept(stream).await {
                    Ok(s) => s,
                    Err(e) => { tracing::warn!("TLS handshake failed: {e}"); return; }
                };
                let io = hyper_util::rt::TokioIo::new(tls);
                let svc = hyper::service::service_fn(move |mut req| {
                    // Inject peer address so axum::extract::ConnectInfo works.
                    req.extensions_mut().insert(axum::extract::ConnectInfo(peer_addr));
                    // Inject pre-computed channel binding if available.
                    if let Some(ref b) = tls_channel_binding {
                        req.extensions_mut().insert(TlsServerEndpointBinding(b.as_ref().clone()));
                    }
                    ...
                });
                hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
                    .serve_connection(io, svc)
                    .await
            });
        }
    }
}
```

Each accepted TCP connection is handed to `tokio_rustls::TlsAcceptor::accept`, which completes the TLS handshake (including client certificate verification if `client_auth` is configured). TLS handshake failures log a warning via `tracing::warn!` and the task returns without serving any HTTP.

For the plain HTTP path, `axum::serve(listener, router.into_make_service_with_connect_info::<SocketAddr>()).await` is used without modification.

ALPN protocols `["h2", "http/1.1"]` are negotiated; hyper's `auto::Builder` handles both HTTP/1.1 and HTTP/2.

**`ConnectInfo` is available in the TLS path.** The accept loop explicitly inserts `axum::extract::ConnectInfo(peer_addr)` into each request's extensions before routing, so handlers can use axum's `ConnectInfo<SocketAddr>` extractor normally regardless of whether TLS is enabled.

**Channel binding injection.** The `tls-server-end-point` binding bytes (see [Channel binding](#channel-binding-srctlschannel_bindingrs) above) are pre-computed once at startup from the leaf certificate DER and stored as `Option<Arc<Vec<u8>>>`. Each spawned connection task clones the `Arc` and injects a `TlsServerEndpointBinding` extension into the request so GSSAPI handlers can access it without re-reading the certificate.

## `build_rustls_server_config` (`src/tls/mod.rs`)

The central assembly function for the ACME listener:

```rust
pub fn build_rustls_server_config(
    tls: &crate::config::TlsConfig,
) -> Result<rustls::ServerConfig, String>
```

1. Calls `loader::load_server_cert_chain` and `loader::load_server_private_key`.
2. Builds the provider: `Arc::new(rustls_native_ossl::default_provider())`.
3. Filters `tls.protocols` to `&rustls::version::TLS12` and/or `&rustls::version::TLS13`. Returns `Err` if the resulting list is empty.
4. If `tls.client_auth` is present: builds `SyntaClientCertVerifier` and calls `.with_client_cert_verifier(verifier)`.
5. If absent: calls `.with_no_client_auth()`.
6. Calls `.with_single_cert(certs, key)` to install the server certificate and key.

Admin endpoints (`/admin/*`) share the same listener and TLS configuration as
the ACME API — there is no separate admin listener or dedicated admin TLS
builder.  Operator mTLS authentication uses the `[tls.client_auth]` section
with `required = false`, so the same listener can serve both mTLS (cert path)
and GSSAPI (no cert presented) connections.

### `leaf_cert_der` (`src/tls/mod.rs`)

```rust
pub fn leaf_cert_der(tls: &crate::config::TlsConfig) -> Result<Vec<u8>, String>
```

Returns the DER bytes of the first (leaf) certificate in the configured `cert_file`.
Used at startup to pre-compute the `tls-server-end-point` channel binding without
keeping a parsed certificate in memory.
