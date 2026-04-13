//! Shared application state threaded through axum handlers via `Arc<AppState>`.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use axum::http::HeaderValue;
use http_body_util::Empty;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use synta_certificate::BackendPrivateKey;
use synta_mtc::crypto::HashAlgorithm;

use crate::config::Config;
use crate::mtc::log::SharedLog;

/// Shared HTTP client for outbound challenge validation requests.
///
/// Using a single shared client allows hyper to pool and reuse TCP connections
/// to challenge responders instead of opening a new connection per validation.
pub type ValidationClient = Client<HttpConnector, Empty<hyper::body::Bytes>>;

/// Top-level application state cloned into every axum handler.
#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub db: sqlx::SqlitePool,
    pub ca: Arc<CaState>,
    pub mtc: Arc<MtcState>,
    /// Present when `[tls]` is enabled and client auth is configured.
    pub tls: Option<Arc<TlsState>>,
    /// In-memory cache of account key material keyed by account ID.
    ///
    /// Populated on first authenticated request per account; evicted when the
    /// account is deactivated or its key is rolled over. Eliminates one DB
    /// round-trip per kid-authenticated POST after the first request, and lets
    /// routes that need the JWK thumbprint avoid a second `get_by_id` call.
    pub spki_cache: Arc<RwLock<HashMap<String, CachedAccount>>>,
    /// Precomputed `Link: <base_url>/acme/directory>;rel="index"` header value.
    ///
    /// Computed once at startup; reused on every ACME response to avoid
    /// `format!()` + `HeaderValue::from_str()` allocations on the hot path.
    pub link_header: Arc<HeaderValue>,
    /// Shared HTTP client for outbound http-01 challenge validation requests.
    ///
    /// `Client` is internally reference-counted and `Clone`; sharing one instance
    /// allows hyper to pool and reuse TCP connections to challenge responders,
    /// avoiding a TCP handshake per validation at ~200 validations/sec.
    pub validation_client: ValidationClient,
}

/// TLS client-auth state available to handlers for introspection.
/// The heavy work (pre-parsed trust anchors via OwnedStore) lives inside
/// `SyntaClientCertVerifier`, which is Arc-d inside the rustls `ServerConfig`.
pub struct TlsState {
    pub client_auth_config: crate::config::ClientAuthConfig,
}

/// CA key material and issuance policy.
///
/// # Concurrency
///
/// `CaState` is shared across all concurrent axum handler tasks via
/// `Arc<CaState>`. `BackendPrivateKey` delegates signing to the underlying
/// `synta_certificate` backend (OpenSSL / AWS-LC), which serialises concurrent
/// operations internally. If the backend ever changes to one that is not
/// thread-safe for concurrent signing, protect `key` with a
/// `tokio::sync::Mutex<BackendPrivateKey>`.
pub struct CaState {
    /// CA private key (used for signing certificates and CRLs).
    pub key: BackendPrivateKey,
    /// DER-encoded CA certificate.
    pub cert_der: Vec<u8>,
    /// Hash algorithm string, e.g. `"sha256"`.
    pub hash_alg: String,
    /// Default validity period for issued end-entity certificates.
    pub validity_days: u32,
    /// Optional CRL distribution point URL.
    pub crl_url: Option<String>,
    /// Optional OCSP responder URL.
    pub ocsp_url: Option<String>,
    /// RFC 5280 §4.2.1.1 key identifier bytes (SHA-1 of the CA public key
    /// BIT STRING value).  Used to validate the AKI component of ARI cert-ids
    /// (RFC 9773 §4.1) — a cert-id whose AKI does not match returns 404.
    pub aki_bytes: Vec<u8>,
}

/// Cached account key material stored in `AppState::spki_cache`.
#[derive(Clone)]
pub struct CachedAccount {
    pub spki_der: Vec<u8>,
    pub jwk_thumbprint: String,
    pub status: String,
}

/// MTC transparency log state.
pub struct MtcState {
    /// Shared, mutex-guarded disk-backed log.  `None` when MTC is disabled.
    pub log: Option<SharedLog>,
    /// Hash algorithm used for log leaf hashing.
    pub algorithm: HashAlgorithm,
}

impl MtcState {
    /// Return `true` when the MTC log is enabled and ready.
    pub fn is_enabled(&self) -> bool {
        self.log.is_some()
    }
}
