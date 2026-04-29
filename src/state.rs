//! Shared application state threaded through axum handlers via `Arc<AppState>`.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};

use axum::http::HeaderValue;
use http_body_util::Empty;
use hyper_rustls::HttpsConnector;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use synta_certificate::BackendPrivateKey;
use synta_mtc::crypto::HashAlgorithm;

use crate::config::Config;
use crate::db::DbKind;
use crate::mtc::cosign::CosignerClient;
use crate::mtc::log::SharedLog;
use crate::profiles::ProfileRegistry;

/// In-memory nonce store.
///
/// Replaces the SQLite-backed nonce table on the hot path. Each JWS request
/// requires a nonce consume + insert. In the DB-backed implementation this costs
/// 4 round-trips (BEGIN IMMEDIATE, DELETE, INSERT, COMMIT). With 6 JWS calls
/// per certificate issuance, that amounts to 24 of the total 49 round-trips —
/// capping throughput at approximately 860 iss/s.
///
/// Moving nonces into memory eliminates those 24 round-trips, lifting the
/// ceiling to ~1650 iss/s with no change to correctness: nonces are short-lived
/// and replay protection holds because the HashMap prevents double-use within
/// the same server process.
///
/// On server restart the in-memory store is empty; any nonces issued before
/// restart are silently dropped. Clients detect the resulting `badNonce` and
/// retry with a fresh nonce per RFC 8555 §6.5.
pub struct NonceBucket {
    inner: Mutex<HashMap<String, i64>>,
}

impl Default for NonceBucket {
    fn default() -> Self {
        Self::new()
    }
}

impl NonceBucket {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
        }
    }

    /// Store a new nonce with its creation timestamp.
    pub fn insert(&self, nonce: &str) {
        let now = nonce_now_secs();
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(nonce.to_string(), now);
    }

    /// Consume `old_nonce` and atomically insert `new_nonce`.
    ///
    /// Returns `true` if `old_nonce` was present and successfully replaced,
    /// `false` if it was not found (replay or unknown).
    pub fn consume_and_insert(&self, old_nonce: &str, new_nonce: &str) -> bool {
        let mut map = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if map.remove(old_nonce).is_none() {
            return false;
        }
        let now = nonce_now_secs();
        map.insert(new_nonce.to_string(), now);
        true
    }

    /// Delete nonces older than `max_age_secs` seconds.  Returns the count of
    /// removed entries.
    pub fn sweep_expired(&self, max_age_secs: i64) -> usize {
        let cutoff = nonce_now_secs().saturating_sub(max_age_secs);
        let mut map = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let before = map.len();
        map.retain(|_, &mut created| created >= cutoff);
        before - map.len()
    }
}

fn nonce_now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

/// Shared HTTP/HTTPS client for outbound challenge validation requests.
///
/// Using a single shared client allows hyper to pool and reuse TCP connections
/// to challenge responders instead of opening a new connection per validation.
/// The HTTPS connector is needed to follow HTTP 3xx redirects that point to
/// HTTPS targets, as permitted by RFC 8555 §8.3.
pub type ValidationClient = Client<HttpsConnector<HttpConnector>, Empty<hyper::body::Bytes>>;

/// In-memory CRL cache: DER bytes + expiry instant.
pub type CrlCache = Arc<Mutex<Option<(Vec<u8>, std::time::Instant)>>>;

/// Top-level application state cloned into every axum handler.
#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub db: crate::db::Db,
    pub db_kind: DbKind,
    pub ca: Arc<CaState>,
    pub mtc: Arc<MtcState>,
    /// Certificate profile registry.  Profiles are cached in memory and
    /// refreshed periodically by a background task started via
    /// [`ProfileRegistry::spawn_refresh_task`]; no external system is
    /// queried at certificate issuance time.
    ///
    /// When no `[profiles]` providers are configured, this holds an empty
    /// registry ([`ProfileRegistry::empty`]) and all issuance falls back to
    /// `CertificateParameters::from_ca` (`digitalSignature` KeyUsage,
    /// `serverAuth` EKU, CA validity and URL defaults).
    pub profiles: Arc<ProfileRegistry>,
    /// Present when `[tls]` is enabled and client auth is configured.
    pub tls: Option<Arc<TlsState>>,
    /// In-memory cache of account key material keyed by account ID.
    ///
    /// Populated on first authenticated request per account; evicted when the
    /// account is deactivated or its key is rolled over. Eliminates one DB
    /// round-trip per kid-authenticated POST after the first request, and lets
    /// routes that need the JWK thumbprint avoid a second `get_by_id` call.
    pub spki_cache: Arc<RwLock<HashMap<String, CachedAccount>>>,
    /// In-memory anti-replay nonce store.
    ///
    /// Replaces the SQLite nonce table on the hot path: consume + insert costs
    /// 4 DB round-trips per JWS call; with 6 JWS calls per issuance that was
    /// 24 of the total 49 round-trips. Moving to in-memory cuts the per-issuance
    /// round-trip count nearly in half and roughly doubles throughput.
    pub nonces: Arc<NonceBucket>,
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
    /// Cached signed CRL DER and the `Instant` after which the entry is stale.
    ///
    /// `None` until the first `GET /ca/crl` request (or after a revocation
    /// that invalidates the cache).  The `Arc<Mutex<…>>` allows the handler
    /// and the revoke route to share the cache without `&mut AppState`.
    pub crl_cache: CrlCache,
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
    /// RFC 7093 §2 Method 1 key identifier bytes (leftmost 20 bytes of the
    /// SHA-256 of the CA public key BIT STRING value).  Used to validate the
    /// AKI component of ARI cert-ids (RFC 9773 §4.1) — a cert-id whose AKI
    /// does not match returns 404.
    pub aki_bytes: Vec<u8>,
    /// When `true`, `issue_with_params` rejects issuance when the computed
    /// validity exceeds 200 days (CA/B Forum BR §6.3.2).
    pub enforce_validity_cap: bool,
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
    /// MTC signing key for checkpoint production.  `None` when not configured.
    /// Must be distinct from the X.509 CA key (§5.5 of the MTC draft).
    pub signing_key: Option<BackendPrivateKey>,
    /// Hash algorithm string for checkpoint signing (e.g. `"sha256"`).
    pub signing_hash_alg: String,
    /// Pre-built HTTPS clients for external cosigners, one per `[[mtc.cosigners]]`
    /// entry.  Built once at startup so TLS config errors surface immediately
    /// and PEM files are not re-read on every checkpoint.
    pub cosigner_clients: Vec<CosignerClient>,
    /// Advisory flock held on `{log_path}.lock` for the process lifetime.
    /// `None` when MTC is disabled.  Keeping the `File` here ensures the lock
    /// is not released prematurely.
    pub _log_lock: Option<std::fs::File>,
}

impl MtcState {
    /// Return `true` when the MTC log is enabled and ready.
    pub fn is_enabled(&self) -> bool {
        self.log.is_some()
    }

    /// Return `true` when checkpoint production is enabled (log + signing key).
    pub fn can_checkpoint(&self) -> bool {
        self.log.is_some() && self.signing_key.is_some()
    }
}
