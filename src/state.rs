//! Shared application state threaded through axum handlers via `Arc<AppState>`.

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Instant;

use indexmap::IndexMap;

pub type AdminAuthLimiter = Arc<tokio::sync::Mutex<HashMap<IpAddr, VecDeque<Instant>>>>;

/// Seen gossip envelope nonces: nonce bytes → first-seen unix timestamp.
pub type GossipNonceCache = Arc<std::sync::Mutex<std::collections::HashMap<Vec<u8>, i64>>>;

/// Per-URL JWKS body cache: raw body bytes + fetch timestamp.
///
/// Keyed by JWKS URL string.  Entries are refreshed after a 5-minute TTL.
pub(crate) type JwksCache = Arc<tokio::sync::Mutex<HashMap<String, (Vec<u8>, std::time::Instant)>>>;

use axum::http::HeaderValue;
use http_body_util::Empty;
use hyper_rustls::HttpsConnector;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use synta_certificate::BackendPrivateKey;
use synta_mtc::crypto::HashAlgorithm;

use crate::audit::{AuditPolicy, AuditState};
use crate::config::Config;
use crate::db::DbKind;
use crate::journal::JournalWriter;
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
///
/// In multi-node deployments, `node_prefix` is set to a stable per-node token
/// (first 11 characters of the node_id).  Nonces issued by this node carry the
/// format `"{node_prefix}.{random}"` and are only accepted by this node.
/// When `node_prefix` is empty (single-node / test mode) the prefix check is
/// skipped and all nonces are accepted.
pub struct NonceBucket {
    inner: Mutex<HashMap<String, i64>>,
    pub node_prefix: String,
}

impl Default for NonceBucket {
    fn default() -> Self {
        Self::new()
    }
}

impl NonceBucket {
    /// Create a bucket with no node prefix (single-node / test mode).
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            node_prefix: String::new(),
        }
    }

    /// Create a bucket with a node-specific prefix for multi-node deployments.
    pub fn with_prefix(prefix: String) -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            node_prefix: prefix,
        }
    }

    /// Returns `true` when `nonce` was issued by this node.
    ///
    /// When `node_prefix` is empty (single-node mode) every nonce is accepted.
    pub fn has_local_prefix(&self, nonce: &str) -> bool {
        if self.node_prefix.is_empty() {
            return true;
        }
        let expected = format!("{}.", self.node_prefix);
        nonce.starts_with(expected.as_str())
    }

    /// Store a new nonce with its creation timestamp.
    pub fn insert(&self, nonce: String) {
        let now = nonce_now_secs();
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(nonce, now);
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
    /// Read-only connection pool for pure-read handlers (WAL concurrent reads).
    ///
    /// For SQLite file-backed databases this is a `?mode=ro` pool that never
    /// acquires the write lock.  For `:memory:` and non-SQLite backends this
    /// is a clone of `db` (no split advantage, but also no regression).
    pub db_ro: crate::db::Db,
    pub db_kind: DbKind,
    /// All CAs keyed by their `id`, in insertion order (first entry = config order).
    pub cas: Arc<IndexMap<String, Arc<CaState>>>,
    /// The CA designated as the default for legacy `/acme/…` routes.
    pub default_ca_id: Arc<String>,
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
    /// Per-CA precomputed `Link: …;rel="index"` header values.
    ///
    /// Keyed by CA ID.  Computed once at startup; reused on every ACME response
    /// to avoid `format!()` + `HeaderValue::from_str()` allocations on the hot path.
    pub link_headers: Arc<HashMap<String, Arc<HeaderValue>>>,
    /// Shared HTTP client for outbound http-01 challenge validation requests.
    ///
    /// `Client` is internally reference-counted and `Clone`; sharing one instance
    /// allows hyper to pool and reuse TCP connections to challenge responders,
    /// avoiding a TCP handshake per validation at ~200 validations/sec.
    pub validation_client: ValidationClient,
    /// Per-CA CRL caches, keyed by CA ID.
    ///
    /// Each entry is `None` until the first `GET /ca/{id}/crl` request (or after a
    /// revocation that invalidates it).  The inner `Arc<Mutex<…>>` allows the CRL
    /// handler and the revoke route to share each cache without `&mut AppState`.
    pub crl_caches: Arc<HashMap<String, CrlCache>>,
    /// Server-side GSSAPI credential for standalone SPNEGO authentication.
    ///
    /// `None` when `[server.gssapi]` is absent from the config.  When present,
    /// the `RemoteUser` extractor uses it to validate `Authorization: Negotiate`
    /// tokens without a reverse proxy.
    pub gss_cred: Option<Arc<akamu_gssapi::GssServerCred>>,
    /// Admin-specific GSSAPI credential, acquired from `[admin.gssapi]` at startup.
    /// Takes precedence over `gss_cred` for admin SPNEGO authentication.
    /// `None` when `[admin.gssapi]` is absent.
    pub admin_gss_cred: Option<Arc<akamu_gssapi::GssServerCred>>,
    /// Decoded master secret for HKDF-based EAB key derivation.
    /// `None` when `[server].eab_master_secret` is absent.
    pub eab_master_secret: Option<Arc<akamu_util::SecretBuffer>>,
    /// Shared in-memory audit state (overflow flag, FAU_ARP.1 alarm counter).
    /// Always present; operations before the admin config is loaded use the
    /// default `AuditPolicy` (no limit, `drop_oldest`, threshold=10, `syslog`).
    pub audit: Arc<AuditState>,
    /// Audit policy extracted from `[admin]` at startup.  Default when `[admin]`
    /// is absent.
    pub audit_policy: Arc<AuditPolicy>,
    /// Journal writer for the audit namespace.
    pub journal: Arc<JournalWriter>,
    /// Admin operator session store (FTA_SSL.3/4/EXT.1).
    ///
    /// Maps opaque 32-byte hex session token → `AdminSession`.  Checked on
    /// every request to the admin listener; entries are evicted when their TTL
    /// expires.  `None` when `[admin]` is absent.
    pub admin_sessions: Option<Arc<tokio::sync::Mutex<HashMap<String, AdminSession>>>>,
    /// Per-source-IP credential-attempt timestamps for admin auth rate-limiting.
    ///
    /// Each entry holds the `Instant`s of recent attempts from that IP within
    /// the rolling 5-minute window.  Entries are swept lazily on each check.
    /// `None` when `[admin]` is absent.
    pub admin_auth_limiter: Option<AdminAuthLimiter>,
    /// Anti-replay cache for EAB session login.
    ///
    /// Records recently seen `"kid.timestamp"` keys (Unix epoch, decimal) so
    /// that a captured request cannot be replayed within the ±60-second window.
    /// Entries are evicted lazily when they are more than 120 seconds old.
    /// `None` when `[admin]` is absent.
    pub eab_session_nonces: Option<Arc<tokio::sync::Mutex<HashMap<String, i64>>>>,
    /// Time the server process started.  Used for uptime reporting in
    /// `GET /admin/stats` and for session-expiry calculations.
    pub startup_time: Instant,
    /// In-memory CRDT replica.  Authoritative for cluster state; the local DB
    /// is a persistence cache.  Guarded by a tokio RwLock so read-heavy
    /// handlers can hold read locks concurrently while gossip merges write.
    pub crdt: Arc<tokio::sync::RwLock<akamu_crdt::AkaCrdt>>,
    /// Stable node identity derived from the node's signing public key
    /// (base64url-nopad of the first 16 bytes of SHA-256(SPKI-DER)).
    /// Used as the `node_id` in all CRDT writes on this node.
    pub node_id: Arc<String>,
    /// ML-KEM-768 private key as PKCS8 DER.  Used by the gossip handler to
    /// decapsulate the per-message session key from inbound CMS EnvelopedData.
    pub node_kem_priv: Arc<Vec<u8>>,
    /// ECDSA P-256 gossip signing private key as PEM bytes.  Used to sign
    /// outbound CMS SignedData so peers can authenticate this node's pushes.
    pub node_gossip_signing_priv: Arc<Vec<u8>>,
    /// DER-encoded self-signed certificate for the gossip signing key.
    /// Embedded in outbound CMS SignedData so peers can pin-verify the sender.
    pub node_gossip_signing_cert: Arc<Vec<u8>>,
    /// Shared HTTP client for outbound gossip pushes.
    /// Plain HTTP is used; CMS SignedData + EnvelopedData provides auth + confidentiality.
    pub gossip_client: Arc<reqwest::Client>,
    /// Seen gossip envelope nonces: nonce bytes → first-seen unix timestamp.
    ///
    /// Prevents an attacker from replaying a captured CMS blob within the
    /// `gossip_envelope_max_age_secs` window.  Entries are evicted lazily once
    /// their timestamp falls outside the window.  Absent nonces (empty `Vec<u8>`)
    /// are not tracked so old peers that omit the field are still accepted.
    pub gossip_nonce_cache: GossipNonceCache,
    /// Signalled after every CRDT write so the gossip loop can fire immediately
    /// rather than waiting out the full configured interval (typically 1–30 s).
    /// This bounds cross-node propagation latency to the gossip debounce window
    /// (~10 ms) instead of the full interval.
    pub write_notify: Arc<tokio::sync::Notify>,
    /// Dedicated pool for CRDT cluster tables (`crdt_cluster_nodes`,
    /// `crdt_order_owners`, `crdt_mtc_writer`, `node_keys`).  Separate from
    /// `db` so that the 30-second periodic cluster-state persist does not
    /// contend with ACME writes on the main pool.
    pub crdt_db: crate::db::Db,
    /// Trust anchors for Token Authority cert chain validation (RFC 9447 §5.3).
    ///
    /// Built from `config.tkauth.trusted_ta_ca_files` at startup.
    /// `None` when `[tkauth]` is absent or `enabled = false`.
    pub tkauth_trust_anchors: Option<std::sync::Arc<synta_x509_verification::OwnedStore>>,
    /// Registry mapping JWT claim names to DER extension encoders.
    ///
    /// Used at finalize time to convert validated `JWTClaimConstraints` claims into
    /// OtherName SANs.  Built from `[tkauth.claim_encoders]` at startup.
    /// `None` when tkauth is disabled or no encoders are configured.
    pub claim_encoder_registry:
        Option<std::sync::Arc<crate::validation::claim_encoder::ClaimEncoderRegistry>>,
    /// In-memory JWKS body cache for `kid`-signed authority tokens (RFC 9447).
    ///
    /// Keyed by JWKS endpoint URL; entries are refreshed after 5 minutes.
    /// `None` when tkauth is disabled.
    pub jwks_cache: Option<JwksCache>,
    /// Write coalescer for SQLite hot-path writes.  `None` for PostgreSQL/MariaDB.
    pub write_coalescer: Option<std::sync::Arc<crate::db::coalescer::WriteCoalescer>>,
}

impl AppState {
    /// Return the default CA state.  Panics only if the server was constructed
    /// incorrectly (i.e. `default_ca_id` is not present in `cas`).
    pub fn default_ca(&self) -> &Arc<CaState> {
        self.cas
            .get(self.default_ca_id.as_str())
            .expect("default CA always present in cas")
    }

    /// Look up a CA by ID.  Returns `None` for unknown CA IDs.
    pub fn get_ca(&self, ca_id: &str) -> Option<&Arc<CaState>> {
        self.cas.get(ca_id)
    }

    /// Look up the CRL cache for a specific CA.  Returns `None` for unknown CA IDs.
    pub fn get_crl_cache(&self, ca_id: &str) -> Option<&CrlCache> {
        self.crl_caches.get(ca_id)
    }

    /// Invalidate the CRL cache for a specific CA (e.g. after revocation).
    pub fn invalidate_crl_cache(&self, ca_id: &str) {
        if let Some(cache) = self.crl_caches.get(ca_id) {
            match cache.lock() {
                Ok(mut g) => *g = None,
                Err(e) => {
                    tracing::error!(ca_id, "CRL cache mutex poisoned — forcing invalidation");
                    *e.into_inner() = None;
                }
            }
        }
    }

    /// Record an audit event, logging (but not propagating) any journal error.
    ///
    /// Convenience wrapper over [`crate::audit::record_or_log`] that bundles
    /// the three audit-related `AppState` fields so call sites pass only the
    /// event.
    ///
    /// Marked `async` for API compatibility with callers that `.await` it,
    /// even though the body contains no `.await` points.  Removing `async`
    /// would be a breaking change for all call sites.
    pub async fn record_audit(&self, ev: crate::audit::AuditEvent) {
        crate::audit::record_or_log(&self.journal, &self.audit, &self.audit_policy, ev);
    }

    /// Record two audit events, logging (but not propagating) any journal error.
    ///
    /// See [`Self::record_audit`] for why this is `async`.
    pub async fn record_audit_pair(
        &self,
        ev1: crate::audit::AuditEvent,
        ev2: crate::audit::AuditEvent,
    ) {
        crate::audit::record_or_log_pair(&self.journal, &self.audit, &self.audit_policy, ev1, ev2);
    }

    /// Return a point-in-time snapshot of the CRDT (cheap clone under read lock).
    pub async fn crdt_snapshot(&self) -> akamu_crdt::AkaCrdt {
        self.crdt.read().await.clone()
    }
}

// ── AppState builder ─────────────────────────────────────────────────────────

pub fn default_validation_client() -> ValidationClient {
    let https = hyper_rustls::HttpsConnectorBuilder::new()
        .with_native_roots()
        .expect("failed to load native root CAs for validation client")
        .https_or_http()
        .enable_http1()
        .build();
    hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new()).build(https)
}

pub struct AppStateBuilder {
    config: Arc<Config>,
    db: crate::db::Db,
    db_ro: Option<crate::db::Db>,
    db_kind: DbKind,
    cas: Arc<IndexMap<String, Arc<CaState>>>,
    default_ca_id: Arc<String>,
    profiles: Option<Arc<ProfileRegistry>>,
    tls: Option<Arc<TlsState>>,
    spki_cache: Option<Arc<RwLock<HashMap<String, CachedAccount>>>>,
    nonces: Option<Arc<NonceBucket>>,
    link_headers: Option<Arc<HashMap<String, Arc<HeaderValue>>>>,
    validation_client: Option<ValidationClient>,
    crl_caches: Option<Arc<HashMap<String, CrlCache>>>,
    gss_cred: Option<Arc<akamu_gssapi::GssServerCred>>,
    admin_gss_cred: Option<Arc<akamu_gssapi::GssServerCred>>,
    eab_master_secret: Option<Arc<akamu_util::SecretBuffer>>,
    audit: Option<Arc<AuditState>>,
    audit_policy: Option<Arc<AuditPolicy>>,
    journal: Option<Arc<JournalWriter>>,
    admin_sessions: Option<Arc<tokio::sync::Mutex<HashMap<String, AdminSession>>>>,
    admin_auth_limiter: Option<AdminAuthLimiter>,
    eab_session_nonces: Option<Arc<tokio::sync::Mutex<HashMap<String, i64>>>>,
    startup_time: Option<Instant>,
    crdt: Option<Arc<tokio::sync::RwLock<akamu_crdt::AkaCrdt>>>,
    node_id: Option<Arc<String>>,
    node_kem_priv: Option<Arc<Vec<u8>>>,
    node_gossip_signing_priv: Option<Arc<Vec<u8>>>,
    node_gossip_signing_cert: Option<Arc<Vec<u8>>>,
    gossip_client: Option<Arc<reqwest::Client>>,
    gossip_nonce_cache: Option<GossipNonceCache>,
    write_notify: Option<Arc<tokio::sync::Notify>>,
    crdt_db: Option<crate::db::Db>,
    tkauth_trust_anchors: Option<Arc<synta_x509_verification::OwnedStore>>,
    claim_encoder_registry: Option<Arc<crate::validation::claim_encoder::ClaimEncoderRegistry>>,
    jwks_cache: Option<JwksCache>,
    write_coalescer: Option<Arc<crate::db::coalescer::WriteCoalescer>>,
}

macro_rules! builder_setter {
    ($name:ident, $ty:ty) => {
        pub fn $name(mut self, v: $ty) -> Self {
            self.$name = Some(v);
            self
        }
    };
}

impl AppStateBuilder {
    pub fn new(
        config: Arc<Config>,
        db: crate::db::Db,
        db_kind: DbKind,
        cas: Arc<IndexMap<String, Arc<CaState>>>,
        default_ca_id: Arc<String>,
    ) -> Self {
        Self {
            config,
            db,
            db_ro: None,
            db_kind,
            cas,
            default_ca_id,
            profiles: None,
            tls: None,
            spki_cache: None,
            nonces: None,
            link_headers: None,
            validation_client: None,
            crl_caches: None,
            gss_cred: None,
            admin_gss_cred: None,
            eab_master_secret: None,
            audit: None,
            audit_policy: None,
            journal: None,
            admin_sessions: None,
            admin_auth_limiter: None,
            eab_session_nonces: None,
            startup_time: None,
            crdt: None,
            node_id: None,
            node_kem_priv: None,
            node_gossip_signing_priv: None,
            node_gossip_signing_cert: None,
            gossip_client: None,
            gossip_nonce_cache: None,
            write_notify: None,
            crdt_db: None,
            tkauth_trust_anchors: None,
            claim_encoder_registry: None,
            jwks_cache: None,
            write_coalescer: None,
        }
    }

    builder_setter!(db_ro, crate::db::Db);
    builder_setter!(profiles, Arc<ProfileRegistry>);
    builder_setter!(tls, Arc<TlsState>);
    builder_setter!(spki_cache, Arc<RwLock<HashMap<String, CachedAccount>>>);
    builder_setter!(nonces, Arc<NonceBucket>);
    builder_setter!(link_headers, Arc<HashMap<String, Arc<HeaderValue>>>);
    builder_setter!(validation_client, ValidationClient);
    builder_setter!(crl_caches, Arc<HashMap<String, CrlCache>>);
    builder_setter!(gss_cred, Arc<akamu_gssapi::GssServerCred>);
    builder_setter!(admin_gss_cred, Arc<akamu_gssapi::GssServerCred>);
    builder_setter!(eab_master_secret, Arc<akamu_util::SecretBuffer>);
    builder_setter!(audit, Arc<AuditState>);
    builder_setter!(audit_policy, Arc<AuditPolicy>);
    builder_setter!(journal, Arc<JournalWriter>);
    builder_setter!(
        admin_sessions,
        Arc<tokio::sync::Mutex<HashMap<String, AdminSession>>>
    );
    builder_setter!(admin_auth_limiter, AdminAuthLimiter);
    builder_setter!(
        eab_session_nonces,
        Arc<tokio::sync::Mutex<HashMap<String, i64>>>
    );
    builder_setter!(startup_time, Instant);
    builder_setter!(crdt, Arc<tokio::sync::RwLock<akamu_crdt::AkaCrdt>>);
    builder_setter!(node_id, Arc<String>);
    builder_setter!(node_kem_priv, Arc<Vec<u8>>);
    builder_setter!(node_gossip_signing_priv, Arc<Vec<u8>>);
    builder_setter!(node_gossip_signing_cert, Arc<Vec<u8>>);
    builder_setter!(gossip_client, Arc<reqwest::Client>);
    builder_setter!(gossip_nonce_cache, GossipNonceCache);
    builder_setter!(write_notify, Arc<tokio::sync::Notify>);
    builder_setter!(crdt_db, crate::db::Db);
    builder_setter!(
        tkauth_trust_anchors,
        Arc<synta_x509_verification::OwnedStore>
    );
    builder_setter!(
        claim_encoder_registry,
        Arc<crate::validation::claim_encoder::ClaimEncoderRegistry>
    );
    builder_setter!(jwks_cache, JwksCache);
    builder_setter!(write_coalescer, Arc<crate::db::coalescer::WriteCoalescer>);

    pub fn build(self) -> Arc<AppState> {
        let db_ro = self.db_ro.unwrap_or_else(|| self.db.clone());
        let crdt_db = self.crdt_db.unwrap_or_else(|| self.db.clone());

        let profiles = self.profiles.unwrap_or_else(|| {
            let ca = self
                .cas
                .get(self.default_ca_id.as_str())
                .expect("default CA must be present in cas");
            ProfileRegistry::empty(ca)
        });

        let nonces = self.nonces.unwrap_or_else(|| Arc::new(NonceBucket::new()));

        let link_headers = self.link_headers.unwrap_or_else(|| {
            let base_url = &self.config.base_url;
            Arc::new(
                self.cas
                    .keys()
                    .map(|id| {
                        let dir_path = format!("/acme/{id}/directory");
                        let val =
                            HeaderValue::from_str(&format!("<{base_url}{dir_path}>;rel=\"index\""))
                                .expect("link header value");
                        (id.clone(), Arc::new(val))
                    })
                    .collect(),
            )
        });

        let crl_caches = self.crl_caches.unwrap_or_else(|| {
            Arc::new(
                self.cas
                    .keys()
                    .map(|id| (id.clone(), CrlCache::default()))
                    .collect(),
            )
        });

        let validation_client = self
            .validation_client
            .unwrap_or_else(default_validation_client);

        Arc::new(AppState {
            config: self.config,
            db: self.db,
            db_ro,
            db_kind: self.db_kind,
            cas: self.cas,
            default_ca_id: self.default_ca_id,
            profiles,
            tls: self.tls,
            spki_cache: self
                .spki_cache
                .unwrap_or_else(|| Arc::new(RwLock::new(HashMap::new()))),
            nonces,
            link_headers,
            validation_client,
            crl_caches,
            gss_cred: self.gss_cred,
            admin_gss_cred: self.admin_gss_cred,
            eab_master_secret: self.eab_master_secret,
            audit: self.audit.unwrap_or_else(|| Arc::new(AuditState::new())),
            audit_policy: self
                .audit_policy
                .unwrap_or_else(|| Arc::new(AuditPolicy::default())),
            journal: self
                .journal
                .unwrap_or_else(|| Arc::new(JournalWriter::with_daemon())),
            admin_sessions: self.admin_sessions,
            admin_auth_limiter: self.admin_auth_limiter,
            eab_session_nonces: self.eab_session_nonces,
            startup_time: self.startup_time.unwrap_or_else(Instant::now),
            crdt: self.crdt.unwrap_or_else(|| {
                Arc::new(tokio::sync::RwLock::new(akamu_crdt::AkaCrdt::default()))
            }),
            node_id: self
                .node_id
                .unwrap_or_else(|| Arc::new("standalone".to_string())),
            node_kem_priv: self.node_kem_priv.unwrap_or_else(|| Arc::new(vec![])),
            node_gossip_signing_priv: self
                .node_gossip_signing_priv
                .unwrap_or_else(|| Arc::new(vec![])),
            node_gossip_signing_cert: self
                .node_gossip_signing_cert
                .unwrap_or_else(|| Arc::new(vec![])),
            gossip_client: self
                .gossip_client
                .unwrap_or_else(|| Arc::new(reqwest::Client::new())),
            gossip_nonce_cache: self.gossip_nonce_cache.unwrap_or_else(|| {
                Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()))
            }),
            write_notify: self
                .write_notify
                .unwrap_or_else(|| Arc::new(tokio::sync::Notify::new())),
            crdt_db,
            tkauth_trust_anchors: self.tkauth_trust_anchors,
            claim_encoder_registry: self.claim_encoder_registry,
            jwks_cache: self.jwks_cache,
            write_coalescer: self.write_coalescer,
        })
    }
}

/// TLS client-auth state available to handlers for introspection.
/// The heavy work (pre-parsed trust anchors via OwnedStore) lives inside
/// `SyntaClientCertVerifier`, which is Arc-d inside the rustls `ServerConfig`.
pub struct TlsState {
    pub client_auth_config: crate::config::ClientAuthConfig,
}

/// Certificate signing backend for a CA.
///
/// Each `[[ca]]` entry uses either a local private key (the default) or
/// delegates signing to an external CA via its REST API.
pub enum SigningBackend {
    /// Local signing using the CA's own private key.
    Local { key: Box<BackendPrivateKey> },
    /// Dogtag PKI remote signing via REST API.
    Dogtag(Arc<crate::ca::dogtag::DogtagSigner>),
}

/// CA key material and issuance policy.
///
/// # Concurrency
///
/// `CaState` is shared across all concurrent axum handler tasks via
/// `Arc<CaState>`. For local signing, `BackendPrivateKey` delegates to the
/// underlying `synta_certificate` backend (OpenSSL / AWS-LC), which serialises
/// concurrent operations internally.
pub struct CaState {
    /// Unique identifier for this CA (matches `CaConfig.id`).
    pub id: String,
    /// Key type string from config, e.g. `"ec:P-256"` or `"rsa:2048"`.
    pub key_type: String,
    /// Signing backend: local key or external CA delegation.
    pub signing: SigningBackend,
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
    /// How long (in seconds) a signed CRL is valid.  Determines the cache TTL.
    pub crl_next_update_secs: u64,
    /// Per-CA CAA identities (falls back to `server.caa_identities` when empty).
    pub caa_identities: Vec<String>,
    /// Per-CA MTC transparency log state.
    pub mtc: Arc<MtcState>,
}

impl CaState {
    /// Returns the local signing key, or `None` for externally-signed CAs.
    pub fn local_key(&self) -> Option<&BackendPrivateKey> {
        match &self.signing {
            SigningBackend::Local { key } => Some(key),
            SigningBackend::Dogtag(_) => None,
        }
    }

    /// Returns `true` when this CA has a local signing key.
    pub fn has_local_key(&self) -> bool {
        self.local_key().is_some()
    }
}

/// Cached account key material stored in `AppState::spki_cache`.
#[derive(Clone)]
pub struct CachedAccount {
    /// DER-encoded SubjectPublicKeyInfo of the account key.
    pub spki_der: Vec<u8>,
    /// RFC 7638 JWK thumbprint (base64url SHA-256 of the canonical JWK).
    pub jwk_thumbprint: String,
    /// Account status string: `"valid"`, `"deactivated"`, or `"revoked"`.
    pub status: String,
}

/// MTC transparency log state for a single CA.
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
    /// How often to produce a checkpoint (seconds).
    pub checkpoint_interval_secs: u64,
    /// Maximum number of checkpoints to retain.
    pub checkpoint_retention_count: u32,
    /// How often to allocate a landmark (seconds).
    pub landmark_interval_secs: u64,
    /// Maximum number of active landmarks to retain.
    pub max_active_landmarks: u32,
    /// Log number for serialNumber encoding (draft-05 §6.1).
    pub log_number: u16,
    /// Minimum valid entry index for Checkpoint (§5.2.3 log pruning).
    pub tree_minimum_index: Option<u64>,
    /// DER-encoded CA TrustAnchorID OID for the mandatory self-cosigner (§5.4).
    /// `None` when the CA does not produce a self-cosignature.
    pub trust_anchor_id_der: Option<Vec<u8>>,
    /// DER-encoded LogID issuer DN for leaf hash computation.
    /// Pre-computed at startup so `append_cert_to_log` can build the same
    /// `TBSCertificateLogEntry` that a verifier will derive from the standalone
    /// cert's TBS.  `None` when MTC signing key is not configured.
    pub logid_issuer_dn_der: Option<Vec<u8>>,
    /// Unix timestamp of the last checkpoint production (for per-CA scheduling).
    pub last_checkpoint: std::sync::atomic::AtomicI64,
    /// Unix timestamp of the last landmark allocation (for per-CA scheduling).
    pub last_landmark: std::sync::atomic::AtomicI64,
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

    /// Unix timestamp of the last checkpoint production.
    pub fn last_checkpoint_at(&self) -> i64 {
        self.last_checkpoint
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Record that a checkpoint was just produced.
    pub fn touch_checkpoint(&self) {
        self.last_checkpoint.store(
            crate::util::unix_now(),
            std::sync::atomic::Ordering::Relaxed,
        );
    }

    /// Unix timestamp of the last landmark allocation.
    pub fn last_landmark_at(&self) -> i64 {
        self.last_landmark
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Record that a landmark was just allocated.
    pub fn touch_landmark(&self) {
        self.last_landmark.store(
            crate::util::unix_now(),
            std::sync::atomic::Ordering::Relaxed,
        );
    }

    /// Build a disabled MTC state (no log, no key, default intervals).
    pub fn disabled() -> Self {
        MtcState {
            log: None,
            algorithm: HashAlgorithm::Sha256,
            signing_key: None,
            signing_hash_alg: "sha256".into(),
            cosigner_clients: vec![],
            _log_lock: None,
            checkpoint_interval_secs: 3600,
            checkpoint_retention_count: 1000,
            landmark_interval_secs: 86400,
            max_active_landmarks: 100,
            log_number: 1,
            tree_minimum_index: None,
            trust_anchor_id_der: None,
            logid_issuer_dn_der: None,
            last_checkpoint: std::sync::atomic::AtomicI64::new(0),
            last_landmark: std::sync::atomic::AtomicI64::new(0),
        }
    }
}

// ── Admin operator session types ──────────────────────────────────────────────

/// Role assigned to an operator account.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperatorRole {
    /// Full administrative access.
    Administrator,
    /// Manages CA operations (issuance, CRL).
    CaOperations,
    /// Registration Authority role (can approve orders).
    CaRa,
    /// Read-only access to audit logs and statistics.
    Auditor,
}

impl std::str::FromStr for OperatorRole {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "administrator" => Ok(OperatorRole::Administrator),
            "ca_operations" => Ok(OperatorRole::CaOperations),
            "ca_ra" => Ok(OperatorRole::CaRa),
            "auditor" => Ok(OperatorRole::Auditor),
            _ => Err(format!("unknown operator role: {s:?}")),
        }
    }
}

impl OperatorRole {
    /// Return the canonical lowercase string representation of the role.
    pub fn as_str(self) -> &'static str {
        match self {
            OperatorRole::Administrator => "administrator",
            OperatorRole::CaOperations => "ca_operations",
            OperatorRole::CaRa => "ca_ra",
            OperatorRole::Auditor => "auditor",
        }
    }
}

impl std::fmt::Display for OperatorRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// How the operator authenticated for this session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdminAuthMethod {
    /// Authenticated via an mTLS client certificate.
    Cert,
    /// Authenticated via a proxy-forwarded client certificate header.
    CertProxy,
    /// Authenticated via GSSAPI/SPNEGO (Kerberos).
    Gssapi,
    /// Authenticated via EAB kid + HMAC-SHA256 signature (web UI secondary login).
    Eab,
}

impl AdminAuthMethod {
    pub fn as_str(self) -> &'static str {
        match self {
            AdminAuthMethod::Cert => "cert",
            AdminAuthMethod::CertProxy => "cert-proxy",
            AdminAuthMethod::Gssapi => "gssapi",
            AdminAuthMethod::Eab => "eab",
        }
    }
}

impl std::fmt::Display for AdminAuthMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// An active admin operator session stored in `AppState::admin_sessions`.
///
/// The operator name is held in a [`akamu_util::SecretBuffer`] that zeroes
/// memory on drop via `OPENSSL_cleanse`, satisfying FDP_RIP.1.
pub struct AdminSession {
    pub operator_id: i64,
    pub name: akamu_util::SecretBuffer,
    pub role: OperatorRole,
    /// CA scope for `ca_ra` (required) and `ca_operations` (optional) operators.
    /// Empty string means server-wide access (administrator, auditor, unscoped ca_operations).
    pub ca_id: String,
    /// When this session token was issued.
    pub created_at: Instant,
    /// Updated on every authenticated request; TTL is measured from this.
    pub last_active_at: Instant,
    pub auth_method: AdminAuthMethod,
}
