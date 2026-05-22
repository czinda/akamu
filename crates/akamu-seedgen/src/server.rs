//! In-process Akamu server setup for the seed-data generator.
//!
//! Mirrors the pattern from `benches/acme_bench.rs`: one `AppState`, one Axum
//! router, one TCP listener — but extended to support multiple CAs.

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, RwLock};
use std::time::Instant;

use indexmap::IndexMap;

use akamu::{
    audit::{AuditPolicy, AuditState},
    ca::init::{compute_aki_from_spki, load_or_generate},
    config::{CaConfig, Config, DatabaseConfig, MtcConfig, ServerConfig},
    db,
    profiles::ProfileRegistry,
    routes,
    state::{AppState, CaState, MtcState, NonceBucket},
};
use akamu_crdt::AkaCrdt;

use crate::spec::CaSpec;

/// Handle to the running in-process server.
pub struct SeedServer {
    /// Base URL, e.g. `http://127.0.0.1:PORT`.
    pub base_url: String,
    /// Port the HTTP-01 challenge responder is listening on (from `ChallengeResponder`).
    pub challenge_port: u16,
    /// Read/write database pool — used for post-processing.
    pub db: akamu::db::Db,
    /// Shared application state (exposes profile registry, cas, etc.).
    pub state: Arc<AppState>,
    /// Handle to the Axum serve task; kept alive so panics are not silently dropped.
    pub server_task: tokio::task::JoinHandle<()>,
}

/// Start an in-process Akamu server from the given CA specs.
///
/// `challenge_port` is the port of the already-started `ChallengeResponder`.
/// `artifacts_dir` is the directory where CA key and certificate PEM files are
/// written. It must already exist when this function is called.
/// `db_url` is the SQLite URL to use for the database (e.g. `sqlite:/tmp/out.sqlite3`).
pub async fn start(
    ca_specs: &[CaSpec],
    challenge_port: u16,
    artifacts_dir: &Path,
    db_url: &str,
) -> SeedServer {
    // Build CaConfig entries from specs (one per CA subdirectory).
    let ca_configs: Vec<CaConfig> = ca_specs
        .iter()
        .map(|s| {
            let ca_dir = artifacts_dir.join(format!("ca-{}", s.id));
            std::fs::create_dir_all(&ca_dir).expect("create CA subdir");
            CaConfig {
                id: s.id.clone(),
                is_default: s.is_default,
                caa_identities: vec![],
                key_file: ca_dir.join("ca.key").to_string_lossy().into_owned(),
                cert_file: ca_dir.join("ca.crt").to_string_lossy().into_owned(),
                key_type: s.key_type.clone(),
                hash_alg: s.hash_alg.clone(),
                validity_days: s.validity_days,
                crl_url: None,
                ocsp_url: None,
                common_name: s.common_name.clone(),
                organization: s.organization.clone(),
                ca_validity_years: s.ca_validity_years,
                crl_next_update_secs: 86400,
                enforce_validity_cap: false,
                require_encrypted_key: false,
                key_password_file: None,
            }
        })
        .collect();

    // Bind the ACME listener first so we know the port.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("ACME listener bind");
    listener.set_nonblocking(true).expect("set_nonblocking");
    let addr = listener.local_addr().expect("ACME listener addr");
    let base_url = format!("http://127.0.0.1:{}", addr.port());

    let config = Arc::new(Config {
        listen_addr: addr.to_string(),
        base_url: base_url.clone(),
        database: DatabaseConfig {
            url: "sqlite::memory:".to_string(),
            max_connections: None,
            require_tls: false,
        },
        cas: ca_configs.clone(),
        mtc: MtcConfig {
            log_path: "/dev/null".into(),
            enabled: false,
            signing_key: None,
            checkpoint_interval_secs: 3600,
            cosigners: vec![],
            landmark_interval_secs: 86400,
            max_active_landmarks: 100,
            checkpoint_retention_count: 1000,
            hash_alg: "sha256".to_string(),
        },
        server: ServerConfig {
            http_validation_port: challenge_port,
            http_validation_allow_private_ips: true,
            ..ServerConfig::default()
        },
        tls: Default::default(),
        profiles: Default::default(),
        admin: None,
        email_challenge: None,
        delegation_upstream: None,
        tkauth: None,
        gossip: None,
        crdt_db_url: None,
    });

    // Open the database.
    db::install_drivers();
    let pool = db::open(db_url, 1, false).await.expect("open database");

    // Initialise CAs: generate key + self-signed cert for each.
    let mut cas_map: IndexMap<String, Arc<CaState>> = IndexMap::new();
    let mut default_ca_id = String::new();

    for (cfg, spec) in ca_configs.iter().zip(ca_specs.iter()) {
        let cfg_clone = cfg.clone();
        let spec_id = spec.id.clone();
        let (key, cert_der) = tokio::task::spawn_blocking(move || {
            load_or_generate(&cfg_clone).unwrap_or_else(|e| panic!("CA init '{spec_id}': {e}"))
        })
        .await
        .unwrap_or_else(|e| panic!("CA init task panicked: {e}"));
        let spki_der = key.public_key().expect("CA public key").spki_der().to_vec();
        let aki_bytes = compute_aki_from_spki(&spki_der)
            .unwrap_or_else(|| panic!("CA '{}': failed to compute AKI from SPKI", spec.id));

        let ca = Arc::new(CaState {
            id: spec.id.clone(),
            key_type: spec.key_type.clone(),
            key,
            cert_der,
            hash_alg: spec.hash_alg.clone(),
            validity_days: spec.validity_days,
            crl_url: None,
            ocsp_url: None,
            aki_bytes,
            enforce_validity_cap: false,
            crl_next_update_secs: 86400,
            caa_identities: vec![],
        });

        if spec.is_default {
            default_ca_id = spec.id.clone();
        }
        cas_map.insert(spec.id.clone(), ca);
    }

    let cas = Arc::new(cas_map);

    // Build per-CA CRL caches and Link headers.
    let crl_caches = Arc::new(
        cas.keys()
            .map(|id| (id.clone(), akamu::state::CrlCache::default()))
            .collect::<HashMap<String, _>>(),
    );
    let link_headers = Arc::new(
        cas.keys()
            .map(|id| {
                // Non-default CAs use /acme/{id}/directory; the default CA uses /acme/directory
                // (backward-compat alias) but also has its own per-CA path.
                let dir_path = format!("/acme/{id}/directory");
                let val = axum::http::HeaderValue::from_str(&format!(
                    "<{base_url}{dir_path}>;rel=\"index\""
                ))
                .expect("link header value");
                (id.clone(), Arc::new(val))
            })
            .collect::<HashMap<String, _>>(),
    );

    // Build the profile registry from the default CA (profiles are added later via setup.rs).
    let default_ca = cas.get(&default_ca_id).expect("default CA in cas map");
    let profiles = ProfileRegistry::empty(default_ca);

    // Build the HTTPS validation client for http-01.
    let validation_client = {
        let https = hyper_rustls::HttpsConnectorBuilder::new()
            .with_native_roots()
            .expect("native roots")
            .https_or_http()
            .enable_http1()
            .build();
        hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
            .build(https)
    };

    let state = Arc::new(AppState {
        config: Arc::clone(&config),
        db: pool.clone(),
        db_ro: pool.clone(),
        db_kind: db::DbKind::Sqlite,
        cas: Arc::clone(&cas),
        default_ca_id: Arc::new(default_ca_id),
        profiles,
        mtc: Arc::new(MtcState {
            log: None,
            algorithm: synta_mtc::crypto::HashAlgorithm::Sha256,
            signing_key: None,
            signing_hash_alg: "sha256".into(),
            cosigner_clients: vec![],
            _log_lock: None,
        }),
        tls: None,
        crl_caches,
        spki_cache: Arc::new(RwLock::new(HashMap::new())),
        nonces: Arc::new(NonceBucket::new()),
        link_headers,
        validation_client,
        gss_cred: None,
        eab_master_secret: None,
        audit: Arc::new(AuditState::new()),
        audit_policy: Arc::new(AuditPolicy::default()),
        admin_sessions: None,
        admin_auth_limiter: None,
        eab_session_nonces: None,
        admin_gss_cred: None,
        startup_time: Instant::now(),
        crdt: Arc::new(tokio::sync::RwLock::new(AkaCrdt::default())),
        node_id: Arc::new("seedgen".to_string()),
        node_kem_priv: Arc::new(vec![]),
        node_gossip_signing_priv: Arc::new(vec![]),
        node_gossip_signing_cert: Arc::new(vec![]),
        gossip_client: Arc::new(reqwest::Client::new()),
        gossip_nonce_cache: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
        write_notify: Arc::new(tokio::sync::Notify::new()),
        crdt_db: pool.clone(),
        tkauth_trust_anchors: None,
    });

    let router = routes::build_router(Arc::clone(&state), None);
    let tokio_listener = tokio::net::TcpListener::from_std(listener).expect("tokio listener");
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel::<()>();
    // Store the JoinHandle so panics inside the server task propagate rather than
    // being silently discarded when the handle is dropped.
    let server_task = tokio::spawn(async move {
        // The TcpListener is already bound and in the OS backlog, so connections
        // queued between this signal and the first axum::serve accept() are buffered.
        // Signal BEFORE axum::serve so ready_rx.await can complete — axum::serve
        // only returns after graceful shutdown.
        let _ = ready_tx.send(());
        if let Err(e) = axum::serve(tokio_listener, router).await {
            tracing::error!("in-process ACME server exited with error: {e}");
        }
    });
    // Wait until the server task has started and signalled readiness.
    // If the task exits before signalling, this returns Err — treat it as a fatal startup failure.
    ready_rx
        .await
        .expect("ACME server task exited before signalling readiness");

    SeedServer {
        base_url,
        challenge_port,
        db: pool,
        state,
        server_task,
    }
}
