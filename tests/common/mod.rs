//! Shared helpers for integration tests.
//!
//! All helpers require `--features test-utils`.
// Each integration test binary includes this module via `mod common;` but only
// uses a subset of its items.  `dead_code` is expected and harmless here.

#![cfg(feature = "test-utils")]
#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use axum::extract::Path;
use axum::routing::get;
use axum::Router;
use synta_certificate::BackendPrivateKey;
use synta_mtc::crypto::HashAlgorithm;
use tokio::net::TcpListener;

use akamu::config::{
    CaConfig, Config, DatabaseConfig, MtcConfig, MtcSigningKeyConfig, ServerConfig,
};
use akamu::mtc::log;
use akamu::state::{AppState, AppStateBuilder, CaState, MtcState};
use akamu::{ca, db};

// ── Port helpers ─────────────────────────────────────────────────────────────

/// Bind an ephemeral TCP port and return the port number and std listener.
pub fn bind_free_port() -> (u16, std::net::TcpListener) {
    let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind to port 0");
    l.set_nonblocking(true).expect("set_nonblocking");
    let port = l.local_addr().expect("local_addr").port();
    (port, l)
}

/// Bind an ephemeral TCP port and return the port and a tokio [`TcpListener`].
pub fn bind_ephemeral() -> (u16, TcpListener) {
    let (port, std_l) = bind_free_port();
    let tokio_l = TcpListener::from_std(std_l).expect("tokio TcpListener from std");
    (port, tokio_l)
}

// ── HTTP-01 challenge solver ─────────────────────────────────────────────────

pub type TokenStore = Arc<RwLock<HashMap<String, String>>>;

/// Start a minimal HTTP-01 challenge responder on `std_listener`.
///
/// Returns the token store: insert `(token, key_authorization)` pairs to
/// make them serveable at `GET /.well-known/acme-challenge/{token}`.
pub async fn start_http01_solver(std_listener: std::net::TcpListener) -> TokenStore {
    let store: TokenStore = Arc::new(RwLock::new(HashMap::new()));
    let store_clone = Arc::clone(&store);

    let app = Router::new().route(
        "/.well-known/acme-challenge/{token}",
        get(move |Path(token): Path<String>| {
            let s = Arc::clone(&store_clone);
            async move { s.read().unwrap().get(&token).cloned().unwrap_or_default() }
        }),
    );

    let listener = TcpListener::from_std(std_listener).expect("tokio TcpListener from std");
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    store
}

// ── MTC test state builder ──────────────────────────────────────────────────

/// Build an `AppState` with a minimal single-CA, in-memory SQLite config
/// suitable for MTC integration tests.
///
/// Creates an Ed25519 MTC signing key and an EC P-256 CA key inside `dir`.
pub async fn build_test_state(dir: &std::path::Path, base_url: &str) -> Arc<AppState> {
    let mtc_log_path = dir.join("mtc.log").to_string_lossy().into_owned();
    let mtc_key_file = dir.join("mtc.key").to_string_lossy().into_owned();

    let config = Arc::new(Config {
        listen_addr: "127.0.0.1:0".into(),
        base_url: base_url.into(),
        database: DatabaseConfig {
            url: "sqlite::memory:".into(),
            max_connections: None,
            require_tls: false,
        },
        cas: vec![CaConfig {
            id: "default".to_owned(),
            is_default: true,
            caa_identities: vec![],
            key_file: Some(dir.join("ca.key").to_string_lossy().into_owned()),
            cert_file: dir.join("ca.crt").to_string_lossy().into_owned(),
            key_type: "ec:P-256".into(),
            hash_alg: "sha256".into(),
            validity_days: 90,
            crl_url: None,
            ocsp_url: None,
            common_name: "Test CA".into(),
            organization: "Test".into(),
            ca_validity_years: 10,
            crl_next_update_secs: 86400,
            enforce_validity_cap: false,
            require_encrypted_key: false,
            key_password_file: None,
            mtc: None,
            default_linter: None,
            signer: None,
        }],
        mtc: Some(MtcConfig {
            log_path: mtc_log_path.clone(),
            enabled: true,
            signing_key: Some(MtcSigningKeyConfig {
                key_file: mtc_key_file.clone(),
                key_type: "ed25519".into(),
                hash_alg: "sha256".into(),
            }),
            checkpoint_interval_secs: 3600,
            cosigners: vec![],
            landmark_interval_secs: 86400,
            max_active_landmarks: 100,
            checkpoint_retention_count: 1000,
            hash_alg: "sha256".into(),
            log_number: 1,
            tree_minimum_index: None,
            trust_anchor_id: Some("32473.2".into()),
            contact: None,
        }),
        server: ServerConfig::default(),
        tls: Default::default(),
        profiles: Default::default(),
        linter: Default::default(),
        admin: None,
        email_challenge: None,
        delegation_upstream: None,
        gossip: None,
        crdt_db_url: None,
        tkauth: None,
    });

    let (ca_key, ca_cert_der) = ca::init::load_or_generate(config.default_ca()).unwrap();
    let ca_spki_der = ca_key.public_key().unwrap().spki_der().to_vec();
    let ca_aki_bytes = ca::init::compute_aki_from_spki(&ca_spki_der).unwrap_or_default();

    db::install_drivers();
    let db_conn = db::open("sqlite::memory:", 1, false).await.unwrap();

    let mtc_key = BackendPrivateKey::generate_ed25519().unwrap();
    let mtc_key_pem = mtc_key.to_pem(None).unwrap();
    std::fs::write(&mtc_key_file, &mtc_key_pem).unwrap();

    let raw_log = log::open_or_create(&mtc_log_path, HashAlgorithm::Sha256).unwrap();
    let shared_log = Arc::new(tokio::sync::Mutex::new(raw_log));

    let ca = Arc::new(CaState {
        id: "default".into(),
        key_type: "ec:P-256".into(),
        crl_next_update_secs: 86400,
        signing: akamu::state::SigningBackend::Local {
            key: Box::new(ca_key),
        },
        cert_der: ca_cert_der,
        hash_alg: "sha256".into(),
        validity_days: 90,
        crl_url: None,
        ocsp_url: None,
        aki_bytes: ca_aki_bytes,
        enforce_validity_cap: false,
        caa_identities: vec![],
        mtc: Arc::new(MtcState {
            log: Some(shared_log),
            algorithm: HashAlgorithm::Sha256,
            signing_key: Some(mtc_key),
            signing_hash_alg: "sha256".into(),
            cosigner_clients: vec![],
            _log_lock: None,
            checkpoint_interval_secs: 3600,
            checkpoint_retention_count: 1000,
            landmark_interval_secs: 86400,
            max_active_landmarks: 100,
            last_checkpoint: std::sync::atomic::AtomicI64::new(0),
            last_landmark: std::sync::atomic::AtomicI64::new(0),
            log_number: 1,
            tree_minimum_index: None,
            trust_anchor_id_der: None,
            trust_anchor_id: Some("32473.2".into()),
            contact: None,
            tlog_origin: Some("oid/1.3.6.1.4.1.32473.2.0.1".into()),
            cosigner_name: Some("oid/1.3.6.1.4.1.32473.2".into()),
            logid_issuer_dn_der: None,
        }),
        default_linter: None,
        cached_der: std::sync::OnceLock::new(),
        lint_store: std::sync::OnceLock::new(),
    });

    let cas = {
        let mut ca_map = indexmap::IndexMap::new();
        ca_map.insert("default".to_string(), ca.clone());
        Arc::new(ca_map)
    };

    AppStateBuilder::new(
        Arc::clone(&config),
        db_conn.clone(),
        db::DbKind::Sqlite,
        cas,
        Arc::new("default".to_string()),
    )
    .node_id(Arc::new("test".to_string()))
    .build()
}
