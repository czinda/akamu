//! ACME server binary entry point.
//!
//! Usage: `acme-server [/path/to/config.toml]`
//! Defaults to `config.toml` in the current working directory.

use std::sync::Arc;

use tracing_subscriber::EnvFilter;

use acme_server::config::Config;
use acme_server::state::{AppState, CaState, MtcState};
use acme_server::{ca, db, mtc, routes};

#[tokio::main]
async fn main() {
    // ── Logging ───────────────────────────────────────────────────────────────
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    if let Err(e) = run().await {
        tracing::error!("fatal: {e}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), String> {
    // ── Configuration ─────────────────────────────────────────────────────────
    let config_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "config.toml".to_string());

    tracing::info!("loading config from '{config_path}'");
    let config = Config::from_file(&config_path)?;
    let config = Arc::new(config);

    // ── Database ──────────────────────────────────────────────────────────────
    tracing::info!("opening database '{}'", config.database.path);
    let db = db::open(&config.database.path)
        .await
        .map_err(|e| format!("database init: {e}"))?;
    let db = Arc::new(db);

    // Sweep nonces older than 24 h at startup (best-effort).
    let _ = db::nonces::sweep_expired(&db, 86400).await;

    // ── CA key and certificate ────────────────────────────────────────────────
    tracing::info!("loading CA from '{}'", config.ca.key_file);
    let (ca_key, ca_cert_der) =
        ca::init::load_or_generate(&config.ca).map_err(|e| format!("CA init: {e}"))?;

    let ca = Arc::new(CaState {
        key: ca_key,
        cert_der: ca_cert_der,
        hash_alg: config.ca.hash_alg.clone(),
        validity_days: config.ca.validity_days,
        crl_url: config.ca.crl_url.clone(),
        ocsp_url: config.ca.ocsp_url.clone(),
    });

    // ── MTC transparency log ──────────────────────────────────────────────────
    let mtc_algorithm = synta_mtc::crypto::HashAlgorithm::Sha256;
    let mtc = if config.mtc.enabled {
        tracing::info!("opening MTC log at '{}'", config.mtc.log_path);
        let log = mtc::log::open_or_create(&config.mtc.log_path, mtc_algorithm)
            .map_err(|e| format!("MTC log init: {e}"))?;
        let shared = Arc::new(tokio::sync::Mutex::new(log));
        Arc::new(MtcState {
            log: Some(shared),
            algorithm: mtc_algorithm,
        })
    } else {
        tracing::info!("MTC logging disabled");
        Arc::new(MtcState {
            log: None,
            algorithm: mtc_algorithm,
        })
    };

    // ── Application state ─────────────────────────────────────────────────────
    let state = Arc::new(AppState {
        config: Arc::clone(&config),
        db: Arc::clone(&db),
        ca,
        mtc,
    });

    // ── HTTP server ───────────────────────────────────────────────────────────
    let router = routes::build_router(Arc::clone(&state));

    let listener = tokio::net::TcpListener::bind(&config.listen_addr)
        .await
        .map_err(|e| format!("bind '{}': {e}", config.listen_addr))?;

    tracing::info!(
        "ACME server listening on {} (base_url={})",
        config.listen_addr,
        config.base_url
    );

    axum::serve(listener, router)
        .await
        .map_err(|e| format!("server error: {e}"))?;

    Ok(())
}
