//! ACME server binary entry point.
//!
//! Usage: `acme-server [/path/to/config.toml]`
//! Defaults to `config.toml` in the current working directory.

use std::sync::Arc;

use tracing_subscriber::EnvFilter;

use acme_server::config::Config;
use acme_server::state::{AppState, CaState, MtcState, TlsState};
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

    // ── TLS bootstrap (auto-generate cert/key if absent) ─────────────────────
    if config.tls.enabled {
        acme_server::tls::init::load_or_generate(&config.tls, &ca)
            .map_err(|e| format!("TLS init: {e}"))?;
    }

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

    // ── TLS state (lean; heavy OwnedStore lives inside SyntaClientCertVerifier) ─
    let tls_state = if config.tls.enabled {
        config.tls.client_auth.as_ref().map(|client_auth| {
            Arc::new(TlsState {
                client_auth_config: client_auth.clone(),
            })
        })
    } else {
        None
    };

    // ── Application state ─────────────────────────────────────────────────────
    let state = Arc::new(AppState {
        config: Arc::clone(&config),
        db: Arc::clone(&db),
        ca,
        mtc,
        tls: tls_state,
    });

    // ── HTTP / TLS server ─────────────────────────────────────────────────────
    let router = routes::build_router(Arc::clone(&state));

    if config.tls.enabled {
        tracing::info!(
            "ACME server listening on {} with TLS (base_url={})",
            config.listen_addr,
            config.base_url
        );
        let server_cfg = acme_server::tls::build_rustls_server_config(&config.tls)
            .map_err(|e| format!("TLS config: {e}"))?;
        let rustls_config =
            axum_server::tls_rustls::RustlsConfig::from_config(Arc::new(server_cfg));
        let addr: std::net::SocketAddr = config
            .listen_addr
            .parse()
            .map_err(|e| format!("parse listen addr '{}': {e}", config.listen_addr))?;
        axum_server::bind_rustls(addr, rustls_config)
            .serve(
                router.into_make_service_with_connect_info::<std::net::SocketAddr>(),
            )
            .await
            .map_err(|e| format!("server error: {e}"))?;
    } else {
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
    }

    Ok(())
}
