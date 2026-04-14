//! ACME server binary entry point.
//!
//! Usage: `akamu [/path/to/config.toml]`
//! Defaults to `config.toml` in the current working directory.

use std::sync::Arc;

use tracing_subscriber::EnvFilter;

use akamu::config::Config;
use akamu::state::{AppState, CaState, MtcState, NonceBucket, TlsState};
use akamu::{ca, db, mtc, routes, star};

use http_body_util::Empty;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;

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

    // CA/B Forum BR §7.1.3.2.1: SHA-1 prohibited in certificate/CRL signatures since 2026-09-15.
    {
        let alg = config.ca.hash_alg.to_lowercase();
        if alg == "sha1" || alg == "sha-1" {
            return Err(format!(
                "ca.hash_alg='{}' is prohibited by CA/B Forum BR §7.1.3.2.1 \
                 (SHA-1 sunset 2026-09-15); use 'sha256', 'sha384', or 'sha512'",
                config.ca.hash_alg
            ));
        }
    }

    // CA/B Forum BR §6.3.2 validity caps: 200 days since 2026-03-15, 100 from 2027-03-15.
    if config.ca.validity_days > 200 {
        tracing::warn!(
            "ca.validity_days={} exceeds the 200-day CA/B Forum BR limit (§6.3.2, since 2026-03-15); \
             certificates issued by this CA cannot be used in public WebPKI chains",
            config.ca.validity_days
        );
    } else if config.ca.validity_days > 100 {
        tracing::warn!(
            "ca.validity_days={} will exceed the upcoming 100-day CA/B Forum BR limit \
             (§6.3.2, from 2027-03-15)",
            config.ca.validity_days
        );
    }

    let config = Arc::new(config);

    // ── Database ──────────────────────────────────────────────────────────────
    db::install_drivers();
    let db_kind = db::DbKind::from_url(&config.database.url);
    let max_connections = config.database.max_connections.unwrap_or(match db_kind {
        db::DbKind::Sqlite => 1,
        _ => 10,
    });
    let migrations_dir = match db_kind {
        db::DbKind::Sqlite => "migrations/sqlite",
        db::DbKind::Postgres => "migrations/postgres",
        db::DbKind::MariaDb => "migrations/mariadb",
    };
    tracing::info!("opening database '{}'", config.database.url);
    let db = db::open(&config.database.url, max_connections, migrations_dir)
        .await
        .map_err(|e| format!("database init: {e}"))?;

    // Sweep DB nonces older than 24 h at startup (best-effort; handles any
    // nonces written by a previous process that used the DB-backed store).
    let _ = db::nonces::sweep_expired(&db, 86400).await;

    // Seed EAB keys from config into the DB (INSERT OR IGNORE — never overwrites
    // keys that were provisioned or consumed by the runtime admin endpoint).
    let now_ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    for (kid, hmac_key_b64u) in &config.server.eab_keys {
        if let Err(e) = db::eab::insert_if_absent(&db, kid, hmac_key_b64u, now_ts).await {
            tracing::warn!("failed to seed EAB key '{kid}': {e}");
        }
    }
    if !config.server.eab_keys.is_empty() {
        tracing::info!(
            "seeded {} EAB key(s) from config",
            config.server.eab_keys.len()
        );
    }

    // ── CA key and certificate ────────────────────────────────────────────────
    tracing::info!("loading CA from '{}'", config.ca.key_file);
    let (ca_key, ca_cert_der) =
        ca::init::load_or_generate(&config.ca).map_err(|e| format!("CA init: {e}"))?;

    let ca_spki_der = ca_key
        .public_key()
        .map_err(|e| format!("CA public key: {e}"))?
        .spki_der()
        .to_vec();
    let ca_aki_bytes = ca::init::compute_aki_from_spki(&ca_spki_der).unwrap_or_default();

    let ca = Arc::new(CaState {
        key: ca_key,
        cert_der: ca_cert_der,
        hash_alg: config.ca.hash_alg.clone(),
        validity_days: config.ca.validity_days,
        crl_url: config.ca.crl_url.clone(),
        ocsp_url: config.ca.ocsp_url.clone(),
        aki_bytes: ca_aki_bytes,
    });

    // ── Certificate profile registry ──────────────────────────────────────────
    let profile_registry = if config.profiles.providers.is_empty() {
        tracing::info!("profiles: no providers configured; using CA defaults for all orders");
        akamu::profiles::ProfileRegistry::empty(&ca)
    } else {
        tracing::info!(
            "profiles: loading from {} provider(s)",
            config.profiles.providers.len()
        );
        akamu::profiles::ProfileRegistry::new(&config.profiles, &ca)
            .await
            .map_err(|e| format!("profile registry init: {e}"))?
    };

    // ── TLS bootstrap (auto-generate cert/key if absent) ─────────────────────
    if config.tls.enabled {
        akamu::tls::init::load_or_generate(&config.tls, &ca)
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
    let nonces = Arc::new(NonceBucket::new());
    let state = Arc::new(AppState {
        config: Arc::clone(&config),
        db: db.clone(),
        db_kind,
        ca,
        mtc,
        profiles: profile_registry.clone(),
        tls: tls_state,
        spki_cache: Arc::new(std::sync::RwLock::new(std::collections::HashMap::new())),
        nonces: Arc::clone(&nonces),
        link_header: Arc::new(
            axum::http::HeaderValue::from_str(&format!(
                "<{}/acme/directory>;rel=\"index\"",
                config.base_url
            ))
            .expect("base_url produces a valid Link header value"),
        ),
        validation_client: Client::builder(TokioExecutor::new())
            .build_http::<Empty<hyper::body::Bytes>>(),
    });

    // Spawn background profile refresh task (no-op when no providers configured).
    profile_registry.spawn_refresh_task();

    // Periodically sweep expired in-memory nonces (every 15 minutes, 24 h TTL).
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(900));
        interval.tick().await; // skip immediate first tick
        loop {
            interval.tick().await;
            nonces.sweep_expired(86400);
        }
    });

    // ── STAR background reissuance task ──────────────────────────────────────
    let _star_task = star::spawn(Arc::clone(&state));

    // ── HTTP / TLS server ─────────────────────────────────────────────────────
    let router = routes::build_router(Arc::clone(&state));

    if config.tls.enabled {
        let mut server_cfg = akamu::tls::build_rustls_server_config(&config.tls)
            .map_err(|e| format!("TLS config: {e}"))?;
        server_cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_cfg));
        let addr: std::net::SocketAddr = config
            .listen_addr
            .parse()
            .map_err(|e| format!("parse listen addr '{}': {e}", config.listen_addr))?;
        let listener = tokio::net::TcpListener::bind(addr)
            .await
            .map_err(|e| format!("bind '{}': {e}", config.listen_addr))?;
        tracing::info!(
            "ACME server listening on {} with TLS (base_url={})",
            config.listen_addr,
            config.base_url
        );
        loop {
            let (stream, _) = listener
                .accept()
                .await
                .map_err(|e| format!("accept: {e}"))?;
            let acceptor = acceptor.clone();
            let router = router.clone();
            tokio::spawn(async move {
                let tls = match acceptor.accept(stream).await {
                    Ok(s) => s,
                    Err(e) => {
                        tracing::warn!("TLS handshake failed: {e}");
                        return;
                    }
                };
                let io = hyper_util::rt::TokioIo::new(tls);
                use tower::ServiceExt as _;
                let svc = hyper::service::service_fn(
                    move |req: hyper::Request<hyper::body::Incoming>| {
                        let router = router.clone();
                        async move {
                            let req = req.map(axum::body::Body::new);
                            Ok::<_, std::convert::Infallible>(router.oneshot(req).await.unwrap())
                        }
                    },
                );
                if let Err(e) = hyper_util::server::conn::auto::Builder::new(
                    hyper_util::rt::TokioExecutor::new(),
                )
                .serve_connection(io, svc)
                .await
                {
                    tracing::warn!("TLS connection error: {e}");
                }
            });
        }
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
