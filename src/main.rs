//! ACME server binary entry point.
//!
//! Usage: `akamu [/path/to/config.toml]`
//! Defaults to `config.toml` in the current working directory.

use std::sync::Arc;

use tracing_subscriber::EnvFilter;

use akamu::audit::AuditState;
use akamu::config::{Config, MtcSigningKeyConfig};
use akamu::state::{AppState, CaState, CrlCache, MtcState, NonceBucket, TlsState};
use akamu::{ca, db, delegation_upstream, mtc, routes, star};
use indexmap::IndexMap;

use hyper_rustls::HttpsConnectorBuilder;
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

/// Load or auto-generate the dedicated MTC signing key.
///
/// Reuses `generate_backend_key` and `BackendPrivateKey::from_pem` from the CA
/// key loading path.  The file is created with the same PEM format.
fn load_or_generate_mtc_key(
    cfg: &MtcSigningKeyConfig,
) -> Result<synta_certificate::BackendPrivateKey, String> {
    use std::path::Path;
    use synta_certificate::BackendPrivateKey;

    if Path::new(&cfg.key_file).exists() {
        let pem = std::fs::read(&cfg.key_file)
            .map_err(|e| format!("read MTC signing key '{}': {e}", cfg.key_file))?;
        BackendPrivateKey::from_pem(&pem, None)
            .map_err(|e| format!("parse MTC signing key '{}': {e}", cfg.key_file))
    } else {
        tracing::info!(
            "generating new MTC signing key ({}) → {}",
            cfg.key_type,
            cfg.key_file
        );
        let key = ca::init::generate_backend_key(&cfg.key_type)
            .map_err(|e| format!("generate MTC signing key: {e}"))?;
        let pem = key
            .to_pem(None)
            .map_err(|e| format!("MTC signing key to PEM: {e}"))?;
        akamu::util::write_key_file(&cfg.key_file, &pem)
            .map_err(|e| format!("write MTC signing key '{}': {e}", cfg.key_file))?;
        Ok(key)
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
    // CA/B Forum BR §6.3.2 validity caps: 200 days since 2026-03-15, 100 from 2027-03-15.
    for ca_cfg in &config.cas {
        let alg = ca_cfg.hash_alg.to_lowercase();
        if alg == "sha1" || alg == "sha-1" {
            return Err(format!(
                "ca[{}].hash_alg='{}' is prohibited by CA/B Forum BR §7.1.3.2.1 \
                 (SHA-1 sunset 2026-09-15); use 'sha256', 'sha384', or 'sha512'",
                ca_cfg.id, ca_cfg.hash_alg
            ));
        }
        if ca_cfg.validity_days > 200 {
            tracing::warn!(
                "ca[{}].validity_days={} exceeds the 200-day CA/B Forum BR limit \
                 (§6.3.2, since 2026-03-15); certificates issued by this CA cannot \
                 be used in public WebPKI chains",
                ca_cfg.id,
                ca_cfg.validity_days
            );
        } else if ca_cfg.validity_days > 100 {
            tracing::warn!(
                "ca[{}].validity_days={} will exceed the upcoming 100-day CA/B Forum \
                 BR limit (§6.3.2, from 2027-03-15)",
                ca_cfg.id,
                ca_cfg.validity_days
            );
        }
    }

    if config.server.account_scope == "ca" {
        return Err("server.account_scope = \"ca\" is not yet supported; \
             remove the setting or set it to \"server\" to start the server."
            .to_string());
    }

    let config = Arc::new(config);

    // ── Database ──────────────────────────────────────────────────────────────
    db::install_drivers();
    let db_kind = db::DbKind::from_url(&config.database.url);
    let max_connections = config.database.max_connections.unwrap_or(match db_kind {
        db::DbKind::Sqlite => 1,
        _ => 10,
    });
    tracing::info!("opening database '{}'", config.database.url);
    let db = db::open(
        &config.database.url,
        max_connections,
        config.database.require_tls,
    )
    .await
    .map_err(|e| format!("database init: {e}"))?;

    let db_ro = match db::open_ro(&config.database.url, 4)
        .await
        .map_err(|e| format!("read-only database pool: {e}"))?
    {
        Some(ro) => {
            tracing::info!("opened read-only pool (4 connections)");
            ro
        }
        None => db.clone(),
    };

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

    // ── CA keys and certificates (one per [[ca]] entry) ───────────────────────
    let mut cas_map: IndexMap<String, Arc<CaState>> = IndexMap::new();
    let mut crl_caches_map: std::collections::HashMap<String, CrlCache> =
        std::collections::HashMap::new();

    for ca_cfg in &config.cas {
        tracing::info!("loading CA '{}' from '{}'", ca_cfg.id, ca_cfg.key_file);
        let (ca_key, ca_cert_der) = ca::init::load_or_generate(ca_cfg)
            .map_err(|e| format!("CA '{}' init: {e}", ca_cfg.id))?;

        let ca_spki_der = ca_key
            .public_key()
            .map_err(|e| format!("CA '{}' public key: {e}", ca_cfg.id))?
            .spki_der()
            .to_vec();
        let ca_aki_bytes = ca::init::compute_aki_from_spki(&ca_spki_der).ok_or_else(|| {
            format!(
                "CA '{}': cannot compute Authority Key Identifier from SPKI",
                ca_cfg.id
            )
        })?;

        // Derive CRL/OCSP URLs if not set explicitly in config.
        let crl_url = ca_cfg.crl_url.clone().or_else(|| {
            if ca_cfg.is_default {
                Some(format!("{}/ca/crl", config.base_url))
            } else {
                Some(format!("{}/ca/{}/crl", config.base_url, ca_cfg.id))
            }
        });
        let ocsp_url = ca_cfg.ocsp_url.clone().or_else(|| {
            if ca_cfg.is_default {
                Some(format!("{}/ca/ocsp", config.base_url))
            } else {
                Some(format!("{}/ca/{}/ocsp", config.base_url, ca_cfg.id))
            }
        });

        let ca_state = Arc::new(CaState {
            id: ca_cfg.id.clone(),
            key_type: ca_cfg.key_type.clone(),
            key: ca_key,
            cert_der: ca_cert_der,
            hash_alg: ca_cfg.hash_alg.clone(),
            validity_days: ca_cfg.validity_days,
            crl_url,
            ocsp_url,
            aki_bytes: ca_aki_bytes,
            enforce_validity_cap: ca_cfg.enforce_validity_cap,
            crl_next_update_secs: ca_cfg.crl_next_update_secs,
            caa_identities: ca_cfg.caa_identities.clone(),
        });
        crl_caches_map.insert(ca_cfg.id.clone(), Default::default());
        cas_map.insert(ca_cfg.id.clone(), ca_state);
    }

    let default_ca_id = config
        .cas
        .iter()
        .find(|c| c.is_default)
        .map(|c| c.id.clone())
        .unwrap_or_else(|| config.cas[0].id.clone());

    // Convenience alias for the default CA (used by code not yet updated to
    // look up the CA from the request context).
    let ca = cas_map
        .get(&default_ca_id)
        .expect("default CA present in map")
        .clone();

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

    // ── Admin bootstrap ───────────────────────────────────────────────────────
    if let Some(ref admin_cfg) = config.admin {
        admin_cfg
            .validate()
            .map_err(|e| format!("admin config: {e}"))?;
        akamu::admin::init::bootstrap_operator_if_needed(admin_cfg, &ca, &db)
            .await
            .map_err(|e| format!("admin operator bootstrap: {e}"))?;
    }

    // ── MTC transparency log ──────────────────────────────────────────────────
    let mtc_algorithm = synta_mtc::crypto::HashAlgorithm::Sha256;

    // Load or generate the MTC signing key (distinct from the CA key per §5.5).
    let (mtc_signing_key, mtc_signing_hash_alg) = if let Some(ref sk_cfg) = config.mtc.signing_key {
        tracing::info!("loading MTC signing key from '{}'", sk_cfg.key_file);
        let key = load_or_generate_mtc_key(sk_cfg)?;
        (Some(key), sk_cfg.hash_alg.clone())
    } else {
        (None, "sha256".to_string())
    };

    // Pre-build cosigner HTTPS clients so TLS config errors surface at startup
    // rather than silently at checkpoint time, and to avoid re-reading PEM files
    // on every checkpoint interval.
    let cosigner_clients: Vec<_> = config
        .mtc
        .cosigners
        .iter()
        .filter_map(|c| match mtc::cosign::build_cosigner_client(c) {
            Ok(client) => Some(client),
            Err(e) => {
                tracing::warn!(url = %c.url, "build cosigner client at startup: {e}");
                None
            }
        })
        .collect();

    let mtc = if config.mtc.enabled {
        tracing::info!("opening MTC log at '{}'", config.mtc.log_path);
        let log_lock =
            mtc::log::acquire_log_lock(&config.mtc.log_path).map_err(|e| format!("{e}"))?;
        let log = mtc::log::open_or_create(&config.mtc.log_path, mtc_algorithm)
            .map_err(|e| format!("MTC log init: {e}"))?;
        let shared = Arc::new(tokio::sync::Mutex::new(log));
        Arc::new(MtcState {
            log: Some(shared),
            algorithm: mtc_algorithm,
            signing_key: mtc_signing_key,
            signing_hash_alg: mtc_signing_hash_alg,
            cosigner_clients,
            _log_lock: Some(log_lock),
        })
    } else {
        tracing::info!("MTC logging disabled");
        Arc::new(MtcState {
            log: None,
            algorithm: mtc_algorithm,
            signing_key: mtc_signing_key,
            signing_hash_alg: mtc_signing_hash_alg,
            cosigner_clients,
            _log_lock: None,
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

    // ── GSSAPI server credential ──────────────────────────────────────────────
    if !config.server.trusted_proxies.is_empty() && config.server.gssapi.is_some() {
        return Err(
            "server.trusted_proxies and server.gssapi cannot both be configured; \
             they are mutually exclusive authentication mechanisms"
                .into(),
        );
    }

    let gss_cred = if let Some(ref gcfg) = config.server.gssapi {
        tracing::info!(
            "initializing GSSAPI credential for service '{}'",
            gcfg.service_name
        );
        tracing::info!("GSSAPI keytab: '{}'", gcfg.keytab_file);
        if !config.tls.enabled {
            tracing::warn!(
                "GSSAPI is configured without TLS; SPNEGO tokens are not protected against \
                 interception or relay attacks — enable TLS or use a TLS-terminating proxy"
            );
        }
        let cred = akamu_gssapi::GssServerCred::acquire(&gcfg.service_name, &gcfg.keytab_file)
            .map_err(|e| format!("GSSAPI credential init: {e}"))?;
        Some(Arc::new(cred))
    } else {
        None
    };

    // ── Admin-specific GSSAPI credential ──────────────────────────────────────
    let admin_gss_cred = if let Some(ref admin_cfg) = config.admin {
        if let Some(ref gcfg) = admin_cfg.gssapi {
            tracing::info!(
                "initializing admin GSSAPI credential for service '{}', keytab: '{}'",
                gcfg.service_name,
                gcfg.keytab_file
            );
            let cred = akamu_gssapi::GssServerCred::acquire(&gcfg.service_name, &gcfg.keytab_file)
                .map_err(|e| format!("admin GSSAPI credential init: {e}"))?;
            Some(Arc::new(cred))
        } else {
            None
        }
    } else {
        None
    };

    // ── EAB master secret ─────────────────────────────────────────────────────
    let eab_master_secret = match config.server.eab_master_secret.as_deref() {
        None => None,
        Some(b64u) => {
            use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
            let bytes = URL_SAFE_NO_PAD
                .decode(b64u)
                .map_err(|e| format!("eab_master_secret base64url decode error: {e}"))?;
            if bytes.len() < 32 {
                return Err(format!(
                    "eab_master_secret must be ≥ 32 bytes after decoding, got {}",
                    bytes.len()
                ));
            }
            tracing::info!(
                "EAB HKDF master secret loaded ({} bytes); \
                 /acme/eab will return full credentials",
                bytes.len()
            );
            Some(Arc::new(zeroize::Zeroizing::new(bytes)))
        }
    };

    // ── Per-CA Link headers ───────────────────────────────────────────────────
    let link_headers_map: std::collections::HashMap<String, Arc<axum::http::HeaderValue>> = config
        .cas
        .iter()
        .map(|ca_cfg| {
            let url = if ca_cfg.is_default {
                format!("<{}/acme/directory>;rel=\"index\"", config.base_url)
            } else {
                format!(
                    "<{}/acme/{}/directory>;rel=\"index\"",
                    config.base_url, ca_cfg.id
                )
            };
            let hv = Arc::new(
                axum::http::HeaderValue::from_str(&url)
                    .expect("base_url + CA ID produce a valid Link header value"),
            );
            (ca_cfg.id.clone(), hv)
        })
        .collect();

    // ── Application state ─────────────────────────────────────────────────────
    let nonces = Arc::new(NonceBucket::new());
    let state = Arc::new(AppState {
        config: Arc::clone(&config),
        db: db.clone(),
        db_ro,
        db_kind,
        cas: Arc::new(cas_map),
        default_ca_id: Arc::new(default_ca_id),
        mtc,
        profiles: profile_registry.clone(),
        tls: tls_state,
        spki_cache: Arc::new(std::sync::RwLock::new(std::collections::HashMap::new())),
        nonces: Arc::clone(&nonces),
        link_headers: Arc::new(link_headers_map),
        validation_client: {
            let https = HttpsConnectorBuilder::new()
                .with_native_roots()
                .expect("failed to load native root CAs for http-01 validation client")
                .https_or_http()
                .enable_http1()
                .build();
            Client::builder(TokioExecutor::new()).build(https)
        },
        crl_caches: Arc::new(crl_caches_map),
        gss_cred,
        admin_gss_cred,
        eab_master_secret,
        audit: Arc::new(AuditState::new()),
        audit_policy: Arc::new(
            config
                .admin
                .as_ref()
                .map(akamu::audit::AuditPolicy::from_admin_config)
                .unwrap_or_default(),
        ),
        admin_sessions: config
            .admin
            .as_ref()
            .map(|_| Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new()))),
        admin_auth_limiter: config
            .admin
            .as_ref()
            .map(|_| Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new()))),
        startup_time: std::time::Instant::now(),
    });

    // ── Seed audit row counter ────────────────────────────────────────────────
    if let Err(e) = state.audit.seed_row_count(&state.db).await {
        tracing::warn!(error = %e, "could not seed audit row count; will fall back to COUNT(*) on first overflow check");
    }

    // ── Startup audit records ─────────────────────────────────────────────────
    let key_file_exists = std::path::Path::new(&config.default_ca().key_file).exists();
    let key_event_type = if key_file_exists {
        akamu::audit::AuditEventType::KeyLoad
    } else {
        akamu::audit::AuditEventType::KeyGenerate
    };
    state
        .record_audit(akamu::audit::AuditEvent::success(key_event_type))
        .await;
    state
        .record_audit(akamu::audit::AuditEvent::success(
            akamu::audit::AuditEventType::CaStart,
        ))
        .await;

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

    // ── MTC checkpoint background task ───────────────────────────────────────
    let _checkpoint_task = mtc::checkpoint::spawn_checkpoint_task(Arc::clone(&state));

    // ── MTC landmark allocation background task ──────────────────────────────
    let _landmark_task = mtc::landmark::spawn_landmark_task(Arc::clone(&state));

    // ── STAR background reissuance task ──────────────────────────────────────
    let _star_task = star::spawn(Arc::clone(&state));

    // ── RFC 9115 IdO→CA upstream delegation task ──────────────────────────────
    let _delegation_task = delegation_upstream::spawn(Arc::clone(&state));

    // ── HTTP / TLS server (serves ACME, admin API, and web UI) ──────────────
    let static_dir = config
        .server
        .webui
        .as_ref()
        .and_then(|w| w.static_dir.as_deref())
        .map(std::path::PathBuf::from);
    let router = routes::build_router(Arc::clone(&state), static_dir.as_deref());

    if config.tls.enabled {
        let mut server_cfg = akamu::tls::build_rustls_server_config(&config.tls)
            .map_err(|e| format!("TLS config: {e}"))?;
        server_cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_cfg));

        // Pre-compute tls-server-end-point channel binding (RFC 5929 §4) once at
        // startup so each connection can inject it without re-reading the cert.
        // Returns None for ML-DSA server certs (no defined hash algorithm).
        let tls_channel_binding: Option<Arc<Vec<u8>>> = {
            match akamu::tls::leaf_cert_der(&config.tls) {
                Err(e) => {
                    tracing::warn!("could not load leaf cert for channel binding: {e}");
                    None
                }
                Ok(der) => {
                    let b = akamu::tls::channel_binding::tls_server_endpoint_binding(&der);
                    if b.is_none() {
                        tracing::info!(
                            "TLS server cert uses ML-DSA or unknown algorithm; \
                             GSSAPI channel bindings disabled"
                        );
                    }
                    b.map(Arc::new)
                }
            }
        };

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
        let shutdown = tokio::signal::ctrl_c();
        tokio::pin!(shutdown);
        loop {
            tokio::select! {
                _ = &mut shutdown => {
                    tracing::info!("received shutdown signal; stopping TLS server");
                    break;
                }
                result = listener.accept() => {
                    let (stream, peer_addr) = result.map_err(|e| format!("accept: {e}"))?;
                    let acceptor = acceptor.clone();
                    let router = router.clone();
                    let tls_channel_binding = tls_channel_binding.clone();
                    tokio::spawn(async move {
                        let tls = match acceptor.accept(stream).await {
                            Ok(s) => s,
                            Err(e) => {
                                tracing::warn!("TLS handshake failed: {e}");
                                return;
                            }
                        };
                        // Extract peer cert before moving tls into TokioIo.
                        let peer_cert: Option<Vec<u8>> = tls
                            .get_ref()
                            .1
                            .peer_certificates()
                            .and_then(|c| c.first())
                            .map(|c| c.as_ref().to_vec());
                        let io = hyper_util::rt::TokioIo::new(tls);
                        use tower::ServiceExt as _;
                        let svc = hyper::service::service_fn(
                            move |mut req: hyper::Request<hyper::body::Incoming>| {
                                req.extensions_mut()
                                    .insert(axum::extract::ConnectInfo(peer_addr));
                                if let Some(ref der) = peer_cert {
                                    req.extensions_mut().insert(
                                        akamu::admin::auth::PeerClientCert(der.clone()),
                                    );
                                }
                                if let Some(ref binding) = tls_channel_binding {
                                    req.extensions_mut().insert(
                                        akamu::tls::channel_binding::TlsServerEndpointBinding(
                                            binding.as_ref().clone(),
                                        ),
                                    );
                                }
                                let router = router.clone();
                                async move {
                                    let req = req.map(axum::body::Body::new);
                                    Ok::<_, std::convert::Infallible>(
                                        router.oneshot(req).await.unwrap(),
                                    )
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
            }
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
        axum::serve(
            listener,
            router.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .with_graceful_shutdown(async {
            tokio::signal::ctrl_c().await.ok();
            tracing::info!("received shutdown signal; stopping server");
        })
        .await
        .map_err(|e| format!("server error: {e}"))?;
    }

    state
        .record_audit(akamu::audit::AuditEvent::success(
            akamu::audit::AuditEventType::CaStop,
        ))
        .await;

    Ok(())
}
