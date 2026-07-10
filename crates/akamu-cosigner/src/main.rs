//! akamu-cosigner — MTC cosigner daemon.
//!
//! Usage: `akamu-cosigner [/path/to/cosigner.toml]`
//! Defaults to `cosigner.toml` in the current working directory.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};

use tracing_subscriber::EnvFilter;

use akamu_cosigner::config::Config;
use akamu_cosigner::error::CosignerError;
use akamu_cosigner::state::AppState;
use akamu_cosigner::{acme, key, routes};
use akamu_util::listen::{
    parse_listen_target, remove_stale_socket, uds_marker_layer, ListenTarget,
};

#[tokio::main]
async fn main() {
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

/// Resolves when the process receives SIGTERM or Ctrl-C.
///
/// Installs the SIGTERM handler once so signal slots are not exhausted.
/// Called from each `with_graceful_shutdown` closure; also used by
/// `start_tls_server` which manages its own select loop.
async fn shutdown_signal(sigterm: &mut tokio::signal::unix::Signal) {
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {},
        _ = sigterm.recv() => {},
    }
    tracing::info!("received shutdown signal; stopping akamu-cosigner");
}

async fn run() -> Result<(), CosignerError> {
    let config_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "cosigner.toml".to_string());

    tracing::info!("loading config from '{config_path}'");
    let config = Config::from_file(&config_path)?;

    // ── Challenge token store (shared with HTTP challenge route + ACME bootstrap) ──
    let challenge_tokens: Arc<RwLock<HashMap<String, String>>> =
        Arc::new(RwLock::new(HashMap::new()));

    // ── Load or generate signing key ──────────────────────────────────────────
    tracing::info!(
        "loading cosigner signing key from '{}'",
        config.signing_key.key_file
    );
    let signing_key = key::load_or_generate(&config.signing_key)?;

    // ── Derive signature algorithm DER ────────────────────────────────────────
    let sig_alg_der = key::sig_alg_der(&signing_key, &config.signing_key.hash_alg)?;

    // ── ACME bootstrap (if configured and cert absent / expiring) ─────────────
    if let Some(ref bootstrap_cfg) = config.acme_bootstrap {
        let needs_cert = acme::cert_needs_renewal(&bootstrap_cfg.cert_file, 30);
        if needs_cert {
            tracing::info!("ACME bootstrap needed for '{}'", bootstrap_cfg.cert_file);
            acme::run_bootstrap(bootstrap_cfg, Arc::clone(&challenge_tokens)).await?;
        } else {
            tracing::info!(
                "existing certificate valid; skipping ACME bootstrap ({})",
                bootstrap_cfg.cert_file
            );
        }
    }

    // ── Load or generate cosigner-id certificate ──────────────────────────────
    let id_cert_path = config.effective_cosigner_id_cert().to_owned();
    if acme::cert_needs_renewal(&id_cert_path, 30) {
        tracing::info!("generating self-signed cosigner-id certificate → {id_cert_path}");
        generate_self_signed_cert(
            &signing_key,
            &config.signing_key.hash_alg,
            &config.server.base_url,
            &id_cert_path,
        )?;
    } else {
        tracing::info!(
            "existing cosigner-id certificate valid; skipping regeneration ({})",
            id_cert_path
        );
    }

    let cosigner_oid = parse_cosigner_oid(&config.cosigner_id.trust_anchor_id)?;

    // ── Build application state ───────────────────────────────────────────────
    let (admin_operators, admin_session_ttl_secs) = match config.admin {
        Some(ref a) => (a.operators.clone(), a.session_ttl_secs),
        None => {
            tracing::warn!(
                "[admin] section not configured; \
                 all admin endpoints will return 401 Unauthorized"
            );
            (vec![], akamu_cosigner::config::DEFAULT_SESSION_TTL_SECS)
        }
    };
    let state = Arc::new(AppState {
        signing_key,
        hash_alg: config.signing_key.hash_alg.clone(),
        sig_alg_der,
        cosigner_oid,
        challenge_tokens: Arc::clone(&challenge_tokens),
        admin_operators,
        admin_sessions: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
        admin_session_ttl_secs,
        startup_time: std::time::Instant::now(),
        signing_stats: Arc::new(Mutex::new((0, None))),
    });

    // ── Build router ──────────────────────────────────────────────────────────
    let router = routes::build_router(Arc::clone(&state));

    // ── Install signal handler once before branching ─────────────────────────
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .map_err(|e| CosignerError::Config(format!("install SIGTERM handler: {e}")))?;

    // ── Start HTTP or HTTPS server ────────────────────────────────────────────
    // Try systemd socket activation first (listenfd), then fall back to config.
    let mut listenfd = listenfd::ListenFd::from_env();
    if listenfd.len() > 1 {
        tracing::warn!(
            count = listenfd.len(),
            "listenfd: more than one socket FD available; only index 0 (Unix) is consumed"
        );
    }
    if let Some(std_listener) = listenfd.take_unix_listener(0).map_err(|e| {
        CosignerError::Config(format!(
            "systemd passed an fd that is not a Unix stream socket ({}); \
             only Unix socket activation is supported — verify ListenStream= \
             in your .socket unit points to a filesystem path, not a TCP address",
            e
        ))
    })? {
        if config.effective_tls().is_some() {
            return Err(CosignerError::Config(
                "TLS cannot be used with a Unix domain socket listener".to_owned(),
            ));
        }
        std_listener
            .set_nonblocking(true)
            .map_err(|e| CosignerError::Config(format!("set_nonblocking: {e}")))?;
        let listener = tokio::net::UnixListener::from_std(std_listener)
            .map_err(|e| CosignerError::Config(format!("tokio UnixListener: {e}")))?;
        tracing::info!("akamu-cosigner listening on systemd-activated Unix socket");
        let router = router.layer(axum::middleware::from_fn(uds_marker_layer));
        axum::serve(listener, router)
            .with_graceful_shutdown(async move { shutdown_signal(&mut sigterm).await })
            .await
            .map_err(|e| CosignerError::Io(e))?;
    } else {
        let target = parse_listen_target(&config.server.listen_addr, "AKAMU_COSIGNER_LISTEN")
            .map_err(CosignerError::Config)?;
        if let Some(tls_cfg) = config.effective_tls() {
            let addr = match target {
                ListenTarget::Tcp(a) => a,
                ListenTarget::Unix(_) => {
                    return Err(CosignerError::Config(
                        "TLS cannot be used with a Unix domain socket listener".to_owned(),
                    ));
                }
            };
            start_tls_server(router, addr, &tls_cfg, sigterm).await?;
        } else {
            match target {
                ListenTarget::Tcp(addr) => {
                    tracing::info!("akamu-cosigner listening on {} (plain HTTP)", addr);
                    let listener = tokio::net::TcpListener::bind(addr)
                        .await
                        .map_err(|e| CosignerError::Config(format!("bind '{}': {e}", addr)))?;
                    axum::serve(listener, router)
                        .with_graceful_shutdown(async move { shutdown_signal(&mut sigterm).await })
                        .await
                        .map_err(|e| CosignerError::Io(e))?;
                }
                ListenTarget::Unix(path) => {
                    remove_stale_socket(&path)
                        .await
                        .map_err(CosignerError::Config)?;
                    let listener = tokio::net::UnixListener::bind(&path)
                        .map_err(|e| CosignerError::Config(format!("bind unix '{}': {e}", path)))?;
                    tracing::info!(path = %path, "akamu-cosigner listening on Unix socket");
                    let router = router.layer(axum::middleware::from_fn(uds_marker_layer));
                    axum::serve(listener, router)
                        .with_graceful_shutdown(async move { shutdown_signal(&mut sigterm).await })
                        .await
                        .map_err(|e| CosignerError::Io(e))?;
                    // Best-effort cleanup of the socket file after graceful shutdown.
                    let _ = std::fs::remove_file(&path);
                }
            }
        }
    }

    Ok(())
}

/// Generate a self-signed cosigner-id certificate and write it as PEM.
///
/// The certificate is self-signed with `signing_key`, uses `base_url`'s
/// hostname as the dNSName SAN, and has 10-year validity.
fn generate_self_signed_cert(
    signing_key: &synta_certificate::BackendPrivateKey,
    hash_alg: &str,
    base_url: &str,
    cert_file: &str,
) -> Result<(), CosignerError> {
    use synta_certificate::{
        encode_key_usage, CertificateBuilder, NameBuilder, PrivateKey as _,
        SubjectAlternativeNameBuilder, KEY_USAGE_DIGITAL_SIGNATURE,
    };

    let hostname = extract_hostname(base_url);

    let name_der = NameBuilder::new()
        .common_name("akamu-cosigner")
        .build()
        .map_err(|e| CosignerError::Crypto(format!("name: {e}")))?;

    let san_der = SubjectAlternativeNameBuilder::new()
        .dns_name(&hostname)
        .build()
        .map_err(|e| CosignerError::Crypto(format!("SAN: {e}")))?;

    let pub_key = signing_key
        .public_key()
        .map_err(|e| CosignerError::Crypto(format!("public key: {e}")))?;
    let spki_der = pub_key.spki_der().to_vec();

    let now_secs = now_unix()?;
    let ten_years = 10 * 365 * 24 * 3600i64;
    let nb = unix_to_time_str(now_secs)?;
    let na = unix_to_time_str(now_secs + ten_years)?;

    let not_before = synta_certificate::parse_time(&nb)
        .map_err(|e| CosignerError::Crypto(format!("notBefore: {e}")))?;
    let not_after = synta_certificate::parse_time(&na)
        .map_err(|e| CosignerError::Crypto(format!("notAfter: {e}")))?;

    let ku_der = encode_key_usage(1 << KEY_USAGE_DIGITAL_SIGNATURE)
        .ok_or_else(|| CosignerError::Crypto("encode Key Usage extension failed".into()))?;

    let signer = signing_key.as_signer(hash_alg);
    let cert_der = CertificateBuilder::new()
        .issuer_name(&name_der)
        .subject_name(&name_der)
        .public_key_der(&spki_der)
        .serial_number(synta::Integer::from_i64(now_secs))
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension_oid(synta_certificate::oids::KEY_USAGE, true, &ku_der)
        .add_extension_oid(synta_certificate::oids::SUBJECT_ALT_NAME, false, &san_der)
        .sign(&signer)
        .map_err(|e| CosignerError::Crypto(format!("sign cosigner-id cert: {e}")))?;

    let pem = synta_certificate::der_to_pem("CERTIFICATE", &cert_der);
    std::fs::write(cert_file, pem)?;
    tracing::info!("self-signed cosigner-id certificate written to '{cert_file}'");
    Ok(())
}

/// Parse a dotted-decimal relative OID string and return the parsed `RelativeOid`.
fn parse_cosigner_oid(oid_str: &str) -> Result<synta::RelativeOid, CosignerError> {
    oid_str.parse().map_err(|e| {
        CosignerError::Config(format!(
            "parse cosigner_id.trust_anchor_id ROID '{oid_str}': {e}"
        ))
    })
}

async fn start_tls_server(
    router: axum::Router,
    listen_addr: std::net::SocketAddr,
    tls_cfg: &akamu_cosigner::config::TlsConfig,
    mut sigterm: tokio::signal::unix::Signal,
) -> Result<(), CosignerError> {
    use std::sync::Arc;

    let certs =
        akamu_util::tls::load_server_cert_chain(&tls_cfg.cert_file).map_err(CosignerError::Tls)?;
    let key =
        akamu_util::tls::load_server_private_key(&tls_cfg.key_file).map_err(CosignerError::Tls)?;

    let server_cfg = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls_native_ossl::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|e| CosignerError::Tls(format!("TLS protocol config: {e}")))?
    .with_no_client_auth()
    .with_single_cert(certs, key)
    .map_err(|e| CosignerError::Tls(format!("TLS cert/key: {e}")))?;

    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_cfg));
    let listener = tokio::net::TcpListener::bind(listen_addr)
        .await
        .map_err(|e| CosignerError::Config(format!("bind '{}': {e}", listen_addr)))?;

    tracing::info!("akamu-cosigner listening on {} with TLS", listen_addr);

    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                tracing::info!("received shutdown signal; stopping akamu-cosigner TLS server");
                break;
            }
            _ = sigterm.recv() => {
                tracing::info!("received SIGTERM; stopping akamu-cosigner TLS server");
                break;
            }
            result = listener.accept() => {
                let (stream, _) = match result {
                    Ok(s) => s,
                    Err(e) => {
                        tracing::warn!("accept error (continuing): {e}");
                        continue;
                    }
                };
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
                                Ok::<_, std::convert::Infallible>(
                                    router
                                        .oneshot(req)
                                        .await
                                        .unwrap_or_else(|e| match e {}),
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
    Ok(())
}

fn extract_hostname(url: &str) -> String {
    let authority = url
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .split('/')
        .next()
        .unwrap_or("");

    if authority.is_empty() {
        tracing::warn!(
            url = %url,
            "could not extract hostname from base_url; \
             self-signed cert will use 'localhost' as SAN dNSName"
        );
        return "localhost".to_owned();
    }

    if authority.starts_with('[') {
        // IPv6 literal: "[::1]" or "[::1]:port"
        return authority
            .split(']')
            .next()
            .map(|s| format!("{s}]"))
            .unwrap_or_else(|| {
                tracing::warn!(
                    url = %url,
                    "malformed IPv6 literal in base_url; \
                     self-signed cert will use 'localhost' as SAN dNSName"
                );
                "localhost".to_owned()
            });
    }

    authority
        .split(':')
        .next()
        .unwrap_or("localhost")
        .to_owned()
}

fn now_unix() -> Result<i64, CosignerError> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .map_err(|e| CosignerError::Crypto(format!("system clock before UNIX epoch: {e}")))
}

fn unix_to_time_str(secs: i64) -> Result<String, CosignerError> {
    let gt = synta::GeneralizedTime::from_unix(secs).ok_or_else(|| {
        CosignerError::Crypto(format!(
            "unix timestamp {secs} out of GeneralizedTime range"
        ))
    })?;
    Ok(format!(
        "{:04}{:02}{:02}{:02}{:02}{:02}Z",
        gt.year, gt.month, gt.day, gt.hour, gt.minute, gt.second
    ))
}
