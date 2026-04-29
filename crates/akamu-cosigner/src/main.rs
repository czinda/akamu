//! akamu-cosigner — MTC cosigner daemon.
//!
//! Usage: `akamu-cosigner [/path/to/cosigner.toml]`
//! Defaults to `cosigner.toml` in the current working directory.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use tracing_subscriber::EnvFilter;

mod acme;
mod config;
mod error;
mod key;
mod routes;
mod state;

use config::Config;
use error::CosignerError;
use state::AppState;

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

    let id_cert_pem = std::fs::read(&id_cert_path)?;
    let id_cert_der = synta_certificate::pem_to_der(&id_cert_pem)
        .into_iter()
        .next()
        .ok_or_else(|| CosignerError::Crypto("no DER block in cosigner-id PEM".into()))?;
    let cosigner_id = parse_cosigner_id(&id_cert_der)?;

    // ── Build application state ───────────────────────────────────────────────
    let state = Arc::new(AppState {
        signing_key,
        hash_alg: config.signing_key.hash_alg.clone(),
        sig_alg_der,
        cosigner_id,
        challenge_tokens: Arc::clone(&challenge_tokens),
    });

    // ── Build router ──────────────────────────────────────────────────────────
    let router = routes::build_router(Arc::clone(&state));

    // ── Start HTTP or HTTPS server ────────────────────────────────────────────
    let listen_addr = config.server.listen_addr.clone();
    if let Some(tls_cfg) = config.effective_tls() {
        start_tls_server(router, &listen_addr, &tls_cfg).await?;
    } else {
        tracing::info!("akamu-cosigner listening on {} (plain HTTP)", listen_addr);
        let listener = tokio::net::TcpListener::bind(&listen_addr)
            .await
            .map_err(|e| CosignerError::Config(format!("bind '{}': {e}", listen_addr)))?;
        axum::serve(listener, router)
            .await
            .map_err(|e| CosignerError::Config(format!("server error: {e}")))?;
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

    let now_secs = now_unix();
    let ten_years = 10 * 365 * 24 * 3600i64;
    let nb = unix_to_time_str(now_secs);
    let na = unix_to_time_str(now_secs + ten_years);

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
        .serial_number(synta::Integer::from_i64(now_unix()))
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

/// Parse `CosignerID` (issuer Name + serial) from a DER-encoded certificate.
///
/// Uses a DER roundtrip to convert the issuer `Name<'a>` (borrowed) into
/// `synta_mtc::types::Name` (owned).
fn parse_cosigner_id(cert_der: &[u8]) -> Result<synta_mtc::types::CosignerID, CosignerError> {
    use synta::traits::Encode;
    use synta::{Decoder, Encoder, Encoding};
    use synta_certificate::owned::Certificate;
    use synta_mtc::types::{CosignerID, Name as MtcName};

    let mut dec = Decoder::new(cert_der, Encoding::Der);
    let cert: Certificate = dec
        .decode()
        .map_err(|e| CosignerError::Asn1(format!("decode cert for CosignerID: {e}")))?;

    let serial = cert.tbs_certificate.serial_number.clone();

    // DER-encode issuer (borrowed from input), then decode as owned MTC Name.
    let mut enc = Encoder::new(Encoding::Der);
    cert.tbs_certificate
        .issuer
        .encode(&mut enc)
        .map_err(|e| CosignerError::Asn1(format!("encode issuer: {e}")))?;
    let issuer_der = enc
        .finish()
        .map_err(|e| CosignerError::Asn1(format!("finish issuer DER: {e}")))?;

    let mut dec2 = Decoder::new(&issuer_der, Encoding::Der);
    let mtc_issuer: MtcName = dec2
        .decode()
        .map_err(|e| CosignerError::Asn1(format!("decode MTC issuer Name: {e}")))?;

    Ok(CosignerID {
        issuer: mtc_issuer,
        serial_number: serial,
    })
}

async fn start_tls_server(
    router: axum::Router,
    listen_addr: &str,
    tls_cfg: &config::TlsConfig,
) -> Result<(), CosignerError> {
    use std::sync::Arc;

    let certs = akamu::tls::loader::load_server_cert_chain(&tls_cfg.cert_file)
        .map_err(CosignerError::Tls)?;
    let key = akamu::tls::loader::load_server_private_key(&tls_cfg.key_file)
        .map_err(CosignerError::Tls)?;

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
        let (stream, _) = match listener.accept().await {
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
            let svc =
                hyper::service::service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
                    let router = router.clone();
                    async move {
                        let req = req.map(axum::body::Body::new);
                        Ok::<_, std::convert::Infallible>(router.oneshot(req).await.unwrap())
                    }
                });
            if let Err(e) =
                hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new())
                    .serve_connection(io, svc)
                    .await
            {
                tracing::warn!("TLS connection error: {e}");
            }
        });
    }
}

fn extract_hostname(url: &str) -> String {
    let authority = url
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .split('/')
        .next()
        .unwrap_or("localhost");

    // IPv6 literal: "[::1]" or "[::1]:port" — return the bracketed address.
    if authority.starts_with('[') {
        return authority
            .split(']')
            .next()
            .map(|s| format!("{s}]"))
            .unwrap_or_else(|| "localhost".to_owned());
    }

    // IPv4 / hostname: strip optional ":port".
    authority
        .split(':')
        .next()
        .unwrap_or("localhost")
        .to_owned()
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

fn unix_to_time_str(secs: i64) -> String {
    let gt = synta::GeneralizedTime::from_unix(secs)
        .unwrap_or_else(|| synta::GeneralizedTime::from_unix(0).unwrap());
    format!(
        "{:04}{:02}{:02}{:02}{:02}{:02}Z",
        gt.year, gt.month, gt.day, gt.hour, gt.minute, gt.second
    )
}
