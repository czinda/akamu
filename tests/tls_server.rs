//! Integration test: full ACME flow over a real TLS socket, with tracing.
//!
//! Each test initialises a `tracing_subscriber` that writes to the per-test
//! output buffer.  Run with `-- --nocapture` to see all log lines:
//!
//!   cargo test --test tls_server -- --nocapture
//!
//! Tests:
//!   test_tls_directory          — GET /acme/directory returns 200 JSON
//!   test_tls_new_nonce          — HEAD /acme/new-nonce returns Replay-Nonce
//!   test_tls_new_account        — nonce→new-account JWS → 201 over TLS
//!   test_tls_full_acme_flow     — complete flow: account→order→bypass→finalize
//!                                  →download cert; logs cert chain content
//!   test_tls_untrusted_ca_rejected — TLS handshake fails with wrong CA

use std::sync::Arc;

use axum::http::header;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use hyper::body::Bytes;
use hyper_util::rt::TokioIo;
use rustls::pki_types::{CertificateDer, ServerName};
use serde_json::{json, Value};
use synta::{Decoder, Encoding};
use synta_certificate::BackendPrivateKey;
use synta_certificate::{
    format_dn, pem_to_der, Certificate, CertificateSigner as _, CsrBuilder, NameBuilder,
    PrivateKey as _, SubjectAlternativeNameBuilder,
};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use akamu::config::{CaConfig, Config, DatabaseConfig, MtcConfig, ServerConfig, TlsConfig};
use akamu::state::{AppState, CaState, MtcState, NonceBucket};
use akamu::{ca, db, routes, tls};

// ── Tracing initialisation ────────────────────────────────────────────────────

/// Initialise the global tracing subscriber for test output.
///
/// Writes to the per-test stdout buffer (visible with `-- --nocapture`).
/// Uses `try_init` so that subsequent calls from parallel tests are silently
/// ignored — the subscriber can only be installed once per process.
///
/// Filter: `acme_server` at DEBUG (server internals), everything else at INFO.
fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_test_writer()
        // compact()          — renders span fields inline; one log line per HTTP exchange
        // with_target(false) — omits module-path prefixes like "tower_http::trace::on_response:"
        .compact()
        .with_target(false)
        .with_env_filter("tower_http=debug,acme_server=debug,info")
        .try_init();
}

// ── Minimal ACME JWS signer (P-256 / ES256) ──────────────────────────────────

struct AcmeKey {
    key: BackendPrivateKey,
    x_b64: String,
    y_b64: String,
}

impl AcmeKey {
    fn generate() -> Self {
        let key = BackendPrivateKey::generate_ec("P-256").unwrap();
        let pub_key = key.public_key().unwrap();
        let (x_bytes, y_bytes) = pub_key.ec_affine_coordinates().unwrap().unwrap();
        let x_b64 = encode_coord(&x_bytes, 32);
        let y_b64 = encode_coord(&y_bytes, 32);
        AcmeKey { key, x_b64, y_b64 }
    }

    fn jwk(&self) -> Value {
        json!({ "kty": "EC", "crv": "P-256", "x": self.x_b64, "y": self.y_b64 })
    }

    fn jws_with_jwk(&self, nonce: &str, url: &str, payload: Option<Value>) -> Value {
        let header = json!({
            "alg": "ES256",
            "nonce": nonce,
            "url": url,
            "jwk": self.jwk(),
        });
        self.build_jws(header, payload)
    }

    fn jws_with_kid(&self, kid: &str, nonce: &str, url: &str, payload: Option<Value>) -> Value {
        let header = json!({
            "alg": "ES256",
            "nonce": nonce,
            "url": url,
            "kid": kid,
        });
        self.build_jws(header, payload)
    }

    fn build_jws(&self, header: Value, payload: Option<Value>) -> Value {
        let protected = URL_SAFE_NO_PAD.encode(header.to_string().as_bytes());
        let payload_b64 = match payload {
            Some(v) => URL_SAFE_NO_PAD.encode(v.to_string().as_bytes()),
            None => String::new(),
        };
        let signing_input = format!("{}.{}", protected, payload_b64);
        let signer = self.key.as_signer("sha256");
        let der_sig = signer.sign_tbs(signing_input.as_bytes()).unwrap();
        let p1363 = ecdsa_der_to_p1363(&der_sig, 32).unwrap();
        let signature = URL_SAFE_NO_PAD.encode(&p1363);
        json!({ "protected": protected, "payload": payload_b64, "signature": signature })
    }
}

fn encode_coord(bytes: &[u8], len: usize) -> String {
    let mut padded = vec![0u8; len];
    let start = len.saturating_sub(bytes.len());
    padded[start..].copy_from_slice(&bytes[bytes.len().saturating_sub(len)..]);
    URL_SAFE_NO_PAD.encode(&padded)
}

fn ecdsa_der_to_p1363(der: &[u8], half: usize) -> Option<Vec<u8>> {
    let inner = strip_tlv(der, 0x30)?;
    let (r, rest) = strip_integer(inner)?;
    let (s, _) = strip_integer(rest)?;
    if r.len() > half || s.len() > half {
        return None;
    }
    let mut out = vec![0u8; half * 2];
    out[half - r.len()..half].copy_from_slice(r);
    out[half * 2 - s.len()..].copy_from_slice(s);
    Some(out)
}

fn strip_tlv<'a>(buf: &'a [u8], tag: u8) -> Option<&'a [u8]> {
    if *buf.first()? != tag {
        return None;
    }
    let (len, rest) = decode_der_len(&buf[1..])?;
    rest.get(..len)
}

fn strip_integer(buf: &[u8]) -> Option<(&[u8], &[u8])> {
    if *buf.first()? != 0x02 {
        return None;
    }
    let (len, rest) = decode_der_len(&buf[1..])?;
    let val = rest.get(..len)?;
    let val = val.strip_prefix(&[0x00u8]).unwrap_or(val);
    Some((val, &rest[len..]))
}

fn decode_der_len(buf: &[u8]) -> Option<(usize, &[u8])> {
    let first = *buf.first()?;
    if first < 0x80 {
        Some((first as usize, &buf[1..]))
    } else if first == 0x81 {
        Some((*buf.get(1)? as usize, &buf[2..]))
    } else if first == 0x82 {
        let len = (*buf.get(1)? as usize) << 8 | *buf.get(2)? as usize;
        Some((len, &buf[3..]))
    } else {
        None
    }
}

// ── Certificate chain inspection ──────────────────────────────────────────────

/// Format a `Time` (UTCTime or GeneralizedTime) for display.
fn fmt_time(t: &synta_certificate::Time) -> String {
    match t {
        synta_certificate::Time::UtcTime(u) => format!("{u}"),
        synta_certificate::Time::GeneralTime(g) => format!("{g}"),
    }
}

/// Parse and log the contents of a PEM certificate chain.
///
/// Logs (at INFO level via tracing):
///   - Number of certificates in the chain
///   - Per-certificate: DER size, subject DN, issuer DN, serial (hex),
///     validity period, Subject Alternative Names
///
/// This is the "what is in the certificate" tracing the tests demonstrate.
fn log_certificate_chain(label: &str, pem: &str) {
    let ders = pem_to_der(pem.as_bytes());
    tracing::info!(
        "┌── {} — {} certificate(s) ────────────────────────",
        label,
        ders.len()
    );

    for (i, der) in ders.iter().enumerate() {
        tracing::info!("│  [cert {}]  {} bytes DER", i, der.len());

        match Decoder::new(der, Encoding::Der).decode::<Certificate<'_>>() {
            Ok(cert) => {
                let tbs = &cert.tbs_certificate;

                // Subject and issuer as RFC 4514 strings.
                let subject = format_dn(tbs.subject.as_bytes());
                let issuer = format_dn(tbs.issuer.as_bytes());
                tracing::info!("│  [cert {}]  subject : {}", i, subject);
                tracing::info!("│  [cert {}]  issuer  : {}", i, issuer);

                // Serial number as uppercase hex.
                let serial_hex: String = tbs
                    .serial_number
                    .as_bytes()
                    .iter()
                    .map(|b| format!("{b:02X}"))
                    .collect::<Vec<_>>()
                    .join(":");
                tracing::info!("│  [cert {}]  serial  : {}", i, serial_hex);

                // Validity period.
                tracing::info!(
                    "│  [cert {}]  valid   : {} → {}",
                    i,
                    fmt_time(&tbs.validity.not_before),
                    fmt_time(&tbs.validity.not_after)
                );

                // Subject Alternative Names (tag 2 = dNSName, 7 = iPAddress).
                let sans = cert.subject_alt_names();
                if sans.is_empty() {
                    tracing::info!("│  [cert {}]  SAN     : (none)", i);
                } else {
                    for (tag, value) in &sans {
                        match tag {
                            2 => {
                                let dns = std::str::from_utf8(value).unwrap_or("<invalid UTF-8>");
                                tracing::info!("│  [cert {}]  SAN     : dNSName = {}", i, dns);
                            }
                            7 if value.len() == 4 => {
                                tracing::info!(
                                    "│  [cert {}]  SAN     : iPAddress = {}.{}.{}.{}",
                                    i,
                                    value[0],
                                    value[1],
                                    value[2],
                                    value[3]
                                );
                            }
                            _ => {
                                tracing::info!(
                                    "│  [cert {}]  SAN     : tag={} bytes={}",
                                    i,
                                    tag,
                                    value.len()
                                );
                            }
                        }
                    }
                }
            }
            Err(e) => {
                tracing::warn!("│  [cert {}]  parse error: {}", i, e);
            }
        }
    }

    tracing::info!("└──────────────────────────────────────────────────────────");
}

// ── HTTPS test client ─────────────────────────────────────────────────────────

/// Build a rustls `ClientConfig` that trusts only the given CA DER.
///
/// Explicitly uses the ring provider so tests don't need a process-level
/// `CryptoProvider::install_default()` call.
fn client_tls_config(ca_der: &[u8]) -> rustls::ClientConfig {
    let mut root_store = rustls::RootCertStore::empty();
    root_store
        .add(CertificateDer::from(ca_der.to_vec()))
        .expect("add CA cert to root store");
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("safe protocol versions")
        .with_root_certificates(root_store)
        .with_no_client_auth()
}

/// Single HTTP/1.1 request over a fresh TLS connection (SNI = "localhost").
struct Response {
    status: u16,
    headers: hyper::http::HeaderMap,
    body: String,
}

async fn https(
    addr: std::net::SocketAddr,
    method: &str,
    path: &str,
    req_headers: &[(&str, &str)],
    body: Option<String>,
    ca_der: &[u8],
) -> Response {
    tracing::debug!("  → {} https://localhost:{}{}", method, addr.port(), path);

    let connector = TlsConnector::from(Arc::new(client_tls_config(ca_der)));
    let stream = TcpStream::connect(addr).await.expect("TCP connect");
    let server_name = ServerName::try_from("localhost").unwrap();
    let tls_stream = connector
        .connect(server_name, stream)
        .await
        .expect("TLS handshake");

    let io = TokioIo::new(tls_stream);
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io)
        .await
        .expect("HTTP/1.1 handshake");
    tokio::spawn(conn);

    let body_bytes: Bytes = match body {
        Some(s) => Bytes::from(s),
        None => Bytes::new(),
    };
    let content_len = body_bytes.len();

    let mut builder = hyper::Request::builder()
        .method(method)
        .uri(format!("https://localhost:{}{}", addr.port(), path))
        .header(header::HOST, "localhost");
    for (name, val) in req_headers {
        builder = builder.header(*name, *val);
    }
    if content_len > 0 {
        builder = builder.header(header::CONTENT_LENGTH, content_len);
    }
    let req = builder.body(http_body_util::Full::new(body_bytes)).unwrap();

    let resp = sender.send_request(req).await.expect("send request");
    let status = resp.status().as_u16();
    let headers = resp.headers().clone();
    let body_bytes = http_body_util::BodyExt::collect(resp.into_body())
        .await
        .expect("read body")
        .to_bytes();
    let body = String::from_utf8_lossy(&body_bytes).into_owned();

    tracing::debug!("  ← {} ({} bytes)", status, body.len());

    Response {
        status,
        headers,
        body,
    }
}

// ── TLS test server ───────────────────────────────────────────────────────────

struct TlsTestServer {
    addr: std::net::SocketAddr,
    /// Base URL including the real port (e.g. "https://localhost:54321").
    base_url: String,
    /// CA certificate DER — used to build the client trust store.
    ca_der: Vec<u8>,
    /// Database connection — used to bypass challenge validation in tests.
    db: akamu::db::Db,
    /// tokio task handle — abort on drop to free the port.
    handle: tokio::task::JoinHandle<()>,
    /// Temp dir kept alive as long as the server lives.
    _dir: tempfile::TempDir,
}

impl Drop for TlsTestServer {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

/// Spin up a full TLS ACME server on a random loopback port.
///
/// Uses `axum_server::from_tcp_rustls` with a bootstrap CA-signed server cert.
/// Initialises the tracing subscriber (first call wins; subsequent calls in
/// parallel tests are silently ignored).
async fn start_tls_server() -> TlsTestServer {
    init_tracing();

    let dir = tempfile::TempDir::new().unwrap();

    // Bind the listener first so we know the actual port before building config.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let addr = listener.local_addr().unwrap();
    let base_url = format!("https://localhost:{}", addr.port());

    let cert_file = dir.path().join("server.crt").to_string_lossy().into_owned();
    let key_file = dir.path().join("server.key").to_string_lossy().into_owned();

    let config = Arc::new(Config {
        listen_addr: format!("127.0.0.1:{}", addr.port()),
        base_url: base_url.clone(),
        database: DatabaseConfig {
            url: "sqlite::memory:".into(),
            max_connections: None,
        },
        ca: CaConfig {
            key_file: dir.path().join("ca.key").to_string_lossy().into_owned(),
            cert_file: dir.path().join("ca.crt").to_string_lossy().into_owned(),
            key_type: "ec:P-256".into(),
            hash_alg: "sha256".into(),
            validity_days: 90,
            crl_url: None,
            ocsp_url: None,
            common_name: "Akāmu TLS Test CA".into(),
            organization: "Akāmu Tests".into(),
            ca_validity_years: 10,
            crl_next_update_secs: 86400,
            enforce_validity_cap: false,
        },
        mtc: MtcConfig {
            log_path: "/dev/null".into(),
            enabled: false,
            signing_key: None,
            checkpoint_interval_secs: 3600,
            cosigners: vec![],
            landmark_interval_secs: 86400,
            max_active_landmarks: 100,
            checkpoint_retention_count: 1000,
        },
        server: ServerConfig::default(),
        profiles: Default::default(),
        tls: TlsConfig {
            enabled: true,
            cert_file: cert_file.clone(),
            key_file: key_file.clone(),
            protocols: vec!["TLSv1.2".into(), "TLSv1.3".into()],
            server_name: "localhost".into(),
            bootstrap_key_type: "ec:P-256".into(),
            client_auth: None,
        },
        admin: None,
    });

    // Initialise CA.
    let (ca_key, ca_cert_der) = ca::init::load_or_generate(&config.ca).unwrap();
    if let Ok(ca_cert) = Decoder::new(&ca_cert_der, Encoding::Der).decode::<Certificate<'_>>() {
        tracing::info!(
            "CA subject : {}",
            format_dn(ca_cert.tbs_certificate.subject.as_bytes())
        );
    }

    db::install_drivers();
    let db_conn = db::open("sqlite::memory:", 1, "./migrations/sqlite")
        .await
        .unwrap();

    let ca_state = Arc::new(CaState {
        key: ca_key,
        cert_der: ca_cert_der.clone(),
        hash_alg: "sha256".into(),
        validity_days: 90,
        crl_url: None,
        ocsp_url: None,
        aki_bytes: Vec::new(),
        enforce_validity_cap: false,
    });

    // Bootstrap TLS cert/key signed by the CA.
    tracing::info!(
        "Bootstrapping TLS server certificate (key_type={}, server_name=localhost)",
        config.tls.bootstrap_key_type
    );
    tls::init::load_or_generate(&config.tls, &ca_state).unwrap();
    tracing::info!("TLS server certificate written: {}", cert_file);

    let mut server_cfg = tls::build_rustls_server_config(&config.tls).unwrap();
    server_cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let tls_acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_cfg));
    let listener = tokio::net::TcpListener::from_std(listener).unwrap();

    let state = Arc::new(AppState {
        config: Arc::clone(&config),
        db: db_conn.clone(),
        db_kind: db::DbKind::Sqlite,
        profiles: akamu::profiles::ProfileRegistry::empty(&ca_state),
        ca: ca_state,
        mtc: Arc::new(MtcState {
            log: None,
            algorithm: synta_mtc::crypto::HashAlgorithm::Sha256,
            signing_key: None,
            signing_hash_alg: "sha256".into(),
            cosigner_clients: vec![],
        }),
        tls: None,
        spki_cache: Arc::new(std::sync::RwLock::new(std::collections::HashMap::new())),
        nonces: Arc::new(NonceBucket::new()),
        link_header: Arc::new(axum::http::HeaderValue::from_static(
            "<https://acme.test/acme/directory>;rel=\"index\"",
        )),
        validation_client: {
            let https = hyper_rustls::HttpsConnectorBuilder::new()
                .with_native_roots()
                .expect("native roots")
                .https_or_http()
                .enable_http1()
                .build();
            hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
                .build(https)
        },
    });

    let router = routes::build_router(Arc::clone(&state));

    tracing::info!("Binding TLS server on {}", addr);
    let handle = tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((stream, _)) => {
                    let acceptor = tls_acceptor.clone();
                    let router = router.clone();
                    tokio::spawn(async move {
                        let tls = match acceptor.accept(stream).await {
                            Ok(s) => s,
                            Err(e) => {
                                tracing::warn!("TLS handshake error: {e}");
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
                Err(e) => {
                    tracing::warn!("accept error: {e}");
                    break;
                }
            }
        }
    });

    // Give the server a moment to start accepting.
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    tracing::info!("TLS server ready at {}", base_url);

    TlsTestServer {
        addr,
        base_url,
        ca_der: ca_cert_der,
        db: db_conn.clone(),
        handle,
        _dir: dir,
    }
}

// ── ACME flow helpers (for full-flow test) ────────────────────────────────────

/// Mark all challenges and authorizations for an order as `valid` and
/// advance the order status to `ready`, bypassing actual challenge validation.
async fn mark_order_ready(db: &akamu::db::Db, order_id: &str) {
    let authz_ids: Vec<(String,)> =
        sqlx::query_as("SELECT id FROM authorizations WHERE order_id = ?")
            .bind(order_id)
            .fetch_all(db)
            .await
            .unwrap();
    for (aid,) in &authz_ids {
        sqlx::query(
            "UPDATE challenges SET status='valid', validated=1700000000 WHERE authz_id = ?",
        )
        .bind(aid)
        .execute(db)
        .await
        .unwrap();
        sqlx::query("UPDATE authorizations SET status='valid', updated=1700000000 WHERE id = ?")
            .bind(aid)
            .execute(db)
            .await
            .unwrap();
    }
    sqlx::query("UPDATE orders SET status='ready', updated=1700000000 WHERE id = ?")
        .bind(order_id)
        .execute(db)
        .await
        .unwrap();
}

/// Build a minimal P-256 CSR for `domain` with a dNSName SAN.
fn make_csr_der(domain: &str) -> Vec<u8> {
    let backend_key = BackendPrivateKey::generate_ec("P-256").unwrap();
    let spki_der = backend_key.public_key().unwrap().spki_der().to_vec();
    let name_der = NameBuilder::new().common_name(domain).build().unwrap();
    let san_der = SubjectAlternativeNameBuilder::new()
        .dns_name(domain)
        .build()
        .unwrap();
    let signer = backend_key.as_signer("sha256");
    CsrBuilder::new()
        .subject_name(&name_der)
        .public_key_der(&spki_der)
        .add_extension_oid(synta_certificate::oids::SUBJECT_ALT_NAME, false, &san_der)
        .sign(&signer)
        .unwrap()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

/// GET /acme/directory over TLS returns 200 with the expected JSON structure.
#[tokio::test]
async fn test_tls_directory() {
    let server = start_tls_server().await;

    tracing::info!("── test_tls_directory ──────────────────────────────────────");
    let r = https(
        server.addr,
        "GET",
        "/acme/directory",
        &[],
        None,
        &server.ca_der,
    )
    .await;

    assert_eq!(
        r.status, 200,
        "directory: expected 200, got {}: {}",
        r.status, r.body
    );
    assert!(
        r.headers
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(|ct| ct.contains("application/json"))
            .unwrap_or(false),
        "directory: Content-Type should be application/json"
    );

    let dir: Value = serde_json::from_str(&r.body).expect("directory response is JSON");
    tracing::info!("directory.newAccount : {}", dir["newAccount"]);
    tracing::info!("directory.newNonce   : {}", dir["newNonce"]);
    tracing::info!("directory.newOrder   : {}", dir["newOrder"]);

    assert!(
        dir["newAccount"].is_string(),
        "directory missing newAccount"
    );
    assert!(dir["newNonce"].is_string(), "directory missing newNonce");
    assert!(dir["newOrder"].is_string(), "directory missing newOrder");
}

/// HEAD /acme/new-nonce returns 200 with a Replay-Nonce header.
#[tokio::test]
async fn test_tls_new_nonce() {
    let server = start_tls_server().await;

    tracing::info!("── test_tls_new_nonce ──────────────────────────────────────");
    let r = https(
        server.addr,
        "HEAD",
        "/acme/new-nonce",
        &[],
        None,
        &server.ca_der,
    )
    .await;

    assert_eq!(r.status, 200, "new-nonce: expected 200, got {}", r.status);
    let nonce = r
        .headers
        .get("replay-nonce")
        .expect("missing Replay-Nonce header")
        .to_str()
        .unwrap();
    tracing::info!("Replay-Nonce : {}", nonce);
}

/// Full nonce → new-account registration over TLS: expect 201 with account URL.
#[tokio::test]
async fn test_tls_new_account() {
    let server = start_tls_server().await;
    let port = server.addr.port();
    let base_url = format!("https://localhost:{port}");

    tracing::info!("── test_tls_new_account ────────────────────────────────────");

    // Step 1: fetch a nonce.
    tracing::info!("Step 1: HEAD /acme/new-nonce");
    let nonce_r = https(
        server.addr,
        "HEAD",
        "/acme/new-nonce",
        &[],
        None,
        &server.ca_der,
    )
    .await;
    assert_eq!(nonce_r.status, 200);
    let nonce = nonce_r.headers["replay-nonce"]
        .to_str()
        .unwrap()
        .to_string();
    tracing::info!("  nonce = {}", nonce);

    // Step 2: POST new-account.
    tracing::info!("Step 2: POST /acme/new-account");
    let key = AcmeKey::generate();
    let jws = key.jws_with_jwk(
        &nonce,
        &format!("{base_url}/acme/new-account"),
        Some(json!({ "termsOfServiceAgreed": true })),
    );
    let r = https(
        server.addr,
        "POST",
        "/acme/new-account",
        &[("Content-Type", "application/jose+json")],
        Some(jws.to_string()),
        &server.ca_der,
    )
    .await;

    assert_eq!(r.status, 201, "expected 201, got {}: {}", r.status, r.body);
    let location = r.headers["location"].to_str().unwrap().to_string();
    tracing::info!("  account URL = {}", location);
    let body: Value = serde_json::from_str(&r.body).unwrap();
    tracing::info!("  account status = {}", body["status"]);
    assert_eq!(body["status"], "valid");
}

/// Complete ACME flow over a real TLS socket, with detailed tracing at each step.
///
/// Flow:
///   1. GET  directory             → log endpoint URLs
///   2. HEAD new-nonce             → get Replay-Nonce
///   3. POST new-account (JWS/JWK) → register; log account URL
///   4. POST new-order             → create order for "tls-test.acme.example"
///   5. DB bypass                  → mark all challenges+authz valid, order ready
///   6. POST finalize (CSR)        → issue certificate; log status + cert URL
///   7. GET  certificate           → download PEM chain; log chain contents
#[tokio::test]
async fn test_tls_full_acme_flow() {
    let server = start_tls_server().await;
    let base_url = server.base_url.clone();
    let domain = "tls-test.acme.example";

    tracing::info!("══ test_tls_full_acme_flow — domain: {} ══", domain);

    // ── Step 1: GET /acme/directory ──────────────────────────────────────────
    tracing::info!("Step 1: GET /acme/directory");
    let r = https(
        server.addr,
        "GET",
        "/acme/directory",
        &[],
        None,
        &server.ca_der,
    )
    .await;
    assert_eq!(r.status, 200);
    let dir: Value = serde_json::from_str(&r.body).unwrap();
    tracing::info!("  newAccount : {}", dir["newAccount"]);
    tracing::info!("  newNonce   : {}", dir["newNonce"]);
    tracing::info!("  newOrder   : {}", dir["newOrder"]);

    // ── Step 2: HEAD /acme/new-nonce ─────────────────────────────────────────
    tracing::info!("Step 2: HEAD /acme/new-nonce");
    let nr = https(
        server.addr,
        "HEAD",
        "/acme/new-nonce",
        &[],
        None,
        &server.ca_der,
    )
    .await;
    assert_eq!(nr.status, 200);
    let nonce = nr.headers["replay-nonce"].to_str().unwrap().to_string();
    tracing::info!("  Replay-Nonce = {}", nonce);

    // ── Step 3: POST /acme/new-account ───────────────────────────────────────
    tracing::info!("Step 3: POST /acme/new-account");
    let acme_key = AcmeKey::generate();
    let jws = acme_key.jws_with_jwk(
        &nonce,
        &format!("{base_url}/acme/new-account"),
        Some(json!({ "termsOfServiceAgreed": true })),
    );
    let r = https(
        server.addr,
        "POST",
        "/acme/new-account",
        &[("Content-Type", "application/jose+json")],
        Some(jws.to_string()),
        &server.ca_der,
    )
    .await;
    assert_eq!(r.status, 201, "new-account failed: {}", r.body);
    let account_url = r.headers["location"].to_str().unwrap().to_string();
    let nonce = r.headers["replay-nonce"].to_str().unwrap().to_string();
    let acct_body: Value = serde_json::from_str(&r.body).unwrap();
    tracing::info!("  account URL    = {}", account_url);
    tracing::info!("  account status = {}", acct_body["status"]);

    // ── Step 4: POST /acme/new-order ─────────────────────────────────────────
    tracing::info!("Step 4: POST /acme/new-order (domain: {})", domain);
    let jws = acme_key.jws_with_kid(
        &account_url,
        &nonce,
        &format!("{base_url}/acme/new-order"),
        Some(json!({ "identifiers": [{ "type": "dns", "value": domain }] })),
    );
    let r = https(
        server.addr,
        "POST",
        "/acme/new-order",
        &[("Content-Type", "application/jose+json")],
        Some(jws.to_string()),
        &server.ca_der,
    )
    .await;
    assert_eq!(r.status, 201, "new-order failed: {}", r.body);
    let order_url = r.headers["location"].to_str().unwrap().to_string();
    let nonce = r.headers["replay-nonce"].to_str().unwrap().to_string();
    let order_body: Value = serde_json::from_str(&r.body).unwrap();
    let order_id = order_url.split('/').next_back().unwrap().to_string();
    tracing::info!("  order URL     = {}", order_url);
    tracing::info!("  order status  = {}", order_body["status"]);
    tracing::info!("  order ID      = {}", order_id);

    // ── Step 5: bypass challenge validation ───────────────────────────────────
    tracing::info!("Step 5: bypassing challenge validation via direct DB update");
    mark_order_ready(&server.db, &order_id).await;
    tracing::info!("  challenges and authz marked valid; order status → ready");

    // ── Step 6: POST /acme/order/{id}/finalize ────────────────────────────────
    tracing::info!("Step 6: POST /acme/order/{}/finalize", order_id);
    let csr_der = make_csr_der(domain);
    let csr_b64 = URL_SAFE_NO_PAD.encode(&csr_der);
    let finalize_path = format!("/acme/order/{order_id}/finalize");
    let jws = acme_key.jws_with_kid(
        &account_url,
        &nonce,
        &format!("{base_url}{finalize_path}"),
        Some(json!({ "csr": csr_b64 })),
    );
    let r = https(
        server.addr,
        "POST",
        &finalize_path,
        &[("Content-Type", "application/jose+json")],
        Some(jws.to_string()),
        &server.ca_der,
    )
    .await;
    assert_eq!(r.status, 200, "finalize failed: {}", r.body);
    let final_body: Value = serde_json::from_str(&r.body).unwrap();
    let cert_url = final_body["certificate"]
        .as_str()
        .expect("finalize response missing 'certificate' URL")
        .to_string();
    tracing::info!("  finalize status = {}", final_body["status"]);
    tracing::info!("  certificate URL = {}", cert_url);
    assert_eq!(
        final_body["status"], "valid",
        "expected order status=valid after finalize"
    );

    // ── Step 7: GET /acme/cert/{id} ──────────────────────────────────────────
    let cert_path = cert_url
        .strip_prefix(&base_url)
        .unwrap_or(&cert_url)
        .to_string();
    tracing::info!("Step 7: GET {} (download certificate chain)", cert_path);
    let r = https(server.addr, "GET", &cert_path, &[], None, &server.ca_der).await;
    assert_eq!(r.status, 200, "cert download failed: {}", r.body);
    assert!(
        r.body.contains("-----BEGIN CERTIFICATE-----"),
        "certificate endpoint should return PEM"
    );
    let cert_count = r.body.matches("-----BEGIN CERTIFICATE-----").count();
    assert!(
        cert_count >= 2,
        "PEM bundle should contain leaf + CA (got {cert_count})"
    );
    tracing::info!(
        "  response contains {} PEM certificate block(s)",
        cert_count
    );

    // ── Certificate chain inspection ──────────────────────────────────────────
    log_certificate_chain("ACME-issued certificate chain", &r.body);

    // Verify the leaf cert contains the expected domain in its SAN.
    let leaf_der = pem_to_der(r.body.as_bytes());
    assert!(!leaf_der.is_empty(), "no DER extracted from PEM chain");
    let leaf_cert = Decoder::new(&leaf_der[0], Encoding::Der)
        .decode::<Certificate<'_>>()
        .expect("leaf cert DER must parse");
    let sans = leaf_cert.subject_alt_names();
    let has_domain = sans
        .iter()
        .any(|(tag, val)| *tag == 2 && val == domain.as_bytes());
    assert!(
        has_domain,
        "leaf certificate SAN must contain dNSName={domain}"
    );
    tracing::info!("✓ leaf certificate SAN contains dNSName={}", domain);
    tracing::info!("✓ complete ACME flow over TLS succeeded");
}

/// Verify that a client trusting a *different* CA cannot complete the TLS
/// handshake — the server certificate is not universally trusted.
#[tokio::test]
async fn test_tls_untrusted_ca_rejected() {
    let server = start_tls_server().await;

    tracing::info!("── test_tls_untrusted_ca_rejected ──────────────────────────");

    // Generate a fresh unrelated CA.
    let dir = tempfile::TempDir::new().unwrap();
    let unrelated_ca_cfg = CaConfig {
        key_file: dir
            .path()
            .join("other-ca.key")
            .to_string_lossy()
            .into_owned(),
        cert_file: dir
            .path()
            .join("other-ca.crt")
            .to_string_lossy()
            .into_owned(),
        key_type: "ec:P-256".into(),
        hash_alg: "sha256".into(),
        validity_days: 90,
        crl_url: None,
        ocsp_url: None,
        common_name: "Unrelated CA".into(),
        organization: "Other".into(),
        ca_validity_years: 10,
        crl_next_update_secs: 86400,
        enforce_validity_cap: false,
    };
    let (_, other_ca_der) = ca::init::load_or_generate(&unrelated_ca_cfg).unwrap();
    tracing::info!("Attempting TLS handshake with unrelated CA trust store…");

    let connector = TlsConnector::from(Arc::new(client_tls_config(&other_ca_der)));
    let stream = TcpStream::connect(server.addr).await.unwrap();
    let server_name = ServerName::try_from("localhost").unwrap();
    let result = connector.connect(server_name, stream).await;

    assert!(
        result.is_err(),
        "TLS handshake must fail when client trusts an unrelated CA"
    );
    tracing::info!("✓ handshake rejected as expected: {}", result.unwrap_err());
}
