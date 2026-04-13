//! External ACME client compatibility test.
//!
//! Uses `instant-acme` (an independent RFC 8555 client library) to perform a
//! complete ACME flow against a live Akāmu server.  This test is structurally
//! independent of the hand-rolled JWS code in `acme_flow.rs` — it brings its
//! own key generation, JWS signing, and HTTP client.
//!
//! Server: runs in plain-HTTP mode so `instant-acme` can connect without
//! custom CA trust.  The http-01 challenge responder listens on a random high
//! port; Akāmu is configured to validate against that port via
//! `server.http_validation_port` (the feature added to fix port-80 testing).
//!
//! Run with:
//!   cargo test --test acme_client_compat -- --nocapture

use std::{collections::HashMap, net::SocketAddr, sync::Arc};

use axum::{
    extract::{Path, State},
    routing::get,
    Router,
};
use instant_acme::{
    Account, ChallengeType, ExternalAccountKey, Identifier, NewAccount, NewOrder, OrderStatus,
};
use synta::{Decoder, Encoding};
use synta_certificate::{
    format_dn, pem_to_der, BackendPrivateKey, Certificate, CsrBuilder, NameBuilder,
    PrivateKey as _, SubjectAlternativeNameBuilder,
};
use tokio::{net::TcpListener, sync::RwLock};

use akamu::{
    ca,
    config::{CaConfig, Config, DatabaseConfig, MtcConfig, ServerConfig},
    db, routes,
    state::{AppState, CaState, MtcState},
};

// ── Tracing ───────────────────────────────────────────────────────────────────

fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_test_writer()
        // compact()          — renders span fields inline; one log line per HTTP exchange
        // with_target(false) — omits module-path prefixes like "tower_http::trace::on_response:"
        .compact()
        .with_target(false)
        // tower_http=debug   — one "finished processing request" line per HTTP call
        //                      (on_request and on_eos are suppressed in build_router)
        // acme_server=debug  — server-side business logic (validation, CA signing, DB)
        // instant_acme=debug — client-side JWS, nonce refresh, retry logic
        .with_env_filter("tower_http=debug,acme_server=debug,instant_acme=debug,info")
        .try_init();
}

// ── Challenge token store (shared between responder and test) ─────────────────

type TokenStore = Arc<RwLock<HashMap<String, String>>>;

/// Start a plain-HTTP challenge responder on a random port.
///
/// Responds to `GET /.well-known/acme-challenge/<token>` with the pre-registered
/// key authorization string.  Tokens are registered via the returned `TokenStore`.
async fn start_challenge_responder() -> (SocketAddr, TokenStore) {
    let store: TokenStore = Arc::new(RwLock::new(HashMap::new()));
    let router = Router::new()
        .route(
            "/.well-known/acme-challenge/{token}",
            get(
                |State(s): State<TokenStore>, Path(token): Path<String>| async move {
                    s.read().await.get(&token).cloned().unwrap_or_default()
                },
            ),
        )
        .with_state(store.clone());

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, router).await.ok() });
    (addr, store)
}

// ── Akāmu server (plain HTTP) ─────────────────────────────────────────────────

struct PlainServer {
    base_url: String,
}

/// Start a plain-HTTP Akāmu server with `http_validation_port` pointing at the
/// challenge responder.
async fn start_plain_server(http_validation_port: u16) -> PlainServer {
    let dir = tempfile::TempDir::new().unwrap();
    let ca_key_path = dir.path().join("ca.key").to_string_lossy().into_owned();
    let ca_cert_path = dir.path().join("ca.crt").to_string_lossy().into_owned();

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let addr = listener.local_addr().unwrap();
    let base_url = format!("http://127.0.0.1:{}", addr.port());

    let config = Arc::new(Config {
        listen_addr: addr.to_string(),
        base_url: base_url.clone(),
        database: DatabaseConfig {
            path: ":memory:".into(),
        },
        ca: CaConfig {
            key_file: ca_key_path,
            cert_file: ca_cert_path,
            key_type: "ec:P-256".into(),
            hash_alg: "sha256".into(),
            validity_days: 90,
            crl_url: None,
            ocsp_url: None,
            common_name: "Compat Test CA".into(),
            organization: "Test".into(),
            ca_validity_years: 10,
        },
        mtc: MtcConfig {
            log_path: "/dev/null".into(),
            enabled: false,
        },
        server: ServerConfig {
            http_validation_port,
            ..ServerConfig::default()
        },
        tls: Default::default(),
    });

    let (ca_key, ca_cert_der) = ca::init::load_or_generate(&config.ca).unwrap();
    tracing::info!(
        subject = %synta_certificate::format_dn(
            synta_certificate::pem_to_der(&std::fs::read(&config.ca.cert_file).unwrap())
                .first()
                .and_then(|der| {
                    let cert: synta_certificate::Certificate =
                        synta::Decoder::new(der, synta::Encoding::Der).decode().ok()?;
                    Some(cert.tbs_certificate.subject.as_bytes().to_vec())
                })
                .as_deref()
                .unwrap_or(&[])
        ),
        "CA initialised"
    );

    let db_conn = db::open(":memory:").await.unwrap();
    let state = Arc::new(AppState {
        config: Arc::clone(&config),
        db: db_conn,
        ca: Arc::new(CaState {
            key: ca_key,
            cert_der: ca_cert_der,
            hash_alg: "sha256".into(),
            validity_days: 90,
            crl_url: None,
            ocsp_url: None,
            aki_bytes: Vec::new(),
        }),
        mtc: Arc::new(MtcState {
            log: None,
            algorithm: synta_mtc::crypto::HashAlgorithm::Sha256,
        }),
        tls: None,
        spki_cache: Arc::new(std::sync::RwLock::new(std::collections::HashMap::new())),
        link_header: Arc::new(axum::http::HeaderValue::from_static(
            "<https://acme.test/acme/directory>;rel=\"index\"",
        )),
        validation_client: hyper_util::client::legacy::Client::builder(
            hyper_util::rt::TokioExecutor::new(),
        )
        .build_http::<http_body_util::Empty<hyper::body::Bytes>>(),
    });

    let router = routes::build_router(state);
    let tokio_listener = tokio::net::TcpListener::from_std(listener).unwrap();
    tokio::spawn(async move {
        let _keep_dir = dir;
        axum::serve(tokio_listener, router).await.ok();
    });

    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    PlainServer { base_url }
}

// ── CSR builder ───────────────────────────────────────────────────────────────

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

// ── Certificate chain logger ──────────────────────────────────────────────────

fn log_certificate_chain(label: &str, pem: &str) {
    let ders = pem_to_der(pem.as_bytes());
    tracing::info!("{label}: {} certificate(s) in chain", ders.len());
    for (i, der) in ders.iter().enumerate() {
        let Ok(cert) = Decoder::new(der, Encoding::Der).decode::<Certificate>() else {
            tracing::warn!("  [{i}] failed to parse certificate");
            continue;
        };
        let tbs = &cert.tbs_certificate;
        let subject = format_dn(tbs.subject.as_bytes());
        let issuer = format_dn(tbs.issuer.as_bytes());
        let serial: String = tbs
            .serial_number
            .as_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(":");
        let sans: Vec<String> = cert
            .subject_alt_names()
            .iter()
            .map(|(tag, val)| match tag {
                2 => format!("DNS:{}", String::from_utf8_lossy(val)),
                7 => format!(
                    "IP:{}",
                    val.iter()
                        .map(|b| b.to_string())
                        .collect::<Vec<_>>()
                        .join(".")
                ),
                _ => format!(
                    "tag{}:{}",
                    tag,
                    val.iter().map(|b| format!("{b:02x}")).collect::<String>()
                ),
            })
            .collect();
        tracing::info!(
            "  [{i}] subject={subject} issuer={issuer} serial={serial} SAN=[{}]",
            sans.join(", ")
        );
    }
}

// ── Test ──────────────────────────────────────────────────────────────────────

/// Full ACME flow using `instant-acme` as an independent client.
///
/// Steps:
///   1. Start http-01 challenge responder on a random high port.
///   2. Start Akāmu (plain HTTP) pointed at that responder port.
///   3. Create ACME account via instant-acme.
///   4. Create order for `test.example.com`.
///   5. Extract http-01 challenge token + key authorization.
///   6. Register token/key-auth in the challenge responder.
///   7. Tell instant-acme to mark the challenge ready (POST to ACME server).
///   8. Poll until order transitions to `ready`.
///   9. Finalize with a DER CSR (synta-generated).
///  10. Poll until certificate is available and verify the SAN.
#[tokio::test]
async fn test_instant_acme_http01_flow() {
    init_tracing();

    // 1. Challenge responder.
    let (responder_addr, challenge_store) = start_challenge_responder().await;
    tracing::info!("challenge responder listening at {responder_addr}");

    // 2. Akāmu server.
    let server = start_plain_server(responder_addr.port()).await;
    let dir_url = format!("{}/acme/directory", server.base_url);
    tracing::info!("ACME directory: {dir_url}");

    // 3. Create ACME account (plain HTTP connector; instant-acme DefaultClient is HTTPS-only).
    let plain_http = hyper_14::Client::new();
    let (account, _credentials) = Account::create_with_http(
        &NewAccount {
            contact: &["mailto:compat-test@example.com"],
            terms_of_service_agreed: true,
            only_return_existing: false,
        },
        &dir_url,
        None::<&ExternalAccountKey>,
        Box::new(plain_http),
    )
    .await
    .expect("create ACME account");
    tracing::info!("ACME account created");

    // 4. Create order.
    // Use "localhost" so Akāmu can reach the challenge responder on 127.0.0.1.
    // test.example.com does not resolve locally, causing http-01 validation to fail.
    let domain = "localhost";
    let mut order = account
        .new_order(&NewOrder {
            identifiers: &[Identifier::Dns(domain.into())],
        })
        .await
        .expect("new order");
    tracing::info!("order created, status: {:?}", order.state().status);

    // 5–7. Handle authorizations.
    let authorizations = order.authorizations().await.expect("authorizations");
    for authz in &authorizations {
        let Some(challenge) = authz
            .challenges
            .iter()
            .find(|c| c.r#type == ChallengeType::Http01)
        else {
            panic!("no http-01 challenge in authorization");
        };

        let key_auth = order.key_authorization(challenge);
        tracing::info!(
            "http-01: token={} key_auth={}",
            challenge.token,
            key_auth.as_str()
        );

        // 6. Register in the challenge responder.
        challenge_store
            .write()
            .await
            .insert(challenge.token.clone(), key_auth.as_str().to_string());

        // 7. Tell the ACME server the challenge is ready for validation.
        order
            .set_challenge_ready(&challenge.url)
            .await
            .expect("set challenge ready");
        tracing::info!(
            "challenge marked ready, Akāmu will validate against port {}",
            responder_addr.port()
        );
    }

    // 8. Poll until order is ready (Akāmu validates http-01 asynchronously).
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        let state = order.refresh().await.expect("refresh order");
        tracing::info!("order status: {:?}", state.status);
        match state.status {
            OrderStatus::Ready => break,
            OrderStatus::Pending | OrderStatus::Processing => {}
            other => panic!("unexpected order status: {other:?}"),
        }
        if std::time::Instant::now() > deadline {
            panic!("timed out waiting for order to become ready");
        }
    }
    tracing::info!("order is ready");

    // 9. Finalize with a synta-generated CSR.
    let csr = make_csr_der(domain);
    order.finalize(&csr).await.expect("finalize order");
    tracing::info!("order finalized");

    // 10. Poll until certificate is available.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    let cert_chain_pem = loop {
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        match order.certificate().await.expect("poll certificate") {
            Some(pem) => break pem,
            None => {}
        }
        if std::time::Instant::now() > deadline {
            panic!("timed out waiting for certificate");
        }
    };

    tracing::info!("certificate downloaded ({} bytes)", cert_chain_pem.len());
    log_certificate_chain("instant-acme issued cert", &cert_chain_pem);

    // Verify: leaf certificate must contain the correct SAN.
    let ders = pem_to_der(cert_chain_pem.as_bytes());
    assert!(!ders.is_empty(), "certificate chain must not be empty");
    let leaf: Certificate = Decoder::new(&ders[0], Encoding::Der)
        .decode()
        .expect("parse leaf certificate");
    let san_ok = leaf
        .subject_alt_names()
        .iter()
        .any(|(tag, val)| *tag == 2 && std::str::from_utf8(val).ok() == Some(domain));
    assert!(san_ok, "leaf certificate SAN must contain {domain}");
    tracing::info!("✓ SAN verified: certificate contains dNSName={domain}");
}
