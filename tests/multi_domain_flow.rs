//! Integration test: multi-domain HTTP-01 certificate issuance.
//!
//! Regression test for issue #32 — `akamu-cli issue` timed out when
//! multiple `--domain` identifiers were specified because the
//! authorization loop polled the order after each individual challenge
//! trigger instead of triggering all challenges first and polling once.
//!
//! This test creates an order with three DNS identifiers, solves all
//! HTTP-01 challenges, polls the order once, finalizes, and verifies
//! that the issued certificate contains all three SANs.

use std::sync::Arc;

use synta::{Decoder, Encoding};
use synta_certificate::{
    BackendPrivateKey, CsrBuilder, NameBuilder, PrivateKey as _, SubjectAlternativeNameBuilder,
};
use tokio::net::TcpListener;

use akamu::config::{CaConfig, Config, DatabaseConfig, MtcConfig, ServerConfig};
use akamu::state::{AppState, AppStateBuilder, CaState, MtcState};
use akamu::{ca, db, routes};

use akamu_client::{AccountKey, AccountOptions, AcmeClient, Identifier};

mod common;
use common::{bind_free_port, start_http01_solver};

// ── Akamu server setup (no MTC) ──────────────────────────────────────────────

async fn build_test_state(
    dir: &std::path::Path,
    base_url: &str,
    http01_port: u16,
) -> Arc<AppState> {
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
            common_name: "Multi-Domain Test CA".into(),
            organization: "Test".into(),
            ca_validity_years: 10,
            crl_next_update_secs: 86400,
            enforce_validity_cap: false,
            require_encrypted_key: false,
            key_password_file: None,
            mtc: None,
            signer: None,
            default_linter: None,
        }],
        linter: Default::default(),
        mtc: Some(MtcConfig {
            log_path: "/dev/null".into(),
            enabled: false,
            signing_key: None,
            checkpoint_interval_secs: 3600,
            cosigners: vec![],
            landmark_interval_secs: 86400,
            max_active_landmarks: 100,
            checkpoint_retention_count: 1000,
            hash_alg: "sha256".into(),
            log_number: 1,
            tree_minimum_index: None,
            trust_anchor_id: None,
            contact: None,
        }),
        server: ServerConfig {
            http_validation_port: http01_port,
            http_validation_allow_private_ips: true,
            ..Default::default()
        },
        tls: Default::default(),
        profiles: Default::default(),
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

    let ca = Arc::new(CaState {
        id: "default".into(),
        key_type: "ec:P-256".into(),
        signing: akamu::state::SigningBackend::Local {
            key: Box::new(ca_key),
        },
        cert_der: ca_cert_der,
        hash_alg: "sha256".into(),
        validity_days: 90,
        crl_url: None,
        ocsp_url: None,
        aki_bytes: ca_aki_bytes,
        crl_next_update_secs: 86400,
        enforce_validity_cap: false,
        caa_identities: vec![],
        mtc: Arc::new(MtcState::disabled()),
        default_linter: None,
    });

    AppStateBuilder::new(
        Arc::clone(&config),
        db_conn.clone(),
        db::DbKind::Sqlite,
        {
            let mut m = indexmap::IndexMap::new();
            m.insert("default".to_string(), ca.clone());
            Arc::new(m)
        },
        Arc::new("default".to_string()),
    )
    .node_id(Arc::new("test".to_string()))
    .build()
}

// ── The test ─────────────────────────────────────────────────────────────────

#[tokio::test]
async fn multi_domain_http01_issue() {
    let _ = tracing_subscriber::fmt().with_env_filter("warn").try_init();

    let domains = [
        "alpha.multi-test.localhost",
        "bravo.multi-test.localhost",
        "charlie.multi-test.localhost",
    ];

    let dir = tempfile::TempDir::new().unwrap();

    // Bind ports atomically.
    let (akamu_port, akamu_std_listener) = bind_free_port();
    let (http01_port, http01_std_listener) = bind_free_port();

    // Start the HTTP-01 challenge responder.
    let challenge_store = start_http01_solver(http01_std_listener).await;

    // Build and start the ACME server.
    let base_url = format!("http://127.0.0.1:{akamu_port}");
    let state = build_test_state(dir.path(), &base_url, http01_port).await;
    let router = routes::build_router(Arc::clone(&state), None);

    let listener = TcpListener::from_std(akamu_std_listener).expect("tokio TcpListener from std");
    tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // ── ACME flow ────────────────────────────────────────────────────────────
    let dir_url = format!("{base_url}/acme/directory");
    let acme = AcmeClient::new(&dir_url)
        .await
        .expect("ACME directory fetch");

    let account_key = Arc::new(AccountKey::generate("ec:P-256").unwrap());
    let account = acme
        .new_account(
            Arc::clone(&account_key),
            &AccountOptions {
                contacts: &[],
                agree_tos: true,
                eab: None,
            },
        )
        .await
        .expect("new_account");

    // Create an order with three DNS identifiers.
    let ids: Vec<Identifier> = domains.iter().map(|d| Identifier::dns(*d)).collect();
    let order = acme.new_order(&account, &ids).await.expect("new_order");

    assert_eq!(
        order.authorizations.len(),
        domains.len(),
        "server must create one authorization per identifier"
    );

    // Trigger all challenges before polling (the fix for issue #32).
    for auth_url in &order.authorizations {
        let auth = acme
            .get_authorization(&account, auth_url)
            .await
            .expect("get_authorization");

        if auth.status == "valid" {
            continue;
        }

        let challenge = auth
            .find_challenge("http-01")
            .expect("http-01 challenge not found");

        let token = challenge.token.as_deref().expect("challenge token");
        let key_auth = account.key_authorization(token);

        challenge_store
            .write()
            .unwrap()
            .insert(token.to_owned(), key_auth);

        acme.trigger_challenge(&account, challenge)
            .await
            .expect("trigger_challenge");
    }

    // Poll the order ONCE — it should become "ready" after all three
    // authorizations are validated.
    let ready_order = acme
        .poll_order(&account, &order.url, std::time::Duration::from_secs(30))
        .await
        .expect("poll_order: all authorizations should be valid");

    assert!(
        ready_order.status == "ready" || ready_order.status == "valid",
        "order status should be ready or valid, got: {}",
        ready_order.status
    );

    // Build a multi-domain CSR.
    let ee_key = BackendPrivateKey::generate_ec("P-256").unwrap();
    let spki_der = ee_key.public_key().unwrap().spki_der().to_vec();
    let name_der = NameBuilder::new().common_name(domains[0]).build().unwrap();
    let mut san_builder = SubjectAlternativeNameBuilder::new();
    for d in &domains {
        san_builder = san_builder.dns_name(d);
    }
    let san_der = san_builder.build().unwrap();
    let signer = ee_key.as_signer("sha256");
    let csr_der = CsrBuilder::new()
        .subject_name(&name_der)
        .public_key_der(&spki_der)
        .add_extension_oid(synta_certificate::oids::SUBJECT_ALT_NAME, false, &san_der)
        .sign(&signer)
        .unwrap();

    // Finalize the order.
    let finalized = acme
        .finalize(&account, &ready_order, &csr_der)
        .await
        .expect("finalize");

    let valid_order = if finalized.certificate.is_some() {
        finalized
    } else {
        acme.poll_order(&account, &finalized.url, std::time::Duration::from_secs(30))
            .await
            .expect("poll_order valid")
    };

    // Download the certificate.
    let cert_url = valid_order.certificate.expect("certificate URL");
    let cert_pem = acme
        .download_certificate(&account, &cert_url)
        .await
        .expect("download certificate");

    // Verify all three SANs are present in the leaf certificate.
    let ders = synta_certificate::pem_to_der(&cert_pem);
    assert!(
        !ders.is_empty(),
        "PEM must contain at least one certificate"
    );
    let leaf: synta_certificate::Certificate =
        Decoder::new(&ders[0], Encoding::Der).decode().unwrap();
    let sans = leaf.subject_alt_names();
    let san_names: Vec<&str> = sans
        .iter()
        .filter_map(|(tag, val)| {
            if *tag == 2 {
                std::str::from_utf8(val).ok()
            } else {
                None
            }
        })
        .collect();

    for d in &domains {
        assert!(
            san_names.contains(d),
            "certificate missing SAN for {d}; found: {san_names:?}"
        );
    }
}
