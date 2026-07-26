//! Integration test: exercise `MtcClient` against a running akamu server.
//!
//! Flow:
//!  1. Start akamu with MTC enabled (no external cosigner needed).
//!  2. Issue a certificate via `AcmeClient`.
//!  3. Force a checkpoint via `produce_checkpoint()`.
//!  4. Use `MtcClient` to query every log endpoint and verify responses.
//!  5. End-to-end: fetch standalone cert → parse → compute leaf hash →
//!     fetch root → verify inclusion proof.

use std::sync::Arc;

use synta_certificate::{
    BackendPrivateKey, NameBuilder, PrivateKey as _, SubjectAlternativeNameBuilder,
};
use synta_mtc::crypto::HashAlgorithm;
use tokio::net::TcpListener;

use akamu::config::{
    CaConfig, Config, DatabaseConfig, MtcConfig, MtcSigningKeyConfig, ServerConfig,
};
use akamu::mtc::checkpoint::{produce_checkpoint, CheckpointParams};
use akamu::mtc::log;
use akamu::state::{AppState, AppStateBuilder, CaState, MtcState};
use akamu::{ca, db, routes};

use akamu_client::mtc_types::CertFetchResult;
use akamu_client::mtc_verify;
use akamu_client::{
    cert_id_from_url, AccountKey, AccountOptions, AcmeClient, Identifier, MtcClient,
};

mod common;
use common::{bind_free_port, start_http01_solver};

// ── server setup (simplified — no cosigner) ─────────────────────────────────

async fn build_state(dir: &std::path::Path, base_url: &str, http01_port: u16) -> Arc<AppState> {
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
            common_name: "MTC Client Test CA".into(),
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
                key_type: "ec:P-256".into(),
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
            friendly_name: None,
        }),
        server: ServerConfig {
            http_validation_port: http01_port,
            http_validation_allow_private_ips: true,
            ..Default::default()
        },
        tls: Default::default(),
        profiles: Default::default(),
        linter: Default::default(),
        admin: None,
        email_challenge: None,
        delegation_upstream: None,
        tkauth: None,
        gossip: None,
        crdt_db_url: None,
    });

    let (ca_key, ca_cert_der) = ca::init::load_or_generate(config.default_ca()).unwrap();
    let ca_spki_der = ca_key.public_key().unwrap().spki_der().to_vec();
    let ca_aki_bytes = ca::init::compute_aki_from_spki(&ca_spki_der).unwrap_or_default();

    db::install_drivers();
    let db_conn = db::open("sqlite::memory:", 1, false).await.unwrap();

    let mtc_key = BackendPrivateKey::generate_ec("P-256").unwrap();
    let mtc_key_pem = mtc_key.to_pem(None).unwrap();
    std::fs::write(&mtc_key_file, &mtc_key_pem).unwrap();

    let raw_log = log::open_or_create(&mtc_log_path, HashAlgorithm::Sha256).unwrap();
    let shared_log = Arc::new(tokio::sync::Mutex::new(raw_log));

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
        mtc: {
            let mtc_spki = mtc_key.public_key().unwrap().spki_der().to_vec();
            let logid_dn =
                akamu::mtc::standalone::build_logid_issuer_dn_der(&mtc_spki, HashAlgorithm::Sha256)
                    .unwrap();
            use synta_certificate::DataHasher as _;
            let mtc_key_hash = synta_certificate::default_data_hasher()
                .hash_data("sha256", &mtc_spki)
                .unwrap();
            let mtc_key_sha256 = native_ossl::util::hex_encode(&mtc_key_hash);
            Arc::new(MtcState {
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
                friendly_name: None,
                signing_key_sha256: Some(mtc_key_sha256),
                tlog_origin: Some("oid/1.3.6.1.4.1.32473.2.0.1".into()),
                cosigner_name: Some("oid/1.3.6.1.4.1.32473.2".into()),
                logid_issuer_dn_der: Some(logid_dn),
            })
        },
        default_linter: None,
        cached_der: std::sync::OnceLock::new(),
        lint_store: std::sync::OnceLock::new(),
    });

    let cas = {
        let mut m = indexmap::IndexMap::new();
        m.insert("default".to_string(), ca);
        Arc::new(m)
    };

    AppStateBuilder::new(
        Arc::clone(&config),
        db_conn,
        db::DbKind::Sqlite,
        cas,
        Arc::new("default".to_string()),
    )
    .node_id(Arc::new("test".to_string()))
    .build()
}

// ── test ─────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn mtc_client_queries_and_verify() {
    let _ = tracing_subscriber::fmt().with_env_filter("warn").try_init();

    let dir = tempfile::TempDir::new().unwrap();
    let (akamu_port, akamu_std_listener) = bind_free_port();
    let (http01_port, http01_std_listener) = bind_free_port();
    let challenge_store = start_http01_solver(http01_std_listener).await;

    let base_url = format!("http://127.0.0.1:{akamu_port}");
    let state = build_state(dir.path(), &base_url, http01_port).await;
    let router = routes::build_router(Arc::clone(&state), None, false);

    let listener = TcpListener::from_std(akamu_std_listener).expect("tokio TcpListener");
    tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // ── ACME flow: register + issue ─────────────────────────────────────────
    let dir_url = format!("{base_url}/acme/directory");
    let acme = AcmeClient::new(&dir_url).await.expect("ACME directory");

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

    let order = acme
        .new_order(&account, &[Identifier::ip("127.0.0.1")])
        .await
        .expect("new_order");

    for auth_url in &order.authorizations {
        let auth = acme
            .get_authorization(&account, auth_url)
            .await
            .expect("get_authorization");
        if auth.status == "valid" {
            continue;
        }
        let challenge = auth.find_challenge("http-01").expect("http-01 challenge");
        let token = challenge.token.as_deref().expect("token");
        let key_auth = account_key.key_authorization(token);
        challenge_store
            .write()
            .unwrap()
            .insert(token.to_owned(), key_auth);
        acme.trigger_challenge(&account, challenge)
            .await
            .expect("trigger_challenge");
    }

    let ready = acme
        .poll_order(&account, &order.url, std::time::Duration::from_secs(30))
        .await
        .expect("poll ready");

    let ee_key = BackendPrivateKey::generate_ec("P-256").unwrap();
    let spki_der = ee_key.public_key().unwrap().spki_der().to_vec();
    let name_der = NameBuilder::new().common_name("127.0.0.1").build().unwrap();
    let san_der = SubjectAlternativeNameBuilder::new()
        .ip_address(&[127, 0, 0, 1])
        .build()
        .unwrap();
    let csr_der = synta_certificate::CsrBuilder::new()
        .subject_name(&name_der)
        .public_key_der(&spki_der)
        .add_extension_oid(synta_certificate::oids::SUBJECT_ALT_NAME, false, &san_der)
        .sign(&ee_key.as_signer("sha256"))
        .unwrap();

    let finalized = acme
        .finalize(&account, &ready, &csr_der)
        .await
        .expect("finalize");
    let valid = acme
        .poll_order(&account, &finalized.url, std::time::Duration::from_secs(30))
        .await
        .expect("poll valid");

    let cert_url = valid.certificate.expect("certificate URL");
    let cert_id = cert_id_from_url(&cert_url).expect("cert_id").to_owned();

    // ── Checkpoint ──────────────────────────────────────────────────────────
    {
        let ca = state.default_ca();
        let mtc = &ca.mtc;
        let origin = mtc.tlog_origin();
        produce_checkpoint(CheckpointParams {
            log: mtc.log.as_ref().expect("MTC log"),
            signing_key: mtc.signing_key.as_ref().expect("MTC signing key"),
            signing_hash_alg: &mtc.signing_hash_alg,
            log_algorithm: mtc.algorithm,
            db: &state.db,
            ca_id: &ca.id,
            cosigners: &mtc.cosigner_clients,
            log_number: mtc.log_number,
            tree_minimum_index: mtc.tree_minimum_index,
            trust_anchor_id_der: mtc.trust_anchor_id_der.as_deref(),
            log_origin: origin,
        })
        .await
        .expect("produce_checkpoint");
    }
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    // ── MtcClient queries ───────────────────────────────────────────────────
    let mtc = MtcClient::new(&dir_url).expect("MtcClient");

    let ts = mtc.tree_size().await.expect("tree_size");
    assert!(ts.tree_size > 0, "tree must be non-empty after checkpoint");

    let root = mtc.root().await.expect("root");
    assert_eq!(root.tree_size, ts.tree_size);
    assert!(!root.root_hash.is_empty(), "root hash must be non-empty");

    let proof = mtc
        .inclusion_proof(&cert_id)
        .await
        .expect("inclusion_proof");
    assert_eq!(proof.tree_size, ts.tree_size);

    let standalone_der = mtc
        .standalone_cert(&cert_id)
        .await
        .expect("standalone_cert");
    assert!(!standalone_der.is_empty());

    let _landmarks = mtc.landmarks().await.expect("landmarks");

    let _landmark_list = mtc.landmark_list().await.expect("landmark_list");

    let checkpoint_text = mtc.tlog_checkpoint().await.expect("checkpoint");
    assert!(!checkpoint_text.is_empty());

    let revoked = mtc.revoked_ranges().await.expect("revoked_ranges");
    assert!(revoked.is_empty(), "no revocations expected");

    // landmark cert for this cert_id
    match mtc
        .landmark_cert_for(&cert_id)
        .await
        .expect("landmark_cert_for")
    {
        CertFetchResult::Ok(der) => assert!(!der.is_empty()),
        CertFetchResult::RetryAfter(_) => {}
    }

    // ── End-to-end verification ─────────────────────────────────────────────
    let (details, mtc_proof) =
        mtc_verify::extract_cert_and_proof(&standalone_der).expect("parse standalone");

    let leaf_hash = mtc_verify::compute_leaf_hash(&standalone_der, HashAlgorithm::Sha256)
        .expect("compute_leaf_hash");

    let sr = mtc
        .subtree_root(mtc_proof.start, mtc_proof.end)
        .await
        .expect("subtree_root");
    let root_hash = mtc_verify::parse_hex_hash(&sr.root_hash).expect("parse subtree/root hash");

    mtc_verify::verify_standalone_inclusion(
        &leaf_hash,
        details.entry_index,
        &mtc_proof,
        &root_hash,
        HashAlgorithm::Sha256,
    )
    .expect("inclusion proof verification must pass");
}
