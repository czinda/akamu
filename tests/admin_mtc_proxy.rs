//! Integration test for the admin MTC read-through proxy
//! (`src/gossip/mtc_admin.rs`, `routes::mtc_proxy::admin_mtc_writer_proxy`)
//! — a non-writer node must forward an already-authorized admin MTC request
//! to the CA's elected writer over the authenticated gossip RPC and relay
//! back exactly what the writer's own handler would have returned, without
//! ever needing the operator's original credential to survive the hop.
//!
//! Node/identity setup mirrors `tests/mtc_proxy.rs`; admin session seeding
//! mirrors `tests/admin_rbac.rs::build_admin_state`.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde_json::Value;
use synta_certificate::BackendPrivateKey;
use synta_mtc::crypto::HashAlgorithm;
use tempfile::TempDir;
use tokio::net::TcpListener;

use akamu::config::{
    AdminConfig, CaConfig, Config, DatabaseConfig, MtcConfig, MtcSigningKeyConfig, ServerConfig,
};
use akamu::mtc::log;
use akamu::state::{
    AdminAuthMethod, AdminSession, AppState, AppStateBuilder, CaState, MtcState, OperatorRole,
};
use akamu::{ca, db, routes};

struct NodeIdentity {
    node_id: String,
    kem_priv_pkcs8: Vec<u8>,
    kem_pub_spki: Vec<u8>,
    sign_priv_pem: Vec<u8>,
    sign_cert_der: Vec<u8>,
    sign_pub_spki: Vec<u8>,
}

fn generate_node_identity() -> NodeIdentity {
    let sign_key = BackendPrivateKey::generate_ec("P-256").expect("ECDSA keygen");
    let sign_pub = sign_key.public_key().expect("signing pub key");
    let sign_pub_spki = sign_pub.spki_der().to_vec();
    let sign_priv_pem = sign_key.to_pem(None).expect("signing key to PEM");

    let aki = ca::init::compute_aki_from_spki(&sign_pub_spki).expect("compute AKI");
    let node_id = URL_SAFE_NO_PAD.encode(&aki);

    let native_sign_key =
        native_ossl::pkey::Pkey::<native_ossl::pkey::Private>::from_pem(&sign_priv_pem)
            .expect("native_ossl sign key from PEM");
    let mut name = native_ossl::x509::X509NameOwned::new().expect("X509Name");
    name.add_entry_by_txt(c"CN", node_id.as_bytes())
        .expect("CN");
    let serial: i64 = {
        let mut buf = [0u8; 7];
        native_ossl::rand::Rand::fill(&mut buf).expect("getrandom for cert serial");
        buf.iter().fold(0i64, |acc, &b| (acc << 8) | i64::from(b))
    };
    let sign_cert_der = native_ossl::x509::X509Builder::new()
        .expect("X509Builder")
        .set_version(2)
        .expect("version")
        .set_serial_number(serial)
        .expect("serial")
        .set_not_before_offset(0)
        .expect("not_before")
        .set_not_after_offset(365 * 86400)
        .expect("not_after")
        .set_subject_name(&name)
        .expect("subject")
        .set_issuer_name(&name)
        .expect("issuer")
        .set_public_key(&native_sign_key)
        .expect("pubkey")
        .sign(&native_sign_key, None)
        .expect("sign")
        .build()
        .to_der()
        .expect("to_der");

    let kem_key = native_ossl::pkey::KeygenCtx::new(c"ML-KEM-768")
        .expect("ML-KEM-768 ctx")
        .generate()
        .expect("ML-KEM-768 keygen");
    let kem_priv_pkcs8 = kem_key.to_pkcs8_der().expect("KEM PKCS8");
    let kem_pub_spki = kem_key.public_key_to_der().expect("KEM SPKI");

    NodeIdentity {
        node_id,
        kem_priv_pkcs8,
        kem_pub_spki,
        sign_priv_pem,
        sign_cert_der,
        sign_pub_spki,
    }
}

struct NodeHandle {
    state: Arc<AppState>,
    _tempdir: TempDir,
}

/// Build an MTC- and admin-enabled `AppState` for `identity`, with no
/// gossip loop — this test drives CRDT/session state directly.
async fn build_node(identity: &NodeIdentity, base_url: &str) -> NodeHandle {
    let dir = TempDir::new().unwrap();
    let mtc_log_path = dir.path().join("mtc.log").to_string_lossy().into_owned();
    let mtc_key_file = dir.path().join("mtc.key").to_string_lossy().into_owned();

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
            key_file: Some(dir.path().join("ca.key").to_string_lossy().into_owned()),
            cert_file: dir.path().join("ca.crt").to_string_lossy().into_owned(),
            key_type: "ec:P-256".into(),
            hash_alg: "sha256".into(),
            validity_days: 90,
            crl_url: None,
            ocsp_url: None,
            common_name: "Admin MTC Proxy Test CA".into(),
            organization: "Test Org".into(),
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
                key_type: "ed25519".into(),
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
        server: ServerConfig::default(),
        tls: Default::default(),
        profiles: Default::default(),
        linter: Default::default(),
        admin: Some(AdminConfig {
            bootstrap_key_type: "ec:P-256".into(),
            bootstrap_operator_cert_file: None,
            bootstrap_operator_key_file: None,
            bootstrap_operator_pkcs12_file: None,
            bootstrap_operator_pkcs12_password: "".into(),
            bootstrap_operator_name: "admin".into(),
            bootstrap_operator_gssapi_principal: None,
            proxy_auth: None,
            gssapi: None,
            session_ttl_secs: 3600,
            session_lock_secs: 900,
            auth_rate_limit: 20,
            audit_max_events: None,
            audit_overflow: "drop_oldest".into(),
            audit_alarm_threshold: 10,
            audit_alarm_action: "syslog".into(),
            max_failed_auth: 5,
            lockout_duration_secs: 1800,
        }),
        email_challenge: None,
        delegation_upstream: None,
        gossip: None,
        crdt_db_url: None,
        tkauth: None,
        policy: None,
    });

    let (ca_key, ca_cert_der) = ca::init::load_or_generate(config.default_ca()).unwrap();
    let ca_spki_der = ca_key.public_key().unwrap().spki_der().to_vec();
    let ca_aki_bytes = ca::init::compute_aki_from_spki(&ca_spki_der).unwrap_or_default();

    db::install_drivers();
    let db_conn = db::open("sqlite::memory:", 1, false).await.unwrap();

    let mtc_key = BackendPrivateKey::generate_ed25519().unwrap();
    std::fs::write(&mtc_key_file, mtc_key.to_pem(None).unwrap()).unwrap();
    let mtc_spki_der = mtc_key.public_key().unwrap().spki_der().to_vec();
    let logid_issuer_dn_der =
        akamu::mtc::standalone::build_logid_issuer_dn_der(&mtc_spki_der, HashAlgorithm::Sha256)
            .unwrap();

    let raw_log = log::open_or_create(&mtc_log_path, HashAlgorithm::Sha256).unwrap();
    let shared_log = Arc::new(tokio::sync::Mutex::new(raw_log));

    let ca_state = Arc::new(CaState {
        id: "default".into(),
        key_type: "ec:P-256".into(),
        crl_next_update_secs: 86400,
        signing: akamu::state::SigningBackend::Local {
            key: Box::new(ca_key),
        },
        cert_der: ca_cert_der,
        hash_alg: "sha256".into(),
        validity_days: 90,
        crl_url: None,
        ocsp_url: None,
        aki_bytes: ca_aki_bytes,
        enforce_validity_cap: false,
        caa_identities: vec![],
        mtc: Arc::new(MtcState {
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
            signing_key_sha256: None,
            tlog_origin: Some("oid/1.3.6.1.4.1.32473.2.0.1".into()),
            cosigner_name: Some("oid/1.3.6.1.4.1.32473.2".into()),
            logid_issuer_dn_der: Some(logid_issuer_dn_der),
        }),
        default_linter: None,
        cached_der: std::sync::OnceLock::new(),
        lint_store: std::sync::OnceLock::new(),
    });
    let cas = {
        let mut m = indexmap::IndexMap::new();
        m.insert("default".to_string(), ca_state.clone());
        Arc::new(m)
    };

    let sessions: Arc<tokio::sync::Mutex<HashMap<String, AdminSession>>> =
        Arc::new(tokio::sync::Mutex::new(HashMap::new()));
    sessions.lock().await.insert(
        "tok-admin".to_string(),
        AdminSession {
            operator_id: 1,
            name: akamu_util::SecretBuffer::from_string("test-admin".to_string()),
            role: OperatorRole::Administrator,
            ca_id: String::new(),
            created_at: Instant::now(),
            last_active_at: Instant::now(),
            auth_method: AdminAuthMethod::Cert,
        },
    );

    let state = AppStateBuilder::new(
        Arc::clone(&config),
        db_conn.clone(),
        db::DbKind::Sqlite,
        cas,
        Arc::new("default".to_string()),
    )
    .admin_sessions(sessions)
    .node_id(Arc::new(identity.node_id.clone()))
    .node_kem_priv(Arc::new(identity.kem_priv_pkcs8.clone()))
    .node_gossip_signing_priv(Arc::new(identity.sign_priv_pem.clone()))
    .node_gossip_signing_cert(Arc::new(identity.sign_cert_der.clone()))
    .build();

    NodeHandle {
        state,
        _tempdir: dir,
    }
}

fn pin_peer(crdt: &mut akamu_crdt::AkaCrdt, peer: &NodeIdentity, gossip_url: &str, now: i64) {
    crdt.cluster_nodes.upsert(
        peer.node_id.clone(),
        akamu_crdt::AkaNodeEntry {
            node_id: peer.node_id.clone(),
            gossip_url: gossip_url.to_string(),
            kem_public_key_der: peer.kem_pub_spki.clone(),
            gossip_signing_pub_key_der: peer.sign_pub_spki.clone(),
            gossip_signing_cert_der: peer.sign_cert_der.clone(),
            ca_ids: vec!["default".to_string()],
            registered_at: now,
        },
        now,
        &peer.node_id,
    );
}

fn unix_to_generalized_time(secs: i64) -> String {
    let gt = synta::GeneralizedTime::from_unix(secs)
        .unwrap_or_else(|| synta::GeneralizedTime::from_unix(0).unwrap());
    format!(
        "{:04}{:02}{:02}{:02}{:02}{:02}Z",
        gt.year, gt.month, gt.day, gt.hour, gt.minute, gt.second
    )
}

/// A minimal valid DER certificate, built with our own CA machinery —
/// mirrors `src/mtc/log.rs`'s private `test_cert_der` test helper.
fn test_cert_der(serial: i64) -> Vec<u8> {
    use synta_certificate::{
        default_key_id_hasher, encode_basic_constraints, encode_subject_key_identifier, parse_time,
        CertificateBuilder, KeyIdMethod, NameBuilder, PrivateKey as _,
    };

    let key = BackendPrivateKey::generate_ec("P-256").unwrap();
    let spki = key.public_key().unwrap().spki_der().to_vec();
    let name_der = NameBuilder::new()
        .common_name("Admin MTC Proxy Test")
        .build()
        .unwrap();
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let now = unix_to_generalized_time(now_secs);
    let exp = unix_to_generalized_time(now_secs + 86400);
    let hasher = default_key_id_hasher();
    let bc = encode_basic_constraints(false, None).unwrap();
    let ski =
        encode_subject_key_identifier(&spki, KeyIdMethod::Rfc7093Method1Sha256, &hasher).unwrap();
    let signer = key.as_signer("sha256");
    CertificateBuilder::new()
        .issuer_name(&name_der)
        .subject_name(&name_der)
        .public_key_der(&spki)
        .serial_number(synta::Integer::from_i64(serial))
        .not_valid_before(parse_time(&now).unwrap())
        .not_valid_after(parse_time(&exp).unwrap())
        .add_extension_oid(synta_certificate::oids::BASIC_CONSTRAINTS, false, &bc)
        .add_extension_oid(synta_certificate::oids::SUBJECT_KEY_IDENTIFIER, false, &ski)
        .sign(&signer)
        .unwrap()
}

/// A non-writer node's `GET /admin/mtc/tree-size` (Bearer-session
/// authenticated) must be forwarded to the writer and return *its* tree
/// size, not the non-writer's own stale local one — proving both that the
/// read-through RPC works and that an operator identity which could never
/// survive a raw HTTP relay (a per-node in-memory Bearer session) succeeds
/// end-to-end here.
#[tokio::test]
async fn non_writer_node_forwards_admin_mtc_reads_to_the_writer() {
    let listener_w = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let listener_n = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url_w = format!(
        "http://127.0.0.1:{}",
        listener_w.local_addr().unwrap().port()
    );
    let url_n = format!(
        "http://127.0.0.1:{}",
        listener_n.local_addr().unwrap().port()
    );

    let id_w = generate_node_identity();
    let id_n = generate_node_identity();

    let writer = build_node(&id_w, &url_w).await;
    let non_writer = build_node(&id_n, &url_n).await;

    let now = akamu::util::unix_now();
    assert!(writer
        .state
        .crdt
        .write()
        .await
        .claim_mtc_writer("default", &id_w.node_id, now, 150));

    {
        let ca_state = writer.state.get_ca("default").unwrap();
        let shared_log = ca_state.mtc.log.as_ref().unwrap();
        let logid_dn = ca_state.mtc.logid_issuer_dn_der.clone().unwrap();
        log::append_cert_to_log(
            shared_log,
            test_cert_der(1),
            logid_dn,
            HashAlgorithm::Sha256,
        )
        .await
        .unwrap();
    }
    let writer_tree_size = log::tree_size(
        writer
            .state
            .get_ca("default")
            .unwrap()
            .mtc
            .log
            .as_ref()
            .unwrap(),
    )
    .await
    .unwrap();
    assert!(writer_tree_size > 1);

    let non_writer_local_tree_size = log::tree_size(
        non_writer
            .state
            .get_ca("default")
            .unwrap()
            .mtc
            .log
            .as_ref()
            .unwrap(),
    )
    .await
    .unwrap();
    assert_ne!(non_writer_local_tree_size, writer_tree_size);

    {
        let mut crdt_n = non_writer.state.crdt.write().await;
        pin_peer(&mut crdt_n, &id_w, &url_w, now);
        assert!(crdt_n.claim_mtc_writer("default", &id_w.node_id, now, 150));
    }
    // The writer must also know the non-writer's identity to verify the
    // forwarded RPC's CMS signature.
    {
        let mut crdt_w = writer.state.crdt.write().await;
        pin_peer(&mut crdt_w, &id_n, &url_n, now);
    }

    let router_w = routes::build_router(Arc::clone(&writer.state), None, false);
    let router_n = routes::build_router(Arc::clone(&non_writer.state), None, false);
    tokio::spawn(async move {
        axum::serve(listener_w, router_w).await.unwrap();
    });
    tokio::spawn(async move {
        axum::serve(listener_n, router_n).await.unwrap();
    });
    tokio::time::sleep(Duration::from_millis(200)).await;

    let client = reqwest::Client::new();
    let resp = client
        .get(format!("{url_n}/admin/mtc/tree-size"))
        .header("authorization", "Bearer tok-admin")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(
        body["tree_size"].as_u64().unwrap(),
        writer_tree_size,
        "non-writer must forward to the writer's tree size, not its own stale local log"
    );
}
