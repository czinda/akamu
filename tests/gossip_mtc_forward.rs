//! Tests for `POST /gossip/mtc/append` (`src/gossip/mtc_forward.rs`) —
//! forwarding an MTC leaf-append to a CA's elected writer node.
//!
//! `MtcAppendRequest`/`MtcAppendOutcome` are private to that module, so these
//! tests mirror their wire shape locally (field-for-field) rather than
//! importing them — the same convention `tests/gossip_handlers.rs` uses for
//! `NodeIdentity`. Round-tripping through CBOR only depends on matching
//! field names/types, not on sharing the Rust type.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::{Deserialize, Serialize};
use synta_certificate::BackendPrivateKey;
use tower::ServiceExt;

use akamu::ca;
use akamu::config::{
    CaConfig, Config, DatabaseConfig, MtcConfig, MtcSigningKeyConfig, ServerConfig,
};
use akamu::db;
use akamu::gossip::crypto::{sign_and_seal, verify_and_open, SealRecipient};
use akamu::gossip::mtc_forward::MtcAppendSuccess;
use akamu::routes;
use akamu::state::{AppState, AppStateBuilder, CaState, MtcState};

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

/// Build an MTC-enabled `AppState` for `identity`, mirroring
/// `tests/common::build_test_state`'s CA/MTC setup combined with
/// `tests/gossip_handlers.rs`'s identity-based signing/KEM key wiring.
async fn build_mtc_gossip_state(identity: &NodeIdentity, base_url: &str) -> Arc<AppState> {
    use akamu::mtc::log;
    use synta_mtc::crypto::HashAlgorithm;

    let dir = tempfile::TempDir::new().unwrap();
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
            common_name: "MTC Forward Test CA".into(),
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
        admin: None,
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

    let ca = Arc::new(CaState {
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
        m.insert("default".to_string(), ca.clone());
        Arc::new(m)
    };

    AppStateBuilder::new(
        Arc::clone(&config),
        db_conn.clone(),
        db::DbKind::Sqlite,
        cas,
        Arc::new("default".to_string()),
    )
    .node_id(Arc::new(identity.node_id.clone()))
    .node_kem_priv(Arc::new(identity.kem_priv_pkcs8.clone()))
    .node_gossip_signing_priv(Arc::new(identity.sign_priv_pem.clone()))
    .node_gossip_signing_cert(Arc::new(identity.sign_cert_der.clone()))
    .build()
}

async fn pin_peer(state: &AppState, peer: &NodeIdentity, gossip_url: &str) {
    let now = akamu::util::unix_now();
    let mut crdt = state.crdt.write().await;
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

/// Format a Unix timestamp as an ASN.1 GeneralizedTime string
/// (`YYYYMMDDHHMMSSZ`), mirroring `src/ca/init.rs`'s private
/// `unix_to_generalized_time` helper (not visible from an integration test).
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
        .common_name("MTC Forward Test")
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

// ── Wire-shape mirrors of the private types in src/gossip/mtc_forward.rs ────

#[derive(Serialize)]
struct WireRequest {
    ca_id: String,
    cert_der: Vec<u8>,
    serial_number: String,
    issued_at: i64,
}

#[derive(Deserialize)]
enum WireOutcome {
    Ok(MtcAppendSuccess),
    NotWriter {
        current_writer: Option<(String, String)>,
    },
    Err(String),
}

fn build_signed_request(
    sender: &NodeIdentity,
    recipient_kem_pub_spki: &[u8],
    ca_id: &str,
    cert_der: &[u8],
    serial_number: &str,
    issued_at: i64,
) -> Vec<u8> {
    let req = WireRequest {
        ca_id: ca_id.to_owned(),
        cert_der: cert_der.to_owned(),
        serial_number: serial_number.to_owned(),
        issued_at,
    };
    let mut plaintext = Vec::new();
    ciborium::into_writer(&req, &mut plaintext).unwrap();
    sign_and_seal(
        &plaintext,
        &[SealRecipient {
            hint: "recipient",
            spki_der: recipient_kem_pub_spki,
        }],
        &sender.sign_priv_pem,
        &sender.sign_cert_der,
    )
    .unwrap()
}

async fn post_append(
    router: &axum::Router,
    node_id: Option<&str>,
    body: Vec<u8>,
) -> (StatusCode, Vec<u8>) {
    let mut req = Request::builder().method("POST").uri("/gossip/mtc/append");
    if let Some(id) = node_id {
        req = req.header("x-akamu-node-id", id);
    }
    let req = req.body(Body::from(body)).unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 10_000_000)
        .await
        .unwrap();
    (status, bytes.to_vec())
}

// ── Tests ────────────────────────────────────────────────────────────────────

/// A node that isn't (and never claimed) the elected writer for a CA must
/// reject a forwarded append with a `NotWriter` outcome, not silently append
/// to its own log — appending here would fork the transparency log.
#[tokio::test]
async fn append_rejects_when_receiver_is_not_the_writer() {
    let writer = generate_node_identity();
    let sender = generate_node_identity();
    let state = build_mtc_gossip_state(&writer, "https://writer.test").await;
    pin_peer(&state, &sender, "https://sender.test").await;
    let router = routes::build_router(Arc::clone(&state), None, false);

    let now = akamu::util::unix_now();
    let body = build_signed_request(
        &sender,
        &writer.kem_pub_spki,
        "default",
        &test_cert_der(1),
        "01",
        now,
    );
    let (status, resp_bytes) = post_append(&router, Some(&sender.node_id), body).await;
    assert_eq!(status, StatusCode::OK);

    let opened = verify_and_open(&resp_bytes, &sender.kem_priv_pkcs8, &writer.sign_pub_spki)
        .expect("verify_and_open response");
    let outcome: WireOutcome = ciborium::from_reader(opened.as_slice()).unwrap();
    assert!(
        matches!(
            outcome,
            WireOutcome::NotWriter {
                current_writer: None
            }
        ),
        "expected NotWriter with no current claimant"
    );
}

/// Golden path: once this node has claimed the writer election for the CA,
/// a forwarded append succeeds and returns a usable leaf_index/proof/
/// tree_size; retrying the identical request (same serial_number) must
/// return the cached result rather than appending the same cert twice.
#[tokio::test]
async fn append_succeeds_when_writer_and_is_idempotent_on_retry() {
    let writer = generate_node_identity();
    let sender = generate_node_identity();
    let state = build_mtc_gossip_state(&writer, "https://writer.test").await;
    pin_peer(&state, &sender, "https://sender.test").await;
    let router = routes::build_router(Arc::clone(&state), None, false);

    let now = akamu::util::unix_now();
    assert!(
        state
            .crdt
            .write()
            .await
            .claim_mtc_writer("default", &writer.node_id, now, 150),
        "test setup: writer must be able to claim its own election"
    );

    let cert_der = test_cert_der(7);
    let body = build_signed_request(
        &sender,
        &writer.kem_pub_spki,
        "default",
        &cert_der,
        "07",
        now,
    );
    let (status, resp_bytes) = post_append(&router, Some(&sender.node_id), body).await;
    assert_eq!(status, StatusCode::OK);
    let opened = verify_and_open(&resp_bytes, &sender.kem_priv_pkcs8, &writer.sign_pub_spki)
        .expect("verify_and_open response");
    let outcome: WireOutcome = ciborium::from_reader(opened.as_slice()).unwrap();
    let first = match outcome {
        WireOutcome::Ok(success) => success,
        WireOutcome::NotWriter { .. } => panic!("expected Ok, got NotWriter"),
        WireOutcome::Err(e) => panic!("expected Ok, got Err({e})"),
    };
    assert!(first.tree_size > 0);

    // Retry with the same serial_number but different cert bytes — must
    // return the SAME cached leaf_index/tree_size, proving it did not
    // append a second leaf.
    let retry_body = build_signed_request(
        &sender,
        &writer.kem_pub_spki,
        "default",
        &test_cert_der(999),
        "07",
        now,
    );
    let (status2, resp_bytes2) = post_append(&router, Some(&sender.node_id), retry_body).await;
    assert_eq!(status2, StatusCode::OK);
    let opened2 = verify_and_open(&resp_bytes2, &sender.kem_priv_pkcs8, &writer.sign_pub_spki)
        .expect("verify_and_open retry response");
    let outcome2: WireOutcome = ciborium::from_reader(opened2.as_slice()).unwrap();
    let second = match outcome2 {
        WireOutcome::Ok(success) => success,
        WireOutcome::NotWriter { .. } => panic!("expected Ok, got NotWriter"),
        WireOutcome::Err(e) => panic!("expected Ok, got Err({e})"),
    };
    assert_eq!(
        second.leaf_index, first.leaf_index,
        "retried forward must return the cached leaf_index, not append again"
    );
    assert_eq!(second.tree_size, first.tree_size);
}
