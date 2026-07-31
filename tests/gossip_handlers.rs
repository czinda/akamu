//! Tests for the gossip HTTP handlers (`src/gossip/handlers.rs`) — the
//! network-facing attack surface for inter-node CRDT sync, mounted
//! unauthenticated (by admin-session standards) on the public listener.
//!
//! `tests/gossip_bootstrap.rs` (marked `#[ignore]`) proves full propagation
//! works end to end over real HTTP sockets, but never exercises the
//! handler's individual fail-closed branches. These tests call the router
//! directly via `oneshot`, so no network sockets or background gossip loop
//! are needed.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::response::IntoResponse as _;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use synta_certificate::BackendPrivateKey;
use tower::ServiceExt;

use akamu::ca;
use akamu::config::{CaConfig, Config, DatabaseConfig, MtcConfig, ServerConfig};
use akamu::db;
use akamu::gossip::crypto::{sign_and_seal, verify_and_open, SealRecipient};
use akamu::gossip::envelope::GossipEnvelope;
use akamu::routes;
use akamu::state::{AppState, AppStateBuilder, CaState, MtcState};

// ── Node identity (mirrors tests/gossip_bootstrap.rs's helper — duplicated
// rather than shared, since it's a small self-contained crypto routine and
// the two test binaries can't share private items) ─────────────────────────

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

// ── State builder (no TCP listener — handlers are exercised via `oneshot`) ──

async fn build_gossip_state(identity: &NodeIdentity, base_url: &str) -> Arc<AppState> {
    let dir = tempfile::TempDir::new().unwrap();

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
            common_name: "Gossip Test CA".into(),
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
    akamu_crdt::db::init_db_kind(false, false);

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
        mtc: Arc::new(MtcState::disabled()),
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

/// Pre-pin a peer's gossip keys in `state`'s CRDT, as `gossip_register` would.
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
    );
}

/// Build a signed+sealed gossip request body carrying an empty CRDT.
fn build_signed_envelope(
    sender: &NodeIdentity,
    recipient_kem_pub_spki: &[u8],
    issued_at: i64,
    nonce: Vec<u8>,
) -> Vec<u8> {
    let crdt = akamu_crdt::AkaCrdt::default();
    let envelope = GossipEnvelope {
        crdt: GossipEnvelope::encode_crdt(&crdt).unwrap(),
        issued_at,
        is_delta: false,
        my_gen: 0,
        request_delta_since: None,
        nonce,
    };
    let plaintext = envelope.encode().unwrap();
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

async fn post_gossip_sync(
    router: &axum::Router,
    node_id: Option<&str>,
    body: Vec<u8>,
) -> (StatusCode, Vec<u8>) {
    let mut req = Request::builder().method("POST").uri("/gossip/sync");
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

#[tokio::test]
async fn gossip_sync_rejects_missing_node_id_header() {
    let a = generate_node_identity();
    let state_a = build_gossip_state(&a, "https://a.test").await;
    let router = routes::build_router(Arc::clone(&state_a), None, false);

    let (status, _) = post_gossip_sync(&router, None, b"irrelevant".to_vec()).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn gossip_sync_rejects_oversized_node_id_header() {
    let a = generate_node_identity();
    let state_a = build_gossip_state(&a, "https://a.test").await;
    let router = routes::build_router(Arc::clone(&state_a), None, false);

    let oversized_id = "x".repeat(65);
    let (status, _) = post_gossip_sync(&router, Some(&oversized_id), b"irrelevant".to_vec()).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

/// Fail-closed guarantee: a sender whose signing/KEM keys have not been
/// pinned via `gossip_register` must be rejected outright — no amount of
/// well-formed CMS wrapping can substitute for an operator-approved pin.
#[tokio::test]
async fn gossip_sync_rejects_unknown_sender() {
    let a = generate_node_identity();
    let state_a = build_gossip_state(&a, "https://a.test").await;
    let router = routes::build_router(Arc::clone(&state_a), None, false);

    // "b" is never pinned in node A's CRDT.
    let (status, _) = post_gossip_sync(&router, Some("b-unknown"), b"garbage".to_vec()).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

/// Golden path: a properly signed-and-sealed envelope from a pinned peer is
/// accepted, merged, and answered with a signed-and-sealed response the
/// sender can decrypt with its own KEM private key.
#[tokio::test]
async fn gossip_sync_accepts_valid_envelope_and_returns_signed_response() {
    let a = generate_node_identity();
    let b = generate_node_identity();
    let state_a = build_gossip_state(&a, "https://a.test").await;
    pin_peer(&state_a, &b, "https://b.test").await;
    let router = routes::build_router(Arc::clone(&state_a), None, false);

    let now = akamu::util::unix_now();
    let body = build_signed_envelope(&b, &a.kem_pub_spki, now, vec![1u8; 16]);
    let (status, resp_bytes) = post_gossip_sync(&router, Some(&b.node_id), body).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "valid envelope from a pinned peer must be accepted"
    );

    // The response must be decryptable by B and signed by A.
    let resp_plaintext = verify_and_open(&resp_bytes, &b.kem_priv_pkcs8, &a.sign_pub_spki)
        .expect("response must verify against A's signing key and decrypt with B's KEM key");
    let resp_envelope =
        GossipEnvelope::decode(&resp_plaintext).expect("response must be a valid envelope");
    assert!(
        !resp_envelope.is_delta,
        "first contact must return full state, not a delta"
    );
}

/// Fail-closed guarantee: replaying an already-seen envelope (identical
/// nonce) must be rejected — this is what prevents a captured gossip push
/// from being resubmitted to re-trigger a merge.
#[tokio::test]
async fn gossip_sync_rejects_replayed_nonce() {
    let a = generate_node_identity();
    let b = generate_node_identity();
    let state_a = build_gossip_state(&a, "https://a.test").await;
    pin_peer(&state_a, &b, "https://b.test").await;
    let router = routes::build_router(Arc::clone(&state_a), None, false);

    let now = akamu::util::unix_now();
    let body = build_signed_envelope(&b, &a.kem_pub_spki, now, vec![7u8; 16]);

    let (status1, _) = post_gossip_sync(&router, Some(&b.node_id), body.clone()).await;
    assert_eq!(
        status1,
        StatusCode::OK,
        "first delivery of a fresh nonce must succeed"
    );

    let (status2, _) = post_gossip_sync(&router, Some(&b.node_id), body).await;
    assert_eq!(
        status2,
        StatusCode::BAD_REQUEST,
        "replaying the exact same envelope must be rejected"
    );
}

/// Fail-closed guarantee: an envelope timestamped further in the past than
/// the configured max age must be rejected, even from a fully-pinned,
/// correctly-signed sender — this bounds how long a captured envelope
/// remains replayable-in-principle (before nonce dedup is even consulted).
#[tokio::test]
async fn gossip_sync_rejects_stale_envelope() {
    let a = generate_node_identity();
    let b = generate_node_identity();
    let state_a = build_gossip_state(&a, "https://a.test").await;
    pin_peer(&state_a, &b, "https://b.test").await;
    let router = routes::build_router(Arc::clone(&state_a), None, false);

    // Default max age (no [gossip] config set) is 300s.
    let stale_ts = akamu::util::unix_now() - 3600;
    let body = build_signed_envelope(&b, &a.kem_pub_spki, stale_ts, vec![9u8; 16]);
    let (status, _) = post_gossip_sync(&router, Some(&b.node_id), body).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

// ── gossip_status CA-scope redaction ─────────────────────────────────────────

fn operator_ctx(
    role: akamu::state::OperatorRole,
    ca_id: &str,
) -> akamu::admin::auth::OperatorContext {
    akamu::admin::auth::OperatorContext {
        operator_id: 1,
        name: "test-operator".into(),
        role,
        ca_id: ca_id.to_string(),
        auth_method: akamu::state::AdminAuthMethod::Cert,
        session_token: None,
    }
}

/// Fail-closed guarantee: cluster topology (this node's id, configured peer
/// URLs) is only meaningful to an operator with server-wide visibility. A
/// CA-scoped operator must not learn it via `GET /admin/gossip/status`.
#[tokio::test]
async fn gossip_status_hides_topology_from_ca_scoped_operator() {
    let a = generate_node_identity();
    let state_a = build_gossip_state(&a, "https://a.test").await;

    let scoped = operator_ctx(akamu::state::OperatorRole::CaRa, "default");
    let resp =
        akamu::gossip::handlers::gossip_status(scoped, axum::extract::State(Arc::clone(&state_a)))
            .await
            .into_response();
    let body = axum::body::to_bytes(resp.into_body(), 100_000)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(
        json["node_id"].is_null(),
        "CA-scoped operator must not see node_id: {json}"
    );
    assert_eq!(
        json["peers"].as_array().map(|a| a.len()),
        Some(0),
        "CA-scoped operator must not see peer topology: {json}"
    );

    let server_wide = operator_ctx(akamu::state::OperatorRole::Administrator, "");
    let resp = akamu::gossip::handlers::gossip_status(
        server_wide,
        axum::extract::State(Arc::clone(&state_a)),
    )
    .await
    .into_response();
    let body = axum::body::to_bytes(resp.into_body(), 100_000)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["node_id"].as_str(), Some(a.node_id.as_str()));
}
