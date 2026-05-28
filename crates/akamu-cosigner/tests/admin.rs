//! Integration tests for cosigner admin authentication routes.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Instant;

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use tower::ServiceExt;

use synta::ObjectIdentifier;
use synta_certificate::BackendPrivateKey;

use akamu::util::sha256_hex;
use akamu_cosigner::admin::PeerClientCert;
use akamu_cosigner::config::CosignerRole;
use akamu_cosigner::routes::build_router;
use akamu_cosigner::state::{AppState, CosignerSession};

fn build_state() -> Arc<AppState> {
    let signing_key = BackendPrivateKey::generate_ec("P-256")
        .expect("generate P-256 key for cosigner test state");
    Arc::new(AppState {
        signing_key,
        hash_alg: "sha256".to_owned(),
        sig_alg_der: vec![],
        cosigner_oid: "1.3.6.1.4.1.44363.47.10.1"
            .parse::<ObjectIdentifier>()
            .expect("parse test TrustAnchorID OID"),
        challenge_tokens: Arc::new(RwLock::new(HashMap::new())),
        admin_operators: vec![],
        admin_sessions: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
        admin_session_ttl_secs: 3600,
        startup_time: Instant::now(),
        signing_stats: Arc::new(Mutex::new((0, None))),
    })
}

async fn seed_session(state: &Arc<AppState>, token: &str, role: CosignerRole) {
    state.admin_sessions.lock().await.insert(
        token.to_string(),
        CosignerSession {
            name: zeroize::Zeroizing::new("test-op".to_string()),
            role,
            operator_id: 0,
            created_at: Instant::now(),
            last_active_at: Instant::now(),
        },
    );
}

async fn get_with_bearer(
    router: &axum::Router,
    path: &str,
    token: &str,
) -> axum::response::Response {
    let req = Request::builder()
        .method(Method::GET)
        .uri(path)
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    router.clone().oneshot(req).await.unwrap()
}

#[tokio::test]
async fn get_status_returns_ok() {
    let state = build_state();
    let router = build_router(Arc::clone(&state));
    seed_session(&state, "tok-status", CosignerRole::Auditor).await;

    let resp = get_with_bearer(&router, "/admin/status", "tok-status").await;
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "GET /admin/status must return 200"
    );

    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["status"], "ok", "status field must be \"ok\"");
    assert!(json["uptime_secs"].is_u64(), "uptime_secs must be a number");
}

#[tokio::test]
async fn get_stats_returns_counters() {
    let state = build_state();
    let router = build_router(Arc::clone(&state));
    seed_session(&state, "tok-stats", CosignerRole::Auditor).await;

    let resp = get_with_bearer(&router, "/admin/stats", "tok-stats").await;
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "GET /admin/stats must return 200"
    );

    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(json["uptime_secs"].is_u64(), "uptime_secs must be present");
    assert!(
        json["checkpoints_signed"].is_u64(),
        "checkpoints_signed must be present"
    );
    assert_eq!(
        json["checkpoints_signed"], 0,
        "fresh server must have 0 checkpoints signed"
    );
}

#[tokio::test]
async fn post_session_with_bearer_returns_token() {
    let state = build_state();
    let router = build_router(Arc::clone(&state));
    seed_session(&state, "tok-session", CosignerRole::Administrator).await;

    let req = Request::builder()
        .method(Method::POST)
        .uri("/admin/session")
        .header(header::AUTHORIZATION, "Bearer tok-session")
        .body(Body::empty())
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "POST /admin/session must return 200"
    );

    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        json["session_token"], "tok-session",
        "session_token in body must match Bearer token"
    );
    assert_eq!(
        json["role"], "administrator",
        "role in body must match session role"
    );
    assert!(
        json["expires_at"].is_string(),
        "expires_at must be a string"
    );
}

#[tokio::test]
async fn unauthenticated_request_returns_401() {
    let state = build_state();
    let router = build_router(Arc::clone(&state));

    let req = Request::builder()
        .method(Method::GET)
        .uri("/admin/status")
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "unauthenticated request must return 401"
    );
}

#[tokio::test]
async fn mtls_cert_issues_session_token() {
    use akamu_cosigner::config::OperatorConfig;

    let signing_key = BackendPrivateKey::generate_ec("P-256")
        .expect("generate P-256 key for mTLS test");
    let op_key = BackendPrivateKey::generate_ec("P-256")
        .expect("generate P-256 operator key");

    // Build a minimal cert DER and derive its SHA-256 fingerprint.
    use synta_certificate::{CertificateBuilder, NameBuilder, PrivateKey as _};
    let name_der = NameBuilder::new()
        .common_name("test-op")
        .build()
        .expect("build test operator name DER");
    let pub_key = op_key.public_key().expect("operator public key");
    let spki_der = pub_key.spki_der().to_vec();
    let not_before = synta_certificate::parse_time("20260101000000Z")
        .expect("parse notBefore time");
    let not_after = synta_certificate::parse_time("20360101000000Z")
        .expect("parse notAfter time");
    let cert_der = CertificateBuilder::new()
        .issuer_name(&name_der)
        .subject_name(&name_der)
        .public_key_der(&spki_der)
        .serial_number(synta::Integer::from_i64(1))
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .sign(&signing_key.as_signer("sha256"))
        .expect("sign test operator cert");

    let fingerprint = sha256_hex(&cert_der).expect("compute cert fingerprint");

    let state = Arc::new(AppState {
        signing_key: BackendPrivateKey::generate_ec("P-256")
            .expect("generate P-256 key for mTLS test state"),
        hash_alg: "sha256".to_owned(),
        sig_alg_der: vec![],
        cosigner_oid: "1.3.6.1.4.1.44363.47.10.1"
            .parse::<ObjectIdentifier>()
            .expect("parse test TrustAnchorID OID"),
        challenge_tokens: Arc::new(RwLock::new(HashMap::new())),
        admin_operators: vec![OperatorConfig {
            name: "mtls-op".to_owned(),
            role: CosignerRole::Auditor,
            cert_fingerprint: Some(fingerprint),
            gssapi_principal: None,
        }],
        admin_sessions: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
        admin_session_ttl_secs: 3600,
        startup_time: Instant::now(),
        signing_stats: Arc::new(Mutex::new((0, None))),
    });

    let router = build_router(Arc::clone(&state));

    let mut req = Request::builder()
        .method(Method::POST)
        .uri("/admin/session")
        .body(Body::empty())
        .unwrap();
    req.extensions_mut().insert(PeerClientCert(cert_der));

    let resp = router.clone().oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "POST /admin/session with valid mTLS cert must return 200"
    );

    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let token = json["session_token"]
        .as_str()
        .expect("session_token must be present");
    assert!(!token.is_empty(), "session_token must be non-empty");

    // Use the issued token as Bearer on GET /admin/stats.
    let stats_resp = get_with_bearer(&router, "/admin/stats", token).await;
    assert_eq!(
        stats_resp.status(),
        StatusCode::OK,
        "mTLS-issued token must work as Bearer"
    );
}
