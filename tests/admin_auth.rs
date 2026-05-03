//! Integration tests for the three admin authentication paths and session lifecycle.
//!
//! T-2: 3-path authentication test
//!   - Bearer: pre-seeded token → GET /admin/stats → 200
//!   - mTLS: inject PeerClientCert with known fingerprint → POST /admin/session → 200
//!     with session_token in JSON body; token usable as Bearer on GET /admin/stats
//!   - Expired token: session past TTL → GET /admin/stats → 401
//!
//! T-3: Operator deactivation purges live sessions immediately.
//!
//! T-5: Audit event end-to-end: insert an event via db::audit::insert,
//!      then query GET /admin/audit?type=<type> and assert the row is present.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use tower::ServiceExt;

use akamu::admin::auth::PeerClientCert;
use akamu::config::{AdminConfig, CaConfig, Config, DatabaseConfig, MtcConfig, ServerConfig};
use akamu::state::{AdminAuthMethod, AdminSession, AppState, CaState, MtcState, NonceBucket, OperatorRole};
use akamu::{ca, db, routes};

use synta_certificate::{BackendPrivateKey, CertificateBuilder, NameBuilder, PrivateKey as _};

// ── SHA-256 helper (mirrors admin::auth::sha256_hex) ─────────────────────────

fn sha256_hex(data: &[u8]) -> String {
    let alg = native_ossl::digest::DigestAlg::fetch(c"SHA2-256", None).unwrap();
    let mut ctx = alg.new_context().unwrap();
    ctx.update(data).unwrap();
    let mut out = [0u8; 32];
    ctx.finish(&mut out).unwrap();
    native_ossl::util::hex_encode(out)
}

// ── Minimal self-signed cert DER ─────────────────────────────────────────────

fn generate_cert_der(key: &BackendPrivateKey) -> Vec<u8> {
    let pub_key = key.public_key().unwrap();
    let spki_der = pub_key.spki_der().to_vec();

    let name_der = NameBuilder::new()
        .common_name("test-operator")
        .build()
        .unwrap();

    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    let gt = |secs: i64| {
        let gt = synta::GeneralizedTime::from_unix(secs).unwrap();
        format!(
            "{:04}{:02}{:02}{:02}{:02}{:02}Z",
            gt.year, gt.month, gt.day, gt.hour, gt.minute, gt.second
        )
    };

    let nb = synta_certificate::parse_time(&gt(now_secs)).unwrap();
    let na = synta_certificate::parse_time(&gt(now_secs + 10 * 365 * 86400)).unwrap();

    let signer = key.as_signer("sha256");
    CertificateBuilder::new()
        .issuer_name(&name_der)
        .subject_name(&name_der)
        .public_key_der(&spki_der)
        .serial_number(synta::Integer::from_i64(1))
        .not_valid_before(nb)
        .not_valid_after(na)
        .sign(&signer)
        .unwrap()
}

// ── AppState builder ──────────────────────────────────────────────────────────

async fn build_state(
    session_ttl_secs: u64,
    auth_rate_limit: u32,
) -> (
    Arc<AppState>,
    Arc<tokio::sync::Mutex<HashMap<String, AdminSession>>>,
    tempfile::TempDir,
) {
    let dir = tempfile::TempDir::new().unwrap();
    let config = Arc::new(Config {
        listen_addr: "127.0.0.1:0".into(),
        base_url: "https://acme.test".into(),
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
            common_name: "Auth Test CA".into(),
            organization: "Test".into(),
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
        tls: Default::default(),
        profiles: Default::default(),
        admin: Some(AdminConfig {
            listen_addr: "127.0.0.1:0".into(),
            cert_file: "dummy.crt".into(),
            key_file: "dummy.key".into(),
            server_name: "localhost".into(),
            bootstrap_key_type: "ec:P-256".into(),
            bootstrap_operator_cert_file: None,
            bootstrap_operator_key_file: None,
            bootstrap_operator_name: "admin".into(),
            ca_certs: vec![],
            gssapi: None,
            session_ttl_secs,
            auth_rate_limit,
            audit_max_rows: None,
            audit_overflow: "drop_oldest".into(),
            audit_alarm_threshold: 10,
            audit_alarm_action: "syslog".into(),
        }),
    });

    let (ca_key, ca_cert_der) = ca::init::load_or_generate(&config.ca).unwrap();
    let ca_spki_der = ca_key.public_key().unwrap().spki_der().to_vec();
    let ca_aki_bytes = ca::init::compute_aki_from_spki(&ca_spki_der).unwrap_or_default();
    db::install_drivers();
    let db_conn = db::open("sqlite::memory:", 1).await.unwrap();

    let ca = Arc::new(CaState {
        key: ca_key,
        cert_der: ca_cert_der,
        hash_alg: "sha256".into(),
        validity_days: 90,
        crl_url: None,
        ocsp_url: None,
        aki_bytes: ca_aki_bytes,
        enforce_validity_cap: false,
    });

    let sessions: Arc<tokio::sync::Mutex<HashMap<String, AdminSession>>> =
        Arc::new(tokio::sync::Mutex::new(HashMap::new()));

    let state = Arc::new(AppState {
        config: Arc::clone(&config),
        db: db_conn,
        db_kind: db::DbKind::Sqlite,
        profiles: akamu::profiles::ProfileRegistry::empty(&ca),
        ca,
        mtc: Arc::new(MtcState {
            log: None,
            algorithm: synta_mtc::crypto::HashAlgorithm::Sha256,
            signing_key: None,
            signing_hash_alg: "sha256".into(),
            cosigner_clients: vec![],
            _log_lock: None,
        }),
        tls: None,
        spki_cache: Arc::new(std::sync::RwLock::new(HashMap::new())),
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
        crl_cache: Default::default(),
        audit: Arc::new(akamu::audit::AuditState::new()),
        audit_policy: Arc::new(akamu::audit::AuditPolicy::default()),
        admin_sessions: Some(Arc::clone(&sessions)),
        admin_auth_limiter: Some(Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new()))),
        startup_time: Instant::now(),
        gss_cred: None,
        admin_gss_cred: None,
        eab_master_secret: None,
    });

    (state, sessions, dir)
}

// ── Request helpers ───────────────────────────────────────────────────────────

async fn get_stats_bearer(router: &axum::Router, token: &str) -> axum::response::Response {
    let req = Request::builder()
        .method(Method::GET)
        .uri("/admin/stats")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    router.clone().oneshot(req).await.unwrap()
}

// ── T-2: Bearer path ──────────────────────────────────────────────────────────

#[tokio::test]
async fn bearer_token_grants_access() {
    let (state, sessions, _dir) = build_state(3600, 20).await;
    let router = routes::build_admin_router(Arc::clone(&state));

    sessions.lock().await.insert(
        "test-bearer-token".to_string(),
        AdminSession {
            operator_id: 1,
            name: "bearer-operator".to_string(),
            role: OperatorRole::Auditor,
            created_at: Instant::now(),
            last_active_at: Instant::now(),
            auth_method: AdminAuthMethod::Cert,
        },
    );

    let resp = get_stats_bearer(&router, "test-bearer-token").await;
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "valid Bearer token must return 200 on GET /admin/stats"
    );
}

// ── T-2: mTLS path ────────────────────────────────────────────────────────────

/// POST /admin/session with a PeerClientCert:
///   - returns 200 with `session_token` in the JSON body
///   - the issued token can be used as Bearer for a follow-up GET /admin/stats
#[tokio::test]
async fn mtls_cert_issues_session_token_usable_as_bearer() {
    let (state, _sessions, _dir) = build_state(3600, 20).await;
    let router = routes::build_admin_router(Arc::clone(&state));

    // Generate a cert and derive its fingerprint.
    let op_key = BackendPrivateKey::generate_ec("P-256").unwrap();
    let cert_der = generate_cert_der(&op_key);
    let fingerprint = sha256_hex(&cert_der);

    // Seed an operator with that fingerprint.
    db::operators::insert(
        &state.db,
        "mtls-operator",
        "auditor",
        Some(&fingerprint),
        None,
        "2026-01-01T00:00:00Z",
    )
    .await
    .unwrap();

    // Step 1: POST /admin/session with a client cert → 200 + session_token in JSON body.
    let mut post_req = Request::builder()
        .method(Method::POST)
        .uri("/admin/session")
        .body(Body::empty())
        .unwrap();
    post_req.extensions_mut().insert(PeerClientCert(cert_der));
    let post_resp = router.clone().oneshot(post_req).await.unwrap();

    assert_eq!(
        post_resp.status(),
        StatusCode::OK,
        "POST /admin/session with valid client cert must return 200"
    );
    let body_bytes = axum::body::to_bytes(post_resp.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    let token = json["session_token"]
        .as_str()
        .expect("POST /admin/session must return session_token in JSON body")
        .to_string();
    assert!(!token.is_empty(), "session_token must be non-empty");

    // Step 2: use the issued token as a Bearer to access GET /admin/stats → 200.
    let stats_resp = get_stats_bearer(&router, &token).await;
    assert_eq!(
        stats_resp.status(),
        StatusCode::OK,
        "session token issued via mTLS must be usable as Bearer on GET /admin/stats"
    );
}

// ── T-2: Expired token ────────────────────────────────────────────────────────

#[tokio::test]
async fn expired_token_returns_401() {
    let (state, sessions, _dir) = build_state(1, 20).await;
    let router = routes::build_admin_router(Arc::clone(&state));

    // Insert a session whose last_active_at is 2 seconds in the past
    // so it is already beyond the 1-second TTL on the very first lookup.
    let stale_instant = Instant::now() - Duration::from_secs(2);
    sessions.lock().await.insert(
        "stale-token".to_string(),
        AdminSession {
            operator_id: 1,
            name: "stale-operator".to_string(),
            role: OperatorRole::Auditor,
            created_at: stale_instant,
            last_active_at: stale_instant,
            auth_method: AdminAuthMethod::Cert,
        },
    );

    let resp = get_stats_bearer(&router, "stale-token").await;
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "expired session token must return 401"
    );
}

// ── T-3: Operator deactivation purges live sessions ───────────────────────────

#[tokio::test]
async fn operator_deactivation_purges_sessions() {
    let (state, sessions, _dir) = build_state(3600, 20).await;
    let router = routes::build_admin_router(Arc::clone(&state));

    // Seed an administrator session for the operator who performs the PATCH.
    sessions.lock().await.insert(
        "admin-token".to_string(),
        AdminSession {
            operator_id: 1,
            name: "admin-operator".to_string(),
            role: OperatorRole::Administrator,
            created_at: Instant::now(),
            last_active_at: Instant::now(),
            auth_method: AdminAuthMethod::Cert,
        },
    );

    // Insert the victim operator in the DB.
    db::operators::insert(
        &state.db,
        "victim-operator",
        "auditor",
        Some("dummy-fingerprint"),
        None,
        "2026-01-01T00:00:00Z",
    )
    .await
    .unwrap();

    // Look up the assigned DB id.
    let op = db::operators::get_by_fingerprint(&state.db, "dummy-fingerprint")
        .await
        .unwrap()
        .unwrap();
    let victim_id = op.id;

    // Seed a live session for the victim.
    sessions.lock().await.insert(
        "victim-token".to_string(),
        AdminSession {
            operator_id: victim_id,
            name: "victim-operator".to_string(),
            role: OperatorRole::Auditor,
            created_at: Instant::now(),
            last_active_at: Instant::now(),
            auth_method: AdminAuthMethod::Cert,
        },
    );

    // Victim's token must work before deactivation.
    let pre = get_stats_bearer(&router, "victim-token").await;
    assert_eq!(
        pre.status(),
        StatusCode::OK,
        "victim token must be valid before deactivation"
    );

    // Administrator deactivates the victim operator.
    let patch_req = Request::builder()
        .method(Method::PATCH)
        .uri(format!("/admin/operators/{victim_id}"))
        .header(header::AUTHORIZATION, "Bearer admin-token")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(r#"{"active":false}"#))
        .unwrap();
    let patch_resp = router.clone().oneshot(patch_req).await.unwrap();
    assert_eq!(
        patch_resp.status(),
        StatusCode::NO_CONTENT,
        "PATCH /admin/operators/{victim_id} must return 204"
    );

    // Victim's token must now be rejected.
    let post = get_stats_bearer(&router, "victim-token").await;
    assert_eq!(
        post.status(),
        StatusCode::UNAUTHORIZED,
        "victim token must be rejected after operator deactivation"
    );
}

// ── T-5: Audit event end-to-end ───────────────────────────────────────────────

#[tokio::test]
async fn audit_event_visible_via_admin_api() {
    let (state, sessions, _dir) = build_state(3600, 20).await;
    let router = routes::build_admin_router(Arc::clone(&state));

    // Seed an auditor session (GET /admin/audit is allowed for auditor role).
    sessions.lock().await.insert(
        "tok-auditor".to_string(),
        AdminSession {
            operator_id: 1,
            name: "audit-operator".to_string(),
            role: OperatorRole::Auditor,
            created_at: Instant::now(),
            last_active_at: Instant::now(),
            auth_method: AdminAuthMethod::Cert,
        },
    );

    // Insert a synthetic account.create audit event directly into the DB.
    akamu::db::audit::insert(
        &state.db,
        "2026-05-02T10:00:00Z",
        "account.create",
        Some("acme:test-account-id"),
        Some("acme:test-account-id"),
        "success",
        None,
    )
    .await
    .unwrap();

    // Query the audit log via the admin API.
    let req = Request::builder()
        .method(Method::GET)
        .uri("/admin/audit?type=account.create")
        .header(header::AUTHORIZATION, "Bearer tok-auditor")
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "GET /admin/audit must return 200"
    );

    let body = http_body_util::BodyExt::collect(resp.into_body())
        .await
        .unwrap()
        .to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    let events = json["events"].as_array().expect("response must have events array");
    assert_eq!(events.len(), 1, "exactly one account.create event must be returned");

    let ev = &events[0];
    assert_eq!(ev["event_type"], "account.create", "event_type must match filter");
    assert_eq!(ev["outcome"], "success", "outcome must be success");
    assert_eq!(
        ev["subject"],
        "acme:test-account-id",
        "subject must match what was inserted"
    );
}

// ── T-7: Session sweep removes expired entries on create ──────────────────────

/// Expired sessions accumulated in the map are swept (removed) the next time
/// `create_session` acquires the lock.  After the sweep only the newly created
/// session remains.
#[tokio::test]
async fn create_session_sweeps_expired_entries() {
    // TTL of 1 second; sessions seeded 2 s in the past are already expired.
    let (state, sessions, _dir) = build_state(1, 20).await;
    let router = routes::build_admin_router(Arc::clone(&state));

    let stale = Instant::now() - Duration::from_secs(2);

    // Pre-populate three expired sessions.
    {
        let mut map = sessions.lock().await;
        for i in 0..3 {
            map.insert(
                format!("stale-{i}"),
                AdminSession {
                    operator_id: i,
                    name: format!("stale-op-{i}"),
                    role: OperatorRole::Auditor,
                    created_at: stale,
                    last_active_at: stale,
                    auth_method: AdminAuthMethod::Cert,
                },
            );
        }
    }

    // Seed an operator whose mTLS cert we will use to create a fresh session.
    let op_key = BackendPrivateKey::generate_ec("P-256").unwrap();
    let cert_der = generate_cert_der(&op_key);
    let fingerprint = sha256_hex(&cert_der);
    db::operators::insert(
        &state.db,
        "sweep-test-operator",
        "auditor",
        Some(&fingerprint),
        None,
        "2026-01-01T00:00:00Z",
    )
    .await
    .unwrap();

    // POST /admin/session triggers create_session → map.retain → sweep.
    let mut req = Request::builder()
        .method(Method::POST)
        .uri("/admin/session")
        .body(Body::empty())
        .unwrap();
    req.extensions_mut().insert(PeerClientCert(cert_der));
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "POST /admin/session must succeed");

    // After the sweep only the one new token should remain.
    let map = sessions.lock().await;
    assert_eq!(
        map.len(),
        1,
        "sweep must remove expired sessions; only the new session should remain"
    );
}

// ── T-8: Sliding TTL refreshes last_active_at on each access ─────────────────

/// Every successful Bearer-token lookup updates `last_active_at`.  Verify by
/// reading the timestamp before and after a GET /admin/stats call.
#[tokio::test]
async fn bearer_lookup_refreshes_last_active_at() {
    let (state, sessions, _dir) = build_state(3600, 20).await;
    let router = routes::build_admin_router(Arc::clone(&state));

    let before = Instant::now();
    sessions.lock().await.insert(
        "sliding-token".to_string(),
        AdminSession {
            operator_id: 1,
            name: "slide-op".to_string(),
            role: OperatorRole::Auditor,
            created_at: before,
            last_active_at: before,
            auth_method: AdminAuthMethod::Cert,
        },
    );

    // Small pause so that a refreshed Instant is measurably newer.
    tokio::time::sleep(Duration::from_millis(5)).await;

    // Lookup via GET /admin/stats; lookup_session updates last_active_at.
    let resp = get_stats_bearer(&router, "sliding-token").await;
    assert_eq!(resp.status(), StatusCode::OK, "token must still be valid");

    // last_active_at must be strictly later than `before`.
    let map = sessions.lock().await;
    let session = map.get("sliding-token").expect("session must still be in map");
    assert!(
        session.last_active_at > before,
        "last_active_at must be refreshed after a successful lookup"
    );
}

// ── T-9: Route handler audit event written to DB ──────────────────────────────

/// A successful mTLS login via POST /admin/session emits an `admin.login`
/// event through `state.record_audit`.  The event must be visible when queried
/// via GET /admin/audit — verifying the full path from handler to DB to API.
#[tokio::test]
async fn login_via_handler_emits_audit_event() {
    let (state, sessions, _dir) = build_state(3600, 20).await;
    let router = routes::build_admin_router(Arc::clone(&state));

    // Seed an auditor session to call GET /admin/audit.
    sessions.lock().await.insert(
        "auditor-tok".to_string(),
        AdminSession {
            operator_id: 999,
            name: "audit-reader".to_string(),
            role: OperatorRole::Auditor,
            created_at: Instant::now(),
            last_active_at: Instant::now(),
            auth_method: AdminAuthMethod::Cert,
        },
    );

    // Create and register an operator whose cert will trigger an AdminLogin event.
    let op_key = BackendPrivateKey::generate_ec("P-256").unwrap();
    let cert_der = generate_cert_der(&op_key);
    let fingerprint = sha256_hex(&cert_der);
    db::operators::insert(
        &state.db,
        "login-audit-operator",
        "administrator",
        Some(&fingerprint),
        None,
        "2026-01-01T00:00:00Z",
    )
    .await
    .unwrap();

    // POST /admin/session — the handler calls state.record_audit(AdminLogin::success).
    let mut req = Request::builder()
        .method(Method::POST)
        .uri("/admin/session")
        .body(Body::empty())
        .unwrap();
    req.extensions_mut().insert(PeerClientCert(cert_der));
    let resp = router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "POST /admin/session must succeed");

    // Query GET /admin/audit?type=admin.login via the API.
    let query_req = Request::builder()
        .method(Method::GET)
        .uri("/admin/audit?type=admin.login")
        .header(header::AUTHORIZATION, "Bearer auditor-tok")
        .body(Body::empty())
        .unwrap();
    let query_resp = router.oneshot(query_req).await.unwrap();
    assert_eq!(query_resp.status(), StatusCode::OK, "GET /admin/audit must return 200");

    let body = axum::body::to_bytes(query_resp.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let events = json["events"].as_array().expect("response must have events array");
    assert!(
        !events.is_empty(),
        "at least one admin.login event must appear after a successful mTLS login"
    );
    let ev = events.iter().find(|e| {
        e["event_type"].as_str() == Some("admin.login") && e["outcome"].as_str() == Some("success")
    });
    assert!(
        ev.is_some(),
        "a successful admin.login event must be recorded in the audit log"
    );
}

// ── T-6: Auth rate limit (H-12) ───────────────────────────────────────────────

#[tokio::test]
async fn auth_rate_limit_returns_429_after_limit_exceeded() {
    use std::net::{Ipv4Addr, SocketAddr};

    // Use a very low rate limit (2 per 5 minutes) so we can trigger it easily.
    let (state, _sessions, _dir) = build_state(3600, 2).await;
    let router = routes::build_admin_router(Arc::clone(&state));

    // A fake source IP that will be tracked by the rate limiter.
    let peer: SocketAddr = SocketAddr::new(Ipv4Addr::new(10, 0, 0, 1).into(), 55000);

    // Send `limit` requests with a GSSAPI Negotiate header (invalid token —
    // GSSAPI is not configured so each is rejected 401, but each increments
    // the per-IP counter).
    for attempt in 1..=2 {
        let mut req = Request::builder()
            .method(Method::POST)
            .uri("/admin/session")
            .header(header::AUTHORIZATION, "Negotiate dGVzdA==")
            .body(Body::empty())
            .unwrap();
        req.extensions_mut()
            .insert(axum::extract::ConnectInfo(peer));
        let resp = router.clone().oneshot(req).await.unwrap();
        assert_ne!(
            resp.status(),
            StatusCode::TOO_MANY_REQUESTS,
            "attempt {attempt}: must not be 429 while below the limit"
        );
    }

    // The (limit + 1)-th request from the same IP must be rate-limited.
    let mut req = Request::builder()
        .method(Method::POST)
        .uri("/admin/session")
        .header(header::AUTHORIZATION, "Negotiate dGVzdA==")
        .body(Body::empty())
        .unwrap();
    req.extensions_mut()
        .insert(axum::extract::ConnectInfo(peer));
    let resp = router.clone().oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "request exceeding rate limit must return 429"
    );

    // A different source IP must NOT be rate-limited.
    let other_peer: SocketAddr = SocketAddr::new(Ipv4Addr::new(10, 0, 0, 2).into(), 55001);
    let mut req = Request::builder()
        .method(Method::POST)
        .uri("/admin/session")
        .header(header::AUTHORIZATION, "Negotiate dGVzdA==")
        .body(Body::empty())
        .unwrap();
    req.extensions_mut()
        .insert(axum::extract::ConnectInfo(other_peer));
    let resp = router.clone().oneshot(req).await.unwrap();
    assert_ne!(
        resp.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "a different source IP must not be affected by another IP's rate limit"
    );
}
