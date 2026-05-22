//! Table-driven RBAC test: verify every admin route enforces the declared
//! role matrix.
//!
//! For each (route, method) pair and for each of the 4 operator roles, send
//! a request with a pre-seeded Bearer token and assert that:
//! - allowed roles return a status other than 403 / 404
//!   (we can't guarantee 200 for write routes without real data, but we
//!   CAN guarantee they don't 403 when the role IS permitted)
//! - disallowed roles get exactly 403

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use tower::ServiceExt;

use akamu::config::{AdminConfig, CaConfig, Config, DatabaseConfig, MtcConfig, ServerConfig};
use akamu::state::{
    AdminAuthMethod, AdminSession, AppState, CaState, MtcState, NonceBucket, OperatorRole,
};
use akamu::{ca, db, routes};

// ── Test state helpers ────────────────────────────────────────────────────────

async fn build_admin_state() -> (Arc<AppState>, tempfile::TempDir) {
    let dir = tempfile::TempDir::new().unwrap();
    let config = Arc::new(Config {
        listen_addr: "127.0.0.1:0".into(),
        base_url: "https://acme.test".into(),
        database: DatabaseConfig {
            url: "sqlite::memory:".into(),
            max_connections: None,
            require_tls: false,
        },
        cas: vec![CaConfig {
            id: "default".to_owned(),

            is_default: true,

            caa_identities: vec![],
            key_file: dir.path().join("ca.key").to_string_lossy().into_owned(),
            cert_file: dir.path().join("ca.crt").to_string_lossy().into_owned(),
            key_type: "ec:P-256".into(),
            hash_alg: "sha256".into(),
            validity_days: 90,
            crl_url: None,
            ocsp_url: None,
            common_name: "RBAC Test CA".into(),
            organization: "Test".into(),
            ca_validity_years: 10,
            crl_next_update_secs: 86400,
            enforce_validity_cap: false,
            require_encrypted_key: false,
            key_password_file: None,
        }],
        mtc: MtcConfig {
            log_path: "/dev/null".into(),
            enabled: false,
            signing_key: None,
            checkpoint_interval_secs: 3600,
            cosigners: vec![],
            landmark_interval_secs: 86400,
            max_active_landmarks: 100,
            checkpoint_retention_count: 1000,
            hash_alg: "sha256".into(),
        },
        server: ServerConfig::default(),
        tls: Default::default(),
        profiles: Default::default(),
        admin: Some(AdminConfig {
            bootstrap_key_type: "ec:P-256".into(),
            bootstrap_operator_cert_file: None,
            bootstrap_operator_key_file: None,
            bootstrap_operator_name: "admin".into(),
            bootstrap_operator_gssapi_principal: None,
            gssapi: None,
            session_ttl_secs: 3600,
            session_lock_secs: 900,
            auth_rate_limit: 20,
            audit_max_rows: None,
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
    });

    let (ca_key, ca_cert_der) = ca::init::load_or_generate(config.default_ca()).unwrap();
    let ca_spki_der = ca_key.public_key().unwrap().spki_der().to_vec();
    let ca_aki_bytes = ca::init::compute_aki_from_spki(&ca_spki_der).unwrap_or_default();
    db::install_drivers();
    let db_conn = db::open("sqlite::memory:", 1, false).await.unwrap();

    let ca = Arc::new(CaState {
        id: "default".into(),
        key_type: "ec:P-256".into(),
        crl_next_update_secs: 86400,
        key: ca_key,
        cert_der: ca_cert_der,
        hash_alg: "sha256".into(),
        validity_days: 90,
        crl_url: None,
        ocsp_url: None,
        aki_bytes: ca_aki_bytes,
        enforce_validity_cap: false,
        caa_identities: vec![],
    });

    let sessions: Arc<tokio::sync::Mutex<HashMap<String, AdminSession>>> =
        Arc::new(tokio::sync::Mutex::new(HashMap::new()));

    let state = Arc::new(AppState {
        config: Arc::clone(&config),
        db: db_conn.clone(),
        db_ro: db_conn.clone(),
        db_kind: db::DbKind::Sqlite,
        profiles: akamu::profiles::ProfileRegistry::empty(&ca),
        cas: {
            let mut _ca_map = indexmap::IndexMap::new();
            _ca_map.insert("default".to_string(), ca.clone());
            Arc::new(_ca_map)
        },
        default_ca_id: Arc::new("default".to_string()),
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
        link_headers: Arc::new({
            let mut _lh_map = std::collections::HashMap::new();

            _lh_map.insert(
                "default".to_string(),
                Arc::new(axum::http::HeaderValue::from_static(
                    "<https://acme.test/acme/directory>;rel=\"index\"",
                )),
            );

            _lh_map
        }),
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
        crl_caches: Arc::new({
            let mut _crl_map = std::collections::HashMap::new();

            _crl_map.insert("default".to_string(), Default::default());

            _crl_map
        }),
        audit: Arc::new(akamu::audit::AuditState::new()),
        audit_policy: Arc::new(akamu::audit::AuditPolicy::default()),
        admin_sessions: Some(Arc::clone(&sessions)),
        admin_auth_limiter: None,
        eab_session_nonces: None,
        startup_time: Instant::now(),
        crdt: Arc::new(tokio::sync::RwLock::new(akamu_crdt::AkaCrdt::default())),
        node_id: Arc::new("test".to_string()),
        node_kem_priv: Arc::new(vec![]),
        node_gossip_signing_priv: Arc::new(vec![]),
        node_gossip_signing_cert: Arc::new(vec![]),
        gossip_client: Arc::new(reqwest::Client::new()),
        gossip_nonce_cache: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
        write_notify: Arc::new(tokio::sync::Notify::new()),
        gss_cred: None,
        admin_gss_cred: None,
        eab_master_secret: None,
        crdt_db: db_conn.clone(),
        tkauth_trust_anchors: None,
    });

    // Pre-seed one session token per role (all server-wide) plus one
    // scoped ca_operations token pinned to the "default" CA.
    {
        let mut map = sessions.lock().await;
        for (token, role) in [
            ("tok-admin", OperatorRole::Administrator),
            ("tok-caops", OperatorRole::CaOperations),
            ("tok-cara", OperatorRole::CaRa),
            ("tok-audit", OperatorRole::Auditor),
        ] {
            map.insert(
                token.to_string(),
                AdminSession {
                    operator_id: 1,
                    name: zeroize::Zeroizing::new(format!("test-{}", role.as_str())),
                    role,
                    created_at: Instant::now(),
                    last_active_at: Instant::now(),
                    auth_method: AdminAuthMethod::Cert,
                    ca_id: String::new(),
                },
            );
        }
        // Scoped ca_operations operator pinned to "default".
        map.insert(
            "tok-caops-scoped".to_string(),
            AdminSession {
                operator_id: 2,
                name: zeroize::Zeroizing::new("test-caops-scoped".to_string()),
                role: OperatorRole::CaOperations,
                created_at: Instant::now(),
                last_active_at: Instant::now(),
                auth_method: AdminAuthMethod::Cert,
                ca_id: "default".to_string(),
            },
        );
    }

    (state, dir)
}

fn token_for(role: OperatorRole) -> &'static str {
    match role {
        OperatorRole::Administrator => "tok-admin",
        OperatorRole::CaOperations => "tok-caops",
        OperatorRole::CaRa => "tok-cara",
        OperatorRole::Auditor => "tok-audit",
    }
}

async fn send_admin(
    router: &axum::Router,
    method: Method,
    path: &str,
    role: OperatorRole,
) -> StatusCode {
    let req = Request::builder()
        .method(method)
        .uri(path)
        .header(header::AUTHORIZATION, format!("Bearer {}", token_for(role)))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from("{}"))
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    resp.status()
}

// ── RBAC table ────────────────────────────────────────────────────────────────

// Each entry: (method, path, [roles that are ALLOWED (not 403)])
// Roles NOT listed will be expected to get 403.
const ALL_ROLES: [OperatorRole; 4] = [
    OperatorRole::Administrator,
    OperatorRole::CaOperations,
    OperatorRole::CaRa,
    OperatorRole::Auditor,
];

type RbacRow = (&'static str, Method, &'static str, &'static [OperatorRole]);

static RBAC_TABLE: &[RbacRow] = &[
    (
        "POST /admin/session",
        Method::POST,
        "/admin/session",
        &ALL_ROLES,
    ),
    (
        "DELETE /admin/session",
        Method::DELETE,
        "/admin/session",
        &ALL_ROLES,
    ),
    ("GET /admin/stats", Method::GET, "/admin/stats", &ALL_ROLES),
    ("GET /admin/eab", Method::GET, "/admin/eab", &ALL_ROLES),
    (
        "GET /admin/account/1/profile-grants",
        Method::GET,
        "/admin/account/1/profile-grants",
        &ALL_ROLES,
    ),
    (
        "GET /admin/certs",
        Method::GET,
        "/admin/certs",
        &[
            OperatorRole::Administrator,
            OperatorRole::CaOperations,
            OperatorRole::CaRa,
            OperatorRole::Auditor,
        ],
    ),
    (
        "POST /admin/eab",
        Method::POST,
        "/admin/eab",
        &[
            OperatorRole::Administrator,
            OperatorRole::CaOperations,
            // CaRa intentionally excluded: EAB keys are server-global and
            // must not be provisioned by a CA-scoped operator.
        ],
    ),
    (
        "POST /admin/revoke",
        Method::POST,
        "/admin/revoke",
        &[
            OperatorRole::Administrator,
            OperatorRole::CaOperations,
            OperatorRole::CaRa,
        ],
    ),
    (
        "DELETE /admin/eab/x",
        Method::DELETE,
        "/admin/eab/no-such-kid",
        &[OperatorRole::Administrator, OperatorRole::CaOperations],
    ),
    (
        "GET /admin/operators",
        Method::GET,
        "/admin/operators",
        &[OperatorRole::Administrator],
    ),
    (
        "POST /admin/operators",
        Method::POST,
        "/admin/operators",
        &[OperatorRole::Administrator],
    ),
    (
        "PATCH /admin/operators/1",
        Method::PATCH,
        "/admin/operators/1",
        &[OperatorRole::Administrator],
    ),
    (
        "GET /admin/audit",
        Method::GET,
        "/admin/audit",
        &[OperatorRole::Administrator, OperatorRole::Auditor],
    ),
    (
        "PUT /admin/account/1/profile-grants",
        Method::PUT,
        "/admin/account/1/profile-grants",
        &[OperatorRole::Administrator, OperatorRole::CaOperations],
    ),
    (
        "DELETE /admin/account/1/profile-grants",
        Method::DELETE,
        "/admin/account/1/profile-grants",
        &[OperatorRole::Administrator],
    ),
    (
        "POST /admin/crl/force",
        Method::POST,
        "/admin/crl/force",
        &[OperatorRole::Administrator, OperatorRole::CaOperations],
    ),
    (
        "GET /admin/delegations",
        Method::GET,
        "/admin/delegations",
        &ALL_ROLES,
    ),
    (
        "POST /admin/delegations",
        Method::POST,
        "/admin/delegations",
        &[OperatorRole::Administrator, OperatorRole::CaOperations],
    ),
    (
        "GET /admin/delegations/{id}",
        Method::GET,
        "/admin/delegations/nonexistent-id",
        &ALL_ROLES,
    ),
    (
        "PUT /admin/delegations/{id}",
        Method::PUT,
        "/admin/delegations/nonexistent-id",
        &[OperatorRole::Administrator, OperatorRole::CaOperations],
    ),
    (
        "DELETE /admin/delegations/{id}",
        Method::DELETE,
        "/admin/delegations/nonexistent-id",
        &[OperatorRole::Administrator, OperatorRole::CaOperations],
    ),
    (
        "PUT /admin/operators/{id}",
        Method::PUT,
        "/admin/operators/1",
        &[OperatorRole::Administrator],
    ),
    (
        "GET /admin/accounts",
        Method::GET,
        "/admin/accounts",
        &ALL_ROLES,
    ),
    (
        "GET /admin/orders",
        Method::GET,
        "/admin/orders",
        &ALL_ROLES,
    ),
    (
        "GET /admin/cas",
        Method::GET,
        "/admin/cas",
        &[OperatorRole::Administrator, OperatorRole::CaOperations],
    ),
    (
        "GET /admin/cas/{id}",
        Method::GET,
        "/admin/cas/default",
        &[OperatorRole::Administrator, OperatorRole::CaOperations],
    ),
    (
        "GET /admin/config",
        Method::GET,
        "/admin/config",
        &[OperatorRole::Administrator],
    ),
    (
        "GET /admin/certs/{id}",
        Method::GET,
        "/admin/certs/nonexistent-cert-id",
        &ALL_ROLES,
    ),
    (
        "GET /admin/certs/{id}/download",
        Method::GET,
        "/admin/certs/nonexistent-cert-id/download",
        &[
            OperatorRole::Administrator,
            OperatorRole::CaOperations,
            OperatorRole::CaRa,
        ],
    ),
    (
        "POST /admin/ca/{id}/crl/force",
        Method::POST,
        "/admin/ca/default/crl/force",
        &[OperatorRole::Administrator, OperatorRole::CaOperations],
    ),
];

// ── Test ──────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn admin_rbac_table() {
    let (state, _dir) = build_admin_state().await;
    let router = routes::build_router(Arc::clone(&state), None);

    // Re-seed helper: some routes (DELETE /admin/session) consume session tokens;
    // re-insert the 4 test tokens before each row so all rows start clean.
    let reseed = |state: &Arc<akamu::state::AppState>| {
        let sessions = Arc::clone(state.admin_sessions.as_ref().unwrap());
        async move {
            let mut map = sessions.lock().await;
            for (token, role) in [
                ("tok-admin", OperatorRole::Administrator),
                ("tok-caops", OperatorRole::CaOperations),
                ("tok-cara", OperatorRole::CaRa),
                ("tok-audit", OperatorRole::Auditor),
            ] {
                map.insert(
                    token.to_string(),
                    akamu::state::AdminSession {
                        operator_id: 1,
                        name: zeroize::Zeroizing::new(format!("test-{}", role.as_str())),
                        role,
                        created_at: Instant::now(),
                        last_active_at: Instant::now(),
                        auth_method: akamu::state::AdminAuthMethod::Cert,
                        ca_id: String::new(),
                    },
                );
            }
        }
    };

    for (label, method, path, allowed) in RBAC_TABLE {
        reseed(&state).await;
        for role in &ALL_ROLES {
            let status = send_admin(&router, method.clone(), path, *role).await;
            let is_allowed = allowed.contains(role);
            if is_allowed {
                assert_ne!(
                    status,
                    StatusCode::FORBIDDEN,
                    "{label}: role {:?} should be allowed but got 403",
                    role
                );
                // Also not 401 — session should be valid
                assert_ne!(
                    status,
                    StatusCode::UNAUTHORIZED,
                    "{label}: role {:?} got 401 (session not found)",
                    role
                );
            } else {
                assert_eq!(
                    status,
                    StatusCode::FORBIDDEN,
                    "{label}: role {:?} should be forbidden but got {status}",
                    role
                );
            }
        }
    }
}

// ── CA-scope guard tests ──────────────────────────────────────────────────────

/// A scoped ca_operations operator can access its own CA.
#[tokio::test]
async fn scoped_ca_operations_sees_own_ca_resource() {
    let (state, _dir) = build_admin_state().await;
    let router = routes::build_router(Arc::clone(&state), None);

    let req = Request::builder()
        .method(Method::GET)
        .uri("/admin/cas/default")
        .header(header::AUTHORIZATION, "Bearer tok-caops-scoped")
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "scoped ca_operations must see its own CA"
    );
}

// ── PUT /admin/operators/{id} ca_id validation tests ─────────────────────────

/// Setting a non-empty ca_id on an administrator role must return 400.
#[tokio::test]
async fn put_operator_ca_id_on_administrator_is_bad_request() {
    let (state, _dir) = build_admin_state().await;
    let router = routes::build_router(Arc::clone(&state), None);

    let req = Request::builder()
        .method(Method::PUT)
        .uri("/admin/operators/1")
        .header(header::AUTHORIZATION, "Bearer tok-admin")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(r#"{"role":"administrator","ca_id":"default"}"#))
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "setting ca_id on administrator must be 400"
    );
}

/// Setting an empty ca_id on a ca_ra role must return 400 (ca_ra requires a scope).
#[tokio::test]
async fn put_operator_empty_ca_id_on_ca_ra_is_bad_request() {
    let (state, _dir) = build_admin_state().await;
    let router = routes::build_router(Arc::clone(&state), None);

    let req = Request::builder()
        .method(Method::PUT)
        .uri("/admin/operators/1")
        .header(header::AUTHORIZATION, "Bearer tok-admin")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(r#"{"role":"ca_ra","ca_id":""}"#))
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "empty ca_id on ca_ra must be 400"
    );
}

/// Setting a valid CA ca_id on a ca_operations role must be accepted (not 400/403).
#[tokio::test]
async fn put_operator_ca_id_on_ca_operations_is_accepted() {
    let (state, _dir) = build_admin_state().await;

    // Insert a real operator so the PUT has a row to update.
    let now = akamu::util::rfc3339_now();
    db::operators::insert(
        &state.db,
        "test-caops-op",
        "ca_operations",
        Some("aa:bb:cc:dd"),
        None,
        "",
        &now,
    )
    .await
    .unwrap();
    let ops = db::operators::list(&state.db, 10, 0).await.unwrap();
    let op_id = ops[0].id;

    let router = routes::build_router(Arc::clone(&state), None);

    let body = format!(r#"{{"role":"ca_operations","ca_id":"default"}}"#);
    let req = Request::builder()
        .method(Method::PUT)
        .uri(format!("/admin/operators/{op_id}"))
        .header(header::AUTHORIZATION, "Bearer tok-admin")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body))
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_ne!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "valid ca_id on ca_operations must not be 400"
    );
    assert_ne!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "valid ca_id on ca_operations must not be 403"
    );
}

/// A scoped ca_operations operator gets 404 for a CA outside its scope.
#[tokio::test]
async fn scoped_ca_operations_blocked_from_other_ca_resource() {
    let (state, _dir) = build_admin_state().await;
    let router = routes::build_router(Arc::clone(&state), None);

    let req = Request::builder()
        .method(Method::GET)
        .uri("/admin/cas/other-ca")
        .header(header::AUTHORIZATION, "Bearer tok-caops-scoped")
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    // 404 — same camouflage as "CA doesn't exist"; the scope mismatch is hidden.
    assert_eq!(
        resp.status(),
        StatusCode::NOT_FOUND,
        "scoped ca_operations must not see CAs outside its scope"
    );
}
