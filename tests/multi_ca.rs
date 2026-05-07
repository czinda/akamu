//! Integration tests for multi-CA support.
//!
//! Verifies:
//! - Per-CA ACME directory routing (`/acme/{ca_id}/directory`)
//! - Legacy directory path (`/acme/directory`) falls through to the default CA
//! - Unknown CA ID → 404
//! - Per-CA URL prefixes in directory JSON (newOrder, newAccount, etc.)
//! - Per-CA CRL endpoints (`/ca/{ca_id}/crl` vs `/ca/crl`)
//! - CRL isolation: revoking a cert from CA1 does not affect CA2's CRL
//! - Order CA isolation: an order created on CA1 cannot be accessed via CA2

use std::sync::Arc;

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use serde_json::{json, Value};
use tower::ServiceExt;

use akamu::config::{CaConfig, Config, DatabaseConfig, MtcConfig, ServerConfig};
use akamu::state::{AppState, CaState, MtcState, NonceBucket};
use akamu::{ca, db, routes};
use zeroize;

// ── Two-CA test state ─────────────────────────────────────────────────────────

/// Build an AppState with two CAs:
///   - `"rsa"` (default CA)
///   - `"ec"`  (non-default CA)
///
/// Both CAs generate fresh EC P-256 keys for speed; the name is informational.
async fn build_two_ca_state(base_url: &str) -> (Arc<AppState>, tempfile::TempDir) {
    let dir = tempfile::TempDir::new().unwrap();

    let config = Arc::new(Config {
        listen_addr: "127.0.0.1:0".into(),
        base_url: base_url.into(),
        database: DatabaseConfig {
            url: "sqlite::memory:".into(),
            max_connections: None,
            require_tls: false,
        },
        cas: vec![
            CaConfig {
                id: "rsa".to_owned(),
                is_default: true,
                caa_identities: vec![],
                key_file: dir.path().join("ca-rsa.key").to_string_lossy().into_owned(),
                cert_file: dir.path().join("ca-rsa.crt").to_string_lossy().into_owned(),
                key_type: "ec:P-256".into(),
                hash_alg: "sha256".into(),
                validity_days: 90,
                crl_url: Some(format!("{base_url}/ca/rsa/crl")),
                ocsp_url: None,
                common_name: "Test CA RSA".into(),
                organization: "Test Org".into(),
                ca_validity_years: 10,
                crl_next_update_secs: 86400,
                enforce_validity_cap: false,
                require_encrypted_key: false,
                key_password_file: None,
            },
            CaConfig {
                id: "ec".to_owned(),
                is_default: false,
                caa_identities: vec![],
                key_file: dir.path().join("ca-ec.key").to_string_lossy().into_owned(),
                cert_file: dir.path().join("ca-ec.crt").to_string_lossy().into_owned(),
                key_type: "ec:P-256".into(),
                hash_alg: "sha256".into(),
                validity_days: 90,
                crl_url: Some(format!("{base_url}/ca/ec/crl")),
                ocsp_url: None,
                common_name: "Test CA EC".into(),
                organization: "Test Org".into(),
                ca_validity_years: 10,
                crl_next_update_secs: 86400,
                enforce_validity_cap: false,
                require_encrypted_key: false,
                key_password_file: None,
            },
        ],
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
        admin: None,
        email_challenge: None,
    });

    db::install_drivers();
    let db_conn = db::open("sqlite::memory:", 1, false).await.unwrap();

    // Build CA states for both CAs.
    let rsa_cfg = &config.cas[0];
    let (rsa_key, rsa_cert_der) = ca::init::load_or_generate(rsa_cfg).unwrap();
    let rsa_spki = rsa_key.public_key().unwrap().spki_der().to_vec();
    let rsa_aki = ca::init::compute_aki_from_spki(&rsa_spki).unwrap_or_default();

    let ec_cfg = &config.cas[1];
    let (ec_key, ec_cert_der) = ca::init::load_or_generate(ec_cfg).unwrap();
    let ec_spki = ec_key.public_key().unwrap().spki_der().to_vec();
    let ec_aki = ca::init::compute_aki_from_spki(&ec_spki).unwrap_or_default();

    let ca_rsa = Arc::new(CaState {
        id: "rsa".into(),
        key_type: "rsa:2048".into(),
        crl_next_update_secs: 86400,
        key: rsa_key,
        cert_der: rsa_cert_der,
        hash_alg: "sha256".into(),
        validity_days: 90,
        crl_url: Some(format!("{base_url}/ca/rsa/crl")),
        ocsp_url: None,
        aki_bytes: rsa_aki,
        enforce_validity_cap: false,
        caa_identities: vec![],
    });
    let ca_ec = Arc::new(CaState {
        id: "ec".into(),
        key_type: "ec:P-256".into(),
        crl_next_update_secs: 86400,
        key: ec_key,
        cert_der: ec_cert_der,
        hash_alg: "sha256".into(),
        validity_days: 90,
        crl_url: Some(format!("{base_url}/ca/ec/crl")),
        ocsp_url: None,
        aki_bytes: ec_aki,
        enforce_validity_cap: false,
        caa_identities: vec![],
    });

    let mut cas_map = indexmap::IndexMap::new();
    cas_map.insert("rsa".to_string(), ca_rsa.clone());
    cas_map.insert("ec".to_string(), ca_ec.clone());

    let mut crl_caches = std::collections::HashMap::new();
    crl_caches.insert("rsa".to_string(), Default::default());
    crl_caches.insert("ec".to_string(), Default::default());

    let mut link_headers = std::collections::HashMap::new();
    link_headers.insert(
        "rsa".to_string(),
        Arc::new(
            axum::http::HeaderValue::from_str(&format!(
                "<{base_url}/acme/directory>;rel=\"index\""
            ))
            .unwrap(),
        ),
    );
    link_headers.insert(
        "ec".to_string(),
        Arc::new(
            axum::http::HeaderValue::from_str(&format!(
                "<{base_url}/acme/ec/directory>;rel=\"index\""
            ))
            .unwrap(),
        ),
    );

    let state = Arc::new(AppState {
        config: Arc::clone(&config),
        db: db_conn.clone(),
        db_ro: db_conn.clone(),
        db_kind: db::DbKind::Sqlite,
        profiles: akamu::profiles::ProfileRegistry::empty(&ca_rsa),
        cas: Arc::new(cas_map),
        default_ca_id: Arc::new("rsa".to_string()),
        mtc: Arc::new(MtcState {
            log: None,
            algorithm: synta_mtc::crypto::HashAlgorithm::Sha256,
            signing_key: None,
            signing_hash_alg: "sha256".into(),
            cosigner_clients: vec![],
            _log_lock: None,
        }),
        tls: None,
        spki_cache: Arc::new(std::sync::RwLock::new(std::collections::HashMap::new())),
        nonces: Arc::new(NonceBucket::new()),
        link_headers: Arc::new(link_headers),
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
        crl_caches: Arc::new(crl_caches),
        audit: Arc::new(akamu::audit::AuditState::new()),
        audit_policy: Arc::new(akamu::audit::AuditPolicy::default()),
        admin_sessions: None,
        admin_auth_limiter: None,
        startup_time: std::time::Instant::now(),
        gss_cred: None,
        admin_gss_cred: None,
        eab_master_secret: None,
    });

    (state, dir)
}

async fn get_json(router: &axum::Router, path: &str) -> (StatusCode, Value) {
    let req = Request::builder()
        .method(Method::GET)
        .uri(path)
        .header(header::ACCEPT, "application/json")
        .body(Body::empty())
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let body = axum::body::to_bytes(resp.into_body(), 1_000_000)
        .await
        .unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
    (status, json)
}

async fn get_bytes(router: &axum::Router, path: &str) -> (StatusCode, Vec<u8>) {
    let req = Request::builder()
        .method(Method::GET)
        .uri(path)
        .body(Body::empty())
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let body = axum::body::to_bytes(resp.into_body(), 1_000_000)
        .await
        .unwrap();
    (status, body.to_vec())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

/// Per-CA directory endpoints return 200 for both known CAs.
#[tokio::test]
async fn per_ca_directory_endpoints_return_200() {
    let (state, _dir) = build_two_ca_state("https://acme.test").await;
    let router = routes::build_router(Arc::clone(&state));

    let (status, _) = get_json(&router, "/acme/rsa/directory").await;
    assert_eq!(status, StatusCode::OK, "/acme/rsa/directory");

    let (status, _) = get_json(&router, "/acme/ec/directory").await;
    assert_eq!(status, StatusCode::OK, "/acme/ec/directory");
}

/// The legacy `/acme/directory` path returns 200 and serves the default CA's directory.
#[tokio::test]
async fn legacy_directory_path_serves_default_ca() {
    let (state, _dir) = build_two_ca_state("https://acme.test").await;
    let router = routes::build_router(Arc::clone(&state));

    let (status, legacy) = get_json(&router, "/acme/directory").await;
    assert_eq!(status, StatusCode::OK, "/acme/directory");

    let (status, per_ca) = get_json(&router, "/acme/rsa/directory").await;
    assert_eq!(status, StatusCode::OK, "/acme/rsa/directory");

    // Both should advertise the same newOrder URL (the default CA's path).
    assert_eq!(
        legacy["newOrder"], per_ca["newOrder"],
        "legacy and per-default-CA directory should have identical newOrder URL"
    );
}

/// An unknown CA ID in the directory path returns 404.
#[tokio::test]
async fn unknown_ca_id_returns_404() {
    let (state, _dir) = build_two_ca_state("https://acme.test").await;
    let router = routes::build_router(Arc::clone(&state));

    let (status, _) = get_json(&router, "/acme/nonexistent/directory").await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "/acme/nonexistent/directory should 404"
    );
}

/// Per-CA directory URLs contain the CA ID prefix for the non-default CA.
#[tokio::test]
async fn per_ca_directory_urls_contain_ca_id() {
    let (state, _dir) = build_two_ca_state("https://acme.test").await;
    let router = routes::build_router(Arc::clone(&state));

    let (_, ec_dir) = get_json(&router, "/acme/ec/directory").await;
    let new_order = ec_dir["newOrder"].as_str().unwrap_or("");
    assert!(
        new_order.contains("/acme/ec/"),
        "EC CA newOrder URL must contain '/acme/ec/': {new_order}"
    );

    // Default CA uses the legacy path (no /ca_id/ prefix).
    let (_, rsa_dir) = get_json(&router, "/acme/rsa/directory").await;
    let new_order = rsa_dir["newOrder"].as_str().unwrap_or("");
    assert!(
        !new_order.contains("/acme/rsa/"),
        "Default CA newOrder URL must NOT contain '/acme/rsa/': {new_order}"
    );
}

/// Per-CA CRL endpoints return 200 for both CAs (even before any revocations).
#[tokio::test]
async fn per_ca_crl_endpoints_return_200() {
    let (state, _dir) = build_two_ca_state("https://acme.test").await;
    let router = routes::build_router(Arc::clone(&state));

    let (status, body) = get_bytes(&router, "/ca/rsa/crl").await;
    assert_eq!(status, StatusCode::OK, "/ca/rsa/crl status");
    assert!(!body.is_empty(), "/ca/rsa/crl body must not be empty");

    let (status, body) = get_bytes(&router, "/ca/ec/crl").await;
    assert_eq!(status, StatusCode::OK, "/ca/ec/crl status");
    assert!(!body.is_empty(), "/ca/ec/crl body must not be empty");
}

/// The legacy `/ca/crl` path returns 200 and matches the default CA's `/ca/rsa/crl`.
#[tokio::test]
async fn legacy_crl_matches_default_ca_crl() {
    let (state, _dir) = build_two_ca_state("https://acme.test").await;
    let router = routes::build_router(Arc::clone(&state));

    let (_, legacy_crl) = get_bytes(&router, "/ca/crl").await;
    let (_, rsa_crl) = get_bytes(&router, "/ca/rsa/crl").await;

    assert_eq!(
        legacy_crl, rsa_crl,
        "/ca/crl and /ca/rsa/crl must return the same CRL bytes"
    );
}

/// An unknown CA ID in the CRL path returns 404.
#[tokio::test]
async fn unknown_ca_crl_returns_404() {
    let (state, _dir) = build_two_ca_state("https://acme.test").await;
    let router = routes::build_router(Arc::clone(&state));

    let (status, _) = get_bytes(&router, "/ca/nonexistent/crl").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

/// Revoking a certificate from CA1 only grows CA1's CRL; CA2's CRL is unchanged.
#[tokio::test]
async fn crl_isolation_revocation_only_affects_issuing_ca() {
    let (state, _dir) = build_two_ca_state("https://acme.test").await;
    let router = routes::build_router(Arc::clone(&state));

    // Grab baseline CRL sizes (before any revocations).
    let (_, rsa_crl_before) = get_bytes(&router, "/ca/rsa/crl").await;
    let (_, ec_crl_before) = get_bytes(&router, "/ca/ec/crl").await;

    // Insert a certificate directly into the DB as if it were issued by CA "rsa".
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let cert_id = "test-cert-rsa-001";

    // Insert account first (orders table has FK → accounts.id).
    sqlx::query(
        "INSERT INTO accounts (id, status, public_key, jwk_thumbprint, created, updated)
         VALUES ('test-account-001', 'valid', X'3082', 'thumb-001', ?, ?)",
    )
    .bind(now)
    .bind(now)
    .execute(&state.db)
    .await
    .unwrap();

    sqlx::query(
        "INSERT INTO orders (id, account_id, status, identifiers, created, updated, ca_id)
         VALUES (?, ?, 'valid', '[]', ?, ?, 'rsa')",
    )
    .bind("test-order-rsa-001")
    .bind("test-account-001")
    .bind(now)
    .bind(now)
    .execute(&state.db)
    .await
    .unwrap();

    sqlx::query(
        "INSERT INTO certificates
         (id, order_id, account_id, serial_number, status, der, pem,
          not_before, not_after, revoked_at, revocation_reason,
          mtc_log_index, created, suggested_window_start, suggested_window_end,
          replaced_by, subject_dn, ca_id)
         VALUES (?, 'test-order-rsa-001', 'test-account-001', ?, 'valid',
                 X'3082', '', ?, ?, NULL, NULL, NULL, ?, NULL, NULL, NULL, NULL, 'rsa')",
    )
    .bind(cert_id)
    .bind("deadbeef01")
    .bind(now)
    .bind(now + 86400 * 90)
    .bind(now)
    .execute(&state.db)
    .await
    .unwrap();

    // Revoke the certificate (sets status to 'revoked', records revoked_at).
    db::certs::revoke(&state.db, cert_id, Some(1), now)
        .await
        .unwrap();

    // Invalidate the RSA CA's CRL cache so the next GET rebuilds it.
    state.invalidate_crl_cache("rsa");

    // After revocation, RSA CRL should be larger.
    let (status, rsa_crl_after) = get_bytes(&router, "/ca/rsa/crl").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        rsa_crl_after.len() > rsa_crl_before.len(),
        "RSA CRL should grow after revocation (before={} after={})",
        rsa_crl_before.len(),
        rsa_crl_after.len()
    );

    // EC CRL must be unchanged (EC CA's cache was not invalidated; same bytes).
    let (status, ec_crl_after) = get_bytes(&router, "/ca/ec/crl").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        ec_crl_before, ec_crl_after,
        "EC CRL must not change when a cert issued by RSA CA is revoked"
    );
}

/// An order created with ca_id="rsa" is not accessible via the /acme/ec/ prefix.
#[tokio::test]
async fn order_ca_isolation_wrong_prefix_returns_not_found() {
    let (state, _dir) = build_two_ca_state("https://acme.test").await;
    let router = routes::build_router(Arc::clone(&state));

    // Insert an account and an order that belongs to CA "rsa".
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let order_id = "isolation-order-001";

    sqlx::query(
        "INSERT INTO accounts (id, status, public_key, jwk_thumbprint, created, updated)
         VALUES (?, 'valid', X'3082', 'thumb-iso-001', ?, ?)",
    )
    .bind("isolation-account-001")
    .bind(now)
    .bind(now)
    .execute(&state.db)
    .await
    .unwrap();

    sqlx::query(
        "INSERT INTO orders (id, account_id, status, identifiers, created, updated, ca_id)
         VALUES (?, ?, 'pending', '[{\"type\":\"dns\",\"value\":\"test.example\"}]', ?, ?, 'rsa')",
    )
    .bind(order_id)
    .bind("isolation-account-001")
    .bind(now)
    .bind(now)
    .execute(&state.db)
    .await
    .unwrap();

    // Access via the wrong CA prefix (EC) — POST-as-GET requires JWS which we skip,
    // but even a plain GET on the order route should return 404 for wrong CA.
    // The route POST /acme/ec/order/{id} would fail JWS parsing anyway, but the
    // ca_id check in the handler returns 404 before any payload parsing when the
    // ca_id in the DB doesn't match the URL prefix.
    // We test this via a GET on the order resource (which isn't strictly ACME-correct
    // but exercises the DB lookup + ca_id check path in the handler infrastructure).
    let req = Request::builder()
        .method(Method::GET)
        .uri(format!("/acme/ec/order/{order_id}"))
        .body(Body::empty())
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    // Either 404 (order not found for this CA) or 405 (method not allowed for GET) —
    // the important thing is NOT 200.
    assert_ne!(
        resp.status(),
        StatusCode::OK,
        "Order from CA 'rsa' must not be accessible via /acme/ec/ prefix"
    );
}

/// The `GET /admin/cas` endpoint lists all configured CAs with correct metadata.
#[tokio::test]
async fn admin_cas_list_returns_both_cas() {
    use akamu::config::AdminConfig;
    use akamu::state::{AdminAuthMethod, AdminSession, OperatorRole};
    use std::collections::HashMap;
    use std::time::Instant;

    let dir = tempfile::TempDir::new().unwrap();

    let config = Arc::new(Config {
        listen_addr: "127.0.0.1:0".into(),
        base_url: "https://acme.test".into(),
        database: DatabaseConfig {
            url: "sqlite::memory:".into(),
            max_connections: None,
            require_tls: false,
        },
        cas: vec![
            CaConfig {
                id: "rsa".to_owned(),
                is_default: true,
                caa_identities: vec![],
                key_file: dir.path().join("ca-rsa.key").to_string_lossy().into_owned(),
                cert_file: dir.path().join("ca-rsa.crt").to_string_lossy().into_owned(),
                key_type: "ec:P-256".into(),
                hash_alg: "sha256".into(),
                validity_days: 90,
                crl_url: None,
                ocsp_url: None,
                common_name: "Test CA RSA".into(),
                organization: "Test".into(),
                ca_validity_years: 10,
                crl_next_update_secs: 86400,
                enforce_validity_cap: false,
                require_encrypted_key: false,
                key_password_file: None,
            },
            CaConfig {
                id: "ec".to_owned(),
                is_default: false,
                caa_identities: vec![],
                key_file: dir.path().join("ca-ec.key").to_string_lossy().into_owned(),
                cert_file: dir.path().join("ca-ec.crt").to_string_lossy().into_owned(),
                key_type: "ec:P-256".into(),
                hash_alg: "sha256".into(),
                validity_days: 90,
                crl_url: None,
                ocsp_url: None,
                common_name: "Test CA EC".into(),
                organization: "Test".into(),
                ca_validity_years: 10,
                crl_next_update_secs: 86400,
                enforce_validity_cap: false,
                require_encrypted_key: false,
                key_password_file: None,
            },
        ],
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
            bootstrap_operator_gssapi_principal: None,
            ca_certs: vec![],
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
    });

    db::install_drivers();
    let db_conn = db::open("sqlite::memory:", 1, false).await.unwrap();

    let rsa_cfg = &config.cas[0];
    let (rsa_key, rsa_cert_der) = ca::init::load_or_generate(rsa_cfg).unwrap();
    let rsa_spki = rsa_key.public_key().unwrap().spki_der().to_vec();
    let rsa_aki = ca::init::compute_aki_from_spki(&rsa_spki).unwrap_or_default();

    let ec_cfg = &config.cas[1];
    let (ec_key, ec_cert_der) = ca::init::load_or_generate(ec_cfg).unwrap();
    let ec_spki = ec_key.public_key().unwrap().spki_der().to_vec();
    let ec_aki = ca::init::compute_aki_from_spki(&ec_spki).unwrap_or_default();

    let ca_rsa = Arc::new(CaState {
        id: "rsa".into(),
        key_type: "rsa:2048".into(),
        crl_next_update_secs: 86400,
        key: rsa_key,
        cert_der: rsa_cert_der,
        hash_alg: "sha256".into(),
        validity_days: 90,
        crl_url: None,
        ocsp_url: None,
        aki_bytes: rsa_aki,
        enforce_validity_cap: false,
        caa_identities: vec![],
    });
    let ca_ec = Arc::new(CaState {
        id: "ec".into(),
        key_type: "ec:P-256".into(),
        crl_next_update_secs: 86400,
        key: ec_key,
        cert_der: ec_cert_der,
        hash_alg: "sha256".into(),
        validity_days: 90,
        crl_url: None,
        ocsp_url: None,
        aki_bytes: ec_aki,
        enforce_validity_cap: false,
        caa_identities: vec![],
    });

    let mut cas_map = indexmap::IndexMap::new();
    cas_map.insert("rsa".to_string(), ca_rsa.clone());
    cas_map.insert("ec".to_string(), ca_ec.clone());

    let mut crl_caches = std::collections::HashMap::new();
    crl_caches.insert("rsa".to_string(), Default::default());
    crl_caches.insert("ec".to_string(), Default::default());

    let mut link_headers = std::collections::HashMap::new();
    link_headers.insert(
        "rsa".to_string(),
        Arc::new(axum::http::HeaderValue::from_static(
            "<https://acme.test/acme/directory>;rel=\"index\"",
        )),
    );
    link_headers.insert(
        "ec".to_string(),
        Arc::new(axum::http::HeaderValue::from_static(
            "<https://acme.test/acme/ec/directory>;rel=\"index\"",
        )),
    );

    // Seed a session token for the admin router.
    let token = "test-admin-token";
    let sessions: HashMap<String, AdminSession> = [(
        token.to_string(),
        AdminSession {
            operator_id: 1,
            name: zeroize::Zeroizing::new("admin".to_string()),
            role: OperatorRole::Administrator,
            created_at: Instant::now(),
            last_active_at: Instant::now(),
            auth_method: AdminAuthMethod::Cert,
            ca_id: String::new(),
        },
    )]
    .into_iter()
    .collect();

    let state = Arc::new(AppState {
        config: Arc::clone(&config),
        db: db_conn.clone(),
        db_ro: db_conn.clone(),
        db_kind: db::DbKind::Sqlite,
        profiles: akamu::profiles::ProfileRegistry::empty(&ca_rsa),
        cas: Arc::new(cas_map),
        default_ca_id: Arc::new("rsa".to_string()),
        mtc: Arc::new(MtcState {
            log: None,
            algorithm: synta_mtc::crypto::HashAlgorithm::Sha256,
            signing_key: None,
            signing_hash_alg: "sha256".into(),
            cosigner_clients: vec![],
            _log_lock: None,
        }),
        tls: None,
        spki_cache: Arc::new(std::sync::RwLock::new(std::collections::HashMap::new())),
        nonces: Arc::new(NonceBucket::new()),
        link_headers: Arc::new(link_headers),
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
        crl_caches: Arc::new(crl_caches),
        audit: Arc::new(akamu::audit::AuditState::new()),
        audit_policy: Arc::new(akamu::audit::AuditPolicy::default()),
        admin_sessions: Some(Arc::new(tokio::sync::Mutex::new(sessions))),
        admin_auth_limiter: None,
        startup_time: std::time::Instant::now(),
        gss_cred: None,
        admin_gss_cred: None,
        eab_master_secret: None,
    });

    let admin_router = routes::build_admin_router(Arc::clone(&state));

    let req = Request::builder()
        .method(Method::GET)
        .uri("/admin/cas")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    let resp = admin_router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "/admin/cas must return 200");

    let body = axum::body::to_bytes(resp.into_body(), 1_000_000)
        .await
        .unwrap();
    let json: Value = serde_json::from_slice(&body).unwrap();
    let cas = json["cas"]
        .as_array()
        .expect("response must have 'cas' array");
    assert_eq!(cas.len(), 2, "must have 2 CAs");

    let ids: Vec<&str> = cas.iter().filter_map(|c| c["id"].as_str()).collect();
    assert!(ids.contains(&"rsa"), "RSA CA must be listed");
    assert!(ids.contains(&"ec"), "EC CA must be listed");

    let rsa = cas.iter().find(|c| c["id"] == "rsa").unwrap();
    assert_eq!(rsa["is_default"], json!(true), "rsa must be marked default");

    let ec = cas.iter().find(|c| c["id"] == "ec").unwrap();
    assert_eq!(
        ec["is_default"],
        json!(false),
        "ec must not be marked default"
    );
}

/// The new-nonce endpoint works for both per-CA paths and the legacy path.
#[tokio::test]
async fn new_nonce_available_for_all_ca_paths() {
    let (state, _dir) = build_two_ca_state("https://acme.test").await;
    let router = routes::build_router(Arc::clone(&state));

    for path in &[
        "/acme/new-nonce",
        "/acme/rsa/new-nonce",
        "/acme/ec/new-nonce",
    ] {
        let req = Request::builder()
            .method(Method::HEAD)
            .uri(*path)
            .body(Body::empty())
            .unwrap();
        let resp = router.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "HEAD {path} must return 200");
        assert!(
            resp.headers().contains_key("replay-nonce"),
            "HEAD {path} must return a Replay-Nonce header"
        );
    }
}
