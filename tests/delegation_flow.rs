//! Integration tests for RFC 9115 ACME Delegated Certificates.
//!
//! Tests the full IdO-facing delegation flow without a network socket:
//!
//!   - Admin creates a delegation config for an NDC account.
//!   - NDC lists delegations via POST-as-GET.
//!   - NDC fetches a single delegation object (CSR template).
//!   - NDC places an order referencing the delegation → `ready`, `authorizations: []`.
//!   - NDC finalises with a CSR that matches the template → `valid`, cert issued.
//!   - NDC finalises with a CSR that violates the template → `badCSR`.
//!   - NDC places an order with an unknown delegation URL → `unknownDelegation`.
//!   - NDC fetches cert via unauthenticated GET when `allow-certificate-get` was granted.
//!   - Another account cannot fetch cert without `allow-certificate-get`.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde_json::{json, Value};
use synta_certificate::{
    BackendPrivateKey, CertificateSigner as _, CsrBuilder, NameBuilder, PrivateKey as _,
    SubjectAlternativeNameBuilder,
};
use tower::ServiceExt;
use zeroize::Zeroizing;

use akamu::config::{AdminConfig, CaConfig, Config, DatabaseConfig, MtcConfig, ServerConfig};
use akamu::state::{
    AdminAuthMethod, AdminSession, AppState, CaState, MtcState, NonceBucket, OperatorRole,
};
use akamu::{ca, db, routes};

// ── TestKey & JWS helpers (mirrors acme_flow.rs) ─────────────────────────────

struct TestKey {
    key: BackendPrivateKey,
    x_b64: String,
    y_b64: String,
}

impl TestKey {
    fn generate() -> Self {
        let key = BackendPrivateKey::generate_ec("P-256").unwrap();
        let pub_key = key.public_key().unwrap();
        let (x_bytes, y_bytes) = pub_key.ec_affine_coordinates().unwrap().unwrap();
        let x_b64 = encode_coord(&x_bytes, 32);
        let y_b64 = encode_coord(&y_bytes, 32);
        TestKey { key, x_b64, y_b64 }
    }

    fn jwk(&self) -> Value {
        json!({"kty": "EC", "crv": "P-256", "x": self.x_b64, "y": self.y_b64})
    }

    fn jws_with_jwk(&self, nonce: &str, url: &str, payload: Option<Value>) -> Value {
        let header = json!({"alg": "ES256", "nonce": nonce, "url": url, "jwk": self.jwk()});
        self.build_jws(header, payload)
    }

    fn jws_with_kid(&self, kid: &str, nonce: &str, url: &str, payload: Option<Value>) -> Value {
        let header = json!({"alg": "ES256", "nonce": nonce, "url": url, "kid": kid});
        self.build_jws(header, payload)
    }

    fn build_jws(&self, header: Value, payload: Option<Value>) -> Value {
        let protected = URL_SAFE_NO_PAD.encode(header.to_string().as_bytes());
        let payload_b64 = match payload {
            Some(v) => URL_SAFE_NO_PAD.encode(v.to_string().as_bytes()),
            None => String::new(),
        };
        let signing_input = format!("{}.{}", protected, payload_b64);
        let signer = self.key.as_signer("sha256");
        let der_sig = signer.sign_tbs(signing_input.as_bytes()).unwrap();
        let p1363 = ecdsa_der_to_p1363(&der_sig, 32).unwrap();
        let signature = URL_SAFE_NO_PAD.encode(&p1363);
        json!({"protected": protected, "payload": payload_b64, "signature": signature})
    }
}

fn encode_coord(bytes: &[u8], len: usize) -> String {
    let mut padded = vec![0u8; len];
    let start = len.saturating_sub(bytes.len());
    padded[start..].copy_from_slice(&bytes[bytes.len().saturating_sub(len)..]);
    URL_SAFE_NO_PAD.encode(&padded)
}

fn ecdsa_der_to_p1363(der: &[u8], half: usize) -> Option<Vec<u8>> {
    let inner = strip_tlv(der, 0x30)?;
    let (r, rest) = strip_integer(inner)?;
    let (s, _) = strip_integer(rest)?;
    if r.len() > half || s.len() > half {
        return None;
    }
    let mut out = vec![0u8; half * 2];
    out[half - r.len()..half].copy_from_slice(r);
    out[half * 2 - s.len()..].copy_from_slice(s);
    Some(out)
}

fn strip_tlv(buf: &[u8], tag: u8) -> Option<&[u8]> {
    if *buf.first()? != tag {
        return None;
    }
    let (len, rest) = decode_der_len(&buf[1..])?;
    rest.get(..len)
}

fn strip_integer(buf: &[u8]) -> Option<(&[u8], &[u8])> {
    if *buf.first()? != 0x02 {
        return None;
    }
    let (len, rest) = decode_der_len(&buf[1..])?;
    let val = rest.get(..len)?;
    let val = val.strip_prefix(&[0x00u8]).unwrap_or(val);
    Some((val, &rest[len..]))
}

fn decode_der_len(buf: &[u8]) -> Option<(usize, &[u8])> {
    let first = *buf.first()?;
    if first < 0x80 {
        Some((first as usize, &buf[1..]))
    } else if first == 0x81 {
        Some((*buf.get(1)? as usize, &buf[2..]))
    } else if first == 0x82 {
        let len = (*buf.get(1)? as usize) << 8 | *buf.get(2)? as usize;
        Some((len, &buf[3..]))
    } else {
        None
    }
}

// ── HTTP helpers ──────────────────────────────────────────────────────────────

async fn send(
    router: &axum::Router,
    req: Request<Body>,
) -> (StatusCode, Value, axum::http::HeaderMap) {
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let headers = resp.headers().clone();
    let body = axum::body::to_bytes(resp.into_body(), 1_000_000)
        .await
        .unwrap();
    let json = serde_json::from_slice(&body).unwrap_or(Value::Null);
    (status, json, headers)
}

async fn head_nonce(router: &axum::Router) -> String {
    let req = Request::builder()
        .method(Method::HEAD)
        .uri("/acme/new-nonce")
        .body(Body::empty())
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    resp.headers()
        .get("replay-nonce")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string()
}

async fn post_acme(
    router: &axum::Router,
    path: &str,
    jws: Value,
) -> (StatusCode, Value, axum::http::HeaderMap) {
    let req = Request::builder()
        .method(Method::POST)
        .uri(path)
        .header(header::CONTENT_TYPE, "application/jose+json")
        .body(Body::from(jws.to_string()))
        .unwrap();
    send(router, req).await
}

async fn get_req(router: &axum::Router, path: &str) -> (StatusCode, Value, axum::http::HeaderMap) {
    let req = Request::builder()
        .method(Method::GET)
        .uri(path)
        .body(Body::empty())
        .unwrap();
    send(router, req).await
}

fn nonce_from(headers: &axum::http::HeaderMap) -> String {
    headers
        .get("replay-nonce")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string()
}

fn location_from(headers: &axum::http::HeaderMap) -> String {
    headers
        .get(header::LOCATION)
        .unwrap()
        .to_str()
        .unwrap()
        .to_string()
}

async fn admin_post(
    router: &axum::Router,
    path: &str,
    token: &str,
    body: Value,
) -> (StatusCode, Value, axum::http::HeaderMap) {
    let req = Request::builder()
        .method(Method::POST)
        .uri(path)
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    send(router, req).await
}

async fn admin_get(
    router: &axum::Router,
    path: &str,
    token: &str,
) -> (StatusCode, Value, axum::http::HeaderMap) {
    let req = Request::builder()
        .method(Method::GET)
        .uri(path)
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    send(router, req).await
}

// ── State builder ─────────────────────────────────────────────────────────────

const BASE_URL: &str = "https://acme.test";

/// Build a test AppState with `delegation_enabled = true` and
/// `allow_certificate_get = true`, and return it along with:
/// - the admin router (with a pre-seeded administrator session)
/// - the ACME router
/// - the admin Bearer token
async fn build_delegation_state() -> (
    Arc<AppState>,
    axum::Router,
    axum::Router,
    String,
    tempfile::TempDir,
) {
    let dir = tempfile::TempDir::new().unwrap();

    let server = ServerConfig {
        delegation_enabled: true,
        allow_certificate_get: true,
        star_allow_certificate_get: true,
        ..Default::default()
    };

    let config = Arc::new(Config {
        listen_addr: "127.0.0.1:0".into(),
        base_url: BASE_URL.into(),
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
            common_name: "Integration Test CA".into(),
            organization: "Test Org".into(),
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
        server,
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
            auth_rate_limit: 100,
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

    let admin_token = "test-admin-token".to_string();
    let sessions: Arc<tokio::sync::Mutex<HashMap<String, AdminSession>>> =
        Arc::new(tokio::sync::Mutex::new(HashMap::new()));
    sessions.lock().await.insert(
        admin_token.clone(),
        AdminSession {
            operator_id: 1,
            name: Zeroizing::new("test-admin".to_string()),
            role: OperatorRole::Administrator,
            ca_id: String::new(),
            created_at: Instant::now(),
            last_active_at: Instant::now(),
            auth_method: AdminAuthMethod::Cert,
        },
    );

    let state = Arc::new(AppState {
        config: Arc::clone(&config),
        db: db_conn.clone(),
        db_ro: db_conn.clone(),
        db_kind: db::DbKind::Sqlite,
        profiles: akamu::profiles::ProfileRegistry::empty(&ca),
        cas: {
            let mut m = indexmap::IndexMap::new();
            m.insert("default".to_string(), ca.clone());
            Arc::new(m)
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
        spki_cache: Arc::new(std::sync::RwLock::new(std::collections::HashMap::new())),
        nonces: Arc::new(NonceBucket::new()),
        link_headers: Arc::new({
            let mut m = std::collections::HashMap::new();
            m.insert(
                "default".to_string(),
                Arc::new(axum::http::HeaderValue::from_static(
                    "<https://acme.test/acme/directory>;rel=\"index\"",
                )),
            );
            m
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
            let mut m = std::collections::HashMap::new();
            m.insert("default".to_string(), Default::default());
            m
        }),
        audit: Arc::new(akamu::audit::AuditState::new()),
        audit_policy: Arc::new(akamu::audit::AuditPolicy::default()),
        admin_sessions: Some(Arc::clone(&sessions)),
        admin_auth_limiter: Some(Arc::new(tokio::sync::Mutex::new(
            std::collections::HashMap::new(),
        ))),
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

    let acme_router = routes::build_router(Arc::clone(&state), None);
    let admin_router = routes::build_router(Arc::clone(&state), None);

    (state, admin_router, acme_router, admin_token, dir)
}

// ── CSR builders ─────────────────────────────────────────────────────────────

/// Build a CSR for `domain` using the given key.
/// The CSR has: CN=domain, SAN=DNS:domain, EC P-256 key.
fn make_csr(domain: &str, key: &BackendPrivateKey) -> Vec<u8> {
    let spki_der = key.public_key().unwrap().spki_der().to_vec();
    let name_der = NameBuilder::new().common_name(domain).build().unwrap();
    let san_der = SubjectAlternativeNameBuilder::new()
        .dns_name(domain)
        .build()
        .unwrap();
    let signer = key.as_signer("sha256");
    CsrBuilder::new()
        .subject_name(&name_der)
        .public_key_der(&spki_der)
        .add_extension_oid(synta_certificate::oids::SUBJECT_ALT_NAME, false, &san_der)
        .sign(&signer)
        .unwrap()
}

/// Build a minimal CSR with *no* SAN extension — used to produce a template-
/// violating CSR (SAN is required by the template).
fn make_csr_no_san(domain: &str, key: &BackendPrivateKey) -> Vec<u8> {
    let spki_der = key.public_key().unwrap().spki_der().to_vec();
    let name_der = NameBuilder::new().common_name(domain).build().unwrap();
    let signer = key.as_signer("sha256");
    CsrBuilder::new()
        .subject_name(&name_der)
        .public_key_der(&spki_der)
        .sign(&signer)
        .unwrap()
}

// ── Template used across tests ────────────────────────────────────────────────

/// A minimal but valid RFC 9115 CSR template that allows EC P-256 keys and
/// requires a SAN extension to be present.
///
/// JSON format (per `CsrTemplate` custom deserialisers):
/// - `keyTypes[].type`: `"EC"` or `"ECDSA"`
/// - `keyTypes[].curve`: named-curve string
/// - `subject.*`: plain string = Literal; `{}` = MandatoryWildcard; `null` = OptionalWildcard
/// - `extensions.subjectAltName`: `{}` = Required; `null` = Optional
fn test_csr_template(domain: &str) -> Value {
    json!({
        "keyTypes": [{"type": "EC", "curve": "P-256"}],
        "subject": {"commonName": domain},
        "extensions": {
            "subjectAltName": {}
        }
    })
}

// ── Account helper ────────────────────────────────────────────────────────────

/// Create a new ACME account and return `(account_url, fresh_nonce)`.
async fn create_account(acme: &axum::Router, key: &TestKey) -> (String, String) {
    let nonce = head_nonce(acme).await;
    let url = format!("{BASE_URL}/acme/new-account");
    let jws = key.jws_with_jwk(&nonce, &url, Some(json!({"termsOfServiceAgreed": true})));
    let (status, _, headers) = post_acme(acme, "/acme/new-account", jws).await;
    assert_eq!(status, StatusCode::CREATED, "new-account must return 201");
    let account_url = location_from(&headers);
    let nonce = nonce_from(&headers);
    (account_url, nonce)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

/// Admin creates a delegation; fetching it via GET returns the object.
#[tokio::test]
async fn admin_create_and_get_delegation() {
    let (state, admin, acme, token, _tmp) = build_delegation_state().await;
    let key = TestKey::generate();
    let (account_url, _) = create_account(&acme, &key).await;
    let account_id = account_url.split('/').next_back().unwrap().to_string();

    let domain = "example.com";

    // Create delegation.
    let (status, body, headers) = admin_post(
        &admin,
        "/admin/delegations",
        &token,
        json!({
            "account_id": account_id,
            "csr_template": test_csr_template(domain),
        }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "create delegation: {body}");
    let location = location_from(&headers);
    assert!(
        location.starts_with("/admin/delegations/"),
        "Location header must point to the new delegation"
    );
    let delegation_id = body["id"].as_str().unwrap().to_string();

    // Get it back.
    let (status, body, _) = admin_get(&admin, &location, &token).await;
    assert_eq!(status, StatusCode::OK, "get delegation: {body}");
    assert_eq!(body["id"].as_str().unwrap(), delegation_id);
    assert_eq!(body["account_id"].as_str().unwrap(), account_id);
    assert!(
        body["csr_template"].is_object(),
        "csr_template must be present"
    );

    // List — must contain the delegation.
    let (status, list_body, _) = admin_get(&admin, "/admin/delegations", &token).await;
    assert_eq!(status, StatusCode::OK);
    let found = list_body["delegations"]
        .as_array()
        .unwrap()
        .iter()
        .any(|d| d["id"].as_str() == Some(&delegation_id));
    assert!(found, "newly created delegation must appear in list");

    drop(state);
}

/// NDC lists delegations and fetches the delegation object via ACME POST-as-GET.
#[tokio::test]
async fn ndc_list_and_fetch_delegation() {
    let (state, admin, acme, token, _tmp) = build_delegation_state().await;
    let key = TestKey::generate();
    let (account_url, _) = create_account(&acme, &key).await;
    let account_id = account_url.split('/').next_back().unwrap().to_string();

    let domain = "ndc.example.com";

    // Admin creates delegation.
    let (status, body, _) = admin_post(
        &admin,
        "/admin/delegations",
        &token,
        json!({"account_id": account_id, "csr_template": test_csr_template(domain)}),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let delegation_id = body["id"].as_str().unwrap().to_string();

    // NDC lists via POST-as-GET to /acme/delegations/{account_id}.
    let nonce = head_nonce(&acme).await;
    let list_url = format!("{BASE_URL}/acme/delegations/{account_id}");
    let jws = key.jws_with_kid(&account_url, &nonce, &list_url, None);
    let (status, body, headers) =
        post_acme(&acme, &format!("/acme/delegations/{account_id}"), jws).await;
    assert_eq!(status, StatusCode::OK, "list delegations: {body}");
    let delegation_urls = body["delegations"].as_array().unwrap();
    let expected_url = format!("{BASE_URL}/acme/delegation/{delegation_id}");
    assert!(
        delegation_urls
            .iter()
            .any(|u| u.as_str() == Some(&expected_url)),
        "delegation URL must appear in list; got {delegation_urls:?}"
    );

    // NDC fetches the delegation object.
    let nonce = nonce_from(&headers);
    let obj_url = format!("{BASE_URL}/acme/delegation/{delegation_id}");
    let jws = key.jws_with_kid(&account_url, &nonce, &obj_url, None);
    let (status, body, _) =
        post_acme(&acme, &format!("/acme/delegation/{delegation_id}"), jws).await;
    assert_eq!(status, StatusCode::OK, "fetch delegation object: {body}");
    assert!(body["csr-template"].is_object());
    assert!(body.get("cname-map").is_none(), "no cname-map was set");

    drop(state);
}

/// NDC places an order referencing a delegation:
/// order must be `ready` with empty `authorizations`.
#[tokio::test]
async fn delegation_order_starts_ready_with_no_authz() {
    let (state, admin, acme, token, _tmp) = build_delegation_state().await;
    let key = TestKey::generate();
    let (account_url, _) = create_account(&acme, &key).await;
    let account_id = account_url.split('/').next_back().unwrap().to_string();

    let domain = "cdn.example.com";

    let (_, body, _) = admin_post(
        &admin,
        "/admin/delegations",
        &token,
        json!({"account_id": account_id, "csr_template": test_csr_template(domain)}),
    )
    .await;
    let delegation_id = body["id"].as_str().unwrap().to_string();
    let delegation_url = format!("{BASE_URL}/acme/delegation/{delegation_id}");

    // Place a delegation order.
    let nonce = head_nonce(&acme).await;
    let new_order_url = format!("{BASE_URL}/acme/new-order");
    let jws = key.jws_with_kid(
        &account_url,
        &nonce,
        &new_order_url,
        Some(json!({
            "identifiers": [{"type": "dns", "value": domain}],
            "delegation": delegation_url,
        })),
    );
    let (status, body, headers) = post_acme(&acme, "/acme/new-order", jws).await;
    assert_eq!(status, StatusCode::CREATED, "new delegation order: {body}");
    assert_eq!(
        body["status"].as_str(),
        Some("ready"),
        "delegation order must start ready"
    );
    assert_eq!(
        body["authorizations"].as_array().map(Vec::len),
        Some(0),
        "delegation order must have no authorizations"
    );
    assert!(
        body["delegation"].as_str().is_some(),
        "order response must echo the delegation URL"
    );

    // Order URL is in Location header.
    let order_url = location_from(&headers);
    let order_path = order_url.strip_prefix(BASE_URL).unwrap();

    // Fetch the order via POST-as-GET; status must still be ready.
    let nonce = nonce_from(&headers);
    let jws = key.jws_with_kid(&account_url, &nonce, &order_url, None);
    let (status, body, _) = post_acme(&acme, order_path, jws).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"].as_str(), Some("ready"));

    drop(state);
}

/// NDC finalises a delegation order with a CSR that matches the template → valid.
#[tokio::test]
async fn delegation_finalize_matching_csr_produces_valid_order() {
    let (state, admin, acme, token, _tmp) = build_delegation_state().await;
    let key = TestKey::generate();
    let (account_url, _) = create_account(&acme, &key).await;
    let account_id = account_url.split('/').next_back().unwrap().to_string();

    let domain = "finalize.example.com";

    let (_, body, _) = admin_post(
        &admin,
        "/admin/delegations",
        &token,
        json!({"account_id": account_id, "csr_template": test_csr_template(domain)}),
    )
    .await;
    let delegation_id = body["id"].as_str().unwrap().to_string();
    let delegation_url = format!("{BASE_URL}/acme/delegation/{delegation_id}");

    // Place order.
    let nonce = head_nonce(&acme).await;
    let new_order_url = format!("{BASE_URL}/acme/new-order");
    let jws = key.jws_with_kid(
        &account_url,
        &nonce,
        &new_order_url,
        Some(json!({
            "identifiers": [{"type": "dns", "value": domain}],
            "delegation": delegation_url,
        })),
    );
    let (status, order_body, headers) = post_acme(&acme, "/acme/new-order", jws).await;
    assert_eq!(status, StatusCode::CREATED);
    let order_url = location_from(&headers);
    let order_id = order_url.split('/').next_back().unwrap();
    let finalize_url = order_body["finalize"].as_str().unwrap().to_string();
    let finalize_path = finalize_url.strip_prefix(BASE_URL).unwrap();

    // Finalize with a matching CSR.
    let ndc_key = BackendPrivateKey::generate_ec("P-256").unwrap();
    let csr_der = make_csr(domain, &ndc_key);
    let csr_b64 = URL_SAFE_NO_PAD.encode(&csr_der);

    let nonce = nonce_from(&headers);
    let jws = key.jws_with_kid(
        &account_url,
        &nonce,
        &finalize_url,
        Some(json!({"csr": csr_b64})),
    );
    let (status, body, headers) = post_acme(&acme, finalize_path, jws).await;
    assert_eq!(status, StatusCode::OK, "finalize: {body}");
    assert_eq!(
        body["status"].as_str(),
        Some("valid"),
        "order must be valid after finalize with matching CSR; body: {body}"
    );
    assert!(
        body["certificate"].as_str().is_some(),
        "valid order must have certificate URL"
    );

    // Fetch the certificate.
    let cert_url = body["certificate"].as_str().unwrap();
    let cert_path = cert_url.strip_prefix(BASE_URL).unwrap();
    let nonce = nonce_from(&headers);
    let jws = key.jws_with_kid(&account_url, &nonce, cert_url, None);
    let (status, _, _) = post_acme(&acme, cert_path, jws).await;
    assert_eq!(status, StatusCode::OK, "cert download must succeed");

    drop((state, order_id));
}

/// NDC finalises a delegation order with a CSR that violates the template
/// (missing SAN) → server must return a `badCSR` error.
#[tokio::test]
async fn delegation_finalize_violating_csr_returns_bad_csr() {
    let (state, admin, acme, token, _tmp) = build_delegation_state().await;
    let key = TestKey::generate();
    let (account_url, _) = create_account(&acme, &key).await;
    let account_id = account_url.split('/').next_back().unwrap().to_string();

    let domain = "bad.example.com";

    let (_, body, _) = admin_post(
        &admin,
        "/admin/delegations",
        &token,
        json!({"account_id": account_id, "csr_template": test_csr_template(domain)}),
    )
    .await;
    let delegation_id = body["id"].as_str().unwrap().to_string();
    let delegation_url = format!("{BASE_URL}/acme/delegation/{delegation_id}");

    let nonce = head_nonce(&acme).await;
    let new_order_url = format!("{BASE_URL}/acme/new-order");
    let jws = key.jws_with_kid(
        &account_url,
        &nonce,
        &new_order_url,
        Some(json!({
            "identifiers": [{"type": "dns", "value": domain}],
            "delegation": delegation_url,
        })),
    );
    let (_, order_body, headers) = post_acme(&acme, "/acme/new-order", jws).await;
    let order_url = location_from(&headers);
    let finalize_url = order_body["finalize"].as_str().unwrap().to_string();
    let finalize_path = finalize_url.strip_prefix(BASE_URL).unwrap();

    // Finalize with a CSR that has NO SAN extension.
    let ndc_key = BackendPrivateKey::generate_ec("P-256").unwrap();
    let bad_csr = make_csr_no_san(domain, &ndc_key);
    let csr_b64 = URL_SAFE_NO_PAD.encode(&bad_csr);

    let nonce = nonce_from(&headers);
    let jws = key.jws_with_kid(
        &account_url,
        &nonce,
        &finalize_url,
        Some(json!({"csr": csr_b64})),
    );
    let (status, body, _) = post_acme(&acme, finalize_path, jws).await;
    // AcmeError::BadCsr maps to HTTP 400 (not 403).
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "template violation must return 400; body: {body}"
    );
    assert!(
        body["type"]
            .as_str()
            .map(|t| t.contains("badCSR"))
            .unwrap_or(false),
        "error type must be badCSR; got {body}"
    );

    drop((state, order_url));
}

/// Placing a delegation order with an unknown delegation URL must return
/// `unknownDelegation` (403).
#[tokio::test]
async fn delegation_order_unknown_delegation_url() {
    let (state, _admin, acme, _token, _tmp) = build_delegation_state().await;
    let key = TestKey::generate();
    let (account_url, _) = create_account(&acme, &key).await;

    let nonce = head_nonce(&acme).await;
    let new_order_url = format!("{BASE_URL}/acme/new-order");
    let fake_delegation = format!("{BASE_URL}/acme/delegation/doesnotexist");
    let jws = key.jws_with_kid(
        &account_url,
        &nonce,
        &new_order_url,
        Some(json!({
            "identifiers": [{"type": "dns", "value": "cdn.example.com"}],
            "delegation": fake_delegation,
        })),
    );
    let (status, body, _) = post_acme(&acme, "/acme/new-order", jws).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "unknown delegation must return 403; body: {body}"
    );
    assert!(
        body["type"]
            .as_str()
            .map(|t| t.contains("unknownDelegation"))
            .unwrap_or(false),
        "error type must be unknownDelegation; got {body}"
    );

    drop(state);
}

/// A delegation owned by account A cannot be used by account B.
#[tokio::test]
async fn delegation_wrong_account_returns_unknown_delegation() {
    let (state, admin, acme, token, _tmp) = build_delegation_state().await;

    // Account A creates a delegation.
    let key_a = TestKey::generate();
    let (account_a_url, _) = create_account(&acme, &key_a).await;
    let account_a_id = account_a_url.split('/').next_back().unwrap().to_string();

    let (_, body, _) = admin_post(
        &admin,
        "/admin/delegations",
        &token,
        json!({
            "account_id": account_a_id,
            "csr_template": test_csr_template("owned.example.com"),
        }),
    )
    .await;
    let delegation_id = body["id"].as_str().unwrap().to_string();
    let delegation_url = format!("{BASE_URL}/acme/delegation/{delegation_id}");

    // Account B tries to use A's delegation URL.
    let key_b = TestKey::generate();
    let (account_b_url, _) = create_account(&acme, &key_b).await;

    let nonce = head_nonce(&acme).await;
    let new_order_url = format!("{BASE_URL}/acme/new-order");
    let jws = key_b.jws_with_kid(
        &account_b_url,
        &nonce,
        &new_order_url,
        Some(json!({
            "identifiers": [{"type": "dns", "value": "owned.example.com"}],
            "delegation": delegation_url,
        })),
    );
    let (status, body, _) = post_acme(&acme, "/acme/new-order", jws).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "wrong account must return 403; body: {body}"
    );
    assert!(
        body["type"]
            .as_str()
            .map(|t| t.contains("unknownDelegation"))
            .unwrap_or(false),
        "error type must be unknownDelegation; got {body}"
    );

    drop(state);
}

/// When `allow-certificate-get` is set on the order, any authenticated account
/// can download the cert via POST-as-GET (RFC 9115 §2.3.5).
#[tokio::test]
async fn allow_certificate_get_permits_cross_account_download() {
    let (state, admin, acme, token, _tmp) = build_delegation_state().await;

    let key_ndc = TestKey::generate();
    let (account_ndc_url, _) = create_account(&acme, &key_ndc).await;
    let account_ndc_id = account_ndc_url.split('/').next_back().unwrap().to_string();

    let domain = "cdn-get.example.com";
    let (_, body, _) = admin_post(
        &admin,
        "/admin/delegations",
        &token,
        json!({"account_id": account_ndc_id, "csr_template": test_csr_template(domain)}),
    )
    .await;
    let delegation_id = body["id"].as_str().unwrap().to_string();
    let delegation_url = format!("{BASE_URL}/acme/delegation/{delegation_id}");

    // NDC places order with allow-certificate-get.
    let nonce = head_nonce(&acme).await;
    let new_order_url = format!("{BASE_URL}/acme/new-order");
    let jws = key_ndc.jws_with_kid(
        &account_ndc_url,
        &nonce,
        &new_order_url,
        Some(json!({
            "identifiers": [{"type": "dns", "value": domain}],
            "delegation": delegation_url,
            "allow-certificate-get": true,
        })),
    );
    let (_, order_body, headers) = post_acme(&acme, "/acme/new-order", jws).await;
    assert_eq!(
        order_body["allow-certificate-get"].as_bool(),
        Some(true),
        "server must echo allow-certificate-get"
    );
    let order_url = location_from(&headers);
    let finalize_url = order_body["finalize"].as_str().unwrap().to_string();
    let finalize_path = finalize_url.strip_prefix(BASE_URL).unwrap();

    // Finalize.
    let ndc_key = BackendPrivateKey::generate_ec("P-256").unwrap();
    let csr_der = make_csr(domain, &ndc_key);
    let csr_b64 = URL_SAFE_NO_PAD.encode(&csr_der);
    let nonce = nonce_from(&headers);
    let jws = key_ndc.jws_with_kid(
        &account_ndc_url,
        &nonce,
        &finalize_url,
        Some(json!({"csr": csr_b64})),
    );
    let (status, body, headers) = post_acme(&acme, finalize_path, jws).await;
    assert_eq!(status, StatusCode::OK, "finalize: {body}");
    let cert_url = body["certificate"].as_str().unwrap().to_string();
    let cert_path = cert_url.strip_prefix(BASE_URL).unwrap();

    // Unauthenticated GET must succeed (RFC 9115 §2.3.5 allows unauthenticated).
    let (status, _, _) = get_req(&acme, cert_path).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "unauthenticated GET must succeed for allow-certificate-get order"
    );

    // A second, unrelated account must also be able to POST-as-GET the cert.
    let key_other = TestKey::generate();
    let (account_other_url, _) = create_account(&acme, &key_other).await;
    let nonce = nonce_from(&headers);
    let jws = key_other.jws_with_kid(&account_other_url, &nonce, &cert_url, None);
    let (status, _, _) = post_acme(&acme, cert_path, jws).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "cross-account POST-as-GET must succeed for allow-certificate-get order"
    );

    drop((state, order_url));
}

/// Without `allow-certificate-get`, a different account cannot download the cert.
#[tokio::test]
async fn without_allow_cert_get_cross_account_download_is_rejected() {
    let (state, admin, acme, token, _tmp) = build_delegation_state().await;

    let key_ndc = TestKey::generate();
    let (account_ndc_url, _) = create_account(&acme, &key_ndc).await;
    let account_ndc_id = account_ndc_url.split('/').next_back().unwrap().to_string();

    let domain = "private-cdn.example.com";
    let (_, body, _) = admin_post(
        &admin,
        "/admin/delegations",
        &token,
        json!({"account_id": account_ndc_id, "csr_template": test_csr_template(domain)}),
    )
    .await;
    let delegation_id = body["id"].as_str().unwrap().to_string();
    let delegation_url = format!("{BASE_URL}/acme/delegation/{delegation_id}");

    // Place order WITHOUT allow-certificate-get.
    let nonce = head_nonce(&acme).await;
    let new_order_url = format!("{BASE_URL}/acme/new-order");
    let jws = key_ndc.jws_with_kid(
        &account_ndc_url,
        &nonce,
        &new_order_url,
        Some(json!({
            "identifiers": [{"type": "dns", "value": domain}],
            "delegation": delegation_url,
        })),
    );
    let (_, order_body, headers) = post_acme(&acme, "/acme/new-order", jws).await;
    let finalize_url = order_body["finalize"].as_str().unwrap().to_string();
    let finalize_path = finalize_url.strip_prefix(BASE_URL).unwrap();

    // Finalize.
    let ndc_key = BackendPrivateKey::generate_ec("P-256").unwrap();
    let csr_der = make_csr(domain, &ndc_key);
    let csr_b64 = URL_SAFE_NO_PAD.encode(&csr_der);
    let nonce = nonce_from(&headers);
    let jws = key_ndc.jws_with_kid(
        &account_ndc_url,
        &nonce,
        &finalize_url,
        Some(json!({"csr": csr_b64})),
    );
    let (status, body, headers) = post_acme(&acme, finalize_path, jws).await;
    assert_eq!(status, StatusCode::OK, "finalize: {body}");
    let cert_url = body["certificate"].as_str().unwrap().to_string();
    let cert_path = cert_url.strip_prefix(BASE_URL).unwrap();

    // A second account must be rejected.
    let key_other = TestKey::generate();
    let (account_other_url, _) = create_account(&acme, &key_other).await;
    let nonce = nonce_from(&headers);
    let jws = key_other.jws_with_kid(&account_other_url, &nonce, &cert_url, None);
    let (status, _, _) = post_acme(&acme, cert_path, jws).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "cross-account download without allow-certificate-get must return 401"
    );

    drop(state);
}

/// notBefore / notAfter must be rejected in delegation orders (RFC 9115 §2.3.2).
#[tokio::test]
async fn delegation_order_rejects_not_before_not_after() {
    let (state, admin, acme, token, _tmp) = build_delegation_state().await;

    let key = TestKey::generate();
    let (account_url, _) = create_account(&acme, &key).await;
    let account_id = account_url.split('/').next_back().unwrap().to_string();

    let (_, body, _) = admin_post(
        &admin,
        "/admin/delegations",
        &token,
        json!({"account_id": account_id, "csr_template": test_csr_template("time.example.com")}),
    )
    .await;
    let delegation_id = body["id"].as_str().unwrap().to_string();
    let delegation_url = format!("{BASE_URL}/acme/delegation/{delegation_id}");

    let nonce = head_nonce(&acme).await;
    let new_order_url = format!("{BASE_URL}/acme/new-order");
    // NewOrderPayload uses snake_case keys (no rename_all), so use "not_before".
    let jws = key.jws_with_kid(
        &account_url,
        &nonce,
        &new_order_url,
        Some(json!({
            "identifiers": [{"type": "dns", "value": "time.example.com"}],
            "delegation": delegation_url,
            "not_before": "2030-01-01T00:00:00Z",
        })),
    );
    let (status, body, _) = post_acme(&acme, "/acme/new-order", jws).await;
    assert!(
        status == StatusCode::BAD_REQUEST || status == StatusCode::FORBIDDEN,
        "not_before in delegation order must be rejected; got {status} {body}"
    );

    drop(state);
}

/// STAR + delegation: an order with both `auto-renewal` and `delegation` starts
/// `ready` (no authz), finalises to `valid`, and the `star-certificate` URL is
/// accessible both as an unauthenticated GET and as an authenticated POST-as-GET.
///
/// RFC 8739 §3 + RFC 9115 §2.3.2: the two features may coexist; the delegated
/// CSR is stored at finalize time so the STAR background task can reissue it.
#[tokio::test]
async fn star_delegation_order_finalizes_to_valid_with_star_cert_url() {
    let (state, admin, acme, token, _tmp) = build_delegation_state().await;
    let key = TestKey::generate();
    let (account_url, _) = create_account(&acme, &key).await;
    let account_id = account_url.split('/').next_back().unwrap().to_string();

    let domain = "star-cdn.example.com";

    // Admin creates a delegation for this NDC account.
    let (status, body, _) = admin_post(
        &admin,
        "/admin/delegations",
        &token,
        json!({"account_id": account_id, "csr_template": test_csr_template(domain)}),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "create delegation: {body}");
    let delegation_id = body["id"].as_str().unwrap().to_string();
    let delegation_url = format!("{BASE_URL}/acme/delegation/{delegation_id}");

    // NDC places an order with both `auto-renewal` and `delegation`.
    // AutoRenewalRequest uses rename_all = "kebab-case" so fields are:
    //   end-date, lifetime, allow-certificate-get
    let nonce = head_nonce(&acme).await;
    let new_order_url = format!("{BASE_URL}/acme/new-order");
    let jws = key.jws_with_kid(
        &account_url,
        &nonce,
        &new_order_url,
        Some(json!({
            "identifiers": [{"type": "dns", "value": domain}],
            "delegation": delegation_url,
            "auto-renewal": {
                "end-date": "2030-01-01T00:00:00Z",
                "lifetime": 86400,
                "allow-certificate-get": true,
            },
        })),
    );
    let (status, order_body, headers) = post_acme(&acme, "/acme/new-order", jws).await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "STAR+delegation new-order: {order_body}"
    );

    // Delegation orders start `ready` with an empty authorizations list.
    assert_eq!(
        order_body["status"].as_str(),
        Some("ready"),
        "STAR+delegation order must start ready"
    );
    assert_eq!(
        order_body["authorizations"].as_array().map(Vec::len),
        Some(0),
        "STAR+delegation order must have no authorizations"
    );

    // Both delegation and auto-renewal fields must be present.
    assert!(
        order_body["delegation"].as_str().is_some(),
        "order response must echo delegation URL"
    );
    let ar = &order_body["auto-renewal"];
    assert!(
        ar.is_object(),
        "auto-renewal must be present in order response"
    );
    assert!(
        ar["end-date"].as_str().is_some(),
        "auto-renewal must have end-date"
    );
    assert_eq!(ar["lifetime"].as_i64(), Some(86400));

    let order_url = location_from(&headers);
    let order_id = order_url.split('/').next_back().unwrap().to_string();
    let finalize_url = order_body["finalize"].as_str().unwrap().to_string();
    let finalize_path = finalize_url.strip_prefix(BASE_URL).unwrap();

    // NDC finalises with a CSR that matches the template.
    let ndc_key = BackendPrivateKey::generate_ec("P-256").unwrap();
    let csr_der = make_csr(domain, &ndc_key);
    let csr_b64 = URL_SAFE_NO_PAD.encode(&csr_der);

    let nonce = nonce_from(&headers);
    let jws = key.jws_with_kid(
        &account_url,
        &nonce,
        &finalize_url,
        Some(json!({"csr": csr_b64})),
    );
    let (status, body, headers) = post_acme(&acme, finalize_path, jws).await;
    assert_eq!(status, StatusCode::OK, "STAR+delegation finalize: {body}");
    assert_eq!(
        body["status"].as_str(),
        Some("valid"),
        "order must be valid after finalize; body: {body}"
    );

    // The response must contain a `star-certificate` URL (not a plain `certificate`).
    let star_cert_url = body["star-certificate"]
        .as_str()
        .expect("star-certificate URL must be present after STAR finalize");
    assert!(
        star_cert_url.contains(&order_id),
        "star-certificate URL must reference the order ID; got {star_cert_url}"
    );
    assert!(
        body.get("certificate").is_none_or(|v| v.is_null()),
        "STAR order must not have plain certificate URL"
    );

    // Unauthenticated GET works because:
    //   server.star_allow_certificate_get = true
    //   order.star_allow_cert_get != 0  (from allowCertificateGet: true)
    let star_cert_path = star_cert_url.strip_prefix(BASE_URL).unwrap();
    let (status, _, _) = get_req(&acme, star_cert_path).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "unauthenticated GET of star-certificate must succeed"
    );

    // Authenticated POST-as-GET by the order owner also works.
    let nonce = nonce_from(&headers);
    let jws = key.jws_with_kid(&account_url, &nonce, star_cert_url, None);
    let (status, _, _) = post_acme(&acme, star_cert_path, jws).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "authenticated POST-as-GET of star-certificate must succeed"
    );

    drop((state, order_id));
}

/// The directory advertises `delegation-enabled` when the feature is on.
#[tokio::test]
async fn directory_advertises_delegation_enabled() {
    let (state, _admin, acme, _token, _tmp) = build_delegation_state().await;

    let req = Request::builder()
        .method(Method::GET)
        .uri("/acme/directory")
        .body(Body::empty())
        .unwrap();
    let (status, body, _) = send(&acme, req).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body["meta"]["delegation-enabled"].as_bool(),
        Some(true),
        "directory meta must contain delegation-enabled: true; meta = {:?}",
        body["meta"]
    );
    assert_eq!(
        body["meta"]["allow-certificate-get"].as_bool(),
        Some(true),
        "directory meta must contain allow-certificate-get: true"
    );

    drop(state);
}

/// Delegation endpoints return 404 when `delegation_enabled` is false.
#[tokio::test]
async fn delegation_disabled_returns_404() {
    let server = ServerConfig {
        delegation_enabled: false,
        ..Default::default()
    };
    let dir = tempfile::TempDir::new().unwrap();
    let config = Arc::new(Config {
        listen_addr: "127.0.0.1:0".into(),
        base_url: BASE_URL.into(),
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
            common_name: "Test CA".into(),
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
        server,
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

    let state = Arc::new(AppState {
        config: Arc::clone(&config),
        db: db_conn.clone(),
        db_ro: db_conn.clone(),
        db_kind: db::DbKind::Sqlite,
        profiles: akamu::profiles::ProfileRegistry::empty(&ca),
        cas: {
            let mut m = indexmap::IndexMap::new();
            m.insert("default".to_string(), ca);
            Arc::new(m)
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
        spki_cache: Arc::new(std::sync::RwLock::new(std::collections::HashMap::new())),
        nonces: Arc::new(NonceBucket::new()),
        link_headers: Arc::new(std::collections::HashMap::new()),
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
            let mut m = std::collections::HashMap::new();
            m.insert("default".to_string(), Default::default());
            m
        }),
        audit: Arc::new(akamu::audit::AuditState::new()),
        audit_policy: Arc::new(akamu::audit::AuditPolicy::default()),
        admin_sessions: None,
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

    let acme = routes::build_router(Arc::clone(&state), None);

    // delegation_enabled = false: POST-as-GET for delegation list must return 404.
    let (status, _, _) = post_acme(
        &acme,
        "/acme/delegations/some-account-id",
        serde_json::json!({}),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "delegation list endpoint must return 404 when delegation_enabled=false"
    );

    // Single delegation fetch must also return 404.
    let (status, _, _) = post_acme(
        &acme,
        "/acme/delegation/some-delegation-id",
        serde_json::json!({}),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "delegation get endpoint must return 404 when delegation_enabled=false"
    );

    drop(state);
}
