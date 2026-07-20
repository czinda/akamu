//! Integration tests for RFC 9773 ACME Renewal Information (ARI).
//!
//! Tests:
//!   1. Directory advertises `renewalInfo` URL.
//!   2. GET /acme/renewal-info returns 200 + Retry-After + valid window, no explanationURL.
//!   3. new-order with valid `replaces` → 201 with `replaces` field in response.
//!   4. After finalize, predecessor cert's `replaced_by` is set.
//!   5. new-order with already-replaced cert → 409 alreadyReplaced.
//!   6. new-order with `replaces` from a different account → 401.
//!   7. new-order with unknown cert_id → 404.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde_json::{json, Value};
use synta_certificate::{
    BackendPrivateKey, CertificateSigner as _, CsrBuilder, NameBuilder, PrivateKey as _,
    SubjectAlternativeNameBuilder,
};
use tower::ServiceExt;

use akamu::config::{CaConfig, Config, DatabaseConfig, MtcConfig, ServerConfig};
use akamu::state::{AppState, AppStateBuilder, CaState, MtcState};
use akamu::{ca, db, routes};

// ── JWS test client (derived from acme_flow.rs) ───────────────────────────────

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
        Self { key, x_b64, y_b64 }
    }

    fn jwk(&self) -> Value {
        json!({ "kty": "EC", "crv": "P-256", "x": self.x_b64, "y": self.y_b64 })
    }

    fn jws_with_jwk(&self, nonce: &str, url: &str, payload: Option<Value>) -> Value {
        let header = json!({ "alg": "ES256", "nonce": nonce, "url": url, "jwk": self.jwk() });
        self.build_jws(header, payload)
    }

    fn jws_with_kid(&self, kid: &str, nonce: &str, url: &str, payload: Option<Value>) -> Value {
        let header = json!({ "alg": "ES256", "nonce": nonce, "url": url, "kid": kid });
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
        let p1363 = ecdsa_der_to_p1363(&der_sig, 32).expect("DER→P1363");
        let signature = URL_SAFE_NO_PAD.encode(&p1363);
        json!({ "protected": protected, "payload": payload_b64, "signature": signature })
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
    let rest = &rest[len..];
    let val = val.strip_prefix(&[0x00u8]).unwrap_or(val);
    Some((val, rest))
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

// ── Test state ────────────────────────────────────────────────────────────────

async fn build_test_state(base_url: &str) -> (Arc<AppState>, tempfile::TempDir) {
    let dir = tempfile::TempDir::new().unwrap();
    let config = Arc::new(Config {
        listen_addr: "127.0.0.1:0".into(),
        base_url: base_url.to_string(),
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
            common_name: "ARI Test CA".into(),
            organization: "ARI Test".into(),
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
    });
    let (ca_key, ca_cert_der) = ca::init::load_or_generate(config.default_ca()).unwrap();
    let ca_spki_der = ca_key.public_key().unwrap().spki_der().to_vec();
    let ca_aki_bytes = akamu::ca::init::compute_aki_from_spki(&ca_spki_der).unwrap_or_default();
    db::install_drivers();
    let db_conn = db::open("sqlite::memory:", 1, false).await.unwrap();
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
    let cas: Arc<indexmap::IndexMap<String, Arc<CaState>>> = {
        let mut _ca_map = indexmap::IndexMap::new();
        _ca_map.insert("default".to_string(), ca.clone());
        Arc::new(_ca_map)
    };
    let state = AppStateBuilder::new(
        Arc::clone(&config),
        db_conn.clone(),
        db::DbKind::Sqlite,
        cas,
        Arc::new("default".to_string()),
    )
    .node_id(Arc::new("test".to_string()))
    .link_headers(Arc::new({
        let mut _lh_map = std::collections::HashMap::new();
        _lh_map.insert(
            "default".to_string(),
            Arc::new(axum::http::HeaderValue::from_static(
                "<https://acme.test/acme/directory>;rel=\"index\"",
            )),
        );
        _lh_map
    }))
    .build();
    (state, dir)
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

async fn get(router: &axum::Router, path: &str) -> (StatusCode, Value, axum::http::HeaderMap) {
    let req = Request::builder()
        .method(Method::GET)
        .uri(path)
        .body(Body::empty())
        .unwrap();
    send(router, req).await
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

fn nonce_header(headers: &axum::http::HeaderMap) -> String {
    headers
        .get("replay-nonce")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string()
}

fn location_header(headers: &axum::http::HeaderMap) -> String {
    headers
        .get(header::LOCATION)
        .unwrap()
        .to_str()
        .unwrap()
        .to_string()
}

// ── DB helpers ────────────────────────────────────────────────────────────────

async fn mark_order_ready(db: &akamu::db::Db, order_id: &str) {
    let authz_ids: Vec<(String,)> =
        sqlx::query_as("SELECT id FROM authorizations WHERE order_id = ?")
            .bind(order_id)
            .fetch_all(db)
            .await
            .unwrap();
    for (aid,) in &authz_ids {
        sqlx::query(
            "UPDATE challenges SET status='valid', validated=1700000000 WHERE authz_id = ?",
        )
        .bind(aid)
        .execute(db)
        .await
        .unwrap();
        sqlx::query("UPDATE authorizations SET status='valid', updated=1700000000 WHERE id = ?")
            .bind(aid)
            .execute(db)
            .await
            .unwrap();
    }
    sqlx::query("UPDATE orders SET status='ready', updated=1700000000 WHERE id = ?")
        .bind(order_id)
        .execute(db)
        .await
        .unwrap();
}

// ── CSR + ARI helpers ─────────────────────────────────────────────────────────

fn make_csr_der(domain: &str) -> Vec<u8> {
    let backend_key = BackendPrivateKey::generate_ec("P-256").unwrap();
    let spki_der = backend_key.public_key().unwrap().spki_der().to_vec();
    let name_der = NameBuilder::new().common_name(domain).build().unwrap();
    let san_der = SubjectAlternativeNameBuilder::new()
        .dns_name(domain)
        .build()
        .unwrap();
    let signer = backend_key.as_signer("sha256");
    CsrBuilder::new()
        .subject_name(&name_der)
        .public_key_der(&spki_der)
        .add_extension_oid(synta_certificate::oids::SUBJECT_ALT_NAME, false, &san_der)
        .sign(&signer)
        .unwrap()
}

/// Build an RFC 9773 cert_id from a hex-encoded serial number and AKI bytes.
fn cert_id_from_serial_hex(serial_hex: &str, aki_bytes: &[u8]) -> String {
    let serial_bytes: Vec<u8> = (0..serial_hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&serial_hex[i..i + 2], 16).unwrap())
        .collect();
    format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(aki_bytes),
        URL_SAFE_NO_PAD.encode(&serial_bytes)
    )
}

// ── Full-issuance helper ──────────────────────────────────────────────────────

/// Register `key` as a new account, issue one certificate for `domain`, and
/// return `(account_url, order_id, cert_id)` where `cert_id` is the RFC 9773
/// `base64url(aki).base64url(serial)` form.
async fn issue_cert(
    router: &axum::Router,
    db: &akamu::db::Db,
    base_url: &str,
    key: &TestKey,
    domain: &str,
    aki_bytes: &[u8],
) -> (String, String, String) {
    // new-account
    let nonce = head_nonce(router).await;
    let jws = key.jws_with_jwk(
        &nonce,
        &format!("{base_url}/acme/new-account"),
        Some(json!({"termsOfServiceAgreed": true})),
    );
    let (_, _, acct_headers) = post_acme(router, "/acme/new-account", jws).await;
    let account_url = location_header(&acct_headers);
    let nonce = nonce_header(&acct_headers);

    // new-order
    let jws = key.jws_with_kid(
        &account_url,
        &nonce,
        &format!("{base_url}/acme/new-order"),
        Some(json!({"identifiers": [{"type": "dns", "value": domain}]})),
    );
    let (status, order_body, order_headers) = post_acme(router, "/acme/new-order", jws).await;
    assert_eq!(status, StatusCode::CREATED, "new-order: {order_body}");
    let nonce = nonce_header(&order_headers);
    let order_url = location_header(&order_headers);
    let order_id = order_url.split('/').next_back().unwrap().to_string();

    mark_order_ready(db, &order_id).await;

    // finalize
    let csr_b64 = URL_SAFE_NO_PAD.encode(make_csr_der(domain));
    let finalize_url = format!("{base_url}/acme/order/{order_id}/finalize");
    let jws = key.jws_with_kid(
        &account_url,
        &nonce,
        &finalize_url,
        Some(json!({"csr": csr_b64})),
    );
    let (status, final_body, _) =
        post_acme(router, &format!("/acme/order/{order_id}/finalize"), jws).await;
    assert_eq!(status, StatusCode::OK, "finalize: {final_body}");

    // get serial from DB → construct cert_id
    let serial_hex: String = sqlx::query_as::<_, (String,)>(
        "SELECT serial_number FROM certificates ORDER BY created DESC LIMIT 1",
    )
    .fetch_one(db)
    .await
    .unwrap()
    .0;
    let cert_id = cert_id_from_serial_hex(&serial_hex, aki_bytes);
    (account_url, order_id, cert_id)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

/// Directory includes `renewalInfo` URL (RFC 9773 §3).
#[tokio::test]
async fn test_directory_includes_renewal_info() {
    let base_url = "https://acme.test";
    let (state, _tmp) = build_test_state(base_url).await;
    let router = routes::build_router(Arc::clone(&state), None, false);

    let (status, body, _) = get(&router, "/acme/directory").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body["renewalInfo"].as_str().unwrap(),
        "https://acme.test/acme/renewal-info",
        "directory must advertise renewalInfo URL"
    );
}

/// GET /acme/renewal-info returns 200, Retry-After header, valid window, no explanationURL.
#[tokio::test]
async fn test_renewal_info_response_format() {
    let base_url = "https://acme.test";
    let (state, _tmp) = build_test_state(base_url).await;
    let db = state.db.clone();
    let router = routes::build_router(Arc::clone(&state), None, false);

    let key = TestKey::generate();
    let (_, _, cert_id) = issue_cert(
        &router,
        &db,
        base_url,
        &key,
        "ari-fmt.example",
        &state.default_ca().aki_bytes,
    )
    .await;

    let (status, body, headers) = get(&router, &format!("/acme/renewal-info/{cert_id}")).await;
    assert_eq!(status, StatusCode::OK, "expected 200: {body}");

    assert!(
        body["suggestedWindow"]["start"].as_str().is_some(),
        "missing suggestedWindow.start"
    );
    assert!(
        body["suggestedWindow"]["end"].as_str().is_some(),
        "missing suggestedWindow.end"
    );

    // explanationURL must be absent (RFC 9773: omit when not set).
    assert!(
        body.get("explanationURL").is_none(),
        "explanationURL must be omitted, got: {body}"
    );

    // Retry-After header must be present (RFC 9773 §4.3).
    assert!(
        headers.contains_key("retry-after"),
        "Retry-After header missing"
    );
}

/// When `ari_explanation_url` is configured, it appears in the renewal-info response.
#[tokio::test]
async fn test_renewal_info_explanation_url() {
    let base_url = "https://acme.test";
    let (state, _tmp) = build_test_state(base_url).await;
    let db = state.db.clone();

    // Rebuild state with ari_explanation_url set.
    let server_cfg = ServerConfig {
        ari_explanation_url: Some("https://ca.example/incident-42".into()),
        ..ServerConfig::default()
    };
    let config = Arc::new(Config {
        listen_addr: "127.0.0.1:0".into(),
        base_url: base_url.to_string(),
        database: DatabaseConfig {
            url: "sqlite::memory:".into(),
            max_connections: None,
            require_tls: false,
        },
        cas: vec![CaConfig {
            id: "default".to_owned(),

            is_default: true,

            caa_identities: vec![],
            key_file: Some("/dev/null".into()),
            cert_file: "/dev/null".into(),
            key_type: "ec:P-256".into(),
            hash_alg: "sha256".into(),
            validity_days: 90,
            crl_url: None,
            ocsp_url: None,
            common_name: "ARI Test CA".into(),
            organization: "ARI Test".into(),
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
        }),
        server: server_cfg,
        tls: Default::default(),
        profiles: Default::default(),
        linter: Default::default(),
        admin: None,
        email_challenge: None,
        delegation_upstream: None,
        gossip: None,
        crdt_db_url: None,
        tkauth: None,
    });
    let state2 = AppStateBuilder::new(
        Arc::clone(&config),
        db.clone(),
        akamu::db::DbKind::Sqlite,
        Arc::clone(&state.cas),
        Arc::clone(&state.default_ca_id),
    )
    .node_id(Arc::new("test".to_string()))
    .link_headers(Arc::new({
        let mut _lh_map = std::collections::HashMap::new();
        _lh_map.insert(
            "default".to_string(),
            Arc::new(axum::http::HeaderValue::from_static(
                "<https://acme.test/acme/directory>;rel=\"index\"",
            )),
        );
        _lh_map
    }))
    .build();
    let router = routes::build_router(Arc::clone(&state2), None);

    let key = TestKey::generate();
    let (_, _, cert_id) = issue_cert(
        &router,
        &db,
        base_url,
        &key,
        "ari-expl.example",
        &state2.default_ca().aki_bytes,
    )
    .await;

    let (status, body, _) = get(&router, &format!("/acme/renewal-info/{cert_id}")).await;
    assert_eq!(status, StatusCode::OK, "expected 200: {body}");
    assert_eq!(
        body["explanationURL"].as_str(),
        Some("https://ca.example/incident-42"),
        "explanationURL must equal the configured value"
    );
}

/// new-order with a valid `replaces` cert_id → 201 with `replaces` echoed in response.
#[tokio::test]
async fn test_new_order_with_replaces_field() {
    let base_url = "https://acme.test";
    let (state, _tmp) = build_test_state(base_url).await;
    let db = state.db.clone();
    let router = routes::build_router(Arc::clone(&state), None, false);

    let key = TestKey::generate();
    let (account_url, _, cert_id) = issue_cert(
        &router,
        &db,
        base_url,
        &key,
        "ari-rpl.example",
        &state.default_ca().aki_bytes,
    )
    .await;

    // new-order that replaces the issued cert.
    let nonce = head_nonce(&router).await;
    let jws = key.jws_with_kid(
        &account_url,
        &nonce,
        &format!("{base_url}/acme/new-order"),
        Some(json!({
            "identifiers": [{"type": "dns", "value": "ari-rpl.example"}],
            "replaces": cert_id,
        })),
    );
    let (status, body, _) = post_acme(&router, "/acme/new-order", jws).await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "new-order with replaces: {body}"
    );
    assert_eq!(
        body["replaces"].as_str(),
        Some(cert_id.as_str()),
        "response must echo the replaces cert_id"
    );
}

/// After finalizing a replacing order, the predecessor cert's `replaced_by` is set.
#[tokio::test]
async fn test_finalize_marks_predecessor_replaced() {
    let base_url = "https://acme.test";
    let (state, _tmp) = build_test_state(base_url).await;
    let db = state.db.clone();
    let router = routes::build_router(Arc::clone(&state), None, false);

    let key = TestKey::generate();
    let (account_url, _, cert_id) = issue_cert(
        &router,
        &db,
        base_url,
        &key,
        "ari-pred.example",
        &state.default_ca().aki_bytes,
    )
    .await;

    // Capture the predecessor's UUID before the second cert is issued.
    let pred_uuid: String =
        sqlx::query_as::<_, (String,)>("SELECT id FROM certificates ORDER BY created ASC LIMIT 1")
            .fetch_one(&db)
            .await
            .unwrap()
            .0;

    // Issue a replacing order.
    let nonce = head_nonce(&router).await;
    let jws = key.jws_with_kid(
        &account_url,
        &nonce,
        &format!("{base_url}/acme/new-order"),
        Some(json!({
            "identifiers": [{"type": "dns", "value": "ari-pred.example"}],
            "replaces": cert_id,
        })),
    );
    let (status, new_order_body, order_headers) = post_acme(&router, "/acme/new-order", jws).await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "replacing new-order: {new_order_body}"
    );
    let nonce = nonce_header(&order_headers);
    let order_url = location_header(&order_headers);
    let order_id = order_url.split('/').next_back().unwrap().to_string();

    mark_order_ready(&db, &order_id).await;

    let csr_b64 = URL_SAFE_NO_PAD.encode(make_csr_der("ari-pred.example"));
    let finalize_url = format!("{base_url}/acme/order/{order_id}/finalize");
    let jws = key.jws_with_kid(
        &account_url,
        &nonce,
        &finalize_url,
        Some(json!({"csr": csr_b64})),
    );
    let (status, final_body, _) =
        post_acme(&router, &format!("/acme/order/{order_id}/finalize"), jws).await;
    assert_eq!(status, StatusCode::OK, "finalize: {final_body}");

    // Verify the predecessor's replaced_by is now the replacing order_id.
    let replaced_by: Option<String> =
        sqlx::query_as::<_, (Option<String>,)>("SELECT replaced_by FROM certificates WHERE id = ?")
            .bind(&pred_uuid)
            .fetch_one(&db)
            .await
            .unwrap()
            .0;
    assert_eq!(
        replaced_by.as_deref(),
        Some(order_id.as_str()),
        "predecessor replaced_by must equal the replacing order_id"
    );
}

/// new-order `replaces` an already-replaced cert → 409 alreadyReplaced.
#[tokio::test]
async fn test_new_order_already_replaced() {
    let base_url = "https://acme.test";
    let (state, _tmp) = build_test_state(base_url).await;
    let db = state.db.clone();
    let router = routes::build_router(Arc::clone(&state), None, false);

    let key = TestKey::generate();
    let (account_url, _, cert_id) = issue_cert(
        &router,
        &db,
        base_url,
        &key,
        "ari-ar.example",
        &state.default_ca().aki_bytes,
    )
    .await;

    // Mark the cert as replaced directly in the DB.
    sqlx::query("UPDATE certificates SET replaced_by = 'some-prior-order'")
        .execute(&db)
        .await
        .unwrap();

    let nonce = head_nonce(&router).await;
    let jws = key.jws_with_kid(
        &account_url,
        &nonce,
        &format!("{base_url}/acme/new-order"),
        Some(json!({
            "identifiers": [{"type": "dns", "value": "ari-ar2.example"}],
            "replaces": cert_id,
        })),
    );
    let (status, body, _) = post_acme(&router, "/acme/new-order", jws).await;
    assert_eq!(status, StatusCode::CONFLICT, "expected 409: {body}");
    assert_eq!(
        body["type"].as_str().unwrap(),
        "urn:ietf:params:acme:error:alreadyReplaced"
    );
}

/// new-order `replaces` a cert from a different account → 401 unauthorized.
#[tokio::test]
async fn test_new_order_replaces_wrong_account() {
    let base_url = "https://acme.test";
    let (state, _tmp) = build_test_state(base_url).await;
    let db = state.db.clone();
    let router = routes::build_router(Arc::clone(&state), None, false);

    // Account A issues a cert.
    let key_a = TestKey::generate();
    let (_, _, cert_id) = issue_cert(
        &router,
        &db,
        base_url,
        &key_a,
        "ari-wa.example",
        &state.default_ca().aki_bytes,
    )
    .await;

    // Account B registers and tries to replace Account A's cert.
    let key_b = TestKey::generate();
    let nonce = head_nonce(&router).await;
    let jws = key_b.jws_with_jwk(
        &nonce,
        &format!("{base_url}/acme/new-account"),
        Some(json!({"termsOfServiceAgreed": true})),
    );
    let (_, _, acct_headers) = post_acme(&router, "/acme/new-account", jws).await;
    let account_b_url = location_header(&acct_headers);
    let nonce = nonce_header(&acct_headers);

    let jws = key_b.jws_with_kid(
        &account_b_url,
        &nonce,
        &format!("{base_url}/acme/new-order"),
        Some(json!({
            "identifiers": [{"type": "dns", "value": "ari-wa2.example"}],
            "replaces": cert_id,
        })),
    );
    let (status, body, _) = post_acme(&router, "/acme/new-order", jws).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "expected 401: {body}");
    assert_eq!(
        body["type"].as_str().unwrap(),
        "urn:ietf:params:acme:error:unauthorized"
    );
}

/// new-order `replaces` an unknown cert_id → 404 not found.
#[tokio::test]
async fn test_new_order_replaces_unknown_cert() {
    let base_url = "https://acme.test";
    let (state, _tmp) = build_test_state(base_url).await;
    let router = routes::build_router(Arc::clone(&state), None, false);

    let key = TestKey::generate();
    let nonce = head_nonce(&router).await;
    let jws = key.jws_with_jwk(
        &nonce,
        &format!("{base_url}/acme/new-account"),
        Some(json!({"termsOfServiceAgreed": true})),
    );
    let (_, _, acct_headers) = post_acme(&router, "/acme/new-account", jws).await;
    let account_url = location_header(&acct_headers);
    let nonce = nonce_header(&acct_headers);

    let unknown = cert_id_from_serial_hex("deadbeefdeadbeef", b"unknown-aki");
    let jws = key.jws_with_kid(
        &account_url,
        &nonce,
        &format!("{base_url}/acme/new-order"),
        Some(json!({
            "identifiers": [{"type": "dns", "value": "ari-unk.example"}],
            "replaces": unknown,
        })),
    );
    let (status, body, _) = post_acme(&router, "/acme/new-order", jws).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "expected 404: {body}");
}
