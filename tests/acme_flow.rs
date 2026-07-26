//! Integration test: full ACME HTTP flow.
//!
//! Uses `tower::ServiceExt::oneshot` to drive the axum router against an
//! in-memory SQLite database and a freshly generated CA key — no network
//! socket is bound.
//!
//! Flow: GET directory → HEAD new-nonce → POST new-account → POST new-order
//!   → bypass challenge validation (direct DB update) → POST finalize
//!   → GET certificate.

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

// ── ACME test client ──────────────────────────────────────────────────────────

/// Wraps an EC P-256 key pair and provides helpers for building JWS requests.
struct TestKey {
    key: BackendPrivateKey,
    x_b64: String,
    y_b64: String,
    _spki_der: Vec<u8>,
}

impl TestKey {
    /// Generate a fresh P-256 key via synta-certificate's crypto backend.
    fn generate() -> Self {
        let key = BackendPrivateKey::generate_ec("P-256").unwrap();
        let pub_key = key.public_key().unwrap();

        // Extract affine (x, y) coordinates — big-endian, minimal bytes.
        let (x_bytes, y_bytes) = pub_key.ec_affine_coordinates().unwrap().unwrap();
        let x_b64 = encode_coord(&x_bytes, 32);
        let y_b64 = encode_coord(&y_bytes, 32);
        let _spki_der = pub_key.spki_der().to_vec();

        TestKey {
            key,
            x_b64,
            y_b64,
            _spki_der,
        }
    }

    fn jwk(&self) -> Value {
        json!({
            "kty": "EC",
            "crv": "P-256",
            "x": self.x_b64,
            "y": self.y_b64,
        })
    }

    /// Build a JWS with a `jwk` key reference (used for new-account).
    fn jws_with_jwk(&self, nonce: &str, url: &str, payload: Option<Value>) -> Value {
        let header = json!({
            "alg": "ES256",
            "nonce": nonce,
            "url": url,
            "jwk": self.jwk(),
        });
        self.build_jws(header, payload)
    }

    /// Build a JWS with a `kid` key reference (used for all subsequent requests).
    fn jws_with_kid(&self, kid: &str, nonce: &str, url: &str, payload: Option<Value>) -> Value {
        let header = json!({
            "alg": "ES256",
            "nonce": nonce,
            "url": url,
            "kid": kid,
        });
        self.build_jws(header, payload)
    }

    /// Build the inner JWS for key-change (signed with this/new key, carries jwk).
    /// The inner JWS uses the key-change URL as `url` and includes a dummy nonce
    /// since JwsProtectedHeader requires the field but it is not validated here.
    fn inner_key_change_jws(
        &self,
        key_change_url: &str,
        account_url: &str,
        old_jwk: &Value,
    ) -> Value {
        let header = json!({
            "alg": "ES256",
            "nonce": "inner-dummy",
            "url": key_change_url,
            "jwk": self.jwk(),
        });
        let payload = json!({
            "account": account_url,
            "oldKey": old_jwk,
        });
        self.build_jws(header, Some(payload))
    }

    fn build_jws(&self, header: Value, payload: Option<Value>) -> Value {
        let protected = URL_SAFE_NO_PAD.encode(header.to_string().as_bytes());
        let payload_b64 = match payload {
            Some(v) => URL_SAFE_NO_PAD.encode(v.to_string().as_bytes()),
            None => String::new(), // POST-as-GET uses empty payload
        };

        // Sign the JWS input: "<protected>.<payload>" using synta's signer.
        // sign_tbs returns DER ECDSA (SEQUENCE{r,s}); JWS requires P1363 (r||s).
        let signing_input = format!("{}.{}", protected, payload_b64);
        let signer = self.key.as_signer("sha256");
        let der_sig = signer.sign_tbs(signing_input.as_bytes()).unwrap();
        let p1363 = ecdsa_der_to_p1363(&der_sig, 32).expect("DER→P1363 conversion");
        let signature = URL_SAFE_NO_PAD.encode(&p1363);

        json!({
            "protected": protected,
            "payload": payload_b64,
            "signature": signature,
        })
    }
}

fn encode_coord(bytes: &[u8], len: usize) -> String {
    let mut padded = vec![0u8; len];
    let start = len.saturating_sub(bytes.len());
    padded[start..].copy_from_slice(&bytes[bytes.len().saturating_sub(len)..]);
    URL_SAFE_NO_PAD.encode(&padded)
}

// ── DER ECDSA → P1363 conversion ─────────────────────────────────────────────

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

// ── Test state setup ──────────────────────────────────────────────────────────

async fn build_test_state(base_url: &str) -> (Arc<AppState>, tempfile::TempDir) {
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
            common_name: "Integration Test CA".into(),
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
    let state = AppStateBuilder::new(
        Arc::clone(&config),
        db_conn.clone(),
        db::DbKind::Sqlite,
        cas,
        Arc::new("default".to_string()),
    )
    .node_id(Arc::new("test".to_string()))
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

// ── DB bypass helper ──────────────────────────────────────────────────────────

/// Mark all challenges and authorizations for an order as `valid` and
/// update the order status to `ready`, bypassing actual challenge validation.
async fn mark_order_ready(db: &akamu::db::Db, order_id: &str) {
    let authz_ids: Vec<(String,)> =
        sqlx::query_as("SELECT id FROM authorizations WHERE order_id = ?")
            .bind(order_id)
            .fetch_all(db)
            .await
            .unwrap();

    for (authz_id,) in &authz_ids {
        sqlx::query(
            "UPDATE challenges SET status='valid', validated=1700000000 WHERE authz_id = ?",
        )
        .bind(authz_id)
        .execute(db)
        .await
        .unwrap();
        sqlx::query("UPDATE authorizations SET status='valid', updated=1700000000 WHERE id = ?")
            .bind(authz_id)
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

// ── ARI cert_id helper ────────────────────────────────────────────────────────

/// Build a minimal RFC 9773 cert_id for a certificate identified by its
/// hex-encoded serial number (as stored in the `certificates.serial_number`
/// column).  Pass `aki_bytes = state.default_ca().aki_bytes` for renewal-info requests;
/// an arbitrary slice is fine for `replaces` lookups (serial-only in the DB).
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

// ── CSR builder ───────────────────────────────────────────────────────────────

/// Build a CSR for `domain` signed by an *existing* `BackendPrivateKey`.
/// Used by tests that need to know the certificate's private key (e.g. JWK revocation).
fn make_csr_der_with_key(domain: &str, backend_key: &BackendPrivateKey) -> Vec<u8> {
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

fn make_ip_csr_der(ip_str: &str) -> Vec<u8> {
    let ip_bytes: Vec<u8> = if let Ok(addr) = ip_str.parse::<std::net::Ipv4Addr>() {
        addr.octets().to_vec()
    } else if let Ok(addr) = ip_str.parse::<std::net::Ipv6Addr>() {
        addr.octets().to_vec()
    } else {
        panic!("invalid IP: {ip_str}")
    };
    let backend_key = BackendPrivateKey::generate_ec("P-256").unwrap();
    let spki_der = backend_key.public_key().unwrap().spki_der().to_vec();
    let name_der = NameBuilder::new().common_name(ip_str).build().unwrap();
    let san_der = SubjectAlternativeNameBuilder::new()
        .ip_address(&ip_bytes)
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

// ── Integration test ──────────────────────────────────────────────────────────

#[tokio::test]
async fn full_acme_flow() {
    let base_url = "https://acme.test";
    let (state, _tmp) = build_test_state(base_url).await;
    let db = state.db.clone();
    let router = routes::build_router(Arc::clone(&state), None, false);

    // ── Step 1: GET /acme/directory ───────────────────────────────────────────
    let (status, dir, _) = get(&router, "/acme/directory").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        dir["newAccount"].as_str().is_some(),
        "directory missing newAccount"
    );
    assert!(
        dir["newNonce"].as_str().is_some(),
        "directory missing newNonce"
    );
    assert!(
        dir["newOrder"].as_str().is_some(),
        "directory missing newOrder"
    );

    // ── Step 2: HEAD /acme/new-nonce ─────────────────────────────────────────
    let nonce = head_nonce(&router).await;
    assert!(!nonce.is_empty(), "nonce must be non-empty");

    // ── Step 3: POST /acme/new-account ───────────────────────────────────────
    let acme_key = TestKey::generate();
    let jws = acme_key.jws_with_jwk(
        &nonce,
        &format!("{}/acme/new-account", base_url),
        Some(json!({"termsOfServiceAgreed": true})),
    );
    let (status, acct_body, acct_headers) = post_acme(&router, "/acme/new-account", jws).await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "new-account failed: {acct_body}"
    );
    assert_eq!(acct_body["status"].as_str().unwrap(), "valid");

    let account_url = location_header(&acct_headers);
    let nonce = nonce_header(&acct_headers);

    // ── Step 4: POST /acme/new-order ─────────────────────────────────────────
    let domain = "integration-test.acme.example";
    let jws = acme_key.jws_with_kid(
        &account_url,
        &nonce,
        &format!("{}/acme/new-order", base_url),
        Some(json!({"identifiers": [{"type": "dns", "value": domain}]})),
    );
    let (status, order_body, order_headers) = post_acme(&router, "/acme/new-order", jws).await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "new-order failed: {order_body}"
    );
    assert_eq!(order_body["status"].as_str().unwrap(), "pending");

    let order_url = location_header(&order_headers);
    let order_id = order_url.split('/').next_back().unwrap().to_string();
    let nonce = nonce_header(&order_headers);

    // ── Step 5: bypass challenge validation ───────────────────────────────────
    mark_order_ready(&db, &order_id).await;

    // ── Step 6: POST /acme/order/{id}/finalize ────────────────────────────────
    let csr_der = make_csr_der(domain);
    let csr_b64 = URL_SAFE_NO_PAD.encode(&csr_der);
    let finalize_url = format!("{}/acme/order/{}/finalize", base_url, order_id);
    let jws = acme_key.jws_with_kid(
        &account_url,
        &nonce,
        &finalize_url,
        Some(json!({"csr": csr_b64})),
    );
    let (status, final_body, final_headers) =
        post_acme(&router, &format!("/acme/order/{}/finalize", order_id), jws).await;
    assert_eq!(status, StatusCode::OK, "finalize failed: {final_body}");
    assert_eq!(final_body["status"].as_str().unwrap(), "valid");

    let cert_url = final_body["certificate"]
        .as_str()
        .expect("finalize response missing 'certificate' URL")
        .to_string();
    let _nonce = nonce_header(&final_headers);

    // ── Step 7: GET /acme/cert/{id} ──────────────────────────────────────────
    let cert_path = cert_url.trim_start_matches(base_url);
    let req = Request::builder()
        .method(Method::GET)
        .uri(cert_path)
        .body(Body::empty())
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let cert_bytes = axum::body::to_bytes(resp.into_body(), 1_000_000)
        .await
        .unwrap();
    let pem = std::str::from_utf8(&cert_bytes).expect("certificate must be UTF-8 PEM");
    assert!(
        pem.contains("-----BEGIN CERTIFICATE-----"),
        "certificate endpoint should return PEM"
    );
    let cert_count = pem.matches("-----BEGIN CERTIFICATE-----").count();
    assert!(
        cert_count >= 2,
        "PEM bundle should contain leaf + CA (got {cert_count})"
    );
}

// ── Helper: create account + order, return (account_url, order_body, nonce, router) ──

async fn setup_account_and_order(
    base_url: &str,
    state: &Arc<AppState>,
    domain: &str,
) -> (axum::Router, TestKey, String, Value, String) {
    let router = routes::build_router(Arc::clone(state), None, false);
    let key = TestKey::generate();

    // Account
    let nonce = head_nonce(&router).await;
    let jws = key.jws_with_jwk(
        &nonce,
        &format!("{base_url}/acme/new-account"),
        Some(json!({"termsOfServiceAgreed": true})),
    );
    let (status, _, acct_headers) = post_acme(&router, "/acme/new-account", jws).await;
    assert_eq!(status, StatusCode::CREATED);
    let account_url = location_header(&acct_headers);
    let nonce = nonce_header(&acct_headers);

    // Order
    let jws = key.jws_with_kid(
        &account_url,
        &nonce,
        &format!("{base_url}/acme/new-order"),
        Some(json!({"identifiers": [{"type": "dns", "value": domain}]})),
    );
    let (status, order_body, order_headers) = post_acme(&router, "/acme/new-order", jws).await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "new-order failed: {order_body}"
    );
    let nonce = nonce_header(&order_headers);

    (router, key, account_url, order_body, nonce)
}

// ── Tests for authz route ─────────────────────────────────────────────────────

#[tokio::test]
async fn test_get_authz() {
    let base_url = "https://acme.test";
    let (state, _tmp) = build_test_state(base_url).await;

    let (router, key, account_url, order_body, nonce) =
        setup_account_and_order(base_url, &state, "authz-test.example").await;

    let authz_url = order_body["authorizations"][0]
        .as_str()
        .unwrap()
        .to_string();
    let authz_path = authz_url.trim_start_matches(base_url).to_string();

    // POST-as-GET (empty payload string "")
    let jws = key.jws_with_kid(&account_url, &nonce, &authz_url, None);
    let (status, authz_body, _) = post_acme(&router, &authz_path, jws).await;
    assert_eq!(status, StatusCode::OK, "get_authz failed: {authz_body}");
    assert_eq!(authz_body["status"].as_str().unwrap(), "pending");
    assert!(authz_body["identifier"]["value"].as_str().is_some());
    let challenges = authz_body["challenges"].as_array().unwrap();
    assert!(
        !challenges.is_empty(),
        "authz must have at least one challenge"
    );
}

#[tokio::test]
async fn test_get_authz_not_found() {
    let base_url = "https://acme.test";
    let (state, _tmp) = build_test_state(base_url).await;

    let (router, key, account_url, _, nonce) =
        setup_account_and_order(base_url, &state, "authz-notfound.example").await;

    // Try to fetch a non-existent authz
    let bogus_url = format!("{base_url}/acme/authz/nonexistent-id");
    let jws = key.jws_with_kid(&account_url, &nonce, &bogus_url, None);
    let (status, body, _) = post_acme(&router, "/acme/authz/nonexistent-id", jws).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "expected 404: {body}");
}

// ── Tests for challenge route ─────────────────────────────────────────────────

#[tokio::test]
async fn test_respond_challenge_triggers_validation() {
    let base_url = "https://acme.test";
    let (state, _tmp) = build_test_state(base_url).await;

    let (router, key, account_url, order_body, nonce) =
        setup_account_and_order(base_url, &state, "chall-test.example").await;

    // Fetch the authz to get challenge info
    let authz_url = order_body["authorizations"][0]
        .as_str()
        .unwrap()
        .to_string();
    let authz_path = authz_url.trim_start_matches(base_url).to_string();
    let jws = key.jws_with_kid(&account_url, &nonce, &authz_url, None);
    let (_, authz_body, authz_headers) = post_acme(&router, &authz_path, jws).await;
    let nonce = nonce_header(&authz_headers);

    let challenges = authz_body["challenges"].as_array().unwrap();
    // Find the http-01 challenge
    let http_chall = challenges
        .iter()
        .find(|c| c["type"].as_str() == Some("http-01"))
        .unwrap();
    let chall_url = http_chall["url"].as_str().unwrap().to_string();
    let chall_path = chall_url.trim_start_matches(base_url).to_string();

    // Respond to the challenge. Validation runs synchronously and fails
    // immediately (no http-01 server running in this test), so the challenge
    // returns "invalid" rather than the old "processing" intermediate state.
    let jws = key.jws_with_kid(&account_url, &nonce, &chall_url, Some(json!({})));
    let (status, chall_body, _) = post_acme(&router, &chall_path, jws).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "challenge response failed: {chall_body}"
    );
    let chall_status = chall_body["status"].as_str().unwrap();
    assert!(
        chall_status == "processing" || chall_status == "valid" || chall_status == "invalid",
        "unexpected challenge status: {chall_status}"
    );
}

#[tokio::test]
async fn test_challenge_not_found() {
    let base_url = "https://acme.test";
    let (state, _tmp) = build_test_state(base_url).await;

    let (router, key, account_url, order_body, nonce) =
        setup_account_and_order(base_url, &state, "chall-notfound.example").await;

    // Get valid authz_id for the URL structure, but use bogus challenge type
    let authz_url = order_body["authorizations"][0]
        .as_str()
        .unwrap()
        .to_string();
    let authz_id = authz_url.split('/').next_back().unwrap();
    let bogus_chall_url = format!("{base_url}/acme/chall/{authz_id}/bogus-type");
    let bogus_chall_path = format!("/acme/chall/{authz_id}/bogus-type");

    let jws = key.jws_with_kid(&account_url, &nonce, &bogus_chall_url, Some(json!({})));
    let (status, body, _) = post_acme(&router, &bogus_chall_path, jws).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "expected 404: {body}");
}

// ── Tests for renewal_info route ──────────────────────────────────────────────

#[tokio::test]
async fn test_renewal_info() {
    let base_url = "https://acme.test";
    let (state, _tmp) = build_test_state(base_url).await;
    let db = state.db.clone();
    let router = routes::build_router(Arc::clone(&state), None, false);
    let domain = "ari-test.example";

    // Create account
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

    // Create order
    let jws = key.jws_with_kid(
        &account_url,
        &nonce,
        &format!("{base_url}/acme/new-order"),
        Some(json!({"identifiers": [{"type": "dns", "value": domain}]})),
    );
    let (_, _, order_headers) = post_acme(&router, "/acme/new-order", jws).await;
    let nonce = nonce_header(&order_headers);

    // Get order_id from DB
    let order_id: String =
        sqlx::query_as::<_, (String,)>("SELECT id FROM orders ORDER BY created DESC LIMIT 1")
            .fetch_one(&db)
            .await
            .unwrap()
            .0;

    mark_order_ready(&db, &order_id).await;

    // Finalize
    let csr_der = make_csr_der(domain);
    let csr_b64 = URL_SAFE_NO_PAD.encode(&csr_der);
    let finalize_url = format!("{base_url}/acme/order/{order_id}/finalize");
    let jws = key.jws_with_kid(
        &account_url,
        &nonce,
        &finalize_url,
        Some(json!({"csr": csr_b64})),
    );
    let (status, final_body, _) =
        post_acme(&router, &format!("/acme/order/{order_id}/finalize"), jws).await;
    assert_eq!(status, StatusCode::OK, "finalize failed: {final_body}");

    // Get serial_number from DB and build RFC 9773 cert_id.
    let serial_hex: String = sqlx::query_as::<_, (String,)>(
        "SELECT serial_number FROM certificates ORDER BY created DESC LIMIT 1",
    )
    .fetch_one(&db)
    .await
    .unwrap()
    .0;
    let cert_id = cert_id_from_serial_hex(&serial_hex, &state.default_ca().aki_bytes);

    // GET /acme/renewal-info/{cert_id}
    let (status, ari_body, _) = get(&router, &format!("/acme/renewal-info/{cert_id}")).await;
    assert_eq!(status, StatusCode::OK, "renewal-info failed: {ari_body}");
    assert!(ari_body["suggestedWindow"]["start"].as_str().is_some());
    assert!(ari_body["suggestedWindow"]["end"].as_str().is_some());
    // RFC 9773 §4.3 — Retry-After header must be present.
    assert!(
        ari_body.get("explanationURL").is_none(),
        "explanationURL must not be present"
    );
}

/// Renewal-info returns the explicitly-set renewal window (covers routes/renewal_info.rs:28).
///
/// Tests the `(Some(s), Some(e)) => (s, e)` match arm — triggered only when
/// `db::certs::set_renewal_window` has been called before the endpoint is queried.
#[tokio::test]
async fn test_renewal_info_explicit_window() {
    let base_url = "https://acme.test";
    let (state, _tmp) = build_test_state(base_url).await;
    let db = state.db.clone();
    let router = routes::build_router(Arc::clone(&state), None, false);
    let domain = "ari-explicit.example";

    // Create account
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

    // Create order
    let jws = key.jws_with_kid(
        &account_url,
        &nonce,
        &format!("{base_url}/acme/new-order"),
        Some(json!({"identifiers": [{"type": "dns", "value": domain}]})),
    );
    let (_, _, order_headers) = post_acme(&router, "/acme/new-order", jws).await;
    let nonce = nonce_header(&order_headers);

    let order_id: String =
        sqlx::query_as::<_, (String,)>("SELECT id FROM orders ORDER BY created DESC LIMIT 1")
            .fetch_one(&db)
            .await
            .unwrap()
            .0;

    mark_order_ready(&db, &order_id).await;

    // Finalize
    let csr_der = make_csr_der(domain);
    let csr_b64 = URL_SAFE_NO_PAD.encode(&csr_der);
    let finalize_url = format!("{base_url}/acme/order/{order_id}/finalize");
    let jws = key.jws_with_kid(
        &account_url,
        &nonce,
        &finalize_url,
        Some(json!({"csr": csr_b64})),
    );
    let (status, final_body, _) =
        post_acme(&router, &format!("/acme/order/{order_id}/finalize"), jws).await;
    assert_eq!(status, StatusCode::OK, "finalize failed: {final_body}");

    let (cert_uuid, serial_hex): (String, String) = sqlx::query_as::<_, (String, String)>(
        "SELECT id, serial_number FROM certificates ORDER BY created DESC LIMIT 1",
    )
    .fetch_one(&db)
    .await
    .unwrap();
    let cert_id = cert_id_from_serial_hex(&serial_hex, &state.default_ca().aki_bytes);

    // Set an explicit renewal window on this certificate.
    let window_start: i64 = 1_800_000_000; // 2027-01-15
    let window_end: i64 = 1_800_086_400; // 2027-01-16
    db::certs::set_renewal_window(&db, &cert_uuid, window_start, window_end)
        .await
        .unwrap();

    // GET /acme/renewal-info/{cert_id} — must use the explicit window, not the computed default.
    let (status, ari_body, _) = get(&router, &format!("/acme/renewal-info/{cert_id}")).await;
    assert_eq!(status, StatusCode::OK, "renewal-info failed: {ari_body}");

    let start_str = ari_body["suggestedWindow"]["start"].as_str().unwrap();
    let end_str = ari_body["suggestedWindow"]["end"].as_str().unwrap();
    // The explicit window timestamps encode to specific RFC 3339 strings.
    assert!(
        start_str.starts_with("2027-"),
        "expected explicit 2027 start, got: {start_str}"
    );
    assert!(
        end_str.starts_with("2027-"),
        "expected explicit 2027 end, got: {end_str}"
    );
}

#[tokio::test]
async fn test_renewal_info_not_found() {
    let base_url = "https://acme.test";
    let (state, _tmp) = build_test_state(base_url).await;
    let router = routes::build_router(Arc::clone(&state), None, false);

    // Well-formed cert_id with correct AKI but no matching serial → 404.
    let unknown = cert_id_from_serial_hex("deadbeefdeadbeef", &state.default_ca().aki_bytes);
    let (status, body, _) = get(&router, &format!("/acme/renewal-info/{unknown}")).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "expected 404: {body}");

    // Malformed cert_id (no dot) → 400 Bad Request.
    let (status, body, _) = get(&router, "/acme/renewal-info/nonexistent-cert").await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "expected 400: {body}");
}

// ── Tests for key_change route ────────────────────────────────────────────────

#[tokio::test]
async fn test_key_change() {
    let base_url = "https://acme.test";
    let (state, _tmp) = build_test_state(base_url).await;
    let router = routes::build_router(Arc::clone(&state), None, false);

    // Create account with old key
    let old_key = TestKey::generate();
    let nonce = head_nonce(&router).await;
    let jws = old_key.jws_with_jwk(
        &nonce,
        &format!("{base_url}/acme/new-account"),
        Some(json!({"termsOfServiceAgreed": true})),
    );
    let (status, _, acct_headers) = post_acme(&router, "/acme/new-account", jws).await;
    assert_eq!(status, StatusCode::CREATED);
    let account_url = location_header(&acct_headers);
    let nonce = nonce_header(&acct_headers);

    // Generate new key
    let new_key = TestKey::generate();
    let key_change_url = format!("{base_url}/acme/key-change");

    // Build inner JWS (signed with new key)
    let old_jwk = old_key.jwk();
    let inner_jws = new_key.inner_key_change_jws(&key_change_url, &account_url, &old_jwk);

    // Build outer JWS (signed with old key, payload = inner_jws)
    let outer_jws = old_key.jws_with_kid(&account_url, &nonce, &key_change_url, Some(inner_jws));

    let (status, body, _) = post_acme(&router, "/acme/key-change", outer_jws).await;
    assert_eq!(status, StatusCode::OK, "key-change failed: {body}");
    assert_eq!(body["status"].as_str().unwrap(), "valid");
}

// ── Tests for revoke route ────────────────────────────────────────────────────

/// Helper: run the full ACME flow and return the cert DER bytes.
async fn issue_cert_for_domain(
    base_url: &str,
    state: &Arc<AppState>,
    domain: &str,
) -> (axum::Router, String) {
    let db = state.db.clone();
    let router = routes::build_router(Arc::clone(state), None, false);
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

    let jws = key.jws_with_kid(
        &account_url,
        &nonce,
        &format!("{base_url}/acme/new-order"),
        Some(json!({"identifiers": [{"type": "dns", "value": domain}]})),
    );
    let (_, _, order_headers) = post_acme(&router, "/acme/new-order", jws).await;
    let nonce = nonce_header(&order_headers);

    let order_id: String =
        sqlx::query_as::<_, (String,)>("SELECT id FROM orders ORDER BY created DESC LIMIT 1")
            .fetch_one(&db)
            .await
            .unwrap()
            .0;
    mark_order_ready(&db, &order_id).await;

    let csr_der = make_csr_der(domain);
    let csr_b64 = URL_SAFE_NO_PAD.encode(&csr_der);
    let finalize_url = format!("{base_url}/acme/order/{order_id}/finalize");
    let jws = key.jws_with_kid(
        &account_url,
        &nonce,
        &finalize_url,
        Some(json!({"csr": csr_b64})),
    );
    let (status, final_body, _) =
        post_acme(&router, &format!("/acme/order/{order_id}/finalize"), jws).await;
    assert_eq!(status, StatusCode::OK, "finalize failed: {final_body}");

    let cert_path = final_body["certificate"]
        .as_str()
        .unwrap()
        .trim_start_matches(base_url)
        .to_string();
    let req = Request::builder()
        .method(Method::GET)
        .uri(&cert_path)
        .body(Body::empty())
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    let cert_bytes = axum::body::to_bytes(resp.into_body(), 1_000_000)
        .await
        .unwrap();
    let pem = std::str::from_utf8(&cert_bytes).unwrap();

    // Extract the leaf cert DER (first PEM block)
    let der_b64 = pem
        .lines()
        .skip_while(|l| !l.starts_with("-----BEGIN CERTIFICATE-----"))
        .skip(1)
        .take_while(|l| !l.starts_with("-----END CERTIFICATE-----"))
        .collect::<Vec<_>>()
        .join("");
    let cert_der = base64::engine::general_purpose::STANDARD
        .decode(&der_b64)
        .unwrap();
    let cert_b64url = URL_SAFE_NO_PAD.encode(&cert_der);

    (router, cert_b64url)
}

#[tokio::test]
async fn test_revoke_cert_by_account() {
    let base_url = "https://acme.test";
    let (state, _tmp) = build_test_state(base_url).await;

    let (router, cert_b64url) =
        issue_cert_for_domain(base_url, &state, "revoke-test.example").await;

    // Create a new account (the cert-issuing account) and revoke
    // Actually the cert was issued by the last account - we need that account's key to revoke
    // Simplest: use a fresh account with JWK to revoke (self-revocation path)
    let revoke_key = TestKey::generate();
    let nonce = head_nonce(&router).await;
    let jws = revoke_key.jws_with_jwk(
        &nonce,
        &format!("{base_url}/acme/new-account"),
        Some(json!({"termsOfServiceAgreed": true})),
    );
    let (_, _, acct_headers) = post_acme(&router, "/acme/new-account", jws).await;
    let revoke_account_url = location_header(&acct_headers);
    let nonce = nonce_header(&acct_headers);

    let revoke_url = format!("{base_url}/acme/revoke-cert");
    let jws = revoke_key.jws_with_kid(
        &revoke_account_url,
        &nonce,
        &revoke_url,
        Some(json!({"certificate": cert_b64url, "reason": 1})),
    );
    // This will fail with Unauthorized since the cert belongs to a different account,
    // but it exercises the route code path
    let (status, body, _) = post_acme(&router, "/acme/revoke-cert", jws).await;
    // Expect either OK (if it worked) or Unauthorized
    assert!(
        status == StatusCode::OK || status == StatusCode::UNAUTHORIZED,
        "unexpected status {status}: {body}"
    );
}

#[tokio::test]
async fn test_revoke_cert_not_found() {
    let base_url = "https://acme.test";
    let (state, _tmp) = build_test_state(base_url).await;
    let router = routes::build_router(Arc::clone(&state), None, false);

    // Create account
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

    // A cert DER that decodes to a valid structure but is not in the DB
    // Use the JWS cert field — send a bogus base64url
    let revoke_url = format!("{base_url}/acme/revoke-cert");
    let fake_cert_b64 = URL_SAFE_NO_PAD.encode(b"not a real certificate DER");
    let jws = key.jws_with_kid(
        &account_url,
        &nonce,
        &revoke_url,
        Some(json!({"certificate": fake_cert_b64})),
    );
    let (status, body, _) = post_acme(&router, "/acme/revoke-cert", jws).await;
    // Should be a bad request (can't parse as DER) or not found
    assert!(
        status.is_client_error(),
        "expected client error: {status}: {body}"
    );
}

// ── Tests for update_account route ───────────────────────────────────────────

#[tokio::test]
async fn test_update_account_post_as_get() {
    let base_url = "https://acme.test";
    let (state, _tmp) = build_test_state(base_url).await;
    let router = routes::build_router(Arc::clone(&state), None, false);

    let key = TestKey::generate();
    let nonce = head_nonce(&router).await;
    let jws = key.jws_with_jwk(
        &nonce,
        &format!("{base_url}/acme/new-account"),
        Some(json!({"termsOfServiceAgreed": true, "contact": ["mailto:test@example.com"]})),
    );
    let (_, _, acct_headers) = post_acme(&router, "/acme/new-account", jws).await;
    let account_url = location_header(&acct_headers);
    let account_id = account_url.split('/').next_back().unwrap().to_string();
    let nonce = nonce_header(&acct_headers);

    // POST-as-GET
    let jws = key.jws_with_kid(&account_url, &nonce, &account_url, None);
    let (status, body, _) = post_acme(&router, &format!("/acme/account/{account_id}"), jws).await;
    assert_eq!(status, StatusCode::OK, "POST-as-GET account failed: {body}");
    assert_eq!(body["status"].as_str().unwrap(), "valid");
}

#[tokio::test]
async fn test_update_account_deactivate() {
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
    let account_id = account_url.split('/').next_back().unwrap().to_string();
    let nonce = nonce_header(&acct_headers);

    let jws = key.jws_with_kid(
        &account_url,
        &nonce,
        &account_url,
        Some(json!({"status": "deactivated"})),
    );
    let (status, body, _) = post_acme(&router, &format!("/acme/account/{account_id}"), jws).await;
    assert_eq!(status, StatusCode::OK, "deactivate failed: {body}");
    assert_eq!(body["status"].as_str().unwrap(), "deactivated");
}

#[tokio::test]
async fn test_get_nonce_via_get() {
    let base_url = "https://acme.test";
    let (state, _tmp) = build_test_state(base_url).await;
    let router = routes::build_router(Arc::clone(&state), None, false);

    // GET /acme/new-nonce returns 204 No Content
    let (status, _, headers) = get(&router, "/acme/new-nonce").await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert!(headers.get("replay-nonce").is_some());
}

// ── New tests for route handler error paths ───────────────────────────────────

/// Verify that using a `kid` header for new-account fails (must use `jwk`).
#[tokio::test]
async fn test_new_account_with_kid_requires_jwk() {
    let base_url = "https://acme.test";
    let (state, _tmp) = build_test_state(base_url).await;
    let router = routes::build_router(Arc::clone(&state), None, false);

    // First create a valid account to get a kid URL.
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

    // Now try new-account with kid instead of jwk.
    let jws = key.jws_with_kid(
        &account_url,
        &nonce,
        &format!("{base_url}/acme/new-account"),
        Some(json!({"termsOfServiceAgreed": true})),
    );
    let (status, _, _) = post_acme(&router, "/acme/new-account", jws).await;
    assert!(
        status.is_client_error(),
        "new-account with kid should fail, got {status}"
    );
}

/// If the same JWK is used for new-account again, the existing account is returned.
#[tokio::test]
async fn test_new_account_returns_existing_when_key_matches() {
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
    let (status1, _, acct_headers1) = post_acme(&router, "/acme/new-account", jws).await;
    assert_eq!(status1, StatusCode::CREATED);
    let account_url1 = location_header(&acct_headers1);
    let nonce = nonce_header(&acct_headers1);

    // Send new-account again with the same JWK.
    let jws = key.jws_with_jwk(
        &nonce,
        &format!("{base_url}/acme/new-account"),
        Some(json!({"termsOfServiceAgreed": true})),
    );
    let (status2, _, acct_headers2) = post_acme(&router, "/acme/new-account", jws).await;
    // Should return 200 with Location pointing to existing account.
    assert_eq!(
        status2,
        StatusCode::OK,
        "second new-account should return existing"
    );
    let account_url2 = location_header(&acct_headers2);
    assert_eq!(
        account_url1, account_url2,
        "Location must point to same account"
    );
}

/// `onlyReturnExisting: true` with an unknown JWK → 400 AccountDoesNotExist.
#[tokio::test]
async fn test_new_account_only_return_existing_not_found() {
    let base_url = "https://acme.test";
    let (state, _tmp) = build_test_state(base_url).await;
    let router = routes::build_router(Arc::clone(&state), None, false);

    let key = TestKey::generate();
    let nonce = head_nonce(&router).await;
    let jws = key.jws_with_jwk(
        &nonce,
        &format!("{base_url}/acme/new-account"),
        Some(json!({"onlyReturnExisting": true})),
    );
    let (status, _, _) = post_acme(&router, "/acme/new-account", jws).await;
    assert!(
        status.is_client_error(),
        "onlyReturnExisting with unknown key should fail, got {status}"
    );
}

/// Update account contact info via POST to account URL.
#[tokio::test]
async fn test_update_account_contact() {
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
    let account_id = account_url.split('/').next_back().unwrap().to_string();
    let nonce = nonce_header(&acct_headers);

    // Update contact.
    let jws = key.jws_with_kid(
        &account_url,
        &nonce,
        &account_url,
        Some(json!({"contact": ["mailto:test@example.com"]})),
    );
    let (status, body, _) = post_acme(&router, &format!("/acme/account/{account_id}"), jws).await;
    assert_eq!(status, StatusCode::OK, "update contact failed: {body}");
    assert_eq!(body["contact"][0].as_str(), Some("mailto:test@example.com"));
}

/// Kid that doesn't match the account ID in the URL → Unauthorized.
#[tokio::test]
async fn test_update_account_kid_mismatch() {
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

    // Use account_url as kid but send request to a different account ID.
    let wrong_id = "00000000-0000-0000-0000-000000000000";
    let wrong_url = format!("{base_url}/acme/account/{wrong_id}");
    let jws = key.jws_with_kid(
        &account_url,
        &nonce,
        &wrong_url,
        Some(json!({"contact": []})),
    );
    let (status, _, _) = post_acme(&router, &format!("/acme/account/{wrong_id}"), jws).await;
    assert!(
        status.is_client_error(),
        "mismatched kid/account-id should fail, got {status}"
    );
}

/// Revoke a certificate using the correct account (success path).
#[tokio::test]
async fn test_revoke_cert_success_with_owner_account() {
    let base_url = "https://acme.test";
    let (state, _tmp) = build_test_state(base_url).await;
    let router = routes::build_router(Arc::clone(&state), None, false);
    let db = state.db.clone();

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

    // Create order.
    let jws = key.jws_with_kid(
        &account_url,
        &nonce,
        &format!("{base_url}/acme/new-order"),
        Some(json!({"identifiers": [{"type": "dns", "value": "revoke-success.test"}]})),
    );
    let (_, _, order_headers) = post_acme(&router, "/acme/new-order", jws).await;
    let nonce = nonce_header(&order_headers);

    let order_id: String =
        sqlx::query_as::<_, (String,)>("SELECT id FROM orders ORDER BY created DESC LIMIT 1")
            .fetch_one(&db)
            .await
            .unwrap()
            .0;
    mark_order_ready(&db, &order_id).await;

    let csr_der = make_csr_der("revoke-success.test");
    let csr_b64 = URL_SAFE_NO_PAD.encode(&csr_der);
    let finalize_url = format!("{base_url}/acme/order/{order_id}/finalize");
    let jws = key.jws_with_kid(
        &account_url,
        &nonce,
        &finalize_url,
        Some(json!({"csr": csr_b64})),
    );
    let (status, body, _) =
        post_acme(&router, &format!("/acme/order/{order_id}/finalize"), jws).await;
    assert_eq!(status, StatusCode::OK, "finalize failed: {body}");

    // Get cert DER.
    let cert_path = body["certificate"]
        .as_str()
        .unwrap()
        .trim_start_matches(base_url)
        .to_string();
    let req = Request::builder()
        .method(Method::GET)
        .uri(&cert_path)
        .body(Body::empty())
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    let cert_bytes = axum::body::to_bytes(resp.into_body(), 1_000_000)
        .await
        .unwrap();
    let pem = std::str::from_utf8(&cert_bytes).unwrap();
    let der_b64 = pem
        .lines()
        .skip_while(|l| !l.starts_with("-----BEGIN"))
        .skip(1)
        .take_while(|l| !l.starts_with("-----END"))
        .collect::<Vec<_>>()
        .join("");
    let cert_der = base64::engine::general_purpose::STANDARD
        .decode(&der_b64)
        .unwrap();
    let cert_b64url = URL_SAFE_NO_PAD.encode(&cert_der);

    // Revoke using the SAME account.
    let nonce = head_nonce(&router).await;
    let revoke_url = format!("{base_url}/acme/revoke-cert");
    let jws = key.jws_with_kid(
        &account_url,
        &nonce,
        &revoke_url,
        Some(json!({"certificate": cert_b64url, "reason": 1})),
    );
    let (status, body, _) = post_acme(&router, "/acme/revoke-cert", jws).await;
    assert_eq!(status, StatusCode::OK, "revoke by owner failed: {body}");
}

/// Revoke an already-revoked cert → 409 AlreadyRevoked.
#[tokio::test]
async fn test_revoke_already_revoked_cert() {
    let base_url = "https://acme.test";
    let (state, _tmp) = build_test_state(base_url).await;
    let (router, cert_b64url) =
        issue_cert_for_domain(base_url, &state, "already-revoked.test").await;

    // Get the account key from the db (we need to issue from same account)
    // Easier: issue fresh cert and revoke twice using the revocation path below.
    // First revoke must succeed; second must fail.
    // But we can't easily re-sign with the original account key from issue_cert_for_domain.
    // Workaround: use the DB to mark the cert as revoked directly, then try again.
    let cert_id: String =
        sqlx::query_as::<_, (String,)>("SELECT id FROM certificates ORDER BY created DESC LIMIT 1")
            .fetch_one(&state.db)
            .await
            .unwrap()
            .0;
    // Directly revoke via DB.
    akamu::db::certs::revoke(&state.db, &cert_id, Some(1), 1_700_000_000, None)
        .await
        .unwrap();

    // Now try to revoke via HTTP using a JWK that doesn't own the cert (will hit AlreadyRevoked before Unauthorized).
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

    let revoke_url = format!("{base_url}/acme/revoke-cert");
    let jws = key.jws_with_kid(
        &account_url,
        &nonce,
        &revoke_url,
        Some(json!({"certificate": cert_b64url})),
    );
    let (status, _, _) = post_acme(&router, "/acme/revoke-cert", jws).await;
    // Should be AlreadyRevoked (409) — checked before authorization
    assert!(
        status.is_client_error(),
        "already-revoked cert should fail, got {status}"
    );
}

/// Revoke with invalid reason code (7 or > 10) → BadRevocationReason.
#[tokio::test]
async fn test_revoke_invalid_reason_code() {
    let base_url = "https://acme.test";
    let (state, _tmp) = build_test_state(base_url).await;
    let (router, cert_b64url) = issue_cert_for_domain(base_url, &state, "bad-reason.test").await;

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

    // reason=7 is not allowed per RFC 8555.
    let revoke_url = format!("{base_url}/acme/revoke-cert");
    let jws = key.jws_with_kid(
        &account_url,
        &nonce,
        &revoke_url,
        Some(json!({"certificate": cert_b64url, "reason": 7})),
    );
    let (status, _, _) = post_acme(&router, "/acme/revoke-cert", jws).await;
    assert!(
        status.is_client_error(),
        "reason=7 should be rejected, got {status}"
    );
}

/// POST new-order with empty identifiers → BadRequest.
#[tokio::test]
async fn test_new_order_empty_identifiers() {
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

    let jws = key.jws_with_kid(
        &account_url,
        &nonce,
        &format!("{base_url}/acme/new-order"),
        Some(json!({"identifiers": []})),
    );
    let (status, _, _) = post_acme(&router, "/acme/new-order", jws).await;
    assert!(
        status.is_client_error(),
        "empty identifiers should fail, got {status}"
    );
}

/// POST new-order with unsupported identifier type → UnsupportedIdentifier.
#[tokio::test]
async fn test_new_order_unsupported_identifier_type() {
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

    let jws = key.jws_with_kid(
        &account_url,
        &nonce,
        &format!("{base_url}/acme/new-order"),
        Some(json!({"identifiers": [{"type": "email", "value": "user@example.com"}]})),
    );
    let (status, _, _) = post_acme(&router, "/acme/new-order", jws).await;
    assert!(
        status.is_client_error(),
        "unsupported identifier type should fail, got {status}"
    );
}

/// POST new-order with IP address identifier.
#[tokio::test]
async fn test_new_order_ip_identifier() {
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

    let jws = key.jws_with_kid(
        &account_url,
        &nonce,
        &format!("{base_url}/acme/new-order"),
        Some(json!({"identifiers": [{"type": "ip", "value": "192.0.2.1"}]})),
    );
    let (status, body, _) = post_acme(&router, "/acme/new-order", jws).await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "ip order should succeed: {body}"
    );
    assert_eq!(body["status"].as_str(), Some("pending"));
}

/// POST-as-GET /acme/order/{id} returns order status.
#[tokio::test]
async fn test_get_order() {
    let base_url = "https://acme.test";
    let (state, _tmp) = build_test_state(base_url).await;
    let router = routes::build_router(Arc::clone(&state), None, false);
    let db = state.db.clone();

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

    let jws = key.jws_with_kid(
        &account_url,
        &nonce,
        &format!("{base_url}/acme/new-order"),
        Some(json!({"identifiers": [{"type": "dns", "value": "get-order.test"}]})),
    );
    let (_, _, order_headers) = post_acme(&router, "/acme/new-order", jws).await;
    let nonce = nonce_header(&order_headers);

    let order_id: String =
        sqlx::query_as::<_, (String,)>("SELECT id FROM orders ORDER BY created DESC LIMIT 1")
            .fetch_one(&db)
            .await
            .unwrap()
            .0;

    // POST-as-GET to get order status.
    let order_url = format!("{base_url}/acme/order/{order_id}");
    let jws = key.jws_with_kid(&account_url, &nonce, &order_url, None);
    let (status, body, _) = post_acme(&router, &format!("/acme/order/{order_id}"), jws).await;
    assert_eq!(status, StatusCode::OK, "get-order failed: {body}");
    assert_eq!(body["status"].as_str(), Some("pending"));
}

/// Finalize an order that belongs to a different account → Unauthorized.
#[tokio::test]
async fn test_finalize_wrong_account() {
    let base_url = "https://acme.test";
    let (state, _tmp) = build_test_state(base_url).await;
    let router = routes::build_router(Arc::clone(&state), None, false);
    let db = state.db.clone();

    // Create two accounts: owner and attacker.
    let owner_key = TestKey::generate();
    let nonce = head_nonce(&router).await;
    let jws = owner_key.jws_with_jwk(
        &nonce,
        &format!("{base_url}/acme/new-account"),
        Some(json!({"termsOfServiceAgreed": true})),
    );
    let (_, _, acct_headers) = post_acme(&router, "/acme/new-account", jws).await;
    let owner_url = location_header(&acct_headers);
    let nonce = nonce_header(&acct_headers);

    // Owner creates an order.
    let jws = owner_key.jws_with_kid(
        &owner_url,
        &nonce,
        &format!("{base_url}/acme/new-order"),
        Some(json!({"identifiers": [{"type": "dns", "value": "wrong-acct.test"}]})),
    );
    let (_, _, order_headers) = post_acme(&router, "/acme/new-order", jws).await;
    let _nonce = nonce_header(&order_headers);
    let order_id: String =
        sqlx::query_as::<_, (String,)>("SELECT id FROM orders ORDER BY created DESC LIMIT 1")
            .fetch_one(&db)
            .await
            .unwrap()
            .0;
    mark_order_ready(&db, &order_id).await;

    // Create attacker account.
    let attacker_key = TestKey::generate();
    let nonce2 = head_nonce(&router).await;
    let jws2 = attacker_key.jws_with_jwk(
        &nonce2,
        &format!("{base_url}/acme/new-account"),
        Some(json!({"termsOfServiceAgreed": true})),
    );
    let (_, _, atk_headers) = post_acme(&router, "/acme/new-account", jws2).await;
    let attacker_url = location_header(&atk_headers);
    let nonce = nonce_header(&atk_headers);

    // Attacker tries to finalize owner's order.
    let csr_der = make_csr_der("wrong-acct.test");
    let csr_b64 = URL_SAFE_NO_PAD.encode(&csr_der);
    let finalize_url = format!("{base_url}/acme/order/{order_id}/finalize");
    let jws = attacker_key.jws_with_kid(
        &attacker_url,
        &nonce,
        &finalize_url,
        Some(json!({"csr": csr_b64})),
    );
    let (status, _, _) = post_acme(&router, &format!("/acme/order/{order_id}/finalize"), jws).await;
    assert!(
        status.is_client_error(),
        "finalize wrong account should fail, got {status}"
    );
}

/// Finalize a pending (not ready) order → OrderNotReady.
#[tokio::test]
async fn test_finalize_order_not_ready() {
    let base_url = "https://acme.test";
    let (state, _tmp) = build_test_state(base_url).await;
    let router = routes::build_router(Arc::clone(&state), None, false);
    let db = state.db.clone();

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

    let jws = key.jws_with_kid(
        &account_url,
        &nonce,
        &format!("{base_url}/acme/new-order"),
        Some(json!({"identifiers": [{"type": "dns", "value": "not-ready.test"}]})),
    );
    let (_, _, order_headers) = post_acme(&router, "/acme/new-order", jws).await;
    let nonce = nonce_header(&order_headers);
    let order_id: String =
        sqlx::query_as::<_, (String,)>("SELECT id FROM orders ORDER BY created DESC LIMIT 1")
            .fetch_one(&db)
            .await
            .unwrap()
            .0;
    // Do NOT call mark_order_ready → order stays in "pending" state.

    let csr_der = make_csr_der("not-ready.test");
    let csr_b64 = URL_SAFE_NO_PAD.encode(&csr_der);
    let finalize_url = format!("{base_url}/acme/order/{order_id}/finalize");
    let jws = key.jws_with_kid(
        &account_url,
        &nonce,
        &finalize_url,
        Some(json!({"csr": csr_b64})),
    );
    let (status, _, _) = post_acme(&router, &format!("/acme/order/{order_id}/finalize"), jws).await;
    assert!(
        status.is_client_error(),
        "finalize non-ready order should fail, got {status}"
    );
}

/// Key-change with no payload → BadRequest.
#[tokio::test]
async fn test_key_change_no_payload() {
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

    // Send key-change with empty payload (POST-as-GET = None).
    let key_change_url = format!("{base_url}/acme/key-change");
    let jws = key.jws_with_kid(&account_url, &nonce, &key_change_url, None);
    let (status, _, _) = post_acme(&router, "/acme/key-change", jws).await;
    assert!(
        status.is_client_error(),
        "key-change with no payload should fail, got {status}"
    );
}

/// Key-change where inner JWS uses kid (not jwk) → BadRequest.
#[tokio::test]
async fn test_key_change_inner_uses_kid() {
    let base_url = "https://acme.test";
    let (state, _tmp) = build_test_state(base_url).await;
    let router = routes::build_router(Arc::clone(&state), None, false);

    let old_key = TestKey::generate();
    let nonce = head_nonce(&router).await;
    let jws = old_key.jws_with_jwk(
        &nonce,
        &format!("{base_url}/acme/new-account"),
        Some(json!({"termsOfServiceAgreed": true})),
    );
    let (_, _, acct_headers) = post_acme(&router, "/acme/new-account", jws).await;
    let account_url = location_header(&acct_headers);
    let nonce = nonce_header(&acct_headers);

    let new_key = TestKey::generate();
    let key_change_url = format!("{base_url}/acme/key-change");

    // Build inner JWS using kid (not jwk) — this should be rejected.
    let inner = new_key.jws_with_kid(
        &account_url,
        "inner-dummy",
        &key_change_url,
        Some(json!({"account": account_url, "oldKey": old_key.jwk()})),
    );

    let jws = old_key.jws_with_kid(&account_url, &nonce, &key_change_url, Some(inner));
    let (status, _, _) = post_acme(&router, "/acme/key-change", jws).await;
    assert!(
        status.is_client_error(),
        "key-change with kid inner JWS should fail, got {status}"
    );
}

/// JWS URL field mismatch → Unauthorized.
#[tokio::test]
async fn test_jws_url_mismatch() {
    let base_url = "https://acme.test";
    let (state, _tmp) = build_test_state(base_url).await;
    let router = routes::build_router(Arc::clone(&state), None, false);

    let key = TestKey::generate();
    let nonce = head_nonce(&router).await;

    // Build a JWS where the `url` field points to a different endpoint.
    let wrong_url = format!("{base_url}/acme/wrong-url");
    let jws = key.jws_with_jwk(
        &nonce,
        &wrong_url,
        Some(json!({"termsOfServiceAgreed": true})),
    );
    let (status, _, _) = post_acme(&router, "/acme/new-account", jws).await;
    assert!(
        status.is_client_error(),
        "JWS url mismatch should fail, got {status}"
    );
}

/// Invalid nonce → BadNonce.
#[tokio::test]
async fn test_bad_nonce() {
    let base_url = "https://acme.test";
    let (state, _tmp) = build_test_state(base_url).await;
    let router = routes::build_router(Arc::clone(&state), None, false);

    let key = TestKey::generate();
    // Use a completely invalid nonce.
    let bad_nonce = "this-nonce-was-never-issued";
    let jws = key.jws_with_jwk(
        bad_nonce,
        &format!("{base_url}/acme/new-account"),
        Some(json!({"termsOfServiceAgreed": true})),
    );
    let (status, _, _) = post_acme(&router, "/acme/new-account", jws).await;
    assert!(
        status.is_client_error(),
        "bad nonce should fail, got {status}"
    );
}

/// Key-change where inner payload `account` field doesn't match the outer account URL.
#[tokio::test]
async fn test_key_change_wrong_inner_account_url() {
    let base_url = "https://acme.test";
    let (state, _tmp) = build_test_state(base_url).await;
    let router = routes::build_router(Arc::clone(&state), None, false);

    let old_key = TestKey::generate();
    let nonce = head_nonce(&router).await;
    let jws = old_key.jws_with_jwk(
        &nonce,
        &format!("{base_url}/acme/new-account"),
        Some(json!({"termsOfServiceAgreed": true})),
    );
    let (_, _, acct_headers) = post_acme(&router, "/acme/new-account", jws).await;
    let account_url = location_header(&acct_headers);
    let nonce = nonce_header(&acct_headers);

    let new_key = TestKey::generate();
    let key_change_url = format!("{base_url}/acme/key-change");

    // Inner payload has the WRONG account URL (different from the kid account).
    let wrong_account_url = format!("{base_url}/acme/account/wrong-id");
    let inner = new_key.inner_key_change_jws(&key_change_url, &wrong_account_url, &old_key.jwk());

    let jws = old_key.jws_with_kid(&account_url, &nonce, &key_change_url, Some(inner));
    let (status, _, _) = post_acme(&router, "/acme/key-change", jws).await;
    assert!(
        status.is_client_error(),
        "key-change with wrong inner account URL should fail, got {status}"
    );
}

/// Key-change where new key is already registered to another account → Conflict.
#[tokio::test]
async fn test_key_change_new_key_already_in_use() {
    let base_url = "https://acme.test";
    let (state, _tmp) = build_test_state(base_url).await;
    let router = routes::build_router(Arc::clone(&state), None, false);

    // Create account A with key1.
    let key1 = TestKey::generate();
    let nonce = head_nonce(&router).await;
    let jws = key1.jws_with_jwk(
        &nonce,
        &format!("{base_url}/acme/new-account"),
        Some(json!({"termsOfServiceAgreed": true})),
    );
    let (_, _, acct_headers1) = post_acme(&router, "/acme/new-account", jws).await;
    let account1_url = location_header(&acct_headers1);
    let nonce = nonce_header(&acct_headers1);

    // Create account B with key2.
    let key2 = TestKey::generate();
    let nonce2 = head_nonce(&router).await;
    let jws2 = key2.jws_with_jwk(
        &nonce2,
        &format!("{base_url}/acme/new-account"),
        Some(json!({"termsOfServiceAgreed": true})),
    );
    let (_, _, _acct_headers2) = post_acme(&router, "/acme/new-account", jws2).await;

    // Try to change account A's key to key2 (already registered to account B).
    let key_change_url = format!("{base_url}/acme/key-change");
    let inner = key2.inner_key_change_jws(&key_change_url, &account1_url, &key1.jwk());
    let jws = key1.jws_with_kid(&account1_url, &nonce, &key_change_url, Some(inner));
    let (status, _, _) = post_acme(&router, "/acme/key-change", jws).await;
    assert!(
        status.is_client_error(),
        "key-change to already-registered key should fail, got {status}"
    );
}

/// Creating a new order with a deactivated account → Unauthorized.
#[tokio::test]
async fn test_new_order_deactivated_account() {
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
    let account_id = account_url.split('/').next_back().unwrap().to_string();
    let nonce = nonce_header(&acct_headers);

    // Deactivate the account.
    let jws = key.jws_with_kid(
        &account_url,
        &nonce,
        &account_url,
        Some(json!({"status": "deactivated"})),
    );
    let (status, _, acct_resp_hdrs) =
        post_acme(&router, &format!("/acme/account/{account_id}"), jws).await;
    assert_eq!(status, StatusCode::OK);
    let nonce = nonce_header(&acct_resp_hdrs);

    // Try to create an order.
    let order_url = format!("{base_url}/acme/new-order");
    let jws = key.jws_with_kid(
        &account_url,
        &nonce,
        &order_url,
        Some(json!({"identifiers": [{"type": "dns", "value": "deactivated.test"}]})),
    );
    let (status, _, _) = post_acme(&router, "/acme/new-order", jws).await;
    assert!(
        status.is_client_error(),
        "deactivated account should not be able to create order, got {status}"
    );
}

/// GET order with an account that does not own that order → Unauthorized.
#[tokio::test]
async fn test_get_order_wrong_account() {
    let base_url = "https://acme.test";
    let (state, _tmp) = build_test_state(base_url).await;
    let router = routes::build_router(Arc::clone(&state), None, false);
    let db = state.db.clone();

    // Owner creates an order.
    let owner_key = TestKey::generate();
    let nonce = head_nonce(&router).await;
    let jws = owner_key.jws_with_jwk(
        &nonce,
        &format!("{base_url}/acme/new-account"),
        Some(json!({"termsOfServiceAgreed": true})),
    );
    let (_, _, acct_headers) = post_acme(&router, "/acme/new-account", jws).await;
    let owner_url = location_header(&acct_headers);
    let nonce = nonce_header(&acct_headers);

    let jws = owner_key.jws_with_kid(
        &owner_url,
        &nonce,
        &format!("{base_url}/acme/new-order"),
        Some(json!({"identifiers": [{"type": "dns", "value": "get-order-wrong.test"}]})),
    );
    let (_, _, _) = post_acme(&router, "/acme/new-order", jws).await;
    let order_id: String =
        sqlx::query_as::<_, (String,)>("SELECT id FROM orders ORDER BY created DESC LIMIT 1")
            .fetch_one(&db)
            .await
            .unwrap()
            .0;

    // Attacker creates account and tries to GET the order.
    let attacker_key = TestKey::generate();
    let nonce2 = head_nonce(&router).await;
    let jws2 = attacker_key.jws_with_jwk(
        &nonce2,
        &format!("{base_url}/acme/new-account"),
        Some(json!({"termsOfServiceAgreed": true})),
    );
    let (_, _, atk_headers) = post_acme(&router, "/acme/new-account", jws2).await;
    let attacker_url = location_header(&atk_headers);
    let nonce = nonce_header(&atk_headers);

    let order_url = format!("{base_url}/acme/order/{order_id}");
    let jws = attacker_key.jws_with_kid(&attacker_url, &nonce, &order_url, None);
    let (status, _, _) = post_acme(&router, &format!("/acme/order/{order_id}"), jws).await;
    assert!(
        status.is_client_error(),
        "get-order with wrong account should fail, got {status}"
    );
}

/// GET authz when a challenge has a `validated` timestamp set.
/// Covers routes/authz.rs line 47 and routes/challenge.rs line 113.
#[tokio::test]
async fn test_authz_challenge_with_validated_timestamp() {
    let base_url = "https://acme.test";
    let (state, _tmp) = build_test_state(base_url).await;
    let db = state.db.clone();

    let (router, key, account_url, order_body, nonce) =
        setup_account_and_order(base_url, &state, "authz-validated.example").await;
    let authz_url = order_body["authorizations"][0]
        .as_str()
        .unwrap()
        .to_string();
    let authz_id = authz_url.split('/').next_back().unwrap().to_string();

    // Set challenge to 'valid' with a validated timestamp.
    sqlx::query(
        "UPDATE challenges SET status='valid', validated=1700000000 WHERE authz_id=? AND type='http-01'",
    )
    .bind(&authz_id)
    .execute(&db)
    .await
    .unwrap();

    // GET the authz — response includes challenge with validated timestamp.
    let authz_path = authz_url.trim_start_matches(base_url).to_string();
    let jws = key.jws_with_kid(&account_url, &nonce, &authz_url, None);
    let (status, body, hdr) = post_acme(&router, &authz_path, jws).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "get authz with validated challenge failed: {body}"
    );
    let challenges = body["challenges"].as_array().unwrap();
    let valid_chall = challenges
        .iter()
        .find(|c| c["status"].as_str() == Some("valid"))
        .unwrap();
    assert!(
        valid_chall["validated"].as_str().is_some(),
        "validated field missing"
    );

    // Also POST directly to the challenge (status != pending → challenge_response with validated).
    let nonce2 = nonce_header(&hdr);
    let chall_url = format!("{base_url}/acme/chall/{authz_id}/http-01");
    let chall_path = format!("/acme/chall/{authz_id}/http-01");
    let jws = key.jws_with_kid(&account_url, &nonce2, &chall_url, Some(json!({})));
    let (status, body, _) = post_acme(&router, &chall_path, jws).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "POST valid challenge failed: {body}"
    );
    assert!(
        body["validated"].as_str().is_some(),
        "validated field missing in challenge response"
    );
}

/// GET authz when a challenge has an `error` field set.
/// Covers routes/authz.rs lines 50-51 and routes/challenge.rs line 116.
#[tokio::test]
async fn test_authz_challenge_with_error_field() {
    let base_url = "https://acme.test";
    let (state, _tmp) = build_test_state(base_url).await;
    let db = state.db.clone();

    let (router, key, account_url, order_body, nonce) =
        setup_account_and_order(base_url, &state, "authz-error.example").await;
    let authz_url = order_body["authorizations"][0]
        .as_str()
        .unwrap()
        .to_string();
    let authz_id = authz_url.split('/').next_back().unwrap().to_string();

    // Set challenge to 'invalid' with a JSON error string.
    let error_json = r#"{"type":"urn:ietf:params:acme:error:dns","detail":"DNS lookup failed"}"#;
    sqlx::query(
        "UPDATE challenges SET status='invalid', error=? WHERE authz_id=? AND type='http-01'",
    )
    .bind(error_json)
    .bind(&authz_id)
    .execute(&db)
    .await
    .unwrap();

    // GET the authz — response includes challenge error.
    let authz_path = authz_url.trim_start_matches(base_url).to_string();
    let jws = key.jws_with_kid(&account_url, &nonce, &authz_url, None);
    let (status, body, hdr) = post_acme(&router, &authz_path, jws).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "get authz with error challenge failed: {body}"
    );
    let challenges = body["challenges"].as_array().unwrap();
    let inv_chall = challenges
        .iter()
        .find(|c| c["status"].as_str() == Some("invalid"))
        .unwrap();
    assert!(
        inv_chall["error"].as_object().is_some(),
        "error field missing in authz response"
    );

    // Also POST directly to the challenge (status != pending → challenge_response with error).
    let nonce2 = nonce_header(&hdr);
    let chall_url = format!("{base_url}/acme/chall/{authz_id}/http-01");
    let chall_path = format!("/acme/chall/{authz_id}/http-01");
    let jws = key.jws_with_kid(&account_url, &nonce2, &chall_url, Some(json!({})));
    let (status, body, _) = post_acme(&router, &chall_path, jws).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "POST invalid challenge failed: {body}"
    );
    assert!(
        body["error"].as_object().is_some(),
        "error field missing in challenge response"
    );
}

/// GET /acme/directory with all optional ServerConfig fields set.
/// Covers the 4 conditional branches in routes/directory.rs.
#[tokio::test]
async fn test_directory_with_optional_fields() {
    let base_url = "https://acme.test";
    let dir = tempfile::TempDir::new().unwrap();
    let config = Arc::new(akamu::config::Config {
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
            common_name: "Dir Test CA".into(),
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
        mtc: Some(akamu::config::MtcConfig {
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
        server: akamu::config::ServerConfig {
            terms_of_service_url: Some("https://example.org/tos".into()),
            website_url: Some("https://example.org".into()),
            caa_identities: vec!["ca.example.org".into()],
            external_account_required: true,
            ..akamu::config::ServerConfig::default()
        },
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
    db::install_drivers();
    let db_conn = db::open("sqlite::memory:", 1, false).await.unwrap();
    let ca = Arc::new(akamu::state::CaState {
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
        aki_bytes: Vec::new(),
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
    let state = AppStateBuilder::new(
        Arc::clone(&config),
        db_conn.clone(),
        db::DbKind::Sqlite,
        cas,
        Arc::new("default".to_string()),
    )
    .node_id(Arc::new("test".to_string()))
    .build();
    let router = routes::build_router(Arc::clone(&state), None, false);
    let (status, dir_body, _) = get(&router, "/acme/directory").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        dir_body["meta"]["termsOfService"].as_str(),
        Some("https://example.org/tos")
    );
    assert_eq!(
        dir_body["meta"]["website"].as_str(),
        Some("https://example.org")
    );
    assert!(dir_body["meta"]["caaIdentities"].as_array().is_some());
    assert_eq!(
        dir_body["meta"]["externalAccountRequired"].as_bool(),
        Some(true)
    );
}

/// GET authz with an account that does not own it → Unauthorized.
/// Covers routes/authz.rs line 30.
#[tokio::test]
async fn test_authz_wrong_account() {
    let base_url = "https://acme.test";
    let (state, _tmp) = build_test_state(base_url).await;

    // Account 1 creates an order to get an authz.
    let (router, _key1, _account1_url, order_body, _nonce1) =
        setup_account_and_order(base_url, &state, "authz-wrong-acct.example").await;
    let authz_url = order_body["authorizations"][0]
        .as_str()
        .unwrap()
        .to_string();
    let authz_path = authz_url.trim_start_matches(base_url).to_string();

    // Account 2 tries to GET the authz.
    let key2 = TestKey::generate();
    let nonce2 = head_nonce(&router).await;
    let jws2 = key2.jws_with_jwk(
        &nonce2,
        &format!("{base_url}/acme/new-account"),
        Some(json!({"termsOfServiceAgreed": true})),
    );
    let (_, _, acct_headers2) = post_acme(&router, "/acme/new-account", jws2).await;
    let account2_url = location_header(&acct_headers2);
    let nonce2 = nonce_header(&acct_headers2);

    let jws = key2.jws_with_kid(&account2_url, &nonce2, &authz_url, None);
    let (status, body, _) = post_acme(&router, &authz_path, jws).await;
    assert!(
        status.is_client_error(),
        "get authz from wrong account should fail, got {status}: {body}"
    );
}

/// POST challenge with an account that does not own the authz → Unauthorized.
/// Covers routes/challenge.rs line 38.
#[tokio::test]
async fn test_challenge_authz_wrong_account() {
    let base_url = "https://acme.test";
    let (state, _tmp) = build_test_state(base_url).await;

    // Account 1 creates an order.
    let (router, _key1, _account1_url, order_body, _nonce1) =
        setup_account_and_order(base_url, &state, "chall-wrong-acct.example").await;
    let authz_url = order_body["authorizations"][0]
        .as_str()
        .unwrap()
        .to_string();
    let authz_id = authz_url.split('/').next_back().unwrap();
    let chall_url = format!("{base_url}/acme/chall/{authz_id}/http-01");
    let chall_path = format!("/acme/chall/{authz_id}/http-01");

    // Account 2 tries to respond to the challenge.
    let key2 = TestKey::generate();
    let nonce2 = head_nonce(&router).await;
    let jws2 = key2.jws_with_jwk(
        &nonce2,
        &format!("{base_url}/acme/new-account"),
        Some(json!({"termsOfServiceAgreed": true})),
    );
    let (_, _, acct_headers2) = post_acme(&router, "/acme/new-account", jws2).await;
    let account2_url = location_header(&acct_headers2);
    let nonce2 = nonce_header(&acct_headers2);

    let jws = key2.jws_with_kid(&account2_url, &nonce2, &chall_url, Some(json!({})));
    let (status, body, _) = post_acme(&router, &chall_path, jws).await;
    assert!(
        status.is_client_error(),
        "challenge from wrong account should fail, got {status}: {body}"
    );
}

/// POST challenge when the authz status is not 'pending' → 200 with current state.
///
/// RFC 8555 §7.5.1: the server MUST ignore the request body and return the
/// current challenge object when the authorization is already resolved.
/// Clients legitimately poll challenge URLs after validation completes.
#[tokio::test]
async fn test_challenge_authz_not_pending() {
    let base_url = "https://acme.test";
    let (state, _tmp) = build_test_state(base_url).await;
    let db = state.db.clone();

    let (router, key, account_url, order_body, nonce) =
        setup_account_and_order(base_url, &state, "chall-authz-not-pending.example").await;
    let authz_url = order_body["authorizations"][0]
        .as_str()
        .unwrap()
        .to_string();
    let authz_id = authz_url.split('/').next_back().unwrap().to_string();

    // Mark the authz as 'valid' to simulate post-validation polling.
    sqlx::query("UPDATE authorizations SET status='valid' WHERE id=?")
        .bind(&authz_id)
        .execute(&db)
        .await
        .unwrap();

    let chall_url = format!("{base_url}/acme/chall/{authz_id}/http-01");
    let chall_path = format!("/acme/chall/{authz_id}/http-01");
    let jws = key.jws_with_kid(&account_url, &nonce, &chall_url, Some(json!({})));
    let (status, body, _) = post_acme(&router, &chall_path, jws).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "re-poll of a resolved challenge must return 200 with current state, got {status}: {body}"
    );
    assert!(
        body["type"].as_str().is_some(),
        "response must contain a challenge object, got: {body}"
    );
}

/// POST challenge when challenge is already 'processing' → returns current state.
/// Covers routes/challenge.rs lines 54-56.
#[tokio::test]
async fn test_challenge_already_processing() {
    let base_url = "https://acme.test";
    let (state, _tmp) = build_test_state(base_url).await;
    let db = state.db.clone();

    let (router, key, account_url, order_body, nonce) =
        setup_account_and_order(base_url, &state, "chall-processing.example").await;
    let authz_url = order_body["authorizations"][0]
        .as_str()
        .unwrap()
        .to_string();
    let authz_id = authz_url.split('/').next_back().unwrap().to_string();

    // Mark the http-01 challenge as 'processing'.
    sqlx::query("UPDATE challenges SET status='processing' WHERE authz_id=? AND type='http-01'")
        .bind(&authz_id)
        .execute(&db)
        .await
        .unwrap();

    let chall_url = format!("{base_url}/acme/chall/{authz_id}/http-01");
    let chall_path = format!("/acme/chall/{authz_id}/http-01");
    let jws = key.jws_with_kid(&account_url, &nonce, &chall_url, Some(json!({})));
    let (status, body, _) = post_acme(&router, &chall_path, jws).await;
    // Should return 200 with processing state (not an error).
    assert_eq!(
        status,
        StatusCode::OK,
        "already-processing challenge should return 200, got {status}: {body}"
    );
    assert_eq!(body["status"].as_str().unwrap_or(""), "processing");
}

/// Revoke a cert using JWK (cert's own key) rather than KID (account key).
/// RFC 8555 §7.6: the signing key MUST be the certificate's actual public key.
/// Covers routes/revoke.rs None branch.
#[tokio::test]
async fn test_revoke_cert_by_jwk() {
    let base_url = "https://acme.test";
    let (state, _tmp) = build_test_state(base_url).await;
    let db = state.db.clone();
    let router = routes::build_router(Arc::clone(&state), None, false);

    // Account key used to create the account and order.
    let account_key = TestKey::generate();
    let nonce = head_nonce(&router).await;
    let jws = account_key.jws_with_jwk(
        &nonce,
        &format!("{base_url}/acme/new-account"),
        Some(json!({"termsOfServiceAgreed": true})),
    );
    let (_, _, acct_headers) = post_acme(&router, "/acme/new-account", jws).await;
    let account_url = location_header(&acct_headers);
    let nonce = nonce_header(&acct_headers);

    let jws = account_key.jws_with_kid(
        &account_url,
        &nonce,
        &format!("{base_url}/acme/new-order"),
        Some(json!({"identifiers": [{"type": "dns", "value": "jwk-revoke.test"}]})),
    );
    let (_, _, order_headers) = post_acme(&router, "/acme/new-order", jws).await;
    let nonce = nonce_header(&order_headers);

    let order_id: String =
        sqlx::query_as::<_, (String,)>("SELECT id FROM orders ORDER BY created DESC LIMIT 1")
            .fetch_one(&db)
            .await
            .unwrap()
            .0;
    mark_order_ready(&db, &order_id).await;

    // Build CSR with a known cert key so we can use it for JWK revocation.
    let cert_backend_key = BackendPrivateKey::generate_ec("P-256").unwrap();
    let csr_der = make_csr_der_with_key("jwk-revoke.test", &cert_backend_key);
    let csr_b64 = URL_SAFE_NO_PAD.encode(&csr_der);
    let finalize_url = format!("{base_url}/acme/order/{order_id}/finalize");
    let jws = account_key.jws_with_kid(
        &account_url,
        &nonce,
        &finalize_url,
        Some(json!({"csr": csr_b64})),
    );
    let (status, final_body, _) =
        post_acme(&router, &format!("/acme/order/{order_id}/finalize"), jws).await;
    assert_eq!(status, StatusCode::OK, "finalize failed: {final_body}");

    // Extract the leaf cert DER.
    let cert_path = final_body["certificate"]
        .as_str()
        .unwrap()
        .trim_start_matches(base_url)
        .to_string();
    let req = Request::builder()
        .method(Method::GET)
        .uri(&cert_path)
        .body(Body::empty())
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    let cert_bytes = axum::body::to_bytes(resp.into_body(), 1_000_000)
        .await
        .unwrap();
    let pem = std::str::from_utf8(&cert_bytes).unwrap();
    let der_b64 = pem
        .lines()
        .skip_while(|l| !l.starts_with("-----BEGIN CERTIFICATE-----"))
        .skip(1)
        .take_while(|l| !l.starts_with("-----END CERTIFICATE-----"))
        .collect::<Vec<_>>()
        .join("");
    let cert_der = base64::engine::general_purpose::STANDARD
        .decode(&der_b64)
        .unwrap();
    let cert_b64url = URL_SAFE_NO_PAD.encode(&cert_der);

    // Build a TestKey from cert_backend_key to sign the revocation JWS.
    let cert_key = {
        let pub_key = cert_backend_key.public_key().unwrap();
        let (x_bytes, y_bytes) = pub_key.ec_affine_coordinates().unwrap().unwrap();
        let x_b64 = encode_coord(&x_bytes, 32);
        let y_b64 = encode_coord(&y_bytes, 32);
        let _spki_der = pub_key.spki_der().to_vec();
        TestKey {
            key: cert_backend_key,
            x_b64,
            y_b64,
            _spki_der,
        }
    };

    // Revoke using the cert's own key (JWK) — RFC 8555 §7.6.
    let nonce = head_nonce(&router).await;
    let revoke_url = format!("{base_url}/acme/revoke-cert");
    let jws = cert_key.jws_with_jwk(
        &nonce,
        &revoke_url,
        Some(json!({"certificate": cert_b64url})),
    );
    let (status, body, _) = post_acme(&router, "/acme/revoke-cert", jws).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "jwk-based cert revoke failed: {body}"
    );
}

/// Finalize a cert with MTC log enabled — verifies the MTC log path in finalize.rs.
#[tokio::test]
async fn test_finalize_with_mtc_enabled() {
    use akamu::mtc::log;
    use synta_mtc::crypto::HashAlgorithm;
    use tokio::sync::Mutex;

    let base_url = "https://acme.test";
    let dir = tempfile::TempDir::new().unwrap();
    let log_path = dir.path().join("mtc.log").to_string_lossy().into_owned();

    let config = Arc::new(akamu::config::Config {
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
            common_name: "MTC Test CA".into(),
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
            log_path: log_path.clone(),
            enabled: true,
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
        server: akamu::config::ServerConfig::default(),
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
    db::install_drivers();
    let db_conn = db::open("sqlite::memory:", 1, false).await.unwrap();
    let algorithm = HashAlgorithm::Sha256;
    let mtc_log = log::open_or_create(&log_path, algorithm).unwrap();
    let shared_log = Arc::new(Mutex::new(mtc_log));

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
        aki_bytes: Vec::new(),
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
    let state = AppStateBuilder::new(
        Arc::clone(&config),
        db_conn.clone(),
        db::DbKind::Sqlite,
        cas,
        Arc::new("default".to_string()),
    )
    .node_id(Arc::new("test".to_string()))
    .build();

    let router = routes::build_router(Arc::clone(&state), None, false);

    // Run a full ACME flow to finalize a cert (triggers MTC log append).
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

    let jws = key.jws_with_kid(
        &account_url,
        &nonce,
        &format!("{base_url}/acme/new-order"),
        Some(json!({"identifiers": [{"type": "dns", "value": "mtc-test.example"}]})),
    );
    let (_, _, order_headers) = post_acme(&router, "/acme/new-order", jws).await;
    let nonce = nonce_header(&order_headers);

    let order_id: String =
        sqlx::query_as::<_, (String,)>("SELECT id FROM orders ORDER BY created DESC LIMIT 1")
            .fetch_one(&db_conn)
            .await
            .unwrap()
            .0;
    mark_order_ready(&db_conn, &order_id).await;

    let csr_der = make_csr_der("mtc-test.example");
    let csr_b64 = URL_SAFE_NO_PAD.encode(&csr_der);
    let finalize_url = format!("{base_url}/acme/order/{order_id}/finalize");
    let jws = key.jws_with_kid(
        &account_url,
        &nonce,
        &finalize_url,
        Some(json!({"csr": csr_b64})),
    );
    let (status, body, _) =
        post_acme(&router, &format!("/acme/order/{order_id}/finalize"), jws).await;
    assert_eq!(status, StatusCode::OK, "finalize with MTC failed: {body}");

    // Give the spawned MTC log task a moment to run.
    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
    // Verify something was logged to the MTC log.
    let tree_size = log::tree_size(&shared_log).await.unwrap();
    assert!(
        tree_size >= 1,
        "MTC log should have at least 1 entry after finalize"
    );
}

/// Finalize an order with an IP SAN — covers ca/issue.rs IP SAN path (lines 117-121).
#[tokio::test]
async fn test_finalize_ip_san() {
    let base_url = "https://acme.test";
    let (state, _tmp) = build_test_state(base_url).await;
    let db = state.db.clone();
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

    let jws = key.jws_with_kid(
        &account_url,
        &nonce,
        &format!("{base_url}/acme/new-order"),
        Some(json!({"identifiers": [{"type": "ip", "value": "192.0.2.1"}]})),
    );
    let (_, _, order_headers) = post_acme(&router, "/acme/new-order", jws).await;
    let nonce = nonce_header(&order_headers);

    let order_id: String =
        sqlx::query_as::<_, (String,)>("SELECT id FROM orders ORDER BY created DESC LIMIT 1")
            .fetch_one(&db)
            .await
            .unwrap()
            .0;
    mark_order_ready(&db, &order_id).await;

    let csr_der = make_ip_csr_der("192.0.2.1");
    let csr_b64 = URL_SAFE_NO_PAD.encode(&csr_der);
    let finalize_url = format!("{base_url}/acme/order/{order_id}/finalize");
    let jws = key.jws_with_kid(
        &account_url,
        &nonce,
        &finalize_url,
        Some(json!({"csr": csr_b64})),
    );
    let (status, body, _) =
        post_acme(&router, &format!("/acme/order/{order_id}/finalize"), jws).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "finalize with IP SAN failed: {body}"
    );
    assert_eq!(
        body["status"].as_str(),
        Some("valid"),
        "order should be valid after IP finalize"
    );
}

/// Deactivating an account and then trying to create a new order — covers routes/order.rs:44.
#[tokio::test]
async fn test_new_order_with_deactivated_account() {
    let base_url = "https://acme.test";
    let (state, _tmp) = build_test_state(base_url).await;
    let router = routes::build_router(Arc::clone(&state), None, false);

    let key = TestKey::generate();

    // Create the account.
    let nonce = head_nonce(&router).await;
    let jws = key.jws_with_jwk(
        &nonce,
        &format!("{base_url}/acme/new-account"),
        Some(json!({"termsOfServiceAgreed": true})),
    );
    let (status, _, acct_headers) = post_acme(&router, "/acme/new-account", jws).await;
    assert_eq!(status, StatusCode::CREATED);
    let account_url = location_header(&acct_headers);
    let nonce = nonce_header(&acct_headers);

    // Deactivate the account.
    let acct_path = account_url.strip_prefix(base_url).unwrap();
    let jws = key.jws_with_kid(
        &account_url,
        &nonce,
        &account_url,
        Some(json!({"status": "deactivated"})),
    );
    let (status, body, headers) = post_acme(&router, acct_path, jws).await;
    assert_eq!(status, StatusCode::OK, "deactivate failed: {body}");
    assert_eq!(body["status"].as_str(), Some("deactivated"));
    let nonce = nonce_header(&headers);

    // Attempt to create a new order — should be rejected because account is deactivated.
    let jws = key.jws_with_kid(
        &account_url,
        &nonce,
        &format!("{base_url}/acme/new-order"),
        Some(json!({"identifiers": [{"type": "dns", "value": "deactivated.test"}]})),
    );
    let (status, body, _) = post_acme(&router, "/acme/new-order", jws).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "expected 401 for deactivated account: {body}"
    );
}

/// Finalize a certificate when OCSP and CRL URLs are configured — covers ca/issue.rs lines 145-158.
#[tokio::test]
async fn test_finalize_with_aia_and_cdp() {
    let base_url = "https://acme.test";
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
            crl_url: Some("http://crl.test/ca.crl".into()),
            ocsp_url: Some("http://ocsp.test/".into()),
            common_name: "Test CA".into(),
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
    });
    let (ca_key, ca_cert_der) = ca::init::load_or_generate(config.default_ca()).unwrap();
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
        crl_url: Some("http://crl.test/ca.crl".into()),
        ocsp_url: Some("http://ocsp.test/".into()),
        aki_bytes: Vec::new(),
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
    let state = AppStateBuilder::new(
        Arc::clone(&config),
        db_conn.clone(),
        db::DbKind::Sqlite,
        cas,
        Arc::new("default".to_string()),
    )
    .node_id(Arc::new("test".to_string()))
    .build();

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

    let jws = key.jws_with_kid(
        &account_url,
        &nonce,
        &format!("{base_url}/acme/new-order"),
        Some(json!({"identifiers": [{"type": "dns", "value": "aia-cdp.test"}]})),
    );
    let (_, _, order_headers) = post_acme(&router, "/acme/new-order", jws).await;
    let nonce = nonce_header(&order_headers);

    let order_id: String =
        sqlx::query_as::<_, (String,)>("SELECT id FROM orders ORDER BY created DESC LIMIT 1")
            .fetch_one(&db_conn)
            .await
            .unwrap()
            .0;
    mark_order_ready(&db_conn, &order_id).await;

    let csr_der = make_csr_der("aia-cdp.test");
    let csr_b64 = URL_SAFE_NO_PAD.encode(&csr_der);
    let finalize_url = format!("{base_url}/acme/order/{order_id}/finalize");
    let jws = key.jws_with_kid(
        &account_url,
        &nonce,
        &finalize_url,
        Some(json!({"csr": csr_b64})),
    );
    let (status, body, _) =
        post_acme(&router, &format!("/acme/order/{order_id}/finalize"), jws).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "finalize with AIA/CDP failed: {body}"
    );
    assert_eq!(
        body["status"].as_str(),
        Some("valid"),
        "order should be valid after AIA/CDP finalize"
    );
}

/// GET /ca/crl returns a DER-encoded CRL that contains the serial of a revoked certificate.
#[tokio::test]
async fn test_crl_endpoint_contains_revoked_serial() {
    let base_url = "https://acme.test";
    let (state, _tmp) = build_test_state(base_url).await;
    let router = routes::build_router(Arc::clone(&state), None, false);
    let db = state.db.clone();

    // Issue a certificate via the full ACME flow.
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

    let jws = key.jws_with_kid(
        &account_url,
        &nonce,
        &format!("{base_url}/acme/new-order"),
        Some(json!({"identifiers": [{"type": "dns", "value": "crl-test.example"}]})),
    );
    let (_, _, order_headers) = post_acme(&router, "/acme/new-order", jws).await;
    let nonce = nonce_header(&order_headers);

    let order_id: String =
        sqlx::query_as::<_, (String,)>("SELECT id FROM orders ORDER BY created DESC LIMIT 1")
            .fetch_one(&db)
            .await
            .unwrap()
            .0;
    mark_order_ready(&db, &order_id).await;

    let csr_der = make_csr_der("crl-test.example");
    let csr_b64 = URL_SAFE_NO_PAD.encode(&csr_der);
    let jws = key.jws_with_kid(
        &account_url,
        &nonce,
        &format!("{base_url}/acme/order/{order_id}/finalize"),
        Some(json!({"csr": csr_b64})),
    );
    let (status, _, _) = post_acme(&router, &format!("/acme/order/{order_id}/finalize"), jws).await;
    assert_eq!(status, StatusCode::OK, "finalize failed");

    // Read the issued cert's serial from the DB.
    let (cert_id, serial_hex): (String, String) = sqlx::query_as::<_, (String, String)>(
        "SELECT id, serial_number FROM certificates ORDER BY created DESC LIMIT 1",
    )
    .fetch_one(&db)
    .await
    .unwrap();

    // CRL should be empty before revocation.
    let req = Request::builder()
        .method(Method::GET)
        .uri("/ca/crl")
        .body(Body::empty())
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "GET /ca/crl failed");
    assert_eq!(
        resp.headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok()),
        Some("application/pkix-crl"),
        "wrong Content-Type for CRL"
    );
    let crl_bytes_before = axum::body::to_bytes(resp.into_body(), 1_000_000)
        .await
        .unwrap();
    assert!(
        !crl_bytes_before.is_empty(),
        "empty CRL DER before revocation"
    );

    // Revoke the certificate via DB (no ACME auth needed for the test).
    akamu::db::certs::revoke(&state.db, &cert_id, Some(1), 1_700_000_000, None)
        .await
        .unwrap();
    // Clear the CRL cache so the next request rebuilds with the new entry.
    state.invalidate_crl_cache(state.default_ca_id.as_str());

    // Fetch CRL again — the revoked serial must appear.
    let req = Request::builder()
        .method(Method::GET)
        .uri("/ca/crl")
        .body(Body::empty())
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "GET /ca/crl after revoke failed"
    );
    let crl_bytes_after = axum::body::to_bytes(resp.into_body(), 1_000_000)
        .await
        .unwrap();

    // The CRL DER should be larger after adding a revoked entry.
    assert!(
        crl_bytes_after.len() > crl_bytes_before.len(),
        "CRL did not grow after adding a revoked entry"
    );

    // Decode the serial hex and verify the bytes appear somewhere in the CRL DER.
    // (A full ASN.1 parse would be ideal but byte-contains is sufficient for integration testing.)
    let serial_bytes: Vec<u8> = (0..serial_hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&serial_hex[i..i + 2], 16).unwrap())
        .collect();
    assert!(
        crl_bytes_after
            .windows(serial_bytes.len())
            .any(|w| w == serial_bytes),
        "revoked serial not found in CRL DER"
    );
}

/// Build a minimal DER-encoded OCSPRequest for one serial number.
///
/// Uses SHA-1 as the hash algorithm with zero-filled issuerNameHash and
/// issuerKeyHash — sufficient for testing the server's decode/lookup/sign loop.
fn build_ocsp_request_der(ca_cert_der: &[u8], serial_bytes: &[u8]) -> Vec<u8> {
    use synta_certificate::{default_key_id_hasher, Certificate, KeyIdHasher as _};

    // SHA-1 AlgorithmIdentifier DER: SEQUENCE { OID 1.3.14.3.2.26, NULL }
    let sha1_alg: &[u8] = &[
        0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00,
    ];
    // SHA-1 OID component array for the hasher.
    const SHA1_OID: &[u32] = &[1, 3, 14, 3, 2, 26];

    // Compute the real issuer hashes from the CA certificate.
    let cert = Certificate::from_der(ca_cert_der).expect("test CA cert must be valid DER");
    let subject_der = cert.tbs_certificate.subject.0;
    let raw_key_bytes = cert
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .as_bytes();
    // issuerKeyHash input = BIT STRING value: 0x00 (unused bits) || key bytes
    let mut key_hash_input = vec![0u8];
    key_hash_input.extend_from_slice(raw_key_bytes);

    let hasher = default_key_id_hasher();
    let name_hash_bytes = hasher
        .hash(SHA1_OID, subject_der)
        .expect("SHA-1 issuerNameHash must succeed");
    let key_hash_bytes = hasher
        .hash(SHA1_OID, &key_hash_input)
        .expect("SHA-1 issuerKeyHash must succeed");

    // Encode as DER OCTET STRING (tag 0x04, length, value).
    let mut name_hash = vec![0x04_u8, name_hash_bytes.len() as u8];
    name_hash.extend_from_slice(&name_hash_bytes);
    let mut key_hash = vec![0x04_u8, key_hash_bytes.len() as u8];
    key_hash.extend_from_slice(&key_hash_bytes);

    // serialNumber: DER INTEGER (prepend 0x00 if high bit set)
    let needs_pad = serial_bytes
        .first()
        .map(|&b| b & 0x80 != 0)
        .unwrap_or(false);
    let int_val_len = serial_bytes.len() + usize::from(needs_pad);
    let mut serial_int = vec![0x02_u8, int_val_len as u8];
    if needs_pad {
        serial_int.push(0x00);
    }
    serial_int.extend_from_slice(serial_bytes);

    // CertID SEQUENCE
    let cert_id_payload_len = sha1_alg.len() + name_hash.len() + key_hash.len() + serial_int.len();
    let mut cert_id = vec![0x30_u8, cert_id_payload_len as u8];
    cert_id.extend_from_slice(sha1_alg);
    cert_id.extend_from_slice(&name_hash);
    cert_id.extend_from_slice(&key_hash);
    cert_id.extend_from_slice(&serial_int);

    // Request SEQUENCE
    let mut request = vec![0x30_u8, cert_id.len() as u8];
    request.extend_from_slice(&cert_id);

    // requestList SEQUENCE OF
    let mut req_list = vec![0x30_u8, request.len() as u8];
    req_list.extend_from_slice(&request);

    // TBSRequest SEQUENCE
    let mut tbs = vec![0x30_u8, req_list.len() as u8];
    tbs.extend_from_slice(&req_list);

    // OCSPRequest SEQUENCE (no optional signature)
    let mut ocsp_req = vec![0x30_u8, tbs.len() as u8];
    ocsp_req.extend_from_slice(&tbs);
    ocsp_req
}

#[tokio::test]
async fn test_ocsp_endpoint_post_and_get() {
    let base_url = "https://acme.test";
    let (state, _tmp) = build_test_state(base_url).await;
    let router = routes::build_router(Arc::clone(&state), None, false);
    let db = state.db.clone();

    // Issue a certificate so there is a valid serial in the DB.
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

    let jws = key.jws_with_kid(
        &account_url,
        &nonce,
        &format!("{base_url}/acme/new-order"),
        Some(json!({"identifiers": [{"type": "dns", "value": "ocsp-test.example"}]})),
    );
    let (_, _, order_headers) = post_acme(&router, "/acme/new-order", jws).await;
    let nonce = nonce_header(&order_headers);

    let order_id: String =
        sqlx::query_as::<_, (String,)>("SELECT id FROM orders ORDER BY created DESC LIMIT 1")
            .fetch_one(&db)
            .await
            .unwrap()
            .0;
    mark_order_ready(&db, &order_id).await;

    let csr_der = make_csr_der("ocsp-test.example");
    let csr_b64 = URL_SAFE_NO_PAD.encode(&csr_der);
    let jws = key.jws_with_kid(
        &account_url,
        &nonce,
        &format!("{base_url}/acme/order/{order_id}/finalize"),
        Some(json!({"csr": csr_b64})),
    );
    let (status, _, _) = post_acme(&router, &format!("/acme/order/{order_id}/finalize"), jws).await;
    assert_eq!(status, StatusCode::OK, "finalize failed");

    // Retrieve the issued cert's serial from the DB.
    let serial_hex: String = sqlx::query_as::<_, (String,)>(
        "SELECT serial_number FROM certificates ORDER BY created DESC LIMIT 1",
    )
    .fetch_one(&db)
    .await
    .unwrap()
    .0;
    let serial_bytes: Vec<u8> = (0..serial_hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&serial_hex[i..i + 2], 16).unwrap())
        .collect();

    let ocsp_req_der = build_ocsp_request_der(&state.default_ca().cert_der, &serial_bytes);

    // ── POST /ca/ocsp ─────────────────────────────────────────────────────────
    let req = Request::builder()
        .method(Method::POST)
        .uri("/ca/ocsp")
        .header("Content-Type", "application/ocsp-request")
        .body(Body::from(ocsp_req_der.clone()))
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "POST /ca/ocsp failed");
    assert_eq!(
        resp.headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok()),
        Some("application/ocsp-response"),
        "wrong Content-Type for OCSP response"
    );
    let post_body = axum::body::to_bytes(resp.into_body(), 1_000_000)
        .await
        .unwrap();
    assert!(!post_body.is_empty(), "OCSP POST response body is empty");
    // A well-formed DER OCSPResponse starts with SEQUENCE tag 0x30.
    assert_eq!(
        post_body[0], 0x30,
        "OCSP POST response is not a DER SEQUENCE"
    );

    // ── GET /ca/ocsp/{base64url(request)} ────────────────────────────────────
    let encoded = URL_SAFE_NO_PAD.encode(&ocsp_req_der);
    let req = Request::builder()
        .method(Method::GET)
        .uri(format!("/ca/ocsp/{encoded}"))
        .body(Body::empty())
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "GET /ca/ocsp failed");
    assert_eq!(
        resp.headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok()),
        Some("application/ocsp-response"),
        "wrong Content-Type for OCSP GET response"
    );
    let get_body = axum::body::to_bytes(resp.into_body(), 1_000_000)
        .await
        .unwrap();
    assert!(!get_body.is_empty(), "OCSP GET response body is empty");
    assert_eq!(get_body[0], 0x30, "OCSP GET response is not a DER SEQUENCE");

    // Both endpoints must produce the same structure (independent of signing
    // time, so just check they're both valid DER starting with SEQUENCE).
    assert!(get_body.len() > 10, "OCSP GET response too short");
}

// ── RFC 8823 S/MIME end-to-end flow ──────────────────────────────────────────

/// Helper: decode the first PEM certificate block to DER.
/// Full RFC 8823 S/MIME issuance: email identifier → email-reply-00 challenge →
/// webhook verification → finalize with rfc822Name CSR → certificate.
///
/// The test drives every protocol layer through the axum router against an
/// in-memory SQLite DB.  A stub send_script captures the ACME_MESSAGE_ID and
/// ACME_TOKEN_PART2 environment variables to temp files so the test can
/// reconstruct the response digest without an actual mail transfer agent.
#[tokio::test]
async fn test_smime_email_reply_00_full_flow() {
    use akamu::config::EmailChallengeConfig;
    use synta_certificate::crypto::{DataHasher, HmacProvider as _};
    use synta_certificate::{default_data_hasher, default_hmac_provider};

    let base_url = "https://acme.test";
    let email_addr = "user@example.com";
    let hmac_secret = "a-test-secret-that-is-at-least-32-bytes!!";

    // ── Stub send_script: write env vars to temp files ────────────────────────
    let tmp = tempfile::TempDir::new().unwrap();
    let script_path = tmp.path().join("send-email.sh");
    let mid_file = tmp.path().join("message_id.txt");
    let tp2_file = tmp.path().join("token_part2.txt");
    std::fs::write(
        &script_path,
        format!(
            "#!/bin/sh\nprintf '%s' \"$ACME_MESSAGE_ID\" > {mid}\nprintf '%s' \"$ACME_TOKEN_PART2\" > {tp2}\n",
            mid = mid_file.display(),
            tp2 = tp2_file.display(),
        ),
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&script_path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    // ── Build AppState with email_challenge enabled ────────────────────────────
    let ca_dir = tmp.path().join("ca");
    std::fs::create_dir_all(&ca_dir).unwrap();
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
            key_file: Some(ca_dir.join("ca.key").to_string_lossy().into_owned()),
            cert_file: ca_dir.join("ca.crt").to_string_lossy().into_owned(),
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
        server: ServerConfig {
            // Non-zero expiry: ServerConfig::default() uses 0, which sets
            // authz_expiry = now + 0 = now.  If the webhook arrives even one
            // second later, verify_response sees now > expires and invalidates
            // the challenge — a spurious intermittent test failure.
            authz_expiry_secs: 3600,
            order_expiry_secs: 3600,
            ..ServerConfig::default()
        },
        tls: Default::default(),
        profiles: Default::default(),
        linter: Default::default(),
        admin: None,
        email_challenge: Some(EmailChallengeConfig {
            enabled: true,
            from_address: "acme@acme.test".into(),
            send_script: script_path.to_string_lossy().into_owned(),
            send_script_timeout_secs: 10,
            webhook_hmac_secret: hmac_secret.into(),
        }),
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
    // Build a profile registry with the S/MIME profile so the finalize route
    // picks up the emailProtection EKU instead of the CA default server_auth.
    let smime_profiles_cfg: akamu::config::ProfilesConfig = toml::from_str(
        r#"
        [providers.local]
        type = "builtin"

        [providers.local.profiles.smime]
        description = "S/MIME end-user certificate (RFC 8823)"
        validity_days = 365
        key_usage = ["digital_signature", "key_encipherment"]
        eku = ["email_protection"]
        allowed_identifiers = ['^email:.*$']
        "#,
    )
    .unwrap();
    let smime_profile_registry = akamu::profiles::ProfileRegistry::new(&smime_profiles_cfg, &ca)
        .await
        .unwrap();
    let cas = {
        let mut m = indexmap::IndexMap::new();
        m.insert("default".to_string(), ca.clone());
        Arc::new(m)
    };
    let state = AppStateBuilder::new(
        Arc::clone(&config),
        db_conn.clone(),
        db::DbKind::Sqlite,
        cas,
        Arc::new("default".to_string()),
    )
    .profiles(smime_profile_registry)
    .node_id(Arc::new("test".to_string()))
    .build();
    let db = state.db.clone();
    let router = routes::build_router(Arc::clone(&state), None, false);

    // ── Step 1: create account ─────────────────────────────────────────────────
    let acme_key = TestKey::generate();
    let nonce = head_nonce(&router).await;
    let jws = acme_key.jws_with_jwk(
        &nonce,
        &format!("{base_url}/acme/new-account"),
        Some(json!({"termsOfServiceAgreed": true})),
    );
    let (status, _, acct_headers) = post_acme(&router, "/acme/new-account", jws).await;
    assert_eq!(status, StatusCode::CREATED);
    let account_url = location_header(&acct_headers);
    let nonce = nonce_header(&acct_headers);

    // ── Step 2: new-order with email identifier and smime profile ────────────
    let jws = acme_key.jws_with_kid(
        &account_url,
        &nonce,
        &format!("{base_url}/acme/new-order"),
        Some(json!({
            "identifiers": [{"type": "email", "value": email_addr}],
            "profile": "smime"
        })),
    );
    let (status, order_body, order_headers) = post_acme(&router, "/acme/new-order", jws).await;
    assert_eq!(status, StatusCode::CREATED, "new-order: {order_body}");
    let order_url = location_header(&order_headers);
    let order_id = order_url.split('/').next_back().unwrap().to_string();
    let nonce = nonce_header(&order_headers);

    // ── Step 3: fetch authorization — confirm email-reply-00 + `from` field ───
    let authz_url = order_body["authorizations"][0]
        .as_str()
        .unwrap()
        .to_string();
    let authz_path = authz_url.trim_start_matches(base_url).to_string();
    let authz_id = authz_url.split('/').next_back().unwrap().to_string();
    let jws = acme_key.jws_with_kid(&account_url, &nonce, &authz_url, None);
    let (status, authz_body, authz_headers) = post_acme(&router, &authz_path, jws).await;
    assert_eq!(status, StatusCode::OK, "authz fetch: {authz_body}");
    let nonce = nonce_header(&authz_headers);

    let challenge = authz_body["challenges"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["type"].as_str() == Some("email-reply-00"))
        .expect("authorization must contain email-reply-00 challenge");
    assert_eq!(challenge["status"].as_str().unwrap(), "pending");
    assert_eq!(
        challenge["from"].as_str().unwrap(),
        "acme@acme.test",
        "email-reply-00 challenge must expose `from` field"
    );
    let token_part2 = challenge["token"].as_str().unwrap().to_string();
    let chall_url = challenge["url"].as_str().unwrap().to_string();
    let chall_path = chall_url.trim_start_matches(base_url).to_string();

    // ── Step 4: POST {} to challenge URL — triggers send_script ───────────────
    let jws = acme_key.jws_with_kid(&account_url, &nonce, &chall_url, Some(json!({})));
    let (status, chall_body, _) = post_acme(&router, &chall_path, jws).await;
    assert_eq!(status, StatusCode::OK, "challenge respond: {chall_body}");
    assert_eq!(
        chall_body["status"].as_str().unwrap(),
        "processing",
        "challenge must be processing after client POST"
    );

    // ── Step 5: poll until background task writes email fields to DB ─────────
    // Fixed sleeps are flaky under load; poll every 50 ms up to 5 s instead.
    let (token_part1, message_id): (String, String) = {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            let row: (Option<String>, Option<String>, String) = sqlx::query_as(
                "SELECT email_token_part1, email_message_id, status \
                 FROM challenges WHERE authz_id = ? AND type = 'email-reply-00'",
            )
            .bind(&authz_id)
            .fetch_one(&db)
            .await
            .expect("challenge row must exist");
            match row {
                (Some(tp1), Some(mid), _) => break (tp1, mid),
                (_, _, ref status) if status == "invalid" => {
                    panic!("background task marked challenge invalid before webhook could be sent");
                }
                _ => {
                    assert!(
                        std::time::Instant::now() < deadline,
                        "background task did not write email token within 5 seconds"
                    );
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                }
            }
        }
    };

    // Cross-check: script received the same values as DB.
    // The script runs AFTER set_email_token, so poll briefly for the files.
    let deadline_script = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        if mid_file.exists() && tp2_file.exists() {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline_script,
            "send_script did not create output files within 5 seconds"
        );
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    let script_mid = std::fs::read_to_string(&mid_file).unwrap();
    assert_eq!(
        script_mid.trim(),
        message_id,
        "ACME_MESSAGE_ID must match DB email_message_id"
    );
    let script_tp2 = std::fs::read_to_string(&tp2_file).unwrap();
    assert_eq!(
        script_tp2.trim(),
        token_part2,
        "ACME_TOKEN_PART2 must match challenge token"
    );
    // Confirm the challenge is still 'processing' (send_script exited 0).
    // Under load the background task's child.wait() may not have been processed
    // yet when the output files first appear; yield explicitly so the task can
    // run its final transition (on_invalid_with_order if the script failed, or
    // no-op on success) before we read the status.
    for _ in 0..5 {
        tokio::task::yield_now().await;
    }
    let chall_status_pre: String = sqlx::query_scalar(
        "SELECT status FROM challenges WHERE authz_id = ? AND type = 'email-reply-00'",
    )
    .bind(&authz_id)
    .fetch_one(&db)
    .await
    .unwrap();
    assert_eq!(
        chall_status_pre, "processing",
        "challenge must be processing before webhook; send_script may have failed"
    );

    // ── Step 6: compute response digest ───────────────────────────────────────
    // RFC 8823 §3: full_token = token_part1 || token_part2
    //              key_auth   = full_token || "." || jwk_thumbprint
    //              response   = base64url(SHA-256(key_auth))
    let thumbprint: String = sqlx::query_as::<_, (String,)>(
        "SELECT a.jwk_thumbprint FROM accounts a \
         JOIN authorizations az ON a.id = az.account_id WHERE az.id = ?",
    )
    .bind(&authz_id)
    .fetch_one(&db)
    .await
    .unwrap()
    .0;

    let key_auth = format!("{token_part1}{token_part2}.{thumbprint}");
    let digest_bytes = default_data_hasher()
        .hash_data("sha256", key_auth.as_bytes())
        .unwrap();
    let digest_b64 = URL_SAFE_NO_PAD.encode(&digest_bytes);
    let acme_response_body =
        format!("-----BEGIN ACME RESPONSE-----\n{digest_b64}\n-----END ACME RESPONSE-----\n");

    // ── Step 7: POST /acme/email-webhook with correct HMAC ────────────────────
    let payload_bytes = serde_json::to_vec(&json!({
        "from":        email_addr,
        "in_reply_to": message_id,
        "dkim_domain": "example.com",
        "dkim_status": "pass",
        "body":        acme_response_body,
    }))
    .unwrap();

    let mac = default_hmac_provider()
        .hmac_compute("sha256", hmac_secret.as_bytes(), &payload_bytes)
        .unwrap();
    let sig_header = format!(
        "sha256={}",
        mac.iter().fold(String::new(), |mut s, b| {
            use std::fmt::Write;
            let _ = write!(s, "{b:02x}");
            s
        })
    );

    let req = Request::builder()
        .method(Method::POST)
        .uri("/acme/email-webhook")
        .header("content-type", "application/json")
        .header("x-akamu-signature", &sig_header)
        .body(Body::from(payload_bytes))
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "webhook must return 200");

    // ── Step 8: confirm challenge, authz, and order state ─────────────────────
    // on_valid runs synchronously within verify_response (before webhook returns
    // 200), so no sleep is needed here.
    let chall_status: String = sqlx::query_as::<_, (String,)>(
        "SELECT status FROM challenges WHERE authz_id = ? AND type = 'email-reply-00'",
    )
    .bind(&authz_id)
    .fetch_one(&db)
    .await
    .unwrap()
    .0;
    assert_eq!(
        chall_status, "valid",
        "challenge must be valid after webhook"
    );

    let authz_status: String =
        sqlx::query_as::<_, (String,)>("SELECT status FROM authorizations WHERE id = ?")
            .bind(&authz_id)
            .fetch_one(&db)
            .await
            .unwrap()
            .0;
    assert_eq!(
        authz_status, "valid",
        "authorization must be valid after challenge"
    );

    let order_status: String =
        sqlx::query_as::<_, (String,)>("SELECT status FROM orders WHERE id = ?")
            .bind(&order_id)
            .fetch_one(&db)
            .await
            .unwrap()
            .0;
    assert_eq!(
        order_status, "ready",
        "order must be ready after authorization becomes valid"
    );

    // ── Step 9: finalize with rfc822Name CSR ──────────────────────────────────
    let ee_key = BackendPrivateKey::generate_ec("P-256").unwrap();
    let spki_der = ee_key.public_key().unwrap().spki_der().to_vec();
    let name_der = NameBuilder::new().common_name(email_addr).build().unwrap();
    // rfc822Name DER: SEQUENCE { [1] IMPLICIT IA5String "user@example.com" }
    // Tag 0x81 = context class, primitive, tag 1 (rfc822Name).
    let email_bytes = email_addr.as_bytes();
    let mut san_der = vec![
        0x30u8,
        (email_bytes.len() + 2) as u8,
        0x81,
        email_bytes.len() as u8,
    ];
    san_der.extend_from_slice(email_bytes);
    let signer = ee_key.as_signer("sha256");
    let csr_der = CsrBuilder::new()
        .subject_name(&name_der)
        .public_key_der(&spki_der)
        .add_extension_oid(synta_certificate::oids::SUBJECT_ALT_NAME, false, &san_der)
        .sign(&signer)
        .unwrap();
    let csr_b64 = URL_SAFE_NO_PAD.encode(&csr_der);

    let nonce = head_nonce(&router).await;
    let finalize_url = format!("{base_url}/acme/order/{order_id}/finalize");
    let jws = acme_key.jws_with_kid(
        &account_url,
        &nonce,
        &finalize_url,
        Some(json!({"csr": csr_b64})),
    );
    let (status, final_body, _) =
        post_acme(&router, &format!("/acme/order/{order_id}/finalize"), jws).await;
    assert_eq!(status, StatusCode::OK, "finalize: {final_body}");
    assert_eq!(final_body["status"].as_str().unwrap(), "valid");

    // ── Step 10: download certificate and verify RFC 8823 fields ──────────────
    let cert_path = final_body["certificate"]
        .as_str()
        .unwrap()
        .trim_start_matches(base_url)
        .to_string();
    let req = Request::builder()
        .method(Method::GET)
        .uri(&cert_path)
        .body(Body::empty())
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let cert_pem_bytes = axum::body::to_bytes(resp.into_body(), 1_000_000)
        .await
        .unwrap();
    let pem = std::str::from_utf8(&cert_pem_bytes).unwrap();
    assert!(
        pem.contains("-----BEGIN CERTIFICATE-----"),
        "certificate endpoint must return PEM"
    );

    let leaf_der = synta_certificate::pem_blocks(pem.as_bytes())
        .into_iter()
        .find(|(label, _)| label == "CERTIFICATE")
        .map(|(_, der)| der)
        .expect("PEM response must contain at least one CERTIFICATE block");
    let cert = synta_certificate::Certificate::from_der(&leaf_der)
        .expect("issued certificate must parse as valid DER");

    // Verify rfc822Name SAN matches the order identifier.
    let sans = cert.subject_alt_names();
    assert!(
        sans.iter().any(
            |(tag, val)| *tag == synta_certificate::general_name::RFC822_NAME
                && val == email_addr.as_bytes()
        ),
        "issued cert must contain rfc822Name SAN '{email_addr}'; got {sans:?}"
    );

    // Verify emailProtection EKU (OID 1.3.6.1.5.5.7.3.4 = 06 08 2b 06 01 05 05 07 03 04).
    let ext_raw = cert
        .tbs_certificate
        .extensions
        .as_ref()
        .map(|e| e.as_bytes())
        .unwrap_or(b"");
    let eku_value = synta_certificate::find_extension_value(
        ext_raw,
        synta_certificate::oids::EXTENDED_KEY_USAGE,
    )
    .expect("issued cert must have an EKU extension");
    let email_prot_oid: &[u8] = &[0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x04];
    assert!(
        eku_value
            .windows(email_prot_oid.len())
            .any(|w| w == email_prot_oid),
        "issued cert must have emailProtection EKU"
    );
}
