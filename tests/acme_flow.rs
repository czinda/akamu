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

use acme_server::config::{CaConfig, Config, DatabaseConfig, MtcConfig, ServerConfig};
use acme_server::state::{AppState, CaState, MtcState};
use acme_server::{ca, db, routes};

// ── ACME test client ──────────────────────────────────────────────────────────

/// Wraps an EC P-256 key pair and provides helpers for building JWS requests.
struct TestKey {
    key: BackendPrivateKey,
    x_b64: String,
    y_b64: String,
    spki_der: Vec<u8>,
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
        let spki_der = pub_key.spki_der().to_vec();

        TestKey { key, x_b64, y_b64, spki_der }
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

fn strip_tlv<'a>(buf: &'a [u8], tag: u8) -> Option<&'a [u8]> {
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
        database: DatabaseConfig { path: ":memory:".into() },
        ca: CaConfig {
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
        },
        mtc: MtcConfig { log_path: "/dev/null".into(), enabled: false },
        server: ServerConfig::default(),
    });

    let (ca_key, ca_cert_der) = ca::init::load_or_generate(&config.ca).unwrap();
    let db_conn = Arc::new(db::open(":memory:").await.unwrap());

    let state = Arc::new(AppState {
        config: Arc::clone(&config),
        db: Arc::clone(&db_conn),
        ca: Arc::new(CaState {
            key: ca_key,
            cert_der: ca_cert_der,
            hash_alg: "sha256".into(),
            validity_days: 90,
            crl_url: None,
            ocsp_url: None,
        }),
        mtc: Arc::new(MtcState {
            log: None,
            algorithm: synta_mtc::crypto::HashAlgorithm::Sha256,
        }),
    });

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
    let body = axum::body::to_bytes(resp.into_body(), 1_000_000).await.unwrap();
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
async fn mark_order_ready(db: &tokio_rusqlite::Connection, order_id: &str) {
    let order_id = order_id.to_string();
    db.call(move |conn| {
        // Collect authorization IDs for this order.
        let authz_ids: Vec<String> = {
            let mut stmt =
                conn.prepare("SELECT id FROM authorizations WHERE order_id = ?1")?;
            let ids: Vec<String> = stmt
                .query_map(rusqlite::params![order_id], |r| r.get(0))?
                .collect::<Result<_, _>>()?;
            ids
        };

        for authz_id in &authz_ids {
            // Mark all challenges for this authz as valid.
            conn.execute(
                "UPDATE challenges SET status='valid', validated=1700000000 \
                 WHERE authz_id = ?1",
                rusqlite::params![authz_id],
            )?;
            // Mark the authz itself as valid.
            conn.execute(
                "UPDATE authorizations SET status='valid', updated=1700000000 \
                 WHERE id = ?1",
                rusqlite::params![authz_id],
            )?;
        }

        // Advance order to ready.
        conn.execute(
            "UPDATE orders SET status='ready', updated=1700000000 WHERE id = ?1",
            rusqlite::params![order_id],
        )?;
        Ok(())
    })
    .await
    .unwrap();
}

// ── CSR builder ───────────────────────────────────────────────────────────────

fn make_csr_der(domain: &str) -> Vec<u8> {
    let backend_key = BackendPrivateKey::generate_ec("P-256").unwrap();
    let spki_der = backend_key.public_key().unwrap().spki_der().to_vec();

    let name_der = NameBuilder::new().common_name(domain).build().unwrap();
    let san_der = SubjectAlternativeNameBuilder::new().dns_name(domain).build().unwrap();
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
    let db = Arc::clone(&state.db);
    let router = routes::build_router(Arc::clone(&state));

    // ── Step 1: GET /acme/directory ───────────────────────────────────────────
    let (status, dir, _) = get(&router, "/acme/directory").await;
    assert_eq!(status, StatusCode::OK);
    assert!(dir["newAccount"].as_str().is_some(), "directory missing newAccount");
    assert!(dir["newNonce"].as_str().is_some(), "directory missing newNonce");
    assert!(dir["newOrder"].as_str().is_some(), "directory missing newOrder");

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
    let (status, acct_body, acct_headers) =
        post_acme(&router, "/acme/new-account", jws).await;
    assert_eq!(status, StatusCode::CREATED, "new-account failed: {acct_body}");
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
    let (status, order_body, order_headers) =
        post_acme(&router, "/acme/new-order", jws).await;
    assert_eq!(status, StatusCode::CREATED, "new-order failed: {order_body}");
    assert_eq!(order_body["status"].as_str().unwrap(), "pending");

    let order_url = location_header(&order_headers);
    let order_id = order_url.split('/').last().unwrap().to_string();
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

    let cert_bytes = axum::body::to_bytes(resp.into_body(), 1_000_000).await.unwrap();
    let pem = std::str::from_utf8(&cert_bytes).expect("certificate must be UTF-8 PEM");
    assert!(
        pem.contains("-----BEGIN CERTIFICATE-----"),
        "certificate endpoint should return PEM"
    );
    let cert_count = pem.matches("-----BEGIN CERTIFICATE-----").count();
    assert!(cert_count >= 2, "PEM bundle should contain leaf + CA (got {cert_count})");
}
