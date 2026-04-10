//! Integration test: full ACME flow using the dns-persist-01 challenge type.
//!
//! Uses the same hand-rolled JWS infrastructure as `acme_flow.rs` (tower oneshot
//! requests against an in-memory router) combined with a looping UDP DNS mock
//! server that answers `_validation-persist.<domain>` TXT queries.
//!
//! Flow:
//!   1. Start a looping mock DNS server on a random port.
//!   2. Build an Akāmu state with `dns_persist_issuer_domain` and
//!      `dns_resolver_addr` pointing at the mock.
//!   3. Create ACME account — extract account URL.
//!   4. Register the TXT record value in the mock DNS (content depends on
//!      the account URL, so we register it after account creation).
//!   5. Create order for a DNS identifier.
//!   6. Fetch the authorization — verify dns-persist-01 challenge is present
//!      with `issuer-domain-names` instead of `token`.
//!   7. POST to the challenge endpoint — triggers background validation.
//!   8. Poll the order until it reaches `ready`.
//!   9. Finalize with a synta-generated CSR.
//!  10. Download the certificate and verify the leaf SAN.
//!  11. (bonus) Repeat for a wildcard order to verify `policy=wildcard` path.
//!
//! Run with:
//!   cargo test --test dns_persist_flow -- --nocapture

use std::sync::Arc;

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde_json::{json, Value};
use synta_certificate::{
    BackendPrivateKey, CertificateSigner as _, CsrBuilder, NameBuilder, PrivateKey as _,
    SubjectAlternativeNameBuilder,
};
use tokio::{net::UdpSocket, sync::RwLock};
use tower::ServiceExt;

use acme_server::config::{CaConfig, Config, DatabaseConfig, MtcConfig, ServerConfig};
use acme_server::state::{AppState, CaState, MtcState};
use acme_server::{ca, db, routes};

// ── Tracing ───────────────────────────────────────────────────────────────────

fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_test_writer()
        // compact()         — renders span fields inline on the same line as the event,
        //                     e.g.: DEBUG request{method=POST uri=/acme/new-order} finished … status=201
        // with_target(false) — omits the "tower_http::trace::on_response:" module-path prefix
        // Together these collapse each HTTP exchange to a single readable line.
        .compact()
        .with_target(false)
        // tower_http=debug  — one "finished processing request" line per HTTP exchange
        //                     (on_request and on_eos are suppressed in build_router)
        // acme_server=debug — server-side validation logic, CA signing, DB updates
        .with_env_filter("tower_http=debug,acme_server=debug,info")
        .try_init();
}

// ── Mock DNS server ───────────────────────────────────────────────────────────

/// A looping UDP DNS server that responds to every TXT query with whatever
/// value is currently held in the shared store.  The store starts as `None`
/// (queries are silently dropped), allowing the test to register the record
/// only after it knows the account URI.
struct MockDns {
    pub port: u16,
    pub txt: Arc<RwLock<Option<String>>>,
}

impl MockDns {
    async fn start() -> Self {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = socket.local_addr().unwrap().port();
        let txt: Arc<RwLock<Option<String>>> = Arc::new(RwLock::new(None));
        let txt_clone = Arc::clone(&txt);

        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            loop {
                let Ok((n, addr)) = socket.recv_from(&mut buf).await else {
                    break;
                };
                let query = buf[..n].to_vec();
                if let Some(ref value) = *txt_clone.read().await {
                    let resp = build_txt_response(&query, value);
                    let _ = socket.send_to(&resp, addr).await;
                }
                // If no record is set yet, ignore the query.
            }
        });

        MockDns { port, txt }
    }

    async fn set_record(&self, txt: &str) {
        *self.txt.write().await = Some(txt.to_string());
    }
}

/// Build a minimal DNS TXT response for a query packet.
///
/// Echoes the question section back and appends one TXT answer record.
fn build_txt_response(query: &[u8], txt_value: &str) -> Vec<u8> {
    let mut pos = 12usize;
    while pos < query.len() {
        let label_len = query[pos] as usize;
        pos += 1;
        if label_len == 0 {
            break;
        }
        pos += label_len;
    }
    pos += 4; // skip QTYPE + QCLASS
    let question_end = pos;

    let txt_bytes = txt_value.as_bytes();
    let rdlength = (txt_bytes.len() + 1) as u16;

    let mut resp = Vec::with_capacity(question_end + 16 + txt_bytes.len());
    resp.extend_from_slice(&query[..2]);          // Transaction ID (echo)
    resp.extend_from_slice(&[0x81, 0x80]);        // QR=1 RD=1 RA=1
    resp.extend_from_slice(&[0x00, 0x01]);        // QDCOUNT=1
    resp.extend_from_slice(&[0x00, 0x01]);        // ANCOUNT=1
    resp.extend_from_slice(&[0x00, 0x00]);        // NSCOUNT=0
    resp.extend_from_slice(&[0x00, 0x00]);        // ARCOUNT=0
    resp.extend_from_slice(&query[12..question_end]); // question section
    resp.extend_from_slice(&[0xC0, 0x0C]);        // name pointer → offset 12
    resp.extend_from_slice(&[0x00, 0x10]);        // TYPE=TXT
    resp.extend_from_slice(&[0x00, 0x01]);        // CLASS=IN
    resp.extend_from_slice(&[0x00, 0x00, 0x00, 0x3C]); // TTL=60
    resp.extend_from_slice(&rdlength.to_be_bytes());
    resp.push(txt_bytes.len() as u8);             // TXT length prefix
    resp.extend_from_slice(txt_bytes);
    resp
}

// ── Akāmu state builder ───────────────────────────────────────────────────────

async fn build_state(
    base_url: &str,
    issuer_domain: &str,
    dns_resolver_addr: &str,
) -> (Arc<AppState>, tempfile::TempDir) {
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
            common_name: "Persist Test CA".into(),
            organization: "Test".into(),
            ca_validity_years: 10,
        },
        mtc: MtcConfig { log_path: "/dev/null".into(), enabled: false },
        server: ServerConfig {
            dns_persist_issuer_domain: Some(issuer_domain.into()),
            dns_resolver_addr: Some(dns_resolver_addr.into()),
            ..ServerConfig::default()
        },
        tls: Default::default(),
    });

    let (ca_key, ca_cert_der) = ca::init::load_or_generate(&config.ca).unwrap();
    let db_conn = Arc::new(db::open(":memory:").await.unwrap());
    let state = Arc::new(AppState {
        config: Arc::clone(&config),
        db: db_conn,
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
        tls: None,
    });
    (state, dir)
}

// ── JWS / request helpers (mirrored from acme_flow.rs) ───────────────────────

struct TestKey {
    key: BackendPrivateKey,
    x_b64: String,
    y_b64: String,
}

impl TestKey {
    fn generate() -> Self {
        let key = BackendPrivateKey::generate_ec("P-256").unwrap();
        let pub_key = key.public_key().unwrap();
        let (x, y) = pub_key.ec_affine_coordinates().unwrap().unwrap();
        let x_b64 = encode_coord(&x, 32);
        let y_b64 = encode_coord(&y, 32);
        TestKey { key, x_b64, y_b64 }
    }

    fn jwk(&self) -> Value {
        json!({ "kty": "EC", "crv": "P-256", "x": self.x_b64, "y": self.y_b64 })
    }

    fn jws_jwk(&self, nonce: &str, url: &str, payload: Option<Value>) -> Value {
        self.build_jws(
            json!({ "alg": "ES256", "nonce": nonce, "url": url, "jwk": self.jwk() }),
            payload,
        )
    }

    fn jws_kid(&self, kid: &str, nonce: &str, url: &str, payload: Option<Value>) -> Value {
        self.build_jws(
            json!({ "alg": "ES256", "nonce": nonce, "url": url, "kid": kid }),
            payload,
        )
    }

    fn build_jws(&self, header: Value, payload: Option<Value>) -> Value {
        let protected = URL_SAFE_NO_PAD.encode(header.to_string().as_bytes());
        let payload_b64 = match payload {
            Some(v) => URL_SAFE_NO_PAD.encode(v.to_string().as_bytes()),
            None => String::new(),
        };
        let input = format!("{protected}.{payload_b64}");
        let signer = self.key.as_signer("sha256");
        let der = signer.sign_tbs(input.as_bytes()).unwrap();
        let sig = URL_SAFE_NO_PAD.encode(&ecdsa_der_to_p1363(&der, 32).unwrap());
        json!({ "protected": protected, "payload": payload_b64, "signature": sig })
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
    let (r, rest) = strip_int(inner)?;
    let (s, _) = strip_int(rest)?;
    if r.len() > half || s.len() > half { return None; }
    let mut out = vec![0u8; half * 2];
    out[half - r.len()..half].copy_from_slice(r);
    out[half * 2 - s.len()..].copy_from_slice(s);
    Some(out)
}

fn strip_tlv<'a>(buf: &'a [u8], tag: u8) -> Option<&'a [u8]> {
    if *buf.first()? != tag { return None; }
    let (len, rest) = decode_len(&buf[1..])?;
    rest.get(..len)
}

fn strip_int(buf: &[u8]) -> Option<(&[u8], &[u8])> {
    if *buf.first()? != 0x02 { return None; }
    let (len, rest) = decode_len(&buf[1..])?;
    let val = rest.get(..len)?.strip_prefix(&[0x00u8]).unwrap_or(rest.get(..len)?);
    Some((val, &rest[len..]))
}

fn decode_len(buf: &[u8]) -> Option<(usize, &[u8])> {
    let first = *buf.first()?;
    if first < 0x80 { Some((first as usize, &buf[1..])) }
    else if first == 0x81 { Some((*buf.get(1)? as usize, &buf[2..])) }
    else if first == 0x82 {
        Some((((*buf.get(1)? as usize) << 8 | *buf.get(2)? as usize), &buf[3..]))
    } else { None }
}

// ── HTTP oneshot helpers ──────────────────────────────────────────────────────

async fn send(router: &axum::Router, req: Request<Body>) -> (StatusCode, Value, axum::http::HeaderMap) {
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let headers = resp.headers().clone();
    let body = axum::body::to_bytes(resp.into_body(), 1_000_000).await.unwrap();
    let json = serde_json::from_slice(&body).unwrap_or(Value::Null);
    (status, json, headers)
}

async fn head_nonce(router: &axum::Router) -> String {
    let req = Request::builder().method(Method::HEAD).uri("/acme/new-nonce")
        .body(Body::empty()).unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    resp.headers().get("replay-nonce").unwrap().to_str().unwrap().to_string()
}

async fn post_acme(router: &axum::Router, path: &str, jws: Value) -> (StatusCode, Value, axum::http::HeaderMap) {
    let req = Request::builder().method(Method::POST).uri(path)
        .header(header::CONTENT_TYPE, "application/jose+json")
        .body(Body::from(jws.to_string())).unwrap();
    send(router, req).await
}

fn nonce_hdr(h: &axum::http::HeaderMap) -> String {
    h.get("replay-nonce").unwrap().to_str().unwrap().to_string()
}

fn location_hdr(h: &axum::http::HeaderMap) -> String {
    h.get(header::LOCATION).unwrap().to_str().unwrap().to_string()
}

// ── CSR builder ───────────────────────────────────────────────────────────────

fn make_csr(domain: &str) -> Vec<u8> {
    let k = BackendPrivateKey::generate_ec("P-256").unwrap();
    let spki = k.public_key().unwrap().spki_der().to_vec();
    let name = NameBuilder::new().common_name(domain).build().unwrap();
    // Use the domain as-is (including any leading "*.") for the SAN dNSName.
    // Wildcard labels are valid in dNSName SANs per RFC 5280 §4.2.1.6, and the
    // CA's CSR validator expects the SAN to match the order identifier exactly.
    let san = SubjectAlternativeNameBuilder::new().dns_name(domain).build().unwrap();
    let signer = k.as_signer("sha256");
    CsrBuilder::new()
        .subject_name(&name)
        .public_key_der(&spki)
        .add_extension_oid(synta_certificate::oids::SUBJECT_ALT_NAME, false, &san)
        .sign(&signer)
        .unwrap()
}

// ── Poll helper ───────────────────────────────────────────────────────────────

/// Poll the order URL (POST-as-GET) until its status matches `target` or the
/// deadline is exceeded.  Returns the final order JSON.
async fn poll_order_status(
    router: &axum::Router,
    key: &TestKey,
    account_url: &str,
    order_url: &str,
    base_url: &str,
    target: &str,
) -> Value {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    let order_path = order_url.trim_start_matches(base_url);
    loop {
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let nonce = head_nonce(router).await;
        let jws = key.jws_kid(account_url, &nonce, order_url, None); // POST-as-GET
        let (_, body, _) = post_acme(router, order_path, jws).await;
        tracing::debug!("order status: {}", body["status"]);
        if body["status"].as_str() == Some(target) {
            return body;
        }
        if std::time::Instant::now() > deadline {
            panic!("timed out waiting for order status '{target}': {body}");
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

/// Full dns-persist-01 flow for a non-wildcard DNS identifier.
#[tokio::test]
async fn dns_persist_01_non_wildcard_flow() {
    init_tracing();

    let base_url = "https://acme.test";
    let issuer = "acme.test";
    let domain = "persist-test.example.com";

    // 1. Start mock DNS server (no record yet).
    let mock_dns = MockDns::start().await;
    tracing::info!("mock DNS listening on 127.0.0.1:{}", mock_dns.port);

    let dns_addr = format!("127.0.0.1:{}", mock_dns.port);
    let (state, _tmp) = build_state(base_url, issuer, &dns_addr).await;
    let router = routes::build_router(Arc::clone(&state));

    // 2. Create ACME account.
    let key = TestKey::generate();
    let nonce = head_nonce(&router).await;
    let jws = key.jws_jwk(&nonce, &format!("{base_url}/acme/new-account"),
        Some(json!({"termsOfServiceAgreed": true})));
    let (status, _, acct_hdrs) = post_acme(&router, "/acme/new-account", jws).await;
    assert_eq!(status, StatusCode::CREATED);
    let account_url = location_hdr(&acct_hdrs);
    let nonce = nonce_hdr(&acct_hdrs);
    tracing::info!("account URL: {account_url}");

    // 3. Register TXT record in mock DNS (now that we know the account URI).
    //    Format: "<issuer>; accounturi=<account_url>"
    let txt_record = format!("{issuer}; accounturi={account_url}");
    mock_dns.set_record(&txt_record).await;
    tracing::info!("TXT record registered: {txt_record}");

    // 4. Create order.
    let jws = key.jws_kid(&account_url, &nonce, &format!("{base_url}/acme/new-order"),
        Some(json!({"identifiers": [{"type": "dns", "value": domain}]})));
    let (status, order_body, order_hdrs) = post_acme(&router, "/acme/new-order", jws).await;
    assert_eq!(status, StatusCode::CREATED, "new-order: {order_body}");
    let order_url = location_hdr(&order_hdrs);
    let nonce = nonce_hdr(&order_hdrs);
    tracing::info!("order URL: {order_url}");

    // 5. Fetch authorization — verify dns-persist-01 challenge shape.
    let authz_url = order_body["authorizations"][0].as_str().unwrap().to_string();
    let authz_path = authz_url.trim_start_matches(base_url);
    let jws = key.jws_kid(&account_url, &nonce, &authz_url, None); // POST-as-GET
    let (status, authz_body, authz_hdrs) = post_acme(&router, authz_path, jws).await;
    assert_eq!(status, StatusCode::OK, "get-authz: {authz_body}");
    let nonce = nonce_hdr(&authz_hdrs);

    let challenges = authz_body["challenges"].as_array().unwrap();
    let dp01 = challenges.iter()
        .find(|c| c["type"] == "dns-persist-01")
        .expect("dns-persist-01 challenge must be present");
    tracing::info!("dns-persist-01 challenge: {dp01}");

    // The challenge must have issuer-domain-names, not token.
    assert_eq!(
        dp01["issuer-domain-names"][0].as_str().unwrap(), issuer,
        "issuer-domain-names must match configured issuer"
    );
    assert!(dp01.get("token").is_none() || dp01["token"].is_null(),
        "dns-persist-01 must not include a token field");

    let chall_url = dp01["url"].as_str().unwrap().to_string();
    let chall_path = chall_url.trim_start_matches(base_url).to_string();

    // 6. POST to challenge endpoint — triggers background DNS validation.
    let jws = key.jws_kid(&account_url, &nonce, &chall_url, Some(json!({})));
    let (status, chall_body, chall_hdrs) = post_acme(&router, &chall_path, jws).await;
    assert_eq!(status, StatusCode::OK, "respond-challenge: {chall_body}");
    assert!(
        chall_body["status"] == "processing" || chall_body["status"] == "valid",
        "challenge status after POST: {}", chall_body["status"]
    );
    tracing::info!("challenge response: {chall_body}");
    let _nonce = nonce_hdr(&chall_hdrs);

    // 7. Poll until order is ready.
    let order_body = poll_order_status(
        &router, &key, &account_url, &order_url, base_url, "ready",
    ).await;
    tracing::info!("order reached 'ready'");

    // Confirm the authorization is now valid.
    let authz_path = authz_url.trim_start_matches(base_url);
    let nonce = head_nonce(&router).await;
    let jws = key.jws_kid(&account_url, &nonce, &authz_url, None);
    let (_, authz_final, _) = post_acme(&router, authz_path, jws).await;
    assert_eq!(authz_final["status"].as_str().unwrap(), "valid",
        "authorization must be valid after challenge passes");

    // 8. Finalize.
    let csr = make_csr(domain);
    let csr_b64 = URL_SAFE_NO_PAD.encode(&csr);
    let finalize_url = order_body["finalize"].as_str().unwrap().to_string();
    let finalize_path = finalize_url.trim_start_matches(base_url).to_string();
    let nonce = head_nonce(&router).await;
    let jws = key.jws_kid(&account_url, &nonce, &finalize_url, Some(json!({"csr": csr_b64})));
    let (status, final_body, _) = post_acme(&router, &finalize_path, jws).await;
    assert_eq!(status, StatusCode::OK, "finalize: {final_body}");
    assert_eq!(final_body["status"].as_str().unwrap(), "valid");

    // 9. Download certificate.
    let cert_url = final_body["certificate"].as_str()
        .expect("finalize must return certificate URL");
    let cert_path = cert_url.trim_start_matches(base_url);
    let req = Request::builder().method(Method::GET).uri(cert_path)
        .body(Body::empty()).unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let cert_bytes = axum::body::to_bytes(resp.into_body(), 1_000_000).await.unwrap();
    let pem = std::str::from_utf8(&cert_bytes).expect("cert must be UTF-8");
    tracing::info!("certificate downloaded ({} bytes, {} certs)",
        pem.len(), pem.matches("BEGIN CERTIFICATE").count());

    // Verify leaf cert contains the expected SAN.
    let ders = synta_certificate::pem_to_der(pem.as_bytes());
    assert!(!ders.is_empty());
    let leaf: synta_certificate::Certificate =
        synta::Decoder::new(&ders[0], synta::Encoding::Der).decode().unwrap();
    let san_ok = leaf.subject_alt_names().iter().any(|(tag, val)|
        *tag == 2 && std::str::from_utf8(val).ok() == Some(domain)
    );
    assert!(san_ok, "leaf cert must have dNSName={domain}");
    tracing::info!("✓ SAN verified: certificate contains dNSName={domain}");
}

/// Full dns-persist-01 flow for a wildcard DNS identifier (`*.example.com`).
/// The TXT record must include `policy=wildcard` for the challenge to pass.
#[tokio::test]
async fn dns_persist_01_wildcard_flow() {
    init_tracing();

    let base_url = "https://acme.test";
    let issuer = "acme.test";
    let domain = "*.wildcard-persist.example.com";

    let mock_dns = MockDns::start().await;
    let dns_addr = format!("127.0.0.1:{}", mock_dns.port);
    let (state, _tmp) = build_state(base_url, issuer, &dns_addr).await;
    let router = routes::build_router(Arc::clone(&state));

    // Create account.
    let key = TestKey::generate();
    let nonce = head_nonce(&router).await;
    let jws = key.jws_jwk(&nonce, &format!("{base_url}/acme/new-account"),
        Some(json!({"termsOfServiceAgreed": true})));
    let (_, _, acct_hdrs) = post_acme(&router, "/acme/new-account", jws).await;
    let account_url = location_hdr(&acct_hdrs);
    let nonce = nonce_hdr(&acct_hdrs);

    // Register TXT record WITH policy=wildcard.
    let txt_record = format!("{issuer}; accounturi={account_url}; policy=wildcard");
    mock_dns.set_record(&txt_record).await;
    tracing::info!("wildcard TXT record: {txt_record}");

    // Create order for wildcard domain.
    let jws = key.jws_kid(&account_url, &nonce, &format!("{base_url}/acme/new-order"),
        Some(json!({"identifiers": [{"type": "dns", "value": domain}]})));
    let (status, order_body, order_hdrs) = post_acme(&router, "/acme/new-order", jws).await;
    assert_eq!(status, StatusCode::CREATED, "new-order: {order_body}");
    let order_url = location_hdr(&order_hdrs);
    let nonce = nonce_hdr(&order_hdrs);
    tracing::info!("wildcard order URL: {order_url}");

    // Fetch authorization — find dns-persist-01 challenge.
    let authz_url = order_body["authorizations"][0].as_str().unwrap().to_string();
    let authz_path = authz_url.trim_start_matches(base_url);
    let jws = key.jws_kid(&account_url, &nonce, &authz_url, None);
    let (_, authz_body, authz_hdrs) = post_acme(&router, authz_path, jws).await;
    let nonce = nonce_hdr(&authz_hdrs);

    let dp01 = authz_body["challenges"].as_array().unwrap()
        .iter()
        .find(|c| c["type"] == "dns-persist-01")
        .expect("dns-persist-01 must be in wildcard order challenges");
    let chall_url = dp01["url"].as_str().unwrap().to_string();
    let chall_path = chall_url.trim_start_matches(base_url).to_string();

    // Trigger validation.
    let jws = key.jws_kid(&account_url, &nonce, &chall_url, Some(json!({})));
    let (status, _, _) = post_acme(&router, &chall_path, jws).await;
    assert_eq!(status, StatusCode::OK);

    // Poll until ready.
    let order_body = poll_order_status(
        &router, &key, &account_url, &order_url, base_url, "ready",
    ).await;
    tracing::info!("wildcard order reached 'ready'");

    // Finalize with a wildcard CSR.
    let csr = make_csr(domain); // strips "*." for dNSName SAN
    let csr_b64 = URL_SAFE_NO_PAD.encode(&csr);
    let finalize_url = order_body["finalize"].as_str().unwrap().to_string();
    let finalize_path = finalize_url.trim_start_matches(base_url).to_string();
    let nonce = head_nonce(&router).await;
    let jws = key.jws_kid(&account_url, &nonce, &finalize_url, Some(json!({"csr": csr_b64})));
    let (status, final_body, _) = post_acme(&router, &finalize_path, jws).await;
    assert_eq!(status, StatusCode::OK, "wildcard finalize: {final_body}");
    assert_eq!(final_body["status"].as_str().unwrap(), "valid");
    tracing::info!("✓ wildcard dns-persist-01 flow completed");
}

/// Ensure that a TXT record missing `policy=wildcard` fails validation for a
/// wildcard order — the order must end up in `invalid` status.
#[tokio::test]
async fn dns_persist_01_wildcard_missing_policy_fails() {
    init_tracing();

    let base_url = "https://acme.test";
    let issuer = "acme.test";
    let domain = "*.nopolicy.example.com";

    let mock_dns = MockDns::start().await;
    let dns_addr = format!("127.0.0.1:{}", mock_dns.port);
    let (state, _tmp) = build_state(base_url, issuer, &dns_addr).await;
    let router = routes::build_router(Arc::clone(&state));

    let key = TestKey::generate();
    let nonce = head_nonce(&router).await;
    let jws = key.jws_jwk(&nonce, &format!("{base_url}/acme/new-account"),
        Some(json!({"termsOfServiceAgreed": true})));
    let (_, _, acct_hdrs) = post_acme(&router, "/acme/new-account", jws).await;
    let account_url = location_hdr(&acct_hdrs);
    let nonce = nonce_hdr(&acct_hdrs);

    // Record WITHOUT policy=wildcard — must fail for wildcard order.
    let txt_record = format!("{issuer}; accounturi={account_url}");
    mock_dns.set_record(&txt_record).await;

    let jws = key.jws_kid(&account_url, &nonce, &format!("{base_url}/acme/new-order"),
        Some(json!({"identifiers": [{"type": "dns", "value": domain}]})));
    let (_, order_body, order_hdrs) = post_acme(&router, "/acme/new-order", jws).await;
    let order_url = location_hdr(&order_hdrs);
    let nonce = nonce_hdr(&order_hdrs);

    let authz_url = order_body["authorizations"][0].as_str().unwrap().to_string();
    let authz_path = authz_url.trim_start_matches(base_url);
    let jws = key.jws_kid(&account_url, &nonce, &authz_url, None);
    let (_, authz_body, authz_hdrs) = post_acme(&router, authz_path, jws).await;
    let nonce = nonce_hdr(&authz_hdrs);

    let dp01 = authz_body["challenges"].as_array().unwrap()
        .iter().find(|c| c["type"] == "dns-persist-01").unwrap();
    let chall_url = dp01["url"].as_str().unwrap().to_string();
    let chall_path = chall_url.trim_start_matches(base_url).to_string();

    let jws = key.jws_kid(&account_url, &nonce, &chall_url, Some(json!({})));
    let (status, _, _) = post_acme(&router, &chall_path, jws).await;
    assert_eq!(status, StatusCode::OK);

    // Validation must fail → order becomes invalid.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    let order_path = order_url.trim_start_matches(base_url);
    let final_status = loop {
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let nonce = head_nonce(&router).await;
        let jws = key.jws_kid(&account_url, &nonce, &order_url, None);
        let (_, body, _) = post_acme(&router, order_path, jws).await;
        let s = body["status"].as_str().unwrap_or("").to_string();
        if s == "invalid" || s == "ready" { break s; }
        if std::time::Instant::now() > deadline {
            panic!("timed out waiting for order to settle: {body}");
        }
    };
    assert_eq!(final_status, "invalid",
        "order must be invalid when policy=wildcard is missing from TXT record");
    tracing::info!("✓ wildcard order correctly rejected without policy=wildcard");
}
