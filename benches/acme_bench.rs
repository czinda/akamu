//! ACME server end-to-end benchmark.
//!
//! Measures issuance throughput and per-phase latency by running full ACME flows
//! (account → order → challenge → finalize → download) against a real TCP server
//! started in-process.  A fixed pool of concurrent worker tasks competes for work
//! tickets from a shared queue, giving constant concurrency throughout the run.
//!
//! # Usage
//!
//!   cargo bench --bench acme_bench -- [OPTIONS]
//!
//! # Key options
//!
//!   --clients N       concurrent workers            [default: 10]
//!   --requests N      issuances to measure          [default: 100]
//!   --warmup N        issuances discarded first     [default: 10]
//!   --challenge TYPE  http-01 | dns-persist-01      [default: http-01]
//!   --key-type TYPE   ec:P-256 | ec:P-384 | rsa:2048 | rsa:4096 | ed25519
//!   --ca-key-type T   CA key type (same syntax)
//!   --wildcard        issue *.bench-N.acme-bench.test  (dns-persist-01 only)
//!   --db PATH             :memory: or file path for SQLite
//!   --pool-connections N  SQLite pool size (ignored for :memory:)  [default: 1]
//!   --output FORMAT       text | json
//!   --verify-cert         parse and check SAN of every issued cert

use std::{
    alloc::{GlobalAlloc, Layout, System},
    cmp::Reverse,
    collections::HashMap,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Instant,
};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use clap::Parser;
use http_body_util::{BodyExt, Full};
use hyper::{body::Bytes, HeaderMap};
use hyper_util::{
    client::legacy::{connect::HttpConnector, Client},
    rt::TokioExecutor,
};
use serde_json::{json, Value};
use synta_certificate::{
    default_data_hasher, BackendPrivateKey, CertificateSigner as _, CsrBuilder, DataHasher,
    NameBuilder, PrivateKey as _, SubjectAlternativeNameBuilder,
};
use tokio::{net::UdpSocket, sync::RwLock};

use akamu::{
    ca,
    config::{CaConfig, Config, DatabaseConfig, MtcConfig, ServerConfig},
    db, routes,
    state::{AppState, CaState, MtcState, NonceBucket},
};

// ── Heap-allocation tracking (borrowed from synta-fuzz/src/main.rs) ───────────
//
// A thin wrapper around the system allocator that maintains four AtomicU64
// counters:
//
//   ALLOC_COUNT — number of alloc() calls since process start.
//   ALLOC_BYTES — cumulative bytes requested (includes subsequently freed
//                 memory, so this measures allocation *pressure*).
//   LIVE_BYTES  — currently live bytes (incremented on alloc, decremented on
//                 dealloc/realloc-shrink).
//   PEAK_BYTES  — maximum LIVE_BYTES seen since the last reset_peak() call.
//
// These give the benchmark two complementary views of memory:
//
//   • Live (LIVE_BYTES) — footprint: how much heap the process actually holds.
//   • Pressure (ALLOC_BYTES) — churn: how much total allocation the workload
//     drives through the allocator, including short-lived temporaries.

static ALLOC_COUNT: AtomicU64 = AtomicU64::new(0);
static ALLOC_BYTES: AtomicU64 = AtomicU64::new(0);
static LIVE_BYTES: AtomicU64 = AtomicU64::new(0);
static PEAK_BYTES: AtomicU64 = AtomicU64::new(0);

struct TrackingAlloc;

unsafe impl GlobalAlloc for TrackingAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { System.alloc(layout) };
        if !ptr.is_null() {
            ALLOC_COUNT.fetch_add(1, Ordering::Relaxed);
            ALLOC_BYTES.fetch_add(layout.size() as u64, Ordering::Relaxed);
            let live = LIVE_BYTES.fetch_add(layout.size() as u64, Ordering::Relaxed)
                + layout.size() as u64;
            update_peak(live);
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) };
        LIVE_BYTES.fetch_sub(layout.size() as u64, Ordering::Relaxed);
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let ptr = unsafe { System.realloc(ptr, layout, new_size) };
        if !ptr.is_null() {
            let old = layout.size() as u64;
            let new = new_size as u64;
            if new > old {
                ALLOC_BYTES.fetch_add(new - old, Ordering::Relaxed);
                let live = LIVE_BYTES.fetch_add(new - old, Ordering::Relaxed) + (new - old);
                update_peak(live);
            } else {
                LIVE_BYTES.fetch_sub(old - new, Ordering::Relaxed);
            }
        }
        ptr
    }
}

#[global_allocator]
static ALLOC: TrackingAlloc = TrackingAlloc;

fn update_peak(live: u64) {
    let mut old = PEAK_BYTES.load(Ordering::Relaxed);
    while live > old {
        match PEAK_BYTES.compare_exchange_weak(old, live, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => break,
            Err(x) => old = x,
        }
    }
}

/// Reset the peak tracker to the current live level.
///
/// Call this just before the measured window begins so that PEAK_BYTES
/// captures the high-water mark *within* that window rather than since
/// process start.
fn reset_peak() {
    PEAK_BYTES.store(LIVE_BYTES.load(Ordering::Relaxed), Ordering::Relaxed);
}

/// Point-in-time snapshot of the four allocation counters.
#[derive(Default, Clone, Copy)]
struct AllocSnapshot {
    live: u64,
    peak: u64,
    total_bytes: u64,
    total_count: u64,
}

fn alloc_snapshot() -> AllocSnapshot {
    AllocSnapshot {
        live: LIVE_BYTES.load(Ordering::Relaxed),
        peak: PEAK_BYTES.load(Ordering::Relaxed),
        total_bytes: ALLOC_BYTES.load(Ordering::Relaxed),
        total_count: ALLOC_COUNT.load(Ordering::Relaxed),
    }
}

/// Memory statistics captured at three milestones in the benchmark run.
struct MemStats {
    /// After process start, before the ACME server is initialised.
    start: AllocSnapshot,
    /// After server init (CA key-gen, DB open, TCP bind) — before any issuances.
    server_ready: AllocSnapshot,
    /// After all issuances (warmup + benchmark) complete.
    after_bench: AllocSnapshot,
    /// Total number of issuances performed (warmup + benchmark), used as
    /// the denominator for per-issuance calculations.
    total_issuances: usize,
}

fn mib(bytes: u64) -> f64 {
    bytes as f64 / (1024.0 * 1024.0)
}

fn kib(bytes: u64) -> f64 {
    bytes as f64 / 1024.0
}

// ── CLI ────────────────────────────────────────────────────────────────────────

#[derive(Parser, Clone, Debug)]
#[command(name = "acme-bench", about = "ACME server end-to-end load benchmark")]
struct Args {
    /// Number of concurrent worker tasks
    #[arg(long, default_value_t = 10)]
    clients: usize,

    /// Total certificate issuances to measure (warmup not counted)
    #[arg(long, default_value_t = 100)]
    requests: usize,

    /// Issuances to run before measurement starts (results discarded)
    #[arg(long, default_value_t = 10)]
    warmup: usize,

    /// Challenge type: http-01 | dns-persist-01
    #[arg(long, default_value = "http-01")]
    challenge: String,

    /// Key type for issued certificates: ec:P-256, ec:P-384, rsa:2048, rsa:4096, ed25519,
    /// ml-dsa-44, ml-dsa-65, ml-dsa-87  (PQ requires OpenSSL 3.5+)
    #[arg(long, default_value = "ec:P-256")]
    key_type: String,

    /// CA key type (same syntax as --key-type)
    #[arg(long, default_value = "ec:P-256")]
    ca_key_type: String,

    /// Database URL — `sqlite::memory:`, `sqlite://path/to/db`,
    /// `postgres://user:pass@host/db`, or `mariadb://user:pass@host/db`
    #[arg(long, default_value = "sqlite::memory:")]
    db: String,

    /// SQLite connection pool size.  Ignored (clamped to 1) when --db is :memory:,
    /// because each in-memory connection opens its own private database.
    /// File-backed databases can use N > 1 to test contention behaviour, but note
    /// that SQLITE_BUSY_SNAPSHOT errors may occur under concurrent write load.
    #[arg(long, default_value_t = 1)]
    pool_connections: u32,

    /// Issue wildcard certificates — dns-persist-01 only
    #[arg(long)]
    wildcard: bool,

    /// Output format: text | json
    #[arg(long, default_value = "text")]
    output: String,

    /// Parse and verify the SAN of each issued certificate
    #[arg(long)]
    verify_cert: bool,

    /// Poll interval in milliseconds for the challenge-ready and finalize-valid loops.
    /// Lower values improve throughput when validation completes in < poll_ms.
    /// http-01 validation finishes in < 5 ms on loopback; 5 ms is a good floor.
    #[arg(long, default_value_t = 50)]
    poll_ms: u64,
}

// ── HTTP client ────────────────────────────────────────────────────────────────

type HyperClient = Client<HttpConnector, Full<Bytes>>;

fn new_http_client() -> HyperClient {
    Client::builder(TokioExecutor::new()).build_http()
}

async fn http_get(client: &HyperClient, url: &str) -> Result<(u16, Vec<u8>, HeaderMap), String> {
    let req = hyper::Request::builder()
        .method("GET")
        .uri(url)
        .body(Full::new(Bytes::new()))
        .map_err(|e| e.to_string())?;
    let resp = client
        .request(req)
        .await
        .map_err(|e| format!("GET {url}: {e}"))?;
    let status = resp.status().as_u16();
    let headers = resp.headers().clone();
    let bytes = resp
        .into_body()
        .collect()
        .await
        .map_err(|e| e.to_string())?
        .to_bytes()
        .to_vec();
    Ok((status, bytes, headers))
}

async fn http_head(client: &HyperClient, url: &str) -> Result<HeaderMap, String> {
    let req = hyper::Request::builder()
        .method("HEAD")
        .uri(url)
        .body(Full::new(Bytes::new()))
        .map_err(|e| e.to_string())?;
    let resp = client
        .request(req)
        .await
        .map_err(|e| format!("HEAD {url}: {e}"))?;
    Ok(resp.headers().clone())
}

async fn http_post_jws(
    client: &HyperClient,
    url: &str,
    jws: &Value,
) -> Result<(u16, Value, HeaderMap), String> {
    let req = hyper::Request::builder()
        .method("POST")
        .uri(url)
        .header("content-type", "application/jose+json")
        .body(Full::new(Bytes::from(jws.to_string())))
        .map_err(|e| e.to_string())?;
    let resp = client
        .request(req)
        .await
        .map_err(|e| format!("POST {url}: {e}"))?;
    let status = resp.status().as_u16();
    let headers = resp.headers().clone();
    let bytes = resp
        .into_body()
        .collect()
        .await
        .map_err(|e| e.to_string())?
        .to_bytes();
    let json = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    Ok((status, json, headers))
}

fn nonce_hdr(h: &HeaderMap) -> Result<String, String> {
    h.get("replay-nonce")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .ok_or_else(|| "missing replay-nonce header".to_string())
}

fn location_hdr(h: &HeaderMap) -> Result<String, String> {
    h.get("location")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .ok_or_else(|| "missing location header".to_string())
}

// ── Hand-rolled ACME JWS client (P-256 / ES256) ───────────────────────────────
//
// Account key is always EC P-256 for simplicity.  The --key-type flag controls
// the certificate key (CSR), not the JWS signing key.
//
// Copied from tests/acme_flow.rs.

struct AccountKey {
    key: BackendPrivateKey,
    x_b64: String,
    y_b64: String,
    /// RFC 7638 JWK thumbprint — used as the key-auth suffix for http-01.
    thumbprint: String,
}

impl AccountKey {
    fn generate() -> Self {
        let key = BackendPrivateKey::generate_ec("P-256").unwrap();
        let pub_key = key.public_key().unwrap();
        let (x_bytes, y_bytes) = pub_key.ec_affine_coordinates().unwrap().unwrap();
        let x_b64 = encode_coord(&x_bytes, 32);
        let y_b64 = encode_coord(&y_bytes, 32);
        let thumbprint = jwk_thumbprint(&x_b64, &y_b64);
        AccountKey {
            key,
            x_b64,
            y_b64,
            thumbprint,
        }
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
            None => String::new(), // POST-as-GET: empty payload
        };
        let input = format!("{protected}.{payload_b64}");
        let signer = self.key.as_signer("sha256");
        let der = signer.sign_tbs(input.as_bytes()).unwrap();
        let sig = URL_SAFE_NO_PAD.encode(ecdsa_der_to_p1363(&der, 32).unwrap());
        json!({ "protected": protected, "payload": payload_b64, "signature": sig })
    }
}

fn encode_coord(bytes: &[u8], len: usize) -> String {
    let mut padded = vec![0u8; len];
    let start = len.saturating_sub(bytes.len());
    padded[start..].copy_from_slice(&bytes[bytes.len().saturating_sub(len)..]);
    URL_SAFE_NO_PAD.encode(&padded)
}

/// RFC 7638 JWK thumbprint: SHA-256 of canonical JWK JSON (keys in alphabetical order).
fn jwk_thumbprint(x_b64: &str, y_b64: &str) -> String {
    let canonical = format!(r#"{{"crv":"P-256","kty":"EC","x":"{x_b64}","y":"{y_b64}"}}"#);
    URL_SAFE_NO_PAD.encode(
        default_data_hasher()
            .hash_data("sha256", canonical.as_bytes())
            .expect("SHA-256 thumbprint"),
    )
}

// DER ECDSA (SEQUENCE{r, s}) → P1363 (r‖s, both padded to `half` bytes).
fn ecdsa_der_to_p1363(der: &[u8], half: usize) -> Option<Vec<u8>> {
    let inner = strip_tlv(der, 0x30)?;
    let (r, rest) = strip_int(inner)?;
    let (s, _) = strip_int(rest)?;
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
    let (len, rest) = decode_len(&buf[1..])?;
    rest.get(..len)
}

fn strip_int(buf: &[u8]) -> Option<(&[u8], &[u8])> {
    if *buf.first()? != 0x02 {
        return None;
    }
    let (len, rest) = decode_len(&buf[1..])?;
    let val = rest
        .get(..len)?
        .strip_prefix(&[0x00u8])
        .unwrap_or(rest.get(..len)?);
    Some((val, &rest[len..]))
}

fn decode_len(buf: &[u8]) -> Option<(usize, &[u8])> {
    let first = *buf.first()?;
    if first < 0x80 {
        Some((first as usize, &buf[1..]))
    } else if first == 0x81 {
        Some((*buf.get(1)? as usize, &buf[2..]))
    } else if first == 0x82 {
        Some((
            ((*buf.get(1)? as usize) << 8 | *buf.get(2)? as usize),
            &buf[3..],
        ))
    } else {
        None
    }
}

// ── Key generation (mirrors ca::init::generate_backend_key, which is pub(crate)) ──

fn generate_key(key_type: &str) -> Result<BackendPrivateKey, String> {
    let err = |e: &dyn std::fmt::Display| format!("generate '{key_type}': {e}");
    match key_type {
        "ec:P-256" | "P-256" => BackendPrivateKey::generate_ec("P-256").map_err(|e| err(&e)),
        "ec:P-384" | "P-384" => BackendPrivateKey::generate_ec("P-384").map_err(|e| err(&e)),
        "ec:P-521" | "P-521" => BackendPrivateKey::generate_ec("P-521").map_err(|e| err(&e)),
        "rsa:2048" | "rsa2048" => BackendPrivateKey::generate_rsa(2048, 65537).map_err(|e| err(&e)),
        "rsa:3072" | "rsa3072" => BackendPrivateKey::generate_rsa(3072, 65537).map_err(|e| err(&e)),
        "rsa:4096" | "rsa4096" => BackendPrivateKey::generate_rsa(4096, 65537).map_err(|e| err(&e)),
        "ed25519" => BackendPrivateKey::generate_ed25519().map_err(|e| err(&e)),
        "ed448" => BackendPrivateKey::generate_ed448().map_err(|e| err(&e)),
        // Post-quantum signature keys (FIPS 204, requires OpenSSL 3.5+).
        "ml-dsa-44" | "ML-DSA-44" => {
            BackendPrivateKey::generate_ml_dsa("ML-DSA-44").map_err(|e| err(&e))
        }
        "ml-dsa-65" | "ML-DSA-65" => {
            BackendPrivateKey::generate_ml_dsa("ML-DSA-65").map_err(|e| err(&e))
        }
        "ml-dsa-87" | "ML-DSA-87" => {
            BackendPrivateKey::generate_ml_dsa("ML-DSA-87").map_err(|e| err(&e))
        }
        other => Err(format!(
            "unknown key type '{other}'; use ec:P-256, rsa:2048, ed25519, ml-dsa-44, …"
        )),
    }
}

// ── CSR builder ────────────────────────────────────────────────────────────────

fn make_csr(domain: &str, key_type: &str) -> Result<Vec<u8>, String> {
    let k = generate_key(key_type)?;
    let spki = k
        .public_key()
        .map_err(|e| e.to_string())?
        .spki_der()
        .to_vec();
    let name = NameBuilder::new()
        .common_name(domain)
        .build()
        .map_err(|e| format!("CSR name: {e}"))?;
    // Use domain as-is (including "*.") — wildcard labels are valid in dNSName SANs
    // (RFC 5280 §4.2.1.6) and must match the order identifier exactly.
    let san = SubjectAlternativeNameBuilder::new()
        .dns_name(domain)
        .build()
        .map_err(|e| format!("CSR SAN: {e}"))?;
    let signer = k.as_signer("sha256");
    CsrBuilder::new()
        .subject_name(&name)
        .public_key_der(&spki)
        .add_extension_oid(synta_certificate::oids::SUBJECT_ALT_NAME, false, &san)
        .sign(&signer)
        .map_err(|e| format!("CSR sign: {e}"))
}

// ── http-01 challenge infrastructure ──────────────────────────────────────────

type ChallengeStore = Arc<RwLock<HashMap<String, String>>>; // token → key_auth

async fn start_challenge_responder() -> (u16, ChallengeStore) {
    use axum::{
        extract::{Path, State},
        routing::get,
        Router,
    };
    let store: ChallengeStore = Arc::new(RwLock::new(HashMap::new()));
    let router = Router::new()
        .route(
            "/.well-known/acme-challenge/{token}",
            get(
                |State(s): State<ChallengeStore>, Path(token): Path<String>| async move {
                    s.read().await.get(&token).cloned().unwrap_or_default()
                },
            ),
        )
        .with_state(store.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move { axum::serve(listener, router).await.ok() });
    (port, store)
}

// ── dns-persist-01 challenge infrastructure ────────────────────────────────────
//
// Multi-domain mock UDP DNS server.  Parses the qname from each incoming query
// and looks it up in a shared HashMap.  Extends the single-record MockDns in
// tests/dns_persist_flow.rs to support one TXT record per worker domain.

type DnsRecords = Arc<RwLock<HashMap<String, String>>>; // qname → txt_value

struct MultiDns {
    pub port: u16,
    pub records: DnsRecords,
}

impl MultiDns {
    async fn start() -> Self {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = socket.local_addr().unwrap().port();
        let records: DnsRecords = Arc::new(RwLock::new(HashMap::new()));
        let records_clone = Arc::clone(&records);
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            loop {
                let Ok((n, addr)) = socket.recv_from(&mut buf).await else {
                    break;
                };
                let query = buf[..n].to_vec();
                let qname = parse_qname(&query);
                let store = records_clone.read().await;
                if let Some(txt) = store.get(&qname) {
                    let resp = build_txt_response(&query, txt);
                    let _ = socket.send_to(&resp, addr).await;
                }
                // Unknown qnames: no response (hickory-resolver retries).
            }
        });
        MultiDns { port, records }
    }

    async fn set_record(&self, qname: &str, txt: &str) {
        self.records
            .write()
            .await
            .insert(qname.to_string(), txt.to_string());
    }
}

/// Parse the DNS qname from a wire-format query into a dotted string with
/// trailing dot, e.g. `"_validation-persist.bench-0.acme-bench.test."`.
fn parse_qname(query: &[u8]) -> String {
    let mut pos = 12usize; // skip 12-byte DNS header
    let mut labels: Vec<String> = Vec::new();
    while pos < query.len() {
        let len = query[pos] as usize;
        pos += 1;
        if len == 0 {
            break;
        }
        if pos + len > query.len() {
            break;
        }
        if let Ok(s) = std::str::from_utf8(&query[pos..pos + len]) {
            labels.push(s.to_lowercase());
        }
        pos += len;
    }
    if labels.is_empty() {
        return ".".to_string();
    }
    format!("{}.", labels.join("."))
}

/// Minimal DNS TXT response.  Copied from tests/dns_persist_flow.rs.
fn build_txt_response(query: &[u8], txt_value: &str) -> Vec<u8> {
    let mut pos = 12usize;
    while pos < query.len() {
        let llen = query[pos] as usize;
        pos += 1;
        if llen == 0 {
            break;
        }
        pos += llen;
    }
    pos += 4; // skip QTYPE + QCLASS
    let question_end = pos;
    let txt_bytes = txt_value.as_bytes();
    let rdlength = (txt_bytes.len() + 1) as u16;
    let mut resp = Vec::with_capacity(question_end + 16 + txt_bytes.len());
    resp.extend_from_slice(&query[..2]); // transaction ID (echo)
    resp.extend_from_slice(&[0x81, 0x80]); // QR=1 RD=1 RA=1
    resp.extend_from_slice(&[0x00, 0x01]); // QDCOUNT=1
    resp.extend_from_slice(&[0x00, 0x01]); // ANCOUNT=1
    resp.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // NSCOUNT=0 ARCOUNT=0
    resp.extend_from_slice(&query[12..question_end]); // question section (echo)
    resp.extend_from_slice(&[0xC0, 0x0C]); // name pointer → offset 12
    resp.extend_from_slice(&[0x00, 0x10]); // TYPE=TXT
    resp.extend_from_slice(&[0x00, 0x01]); // CLASS=IN
    resp.extend_from_slice(&[0x00, 0x00, 0x00, 0x3C]); // TTL=60
    resp.extend_from_slice(&rdlength.to_be_bytes());
    resp.push(txt_bytes.len() as u8); // TXT char-string length prefix
    resp.extend_from_slice(txt_bytes);
    resp
}

// ── In-process server startup ──────────────────────────────────────────────────

struct BenchServer {
    pub base_url: String,
    /// Shared challenge store for http-01 workers.
    pub challenge_store: Option<ChallengeStore>,
    /// Multi-domain DNS server for dns-persist-01 workers.
    pub dns: Option<Arc<MultiDns>>,
    // Keep the CA temp directory alive for the server's lifetime.
    _dir: tempfile::TempDir,
}

async fn start_server(args: &Args) -> BenchServer {
    let dir = tempfile::TempDir::new().unwrap();

    // Challenge infrastructure depends on the chosen challenge type.
    let (challenge_store, dns, http_validation_port, dns_resolver_addr, issuer_domain) = match args.challenge.as_str() {
            "dns-persist-01" => {
                let dns = Arc::new(MultiDns::start().await);
                let resolver = format!("127.0.0.1:{}", dns.port);
                (None, Some(dns), 80u16, Some(resolver), Some("acme-bench.test".to_string()))
            }
            _ /* http-01 */ => {
                let (port, store) = start_challenge_responder().await;
                (Some(store), None, port, None, None)
            }
        };

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let addr = listener.local_addr().unwrap();
    let base_url = format!("http://127.0.0.1:{}", addr.port());

    let config = Arc::new(Config {
        listen_addr: addr.to_string(),
        base_url: base_url.clone(),
        database: DatabaseConfig {
            url: args.db.clone(),
            max_connections: None,
        },
        ca: CaConfig {
            key_file: dir.path().join("ca.key").to_string_lossy().into_owned(),
            cert_file: dir.path().join("ca.crt").to_string_lossy().into_owned(),
            key_type: args.ca_key_type.clone(),
            // ML-DSA is a pure lattice scheme; the hash_alg field is ignored for
            // PQ keys. "sha256" is the correct default for EC/RSA/Ed keys.
            hash_alg: "sha256".into(),
            validity_days: 90,
            crl_url: None,
            ocsp_url: None,
            common_name: "Bench CA".into(),
            organization: "Bench".into(),
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
        server: ServerConfig {
            http_validation_port,
            dns_persist_issuer_domains: issuer_domain.into_iter().collect(),
            dns_resolver_addr,
            ..ServerConfig::default()
        },
        tls: Default::default(),
        profiles: Default::default(),
        admin: None,
    });

    let (ca_key, ca_cert_der) = ca::init::load_or_generate(&config.ca).unwrap();
    let ca_spki_der = ca_key.public_key().unwrap().spki_der().to_vec();
    let ca_aki_bytes = akamu::ca::init::compute_aki_from_spki(&ca_spki_der).unwrap_or_default();
    db::install_drivers();
    let db_kind = db::DbKind::from_url(&args.db);
    // Clamp pool size to 1 for sqlite::memory: (each connection gets its own DB).
    let effective_pool = if db_kind == db::DbKind::Sqlite && args.db.contains(":memory:") {
        1
    } else {
        args.pool_connections.max(1)
    };
    let db_conn = db::open(&args.db, effective_pool).await.unwrap();
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
    let state = Arc::new(AppState {
        config: Arc::clone(&config),
        db: db_conn,
        db_kind,
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
        crl_cache: Default::default(),
        spki_cache: Arc::new(std::sync::RwLock::new(std::collections::HashMap::new())),
        nonces: Arc::new(NonceBucket::new()),
        link_header: Arc::new(
            axum::http::HeaderValue::from_str(&format!(
                "<{}/acme/directory>;rel=\"index\"",
                base_url
            ))
            .expect("base_url produces a valid Link header value"),
        ),
        validation_client: {
            let https = hyper_rustls::HttpsConnectorBuilder::new()
                .with_native_roots()
                .expect("native root CAs")
                .https_or_http()
                .enable_http1()
                .build();
            hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
                .build(https)
        },
        gss_cred: None,
        eab_master_secret: None,
        audit: Arc::new(akamu::audit::AuditState::new()),
        audit_policy: Arc::new(akamu::audit::AuditPolicy::default()),
        admin_sessions: None,
        startup_time: std::time::Instant::now(),
    });

    let router = routes::build_router(state);
    let tokio_listener = tokio::net::TcpListener::from_std(listener).unwrap();
    tokio::spawn(async move {
        axum::serve(tokio_listener, router).await.ok();
    });
    // Allow the server to finish binding before workers start.
    tokio::time::sleep(std::time::Duration::from_millis(30)).await;

    BenchServer {
        base_url,
        challenge_store,
        dns,
        _dir: dir,
    }
}

// ── Per-issuance timing record ─────────────────────────────────────────────────

#[derive(Clone)]
struct IssuanceTiming {
    worker_id: usize,
    request_id: usize,
    success: bool,
    error: Option<String>,
    /// 0 when the account was reused from a previous issuance by this worker.
    account_us: u64,
    order_us: u64,
    authz_us: u64,
    challenge_us: u64,
    finalize_us: u64,
    download_us: u64,
    /// Wall time from start-of-order to cert-download-complete (account excluded).
    total_us: u64,
}

impl IssuanceTiming {
    fn failed(worker_id: usize, request_id: usize, msg: String) -> Self {
        IssuanceTiming {
            worker_id,
            request_id,
            success: false,
            error: Some(msg),
            account_us: 0,
            order_us: 0,
            authz_us: 0,
            challenge_us: 0,
            finalize_us: 0,
            download_us: 0,
            total_us: 0,
        }
    }
}

// ── Worker state (one account shared across all issuances from this worker) ────

struct WorkerState {
    id: usize,
    key: AccountKey,
    account_url: Option<String>,
    /// Domain identifier used in all orders from this worker.
    domain: String,
    /// Nonce carried over from the previous issuance's last response.
    /// Each POST response includes Replay-Nonce; threading it eliminates the
    /// HEAD /new-nonce round-trip at the start of every subsequent issuance.
    last_nonce: Option<String>,
}

impl WorkerState {
    fn new(id: usize, args: &Args) -> Self {
        let domain = match args.challenge.as_str() {
            "dns-persist-01" => {
                let base = format!("bench-{id}.acme-bench.test");
                if args.wildcard {
                    format!("*.{base}")
                } else {
                    base
                }
            }
            // http-01: all workers order a cert for "localhost" (resolves to 127.0.0.1).
            _ => "localhost".to_string(),
        };
        WorkerState {
            id,
            key: AccountKey::generate(),
            account_url: None,
            domain,
            last_nonce: None,
        }
    }
}

// ── ACME protocol helpers ──────────────────────────────────────────────────────

async fn fetch_nonce(client: &HyperClient, new_nonce_url: &str) -> Result<String, String> {
    let headers = http_head(client, new_nonce_url).await?;
    nonce_hdr(&headers)
}

/// Create a new ACME account. Returns (account_url, next_nonce) so the caller
/// can chain the nonce directly into the following new-order request.
async fn create_account(
    worker: &WorkerState,
    server: &BenchServer,
    client: &HyperClient,
) -> Result<(String, String), String> {
    let nonce_url = format!("{}/acme/new-nonce", server.base_url);
    let acct_url = format!("{}/acme/new-account", server.base_url);
    let nonce = fetch_nonce(client, &nonce_url).await?;
    let jws = worker.key.jws_jwk(
        &nonce,
        &acct_url,
        Some(json!({"termsOfServiceAgreed": true})),
    );
    let (status, body, headers) = http_post_jws(client, &acct_url, &jws).await?;
    if status != 201 {
        return Err(format!("new-account {status}: {body}"));
    }
    let account_url = location_hdr(&headers)?;
    let next_nonce = nonce_hdr(&headers)?;
    Ok((account_url, next_nonce))
}

/// POST new-order using the supplied nonce (no HEAD needed). Returns
/// (order_url, authz_url, finalize_url, next_nonce) so the nonce can be
/// chained to the following get-authz request.
async fn new_order(
    worker: &WorkerState,
    server: &BenchServer,
    client: &HyperClient,
    account_url: &str,
    nonce: &str,
) -> Result<(String, String, String, String), String> {
    let order_url = format!("{}/acme/new-order", server.base_url);
    let payload = json!({"identifiers": [{"type": "dns", "value": worker.domain}]});
    let jws = worker
        .key
        .jws_kid(account_url, nonce, &order_url, Some(payload));
    let (status, body, headers) = http_post_jws(client, &order_url, &jws).await?;
    if status != 201 {
        return Err(format!("new-order {status}: {body}"));
    }
    let loc = location_hdr(&headers)?;
    let next_nonce = nonce_hdr(&headers)?;
    let authz_url = body["authorizations"][0]
        .as_str()
        .ok_or("missing authorizations[0]")?
        .to_string();
    let fin_url = body["finalize"]
        .as_str()
        .ok_or("missing finalize URL")?
        .to_string();
    Ok((loc, authz_url, fin_url, next_nonce))
}

/// POST-as-GET the authz using the supplied nonce (no HEAD needed). Returns
/// (challenge_url, token_or_none, next_nonce).
async fn get_authz(
    worker: &WorkerState,
    server: &BenchServer,
    client: &HyperClient,
    account_url: &str,
    authz_url: &str,
    challenge_type: &str,
    nonce: &str,
) -> Result<(String, Option<String>, String), String> {
    // authz_url is a full URL; the server expects the full URL in the JWS header.
    let path = authz_url.trim_start_matches(&server.base_url);
    let jws = worker.key.jws_kid(account_url, nonce, authz_url, None);
    let (status, body, headers) =
        http_post_jws(client, &format!("{}{path}", server.base_url), &jws).await?;
    if status != 200 {
        return Err(format!("authz {status}: {body}"));
    }
    let next_nonce = nonce_hdr(&headers)?;
    let challenges = body["challenges"].as_array().ok_or("no challenges")?;
    let chall = challenges
        .iter()
        .find(|c| c["type"].as_str() == Some(challenge_type))
        .ok_or_else(|| format!("no {challenge_type} challenge"))?;
    let chall_url = chall["url"].as_str().ok_or("no challenge url")?.to_string();
    let token = chall["token"].as_str().map(|s| s.to_string());
    Ok((chall_url, token, next_nonce))
}

/// Shared per-issuance context passed to `respond_and_poll` and `finalize_and_poll`.
struct IssuanceCtx<'a> {
    worker: &'a WorkerState,
    server: &'a BenchServer,
    client: &'a HyperClient,
    account_url: &'a str,
}

/// POST the challenge response (using the supplied nonce, no HEAD needed), then
/// poll the order until `ready` or terminal, threading the nonce from each
/// response to the next poll. Returns the nonce from the last poll response so
/// the caller can chain it into the finalize request.
async fn respond_and_poll(
    ctx: &IssuanceCtx<'_>,
    chall_url: &str,
    order_url: &str,
    nonce: &str,
    poll_ms: u64,
) -> Result<String, String> {
    let (worker, server, client, account_url) =
        (ctx.worker, ctx.server, ctx.client, ctx.account_url);
    let nonce_url = format!("{}/acme/new-nonce", server.base_url);
    let chall_path = chall_url.trim_start_matches(&server.base_url);
    let jws = worker
        .key
        .jws_kid(account_url, nonce, chall_url, Some(json!({})));
    let (status, body, headers) =
        http_post_jws(client, &format!("{}{chall_path}", server.base_url), &jws).await?;
    if status != 200 {
        return Err(format!("challenge respond {status}: {body}"));
    }
    // Thread the nonce from the challenge response into the poll loop.
    let mut cur_nonce = nonce_hdr(&headers).unwrap_or_else(|_| String::new());

    let order_path = order_url.trim_start_matches(&server.base_url);
    let deadline = Instant::now() + std::time::Duration::from_secs(30);
    // Adaptive backoff: start at 1 ms, double each miss, cap at poll_ms.
    // Real-world ACME clients use exponential backoff; on loopback http-01
    // validation completes in ~1-3 ms so the first or second poll usually wins.
    let mut next_sleep_ms: u64 = 1;
    loop {
        tokio::time::sleep(std::time::Duration::from_millis(next_sleep_ms)).await;
        next_sleep_ms = (next_sleep_ms * 2).min(poll_ms);
        if Instant::now() > deadline {
            return Err("timed out waiting for order ready".to_string());
        }
        // Use the nonce from the previous response; fall back to HEAD only if lost.
        let poll_nonce = if cur_nonce.is_empty() {
            fetch_nonce(client, &nonce_url).await?
        } else {
            std::mem::take(&mut cur_nonce)
        };
        let jws = worker
            .key
            .jws_kid(account_url, &poll_nonce, order_url, None);
        let (_, body, headers) =
            http_post_jws(client, &format!("{}{order_path}", server.base_url), &jws).await?;
        cur_nonce = nonce_hdr(&headers).unwrap_or_default();
        match body["status"].as_str() {
            Some("ready") | Some("valid") => return Ok(cur_nonce),
            Some("invalid") => return Err(format!("order invalid: {}", body["error"])),
            _ => continue,
        }
    }
}

/// Finalize the order with a CSR using the supplied nonce (no HEAD needed).
/// Returns (cert_url, next_nonce). The nonce is taken from the finalize response
/// and can be stored for the next issuance. The poll loop is only a fallback —
/// this server returns status="valid" synchronously in the finalize response.
async fn finalize_and_poll(
    ctx: &IssuanceCtx<'_>,
    order_url: &str,
    finalize_url: &str,
    key_type: &str,
    nonce: &str,
) -> Result<(String, Option<String>), String> {
    let (worker, server, client, account_url) =
        (ctx.worker, ctx.server, ctx.client, ctx.account_url);
    let nonce_url = format!("{}/acme/new-nonce", server.base_url);
    let csr_der = make_csr(&worker.domain, key_type)?;
    let csr_b64 = URL_SAFE_NO_PAD.encode(&csr_der);
    let fin_path = finalize_url.trim_start_matches(&server.base_url);
    let jws = worker.key.jws_kid(
        account_url,
        nonce,
        finalize_url,
        Some(json!({"csr": csr_b64})),
    );
    let (status, body, headers) =
        http_post_jws(client, &format!("{}{fin_path}", server.base_url), &jws).await?;
    if status != 200 {
        return Err(format!("finalize {status}: {body}"));
    }
    let next_nonce = nonce_hdr(&headers).ok();
    // RFC 8555 §7.4: the finalize response IS the order object. If the server
    // has already moved the order to "valid" synchronously, skip the poll loop
    // entirely — no sleep needed. This server finalizes certificates in-line so
    // "valid" is always present here; the loop below only fires as a fallback.
    if body["status"].as_str() == Some("valid") {
        let cert_url = body["certificate"]
            .as_str()
            .ok_or_else(|| "no certificate URL in finalize response".to_string())?
            .to_string();
        return Ok((cert_url, next_nonce));
    }

    let mut cur_nonce = next_nonce;
    let order_path = order_url.trim_start_matches(&server.base_url);
    let deadline = Instant::now() + std::time::Duration::from_secs(30);
    loop {
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        if Instant::now() > deadline {
            return Err("timed out waiting for order valid".to_string());
        }
        let poll_nonce = if let Some(n) = cur_nonce.take() {
            n
        } else {
            fetch_nonce(client, &nonce_url).await?
        };
        let jws = worker
            .key
            .jws_kid(account_url, &poll_nonce, order_url, None);
        let (_, body, headers) =
            http_post_jws(client, &format!("{}{order_path}", server.base_url), &jws).await?;
        cur_nonce = nonce_hdr(&headers).ok();
        match body["status"].as_str() {
            Some("valid") => {
                let cert_url = body["certificate"]
                    .as_str()
                    .ok_or_else(|| "no certificate URL in valid order".to_string())?
                    .to_string();
                return Ok((cert_url, cur_nonce));
            }
            Some("invalid") => {
                return Err(format!("order invalid after finalize: {}", body["error"]))
            }
            _ => continue,
        }
    }
}

fn verify_cert_san(pem: &str, domain: &str) -> Result<(), String> {
    use synta::{Decoder, Encoding};
    use synta_certificate::Certificate;
    let ders = synta_certificate::pem_to_der(pem.as_bytes());
    let leaf = ders.first().ok_or("no cert in PEM")?;
    let cert: Certificate = Decoder::new(leaf, Encoding::Der)
        .decode()
        .map_err(|e| format!("parse cert: {e}"))?;
    let found = cert
        .subject_alt_names()
        .iter()
        .any(|(tag, val)| *tag == 2 && String::from_utf8_lossy(val) == domain);
    if found {
        Ok(())
    } else {
        Err(format!("SAN '{domain}' not in cert"))
    }
}

// ── Full issuance flow ─────────────────────────────────────────────────────────

async fn run_issuance(
    worker: &mut WorkerState,
    server: &BenchServer,
    client: &HyperClient,
    args: &Args,
    request_id: usize,
) -> IssuanceTiming {
    let wid = worker.id;

    // ── Account (first issuance per worker only) ───────────────────────────────
    // create_account returns (account_url, next_nonce) so the nonce from the
    // new-account response can be threaded directly into the new-order request,
    // eliminating the HEAD /new-nonce that would otherwise precede it.
    let nonce_url = format!("{}/acme/new-nonce", server.base_url);
    let (account_us, nonce) = if worker.account_url.is_none() {
        let t = Instant::now();
        match create_account(worker, server, client).await {
            Ok((url, nonce)) => {
                // Register dns-persist-01 TXT record now that we have the account URI.
                if args.challenge == "dns-persist-01" {
                    if let Some(ref dns) = server.dns {
                        let base = worker.domain.trim_start_matches("*.");
                        let qname = format!("_validation-persist.{}.", base);
                        let txt = if args.wildcard {
                            format!("acme-bench.test; accounturi={}; policy=wildcard", url)
                        } else {
                            format!("acme-bench.test; accounturi={}", url)
                        };
                        dns.set_record(&qname, &txt).await;
                    }
                }
                worker.account_url = Some(url);
                (t.elapsed().as_micros() as u64, nonce)
            }
            Err(e) => return IssuanceTiming::failed(wid, request_id, format!("account: {e}")),
        }
    } else {
        // Reuse the nonce carried from the previous issuance's last response.
        // Fall back to HEAD only if no nonce is available (first time or after error).
        let n = if let Some(n) = worker.last_nonce.take() {
            n
        } else {
            match fetch_nonce(client, &nonce_url).await {
                Ok(n) => n,
                Err(e) => return IssuanceTiming::failed(wid, request_id, format!("nonce: {e}")),
            }
        };
        (0, n)
    };
    let account_url = worker.account_url.clone().unwrap();

    // ── New order (uses nonce from account creation or previous issuance) ───────
    let t_total = Instant::now();
    let t = Instant::now();
    let (order_url, authz_url, fin_url, nonce) =
        match new_order(worker, server, client, &account_url, &nonce).await {
            Ok(v) => v,
            Err(e) => return IssuanceTiming::failed(wid, request_id, format!("new-order: {e}")),
        };
    let order_us = t.elapsed().as_micros() as u64;

    // ── Get authorization (uses nonce from new-order response) ─────────────────
    let t = Instant::now();
    let (chall_url, token, nonce) = match get_authz(
        worker,
        server,
        client,
        &account_url,
        &authz_url,
        &args.challenge,
        &nonce,
    )
    .await
    {
        Ok(v) => v,
        Err(e) => return IssuanceTiming::failed(wid, request_id, format!("authz: {e}")),
    };
    let authz_us = t.elapsed().as_micros() as u64;

    // ── Register http-01 challenge response ────────────────────────────────────
    // dns-persist-01 TXT record was registered once after account creation.
    if args.challenge == "http-01" {
        if let (Some(ref store), Some(ref tok)) = (&server.challenge_store, &token) {
            let key_auth = format!("{}.{}", tok, worker.key.thumbprint);
            store.write().await.insert(tok.clone(), key_auth);
        }
    }

    // ── Trigger challenge (uses nonce from authz response) → poll until ready ──
    let ctx = IssuanceCtx {
        worker,
        server,
        client,
        account_url: &account_url,
    };
    let t = Instant::now();
    let nonce = match respond_and_poll(&ctx, &chall_url, &order_url, &nonce, args.poll_ms).await {
        Ok(n) => n,
        Err(e) => return IssuanceTiming::failed(wid, request_id, format!("challenge: {e}")),
    };
    let challenge_us = t.elapsed().as_micros() as u64;

    // ── Finalize (uses nonce from last poll response) → cert URL ───────────────
    let t = Instant::now();
    let (cert_url, leftover_nonce) =
        match finalize_and_poll(&ctx, &order_url, &fin_url, &args.key_type, &nonce).await {
            Ok(v) => v,
            Err(e) => return IssuanceTiming::failed(wid, request_id, format!("finalize: {e}")),
        };
    // Store the nonce for the next issuance (cert download is a GET — no nonce used).
    worker.last_nonce = leftover_nonce;
    let finalize_us = t.elapsed().as_micros() as u64;

    // ── Download certificate ───────────────────────────────────────────────────
    let t = Instant::now();
    let (dl_status, dl_body, _) = match http_get(client, &cert_url).await {
        Ok(v) => v,
        Err(e) => return IssuanceTiming::failed(wid, request_id, format!("download: {e}")),
    };
    if dl_status != 200 {
        return IssuanceTiming::failed(wid, request_id, format!("cert download {dl_status}"));
    }
    let download_us = t.elapsed().as_micros() as u64;

    // ── Optional SAN verification ──────────────────────────────────────────────
    if args.verify_cert {
        if let Ok(pem) = String::from_utf8(dl_body) {
            if let Err(e) = verify_cert_san(&pem, &worker.domain) {
                return IssuanceTiming::failed(wid, request_id, format!("verify: {e}"));
            }
        }
    }

    // ── Clean up http-01 token ─────────────────────────────────────────────────
    if let (Some(ref store), Some(ref tok)) = (&server.challenge_store, &token) {
        store.write().await.remove(tok);
    }

    let total_us = t_total.elapsed().as_micros() as u64;
    IssuanceTiming {
        worker_id: wid,
        request_id,
        success: true,
        error: None,
        account_us,
        order_us,
        authz_us,
        challenge_us,
        finalize_us,
        download_us,
        total_us,
    }
}

// ── Statistics ─────────────────────────────────────────────────────────────────

/// p-th percentile of a pre-sorted slice, returned in milliseconds.
fn pct_ms(sorted: &[u64], p: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let idx = ((sorted.len() as f64 * p / 100.0).ceil() as usize).saturating_sub(1);
    sorted[idx.min(sorted.len() - 1)] as f64 / 1000.0
}

fn mean_ms(v: &[u64]) -> f64 {
    if v.is_empty() {
        return 0.0;
    }
    v.iter().sum::<u64>() as f64 / v.len() as f64 / 1000.0
}

fn min_ms(v: &[u64]) -> f64 {
    v.iter().min().copied().unwrap_or(0) as f64 / 1000.0
}
fn max_ms(v: &[u64]) -> f64 {
    v.iter().max().copied().unwrap_or(0) as f64 / 1000.0
}

// ── Report output ──────────────────────────────────────────────────────────────

fn text_report(args: &Args, timings: &[IssuanceTiming], bench_wall: f64, mem: &MemStats) {
    let ok: Vec<&IssuanceTiming> = timings.iter().filter(|t| t.success).collect();
    let err: Vec<&IssuanceTiming> = timings.iter().filter(|t| !t.success).collect();
    let n_ok = ok.len();
    let n_err = err.len();
    let tput = if bench_wall > 0.0 {
        n_ok as f64 / bench_wall
    } else {
        0.0
    };

    println!("\nACME Benchmark");
    let effective_pool = if args.db.contains(":memory:") {
        1
    } else {
        args.pool_connections.max(1)
    };
    println!(
        "  challenge={}  clients={}  requests={}  key={}  ca={}  db={}  pool={}{}",
        args.challenge,
        args.clients,
        args.requests,
        args.key_type,
        args.ca_key_type,
        args.db,
        effective_pool,
        if args.wildcard { "  wildcard=true" } else { "" },
    );
    if args.warmup > 0 {
        println!("  Warmup: {} issuances discarded", args.warmup);
    }

    println!(
        "\nResults  ({n_ok} ok / {n_err} err out of {}):",
        n_ok + n_err
    );
    println!("  Throughput:  {tput:.1} issuances/sec   wall: {bench_wall:.3} s");

    if n_ok > 0 {
        let mut totals: Vec<u64> = ok.iter().map(|t| t.total_us).collect();
        totals.sort_unstable();
        println!("\n  End-to-end latency, ms  (account creation not included in total):");
        println!(
            "    mean={:.1}   p50={:.1}   p95={:.1}   p99={:.1}   max={:.1}   min={:.1}",
            mean_ms(&totals),
            pct_ms(&totals, 50.0),
            pct_ms(&totals, 95.0),
            pct_ms(&totals, 99.0),
            max_ms(&totals),
            min_ms(&totals),
        );

        let acct_v: Vec<u64> = ok
            .iter()
            .filter(|t| t.account_us > 0)
            .map(|t| t.account_us)
            .collect();
        let order_v: Vec<u64> = ok.iter().map(|t| t.order_us).collect();
        let authz_v: Vec<u64> = ok.iter().map(|t| t.authz_us).collect();
        let chall_v: Vec<u64> = ok.iter().map(|t| t.challenge_us).collect();
        let fin_v: Vec<u64> = ok.iter().map(|t| t.finalize_us).collect();
        let dl_v: Vec<u64> = ok.iter().map(|t| t.download_us).collect();

        println!("\n  Phase breakdown, mean ms:");
        if !acct_v.is_empty() {
            println!("    new-account (1st/worker):  {:.1}", mean_ms(&acct_v));
        }
        println!("    new-order:                 {:.1}", mean_ms(&order_v));
        println!("    authz fetch:               {:.1}", mean_ms(&authz_v));
        println!("    challenge → validated:     {:.1}", mean_ms(&chall_v));
        println!("    finalize → valid:          {:.1}", mean_ms(&fin_v));
        println!("    cert download:             {:.1}", mean_ms(&dl_v));
    }

    if !err.is_empty() {
        let mut counts: HashMap<String, usize> = HashMap::new();
        for t in &err {
            *counts
                .entry(t.error.clone().unwrap_or_default())
                .or_insert(0) += 1;
        }
        let mut sorted: Vec<_> = counts.into_iter().collect();
        sorted.sort_by_key(|a| Reverse(a.1));
        println!("\n  Errors ({n_err}):");
        for (msg, count) in sorted.iter().take(10) {
            println!("    [{count}] {msg}");
        }
    }

    // ── Memory section ─────────────────────────────────────────────────────────
    {
        let s = &mem.start;
        let r = &mem.server_ready;
        let b = &mem.after_bench;
        let n = mem.total_issuances;

        let server_overhead = b.live.saturating_sub(s.live);
        let issuance_growth = b.live.saturating_sub(r.live);
        let issuance_alloc = b.total_bytes.saturating_sub(r.total_bytes);
        let per_iss_growth_kib = if n > 0 {
            kib(issuance_growth) / n as f64
        } else {
            0.0
        };
        let per_iss_alloc_mib = if n > 0 {
            mib(issuance_alloc) / n as f64
        } else {
            0.0
        };

        println!("\n  Heap (allocator counters):");
        println!("    process start:    {:7.1} MiB  live", mib(s.live));
        println!(
            "    server ready:     {:7.1} MiB  live   (server overhead: +{:.1} MiB)",
            mib(r.live),
            mib(server_overhead),
        );
        println!(
            "    after {:4} iss.:  {:7.1} MiB  live   (issuance growth: +{:.1} MiB, {:.1} KiB/iss.)",
            n,
            mib(b.live),
            mib(issuance_growth),
            per_iss_growth_kib,
        );
        println!(
            "    peak live:        {:7.1} MiB         (high-water mark during issuances)",
            mib(b.peak)
        );
        println!(
            "    alloc pressure:   {:7.1} MiB  total  ({:.3} MiB/iss. requested, incl. freed)",
            mib(issuance_alloc),
            per_iss_alloc_mib,
        );
    }

    println!();
}

fn json_report(args: &Args, timings: &[IssuanceTiming], bench_wall: f64, mem: &MemStats) {
    let ok: Vec<&IssuanceTiming> = timings.iter().filter(|t| t.success).collect();
    let n_ok = ok.len();
    let n_err = timings.len() - n_ok;
    let tput = if bench_wall > 0.0 {
        n_ok as f64 / bench_wall
    } else {
        0.0
    };
    let mut totals: Vec<u64> = ok.iter().map(|t| t.total_us).collect();
    totals.sort_unstable();

    let n = mem.total_issuances;
    let issuance_growth = mem.after_bench.live.saturating_sub(mem.server_ready.live);
    let issuance_alloc = mem
        .after_bench
        .total_bytes
        .saturating_sub(mem.server_ready.total_bytes);

    let out = json!({
        "config": {
            "clients": args.clients, "requests": args.requests, "warmup": args.warmup,
            "challenge": args.challenge, "key_type": args.key_type,
            "ca_key_type": args.ca_key_type, "db": args.db, "wildcard": args.wildcard,
            "pool_connections": if args.db.contains(":memory:") { 1 } else { args.pool_connections.max(1) },
        },
        "summary": {
            "ok": n_ok, "err": n_err, "total": n_ok + n_err,
            "throughput_per_sec": (tput * 10.0).round() / 10.0,
            "wall_sec": (bench_wall * 1000.0).round() / 1000.0,
            "total_latency_ms": {
                "mean": mean_ms(&totals), "p50": pct_ms(&totals, 50.0),
                "p95": pct_ms(&totals, 95.0), "p99": pct_ms(&totals, 99.0),
                "max": max_ms(&totals), "min": min_ms(&totals),
            },
        },
        "phases": {
            "new_order_ms":    mean_ms(&ok.iter().map(|t| t.order_us).collect::<Vec<_>>()),
            "authz_ms":        mean_ms(&ok.iter().map(|t| t.authz_us).collect::<Vec<_>>()),
            "challenge_ms":    mean_ms(&ok.iter().map(|t| t.challenge_us).collect::<Vec<_>>()),
            "finalize_ms":     mean_ms(&ok.iter().map(|t| t.finalize_us).collect::<Vec<_>>()),
            "download_ms":     mean_ms(&ok.iter().map(|t| t.download_us).collect::<Vec<_>>()),
        },
        "memory": {
            // All values in bytes; divide by 1 MiB (1 048 576) for MiB.
            "start_live_bytes":         mem.start.live,
            "server_ready_live_bytes":  mem.server_ready.live,
            "after_bench_live_bytes":   mem.after_bench.live,
            "peak_live_bytes":          mem.after_bench.peak,
            "server_overhead_bytes":    mem.after_bench.live.saturating_sub(mem.start.live),
            "issuance_growth_bytes":    issuance_growth,
            "per_issuance_growth_bytes": if n > 0 { issuance_growth / n as u64 } else { 0 },
            "issuance_alloc_bytes":     issuance_alloc,
            "per_issuance_alloc_bytes": if n > 0 { issuance_alloc / n as u64 } else { 0 },
            "total_alloc_count":        mem.after_bench.total_count,
        },
        "raw": timings.iter().map(|t| json!({
            "worker_id": t.worker_id, "request_id": t.request_id,
            "success": t.success, "error": t.error,
            "account_us": t.account_us, "order_us": t.order_us,
            "authz_us": t.authz_us, "challenge_us": t.challenge_us,
            "finalize_us": t.finalize_us, "download_us": t.download_us,
            "total_us": t.total_us,
        })).collect::<Vec<_>>(),
    });
    println!("{}", serde_json::to_string_pretty(&out).unwrap());
}

// ── main ───────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    // `cargo bench` injects `--bench` into argv; strip it before clap sees it.
    let raw: Vec<String> = std::env::args().filter(|a| a != "--bench").collect();
    let args = Args::parse_from(raw);

    // Suppress server tracing so the benchmark output is clean.
    // Set RUST_LOG=debug to see request traces.
    // Always write logs to stderr so that --output json produces clean stdout.
    let _ = tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(std::env::var("RUST_LOG").unwrap_or_else(|_| "error".to_string()))
        .try_init();

    // Validate arguments.
    match args.challenge.as_str() {
        "http-01" | "dns-persist-01" => {}
        other => {
            eprintln!("error: unknown challenge '{other}'. Valid: http-01, dns-persist-01");
            std::process::exit(1);
        }
    }
    if args.wildcard && args.challenge != "dns-persist-01" {
        eprintln!("error: --wildcard requires --challenge dns-persist-01");
        std::process::exit(1);
    }
    if args.clients == 0 || args.requests == 0 {
        eprintln!("error: --clients and --requests must be > 0");
        std::process::exit(1);
    }

    eprintln!(
        "Starting server (ca-key={}, db={})…",
        args.ca_key_type, args.db
    );
    let mem_start = alloc_snapshot();
    let server = Arc::new(start_server(&args).await);
    let mem_server_ready = alloc_snapshot();
    eprintln!("Server ready at {}", server.base_url);

    let total = args.warmup + args.requests;
    eprintln!(
        "Running {} warmup + {} benchmark issuances with {} concurrent workers…",
        args.warmup, args.requests, args.clients,
    );

    // Work-queue model: pre-fill a channel with `total` request IDs,
    // drain them with `clients` concurrent worker tasks.
    let (tx, rx) = tokio::sync::mpsc::channel::<usize>(total + 1);
    for i in 0..total {
        tx.send(i).await.unwrap();
    }
    drop(tx);
    let rx = Arc::new(tokio::sync::Mutex::new(rx));

    let (result_tx, mut result_rx) = tokio::sync::mpsc::channel::<IssuanceTiming>(total + 1);

    // Atomics for measuring only the benchmark window (excluding warmup).
    let first_bench_us = Arc::new(AtomicU64::new(u64::MAX));
    let last_bench_us = Arc::new(AtomicU64::new(0));
    let t_epoch = Instant::now();

    reset_peak();
    let mut handles = Vec::new();
    for worker_id in 0..args.clients {
        let args = args.clone();
        let server = Arc::clone(&server);
        let rx = Arc::clone(&rx);
        let result_tx = result_tx.clone();
        let first_us = Arc::clone(&first_bench_us);
        let last_us = Arc::clone(&last_bench_us);

        handles.push(tokio::spawn(async move {
            let mut worker = WorkerState::new(worker_id, &args);
            let client = new_http_client();
            loop {
                let request_id = {
                    let mut r = rx.lock().await;
                    match r.recv().await {
                        Some(id) => id,
                        None => break,
                    }
                };
                let is_warmup = request_id < args.warmup;
                let t_start_us = t_epoch.elapsed().as_micros() as u64;
                let timing = run_issuance(&mut worker, &server, &client, &args, request_id).await;
                let t_end_us = t_epoch.elapsed().as_micros() as u64;

                if !is_warmup {
                    first_us.fetch_min(t_start_us, Ordering::Relaxed);
                    last_us.fetch_max(t_end_us, Ordering::Relaxed);
                }
                let _ = result_tx.send(timing).await;
            }
        }));
    }
    drop(result_tx);

    let mut all: Vec<IssuanceTiming> = Vec::with_capacity(total);
    while let Some(t) = result_rx.recv().await {
        all.push(t);
    }
    for h in handles {
        h.await.unwrap();
    }
    let mem_after_bench = alloc_snapshot();
    let mem = MemStats {
        start: mem_start,
        server_ready: mem_server_ready,
        after_bench: mem_after_bench,
        total_issuances: args.warmup + args.requests,
    };

    // Compute benchmark wall time from the first non-warmup start to the last end.
    let f = first_bench_us.load(Ordering::Relaxed);
    let l = last_bench_us.load(Ordering::Relaxed);
    let bench_wall = if l > f {
        (l - f) as f64 / 1_000_000.0
    } else {
        t_epoch.elapsed().as_secs_f64()
    };

    // Separate warmup results out; warmup IDs are 0..warmup-1.
    let bench_timings: Vec<IssuanceTiming> = all
        .into_iter()
        .filter(|t| t.request_id >= args.warmup)
        .collect();

    match args.output.as_str() {
        "json" => json_report(&args, &bench_timings, bench_wall, &mem),
        _ => text_report(&args, &bench_timings, bench_wall, &mem),
    }
}
