//! MTC cosigners store interop tests.
//!
//! Verifies that akamu can consume and validate MTC tlog endpoints from
//! external cosigners stores (Google Chrome Testing and Validation Trust
//! Store, Geomys mirroring cosigner) and from a locally-spawned akamu
//! instance using the same verification harness.
//!
//! External tests are gated behind `#[ignore]` (they require network access):
//!
//! ```shell
//! cargo test --test mtc_cosigners_interop -- --ignored
//! ```

mod common;

use serde::Deserialize;
use synta_certificate::DataHasher;

// ── Constants ────────────────────────────────────────────────────────────────

const GOOGLE_COSIGNERS_URL: &str = "https://www.gstatic.com/mtcs/cosigners/v1/cosigners.json";
const GEOMYS_MIRROR_URL: &str = "https://witness.navigli.sunlight.geomys.org/mirror/mirror.v0.json";

// ── Google cosigners store types ─────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct CosignersStore {
    timestamp: Option<String>,
    version: String,
    operators: Vec<Operator>,
    #[serde(default)]
    issuers: Vec<Signer>,
    #[serde(default)]
    mirrors: Vec<Signer>,
}

#[derive(Debug, Deserialize)]
struct Operator {
    name: String,
    #[allow(dead_code)]
    email: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
struct Signer {
    friendly_name: String,
    base_id: String,
    base_url: String,
    #[serde(default)]
    r#type: Option<String>,
    #[serde(default)]
    realm: Option<String>,
    key_sha256: String,
    #[serde(default)]
    max_cert_lifetime_seconds: Option<u64>,
}

// ── Geomys mirror config types ───────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct MirrorConfig {
    name: String,
    #[allow(dead_code)]
    submission_url: Option<String>,
    monitoring_url: String,
    #[allow(dead_code)]
    verifier_keys: Option<Vec<String>>,
    key: String,
    cosigner_id: String,
}

// ── Normalized endpoint ──────────────────────────────────────────────────────

#[derive(Debug, Clone)]
enum CosignerType {
    Issuer,
    Mirror,
}

#[derive(Debug, Clone)]
struct CosignerEndpoint {
    name: String,
    base_url: String,
    cosigner_id: String,
    key_sha256: Option<String>,
    cosigner_type: CosignerType,
}

impl CosignerEndpoint {
    fn from_google_signer(s: &Signer) -> Self {
        let cosigner_type = match s.r#type.as_deref() {
            Some("MIRROR") => CosignerType::Mirror,
            _ => CosignerType::Issuer,
        };
        CosignerEndpoint {
            name: s.friendly_name.clone(),
            base_url: s.base_url.trim_end_matches('/').to_string(),
            cosigner_id: s.base_id.clone(),
            key_sha256: Some(s.key_sha256.clone()),
            cosigner_type,
        }
    }

    fn from_geomys_mirror(m: &MirrorConfig) -> Self {
        CosignerEndpoint {
            name: m.name.clone(),
            base_url: m.monitoring_url.trim_end_matches('/').to_string(),
            cosigner_id: m.cosigner_id.clone(),
            key_sha256: None,
            cosigner_type: CosignerType::Mirror,
        }
    }
}

// ── Verification harness ─────────────────────────────────────────────────────

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;

#[derive(Debug)]
struct CheckResult {
    check_name: &'static str,
    passed: bool,
    detail: String,
}

impl CheckResult {
    fn pass(name: &'static str, detail: impl Into<String>) -> Self {
        CheckResult {
            check_name: name,
            passed: true,
            detail: detail.into(),
        }
    }

    fn fail(name: &'static str, detail: impl Into<String>) -> Self {
        CheckResult {
            check_name: name,
            passed: false,
            detail: detail.into(),
        }
    }
}

fn assert_all_passed(endpoint_name: &str, results: &[CheckResult]) {
    let failures: Vec<_> = results.iter().filter(|r| !r.passed).collect();
    if !failures.is_empty() {
        let msg = failures
            .iter()
            .map(|f| format!("  FAIL [{}]: {}", f.check_name, f.detail))
            .collect::<Vec<_>>()
            .join("\n");
        panic!(
            "Cosigner '{}' failed {} check(s):\n{}",
            endpoint_name,
            failures.len(),
            msg
        );
    }
}

async fn verify_issuer_tlog(
    client: &reqwest::Client,
    endpoint: &CosignerEndpoint,
) -> Vec<CheckResult> {
    let mut results = Vec::new();

    // Check 1: Fetch checkpoint
    let checkpoint_url = format!("{}/checkpoint", endpoint.base_url);
    let resp = match client.get(&checkpoint_url).send().await {
        Ok(r) => r,
        Err(e) => {
            results.push(CheckResult::fail(
                "checkpoint_fetch",
                format!("HTTP error: {e}"),
            ));
            return results;
        }
    };

    if resp.status() != 200 {
        results.push(CheckResult::fail(
            "checkpoint_fetch",
            format!("expected 200, got {}", resp.status()),
        ));
        return results;
    }
    results.push(CheckResult::pass("checkpoint_fetch", "HTTP 200"));

    let body = match resp.text().await {
        Ok(b) => b,
        Err(e) => {
            results.push(CheckResult::fail(
                "checkpoint_parse",
                format!("body read error: {e}"),
            ));
            return results;
        }
    };

    // Check 2: Parse signed-note checkpoint
    let lines: Vec<&str> = body.lines().collect();
    if lines.len() < 4 {
        results.push(CheckResult::fail(
            "checkpoint_parse",
            format!("expected >= 4 lines, got {}", lines.len()),
        ));
        return results;
    }

    let origin = lines[0];
    let tree_size: u64 = match lines[1].parse() {
        Ok(n) => n,
        Err(e) => {
            results.push(CheckResult::fail(
                "checkpoint_parse",
                format!("tree_size parse error: {e} (line: '{}')", lines[1]),
            ));
            return results;
        }
    };

    if tree_size == 0 {
        results.push(CheckResult::fail("checkpoint_parse", "tree_size is 0"));
        return results;
    }

    let root_b64 = lines[2];
    let root = match BASE64.decode(root_b64) {
        Ok(r) if r.len() == 32 => r,
        Ok(r) => {
            results.push(CheckResult::fail(
                "checkpoint_parse",
                format!("root hash length {} != 32", r.len()),
            ));
            return results;
        }
        Err(e) => {
            results.push(CheckResult::fail(
                "checkpoint_parse",
                format!("root base64 decode error: {e}"),
            ));
            return results;
        }
    };

    let has_sig = body.contains('\u{2014}');
    if !has_sig {
        results.push(CheckResult::fail(
            "checkpoint_parse",
            "no em-dash signature line",
        ));
        return results;
    }

    results.push(CheckResult::pass(
        "checkpoint_parse",
        format!(
            "origin={origin}, tree_size={tree_size}, root={}...",
            native_ossl::util::hex_encode(&root[..4])
        ),
    ));

    // Check 3: Fetch a level-0 tile
    let tile_width = std::cmp::min(tree_size, 256) as usize;
    let tile_url = format!("{}/tile/0/000.p/{tile_width}", endpoint.base_url);
    match client.get(&tile_url).send().await {
        Ok(resp) if resp.status() == 200 => match resp.bytes().await {
            Ok(bytes) if bytes.len() == tile_width * 32 => {
                results.push(CheckResult::pass(
                    "tile_fetch",
                    format!("{tile_width} hashes, {} bytes", bytes.len()),
                ));
            }
            Ok(bytes) => {
                results.push(CheckResult::fail(
                    "tile_fetch",
                    format!(
                        "expected {} bytes ({tile_width} * 32), got {}",
                        tile_width * 32,
                        bytes.len()
                    ),
                ));
            }
            Err(e) => {
                results.push(CheckResult::fail(
                    "tile_fetch",
                    format!("body read error: {e}"),
                ));
            }
        },
        Ok(resp) => {
            results.push(CheckResult::fail(
                "tile_fetch",
                format!("expected 200, got {}", resp.status()),
            ));
        }
        Err(e) => {
            results.push(CheckResult::fail("tile_fetch", format!("HTTP error: {e}")));
        }
    }

    // Check 4: Fetch cosignature
    let cosig_url = format!("{}/cosignature", endpoint.base_url);
    match client.get(&cosig_url).send().await {
        Ok(resp) if resp.status() == 200 => match resp.text().await {
            Ok(cosig_body) => {
                if let Some(sig_line) = cosig_body.lines().find(|l| l.starts_with('\u{2014}')) {
                    if let Some(b64_part) = sig_line.splitn(3, ' ').nth(2) {
                        match BASE64.decode(b64_part) {
                            Ok(blob) if blob.len() >= 12 => {
                                let ts = u64::from_be_bytes(blob[4..12].try_into().unwrap());
                                if ts > 1_577_836_800 {
                                    results.push(CheckResult::pass(
                                        "cosignature_fetch",
                                        format!("blob {} bytes, timestamp={ts}", blob.len()),
                                    ));
                                } else {
                                    results.push(CheckResult::fail(
                                        "cosignature_fetch",
                                        format!("timestamp {ts} too old"),
                                    ));
                                }
                            }
                            Ok(blob) => {
                                results.push(CheckResult::fail(
                                    "cosignature_fetch",
                                    format!("blob too short: {} bytes", blob.len()),
                                ));
                            }
                            Err(e) => {
                                results.push(CheckResult::fail(
                                    "cosignature_fetch",
                                    format!("base64 decode error: {e}"),
                                ));
                            }
                        }
                    } else {
                        results.push(CheckResult::fail(
                            "cosignature_fetch",
                            "em-dash line missing base64 part",
                        ));
                    }
                } else {
                    results.push(CheckResult::fail(
                        "cosignature_fetch",
                        "no em-dash signature line",
                    ));
                }
            }
            Err(e) => {
                results.push(CheckResult::fail(
                    "cosignature_fetch",
                    format!("body read error: {e}"),
                ));
            }
        },
        Ok(resp) => {
            results.push(CheckResult::fail(
                "cosignature_fetch",
                format!("expected 200, got {}", resp.status()),
            ));
        }
        Err(e) => {
            results.push(CheckResult::fail(
                "cosignature_fetch",
                format!("HTTP error: {e}"),
            ));
        }
    }

    results
}

async fn verify_mirror_metadata(
    _client: &reqwest::Client,
    endpoint: &CosignerEndpoint,
    raw_key_b64: Option<&str>,
) -> Vec<CheckResult> {
    let mut results = Vec::new();

    if let Some(key_b64) = raw_key_b64 {
        match BASE64.decode(key_b64) {
            Ok(spki_der) => {
                let hasher = synta_certificate::default_data_hasher();
                match hasher.hash_data("sha256", &spki_der) {
                    Ok(hash) => {
                        let computed_hex = native_ossl::util::hex_encode(&hash);
                        if let Some(expected) = &endpoint.key_sha256 {
                            if computed_hex == *expected {
                                results.push(CheckResult::pass(
                                    "key_hash_match",
                                    format!("SHA-256 matches: {}", &computed_hex[..16]),
                                ));
                            } else {
                                results.push(CheckResult::fail(
                                    "key_hash_match",
                                    format!(
                                        "mismatch: computed={}, expected={}",
                                        &computed_hex[..16],
                                        &expected[..16]
                                    ),
                                ));
                            }
                        } else {
                            results.push(CheckResult::pass(
                                "key_hash_match",
                                "no expected hash to compare (skipped)",
                            ));
                        }
                    }
                    Err(e) => {
                        results.push(CheckResult::fail(
                            "key_hash_match",
                            format!("hash error: {e}"),
                        ));
                    }
                }
            }
            Err(e) => {
                results.push(CheckResult::fail(
                    "key_hash_match",
                    format!("base64 decode error: {e}"),
                ));
            }
        }
    }

    if !endpoint.cosigner_id.is_empty() {
        results.push(CheckResult::pass(
            "cosigner_id_present",
            format!("OID: {}", endpoint.cosigner_id),
        ));
    } else {
        results.push(CheckResult::fail(
            "cosigner_id_present",
            "empty cosigner_id",
        ));
    }

    results
}

// ── External interop tests (require network) ─────────────────────────────────

#[tokio::test]
#[ignore]
async fn google_cosigners_store() {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .unwrap();

    let resp = client
        .get(GOOGLE_COSIGNERS_URL)
        .send()
        .await
        .expect("failed to fetch Google cosigners store");
    assert_eq!(resp.status(), 200, "Google store returned non-200");

    let store: CosignersStore = resp
        .json()
        .await
        .expect("failed to parse Google cosigners store JSON");

    eprintln!(
        "Google store v{}: {} issuers, {} mirrors, {} operators",
        store.version,
        store.issuers.len(),
        store.mirrors.len(),
        store.operators.len(),
    );

    for signer in &store.issuers {
        let ep = CosignerEndpoint::from_google_signer(signer);
        eprintln!("  Testing issuer: {} ({})", ep.name, ep.base_url);
        let results = verify_issuer_tlog(&client, &ep).await;
        for r in &results {
            eprintln!(
                "    [{}] {}: {}",
                if r.passed { "PASS" } else { "FAIL" },
                r.check_name,
                r.detail,
            );
        }
        assert_all_passed(&ep.name, &results);
    }

    for signer in &store.mirrors {
        let ep = CosignerEndpoint::from_google_signer(signer);
        eprintln!("  Testing mirror: {} ({})", ep.name, ep.base_url);
        let results = verify_mirror_metadata(&client, &ep, None).await;
        for r in &results {
            eprintln!(
                "    [{}] {}: {}",
                if r.passed { "PASS" } else { "FAIL" },
                r.check_name,
                r.detail,
            );
        }
        assert_all_passed(&ep.name, &results);
    }
}

#[tokio::test]
#[ignore]
async fn geomys_mirror() {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .unwrap();

    let resp = client
        .get(GEOMYS_MIRROR_URL)
        .send()
        .await
        .expect("failed to fetch Geomys mirror config");
    assert_eq!(resp.status(), 200, "Geomys mirror config returned non-200");

    let mirror: MirrorConfig = resp
        .json()
        .await
        .expect("failed to parse Geomys mirror config JSON");

    eprintln!(
        "Geomys mirror: name={}, cosigner_id={}, monitoring={}",
        mirror.name, mirror.cosigner_id, mirror.monitoring_url,
    );

    let ep = CosignerEndpoint::from_geomys_mirror(&mirror);
    let results = verify_mirror_metadata(&client, &ep, Some(&mirror.key)).await;
    for r in &results {
        eprintln!(
            "  [{}] {}: {}",
            if r.passed { "PASS" } else { "FAIL" },
            r.check_name,
            r.detail,
        );
    }
    assert_all_passed(&ep.name, &results);
}

// ── Akamu self-test (local, no network) ──────────────────────────────────────

#[tokio::test]
#[cfg(feature = "test-utils")]
async fn akamu_self_test() {
    use std::net::SocketAddr;
    use std::sync::Arc;

    use synta_certificate::BackendPrivateKey;
    use synta_mtc::crypto::HashAlgorithm;
    use tokio::net::TcpListener;

    use akamu::config::{
        CaConfig, Config, DatabaseConfig, MtcConfig, MtcSigningKeyConfig, ServerConfig,
    };
    use akamu::mtc::log;
    use akamu::state::{AppStateBuilder, CaState, MtcState};
    use akamu::{ca, db, routes};

    let std_l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    std_l.set_nonblocking(true).unwrap();
    let port = std_l.local_addr().unwrap().port();
    let listener = TcpListener::from_std(std_l).unwrap();
    let base_url = format!("http://127.0.0.1:{port}");

    let dir = tempfile::TempDir::new().unwrap();
    let mtc_log_path = dir.path().join("mtc.log").to_string_lossy().into_owned();
    let mtc_key_file = dir.path().join("mtc.key").to_string_lossy().into_owned();

    let config = Arc::new(Config {
        listen_addr: "127.0.0.1:0".into(),
        base_url: base_url.clone(),
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
            common_name: "Interop Self-Test CA".into(),
            organization: "Test".into(),
            ca_validity_years: 10,
            crl_next_update_secs: 86400,
            enforce_validity_cap: false,
            require_encrypted_key: false,
            key_password_file: None,
            mtc: None,
            signer: None,
            default_linter: None,
        }],
        mtc: Some(MtcConfig {
            log_path: mtc_log_path.clone(),
            enabled: true,
            signing_key: Some(MtcSigningKeyConfig {
                key_file: mtc_key_file.clone(),
                key_type: "ed25519".into(),
                hash_alg: "sha256".into(),
            }),
            checkpoint_interval_secs: 3600,
            cosigners: vec![],
            landmark_interval_secs: 86400,
            max_active_landmarks: 100,
            checkpoint_retention_count: 1000,
            hash_alg: "sha256".into(),
            log_number: 1,
            tree_minimum_index: None,
            trust_anchor_id: Some("32473.2".into()),
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
    let ca_aki_bytes = ca::init::compute_aki_from_spki(&ca_spki_der).unwrap_or_default();

    db::install_drivers();
    let db_conn = db::open("sqlite::memory:", 1, false).await.unwrap();

    let mtc_key = BackendPrivateKey::generate_ed25519().unwrap();
    let mtc_key_pem = mtc_key.to_pem(None).unwrap();
    std::fs::write(&mtc_key_file, &mtc_key_pem).unwrap();

    let raw_log = log::open_or_create(&mtc_log_path, HashAlgorithm::Sha256).unwrap();
    let shared_log = Arc::new(tokio::sync::Mutex::new(raw_log));

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
        mtc: Arc::new(MtcState {
            log: Some(shared_log),
            algorithm: HashAlgorithm::Sha256,
            signing_key: Some(mtc_key),
            signing_hash_alg: "sha256".into(),
            cosigner_clients: vec![],
            _log_lock: None,
            checkpoint_interval_secs: 3600,
            checkpoint_retention_count: 1000,
            landmark_interval_secs: 86400,
            max_active_landmarks: 100,
            last_checkpoint: std::sync::atomic::AtomicI64::new(0),
            last_landmark: std::sync::atomic::AtomicI64::new(0),
            log_number: 1,
            tree_minimum_index: None,
            trust_anchor_id_der: None,
            trust_anchor_id: Some("32473.2".into()),
            contact: None,
            tlog_origin: Some("oid/1.3.6.1.4.1.32473.2.0.1".into()),
            cosigner_name: Some("oid/1.3.6.1.4.1.32473.2".into()),
            logid_issuer_dn_der: None,
        }),
        default_linter: None,
        cached_der: std::sync::OnceLock::new(),
        lint_store: std::sync::OnceLock::new(),
    });

    let cas = {
        let mut ca_map = indexmap::IndexMap::new();
        ca_map.insert("default".to_string(), ca.clone());
        Arc::new(ca_map)
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

    let app = routes::build_router(Arc::clone(&state), None, false);
    let addr: SocketAddr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let ep = CosignerEndpoint {
        name: "akamu-self-test".to_string(),
        base_url: format!("http://{addr}/acme/default/mtc"),
        cosigner_id: "32473.2".to_string(),
        key_sha256: None,
        cosigner_type: CosignerType::Issuer,
    };

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .unwrap();

    let results = verify_issuer_tlog(&client, &ep).await;
    for r in &results {
        eprintln!(
            "  [{}] {}: {}",
            if r.passed { "PASS" } else { "FAIL" },
            r.check_name,
            r.detail,
        );
    }
    assert_all_passed(&ep.name, &results);
}

// ── Unit tests for JSON parsing ──────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_google_cosigners_store_sample() {
        let json = r#"{
            "timestamp": "2026-07-22T21:29:05Z",
            "version": "2.0.3",
            "operators": [{"name": "Test Operator"}],
            "issuers": [{
                "friendly_name": "test_issuer",
                "base_id": "44363.48.8",
                "base_url": "https://example.com",
                "type": "ISSUER",
                "realm": "UNTRUSTED_VALIDATION_ONLY",
                "key_sha256": "abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234"
            }],
            "mirrors": [{
                "friendly_name": "test_mirror",
                "base_id": "11129.11.99.2",
                "base_url": "https://mirror.example.com/mirror",
                "type": "MIRROR",
                "realm": "UNTRUSTED_VALIDATION_ONLY",
                "key_sha256": "1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd"
            }]
        }"#;
        let store: CosignersStore = serde_json::from_str(json).unwrap();
        assert_eq!(store.version, "2.0.3");
        assert_eq!(store.issuers.len(), 1);
        assert_eq!(store.mirrors.len(), 1);

        let ep = CosignerEndpoint::from_google_signer(&store.issuers[0]);
        assert_eq!(ep.cosigner_id, "44363.48.8");
        assert!(matches!(ep.cosigner_type, CosignerType::Issuer));

        let mp = CosignerEndpoint::from_google_signer(&store.mirrors[0]);
        assert!(matches!(mp.cosigner_type, CosignerType::Mirror));
    }

    #[test]
    fn parse_geomys_mirror_config_sample() {
        let json = r#"{
            "name": "oid/1.3.6.1.4.1.66252.128.0",
            "submission_url": "https://witness.example.org/",
            "monitoring_url": "https://monitor.example.org/mirror/",
            "verifier_keys": ["somekey"],
            "key": "MIIB...",
            "cosigner_id": "66252.128.0"
        }"#;
        let cfg: MirrorConfig = serde_json::from_str(json).unwrap();
        assert_eq!(cfg.cosigner_id, "66252.128.0");

        let ep = CosignerEndpoint::from_geomys_mirror(&cfg);
        assert_eq!(ep.base_url, "https://monitor.example.org/mirror");
        assert!(matches!(ep.cosigner_type, CosignerType::Mirror));
    }
}
