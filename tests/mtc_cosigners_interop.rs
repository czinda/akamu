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

// ── Constants ────────────────────────────────────────────────────────────────

const GOOGLE_COSIGNERS_URL: &str =
    "https://www.gstatic.com/mtcs/cosigners/v1/cosigners.json";
const GEOMYS_MIRROR_URL: &str =
    "https://witness.navigli.sunlight.geomys.org/mirror/mirror.v0.json";

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
