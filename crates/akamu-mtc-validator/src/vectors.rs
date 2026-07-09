//! Deserialization types for the MTC demo test vector format (mtc.json).
//!
//! Schema mirrors <https://github.com/ietf-plants-wg/merkle-tree-certs/blob/main/demo/config.go>

use base64::Engine as _;
use serde::Deserialize;
use std::path::Path;

/// Top-level test vector configuration (mtc.json).
#[derive(Debug, Clone, Deserialize)]
pub struct MtcVectors {
    #[serde(rename = "Version")]
    pub version: String,
    /// Trust Anchor ID in dotted-decimal notation (e.g. "32473.1").
    #[serde(rename = "ID")]
    pub id: String,
    #[serde(rename = "LogNumber")]
    pub log_number: u32,
    #[serde(rename = "Cosigners")]
    pub cosigners: Vec<CosignerConfig>,
    #[serde(rename = "CACert")]
    pub ca_cert: CACertConfig,
    #[serde(rename = "Entries")]
    pub entries: Vec<EntryConfig>,
}

impl MtcVectors {
    /// Load and parse mtc.json from the given path.
    pub fn load(path: &Path) -> crate::Result<Self> {
        let data = std::fs::read_to_string(path)
            .map_err(|e| crate::Error::Io(format!("read {}: {}", path.display(), e)))?;
        serde_json::from_str(&data)
            .map_err(|e| crate::Error::Parse(format!("parse {}: {}", path.display(), e)))
    }

    /// Compute the LogID OID arc string from the CA Trust Anchor ID and log number.
    ///
    /// Per spec plants-04: LogID = TrustAnchorID || arc(0) || arc(LogNumber).
    /// Returns the dotted-decimal string, e.g. "32473.1.0.1".
    pub fn log_id_string(&self) -> String {
        format!("{}.0.{}", self.id, self.log_number)
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct CosignerConfig {
    #[serde(rename = "CosignerID")]
    pub cosigner_id: String,
    #[serde(rename = "SignatureAlgorithm")]
    pub signature_algorithm: String,
    /// PKCS#8 private key, base64-encoded DER.
    #[serde(rename = "PrivateKey", deserialize_with = "deser_base64")]
    pub private_key: Vec<u8>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CACertConfig {
    #[serde(rename = "NotBefore")]
    pub not_before: String,
    #[serde(rename = "NotAfter")]
    pub not_after: String,
    #[serde(rename = "IsCA", default)]
    pub is_ca: bool,
    #[serde(rename = "KeyUsage", default)]
    pub key_usage: Vec<String>,
    #[serde(rename = "MinSerial", default)]
    pub min_serial: u64,
}

/// One "entry template" that may be repeated and may have certificate configs.
#[derive(Debug, Clone, Deserialize)]
pub struct EntryConfig {
    /// Repeat this entry N times in the log (default: 1).
    #[serde(rename = "Repeat", default)]
    pub repeat: u64,
    /// If true, this entry is a null_entry.
    #[serde(rename = "Null", default)]
    pub null: bool,
    /// DER-encoded SubjectPublicKeyInfo (base64), optional for null entries.
    #[serde(rename = "PublicKey", default, deserialize_with = "deser_base64_opt")]
    pub public_key: Option<Vec<u8>>,
    #[serde(rename = "Subject", default)]
    pub subject: Option<SubjectConfig>,
    #[serde(rename = "NotBefore", default)]
    pub not_before: Option<String>,
    #[serde(rename = "NotAfter", default)]
    pub not_after: Option<String>,
    #[serde(rename = "DNSNames", default)]
    pub dns_names: Vec<String>,
    #[serde(rename = "KeyUsage", default)]
    pub key_usage: Vec<String>,
    #[serde(rename = "ExtKeyUsage", default)]
    pub ext_key_usage: Vec<String>,
    #[serde(rename = "IsCA", default)]
    pub is_ca: Option<bool>,
    #[serde(rename = "MaxPathLen", default)]
    pub max_path_len: Option<i64>,
    /// Checkpoint sequence names that this entry triggers (e.g. ["fast", "landmark"]).
    #[serde(rename = "Checkpoints", default)]
    pub checkpoints: Vec<String>,
    /// Certificates to produce from this entry (one per subtree/checkpoint).
    #[serde(rename = "Certificates", default)]
    pub certificates: Vec<CertificateConfig>,
}

impl EntryConfig {
    pub fn effective_repeat(&self) -> u64 {
        if self.repeat == 0 {
            1
        } else {
            self.repeat
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct SubjectConfig {
    #[serde(rename = "CommonName", default)]
    pub common_name: String,
    #[serde(rename = "Country", default)]
    pub country: Vec<String>,
    #[serde(rename = "Organization", default)]
    pub organization: Vec<String>,
    #[serde(rename = "OrganizationalUnit", default)]
    pub organizational_unit: Vec<String>,
    #[serde(rename = "Locality", default)]
    pub locality: Vec<String>,
    #[serde(rename = "Province", default)]
    pub province: Vec<String>,
    #[serde(rename = "StreetAddress", default)]
    pub street_address: Vec<String>,
    #[serde(rename = "PostalCode", default)]
    pub postal_code: Vec<String>,
    #[serde(rename = "SerialNumber", default)]
    pub serial_number: String,
}

/// A certificate to produce from a log entry, with subtree bounds.
#[derive(Debug, Clone, Deserialize)]
pub struct CertificateConfig {
    /// Checkpoint sequence name (mutually exclusive with SubtreeEnd).
    #[serde(rename = "Checkpoint", default)]
    pub checkpoint: String,
    /// Cosigner IDs to include.
    #[serde(rename = "Cosigners", default)]
    pub cosigners: Vec<String>,
    /// Explicit subtree start (mutually exclusive with Checkpoint).
    #[serde(rename = "SubtreeStart", default)]
    pub subtree_start: u64,
    /// Explicit subtree end (mutually exclusive with Checkpoint).
    #[serde(rename = "SubtreeEnd", default)]
    pub subtree_end: u64,
    /// If true, flip a bit in the proof (negative test vector).
    #[serde(rename = "BitFlipProof", default)]
    pub bit_flip_proof: bool,
}

fn deser_base64<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    base64::engine::general_purpose::STANDARD
        .decode(s.as_bytes())
        .map_err(serde::de::Error::custom)
}

fn deser_base64_opt<'de, D>(deserializer: D) -> Result<Option<Vec<u8>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let opt = Option::<String>::deserialize(deserializer)?;
    match opt {
        None => Ok(None),
        Some(s) => base64::engine::general_purpose::STANDARD
            .decode(s.as_bytes())
            .map(Some)
            .map_err(serde::de::Error::custom),
    }
}
