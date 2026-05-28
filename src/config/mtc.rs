use serde::Deserialize;

use super::ca::{default_hash_alg, default_key_type};

/// MTC signing key parameters for checkpoint production.
///
/// The signing key MUST be distinct from the X.509 CA key (§5.5 of
/// draft-ietf-plants-merkle-tree-certs).  When absent, checkpoint
/// production and standalone certificate construction are disabled.
///
/// ```toml
/// [mtc.signing_key]
/// key_file = "/var/lib/akamu/mtc-signing.key"
/// key_type = "ec:P-256"
/// hash_alg = "sha256"
/// ```
#[derive(Debug, Clone, Deserialize)]
pub struct MtcSigningKeyConfig {
    /// PEM file for the MTC signing key (generated on first run if absent).
    pub key_file: String,
    /// Key algorithm: same values as `[ca].key_type` ("ec:P-256", "ed25519", …).
    #[serde(default = "default_key_type")]
    pub key_type: String,
    /// Hash algorithm for signatures: "sha256", "sha384", "sha512".
    #[serde(default = "default_hash_alg")]
    pub hash_alg: String,
}

/// Configuration for a single external MTC cosigner.
///
/// Akāmu POSTs the DER-encoded `Checkpoint` to `url`; the cosigner is expected
/// to return a DER-encoded `SubtreeSignature`.  Partial failures are logged and
/// skipped — the standalone certificate is built with whatever signatures arrive.
#[derive(Debug, Clone, Deserialize)]
pub struct CosignerConfig {
    /// URL to POST the DER checkpoint to.
    pub url: String,
    /// Path to the cosigner's X.509 certificate PEM file.  When set, the
    /// signature in the returned `SubtreeSignature` is verified against the
    /// cosigner's public key before the signature is stored.
    pub cosigner_id_cert_pem: Option<String>,
    /// Expected `TrustAnchorID` OID (dotted-decimal) of this cosigner.
    ///
    /// Per draft-ietf-plants-merkle-tree-certs-04 §4.1, `CosignerID` is an
    /// `OBJECT IDENTIFIER` assigned to the cosigner.  When set, the OID in
    /// the returned `SubtreeSignature.cosigner` must match this value.
    /// When absent, the OID identity check is skipped (cryptographic
    /// verification via `cosigner_id_cert_pem` still applies when set).
    pub trust_anchor_id: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct MtcConfig {
    /// Path to the MTC disk-backed log file.
    pub log_path: String,
    /// Whether to append issued certificates to the MTC log.
    #[serde(default)]
    pub enabled: bool,
    /// MTC signing key for checkpoint production.  Absent → checkpoints disabled.
    pub signing_key: Option<MtcSigningKeyConfig>,
    /// How often the checkpoint background task fires (seconds).  Default: 3600 (1 h).
    #[serde(default = "default_checkpoint_interval_secs")]
    pub checkpoint_interval_secs: u64,
    /// External cosigners.  Each entry is a `[[mtc.cosigners]]` table.
    #[serde(default)]
    pub cosigners: Vec<CosignerConfig>,
    /// How often to freeze a new landmark tree size (seconds).  Default: 86400 (1 day).
    #[serde(default = "default_landmark_interval_secs")]
    pub landmark_interval_secs: u64,
    /// Maximum number of active (non-expired) landmarks to retain.
    /// Once exceeded, the oldest landmark is available to relying parties for
    /// `ceil(max_cert_lifetime / landmark_interval) + 1` overlap.  Default: 100.
    #[serde(default = "default_max_active_landmarks")]
    pub max_active_landmarks: u32,
    /// Maximum number of checkpoints to retain in the database.
    /// Older checkpoints (and their cosignatures) are pruned after each new
    /// checkpoint is produced.  Default: 1000.
    #[serde(default = "default_checkpoint_retention_count")]
    pub checkpoint_retention_count: u32,
    /// Hash algorithm used for Merkle tree leaf hashing.  Default: `"sha256"`.
    /// Valid values: `sha256`, `sha384`, `sha512`, `sha3-256`, `sha3-384`, `sha3-512`.
    ///
    /// WARNING: changing this for an existing log requires deleting the log file
    /// and recreating it; the algorithm is stored in the log's file header.
    #[serde(default = "default_hash_alg")]
    pub hash_alg: String,
}

fn default_checkpoint_interval_secs() -> u64 {
    3600
}

fn default_landmark_interval_secs() -> u64 {
    86400
}

fn default_max_active_landmarks() -> u32 {
    100
}

fn default_checkpoint_retention_count() -> u32 {
    1000
}
