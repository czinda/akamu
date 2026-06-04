use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AkaNodeEntry {
    pub node_id: String,
    pub gossip_url: String,
    pub kem_public_key_der: Vec<u8>,
    pub gossip_signing_pub_key_der: Vec<u8>,
    pub gossip_signing_cert_der: Vec<u8>,
    pub ca_ids: Vec<String>,
    pub registered_at: i64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AccountEntry {
    pub account_id: String,
    pub status: String,
    pub contact: Option<String>,
    pub public_key_der: Vec<u8>,
    pub jwk_thumbprint: String,
    pub created: i64,
    pub updated: i64,
    pub profile_grants: Option<String>,
    pub ca_id: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OrderEntry {
    pub order_id: String,
    pub account_id: String,
    pub status: String,
    pub expires: Option<i64>,
    pub identifiers: String,
    pub not_before: Option<i64>,
    pub not_after: Option<i64>,
    pub error: Option<String>,
    pub certificate_id: Option<String>,
    pub created: i64,
    pub updated: i64,
    pub ca_id: String,
    pub processing_node_id: Option<String>,
    pub processing_claimed_at: Option<i64>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AuthzEntry {
    pub authz_id: String,
    pub order_id: String,
    pub account_id: String,
    pub status: String,
    pub identifier: String,
    pub expires: Option<i64>,
    pub wildcard: bool,
    pub created: i64,
    pub updated: i64,
    pub ca_id: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ChallengeEntry {
    pub challenge_id: String,
    pub authz_id: String,
    pub challenge_type: String,
    pub status: String,
    pub token: String,
    pub validated: Option<i64>,
    pub error: Option<String>,
    pub created: i64,
    pub updated: i64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CertEntry {
    pub cert_id: String,
    pub order_id: String,
    pub account_id: String,
    pub serial_number: String,
    pub status: String,
    pub not_before: i64,
    pub not_after: i64,
    pub revoked_at: Option<i64>,
    pub revocation_reason: Option<i64>,
    pub created: i64,
    pub ca_id: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EabKeyEntry {
    pub kid: String,
    /// HMAC secret. Skipped from serde so it is never gossiped to peers.
    /// Only the issuing node has the key; consumption status (`used_at`) is
    /// the only EAB metadata that needs cluster-wide replication.
    #[serde(skip)]
    pub hmac_key_b64u: String,
    pub created: i64,
    pub used_at: Option<i64>,
    pub profile_grants: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OperatorEntry {
    pub operator_id: i64,
    pub name: String,
    pub role: String,
    pub ca_id: String,
    pub created: i64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DelegationEntry {
    pub delegation_id: String,
    pub account_id: String,
    pub csr_template: String,
    pub created: i64,
    pub ca_id: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MtcCheckpointEntry {
    pub tree_size: u64,
    pub root_hex: String,
    pub signature: Vec<u8>,
    pub created_at: i64,
}

/// A cosignature from one cosigner on one MTC checkpoint.
///
/// Stored as `LwwMap<(checkpoint_id, cosigner_url), MtcCosigEntry>` so that an
/// updated signature from the same cosigner for the same checkpoint overwrites
/// the earlier one (LWW semantics) rather than being silently dropped.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct MtcCosigEntry {
    pub checkpoint_id: String,
    pub cosigner_url: String,
    pub signature: Vec<u8>,
    pub signed_at: i64,
}

/// Gossip-consensus ownership: which node claimed processing rights for an order.
/// Ownership lapses when `claimed_at + ownership_ttl_secs < now`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrderOwner {
    pub node_id: String,
    pub claimed_at: i64,
}

/// Gossip-consensus election: which node is the single MTC log writer.
/// Same TTL-lapse recovery as OrderOwner.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MtcWriter {
    pub node_id: String,
    pub claimed_at: i64,
}
