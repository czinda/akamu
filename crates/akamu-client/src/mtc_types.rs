use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TreeSize {
    pub tree_size: u64,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TreeRoot {
    pub tree_size: u64,
    pub root_hash: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InclusionProofResponse {
    pub leaf_index: u64,
    pub tree_size: u64,
    pub proof: Vec<ProofNode>,
}

#[derive(Debug, Deserialize)]
pub struct ProofNode {
    pub hash: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Landmark {
    pub sequence_no: i64,
    pub tree_size: i64,
    pub created_at: i64,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConsistencyProofResponse {
    pub from_size: u64,
    pub to_size: u64,
    pub from_root: String,
    pub to_root: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SubtreeRootResponse {
    pub start: u64,
    pub end: u64,
    pub root_hash: String,
}

pub type RevokedRange = [i64; 2];

#[derive(Debug)]
pub enum CertFetchResult {
    Ok(Vec<u8>),
    RetryAfter(u64),
}
