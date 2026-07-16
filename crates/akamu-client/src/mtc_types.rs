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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deserialize_tree_size() {
        let json = r#"{"treeSize": 42}"#;
        let ts: TreeSize = serde_json::from_str(json).unwrap();
        assert_eq!(ts.tree_size, 42);
    }

    #[test]
    fn deserialize_tree_root() {
        let json = r#"{"treeSize": 10, "rootHash": "abcd1234"}"#;
        let root: TreeRoot = serde_json::from_str(json).unwrap();
        assert_eq!(root.tree_size, 10);
        assert_eq!(root.root_hash, "abcd1234");
    }

    #[test]
    fn deserialize_inclusion_proof() {
        let json = r#"{
            "leafIndex": 5,
            "treeSize": 10,
            "proof": [{"hash": "aa"}, {"hash": "bb"}]
        }"#;
        let proof: InclusionProofResponse = serde_json::from_str(json).unwrap();
        assert_eq!(proof.leaf_index, 5);
        assert_eq!(proof.tree_size, 10);
        assert_eq!(proof.proof.len(), 2);
        assert_eq!(proof.proof[0].hash, "aa");
    }

    #[test]
    fn deserialize_landmark() {
        let json = r#"{"sequenceNo": 1, "treeSize": 100, "createdAt": 1700000000}"#;
        let lm: Landmark = serde_json::from_str(json).unwrap();
        assert_eq!(lm.sequence_no, 1);
        assert_eq!(lm.tree_size, 100);
        assert_eq!(lm.created_at, 1700000000);
    }

    #[test]
    fn deserialize_consistency_proof() {
        let json = r#"{
            "fromSize": 5, "toSize": 10,
            "fromRoot": "aabb", "toRoot": "ccdd"
        }"#;
        let cp: ConsistencyProofResponse = serde_json::from_str(json).unwrap();
        assert_eq!(cp.from_size, 5);
        assert_eq!(cp.to_size, 10);
        assert_eq!(cp.from_root, "aabb");
        assert_eq!(cp.to_root, "ccdd");
    }

    #[test]
    fn deserialize_subtree_root() {
        let json = r#"{"start": 0, "end": 8, "rootHash": "deadbeef"}"#;
        let sr: SubtreeRootResponse = serde_json::from_str(json).unwrap();
        assert_eq!(sr.start, 0);
        assert_eq!(sr.end, 8);
        assert_eq!(sr.root_hash, "deadbeef");
    }

    #[test]
    fn deserialize_revoked_ranges() {
        let json = r#"[[0, 5], [10, 20]]"#;
        let ranges: Vec<RevokedRange> = serde_json::from_str(json).unwrap();
        assert_eq!(ranges.len(), 2);
        assert_eq!(ranges[0], [0, 5]);
        assert_eq!(ranges[1], [10, 20]);
    }
}
