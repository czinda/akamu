use serde::{Deserialize, Serialize};

/// Authenticated gossip payload wrapper.
///
/// The inner CRDT bytes are CBOR-encoded, then the envelope itself is CBOR-encoded
/// before `sign_and_seal` wraps it in `SignedData(EnvelopedData)`.  The `issued_at`
/// timestamp prevents replay attacks after tombstone GC has purged suppressing entries.
#[derive(Debug, Serialize, Deserialize)]
pub struct GossipEnvelope {
    /// CBOR-encoded `AkaCrdt` (full state or delta).
    #[serde(rename = "p")]
    pub crdt: Vec<u8>,
    #[serde(rename = "t")]
    pub issued_at: i64,
    /// `true` when `crdt` is a sparse delta rather than the full state.
    #[serde(rename = "d", default)]
    pub is_delta: bool,
    /// Sender's `CRDT_GENERATION` at send time.  Receiver records this and sends it
    /// back as `request_delta_since` in future rounds to ask for a delta response.
    #[serde(rename = "g", default)]
    pub my_gen: u64,
    /// Ask the receiver to respond with a delta since this generation of theirs.
    /// `None` requests a full-state response.
    #[serde(rename = "r", default)]
    pub request_delta_since: Option<u64>,
    /// 16 random bytes generated fresh for each push; used by the receiver to
    /// deduplicate replayed envelopes within the `issued_at` window.
    /// Absent on old peers (`default = []`); receiver skips dedup in that case.
    #[serde(rename = "n", default)]
    pub nonce: Vec<u8>,
}

impl GossipEnvelope {
    pub fn encode_crdt(
        crdt: &akamu_crdt::AkaCrdt,
    ) -> Result<Vec<u8>, ciborium::ser::Error<std::io::Error>> {
        let mut buf = Vec::new();
        ciborium::into_writer(crdt, &mut buf)?;
        Ok(buf)
    }

    pub fn decode_crdt(&self) -> Result<akamu_crdt::AkaCrdt, ciborium::de::Error<std::io::Error>> {
        ciborium::from_reader(self.crdt.as_slice())
    }

    /// CBOR-encode this envelope.
    pub fn encode(&self) -> Result<Vec<u8>, ciborium::ser::Error<std::io::Error>> {
        let mut buf = Vec::new();
        ciborium::into_writer(self, &mut buf)?;
        Ok(buf)
    }

    /// CBOR-decode an envelope from bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, ciborium::de::Error<std::io::Error>> {
        ciborium::from_reader(bytes)
    }
}
