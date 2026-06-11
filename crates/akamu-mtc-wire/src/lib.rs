//! MTC wire-format helpers shared between `akamu-cosigner` and integration tests.
//!
//! This crate exists to avoid duplicating the `build_cosigned_message` function
//! across the cosigner daemon crate and the root crate's integration tests.
//! Those two crates cannot share code via a direct dependency (akamu-cosigner
//! depends on akamu, so the reverse direction would be circular), hence this
//! thin shared crate.

use synta::ObjectIdentifier;
use synta_mtc::types::{Checkpoint, Subtree};

/// Build the TLS `CosignedMessage` wire structure that cosigners sign (spec §5.4.1).
///
/// ```text
/// struct {
///     uint8 label[12] = "subtree/v1\n\0";
///     opaque cosigner_name<1..2^8-1>;
///     uint64 timestamp;
///     opaque log_origin<1..2^8-1>;
///     uint64 start;
///     uint64 end;
///     HashValue subtree_hash;
/// } CosignedMessage;
/// ```
///
/// `cosigner_name` is `"oid/{dotted-decimal-OID}"` using the cosigner's
/// `TrustAnchorID` OID.  `log_origin` should be `"oid/{log-TrustAnchorID}"` per
/// §5.3.1; currently callers pass `"oid/{hash-algorithm-OID}"` for compatibility
/// with `synta-mtc`'s internal `validate_cosignature_quorum_with_crypto`.
/// The `timestamp` is the Unix seconds from the checkpoint's `GeneralizedTime`
/// (0 when the checkpoint carries no time information or for pre-epoch dates).
pub fn build_cosigned_message(
    cosigner: &ObjectIdentifier,
    subtree: &Subtree,
    checkpoint: &Checkpoint<'_>,
    log_origin: &str,
) -> Result<Vec<u8>, String> {
    const LABEL: &[u8; 12] = b"subtree/v1\n\0";

    let cosigner_name = format!("oid/{cosigner}");
    let cosigner_name_bytes = cosigner_name.as_bytes();
    if cosigner_name_bytes.len() > 255 {
        return Err("cosigner_name too long for CosignedMessage".into());
    }

    let log_origin_bytes = log_origin.as_bytes();
    if log_origin_bytes.len() > 255 {
        return Err("log_origin too long for CosignedMessage".into());
    }

    let unix_secs = checkpoint.timestamp.to_unix();
    let timestamp: u64 = if unix_secs < 0 { 0 } else { unix_secs as u64 };

    let start = subtree
        .start
        .as_u64()
        .map_err(|_| "subtree start overflows u64".to_string())?;
    let end = subtree
        .end
        .as_u64()
        .map_err(|_| "subtree end overflows u64".to_string())?;
    let subtree_hash = subtree.value.as_bytes();

    let mut msg = Vec::with_capacity(
        12                              // LABEL "subtree/v1\n\0"
        + 1 + cosigner_name_bytes.len() // u8 length prefix + cosigner_name bytes
        + 8                             // timestamp u64
        + 1 + log_origin_bytes.len()    // u8 length prefix + log_origin bytes
        + 8                             // start u64
        + 8                             // end u64
        + subtree_hash.len(), // HashValue
    );
    msg.extend_from_slice(LABEL);
    msg.push(cosigner_name_bytes.len() as u8);
    msg.extend_from_slice(cosigner_name_bytes);
    msg.extend_from_slice(&timestamp.to_be_bytes());
    msg.push(log_origin_bytes.len() as u8);
    msg.extend_from_slice(log_origin_bytes);
    msg.extend_from_slice(&start.to_be_bytes());
    msg.extend_from_slice(&end.to_be_bytes());
    msg.extend_from_slice(subtree_hash);

    Ok(msg)
}
