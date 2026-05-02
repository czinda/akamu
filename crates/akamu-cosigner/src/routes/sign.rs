use std::sync::Arc;

use axum::{body::Bytes, extract::State, http::StatusCode, response::IntoResponse};
use synta::types::primitive::Integer;
use synta::types::string::OctetString;
use synta::{BitString, Decoder, Encoding};
use synta_certificate::{AlgorithmIdentifier, SubjectPublicKeyInfo};
use synta_certificate::{CertificateSigner as _, PrivateKey as _};
use synta_mtc::types::{Checkpoint, CosignerID, Subtree, SubtreeSignature};

use crate::error::CosignerError;
use crate::state::AppState;

/// `POST /sign` — the core MTC cosigner endpoint.
///
/// Accepts a DER-encoded `Checkpoint`, signs the TLS-encoded `CosignedMessage`
/// (spec §5.4.1), and returns a DER-encoded `SubtreeSignature`.  The subtree
/// covers the full checkpoint range `[0, tree_size)`.
pub async fn post_sign(
    State(state): State<Arc<AppState>>,
    body: Bytes,
) -> Result<impl IntoResponse, CosignerError> {
    // ── 1. Decode incoming Checkpoint DER ────────────────────────────────────
    let checkpoint: Checkpoint = Decoder::new(&body, Encoding::Der)
        .decode()
        .map_err(|e| CosignerError::BadRequest(format!("invalid Checkpoint DER: {e}")))?;

    // ── 2. Build subtree spanning the full checkpoint ─────────────────────────
    let tree_size = checkpoint
        .tree_size
        .as_u64()
        .map_err(|_| CosignerError::BadRequest("tree_size out of range".into()))?;

    if tree_size == 0 {
        return Err(CosignerError::BadRequest("tree_size must be > 0".into()));
    }

    let root_bytes = checkpoint.root_value.as_bytes().to_vec();
    let subtree = Subtree {
        start: Integer::from(0u64),
        end: Integer::from(tree_size),
        value: OctetString::from(root_bytes),
    };

    // ── 3. Reconstruct CosignerID from stored DER fields ─────────────────────
    let cosigner_hash_alg: AlgorithmIdentifier =
        Decoder::new(&state.cosigner_hash_alg_der, Encoding::Der)
            .decode()
            .map_err(|e| CosignerError::Asn1(format!("decode cosigner hash_alg: {e}")))?;
    let cosigner_spki: SubjectPublicKeyInfo = Decoder::new(&state.cosigner_spki_der, Encoding::Der)
        .decode()
        .map_err(|e| CosignerError::Asn1(format!("decode cosigner SPKI: {e}")))?;
    let cosigner_id = CosignerID {
        hash_algorithm: cosigner_hash_alg,
        public_key: cosigner_spki,
    };

    // ── 4. Build TLS-encoded CosignedMessage (spec §5.4.1) ───────────────────
    let cosigned_msg = build_cosigned_message(&cosigner_id, &subtree, &checkpoint)
        .map_err(|e| CosignerError::Asn1(format!("build CosignedMessage: {e}")))?;

    // ── 5. Sign the CosignedMessage ───────────────────────────────────────────
    let signer = state.signing_key.as_signer(&state.hash_alg);
    let sig_bytes = signer
        .sign_tbs(&cosigned_msg)
        .map_err(|e| CosignerError::Crypto(format!("sign CosignedMessage: {e}")))?;

    // ── 6. Decode AlgorithmIdentifier from stored DER (per-request, cheap) ───
    let sig_alg_der = state.sig_alg_der.as_slice();
    let signature_algorithm: AlgorithmIdentifier = Decoder::new(sig_alg_der, Encoding::Der)
        .decode()
        .map_err(|e| CosignerError::Asn1(format!("decode sig alg: {e}")))?;

    // ── 7. Build SubtreeSignature ─────────────────────────────────────────────
    let subtree_sig = SubtreeSignature {
        cosigner: cosigner_id,
        subtree,
        checkpoint,
        signature_algorithm,
        signature: BitString::new(sig_bytes, 0)
            .map_err(|e| CosignerError::Asn1(format!("wrap signature bits: {e}")))?,
    };

    // ── 8. DER-encode and return ──────────────────────────────────────────────
    let response_der = subtree_sig
        .to_der()
        .map_err(|e| CosignerError::Asn1(format!("encode SubtreeSignature: {e}")))?;

    Ok((
        StatusCode::OK,
        [("content-type", "application/octet-stream")],
        response_der,
    ))
}

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
/// Both `cosigner_name` and `log_origin` are `"oid/{dotted-decimal-OID}"` strings.
/// The `timestamp` is the Unix seconds from the checkpoint's `GeneralizedTime`
/// (0 when the checkpoint carries no time information or for pre-epoch dates).
fn build_cosigned_message(
    cosigner: &CosignerID<'_>,
    subtree: &Subtree,
    checkpoint: &Checkpoint<'_>,
) -> Result<Vec<u8>, String> {
    const LABEL: &[u8; 12] = b"subtree/v1\n\0";

    let cosigner_name = format!("oid/{}", cosigner.hash_algorithm.algorithm);
    let cosigner_name_bytes = cosigner_name.as_bytes();
    if cosigner_name_bytes.len() > 255 {
        return Err("cosigner_name too long for CosignedMessage".into());
    }

    let log_origin = format!("oid/{}", checkpoint.log_id.hash_algorithm.algorithm);
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
        12 + 1
            + cosigner_name_bytes.len()
            + 8
            + 1
            + log_origin_bytes.len()
            + 8
            + 8
            + subtree_hash.len(),
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
