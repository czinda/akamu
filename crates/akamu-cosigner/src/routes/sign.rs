use std::sync::Arc;

use axum::{body::Bytes, extract::State, http::StatusCode, response::IntoResponse};
use synta::types::primitive::Integer;
use synta::types::string::OctetString;
use synta::{BitString, Decoder, Encoding};
use synta_certificate::AlgorithmIdentifier;
use synta_certificate::{CertificateSigner as _, PrivateKey as _};
use synta_mtc::types::{Checkpoint, Subtree, SubtreeSignature};

use crate::error::CosignerError;
use crate::state::AppState;

/// `POST /sign` — the core MTC cosigner endpoint.
///
/// Accepts a DER-encoded `Checkpoint`, signs it with the cosigner key, and
/// returns a DER-encoded `SubtreeSignature`.  The subtree covers the full
/// checkpoint range `[0, tree_size)`.
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

    // ── 3. Sign the raw incoming DER (not re-encoded) ────────────────────────
    let signer = state.signing_key.as_signer(&state.hash_alg);
    let sig_bytes = signer
        .sign_tbs(&body)
        .map_err(|e| CosignerError::Crypto(format!("sign checkpoint: {e}")))?;

    // ── 4. Decode AlgorithmIdentifier from stored DER (per-request, cheap) ───
    let sig_alg_der = state.sig_alg_der.as_slice();
    let signature_algorithm: AlgorithmIdentifier = Decoder::new(sig_alg_der, Encoding::Der)
        .decode()
        .map_err(|e| CosignerError::Asn1(format!("decode sig alg: {e}")))?;

    // ── 5. Build SubtreeSignature ─────────────────────────────────────────────
    let subtree_sig = SubtreeSignature {
        cosigner: state.cosigner_id.clone(),
        subtree,
        checkpoint,
        signature_algorithm,
        signature: BitString::new(sig_bytes, 0)
            .map_err(|e| CosignerError::Asn1(format!("wrap signature bits: {e}")))?,
    };

    // ── 6. DER-encode and return ──────────────────────────────────────────────
    let response_der = subtree_sig
        .to_der()
        .map_err(|e| CosignerError::Asn1(format!("encode SubtreeSignature: {e}")))?;

    Ok((
        StatusCode::OK,
        [("content-type", "application/octet-stream")],
        response_der,
    ))
}
