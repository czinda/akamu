use std::sync::Arc;

use axum::{body::Bytes, extract::State, http::StatusCode, response::IntoResponse};
use synta::types::primitive::Integer;
use synta::types::string::OctetString;
use synta::{BitString, Decoder, Encoding};
use synta_certificate::{AlgorithmIdentifier, CertificateSigner as _, PrivateKey as _};
use synta_mtc::types::{Checkpoint, Subtree, SubtreeSignature};

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

    // ── 3. Clone CosignerID (TrustAnchorID = RelativeOid) from state ──────────
    let cosigner_id = state.cosigner_oid.clone();

    // ── 4. Build TLS-encoded CosignedMessage (spec §5.4.1) ───────────────────
    // log_origin per §5.3.1: should be "oid/<log TrustAnchorID>".
    // TODO: once synta-mtc's validate_cosignature_quorum_with_crypto accepts
    // log_origin as a parameter, switch to oid/{log_trust_anchor_id}.
    let log_origin = format!("oid/{}", checkpoint.log_id.hash_algorithm.algorithm);

    let cosigned_msg =
        akamu_mtc_wire::build_cosigned_message(&cosigner_id, &subtree, &checkpoint, &log_origin)
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
        .map_err(|e| {
            tracing::error!("BUG: failed to decode pre-loaded sig_alg DER: {e}");
            CosignerError::Asn1(format!("decode sig alg: {e}"))
        })?;

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

    // Update signing statistics for GET /admin/stats (single lock for consistency).
    {
        let mut stats = state
            .signing_stats
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        stats.0 += 1;
        stats.1 = Some(crate::util::unix_now());
    }

    Ok((
        StatusCode::OK,
        [("content-type", "application/octet-stream")],
        response_der,
    ))
}
