//! `POST /gossip/mtc/append` — forward an MTC leaf-append to this CA's
//! elected writer node.
//!
//! The MTC log is a local, per-node disk file (exclusive `flock`); only one
//! process may ever append to it. When a node that isn't the elected
//! `mtc_writer` for a CA needs to log a certificate, it calls
//! [`forward_append`] instead of appending locally. This handler is the
//! receiving side, using the identical CMS trust model `/gossip/sync`
//! already uses (`crate::gossip::crypto`) — pinned peer keys via
//! `cluster_nodes`, sender identified by the `x-akamu-node-id` header.
//!
//! `append_cert_to_log` requires no private key material (it only hashes
//! and writes to disk), so this endpoint never touches the CA's or the
//! MTC log's signing keys.

use std::sync::Arc;

use axum::body::Bytes;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use serde::{Deserialize, Serialize};

use crate::db;
use crate::error::AcmeError;
use crate::gossip::crypto::{sign_and_seal, verify_and_open, SealRecipient};
use crate::state::AppState;
use crate::util::unix_now;

/// Request body, CBOR-encoded then CMS-sealed the same way a `GossipEnvelope`
/// is. `algorithm`/`logid_issuer_dn_der` are deliberately not included: the
/// writer resolves both from its own CA config, the same way it would for a
/// local append, rather than trusting values asserted by the forwarding peer.
#[derive(Debug, Serialize, Deserialize)]
struct MtcAppendRequest {
    ca_id: String,
    cert_der: Vec<u8>,
    serial_number: String,
    issued_at: i64,
}

/// Successful append result — everything the caller needs to build the
/// standalone certificate locally, without a second round-trip.
#[derive(Debug, Serialize, Deserialize)]
pub struct MtcAppendSuccess {
    pub leaf_index: u64,
    pub proof: Vec<Vec<u8>>,
    pub tree_size: u64,
}

#[derive(Debug, Serialize, Deserialize)]
enum MtcAppendOutcome {
    Ok(MtcAppendSuccess),
    /// The receiving node does not (or no longer) believe it holds the
    /// writer election for this CA. `current_writer` is `(node_id,
    /// gossip_url)` for whoever it currently believes holds it, if known,
    /// so the caller can retry directly against the right target.
    NotWriter {
        current_writer: Option<(String, String)>,
    },
    Err(String),
}

/// Result of a forward attempt, distinguishing a clean "wrong node, retry
/// elsewhere" rejection from an actual failure (network, decode, MTC error).
pub enum ForwardOutcome {
    Success(MtcAppendSuccess),
    NotWriter {
        current_writer: Option<(String, String)>,
    },
}

// ── Client side ──────────────────────────────────────────────────────────────

/// Forward a leaf-append request to `writer_node_id` at `writer_url`.
pub async fn forward_append(
    state: &AppState,
    ca_id: &str,
    writer_node_id: &str,
    writer_url: &str,
    cert_der: &[u8],
    serial_number: &str,
) -> Result<ForwardOutcome, AcmeError> {
    let (writer_kem_key, writer_signing_pub) = {
        let crdt = state.crdt.read().await;
        let node = crdt.cluster_nodes.get(writer_node_id).ok_or_else(|| {
            AcmeError::ServiceUnavailable(format!(
                "MTC writer '{writer_node_id}' for CA '{ca_id}' is not a known cluster node"
            ))
        })?;
        (
            node.kem_public_key_der.clone(),
            node.gossip_signing_pub_key_der.clone(),
        )
    };
    if writer_kem_key.is_empty() || writer_signing_pub.is_empty() {
        return Err(AcmeError::ServiceUnavailable(format!(
            "MTC writer '{writer_node_id}' has no pinned gossip keys"
        )));
    }

    let request = MtcAppendRequest {
        ca_id: ca_id.to_owned(),
        cert_der: cert_der.to_owned(),
        serial_number: serial_number.to_owned(),
        issued_at: unix_now(),
    };
    let mut request_bytes = Vec::new();
    ciborium::into_writer(&request, &mut request_bytes)
        .map_err(|e| AcmeError::Mtc(format!("encode MTC append request: {e}")))?;

    let signed_body = sign_and_seal(
        &request_bytes,
        &[SealRecipient {
            hint: writer_node_id,
            spki_der: &writer_kem_key,
        }],
        &state.node_gossip_signing_priv,
        &state.node_gossip_signing_cert,
    )
    .map_err(|e| AcmeError::Mtc(format!("sign MTC append request: {e}")))?;

    let post_url = format!("{}/gossip/mtc/append", writer_url.trim_end_matches('/'));
    let resp = state
        .gossip_client
        .post(&post_url)
        .header("content-type", "application/pkcs7-mime")
        .header("x-akamu-node-id", state.node_id.as_str())
        .body(signed_body)
        .send()
        .await
        .map_err(|e| {
            AcmeError::ServiceUnavailable(format!("MTC writer '{writer_node_id}' unreachable: {e}"))
        })?;

    if !resp.status().is_success() {
        return Err(AcmeError::ServiceUnavailable(format!(
            "MTC writer '{writer_node_id}' returned {}",
            resp.status()
        )));
    }
    let resp_bytes = resp
        .bytes()
        .await
        .map_err(|e| AcmeError::Mtc(format!("read MTC append response: {e}")))?;

    let opened = verify_and_open(&resp_bytes, &state.node_kem_priv, &writer_signing_pub)
        .map_err(|e| AcmeError::Mtc(format!("verify MTC append response: {e}")))?;
    let outcome: MtcAppendOutcome = ciborium::from_reader(opened.as_slice())
        .map_err(|e| AcmeError::Mtc(format!("decode MTC append response: {e}")))?;

    match outcome {
        MtcAppendOutcome::Ok(success) => Ok(ForwardOutcome::Success(success)),
        MtcAppendOutcome::NotWriter { current_writer } => {
            Ok(ForwardOutcome::NotWriter { current_writer })
        }
        MtcAppendOutcome::Err(message) => Err(AcmeError::Mtc(format!(
            "MTC writer '{writer_node_id}' rejected append: {message}"
        ))),
    }
}

// ── Server side ──────────────────────────────────────────────────────────────

/// `POST /gossip/mtc/append` handler.
pub async fn handle_append(
    axum::extract::State(state): axum::extract::State<Arc<AppState>>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    let sender_node_id = headers
        .get("x-akamu-node-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_owned();
    if sender_node_id.is_empty() {
        tracing::warn!("gossip/mtc/append: missing x-akamu-node-id header");
        return StatusCode::BAD_REQUEST.into_response();
    }
    if sender_node_id.len() > 64 {
        tracing::warn!(
            len = sender_node_id.len(),
            "gossip/mtc/append: x-akamu-node-id too long"
        );
        return StatusCode::BAD_REQUEST.into_response();
    }

    // Same pinned-key requirement as /gossip/sync: both keys pre-registered
    // via /admin/gossip/register, no TOFU.
    let (sender_signing_pub, sender_kem_key): (Vec<u8>, Vec<u8>) = {
        let crdt = state.crdt.read().await;
        match crdt.cluster_nodes.get(&sender_node_id) {
            Some(n)
                if !n.gossip_signing_pub_key_der.is_empty() && !n.kem_public_key_der.is_empty() =>
            {
                (
                    n.gossip_signing_pub_key_der.clone(),
                    n.kem_public_key_der.clone(),
                )
            }
            _ => {
                tracing::warn!(
                    sender = %sender_node_id,
                    "gossip/mtc/append: no pinned signing key for sender"
                );
                return StatusCode::UNAUTHORIZED.into_response();
            }
        }
    };

    let plaintext = match verify_and_open(&body, &state.node_kem_priv, &sender_signing_pub) {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(sender = %sender_node_id, error = %e, "gossip/mtc/append: verify_and_open failed");
            return StatusCode::UNAUTHORIZED.into_response();
        }
    };
    let request: MtcAppendRequest = match ciborium::from_reader(plaintext.as_slice()) {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(sender = %sender_node_id, error = %e, "gossip/mtc/append: CBOR decode request failed");
            return StatusCode::BAD_REQUEST.into_response();
        }
    };

    let now = unix_now();
    let max_age = state
        .config
        .gossip
        .as_ref()
        .map(|g| g.gossip_envelope_max_age_secs as i64)
        .unwrap_or(300);
    let clock_skew = state
        .config
        .gossip
        .as_ref()
        .map(|g| g.clock_skew_tolerance_secs as i64)
        .unwrap_or(30);
    if request.issued_at > now + clock_skew || request.issued_at < now - max_age {
        tracing::warn!(
            sender = %sender_node_id,
            issued_at = request.issued_at,
            "gossip/mtc/append: rejecting out-of-window request"
        );
        return StatusCode::BAD_REQUEST.into_response();
    }

    let outcome = process_append(&state, &request, now).await;

    let mut outcome_bytes = Vec::new();
    if let Err(e) = ciborium::into_writer(&outcome, &mut outcome_bytes) {
        tracing::error!(sender = %sender_node_id, error = %e, "gossip/mtc/append: encode response failed");
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    let resp_body = match sign_and_seal(
        &outcome_bytes,
        &[SealRecipient {
            hint: &sender_node_id,
            spki_der: &sender_kem_key,
        }],
        &state.node_gossip_signing_priv,
        &state.node_gossip_signing_cert,
    ) {
        Ok(b) => b,
        Err(e) => {
            tracing::error!(sender = %sender_node_id, error = %e, "gossip/mtc/append: sign_and_seal response failed");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    (
        StatusCode::OK,
        [("content-type", "application/pkcs7-mime")],
        resp_body,
    )
        .into_response()
}

async fn process_append(
    state: &AppState,
    request: &MtcAppendRequest,
    now: i64,
) -> MtcAppendOutcome {
    let ttl = state
        .config
        .gossip
        .as_ref()
        .map(|g| g.ownership_ttl_secs as i64)
        .unwrap_or(150);

    if !state
        .crdt
        .read()
        .await
        .is_mtc_writer(&request.ca_id, &state.node_id, now, ttl)
    {
        let current_writer = {
            let crdt = state.crdt.read().await;
            crdt.mtc_writer_claimant(&request.ca_id)
                .and_then(|node_id| {
                    crdt.cluster_nodes
                        .get(node_id)
                        .map(|n| (node_id.to_owned(), n.gossip_url.clone()))
                })
        };
        return MtcAppendOutcome::NotWriter { current_writer };
    }

    match db::mtc_forwarded_appends::get(&state.db, &request.ca_id, &request.serial_number).await {
        Ok(Some(cached)) => {
            let proof: Vec<Vec<u8>> = match ciborium::from_reader(cached.proof_cbor.as_slice()) {
                Ok(p) => p,
                Err(e) => return MtcAppendOutcome::Err(format!("decode cached proof: {e}")),
            };
            return MtcAppendOutcome::Ok(MtcAppendSuccess {
                leaf_index: cached.leaf_index as u64,
                proof,
                tree_size: cached.tree_size as u64,
            });
        }
        Ok(None) => {}
        Err(e) => return MtcAppendOutcome::Err(format!("idempotency lookup failed: {e}")),
    }

    let Some(ca) = state.get_ca(&request.ca_id) else {
        return MtcAppendOutcome::Err(format!("unknown CA '{}'", request.ca_id));
    };
    let (Some(log), Some(logid_issuer_dn_der)) =
        (ca.mtc.log.as_ref(), ca.mtc.logid_issuer_dn_der.as_ref())
    else {
        return MtcAppendOutcome::Err(format!("MTC not configured for CA '{}'", request.ca_id));
    };

    let leaf_index = match crate::mtc::log::append_cert_to_log(
        log,
        request.cert_der.clone(),
        logid_issuer_dn_der.clone(),
        ca.mtc.algorithm,
    )
    .await
    {
        Ok(idx) => idx,
        Err(e) => return MtcAppendOutcome::Err(format!("append_cert_to_log: {e}")),
    };
    let (proof, tree_size) = match crate::mtc::log::proof_and_tree_size(log, leaf_index).await {
        Ok(pt) => pt,
        Err(e) => return MtcAppendOutcome::Err(format!("proof_and_tree_size: {e}")),
    };

    let mut proof_cbor = Vec::new();
    if let Err(e) = ciborium::into_writer(&proof, &mut proof_cbor) {
        return MtcAppendOutcome::Err(format!("encode proof for idempotency cache: {e}"));
    }
    if let Err(e) = db::mtc_forwarded_appends::insert_if_absent(
        &state.db,
        &request.ca_id,
        &request.serial_number,
        leaf_index as i64,
        tree_size as i64,
        &proof_cbor,
        now,
    )
    .await
    {
        // The leaf is already appended at this point; failing to cache the
        // result only risks a future retry re-appending, not data loss for
        // this response — log and still return success.
        tracing::error!(
            ca_id = %request.ca_id,
            serial_number = %request.serial_number,
            error = %e,
            "gossip/mtc/append: failed to persist idempotency cache entry"
        );
    }

    MtcAppendOutcome::Ok(MtcAppendSuccess {
        leaf_index,
        proof,
        tree_size,
    })
}
