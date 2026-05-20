//! Gossip HTTP handlers mounted on the admin router.
//!
//! `POST /admin/gossip/sync`  — receive a peer's CRDT push, merge, respond with our delta.
//! `GET  /admin/gossip/status` — observability snapshot.

use std::sync::Arc;

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::Json;

use akamu_crdt::CRDT_GENERATION;

use crate::gossip::crypto::{sign_and_seal, verify_and_open, SealRecipient};
use crate::gossip::envelope::GossipEnvelope;
use crate::state::AppState;
use crate::util::unix_now;

pub async fn gossip_sync(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> impl IntoResponse {
    let sender_node_id = headers
        .get("x-akamu-node-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_owned();

    if sender_node_id.is_empty() {
        tracing::warn!("gossip/sync: missing x-akamu-node-id header");
        return StatusCode::BAD_REQUEST.into_response();
    }

    // Reject unknown senders: node must already be in our CRDT cluster_nodes.
    let sender_signing_pub: Vec<u8> = {
        let crdt = state.crdt.read().await;
        match crdt
            .cluster_nodes
            .get(&sender_node_id)
            .filter(|e| !e.gossip_signing_pub_key_der.is_empty())
            .map(|e| e.gossip_signing_pub_key_der.clone())
        {
            Some(k) => k,
            None => {
                tracing::warn!(
                    sender = %sender_node_id,
                    "gossip/sync: no pinned signing key for sender"
                );
                return StatusCode::UNAUTHORIZED.into_response();
            }
        }
    };

    let plaintext = match verify_and_open(&body, &state.node_kem_priv, Some(&sender_signing_pub)) {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(%e, sender = %sender_node_id, "gossip/sync: verify_and_open failed");
            return StatusCode::UNAUTHORIZED.into_response();
        }
    };

    let envelope = match GossipEnvelope::decode(&plaintext) {
        Ok(e) => e,
        Err(e) => {
            tracing::warn!(sender = %sender_node_id, err = %e, "gossip/sync: CBOR decode envelope failed");
            return StatusCode::BAD_REQUEST.into_response();
        }
    };

    let tombstone_ttl = state
        .config
        .gossip
        .as_ref()
        .map(|g| g.tombstone_ttl_secs as i64)
        .unwrap_or(604_800);

    let now_ts = unix_now();
    if envelope.issued_at < now_ts - tombstone_ttl {
        tracing::warn!(
            sender = %sender_node_id,
            issued_at = envelope.issued_at,
            "gossip/sync: rejecting stale envelope"
        );
        return StatusCode::BAD_REQUEST.into_response();
    }

    let peer_crdt = match envelope.decode_crdt() {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(sender = %sender_node_id, err = %e, "gossip/sync: CBOR decode CRDT failed");
            return StatusCode::BAD_REQUEST.into_response();
        }
    };

    // Snapshot pre-merge generation so the response excludes entries just received.
    let pre_merge_gen = CRDT_GENERATION.load(std::sync::atomic::Ordering::Relaxed);
    let request_delta_since = envelope.request_delta_since;

    {
        let mut crdt = state.crdt.write().await;
        akamu_crdt::Merge::merge(&mut *crdt, peer_crdt);
    }

    if let Err(e) = akamu_crdt::db::persist_crdt(&state.db, &*state.crdt.read().await).await {
        tracing::error!(sender = %sender_node_id, err = %e, "gossip/sync: persist after merge failed");
    }

    // Look up sender's KEM key (now available after merge).
    let sender_kem_key: Option<Vec<u8>> = {
        let crdt = state.crdt.read().await;
        crdt.cluster_nodes
            .get(&sender_node_id)
            .filter(|e| !e.kem_public_key_der.is_empty())
            .map(|e| e.kem_public_key_der.clone())
    };
    let Some(sender_kem_key) = sender_kem_key else {
        tracing::warn!(sender = %sender_node_id, "gossip/sync: sender has no KEM key for response encryption");
        return StatusCode::BAD_REQUEST.into_response();
    };

    let post_merge_gen = CRDT_GENERATION.load(std::sync::atomic::Ordering::Relaxed);

    let response_bytes = {
        let crdt = state.crdt.read().await;
        let (response_crdt, is_delta) = match request_delta_since {
            Some(since) => (crdt.delta_range(since, pre_merge_gen), true),
            None => (crdt.clone(), false),
        };
        let crdt_bytes = match GossipEnvelope::encode_crdt(&response_crdt) {
            Ok(b) => b,
            Err(e) => {
                tracing::error!(sender = %sender_node_id, err = %e, "gossip/sync: CBOR encode response CRDT failed");
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
        };
        let resp_envelope = GossipEnvelope {
            crdt: crdt_bytes,
            issued_at: unix_now(),
            is_delta,
            my_gen: post_merge_gen,
            request_delta_since: None,
        };
        match resp_envelope.encode() {
            Ok(b) => b,
            Err(e) => {
                tracing::error!(sender = %sender_node_id, err = %e, "gossip/sync: CBOR encode response envelope failed");
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
        }
    };

    let resp_body = match sign_and_seal(
        &response_bytes,
        &[SealRecipient {
            hint: &sender_node_id,
            spki_der: &sender_kem_key,
        }],
        &state.node_gossip_signing_priv,
        &state.node_gossip_signing_cert,
    ) {
        Ok(b) => b,
        Err(e) => {
            tracing::error!(%e, sender = %sender_node_id, "gossip/sync: sign_and_seal response failed");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    tracing::debug!(sender = %sender_node_id, "gossip/sync: merge complete");

    (
        StatusCode::OK,
        [("content-type", "application/pkcs7-mime")],
        resp_body,
    )
        .into_response()
}

pub async fn gossip_status(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let crdt = state.crdt.read().await;
    let counts = crdt.entry_counts();
    let crdt_generation = CRDT_GENERATION.load(std::sync::atomic::Ordering::Relaxed);

    let node_entry = crdt.cluster_nodes.get(state.node_id.as_str());
    let kem_enrolled = node_entry
        .map(|e| !e.kem_public_key_der.is_empty())
        .unwrap_or(false);
    let gossip_signing_enrolled = node_entry
        .map(|e| !e.gossip_signing_pub_key_der.is_empty())
        .unwrap_or(false);

    let peers = state
        .config
        .gossip
        .as_ref()
        .map(|g| g.peers.clone())
        .unwrap_or_default();

    Json(serde_json::json!({
        "node_id": state.node_id.as_str(),
        "crdt_generation": crdt_generation,
        "kem_enrolled": kem_enrolled,
        "gossip_signing_enrolled": gossip_signing_enrolled,
        "peers": peers,
        "counts": {
            "cluster_nodes": counts.cluster_nodes,
            "accounts": counts.accounts,
            "orders": counts.orders,
            "authorizations": counts.authorizations,
            "challenges": counts.challenges,
            "certificates": counts.certificates,
            "eab_keys": counts.eab_keys,
            "operators": counts.operators,
            "delegations": counts.delegations,
            "mtc_checkpoints": counts.mtc_checkpoints,
            "mtc_cosignatures": counts.mtc_cosignatures,
            "audit_events": counts.audit_events,
        }
    }))
    .into_response()
}
