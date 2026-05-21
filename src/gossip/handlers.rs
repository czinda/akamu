//! Gossip HTTP handlers mounted on the admin router.
//!
//! `POST /admin/gossip/sync`  — receive a peer's CRDT push, merge, respond with our delta.
//! `GET  /admin/gossip/status` — observability snapshot.

use std::sync::Arc;

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::Json;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;

use akamu_crdt::{AkaNodeEntry, CRDT_GENERATION};

use crate::admin::auth::OperatorContext;
use crate::gossip::crypto::{random_nonce, sign_and_seal, verify_and_open, SealRecipient};
use crate::gossip::envelope::GossipEnvelope;
use crate::require_role;
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
    // Bound the header length before any lock acquisition to limit pre-auth resource use.
    if sender_node_id.len() > 64 {
        tracing::warn!(len = sender_node_id.len(), "gossip/sync: x-akamu-node-id too long");
        return StatusCode::BAD_REQUEST.into_response();
    }

    // Reject unknown senders: both signing key and KEM key must be pre-pinned.
    // KEM key is looked up here (pre-merge) so an attacker cannot redirect our
    // encrypted response by supplying a modified cluster_nodes entry in their CRDT.
    let (sender_signing_pub, sender_kem_key): (Vec<u8>, Vec<u8>) = {
        let crdt = state.crdt.read().await;
        let node = match crdt.cluster_nodes.get(&sender_node_id) {
            Some(n)
                if !n.gossip_signing_pub_key_der.is_empty() && !n.kem_public_key_der.is_empty() =>
            {
                n
            }
            _ => {
                tracing::warn!(
                    sender = %sender_node_id,
                    "gossip/sync: no pinned signing key for sender"
                );
                return StatusCode::UNAUTHORIZED.into_response();
            }
        };
        (
            node.gossip_signing_pub_key_der.clone(),
            node.kem_public_key_der.clone(),
        )
    };

    let plaintext = match verify_and_open(&body, &state.node_kem_priv, &sender_signing_pub) {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(%e, sender = %sender_node_id, "gossip/sync: verify_and_open failed");
            return StatusCode::UNAUTHORIZED.into_response();
        }
    };

    let envelope = match GossipEnvelope::decode(&plaintext) {
        Ok(e) => e,
        Err(e) => {
            tracing::warn!(sender = %sender_node_id, error = %e, "gossip/sync: CBOR decode envelope failed");
            return StatusCode::BAD_REQUEST.into_response();
        }
    };

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

    let now_ts = unix_now();
    if envelope.issued_at > now_ts + clock_skew {
        tracing::warn!(
            sender = %sender_node_id,
            issued_at = envelope.issued_at,
            "gossip/sync: rejecting future-dated envelope"
        );
        return StatusCode::BAD_REQUEST.into_response();
    }
    if envelope.issued_at < now_ts - max_age {
        tracing::warn!(
            sender = %sender_node_id,
            issued_at = envelope.issued_at,
            "gossip/sync: rejecting stale envelope"
        );
        return StatusCode::BAD_REQUEST.into_response();
    }

    // Deduplicate by nonce to prevent replay within the issued_at window.
    // Nonces are optional (old peers omit them); skip dedup when nonce is absent.
    // Reject short nonces: anything under 16 bytes provides a negligible dedup space.
    if !envelope.nonce.is_empty() {
        if envelope.nonce.len() < 16 {
            tracing::warn!(
                sender = %sender_node_id,
                len = envelope.nonce.len(),
                "gossip/sync: nonce too short — rejecting"
            );
            return StatusCode::BAD_REQUEST.into_response();
        }
        // Cap nonce length to prevent a large HashMap key from being injected.
        if envelope.nonce.len() > 32 {
            tracing::warn!(
                sender = %sender_node_id,
                len = envelope.nonce.len(),
                "gossip/sync: nonce too long — rejecting"
            );
            return StatusCode::BAD_REQUEST.into_response();
        }
        let mut nonce_cache = state
            .gossip_nonce_cache
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        // Evict expired entries lazily.
        nonce_cache.retain(|_, &mut ts| ts >= now_ts - max_age);
        // Bound cache size to prevent memory exhaustion from a compromised peer.
        const GOSSIP_NONCE_CACHE_MAX: usize = 10_000;
        if nonce_cache.len() >= GOSSIP_NONCE_CACHE_MAX {
            tracing::warn!(
                sender = %sender_node_id,
                "gossip/sync: nonce cache full — rejecting"
            );
            return StatusCode::TOO_MANY_REQUESTS.into_response();
        }
        if nonce_cache.insert(envelope.nonce.clone(), now_ts).is_some() {
            tracing::warn!(
                sender = %sender_node_id,
                "gossip/sync: duplicate nonce — rejecting replay"
            );
            return StatusCode::BAD_REQUEST.into_response();
        }
    }

    let peer_crdt = match envelope.decode_crdt() {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(sender = %sender_node_id, error = %e, "gossip/sync: CBOR decode CRDT failed");
            return StatusCode::BAD_REQUEST.into_response();
        }
    };

    let request_delta_since = envelope.request_delta_since;

    // Merge under write lock.  post_merge_gen is captured inside the write lock
    // to avoid racing with concurrent hook writes.
    let (pre_merge_gen, post_merge_gen) = {
        let mut crdt = state.crdt.write().await;
        let pre_merge_gen = CRDT_GENERATION.load(std::sync::atomic::Ordering::Acquire);
        akamu_crdt::Merge::merge(&mut *crdt, peer_crdt);
        let post_merge_gen = CRDT_GENERATION.load(std::sync::atomic::Ordering::Acquire);
        (pre_merge_gen, post_merge_gen)
    };

    // The DB persist is intentionally omitted from the gossip hot path.  The DB is
    // a restart-recovery cache; the in-memory CRDT is the source of truth for live
    // requests.  Calling persist_crdt on every gossip receive would contend with
    // concurrent ACME DB writes on a shared pool.  The gossip loop persists on a
    // slow timer (every 30 s) instead.

    // Build response CBOR under a read-lock without cloning the full CRDT.
    // For the common case (Some(since)) only the small delta is allocated;
    // for first-contact (None) the full CRDT is serialised directly from the guard.
    let (crdt_bytes, is_delta) = {
        let crdt = state.crdt.read().await;
        match request_delta_since {
            Some(since) => {
                let delta = crdt.delta_range(since, pre_merge_gen);
                match GossipEnvelope::encode_crdt(&delta) {
                    Ok(b) => (b, true),
                    Err(e) => {
                        tracing::error!(sender = %sender_node_id, error = %e, "gossip/sync: CBOR encode response delta failed");
                        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
                    }
                }
            }
            None => match GossipEnvelope::encode_crdt(&crdt) {
                Ok(b) => (b, false),
                Err(e) => {
                    tracing::error!(sender = %sender_node_id, error = %e, "gossip/sync: CBOR encode response CRDT failed");
                    return StatusCode::INTERNAL_SERVER_ERROR.into_response();
                }
            },
        }
    };

    let resp_nonce = match random_nonce() {
        Ok(n) => n,
        Err(e) => {
            tracing::error!(sender = %sender_node_id, error = %e, "gossip/sync: random_nonce for response failed");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };
    let resp_envelope = GossipEnvelope {
        crdt: crdt_bytes,
        issued_at: unix_now(),
        is_delta,
        my_gen: post_merge_gen,
        request_delta_since: None,
        nonce: resp_nonce,
    };
    let response_bytes = match resp_envelope.encode() {
        Ok(b) => b,
        Err(e) => {
            tracing::error!(sender = %sender_node_id, error = %e, "gossip/sync: CBOR encode response envelope failed");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
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

/// `POST /admin/gossip/register` — pre-pin a peer node's gossip keys (H-8).
///
/// An operator MUST call this endpoint before the gossip loop will push state to
/// or accept signed responses from the peer.  Requires `administrator` role.
///
/// # Request body (JSON)
///
/// ```json
/// {
///   "node_id":                  "…",
///   "gossip_url":               "https://peer.acme.internal:8443",
///   "kem_public_key_b64u":      "<SPKI DER, base64url>",
///   "gossip_signing_pub_key_b64u": "<SPKI DER, base64url>",
///   "gossip_signing_cert_b64u": "<X.509 DER, base64url>",
///   "ca_ids":                   ["ca1"]     // optional; defaults to []
/// }
/// ```
pub async fn gossip_register(
    operator: OperatorContext,
    State(state): State<Arc<AppState>>,
    Json(body): Json<GossipRegisterRequest>,
) -> impl IntoResponse {
    require_role!(operator, state, Administrator);

    if body.node_id.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"detail": "node_id is required"})),
        )
            .into_response();
    }
    if body.node_id == state.node_id.as_str() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"detail": "cannot register own node_id"})),
        )
            .into_response();
    }
    if body.gossip_url.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"detail": "gossip_url is required"})),
        )
            .into_response();
    }

    let kem_key = match URL_SAFE_NO_PAD.decode(&body.kem_public_key_b64u) {
        Ok(b) => b,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"detail": "kem_public_key_b64u: invalid base64url"})),
            )
                .into_response();
        }
    };
    let signing_pub = match URL_SAFE_NO_PAD.decode(&body.gossip_signing_pub_key_b64u) {
        Ok(b) => b,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(
                    serde_json::json!({"detail": "gossip_signing_pub_key_b64u: invalid base64url"}),
                ),
            )
                .into_response();
        }
    };
    let signing_cert = match URL_SAFE_NO_PAD.decode(&body.gossip_signing_cert_b64u) {
        Ok(b) => b,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"detail": "gossip_signing_cert_b64u: invalid base64url"})),
            )
                .into_response();
        }
    };

    if kem_key.is_empty() || signing_pub.is_empty() || signing_cert.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"detail": "kem, signing pub, and signing cert must all be non-empty"})),
        )
            .into_response();
    }

    let now = unix_now();
    let entry = AkaNodeEntry {
        node_id: body.node_id.clone(),
        gossip_url: body.gossip_url.clone(),
        kem_public_key_der: kem_key,
        gossip_signing_pub_key_der: signing_pub,
        gossip_signing_cert_der: signing_cert,
        ca_ids: body.ca_ids.clone(),
        registered_at: now,
    };

    {
        let mut crdt = state.crdt.write().await;
        crdt.cluster_nodes.upsert(body.node_id.clone(), entry, now);
    }
    let crdt_snapshot = {
        let crdt = state.crdt.read().await;
        crdt.clone()
    };

    if let Err(e) = akamu_crdt::db::persist_crdt_cluster(&state.crdt_db, &crdt_snapshot).await {
        tracing::error!(node_id = %body.node_id, error = %e, "gossip/register: persist failed");
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }

    tracing::info!(
        node_id = %body.node_id,
        gossip_url = %body.gossip_url,
        operator = %operator.name,
        "gossip/register: peer enrolled"
    );

    Json(serde_json::json!({
        "node_id": body.node_id,
        "gossip_url": body.gossip_url,
        "ca_ids": body.ca_ids,
        "registered_at": now,
    }))
    .into_response()
}

#[derive(serde::Deserialize)]
pub struct GossipRegisterRequest {
    pub node_id: String,
    pub gossip_url: String,
    pub kem_public_key_b64u: String,
    pub gossip_signing_pub_key_b64u: String,
    pub gossip_signing_cert_b64u: String,
    #[serde(default)]
    pub ca_ids: Vec<String>,
}

pub async fn gossip_status(
    operator: OperatorContext,
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    require_role!(operator, state, Auditor);
    let crdt = state.crdt.read().await;
    let counts = crdt.entry_counts();
    let crdt_generation = CRDT_GENERATION.load(std::sync::atomic::Ordering::Acquire);

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
