//! `POST /gossip/mtc/admin-query` — read-through forwarding for admin MTC
//! routes (`/admin/mtc/*`, `/admin/ca/{id}/mtc/*`) to a CA's elected writer.
//!
//! Unlike the public `/acme/mtc/*` proxy (`routes::mtc_proxy`), admin routes
//! carry operator identity that cannot survive a raw HTTP relay: Bearer
//! session tokens live in a per-node in-memory map
//! (`AppState::admin_sessions`), direct mTLS client certs are terminated at
//! the receiving node's socket, and the proxy-cert-header path only trusts
//! the *direct* TCP peer's IP. None of that reaches a second hop.
//!
//! Instead, `admin_rbac_gate` authenticates and authorizes the operator on
//! the node that actually received the request — *before* any forwarding
//! decision is made. All that needs to cross the wire afterward is "which
//! CA, which query, and who already authorized this" (the last part purely
//! for audit-log fidelity on the writer). This reuses the exact CMS trust
//! model `gossip::mtc_forward` already established for leaf-append
//! forwarding: a CBOR request, `sign_and_seal`ed with the sender's node
//! identity, verified against a pinned key from `cluster_nodes` — no
//! operator credential is ever put on the wire.
//!
//! The server side calls the existing `routes::admin::mtc` handler
//! functions directly, in-process, with a synthetic unscoped
//! `OperatorContext` (the real CA-scope check already happened on the
//! calling node) carrying the real operator's name/role through for audit
//! attribution. This reuses every handler's response-building logic
//! unchanged.

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};

use crate::admin::auth::OperatorContext;
use crate::error::AcmeError;
use crate::gossip::crypto::{sign_and_seal, verify_and_open, SealRecipient};
use crate::routes::admin;
use crate::routes::admin::mtc::{ConsistencyQuery, MtcQuery, SubtreeRootQuery};
use crate::state::{AdminAuthMethod, AppState, OperatorRole};
use crate::util::unix_now;

/// Which admin MTC read or action to perform on the writer. Carries only the
/// parameters each corresponding `routes::admin::mtc` handler needs beyond
/// `ca_id` (already a top-level [`AdminMtcRequest`] field). Constructed by
/// `routes::mtc_proxy`'s admin middleware from the matched route.
#[derive(Debug, Serialize, Deserialize)]
pub(crate) enum AdminMtcQuery {
    TreeSize,
    Root,
    Landmarks,
    LandmarkList,
    InclusionProof { cert_id: String },
    Standalone { cert_id: String },
    LandmarkCert { seq: i64 },
    LandmarkCertDetails { seq: i64 },
    ConsistencyProof { from: u64, to: u64 },
    SubtreeRoot { start: u64, end: u64 },
    RevokedRanges,
    Checkpoint,
    Cosignature,
    ForceCheckpoint,
    ForceLandmark,
    LogListEntry,
}

#[derive(Debug, Serialize, Deserialize)]
struct AdminMtcRequest {
    ca_id: String,
    /// The real operator's identity, carried through purely so the writer's
    /// audit log (for the force-checkpoint/force-landmark actions) names the
    /// actual actor instead of the forwarding node. Not used for
    /// authorization — that already happened on the sending node.
    operator_name: String,
    operator_role: String,
    query: AdminMtcQuery,
    issued_at: i64,
}

#[derive(Debug, Serialize, Deserialize)]
enum AdminMtcOutcome {
    Response {
        status: u16,
        content_type: Option<String>,
        body: Vec<u8>,
    },
    Err(String),
}

// ── Client side ──────────────────────────────────────────────────────────────

/// Everything needed to forward one admin MTC read/action to a CA's elected
/// writer — grouped into a struct rather than threaded as loose parameters.
pub(crate) struct AdminQueryForward<'a> {
    pub ca_id: &'a str,
    pub writer_node_id: &'a str,
    pub writer_url: &'a str,
    pub operator_name: &'a str,
    pub operator_role: OperatorRole,
    pub query: AdminMtcQuery,
}

async fn query_writer(
    state: &AppState,
    forward: AdminQueryForward<'_>,
) -> Result<Response, AcmeError> {
    let AdminQueryForward {
        ca_id,
        writer_node_id,
        writer_url,
        operator_name,
        operator_role,
        query,
    } = forward;
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

    let request = AdminMtcRequest {
        ca_id: ca_id.to_owned(),
        operator_name: operator_name.to_owned(),
        operator_role: operator_role.as_str().to_owned(),
        query,
        issued_at: unix_now(),
    };
    let mut request_bytes = Vec::new();
    ciborium::into_writer(&request, &mut request_bytes)
        .map_err(|e| AcmeError::Mtc(format!("encode admin MTC query request: {e}")))?;

    let signed_body = sign_and_seal(
        &request_bytes,
        &[SealRecipient {
            hint: writer_node_id,
            spki_der: &writer_kem_key,
        }],
        &state.node_gossip_signing_priv,
        &state.node_gossip_signing_cert,
    )
    .map_err(|e| AcmeError::Mtc(format!("sign admin MTC query request: {e}")))?;

    let post_url = format!(
        "{}/gossip/mtc/admin-query",
        writer_url.trim_end_matches('/')
    );
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
        .map_err(|e| AcmeError::Mtc(format!("read admin MTC query response: {e}")))?;

    let opened = verify_and_open(&resp_bytes, &state.node_kem_priv, &writer_signing_pub)
        .map_err(|e| AcmeError::Mtc(format!("verify admin MTC query response: {e}")))?;
    let outcome: AdminMtcOutcome = ciborium::from_reader(opened.as_slice())
        .map_err(|e| AcmeError::Mtc(format!("decode admin MTC query response: {e}")))?;

    match outcome {
        AdminMtcOutcome::Response {
            status,
            content_type,
            body,
        } => {
            let status = StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_GATEWAY);
            let mut builder = Response::builder().status(status);
            if let Some(ct) = content_type {
                builder = builder.header(axum::http::header::CONTENT_TYPE, ct);
            }
            builder
                .body(axum::body::Body::from(body))
                .map_err(|e| AcmeError::Mtc(format!("build proxied admin response: {e}")))
        }
        AdminMtcOutcome::Err(message) => Err(AcmeError::ServiceUnavailable(format!(
            "MTC writer '{writer_node_id}' rejected admin query: {message}"
        ))),
    }
}

/// Forward an admin MTC read/action to its writer, returning the response it
/// would have produced locally, or `StatusCode::BAD_GATEWAY` on any
/// transport/protocol failure. The single entry point `routes::mtc_proxy`'s
/// admin middleware calls.
pub(crate) async fn forward_admin_query(
    state: &AppState,
    forward: AdminQueryForward<'_>,
) -> Response {
    let (ca_id, writer_node_id) = (forward.ca_id.to_owned(), forward.writer_node_id.to_owned());
    match query_writer(state, forward).await {
        Ok(resp) => resp,
        Err(e) => {
            tracing::warn!(ca_id, writer_node_id, error = %e, "admin MTC proxy: forward failed");
            StatusCode::BAD_GATEWAY.into_response()
        }
    }
}

// ── Server side ──────────────────────────────────────────────────────────────

/// `POST /gossip/mtc/admin-query` handler.
pub async fn handle_admin_query(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    let sender_node_id = headers
        .get("x-akamu-node-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_owned();
    if sender_node_id.is_empty() || sender_node_id.len() > 64 {
        tracing::warn!("gossip/mtc/admin-query: missing or oversized x-akamu-node-id header");
        return StatusCode::BAD_REQUEST.into_response();
    }

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
                    "gossip/mtc/admin-query: no pinned signing key for sender"
                );
                return StatusCode::UNAUTHORIZED.into_response();
            }
        }
    };

    let plaintext = match verify_and_open(&body, &state.node_kem_priv, &sender_signing_pub) {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(sender = %sender_node_id, error = %e, "gossip/mtc/admin-query: verify_and_open failed");
            return StatusCode::UNAUTHORIZED.into_response();
        }
    };
    let request: AdminMtcRequest = match ciborium::from_reader(plaintext.as_slice()) {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(sender = %sender_node_id, error = %e, "gossip/mtc/admin-query: CBOR decode request failed");
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
            "gossip/mtc/admin-query: rejecting out-of-window request"
        );
        return StatusCode::BAD_REQUEST.into_response();
    }

    let outcome = process_admin_query(&state, &request, now).await;

    let mut outcome_bytes = Vec::new();
    if let Err(e) = ciborium::into_writer(&outcome, &mut outcome_bytes) {
        tracing::error!(sender = %sender_node_id, error = %e, "gossip/mtc/admin-query: encode response failed");
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
            tracing::error!(sender = %sender_node_id, error = %e, "gossip/mtc/admin-query: sign_and_seal response failed");
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

async fn process_admin_query(
    state: &Arc<AppState>,
    request: &AdminMtcRequest,
    now: i64,
) -> AdminMtcOutcome {
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
        return AdminMtcOutcome::Err(format!(
            "not the current MTC writer for CA '{}'",
            request.ca_id
        ));
    }

    let role: OperatorRole = match request.operator_role.parse() {
        Ok(r) => r,
        Err(e) => return AdminMtcOutcome::Err(format!("invalid operator_role: {e}")),
    };
    // Unscoped: the real CA-scope check already happened on the node that
    // received the operator's original request.
    let operator = OperatorContext {
        operator_id: 0,
        name: request.operator_name.clone(),
        role,
        ca_id: String::new(),
        auth_method: AdminAuthMethod::InternalPeer,
        session_token: None,
    };

    let response = dispatch(state, operator, &request.ca_id, &request.query).await;
    let status = response.status().as_u16();
    let content_type = response
        .headers()
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(String::from);
    let body = match axum::body::to_bytes(response.into_body(), 10 * 1024 * 1024).await {
        Ok(b) => b.to_vec(),
        Err(e) => return AdminMtcOutcome::Err(format!("buffer local response body: {e}")),
    };
    AdminMtcOutcome::Response {
        status,
        content_type,
        body,
    }
}

async fn dispatch(
    state: &Arc<AppState>,
    operator: OperatorContext,
    ca_id: &str,
    query: &AdminMtcQuery,
) -> Response {
    let st = State(Arc::clone(state));
    let result = match query {
        AdminMtcQuery::TreeSize => {
            admin::mtc::get_tree_size(
                operator,
                st,
                Query(MtcQuery {
                    ca_id: Some(ca_id.to_owned()),
                }),
            )
            .await
        }
        AdminMtcQuery::Root => {
            admin::mtc::get_root(
                operator,
                st,
                Query(MtcQuery {
                    ca_id: Some(ca_id.to_owned()),
                }),
            )
            .await
        }
        AdminMtcQuery::Landmarks => {
            admin::mtc::get_landmarks(
                operator,
                st,
                Query(MtcQuery {
                    ca_id: Some(ca_id.to_owned()),
                }),
            )
            .await
        }
        AdminMtcQuery::LandmarkList => {
            admin::mtc::get_landmark_list(
                operator,
                st,
                Query(MtcQuery {
                    ca_id: Some(ca_id.to_owned()),
                }),
            )
            .await
        }
        AdminMtcQuery::InclusionProof { cert_id } => {
            admin::mtc::get_inclusion_proof(operator, st, Path(cert_id.clone())).await
        }
        AdminMtcQuery::Standalone { cert_id } => {
            admin::mtc::get_standalone(operator, st, Path(cert_id.clone())).await
        }
        AdminMtcQuery::LandmarkCert { seq } => {
            admin::mtc::get_landmark_cert(
                operator,
                st,
                Path(*seq),
                Query(MtcQuery {
                    ca_id: Some(ca_id.to_owned()),
                }),
            )
            .await
        }
        AdminMtcQuery::LandmarkCertDetails { seq } => {
            admin::mtc::get_landmark_cert_details(
                operator,
                st,
                Path(*seq),
                Query(MtcQuery {
                    ca_id: Some(ca_id.to_owned()),
                }),
            )
            .await
        }
        AdminMtcQuery::ConsistencyProof { from, to } => {
            admin::mtc::get_consistency_proof(
                operator,
                st,
                Query(ConsistencyQuery {
                    ca_id: Some(ca_id.to_owned()),
                    from: Some(*from),
                    to: Some(*to),
                }),
            )
            .await
        }
        AdminMtcQuery::SubtreeRoot { start, end } => {
            admin::mtc::get_subtree_root(
                operator,
                st,
                Query(SubtreeRootQuery {
                    ca_id: Some(ca_id.to_owned()),
                    start: Some(*start),
                    end: Some(*end),
                }),
            )
            .await
        }
        AdminMtcQuery::RevokedRanges => {
            admin::mtc::get_revoked_ranges(
                operator,
                st,
                Query(MtcQuery {
                    ca_id: Some(ca_id.to_owned()),
                }),
            )
            .await
        }
        AdminMtcQuery::Checkpoint => {
            admin::mtc::get_checkpoint(
                operator,
                st,
                Query(MtcQuery {
                    ca_id: Some(ca_id.to_owned()),
                }),
            )
            .await
        }
        AdminMtcQuery::Cosignature => {
            admin::mtc::get_cosignature(
                operator,
                st,
                Query(MtcQuery {
                    ca_id: Some(ca_id.to_owned()),
                }),
            )
            .await
        }
        AdminMtcQuery::ForceCheckpoint => {
            admin::mtc::post_force_checkpoint(operator, st, Path(ca_id.to_owned())).await
        }
        AdminMtcQuery::ForceLandmark => {
            admin::mtc::post_force_landmark(operator, st, Path(ca_id.to_owned())).await
        }
        AdminMtcQuery::LogListEntry => {
            admin::mtc::get_log_list_entry(operator, st, Path(ca_id.to_owned())).await
        }
    };
    match result {
        Ok(resp) => resp,
        Err(e) => e.into_response(),
    }
}
