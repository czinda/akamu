//! Reverse-proxy middleware for the public `/acme/mtc/*` read routes.
//!
//! For a given CA, the elected `mtc_writer` (see `crates/akamu-crdt` and
//! `gossip::mtc_forward`) is the only node whose local MTC log/DB state is
//! guaranteed current — every leaf-append is funneled to it. A non-writer
//! node's local state is frozen at whatever it had when it stopped being
//! (or never was) the writer, so serving these reads locally on a
//! non-writer would silently return stale, incomplete, or empty data to
//! external monitors/auditors. This middleware makes the writer the sole
//! real backend: any node that isn't the writer for the requested CA
//! transparently relays the whole request to the writer's same path and
//! streams the response back, so every one of these routes is correct
//! regardless of which cluster node a client happens to hit.
//!
//! Deliberately plain internal HTTP (no CMS wrap, unlike
//! `gossip::mtc_forward`'s authenticated append RPC): every route this
//! layer covers returns public data — this is a transparency log, third
//! parties are *supposed* to read it — and node-to-node traffic already
//! runs over the same trusted network path gossip itself assumes. Paying
//! ML-KEM-768/AES-256-GCM/ECDSA overhead to protect confidentiality that
//! doesn't need protecting would be wasted cost.
//!
//! `/admin/mtc/*` and `/admin/ca/{id}/mtc/*` have the same staleness
//! exposure but can't reuse this mechanism: their operator identity (Bearer
//! session, mTLS client cert, proxy-forwarded cert header) cannot survive a
//! raw HTTP relay to a second node. [`admin_mtc_writer_proxy`] instead
//! forwards a *description* of the already-authorized request over the
//! authenticated peer channel `gossip::mtc_admin` provides — see that
//! module for the full rationale.

use std::collections::HashMap;
use std::sync::Arc;

use axum::extract::{MatchedPath, Path, Query, Request, State};
use axum::http::{Method, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

use crate::admin::auth::OperatorContext;
use crate::db;
use crate::gossip::mtc_admin::{self, AdminMtcQuery, AdminQueryForward};
use crate::state::AppState;
use crate::util::unix_now;

use super::CaId;

pub(super) async fn mtc_writer_proxy(
    State(state): State<Arc<AppState>>,
    ca_id: CaId,
    req: Request,
    next: Next,
) -> Response {
    let now = unix_now();
    let ttl = state
        .config
        .gossip
        .as_ref()
        .map(|g| g.ownership_ttl_secs as i64)
        .unwrap_or(150);

    // Fast path: this node is (or is trivially, for a single-node
    // deployment, always) the writer — zero proxying overhead.
    if state
        .crdt
        .read()
        .await
        .is_mtc_writer(&ca_id.0, &state.node_id, now, ttl)
    {
        return next.run(req).await;
    }

    let Some(writer_url) = current_writer_url(&state, &ca_id.0).await else {
        // No writer elected yet for this CA (fresh/idle) — serve local
        // best-effort, matching pre-election behavior rather than failing
        // a read outright.
        return next.run(req).await;
    };

    proxy_to(&state.gossip_client, &writer_url, req).await
}

async fn current_writer_url(state: &AppState, ca_id: &str) -> Option<String> {
    let crdt = state.crdt.read().await;
    let writer_node_id = crdt.mtc_writer_claimant(ca_id)?;
    crdt.cluster_nodes
        .get(writer_node_id)
        .map(|n| n.gossip_url.clone())
}

/// Relay `req` to `{writer_url}{original path+query}` over plain HTTP,
/// streaming the response back verbatim.
async fn proxy_to(client: &reqwest::Client, writer_url: &str, req: Request) -> Response {
    let path_and_query = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");
    let target = format!("{}{path_and_query}", writer_url.trim_end_matches('/'));

    let method = req.method().clone();
    let headers = req.headers().clone();
    let body_bytes = match axum::body::to_bytes(req.into_body(), 10 * 1024 * 1024).await {
        Ok(b) => b,
        Err(e) => {
            tracing::error!(error = %e, "mtc proxy: failed to buffer request body");
            return StatusCode::BAD_GATEWAY.into_response();
        }
    };

    let reqwest_method =
        reqwest::Method::from_bytes(method.as_str().as_bytes()).unwrap_or(reqwest::Method::GET);
    let mut builder = client.request(reqwest_method, &target);
    for (name, value) in headers.iter() {
        // Hop-by-hop / destination-specific headers must not be forwarded
        // verbatim — reqwest recomputes host/content-length/connection for
        // the outbound request itself.
        if matches!(name.as_str(), "host" | "content-length" | "connection") {
            continue;
        }
        builder = builder.header(name.as_str(), value.as_bytes());
    }

    let resp = match builder.body(body_bytes).send().await {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(target = %target, error = %e, "mtc proxy: request to writer failed");
            return StatusCode::BAD_GATEWAY.into_response();
        }
    };

    let status = StatusCode::from_u16(resp.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
    let mut response_builder = Response::builder().status(status);
    for (name, value) in resp.headers().iter() {
        if matches!(
            name.as_str(),
            "content-length" | "connection" | "transfer-encoding"
        ) {
            continue;
        }
        if let Some(headers_mut) = response_builder.headers_mut() {
            headers_mut.insert(name.clone(), value.clone());
        }
    }

    let resp_bytes = match resp.bytes().await {
        Ok(b) => b,
        Err(e) => {
            tracing::warn!(target = %target, error = %e, "mtc proxy: failed to read writer response body");
            return StatusCode::BAD_GATEWAY.into_response();
        }
    };

    response_builder
        .body(axum::body::Body::from(resp_bytes))
        .map(IntoResponse::into_response)
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

// ── Admin MTC routes ─────────────────────────────────────────────────────────

/// Reverse-proxy for admin MTC routes — see the module doc for why this
/// forwards a typed query over `gossip::mtc_admin` rather than relaying the
/// raw HTTP request the way [`mtc_writer_proxy`] does.
///
/// `operator` reuses whatever `admin::rbac::admin_rbac_gate` already
/// resolved into request extensions (its `FromRequestParts` impl's fast
/// path) — this middleware runs *after* that gate (see
/// `routes::build_admin_router`), so RBAC has already run.
pub(super) async fn admin_mtc_writer_proxy(
    State(state): State<Arc<AppState>>,
    matched: MatchedPath,
    Path(path_params): Path<HashMap<String, String>>,
    Query(query_params): Query<HashMap<String, String>>,
    operator: OperatorContext,
    req: Request,
    next: Next,
) -> Response {
    let Some((ca_id, query)) = resolve_admin_mtc_query(
        &state,
        matched.as_str(),
        req.method(),
        &path_params,
        &query_params,
    )
    .await
    else {
        // Couldn't resolve a (ca_id, query) pair — missing/invalid required
        // params, or (for the cert-id routes) no such certificate. Defer to
        // the real handler so it produces the correct 400/404 rather than
        // duplicating that validation here.
        return next.run(req).await;
    };

    let now = unix_now();
    let ttl = state
        .config
        .gossip
        .as_ref()
        .map(|g| g.ownership_ttl_secs as i64)
        .unwrap_or(150);
    if state
        .crdt
        .read()
        .await
        .is_mtc_writer(&ca_id, &state.node_id, now, ttl)
    {
        return next.run(req).await;
    }
    let Some((writer_node_id, writer_url)) = current_writer(&state, &ca_id).await else {
        return next.run(req).await;
    };

    mtc_admin::forward_admin_query(
        &state,
        AdminQueryForward {
            ca_id: &ca_id,
            writer_node_id: &writer_node_id,
            writer_url: &writer_url,
            operator_name: &operator.name,
            operator_role: operator.role,
            query,
        },
    )
    .await
}

async fn current_writer(state: &AppState, ca_id: &str) -> Option<(String, String)> {
    let crdt = state.crdt.read().await;
    let writer_node_id = crdt.mtc_writer_claimant(ca_id)?.to_owned();
    let gossip_url = crdt.cluster_nodes.get(&writer_node_id)?.gossip_url.clone();
    Some((writer_node_id, gossip_url))
}

/// Map a matched admin MTC route to its `(ca_id, AdminMtcQuery)`, using
/// whichever of the three CA-resolution strategies that route's handler
/// (`routes::admin::mtc`) actually uses: an optional `ca_id` query parameter
/// defaulting to the server's default CA, a `{id}`/`{seq}` path parameter, or
/// (for the two certificate-download routes, which carry no CA identifier of
/// their own) a DB lookup by `cert_id`.
async fn resolve_admin_mtc_query(
    state: &AppState,
    route: &str,
    method: &Method,
    path_params: &HashMap<String, String>,
    query_params: &HashMap<String, String>,
) -> Option<(String, AdminMtcQuery)> {
    let ca_id_from_query = || {
        query_params
            .get("ca_id")
            .cloned()
            .unwrap_or_else(|| (*state.default_ca_id).clone())
    };

    match (method.as_str(), route) {
        ("GET", "/admin/mtc/tree-size") => Some((ca_id_from_query(), AdminMtcQuery::TreeSize)),
        ("GET", "/admin/mtc/root") => Some((ca_id_from_query(), AdminMtcQuery::Root)),
        ("GET", "/admin/mtc/landmarks") => Some((ca_id_from_query(), AdminMtcQuery::Landmarks)),
        ("GET", "/admin/mtc/landmark-list") => {
            Some((ca_id_from_query(), AdminMtcQuery::LandmarkList))
        }
        ("GET", "/admin/mtc/inclusion-proof/{cert_id}") => {
            let cert_id = path_params.get("cert_id")?.clone();
            let ca_id = db::certs::get_by_id(&state.db_ro, &cert_id)
                .await
                .ok()??
                .ca_id;
            Some((ca_id, AdminMtcQuery::InclusionProof { cert_id }))
        }
        ("GET", "/admin/mtc/standalone/{cert_id}") => {
            let cert_id = path_params.get("cert_id")?.clone();
            let ca_id = db::certs::get_by_id(&state.db_ro, &cert_id)
                .await
                .ok()??
                .ca_id;
            Some((ca_id, AdminMtcQuery::Standalone { cert_id }))
        }
        ("GET", "/admin/mtc/landmarks/{seq}/cert") => {
            let seq: i64 = path_params.get("seq")?.parse().ok()?;
            Some((ca_id_from_query(), AdminMtcQuery::LandmarkCert { seq }))
        }
        ("GET", "/admin/mtc/landmarks/{seq}/cert-details") => {
            let seq: i64 = path_params.get("seq")?.parse().ok()?;
            Some((
                ca_id_from_query(),
                AdminMtcQuery::LandmarkCertDetails { seq },
            ))
        }
        ("GET", "/admin/mtc/consistency-proof") => {
            let from: u64 = query_params.get("from")?.parse().ok()?;
            let to: u64 = query_params.get("to")?.parse().ok()?;
            Some((
                ca_id_from_query(),
                AdminMtcQuery::ConsistencyProof { from, to },
            ))
        }
        ("GET", "/admin/mtc/subtree-root") => {
            let start: u64 = query_params.get("start")?.parse().ok()?;
            let end: u64 = query_params.get("end")?.parse().ok()?;
            Some((
                ca_id_from_query(),
                AdminMtcQuery::SubtreeRoot { start, end },
            ))
        }
        ("GET", "/admin/mtc/revoked-ranges") => {
            Some((ca_id_from_query(), AdminMtcQuery::RevokedRanges))
        }
        ("GET", "/admin/mtc/checkpoint") => Some((ca_id_from_query(), AdminMtcQuery::Checkpoint)),
        ("GET", "/admin/mtc/cosignature") => Some((ca_id_from_query(), AdminMtcQuery::Cosignature)),
        ("POST", "/admin/ca/{id}/mtc/force-checkpoint") => Some((
            path_params.get("id")?.clone(),
            AdminMtcQuery::ForceCheckpoint,
        )),
        ("POST", "/admin/ca/{id}/mtc/force-landmark") => {
            Some((path_params.get("id")?.clone(), AdminMtcQuery::ForceLandmark))
        }
        ("GET", "/admin/ca/{id}/mtc/log-list-entry") => {
            Some((path_params.get("id")?.clone(), AdminMtcQuery::LogListEntry))
        }
        _ => None,
    }
}
