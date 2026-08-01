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
//! Scope note: `/admin/mtc/*` and `/admin/ca/{id}/mtc/*` have the same
//! staleness exposure but are not covered here — their CA resolution is
//! RBAC/operator-scope-dependent (query param or path param depending on
//! the route, sometimes falling back to the operator's own CA scope) rather
//! than the uniform `CaId` extractor these public routes use, so proxying
//! them needs its own design pass. Tracked separately; operators hitting a
//! non-writer node's admin MTC endpoints should cross-check against the
//! writer in the meantime.

use std::sync::Arc;

use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

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
