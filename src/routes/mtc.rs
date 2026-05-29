//! Read-only HTTP endpoints for the MTC transparency log.
//!
//! All endpoints return 404 when MTC logging is disabled for the resolved CA.

use std::collections::HashMap;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::json;
use std::sync::Arc;

use crate::db;
use crate::error::AcmeError;
use crate::mtc::{log, tlog};
use crate::state::AppState;

use super::{acme_prefix, CaId};

/// X-MTC-Version header value for draft-04 responses.
pub const MTC_DRAFT_VERSION: &str = "draft-04";

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// GET /acme/mtc/tree-size  or  GET /acme/{ca_id}/mtc/tree-size
pub async fn get_tree_size(
    State(state): State<Arc<AppState>>,
    ca_id: CaId,
) -> Result<Response, AcmeError> {
    let ca = state.get_ca(&ca_id.0).ok_or(AcmeError::NotFound)?;
    let shared_log = ca.mtc.log.as_ref().ok_or(AcmeError::NotFound)?;
    let size = log::tree_size(shared_log).await?;
    Ok((StatusCode::OK, axum::Json(json!({ "treeSize": size }))).into_response())
}

/// GET /acme/mtc/root  or  GET /acme/{ca_id}/mtc/root
pub async fn get_root(
    State(state): State<Arc<AppState>>,
    ca_id: CaId,
) -> Result<Response, AcmeError> {
    let ca = state.get_ca(&ca_id.0).ok_or(AcmeError::NotFound)?;
    let shared_log = ca.mtc.log.as_ref().ok_or(AcmeError::NotFound)?;
    let (size, root) = log::tree_size_and_root(shared_log).await?;
    Ok((
        StatusCode::OK,
        axum::Json(json!({ "treeSize": size, "rootHash": hex(&root) })),
    )
        .into_response())
}

/// GET /acme/mtc/inclusion-proof/{cert_id}  or  GET /acme/{ca_id}/mtc/inclusion-proof/{cert_id}
pub async fn get_inclusion_proof(
    State(state): State<Arc<AppState>>,
    ca_id: CaId,
    Path(params): Path<HashMap<String, String>>,
) -> Result<Response, AcmeError> {
    let cert_id = params.get("cert_id").ok_or(AcmeError::NotFound)?;
    let ca = state.get_ca(&ca_id.0).ok_or(AcmeError::NotFound)?;
    let shared_log = ca.mtc.log.as_ref().ok_or(AcmeError::NotFound)?;

    let cert = db::certs::get_by_id(&state.db, cert_id)
        .await?
        .ok_or(AcmeError::NotFound)?;

    let leaf_index = cert.mtc_log_index.ok_or(AcmeError::NotFound)? as u64;

    let (proof_hashes, size) = log::proof_and_tree_size(shared_log, leaf_index).await?;
    let proof: Vec<_> = proof_hashes
        .into_iter()
        .map(|hash| json!({ "hash": hex(&hash) }))
        .collect();

    Ok((
        StatusCode::OK,
        axum::Json(json!({
            "leafIndex": leaf_index,
            "treeSize": size,
            "proof": proof,
        })),
    )
        .into_response())
}

/// GET /acme/mtc/cert/{cert_id}/standalone  or  GET /acme/{ca_id}/mtc/cert/{cert_id}/standalone
pub async fn get_standalone(
    State(state): State<Arc<AppState>>,
    ca_id: CaId,
    Path(params): Path<HashMap<String, String>>,
) -> Result<Response, AcmeError> {
    let cert_id = params.get("cert_id").ok_or(AcmeError::NotFound)?;
    let ca = state.get_ca(&ca_id.0).ok_or(AcmeError::NotFound)?;
    ca.mtc.log.as_ref().ok_or(AcmeError::NotFound)?;

    let der = db::certs::get_mtc_standalone_der(&state.db, cert_id)
        .await?
        .ok_or(AcmeError::NotFound)?;

    Ok((
        StatusCode::OK,
        [
            (
                axum::http::header::CONTENT_TYPE,
                axum::http::HeaderValue::from_static("application/pkix-cert"),
            ),
            (
                axum::http::HeaderName::from_static("x-mtc-version"),
                axum::http::HeaderValue::from_static(MTC_DRAFT_VERSION),
            ),
        ],
        der,
    )
        .into_response())
}

/// GET /acme/mtc/landmarks  or  GET /acme/{ca_id}/mtc/landmarks
pub async fn get_landmarks(
    State(state): State<Arc<AppState>>,
    ca_id: CaId,
) -> Result<Response, AcmeError> {
    let ca = state.get_ca(&ca_id.0).ok_or(AcmeError::NotFound)?;
    ca.mtc.log.as_ref().ok_or(AcmeError::NotFound)?;

    let landmarks = db::landmarks::list(&state.db, &ca_id.0).await?;
    let body: Vec<_> = landmarks
        .iter()
        .map(|l| {
            json!({
                "sequenceNo": l.sequence_no,
                "treeSize": l.tree_size,
                "createdAt": l.created,
            })
        })
        .collect();

    Ok((StatusCode::OK, axum::Json(body)).into_response())
}

/// GET /acme/mtc/landmarks/{seq}/cert  or  GET /acme/{ca_id}/mtc/landmarks/{seq}/cert
pub async fn get_landmark_cert(
    State(state): State<Arc<AppState>>,
    ca_id: CaId,
    Path(params): Path<HashMap<String, String>>,
) -> Result<Response, AcmeError> {
    let seq: i64 = params
        .get("seq")
        .and_then(|s| s.parse().ok())
        .ok_or(AcmeError::NotFound)?;
    let ca = state.get_ca(&ca_id.0).ok_or(AcmeError::NotFound)?;
    ca.mtc.log.as_ref().ok_or(AcmeError::NotFound)?;

    let landmark = db::landmarks::get_by_seq(&state.db, &ca_id.0, seq)
        .await?
        .ok_or(AcmeError::NotFound)?;

    let der = landmark.cert_der.ok_or(AcmeError::NotFound)?;

    Ok((
        StatusCode::OK,
        [
            (
                axum::http::header::CONTENT_TYPE,
                axum::http::HeaderValue::from_static("application/pkix-cert"),
            ),
            (
                axum::http::HeaderName::from_static("x-mtc-version"),
                axum::http::HeaderValue::from_static(MTC_DRAFT_VERSION),
            ),
        ],
        der,
    )
        .into_response())
}

// ── C2SP tlog-tiles API ───────────────────────────────────────────────────────

/// GET /acme/mtc/tlog/checkpoint  or  GET /acme/{ca_id}/mtc/tlog/checkpoint
pub async fn get_tlog_checkpoint(
    State(state): State<Arc<AppState>>,
    ca_id: CaId,
) -> Result<Response, AcmeError> {
    let ca = state.get_ca(&ca_id.0).ok_or(AcmeError::NotFound)?;
    let shared_log = ca.mtc.log.as_ref().ok_or(AcmeError::NotFound)?;
    let key =
        ca.mtc.signing_key.as_ref().ok_or_else(|| {
            AcmeError::ServiceUnavailable("MTC signing key not configured".into())
        })?;

    let pfx = acme_prefix(&state.config.base_url, &ca_id.0, &state.default_ca_id);
    let origin = format!("{pfx}/mtc/tlog");
    let key_name = origin.clone();
    let hash_alg = &ca.mtc.signing_hash_alg;

    let note =
        tlog::produce_operator_checkpoint(shared_log, &key_name, key, hash_alg, &origin).await?;

    Ok((
        StatusCode::OK,
        [
            (
                axum::http::header::CONTENT_TYPE,
                axum::http::HeaderValue::from_static("text/plain; charset=utf-8"),
            ),
            (
                axum::http::header::CACHE_CONTROL,
                axum::http::HeaderValue::from_static("no-store"),
            ),
        ],
        note,
    )
        .into_response())
}

/// GET /acme/mtc/tlog/tile/{*path}  or  GET /acme/{ca_id}/mtc/tlog/tile/{*path}
pub async fn get_tlog_tile(
    State(state): State<Arc<AppState>>,
    ca_id: CaId,
    Path(params): Path<HashMap<String, String>>,
) -> Result<Response, AcmeError> {
    let path = params.get("path").ok_or(AcmeError::NotFound)?;
    let ca = state.get_ca(&ca_id.0).ok_or(AcmeError::NotFound)?;
    let shared_log = ca.mtc.log.as_ref().ok_or(AcmeError::NotFound)?;

    if path.starts_with("entries/") {
        return Ok((
            StatusCode::NOT_IMPLEMENTED,
            "entry bundles are not available; only hash tiles are served",
        )
            .into_response());
    }

    let tile = tlog::parse_tile_path(path)?;
    let bytes = tlog::get_tile_bytes(shared_log, ca.mtc.algorithm, &tile).await?;

    let cache = if tile.partial_width.is_some() {
        axum::http::HeaderValue::from_static("no-store")
    } else {
        axum::http::HeaderValue::from_static("public, max-age=86400")
    };

    let mut resp = (
        StatusCode::OK,
        [(
            axum::http::header::CONTENT_TYPE,
            axum::http::HeaderValue::from_static("application/octet-stream"),
        )],
        bytes,
    )
        .into_response();
    resp.headers_mut()
        .insert(axum::http::header::CACHE_CONTROL, cache);
    Ok(resp)
}

/// GET /acme/mtc/tlog/cosignature  or  GET /acme/{ca_id}/mtc/tlog/cosignature
pub async fn get_tlog_cosignature(
    State(state): State<Arc<AppState>>,
    ca_id: CaId,
) -> Result<Response, AcmeError> {
    let ca = state.get_ca(&ca_id.0).ok_or(AcmeError::NotFound)?;
    let shared_log = ca.mtc.log.as_ref().ok_or(AcmeError::NotFound)?;
    let key =
        ca.mtc.signing_key.as_ref().ok_or_else(|| {
            AcmeError::ServiceUnavailable("MTC signing key not configured".into())
        })?;

    let pfx = acme_prefix(&state.config.base_url, &ca_id.0, &state.default_ca_id);
    let origin = format!("{pfx}/mtc/tlog");
    let key_name = origin.clone();
    let hash_alg = &ca.mtc.signing_hash_alg;

    let note =
        tlog::produce_cosigner_checkpoint(shared_log, &key_name, key, hash_alg, &origin).await?;

    Ok((
        StatusCode::OK,
        [
            (
                axum::http::header::CONTENT_TYPE,
                axum::http::HeaderValue::from_static("text/plain; charset=utf-8"),
            ),
            (
                axum::http::header::CACHE_CONTROL,
                axum::http::HeaderValue::from_static("no-store"),
            ),
        ],
        note,
    )
        .into_response())
}
