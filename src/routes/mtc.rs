//! Read-only HTTP endpoints for the MTC transparency log.
//!
//! All endpoints return 404 when MTC logging is disabled.

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::json;

use crate::db;
use crate::error::AcmeError;
use crate::mtc::log;
use crate::state::AppState;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// GET /acme/mtc/tree-size
pub async fn get_tree_size(State(state): State<Arc<AppState>>) -> Result<Response, AcmeError> {
    let shared_log = state.mtc.log.as_ref().ok_or(AcmeError::NotFound)?;
    let size = log::tree_size(shared_log).await?;
    Ok((StatusCode::OK, axum::Json(json!({ "treeSize": size }))).into_response())
}

/// GET /acme/mtc/root
pub async fn get_root(State(state): State<Arc<AppState>>) -> Result<Response, AcmeError> {
    let shared_log = state.mtc.log.as_ref().ok_or(AcmeError::NotFound)?;
    let size = log::tree_size(shared_log).await?;
    let root = log::compute_root(shared_log).await?;
    Ok((
        StatusCode::OK,
        axum::Json(json!({ "treeSize": size, "rootHash": hex(&root) })),
    )
        .into_response())
}

/// GET /acme/mtc/inclusion-proof/{cert_id}
pub async fn get_inclusion_proof(
    State(state): State<Arc<AppState>>,
    Path(cert_id): Path<String>,
) -> Result<Response, AcmeError> {
    let shared_log = state.mtc.log.as_ref().ok_or(AcmeError::NotFound)?;

    let cert = db::certs::get_by_id(&state.db, &cert_id)
        .await?
        .ok_or(AcmeError::NotFound)?;

    let leaf_index = cert
        .mtc_log_index
        .ok_or(AcmeError::NotFound)? as u64;

    let proof_pairs = log::generate_proof(shared_log, leaf_index).await?;
    let proof: Vec<String> = proof_pairs
        .into_iter()
        .map(|(_, hash)| hex(&hash))
        .collect();

    let size = log::tree_size(shared_log).await?;
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

/// GET /acme/mtc/cert/{cert_id}/standalone
///
/// Returns the DER-encoded `StandaloneCertificate` for the given certificate,
/// or 404 if the certificate is not found, has no MTC log index, or its
/// standalone cert has not yet been built (waiting for the next checkpoint).
pub async fn get_standalone(
    State(state): State<Arc<AppState>>,
    Path(cert_id): Path<String>,
) -> Result<Response, AcmeError> {
    // MTC must be enabled.
    if state.mtc.log.is_none() {
        return Err(AcmeError::NotFound);
    }

    let der = db::certs::get_mtc_standalone_der(&state.db, &cert_id)
        .await?
        .ok_or(AcmeError::NotFound)?;

    Ok((
        StatusCode::OK,
        [(
            axum::http::header::CONTENT_TYPE,
            axum::http::HeaderValue::from_static("application/pkix-cert"),
        )],
        der,
    )
        .into_response())
}
