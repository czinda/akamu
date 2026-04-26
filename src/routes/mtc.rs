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
    let (size, root) = log::tree_size_and_root(shared_log).await?;
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

    let leaf_index = cert.mtc_log_index.ok_or(AcmeError::NotFound)? as u64;

    // Fetch proof and tree size under one lock to prevent TOCTOU.
    let (proof_pairs, size) = log::proof_and_tree_size(shared_log, leaf_index).await?;
    let proof: Vec<_> = proof_pairs
        .into_iter()
        .map(|(left, hash)| json!({ "left": left, "hash": hex(&hash) }))
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

/// GET /acme/mtc/cert/{cert_id}/standalone
///
/// Returns the DER-encoded `StandaloneCertificate` for the given certificate,
/// or 404 if the certificate is not found, has no MTC log index, or its
/// standalone cert has not yet been built (waiting for the next checkpoint).
pub async fn get_standalone(
    State(state): State<Arc<AppState>>,
    Path(cert_id): Path<String>,
) -> Result<Response, AcmeError> {
    state.mtc.log.as_ref().ok_or(AcmeError::NotFound)?;

    let der = db::certs::get_mtc_standalone_der(&state.db, &cert_id)
        .await?
        .ok_or(AcmeError::NotFound)?;

    Ok((
        StatusCode::OK,
        [(
            axum::http::header::CONTENT_TYPE,
            axum::http::HeaderValue::from_static("application/octet-stream"),
        )],
        der,
    )
        .into_response())
}

/// GET /acme/mtc/landmarks
///
/// Returns a JSON array of all allocated landmarks ordered by sequence number.
pub async fn get_landmarks(State(state): State<Arc<AppState>>) -> Result<Response, AcmeError> {
    state.mtc.log.as_ref().ok_or(AcmeError::NotFound)?;

    let landmarks = db::landmarks::list(&state.db).await?;
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

/// GET /acme/mtc/landmarks/{seq}/cert
///
/// Returns the DER-encoded `LandmarkCertificate` for the landmark with the
/// given sequence number, or 404 if not found or not yet built.
pub async fn get_landmark_cert(
    State(state): State<Arc<AppState>>,
    Path(seq): Path<i64>,
) -> Result<Response, AcmeError> {
    state.mtc.log.as_ref().ok_or(AcmeError::NotFound)?;

    let landmark = db::landmarks::get_by_seq(&state.db, seq)
        .await?
        .ok_or(AcmeError::NotFound)?;

    let der = landmark.cert_der.ok_or(AcmeError::NotFound)?;

    Ok((
        StatusCode::OK,
        [(
            axum::http::header::CONTENT_TYPE,
            axum::http::HeaderValue::from_static("application/octet-stream"),
        )],
        der,
    )
        .into_response())
}
