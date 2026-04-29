//! Read-only HTTP endpoints for the MTC transparency log.
//!
//! All endpoints return 404 when MTC logging is disabled.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::json;

use crate::db;
use crate::error::AcmeError;
use crate::mtc::{log, tlog};
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

// ── C2SP tlog-tiles API ───────────────────────────────────────────────────────

/// GET /acme/mtc/tlog/checkpoint
///
/// Returns the current C2SP signed-note checkpoint for the MTC transparency
/// log.  The note is signed by the MTC signing key (Ed25519 → type 0x01,
/// ECDSA → type 0x02).
///
/// Returns 404 when MTC logging is disabled and 503 when no signing key is
/// configured.
pub async fn get_tlog_checkpoint(
    State(state): State<Arc<AppState>>,
) -> Result<Response, AcmeError> {
    let shared_log = state.mtc.log.as_ref().ok_or(AcmeError::NotFound)?;
    let key = state
        .mtc
        .signing_key
        .as_ref()
        .ok_or_else(|| AcmeError::Internal("MTC signing key not configured".into()))?;

    let origin = format!("{}/acme/mtc/tlog", state.config.base_url);
    let key_name = origin.clone();
    let hash_alg = &state.mtc.signing_hash_alg;

    let note =
        tlog::produce_operator_checkpoint(shared_log, &key_name, key, hash_alg, &origin).await?;

    Ok((
        StatusCode::OK,
        [(
            axum::http::header::CONTENT_TYPE,
            axum::http::HeaderValue::from_static("text/plain; charset=utf-8"),
        )],
        note,
    )
        .into_response())
}

/// GET /acme/mtc/tlog/tile/{*path}
///
/// Serves a C2SP tlog-tiles hash tile.  The path component encodes:
/// `{level}/{tile_index_path}[.p/{width}]`
///
/// Level-0 tiles contain raw leaf hashes (32 bytes each for SHA-256).
/// Level-L tiles contain MTH subtree roots (covering 256^L leaves each).
/// Partial tiles (`.p/{width}`) contain fewer than 256 entries.
///
/// Returns 404 for tiles beyond the current log size or when MTC is disabled.
/// Returns 501 for entry bundle requests (`tile/entries/…`) because Akāmu
/// stores only leaf hashes, not the raw entry data.
pub async fn get_tlog_tile(
    State(state): State<Arc<AppState>>,
    Path(path): Path<String>,
) -> Result<Response, AcmeError> {
    let shared_log = state.mtc.log.as_ref().ok_or(AcmeError::NotFound)?;

    // Entry bundles are served at `tile/entries/…` — Akāmu stores hashes only.
    if path.starts_with("entries/") {
        return Ok((
            StatusCode::NOT_IMPLEMENTED,
            "entry bundles are not available; only hash tiles are served",
        )
            .into_response());
    }

    let tile = tlog::parse_tile_path(&path)?;
    let bytes = tlog::get_tile_bytes(shared_log, state.mtc.algorithm, &tile).await?;

    Ok((
        StatusCode::OK,
        [(
            axum::http::header::CONTENT_TYPE,
            axum::http::HeaderValue::from_static("application/octet-stream"),
        )],
        bytes,
    )
        .into_response())
}

/// GET /acme/mtc/tlog/cosignature
///
/// Returns a C2SP cosignature for the current checkpoint produced by Akāmu's
/// MTC signing key acting as a cosigner (Ed25519 → type 0x04, ML-DSA-44 →
/// type 0x06).
///
/// This endpoint allows Akāmu to act as a transparency-log cosigner for its
/// own log (e.g. when it also holds a separate cosigner key).  The timestamp
/// embedded in the cosignature blob is the current POSIX time.
///
/// Returns 404 when MTC logging is disabled and 503 when no signing key is
/// configured or the key type does not support the cosignature role.
pub async fn get_tlog_cosignature(
    State(state): State<Arc<AppState>>,
) -> Result<Response, AcmeError> {
    let shared_log = state.mtc.log.as_ref().ok_or(AcmeError::NotFound)?;
    let key = state
        .mtc
        .signing_key
        .as_ref()
        .ok_or_else(|| AcmeError::Internal("MTC signing key not configured".into()))?;

    let origin = format!("{}/acme/mtc/tlog", state.config.base_url);
    let key_name = origin.clone();
    let hash_alg = &state.mtc.signing_hash_alg;
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let note = tlog::produce_cosigner_checkpoint(shared_log, &key_name, key, hash_alg, &origin, ts)
        .await?;

    Ok((
        StatusCode::OK,
        [(
            axum::http::header::CONTENT_TYPE,
            axum::http::HeaderValue::from_static("text/plain; charset=utf-8"),
        )],
        note,
    )
        .into_response())
}
