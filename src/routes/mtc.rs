//! Read-only HTTP endpoints for the MTC transparency log.
//!
//! All endpoints return 404 when MTC logging is disabled for the resolved CA.

use std::collections::HashMap;

use axum::extract::{Path, Query, State};
use axum::http::{HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;

use native_ossl::util::hex_encode;

use crate::db;
use crate::error::AcmeError;
use crate::mtc::{log, tlog};
use crate::state::AppState;

use super::CaId;

/// X-MTC-Version header value for draft-05 responses.
pub const MTC_DRAFT_VERSION: &str = "draft-05";

fn service_unavailable_with_retry(retry_secs: u64, detail: &str) -> Response {
    let body = serde_json::json!({
        "type": "urn:ietf:params:acme:error:serverInternal",
        "detail": detail
    });
    let mut resp = (
        StatusCode::SERVICE_UNAVAILABLE,
        serde_json::to_string(&body).expect("static JSON"),
    )
        .into_response();
    resp.headers_mut().insert(
        axum::http::header::CONTENT_TYPE,
        HeaderValue::from_static("application/problem+json"),
    );
    if let Ok(val) = HeaderValue::from_str(&retry_secs.to_string()) {
        resp.headers_mut().insert("retry-after", val);
    }
    resp
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
        axum::Json(json!({ "treeSize": size, "rootHash": hex_encode(&root) })),
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

    let cert = db::certs::get_by_id(&state.db_ro, cert_id)
        .await?
        .ok_or(AcmeError::NotFound)?;

    let log_index = cert.mtc_log_index.ok_or(AcmeError::NotFound)?;
    let leaf_index =
        u64::try_from(log_index).map_err(|_| AcmeError::Internal("invalid log index".into()))?;

    let (proof_hashes, size) = log::proof_and_tree_size(shared_log, leaf_index).await?;
    let proof: Vec<_> = proof_hashes
        .into_iter()
        .map(|hash| json!({ "hash": hex_encode(&hash) }))
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

    let der = db::certs::get_mtc_standalone_der(&state.db_ro, cert_id)
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

/// GET /acme/mtc/cert/{cert_id}/landmark  or  GET /acme/{ca_id}/mtc/cert/{cert_id}/landmark
///
/// Serves the landmark-relative MTC certificate for the given cert, i.e. the
/// first landmark whose tree_size covers the cert's log index.
pub async fn get_landmark_for_cert(
    State(state): State<Arc<AppState>>,
    ca_id: CaId,
    Path(params): Path<HashMap<String, String>>,
) -> Result<Response, AcmeError> {
    let cert_id = params.get("cert_id").ok_or(AcmeError::NotFound)?;
    let ca = state.get_ca(&ca_id.0).ok_or(AcmeError::NotFound)?;
    ca.mtc.log.as_ref().ok_or(AcmeError::NotFound)?;

    let cert = db::certs::get_by_id(&state.db_ro, cert_id)
        .await?
        .ok_or(AcmeError::NotFound)?;
    let log_index = cert.mtc_log_index.ok_or(AcmeError::NotFound)?;

    let landmark = db::landmarks::get_covering(&state.db_ro, &ca_id.0, log_index).await?;

    match landmark {
        Some(lm) => match lm.cert_der {
            Some(der) => Ok((
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
                .into_response()),
            None => {
                let retry = ca.mtc.checkpoint_interval_secs.max(60);
                Ok(service_unavailable_with_retry(
                    retry,
                    "landmark certificate not yet available",
                ))
            }
        },
        None => {
            let retry = ca.mtc.checkpoint_interval_secs.max(60);
            Ok(service_unavailable_with_retry(
                retry,
                "no landmark covers this certificate yet",
            ))
        }
    }
}

/// GET /acme/mtc/landmarks  or  GET /acme/{ca_id}/mtc/landmarks
pub async fn get_landmarks(
    State(state): State<Arc<AppState>>,
    ca_id: CaId,
) -> Result<Response, AcmeError> {
    let ca = state.get_ca(&ca_id.0).ok_or(AcmeError::NotFound)?;
    ca.mtc.log.as_ref().ok_or(AcmeError::NotFound)?;

    let landmarks = db::landmarks::list(&state.db_ro, &ca_id.0).await?;
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

/// GET /acme/mtc/landmark-list  or  GET /acme/{ca_id}/mtc/landmark-list
///
/// Serves the landmark list in spec §3.4 text/plain format for use by
/// `LandmarkDistributor` clients and spec-compliant relying parties.
///
/// Format: `{last_seq_no} {count}\n{tree_size_newest}\n...\n{prev_tree_size}\n`
pub async fn get_landmark_list(
    State(state): State<Arc<AppState>>,
    ca_id: CaId,
) -> Result<Response, AcmeError> {
    let ca = state.get_ca(&ca_id.0).ok_or(AcmeError::NotFound)?;
    ca.mtc.log.as_ref().ok_or(AcmeError::NotFound)?;

    let landmarks = db::landmarks::list(&state.db_ro, &ca_id.0).await?;

    let body = if landmarks.is_empty() {
        String::new()
    } else {
        let count = landmarks.len();
        let last_seq = landmarks.last().unwrap().sequence_no;
        let mut s = format!("{last_seq} {count}\n");
        for lm in landmarks.iter().rev() {
            s.push_str(&format!("{}\n", lm.tree_size));
        }
        // prev_tree_size = 0: covers all entries from genesis.
        // Update when pruning tracking is added.
        s.push_str("0\n");
        s
    };

    Ok((
        StatusCode::OK,
        [
            (
                axum::http::header::CONTENT_TYPE,
                axum::http::HeaderValue::from_static("text/plain; charset=utf-8"),
            ),
            (
                axum::http::HeaderName::from_static("x-mtc-version"),
                axum::http::HeaderValue::from_static(MTC_DRAFT_VERSION),
            ),
        ],
        body,
    )
        .into_response())
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

    let landmark = db::landmarks::get_by_seq(&state.db_ro, &ca_id.0, seq)
        .await?
        .ok_or(AcmeError::NotFound)?;

    let Some(der) = landmark.cert_der else {
        let retry = ca.mtc.checkpoint_interval_secs.max(60);
        return Ok(service_unavailable_with_retry(
            retry,
            "landmark certificate not yet available",
        ));
    };

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

    let origin = ca.mtc.tlog_origin().ok_or_else(|| {
        AcmeError::ServiceUnavailable("mtc.trust_anchor_id not configured".into())
    })?;
    let hash_alg = &ca.mtc.signing_hash_alg;

    let note = tlog::produce_operator_checkpoint(shared_log, origin, key, hash_alg, origin).await?;

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

    let cosigner_name = ca.mtc.cosigner_name().ok_or_else(|| {
        AcmeError::ServiceUnavailable("mtc.trust_anchor_id not configured".into())
    })?;
    let origin = ca.mtc.tlog_origin().ok_or_else(|| {
        AcmeError::ServiceUnavailable("mtc.trust_anchor_id not configured".into())
    })?;
    let hash_alg = &ca.mtc.signing_hash_alg;

    let note =
        tlog::produce_cosigner_checkpoint(shared_log, cosigner_name, key, hash_alg, origin).await?;

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

#[derive(Deserialize)]
pub struct ConsistencyParams {
    pub from: u64,
    pub to: u64,
}

/// GET /acme/mtc/consistency-proof?from={old_size}&to={new_size}
///
/// Returns the Merkle roots at both tree sizes so a monitor can verify
/// that the tree at `to` extends the tree at `from`.
pub async fn get_consistency_proof(
    State(state): State<Arc<AppState>>,
    ca_id: CaId,
    Query(params): Query<ConsistencyParams>,
) -> Result<Response, AcmeError> {
    let ca = state.get_ca(&ca_id.0).ok_or(AcmeError::NotFound)?;
    let shared_log = ca.mtc.log.as_ref().ok_or(AcmeError::NotFound)?;

    if params.from == 0 || params.to == 0 {
        return Err(AcmeError::BadRequest("from and to must be positive".into()));
    }
    if params.from >= params.to {
        return Err(AcmeError::BadRequest("from must be less than to".into()));
    }

    let current_size = log::tree_size(shared_log).await?;
    if params.to > current_size {
        return Err(AcmeError::BadRequest(format!(
            "to ({}) exceeds current tree size ({})",
            params.to, current_size
        )));
    }

    let (from_root, to_root) =
        log::compute_roots_at_sizes(shared_log, ca.mtc.algorithm, params.from, params.to).await?;

    Ok((
        StatusCode::OK,
        axum::Json(json!({
            "fromSize": params.from,
            "toSize": params.to,
            "fromRoot": hex_encode(&from_root),
            "toRoot": hex_encode(&to_root),
        })),
    )
        .into_response())
}

#[derive(Deserialize)]
pub struct SubtreeRootParams {
    pub start: u64,
    pub end: u64,
}

/// GET /acme/mtc/subtree-root?start={start}&end={end}
///
/// Returns the Merkle root hash for the subtree `[start, end)`.  The subtree
/// must satisfy the alignment constraint from §4.3.1 (`start` is a multiple
/// of `BIT_CEIL(end - start)`).
pub async fn get_subtree_root(
    State(state): State<Arc<AppState>>,
    ca_id: CaId,
    Query(params): Query<SubtreeRootParams>,
) -> Result<Response, AcmeError> {
    let ca = state.get_ca(&ca_id.0).ok_or(AcmeError::NotFound)?;
    let shared_log = ca.mtc.log.as_ref().ok_or(AcmeError::NotFound)?;

    if params.start >= params.end {
        return Err(AcmeError::BadRequest("start must be less than end".into()));
    }

    let size = params.end - params.start;
    let alignment = size.checked_next_power_of_two().unwrap_or(u64::MAX);
    if !params.start.is_multiple_of(alignment) {
        return Err(AcmeError::BadRequest(format!(
            "start {} is not aligned to BIT_CEIL({}) = {} (§4.3.1)",
            params.start, size, alignment
        )));
    }

    let current_size = log::tree_size(shared_log).await?;
    if params.end > current_size {
        return Err(AcmeError::BadRequest(format!(
            "end ({}) exceeds current tree size ({})",
            params.end, current_size
        )));
    }

    let hashes = log::read_hash_range(
        shared_log,
        params.start,
        (params.end - params.start) as usize,
    )
    .await?;
    let subtree_root = synta_mtc::crypto::generate_subtree_hash(ca.mtc.algorithm, &hashes)
        .map_err(|e| AcmeError::Mtc(format!("generate_subtree_hash: {e}")))?;

    Ok((
        StatusCode::OK,
        axum::Json(json!({
            "start": params.start,
            "end": params.end,
            "rootHash": hex_encode(&subtree_root),
        })),
    )
        .into_response())
}

/// GET /acme/mtc/discovery  or  GET /acme/{ca_id}/mtc/discovery
///
/// Returns a CosignersStore-compatible JSON object describing this issuer
/// and its configured external cosigners.
pub async fn get_discovery(
    State(state): State<Arc<AppState>>,
    ca_id: CaId,
) -> Result<Response, AcmeError> {
    let ca = state.get_ca(&ca_id.0).ok_or(AcmeError::NotFound)?;
    ca.mtc.log.as_ref().ok_or(AcmeError::NotFound)?;

    let key_sha256 =
        ca.mtc.signing_key_sha256.as_deref().ok_or_else(|| {
            AcmeError::ServiceUnavailable("MTC signing key not configured".into())
        })?;
    let base_id = ca.mtc.trust_anchor_id.as_deref().ok_or_else(|| {
        AcmeError::ServiceUnavailable("mtc.trust_anchor_id not configured".into())
    })?;

    let pfx = super::acme_prefix(&state.config.base_url, &ca_id.0, &state.default_ca_id);

    let friendly = ca.mtc.friendly_name.as_deref().unwrap_or(&ca_id.0);

    let issuer = json!({
        "friendly_name": friendly,
        "base_id": base_id,
        "base_url": format!("{pfx}/mtc"),
        "type": "ISSUER",
        "key_sha256": key_sha256,
        "max_cert_lifetime_seconds": u64::from(ca.validity_days) * 86400,
    });

    let cosigners: Vec<_> = ca
        .mtc
        .cosigner_clients
        .iter()
        .map(|c| {
            let mut obj = json!({
                "base_url": c.url,
                "type": "COSIGNER",
            });
            if let Some(ref name) = c.friendly_name {
                obj["friendly_name"] = json!(name);
            } else {
                obj["friendly_name"] = json!(&c.url);
            }
            if let Some(ref id) = c.trust_anchor_id {
                obj["base_id"] = json!(id);
            }
            if let Some(ref hash) = c.key_sha256 {
                obj["key_sha256"] = json!(hash);
            }
            obj
        })
        .collect();

    let body = json!({
        "version": "1.0",
        "issuers": [issuer],
        "cosigners": cosigners,
    });

    let mut resp = (StatusCode::OK, axum::Json(body)).into_response();
    resp.headers_mut().insert(
        axum::http::header::CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=3600"),
    );
    Ok(resp)
}

/// GET /acme/mtc/revoked-ranges  or  GET /acme/{ca_id}/mtc/revoked-ranges
///
/// Returns a JSON array of `[start, end]` pairs representing revoked log entry
/// index ranges (§5.6).  Relying parties use these to reject standalone
/// certificates whose serial number falls within a revoked range.
pub async fn get_revoked_ranges(
    State(state): State<Arc<AppState>>,
    ca_id: CaId,
) -> Result<Response, AcmeError> {
    let _ca = state.get_ca(&ca_id.0).ok_or(AcmeError::NotFound)?;
    let rows = db::revoked_ranges::get_all(&state.db_ro, &ca_id.0).await?;
    let ranges: Vec<_> = rows.iter().map(|r| [r.range_start, r.range_end]).collect();
    Ok((StatusCode::OK, axum::Json(json!(ranges))).into_response())
}
