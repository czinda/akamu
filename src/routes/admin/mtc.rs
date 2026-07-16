//! Admin MTC transparency log endpoints.
//!
//! These endpoints mirror the public `/acme/mtc/…` endpoints on the admin
//! listener and add admin-only actions (force-checkpoint, force-landmark).

use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::{HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;
use serde_json::json;

use native_ossl::util::hex_encode;

use crate::admin::auth::OperatorContext;
use crate::audit::{AuditEvent, AuditEventType};
use crate::db;
use crate::error::AcmeError;
use crate::mtc::{
    checkpoint::{produce_checkpoint, CheckpointParams},
    landmark::{maybe_allocate_landmark, LandmarkAllocationParams},
    log, tlog,
};
use crate::require_role;
use crate::routes::acme_prefix;
use crate::state::{AppState, CaState};

#[derive(Deserialize)]
pub struct MtcQuery {
    pub ca_id: Option<String>,
}

fn resolve_ca<'a>(
    state: &'a AppState,
    ca_id_opt: Option<&'a str>,
    operator: &OperatorContext,
) -> Option<(&'a str, &'a Arc<CaState>)> {
    let ca_id = ca_id_opt.unwrap_or(&state.default_ca_id);
    if let Some(scope) = operator.ca_scope() {
        if ca_id != scope {
            tracing::debug!(ca_id, operator = %operator.name, "CA scope mismatch");
            return None;
        }
    }
    state.get_ca(ca_id).map(|ca| (ca_id, ca))
}

fn not_found() -> Response {
    (
        StatusCode::NOT_FOUND,
        Json(json!({"status": 404, "detail": "not found"})),
    )
        .into_response()
}

fn mtc_disabled() -> Response {
    (
        StatusCode::NOT_FOUND,
        Json(json!({"status": 404, "detail": "MTC not enabled for this CA"})),
    )
        .into_response()
}

// ── Read-only query endpoints ───────────────────────────────────────────────

/// `GET /admin/mtc/tree-size`
///
/// Returns the current MTC log tree size.  Requires: Administrator | CaOperations | Auditor.
pub async fn get_tree_size(
    operator: OperatorContext,
    State(state): State<Arc<AppState>>,
    Query(q): Query<MtcQuery>,
) -> Response {
    require_role!(operator, state, Administrator | CaOperations | Auditor);
    let Some((_ca_id, ca)) = resolve_ca(&state, q.ca_id.as_deref(), &operator) else {
        return not_found();
    };
    let Some(shared_log) = ca.mtc.log.as_ref() else {
        return mtc_disabled();
    };
    match log::tree_size(shared_log).await {
        Ok(size) => (StatusCode::OK, Json(json!({"treeSize": size}))).into_response(),
        Err(e) => e.into_response(),
    }
}

/// `GET /admin/mtc/root`
///
/// Returns tree size and root hash.  Requires: Administrator | CaOperations | Auditor.
pub async fn get_root(
    operator: OperatorContext,
    State(state): State<Arc<AppState>>,
    Query(q): Query<MtcQuery>,
) -> Response {
    require_role!(operator, state, Administrator | CaOperations | Auditor);
    let Some((_ca_id, ca)) = resolve_ca(&state, q.ca_id.as_deref(), &operator) else {
        return not_found();
    };
    let Some(shared_log) = ca.mtc.log.as_ref() else {
        return mtc_disabled();
    };
    match log::tree_size_and_root(shared_log).await {
        Ok((size, root)) => (
            StatusCode::OK,
            Json(json!({"treeSize": size, "rootHash": hex_encode(&root)})),
        )
            .into_response(),
        Err(e) => e.into_response(),
    }
}

/// `GET /admin/mtc/landmarks`
///
/// Returns landmark list as JSON.  Requires: Administrator | CaOperations | Auditor.
pub async fn get_landmarks(
    operator: OperatorContext,
    State(state): State<Arc<AppState>>,
    Query(q): Query<MtcQuery>,
) -> Response {
    require_role!(operator, state, Administrator | CaOperations | Auditor);
    let Some((ca_id, ca)) = resolve_ca(&state, q.ca_id.as_deref(), &operator) else {
        return not_found();
    };
    if ca.mtc.log.is_none() {
        return mtc_disabled();
    }
    match db::landmarks::list(&state.db_ro, ca_id).await {
        Ok(landmarks) => {
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
            (StatusCode::OK, Json(json!(body))).into_response()
        }
        Err(e) => e.into_response(),
    }
}

/// `GET /admin/mtc/landmark-list`
///
/// Returns landmarks in spec section 3.4 text format.  Requires: Administrator | CaOperations | Auditor.
pub async fn get_landmark_list(
    operator: OperatorContext,
    State(state): State<Arc<AppState>>,
    Query(q): Query<MtcQuery>,
) -> Response {
    require_role!(operator, state, Administrator | CaOperations | Auditor);
    let Some((ca_id, ca)) = resolve_ca(&state, q.ca_id.as_deref(), &operator) else {
        return not_found();
    };
    if ca.mtc.log.is_none() {
        return mtc_disabled();
    }
    match db::landmarks::list(&state.db_ro, ca_id).await {
        Ok(landmarks) => {
            let body = if landmarks.is_empty() {
                String::new()
            } else {
                let count = landmarks.len();
                let last_seq = landmarks.last().unwrap().sequence_no;
                let mut s = format!("{last_seq} {count}\n");
                for lm in landmarks.iter().rev() {
                    s.push_str(&format!("{}\n", lm.tree_size));
                }
                s.push_str("0\n");
                s
            };
            (
                StatusCode::OK,
                [(
                    axum::http::header::CONTENT_TYPE,
                    HeaderValue::from_static("text/plain; charset=utf-8"),
                )],
                body,
            )
                .into_response()
        }
        Err(e) => e.into_response(),
    }
}

/// `GET /admin/mtc/inclusion-proof/{cert_id}`
///
/// Returns inclusion proof for a certificate.  Requires: Administrator | CaOperations | Auditor.
pub async fn get_inclusion_proof(
    operator: OperatorContext,
    State(state): State<Arc<AppState>>,
    Path(cert_id): Path<String>,
) -> Response {
    require_role!(operator, state, Administrator | CaOperations | Auditor);
    let cert = match db::certs::get_by_id(&state.db_ro, &cert_id).await {
        Ok(Some(c)) => c,
        Ok(None) => return not_found(),
        Err(e) => return e.into_response(),
    };
    if let Some(scope) = operator.ca_scope() {
        if cert.ca_id != scope {
            return not_found();
        }
    }
    let ca_id = cert.ca_id.as_str();
    let ca = match state.get_ca(ca_id) {
        Some(ca) => ca,
        None => return not_found(),
    };
    let Some(shared_log) = ca.mtc.log.as_ref() else {
        return mtc_disabled();
    };
    let Some(log_index) = cert.mtc_log_index else {
        return not_found();
    };
    let leaf_index = match u64::try_from(log_index) {
        Ok(i) => i,
        Err(_) => {
            return AcmeError::Internal("invalid log index".into()).into_response();
        }
    };
    match log::proof_and_tree_size(shared_log, leaf_index).await {
        Ok((proof_hashes, size)) => {
            let proof: Vec<_> = proof_hashes
                .into_iter()
                .map(|hash| json!({"hash": hex_encode(&hash)}))
                .collect();
            (
                StatusCode::OK,
                Json(json!({
                    "leafIndex": leaf_index,
                    "treeSize": size,
                    "proof": proof,
                })),
            )
                .into_response()
        }
        Err(e) => e.into_response(),
    }
}

/// `GET /admin/mtc/standalone/{cert_id}`
///
/// Downloads standalone DER certificate.  Requires: Administrator | CaOperations.
pub async fn get_standalone(
    operator: OperatorContext,
    State(state): State<Arc<AppState>>,
    Path(cert_id): Path<String>,
) -> Response {
    require_role!(operator, state, Administrator | CaOperations);
    let cert_ca = match db::certs::get_by_id(&state.db_ro, &cert_id).await {
        Ok(Some(c)) => c,
        Ok(None) => return not_found(),
        Err(e) => return e.into_response(),
    };
    if let Some(scope) = operator.ca_scope() {
        if cert_ca.ca_id != scope {
            return not_found();
        }
    }
    match db::certs::get_mtc_standalone_der(&state.db_ro, &cert_id).await {
        Ok(Some(der)) => (
            StatusCode::OK,
            [(
                axum::http::header::CONTENT_TYPE,
                HeaderValue::from_static("application/octet-stream"),
            )],
            der,
        )
            .into_response(),
        Ok(None) => not_found(),
        Err(e) => e.into_response(),
    }
}

/// `GET /admin/mtc/landmarks/{seq}/cert`
///
/// Downloads landmark certificate DER.  Requires: Administrator | CaOperations.
pub async fn get_landmark_cert(
    operator: OperatorContext,
    State(state): State<Arc<AppState>>,
    Path(seq): Path<i64>,
    Query(q): Query<MtcQuery>,
) -> Response {
    require_role!(operator, state, Administrator | CaOperations);
    let Some((ca_id, ca)) = resolve_ca(&state, q.ca_id.as_deref(), &operator) else {
        return not_found();
    };
    if ca.mtc.log.is_none() {
        return mtc_disabled();
    }
    match db::landmarks::get_by_seq(&state.db_ro, ca_id, seq).await {
        Ok(Some(lm)) => match lm.cert_der {
            Some(der) => (
                StatusCode::OK,
                [(
                    axum::http::header::CONTENT_TYPE,
                    HeaderValue::from_static("application/octet-stream"),
                )],
                der,
            )
                .into_response(),
            None => (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"detail": "landmark certificate not yet built"})),
            )
                .into_response(),
        },
        Ok(None) => not_found(),
        Err(e) => e.into_response(),
    }
}

#[derive(Deserialize)]
pub struct ConsistencyQuery {
    pub ca_id: Option<String>,
    pub from: u64,
    pub to: u64,
}

/// `GET /admin/mtc/consistency-proof`
///
/// Returns root hashes for consistency verification.  Requires: Administrator | CaOperations | Auditor.
pub async fn get_consistency_proof(
    operator: OperatorContext,
    State(state): State<Arc<AppState>>,
    Query(q): Query<ConsistencyQuery>,
) -> Response {
    require_role!(operator, state, Administrator | CaOperations | Auditor);
    let Some((_ca_id, ca)) = resolve_ca(&state, q.ca_id.as_deref(), &operator) else {
        return not_found();
    };
    let Some(shared_log) = ca.mtc.log.as_ref() else {
        return mtc_disabled();
    };
    if q.from == 0 || q.to == 0 || q.from >= q.to {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"detail": "from and to must be positive with from < to"})),
        )
            .into_response();
    }
    let current_size = match log::tree_size(shared_log).await {
        Ok(s) => s,
        Err(e) => return e.into_response(),
    };
    if q.to > current_size {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"detail": format!("to ({}) exceeds tree size ({})", q.to, current_size)})),
        )
            .into_response();
    }
    let from_root = match log::compute_root_at_size(shared_log, ca.mtc.algorithm, q.from).await {
        Ok(r) => r,
        Err(e) => return e.into_response(),
    };
    let to_root = match log::compute_root_at_size(shared_log, ca.mtc.algorithm, q.to).await {
        Ok(r) => r,
        Err(e) => return e.into_response(),
    };
    (
        StatusCode::OK,
        Json(json!({
            "fromSize": q.from,
            "toSize": q.to,
            "fromRoot": hex_encode(&from_root),
            "toRoot": hex_encode(&to_root),
        })),
    )
        .into_response()
}

#[derive(Deserialize)]
pub struct SubtreeRootQuery {
    pub ca_id: Option<String>,
    pub start: u64,
    pub end: u64,
}

/// `GET /admin/mtc/subtree-root`
///
/// Computes subtree root hash over a leaf range.  Requires: Administrator | CaOperations | Auditor.
pub async fn get_subtree_root(
    operator: OperatorContext,
    State(state): State<Arc<AppState>>,
    Query(q): Query<SubtreeRootQuery>,
) -> Response {
    require_role!(operator, state, Administrator | CaOperations | Auditor);
    let Some((_ca_id, ca)) = resolve_ca(&state, q.ca_id.as_deref(), &operator) else {
        return not_found();
    };
    let Some(shared_log) = ca.mtc.log.as_ref() else {
        return mtc_disabled();
    };
    if q.start >= q.end {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"detail": "start must be less than end"})),
        )
            .into_response();
    }
    let size = q.end - q.start;
    let alignment = size.checked_next_power_of_two().unwrap_or(u64::MAX);
    if !q.start.is_multiple_of(alignment) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"detail": format!(
                "start must be aligned to the next power of two of the range size \
                 (start={}, size={size}, required alignment={alignment})",
                q.start
            )})),
        )
            .into_response();
    }
    let current_size = match log::tree_size(shared_log).await {
        Ok(s) => s,
        Err(e) => return e.into_response(),
    };
    if q.end > current_size {
        return (
            StatusCode::BAD_REQUEST,
            Json(
                json!({"detail": format!("end ({}) exceeds tree size ({})", q.end, current_size)}),
            ),
        )
            .into_response();
    }
    let hashes = match log::read_hash_range(shared_log, q.start, (q.end - q.start) as usize).await {
        Ok(h) => h,
        Err(e) => return e.into_response(),
    };
    match synta_mtc::crypto::generate_subtree_hash(ca.mtc.algorithm, &hashes) {
        Ok(root) => (
            StatusCode::OK,
            Json(json!({
                "start": q.start,
                "end": q.end,
                "rootHash": hex_encode(&root),
            })),
        )
            .into_response(),
        Err(e) => AcmeError::Mtc(format!("generate_subtree_hash: {e}")).into_response(),
    }
}

/// `GET /admin/mtc/revoked-ranges`
///
/// Returns revoked leaf-index ranges.  Requires: Administrator | CaOperations | Auditor.
pub async fn get_revoked_ranges(
    operator: OperatorContext,
    State(state): State<Arc<AppState>>,
    Query(q): Query<MtcQuery>,
) -> Response {
    require_role!(operator, state, Administrator | CaOperations | Auditor);
    let Some((ca_id, ca)) = resolve_ca(&state, q.ca_id.as_deref(), &operator) else {
        return not_found();
    };
    if ca.mtc.log.is_none() {
        return mtc_disabled();
    }
    match db::revoked_ranges::get_all(&state.db_ro, ca_id).await {
        Ok(rows) => {
            let ranges: Vec<_> = rows.iter().map(|r| [r.range_start, r.range_end]).collect();
            (StatusCode::OK, Json(json!(ranges))).into_response()
        }
        Err(e) => e.into_response(),
    }
}

/// `GET /admin/mtc/checkpoint`
///
/// Returns C2SP tlog operator checkpoint.  Requires: Administrator | CaOperations | Auditor.
pub async fn get_checkpoint(
    operator: OperatorContext,
    State(state): State<Arc<AppState>>,
    Query(q): Query<MtcQuery>,
) -> Response {
    require_role!(operator, state, Administrator | CaOperations | Auditor);
    let Some((ca_id, ca)) = resolve_ca(&state, q.ca_id.as_deref(), &operator) else {
        return not_found();
    };
    let Some(shared_log) = ca.mtc.log.as_ref() else {
        return mtc_disabled();
    };
    let Some(key) = ca.mtc.signing_key.as_ref() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"detail": "MTC signing key not configured"})),
        )
            .into_response();
    };
    let pfx = acme_prefix(&state.config.base_url, ca_id, &state.default_ca_id);
    let origin = format!("{pfx}/mtc/tlog");
    let key_name = origin.clone();
    match tlog::produce_operator_checkpoint(
        shared_log,
        &key_name,
        key,
        &ca.mtc.signing_hash_alg,
        &origin,
    )
    .await
    {
        Ok(note) => (
            StatusCode::OK,
            [(
                axum::http::header::CONTENT_TYPE,
                HeaderValue::from_static("text/plain; charset=utf-8"),
            )],
            note,
        )
            .into_response(),
        Err(e) => e.into_response(),
    }
}

/// `GET /admin/mtc/cosignature`
///
/// Returns C2SP tlog cosignature checkpoint.  Requires: Administrator | CaOperations | Auditor.
pub async fn get_cosignature(
    operator: OperatorContext,
    State(state): State<Arc<AppState>>,
    Query(q): Query<MtcQuery>,
) -> Response {
    require_role!(operator, state, Administrator | CaOperations | Auditor);
    let Some((ca_id, ca)) = resolve_ca(&state, q.ca_id.as_deref(), &operator) else {
        return not_found();
    };
    let Some(shared_log) = ca.mtc.log.as_ref() else {
        return mtc_disabled();
    };
    let Some(key) = ca.mtc.signing_key.as_ref() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"detail": "MTC signing key not configured"})),
        )
            .into_response();
    };
    let pfx = acme_prefix(&state.config.base_url, ca_id, &state.default_ca_id);
    let origin = format!("{pfx}/mtc/tlog");
    let key_name = origin.clone();
    match tlog::produce_cosigner_checkpoint(
        shared_log,
        &key_name,
        key,
        &ca.mtc.signing_hash_alg,
        &origin,
    )
    .await
    {
        Ok(note) => (
            StatusCode::OK,
            [(
                axum::http::header::CONTENT_TYPE,
                HeaderValue::from_static("text/plain; charset=utf-8"),
            )],
            note,
        )
            .into_response(),
        Err(e) => e.into_response(),
    }
}

// ── Admin-only action endpoints ─────────────────────────────────────────────

/// `POST /admin/ca/{id}/mtc/force-checkpoint`
///
/// Forces an immediate MTC checkpoint.  Requires: Administrator | CaOperations.
pub async fn post_force_checkpoint(
    operator: OperatorContext,
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Response {
    require_role!(operator, state, Administrator | CaOperations);
    if operator.ca_scope().is_some_and(|scope| id != scope) {
        return not_found();
    }
    let Some(ca) = state.get_ca(&id) else {
        return not_found();
    };
    let (Some(log), Some(signing_key)) = (ca.mtc.log.as_ref(), ca.mtc.signing_key.as_ref()) else {
        return mtc_disabled();
    };
    let result = produce_checkpoint(CheckpointParams {
        log,
        signing_key,
        signing_hash_alg: &ca.mtc.signing_hash_alg,
        log_algorithm: ca.mtc.algorithm,
        db: &state.db,
        ca_id: &id,
        cosigners: &ca.mtc.cosigner_clients,
        log_number: ca.mtc.log_number,
        tree_minimum_index: ca.mtc.tree_minimum_index,
        trust_anchor_id_der: ca.mtc.trust_anchor_id_der.as_deref(),
    })
    .await;
    match result {
        Ok(()) => {
            ca.mtc.touch_checkpoint();
            if let Err(e) =
                db::checkpoints::prune_oldest(&state.db, &id, ca.mtc.checkpoint_retention_count)
                    .await
            {
                tracing::warn!(ca_id = %id, "prune old MTC checkpoints: {e}");
            }
            state
                .record_audit(
                    AuditEvent::success(AuditEventType::AdminAction)
                        .with_principal(&operator.name)
                        .with_detail(
                            json!({"action": "mtc.force-checkpoint", "ca_id": id}).to_string(),
                        ),
                )
                .await;
            StatusCode::NO_CONTENT.into_response()
        }
        Err(e) => {
            tracing::error!(ca_id = %id, "force checkpoint failed: {e}");
            e.into_response()
        }
    }
}

/// `POST /admin/ca/{id}/mtc/force-landmark`
///
/// Forces an immediate MTC landmark allocation.  Requires: Administrator | CaOperations.
pub async fn post_force_landmark(
    operator: OperatorContext,
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Response {
    require_role!(operator, state, Administrator | CaOperations);
    if operator.ca_scope().is_some_and(|scope| id != scope) {
        return not_found();
    }
    let Some(ca) = state.get_ca(&id) else {
        return not_found();
    };
    let (Some(log), Some(signing_key)) = (ca.mtc.log.as_ref(), ca.mtc.signing_key.as_ref()) else {
        return mtc_disabled();
    };
    let params = LandmarkAllocationParams {
        log,
        signing_key,
        signing_hash_alg: &ca.mtc.signing_hash_alg,
        log_algorithm: ca.mtc.algorithm,
        db: &state.db,
        db_kind: state.db_kind,
        ca_id: &id,
        keep_count: ca.mtc.max_active_landmarks,
    };
    match maybe_allocate_landmark(&params).await {
        Ok(()) => {
            ca.mtc.touch_landmark();
            state
                .record_audit(
                    AuditEvent::success(AuditEventType::AdminAction)
                        .with_principal(&operator.name)
                        .with_detail(
                            json!({"action": "mtc.force-landmark", "ca_id": id}).to_string(),
                        ),
                )
                .await;
            StatusCode::NO_CONTENT.into_response()
        }
        Err(e) => {
            tracing::error!(ca_id = %id, "force landmark failed: {e}");
            e.into_response()
        }
    }
}
