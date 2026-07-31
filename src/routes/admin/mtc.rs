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
use crate::mtc::{
    checkpoint::{produce_checkpoint, CheckpointParams},
    landmark::{maybe_allocate_landmark, LandmarkAllocationParams},
    log, tlog,
    tlog::NoteSigningRole,
};
use crate::state::{AppState, CaState};

use super::error::AdminApiError;

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

fn not_found() -> AdminApiError {
    AdminApiError::NotFound("not found".into())
}

fn mtc_disabled() -> AdminApiError {
    AdminApiError::NotFound("MTC not enabled for this CA".into())
}

// ── Read-only query endpoints ───────────────────────────────────────────────

/// `GET /admin/mtc/tree-size`
///
/// Returns the current MTC log tree size.  Requires: Administrator | CaOperations | Auditor.
pub async fn get_tree_size(
    operator: OperatorContext,
    State(state): State<Arc<AppState>>,
    Query(q): Query<MtcQuery>,
) -> Result<Response, AdminApiError> {
    let Some((_ca_id, ca)) = resolve_ca(&state, q.ca_id.as_deref(), &operator) else {
        return Err(not_found());
    };
    let Some(shared_log) = ca.mtc.log.as_ref() else {
        return Err(mtc_disabled());
    };
    let size = log::tree_size(shared_log).await?;
    Ok((StatusCode::OK, Json(json!({"tree_size": size}))).into_response())
}

/// `GET /admin/mtc/root`
///
/// Returns tree size and root hash.  Requires: Administrator | CaOperations | Auditor.
pub async fn get_root(
    operator: OperatorContext,
    State(state): State<Arc<AppState>>,
    Query(q): Query<MtcQuery>,
) -> Result<Response, AdminApiError> {
    let Some((_ca_id, ca)) = resolve_ca(&state, q.ca_id.as_deref(), &operator) else {
        return Err(not_found());
    };
    let Some(shared_log) = ca.mtc.log.as_ref() else {
        return Err(mtc_disabled());
    };
    let (size, root) = log::tree_size_and_root(shared_log).await?;
    Ok((
        StatusCode::OK,
        Json(json!({"tree_size": size, "root_hash": hex_encode(&root)})),
    )
        .into_response())
}

/// `GET /admin/mtc/landmarks`
///
/// Returns landmark list as JSON.  Requires: Administrator | CaOperations | Auditor.
pub async fn get_landmarks(
    operator: OperatorContext,
    State(state): State<Arc<AppState>>,
    Query(q): Query<MtcQuery>,
) -> Result<Response, AdminApiError> {
    let Some((ca_id, ca)) = resolve_ca(&state, q.ca_id.as_deref(), &operator) else {
        return Err(not_found());
    };
    if ca.mtc.log.is_none() {
        return Err(mtc_disabled());
    }
    let landmarks = db::landmarks::list(&state.db_ro, ca_id).await?;
    let body: Vec<_> = landmarks
        .iter()
        .map(|l| {
            json!({
                "sequence_no": l.sequence_no,
                "tree_size": l.tree_size,
                "created_at": l.created,
            })
        })
        .collect();
    Ok((
        StatusCode::OK,
        Json(json!({"landmarks": body, "total": body.len()})),
    )
        .into_response())
}

/// `GET /admin/mtc/landmark-list`
///
/// Returns landmarks in spec section 3.4 text format.  Requires: Administrator | CaOperations | Auditor.
pub async fn get_landmark_list(
    operator: OperatorContext,
    State(state): State<Arc<AppState>>,
    Query(q): Query<MtcQuery>,
) -> Result<Response, AdminApiError> {
    let Some((ca_id, ca)) = resolve_ca(&state, q.ca_id.as_deref(), &operator) else {
        return Err(not_found());
    };
    if ca.mtc.log.is_none() {
        return Err(mtc_disabled());
    }
    let landmarks = db::landmarks::list(&state.db_ro, ca_id).await?;
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
    Ok((
        StatusCode::OK,
        [(
            axum::http::header::CONTENT_TYPE,
            HeaderValue::from_static("text/plain; charset=utf-8"),
        )],
        body,
    )
        .into_response())
}

/// `GET /admin/mtc/inclusion-proof/{cert_id}`
///
/// Returns inclusion proof for a certificate.  Requires: Administrator | CaOperations | Auditor.
pub async fn get_inclusion_proof(
    operator: OperatorContext,
    State(state): State<Arc<AppState>>,
    Path(cert_id): Path<String>,
) -> Result<Response, AdminApiError> {
    let cert = match db::certs::get_by_id(&state.db_ro, &cert_id).await? {
        Some(c) => c,
        None => return Err(not_found()),
    };
    if let Some(scope) = operator.ca_scope() {
        if cert.ca_id != scope {
            return Err(not_found());
        }
    }
    let ca_id = cert.ca_id.as_str();
    let ca = match state.get_ca(ca_id) {
        Some(ca) => ca,
        None => return Err(not_found()),
    };
    let Some(shared_log) = ca.mtc.log.as_ref() else {
        return Err(mtc_disabled());
    };
    let Some(log_index) = cert.mtc_log_index else {
        return Err(not_found());
    };
    let leaf_index = u64::try_from(log_index).map_err(|e| {
        AdminApiError::Internal(format!(
            "get_inclusion_proof: cert {cert_id} has negative mtc_log_index {log_index}: {e}"
        ))
    })?;
    let (proof_hashes, size) = log::proof_and_tree_size(shared_log, leaf_index).await?;
    let proof: Vec<_> = proof_hashes
        .into_iter()
        .map(|hash| json!({"hash": hex_encode(&hash)}))
        .collect();
    Ok((
        StatusCode::OK,
        Json(json!({
            "leaf_index": leaf_index,
            "tree_size": size,
            "proof": proof,
        })),
    )
        .into_response())
}

/// `GET /admin/mtc/standalone/{cert_id}`
///
/// Downloads standalone DER certificate.  Requires: Administrator | CaOperations.
pub async fn get_standalone(
    operator: OperatorContext,
    State(state): State<Arc<AppState>>,
    Path(cert_id): Path<String>,
) -> Result<Response, AdminApiError> {
    let cert_ca = match db::certs::get_by_id(&state.db_ro, &cert_id).await? {
        Some(c) => c,
        None => return Err(not_found()),
    };
    if let Some(scope) = operator.ca_scope() {
        if cert_ca.ca_id != scope {
            return Err(not_found());
        }
    }
    match db::certs::get_mtc_standalone_der(&state.db_ro, &cert_id).await? {
        Some(der) => Ok((
            StatusCode::OK,
            [(
                axum::http::header::CONTENT_TYPE,
                HeaderValue::from_static("application/octet-stream"),
            )],
            der,
        )
            .into_response()),
        None => Err(not_found()),
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
) -> Result<Response, AdminApiError> {
    let Some((ca_id, ca)) = resolve_ca(&state, q.ca_id.as_deref(), &operator) else {
        return Err(not_found());
    };
    if ca.mtc.log.is_none() {
        return Err(mtc_disabled());
    }
    match db::landmarks::get_by_seq(&state.db_ro, ca_id, seq).await? {
        Some(lm) => match lm.cert_der {
            Some(der) => Ok((
                StatusCode::OK,
                [(
                    axum::http::header::CONTENT_TYPE,
                    HeaderValue::from_static("application/octet-stream"),
                )],
                der,
            )
                .into_response()),
            None => Err(AdminApiError::ServiceUnavailable(
                "landmark certificate not yet built".into(),
            )),
        },
        None => Err(not_found()),
    }
}

/// `GET /admin/mtc/landmarks/{seq}/cert-details`
///
/// Returns parsed landmark certificate details as JSON.
/// Requires: Administrator | CaOperations | Auditor.
pub async fn get_landmark_cert_details(
    operator: OperatorContext,
    State(state): State<Arc<AppState>>,
    Path(seq): Path<i64>,
    Query(q): Query<MtcQuery>,
) -> Result<Response, AdminApiError> {
    let Some((ca_id, ca)) = resolve_ca(&state, q.ca_id.as_deref(), &operator) else {
        return Err(not_found());
    };
    if ca.mtc.log.is_none() {
        return Err(mtc_disabled());
    }
    match db::landmarks::get_by_seq(&state.db_ro, ca_id, seq).await? {
        Some(lm) => match lm.cert_der {
            Some(der) => {
                let cert_text = super::describe_landmark_cert_der(&der);
                Ok((
                    StatusCode::OK,
                    Json(json!({
                        "sequence_no": seq,
                        "cert_text": cert_text,
                    })),
                )
                    .into_response())
            }
            None => Err(AdminApiError::ServiceUnavailable(
                "landmark certificate not yet built".into(),
            )),
        },
        None => Err(not_found()),
    }
}

#[derive(Deserialize)]
pub struct ConsistencyQuery {
    pub ca_id: Option<String>,
    // `Option` (rather than required `u64`) so a missing/malformed query
    // string fails inside the handler rather than via the `Query<T>`
    // extractor rejecting the request with 400 outside our control.
    pub from: Option<u64>,
    pub to: Option<u64>,
}

/// `GET /admin/mtc/consistency-proof`
///
/// Returns root hashes for consistency verification.  Requires: Administrator | CaOperations | Auditor.
pub async fn get_consistency_proof(
    operator: OperatorContext,
    State(state): State<Arc<AppState>>,
    Query(q): Query<ConsistencyQuery>,
) -> Result<Response, AdminApiError> {
    let Some((_ca_id, ca)) = resolve_ca(&state, q.ca_id.as_deref(), &operator) else {
        return Err(not_found());
    };
    let Some(shared_log) = ca.mtc.log.as_ref() else {
        return Err(mtc_disabled());
    };
    let (Some(from), Some(to)) = (q.from, q.to) else {
        return Err(AdminApiError::BadRequest(
            "from and to query parameters are required".into(),
        ));
    };
    if from == 0 || to == 0 || from >= to {
        return Err(AdminApiError::BadRequest(
            "from and to must be positive with from < to".into(),
        ));
    }
    let current_size = log::tree_size(shared_log).await?;
    if to > current_size {
        return Err(AdminApiError::BadRequest(format!(
            "to ({to}) exceeds tree size ({current_size})"
        )));
    }
    let from_root = log::compute_root_at_size(shared_log, ca.mtc.algorithm, from).await?;
    let to_root = log::compute_root_at_size(shared_log, ca.mtc.algorithm, to).await?;
    Ok((
        StatusCode::OK,
        Json(json!({
            "from_size": from,
            "to_size": to,
            "from_root": hex_encode(&from_root),
            "to_root": hex_encode(&to_root),
        })),
    )
        .into_response())
}

#[derive(Deserialize)]
pub struct SubtreeRootQuery {
    pub ca_id: Option<String>,
    // See the comment on `ConsistencyQuery::from`.
    pub start: Option<u64>,
    pub end: Option<u64>,
}

/// `GET /admin/mtc/subtree-root`
///
/// Computes subtree root hash over a leaf range.  Requires: Administrator | CaOperations | Auditor.
pub async fn get_subtree_root(
    operator: OperatorContext,
    State(state): State<Arc<AppState>>,
    Query(q): Query<SubtreeRootQuery>,
) -> Result<Response, AdminApiError> {
    let Some((_ca_id, ca)) = resolve_ca(&state, q.ca_id.as_deref(), &operator) else {
        return Err(not_found());
    };
    let Some(shared_log) = ca.mtc.log.as_ref() else {
        return Err(mtc_disabled());
    };
    let (Some(start), Some(end)) = (q.start, q.end) else {
        return Err(AdminApiError::BadRequest(
            "start and end query parameters are required".into(),
        ));
    };
    if start >= end {
        return Err(AdminApiError::BadRequest(
            "start must be less than end".into(),
        ));
    }
    let size = end - start;
    let alignment = size.checked_next_power_of_two().unwrap_or(u64::MAX);
    if !start.is_multiple_of(alignment) {
        return Err(AdminApiError::BadRequest(format!(
            "start must be aligned to the next power of two of the range size \
             (start={start}, size={size}, required alignment={alignment})"
        )));
    }
    let current_size = log::tree_size(shared_log).await?;
    if end > current_size {
        return Err(AdminApiError::BadRequest(format!(
            "end ({end}) exceeds tree size ({current_size})"
        )));
    }
    let hashes = log::read_hash_range(shared_log, start, (end - start) as usize).await?;
    let root = synta_mtc::crypto::generate_subtree_hash(ca.mtc.algorithm, &hashes)
        .map_err(|e| AdminApiError::Internal(format!("generate_subtree_hash: {e}")))?;
    Ok((
        StatusCode::OK,
        Json(json!({
            "start": start,
            "end": end,
            "root_hash": hex_encode(&root),
        })),
    )
        .into_response())
}

/// `GET /admin/mtc/revoked-ranges`
///
/// Returns revoked leaf-index ranges.  Requires: Administrator | CaOperations | Auditor.
pub async fn get_revoked_ranges(
    operator: OperatorContext,
    State(state): State<Arc<AppState>>,
    Query(q): Query<MtcQuery>,
) -> Result<Response, AdminApiError> {
    let Some((ca_id, ca)) = resolve_ca(&state, q.ca_id.as_deref(), &operator) else {
        return Err(not_found());
    };
    if ca.mtc.log.is_none() {
        return Err(mtc_disabled());
    }
    let rows = db::revoked_ranges::get_all(&state.db_ro, ca_id).await?;
    let ranges: Vec<_> = rows
        .iter()
        .map(|r| json!({"start": r.range_start, "end": r.range_end}))
        .collect();
    Ok((
        StatusCode::OK,
        Json(json!({"revoked_ranges": ranges, "total": ranges.len()})),
    )
        .into_response())
}

/// `GET /admin/mtc/checkpoint`
///
/// Returns C2SP tlog operator checkpoint.  Requires: Administrator | CaOperations | Auditor.
pub async fn get_checkpoint(
    operator: OperatorContext,
    State(state): State<Arc<AppState>>,
    Query(q): Query<MtcQuery>,
) -> Result<Response, AdminApiError> {
    let Some((_ca_id, ca)) = resolve_ca(&state, q.ca_id.as_deref(), &operator) else {
        return Err(not_found());
    };
    let Some(shared_log) = ca.mtc.log.as_ref() else {
        return Err(mtc_disabled());
    };
    let Some(key) = ca.mtc.signing_key.as_ref() else {
        return Err(AdminApiError::ServiceUnavailable(
            "MTC signing key not configured".into(),
        ));
    };
    let Some(origin) = ca.mtc.tlog_origin() else {
        return Err(AdminApiError::ServiceUnavailable(
            "mtc.trust_anchor_id not configured".into(),
        ));
    };
    let note = tlog::produce_operator_checkpoint(
        shared_log,
        origin,
        key,
        &ca.mtc.signing_hash_alg,
        origin,
    )
    .await?;
    Ok((
        StatusCode::OK,
        [(
            axum::http::header::CONTENT_TYPE,
            HeaderValue::from_static("text/plain; charset=utf-8"),
        )],
        note,
    )
        .into_response())
}

/// `GET /admin/mtc/cosignature`
///
/// Returns C2SP tlog cosignature checkpoint.  Requires: Administrator | CaOperations | Auditor.
pub async fn get_cosignature(
    operator: OperatorContext,
    State(state): State<Arc<AppState>>,
    Query(q): Query<MtcQuery>,
) -> Result<Response, AdminApiError> {
    let Some((_ca_id, ca)) = resolve_ca(&state, q.ca_id.as_deref(), &operator) else {
        return Err(not_found());
    };
    let Some(shared_log) = ca.mtc.log.as_ref() else {
        return Err(mtc_disabled());
    };
    let Some(key) = ca.mtc.signing_key.as_ref() else {
        return Err(AdminApiError::ServiceUnavailable(
            "MTC signing key not configured".into(),
        ));
    };
    let Some(cosigner_name) = ca.mtc.cosigner_name() else {
        return Err(AdminApiError::ServiceUnavailable(
            "mtc.trust_anchor_id not configured".into(),
        ));
    };
    let Some(origin) = ca.mtc.tlog_origin() else {
        return Err(AdminApiError::ServiceUnavailable(
            "mtc.trust_anchor_id not configured".into(),
        ));
    };
    let note = tlog::produce_cosigner_checkpoint(
        shared_log,
        cosigner_name,
        key,
        &ca.mtc.signing_hash_alg,
        origin,
    )
    .await?;
    Ok((
        StatusCode::OK,
        [(
            axum::http::header::CONTENT_TYPE,
            HeaderValue::from_static("text/plain; charset=utf-8"),
        )],
        note,
    )
        .into_response())
}

// ── Admin-only action endpoints ─────────────────────────────────────────────

/// `POST /admin/ca/{id}/mtc/force-checkpoint`
///
/// Forces an immediate MTC checkpoint.  Requires: Administrator | CaOperations.
pub async fn post_force_checkpoint(
    operator: OperatorContext,
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Response, AdminApiError> {
    if operator.ca_scope().is_some_and(|scope| id != scope) {
        return Err(not_found());
    }
    let Some(ca) = state.get_ca(&id) else {
        return Err(not_found());
    };
    let (Some(log), Some(signing_key)) = (ca.mtc.log.as_ref(), ca.mtc.signing_key.as_ref()) else {
        return Err(mtc_disabled());
    };
    let origin = ca.mtc.tlog_origin();
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
        log_origin: origin,
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
            Ok(StatusCode::NO_CONTENT.into_response())
        }
        Err(e) => Err(AdminApiError::Internal(format!(
            "force checkpoint failed for ca_id {id}: {e}"
        ))),
    }
}

/// `POST /admin/ca/{id}/mtc/force-landmark`
///
/// Forces an immediate MTC landmark allocation.  Requires: Administrator | CaOperations.
pub async fn post_force_landmark(
    operator: OperatorContext,
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Response, AdminApiError> {
    if operator.ca_scope().is_some_and(|scope| id != scope) {
        return Err(not_found());
    }
    let Some(ca) = state.get_ca(&id) else {
        return Err(not_found());
    };
    let (Some(log), Some(signing_key)) = (ca.mtc.log.as_ref(), ca.mtc.signing_key.as_ref()) else {
        return Err(mtc_disabled());
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
            Ok(StatusCode::NO_CONTENT.into_response())
        }
        Err(e) => Err(AdminApiError::Internal(format!(
            "force landmark failed for ca_id {id}: {e}"
        ))),
    }
}

/// `GET /admin/ca/{id}/mtc/log-list-entry`
///
/// Returns a Witness Network log-list entry for this CA's MTC issuance log.
/// Requires: Administrator | CaOperations | Auditor.
pub async fn get_log_list_entry(
    operator: OperatorContext,
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Response, AdminApiError> {
    if operator.ca_scope().is_some_and(|scope| id != scope) {
        return Err(not_found());
    }
    let Some(ca) = state.get_ca(&id) else {
        return Err(not_found());
    };
    let Some(signing_key) = ca.mtc.signing_key.as_ref() else {
        return Err(mtc_disabled());
    };
    let Some(origin) = ca.mtc.tlog_origin() else {
        return Err(AdminApiError::NotFound(
            "mtc.trust_anchor_id not configured".into(),
        ));
    };

    let vkey = tlog::format_vkey(origin, signing_key, NoteSigningRole::LogOperator)
        .map_err(|e| AdminApiError::Internal(format!("format vkey for ca_id {id}: {e}")))?;

    let Some(contact) = ca.mtc.contact.as_deref() else {
        return Err(AdminApiError::NotFound(
            "mtc.contact not configured; set it in [mtc] config before generating a log-list entry"
                .into(),
        ));
    };

    let qpd = ca.mtc.checkpoint_interval_secs;
    let entry = format!("vkey {vkey}\norigin {origin}\nqpd {qpd}\ncontact {contact}\n");

    Ok((
        StatusCode::OK,
        [(
            axum::http::header::CONTENT_TYPE,
            HeaderValue::from_static("text/plain; charset=utf-8"),
        )],
        entry,
    )
        .into_response())
}
