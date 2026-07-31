//! Admin operator management handlers.

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;
use serde_json::json;

use crate::admin::auth::OperatorContext;
use crate::audit::{AuditEvent, AuditEventType};
use crate::crdt_hooks;
use crate::db;
use crate::state::AppState;

use super::super::unix_now;
use super::error::AdminApiError;

#[derive(Deserialize)]
struct NewOperatorPayload {
    name: String,
    role: String,
    cert_fingerprint: Option<String>,
    gssapi_principal: Option<String>,
    /// CA scope for `ca_ra` operators. Empty/absent means server-wide.
    #[serde(default)]
    ca_id: String,
}

#[derive(Deserialize)]
struct PatchOperatorPayload {
    /// `true` to activate, `false` to deactivate.
    active: bool,
}

/// `GET /admin/operators`
///
/// List all operators (active and inactive).
/// Query params: `limit` (≤1000, default 1000), `offset` (default 0).
/// Requires: `administrator`.
pub async fn get_operators(
    operator: OperatorContext,
    State(state): State<Arc<AppState>>,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> Result<Response, AdminApiError> {
    let limit: i64 = params
        .get("limit")
        .and_then(|v| v.parse().ok())
        .unwrap_or(1000)
        .clamp(1, 1000);
    let offset: i64 = params
        .get("offset")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0)
        .max(0);

    let ca_scope = operator.ca_scope().map(|s| s.to_string());
    let result = if let Some(ref scope_ca) = ca_scope {
        db::operators::list_by_ca(&state.db, scope_ca, limit, offset).await
    } else {
        db::operators::list(&state.db, limit, offset).await
    };
    match result {
        Ok(rows) => {
            let list: Vec<_> = rows
                .into_iter()
                .map(|r| {
                    json!({
                        "id": r.id,
                        "name": r.name,
                        "role": r.role,
                        "ca_id": r.ca_id,
                        "cert_fingerprint": r.cert_fingerprint,
                        "gssapi_principal": r.gssapi_principal,
                        "created_at": r.created_at,
                        "last_seen_at": r.last_seen_at,
                        "active": r.active != 0,
                        "failed_attempts": r.failed_attempts,
                        "locked_until": r.locked_until,
                    })
                })
                .collect();
            Ok((StatusCode::OK, Json(json!({"operators": list}))).into_response())
        }
        Err(e) => Err(AdminApiError::Internal(format!(
            "get_operators: db error: {e}"
        ))),
    }
}

/// `POST /admin/operators`
///
/// Add a new operator.  At least one of `cert_fingerprint` or `gssapi_principal`
/// must be provided.
/// Requires: `administrator`.
pub async fn post_operators(
    operator: OperatorContext,
    State(state): State<Arc<AppState>>,
    body: Bytes,
) -> Result<Response, AdminApiError> {
    let payload: NewOperatorPayload = serde_json::from_slice(&body)
        .map_err(|e| AdminApiError::BadRequest(format!("invalid JSON: {e}")))?;

    if payload.name.is_empty() {
        return Err(AdminApiError::BadRequest("name is required".into()));
    }
    match payload.role.as_str() {
        "administrator" | "ca_operations" | "ca_ra" | "auditor" => {}
        _ => {
            return Err(AdminApiError::BadRequest(
                "role must be administrator, ca_operations, ca_ra, or auditor".into(),
            ))
        }
    }
    if payload.cert_fingerprint.is_none() && payload.gssapi_principal.is_none() {
        return Err(AdminApiError::BadRequest(
            "at least one of cert_fingerprint or gssapi_principal is required".into(),
        ));
    }
    if !payload.ca_id.is_empty() && !state.cas.contains_key(payload.ca_id.as_str()) {
        return Err(AdminApiError::BadRequest(format!(
            "unknown ca_id '{}'",
            payload.ca_id
        )));
    }
    if payload.ca_id.is_empty() && payload.role == "ca_ra" {
        return Err(AdminApiError::BadRequest(
            "ca_ra operators must have a non-empty ca_id".into(),
        ));
    }
    if let Some(scope_ca) = operator.ca_scope() {
        if payload.ca_id != scope_ca {
            return Err(AdminApiError::Forbidden(
                "CA-scoped operator can only create operators for their own CA".into(),
            ));
        }
    }

    let now = crate::util::rfc3339_now();
    let result = db::operators::insert(
        &state.db,
        &payload.name,
        &payload.role,
        payload.cert_fingerprint.as_deref(),
        payload.gssapi_principal.as_deref(),
        &payload.ca_id,
        &now,
    )
    .await;

    match result {
        Ok(()) => {
            // Look up the newly inserted operator to retrieve its DB-assigned id.
            let op_row = if let Some(fp) = payload.cert_fingerprint.as_deref() {
                db::operators::get_by_fingerprint(&state.db, fp).await
            } else if let Some(p) = payload.gssapi_principal.as_deref() {
                db::operators::get_by_principal(&state.db, p).await
            } else {
                Ok(None) // unreachable: validated above
            };
            let op_id = match op_row {
                Ok(Some(row)) => row.id,
                Ok(None) => {
                    return Err(AdminApiError::Internal(
                        "post_operators: operator not found after insert".into(),
                    ));
                }
                Err(e) => {
                    return Err(AdminApiError::Internal(format!(
                        "post_operators: id lookup db error: {e}"
                    )));
                }
            };
            state
                .record_audit(
                    AuditEvent::success(AuditEventType::AdminAction)
                        .with_principal(&operator.name)
                        .with_detail(
                            json!({"action": "operator.create", "name": payload.name, "id": op_id})
                                .to_string(),
                        ),
                )
                .await;
            crdt_hooks::on_operator_upsert(
                &state,
                op_id,
                &payload.name,
                &payload.role,
                &payload.ca_id,
                unix_now(),
            )
            .await;
            Ok((
                StatusCode::CREATED,
                Json(json!({"id": op_id, "name": payload.name, "created_at": now})),
            )
                .into_response())
        }
        Err(crate::error::AcmeError::Database(ref msg))
            if crate::db::is_unique_constraint_violation(msg) =>
        {
            Err(AdminApiError::Conflict(
                "operator with this fingerprint or principal already exists".into(),
            ))
        }
        Err(e) => Err(AdminApiError::Internal(format!(
            "post_operators: db error: {e}"
        ))),
    }
}

/// `PATCH /admin/operators/{id}`
///
/// Activate or deactivate an operator.
/// Requires: `administrator`.
pub async fn patch_operator(
    operator: OperatorContext,
    State(state): State<Arc<AppState>>,
    Path(id): Path<i64>,
    body: Bytes,
) -> Result<Response, AdminApiError> {
    let payload: PatchOperatorPayload = serde_json::from_slice(&body)
        .map_err(|e| AdminApiError::BadRequest(format!("invalid JSON: {e}")))?;

    if let Some(scope_ca) = operator.ca_scope() {
        match db::operators::get_by_id(&state.db, id).await {
            Ok(Some(ref op)) if op.ca_id != scope_ca => {
                return Err(AdminApiError::NotFound("operator not found".into()));
            }
            Ok(None) => {
                return Err(AdminApiError::NotFound("operator not found".into()));
            }
            Err(e) => {
                return Err(AdminApiError::Internal(format!(
                    "patch_operator: db lookup for ca_scope check: {e}"
                )));
            }
            _ => {}
        }
    }

    let now = crate::util::rfc3339_now();
    match db::operators::set_active(&state.db, id, payload.active, &now).await {
        Ok(0) => Err(AdminApiError::NotFound("operator not found".into())),
        Ok(_) => {
            let action = if payload.active {
                "operator.activate"
            } else {
                "operator.deactivate"
            };
            // Revoked operators must not retain live session tokens.
            if !payload.active {
                if let Some(sessions) = &state.admin_sessions {
                    sessions.lock().await.retain(|_, s| s.operator_id != id);
                }
            }
            state
                .record_audit(
                    AuditEvent::success(AuditEventType::AdminAction)
                        .with_principal(&operator.name)
                        .with_detail(json!({"action": action, "operator_id": id}).to_string()),
                )
                .await;
            if !payload.active {
                crdt_hooks::on_operator_tombstone(&state, id, unix_now()).await;
            }
            Ok(StatusCode::NO_CONTENT.into_response())
        }
        Err(e) => Err(AdminApiError::Internal(format!(
            "patch_operator: db error: {e}"
        ))),
    }
}

/// `POST /admin/operators/{id}/unlock`
///
/// Reset an operator's failed-authentication counter and clear the lockout
/// timestamp (FIA_AFL.1).  Requires: `administrator`.
pub async fn unlock_operator(
    operator: OperatorContext,
    State(state): State<Arc<AppState>>,
    Path(id): Path<i64>,
) -> Result<Response, AdminApiError> {
    if let Some(scope_ca) = operator.ca_scope() {
        match db::operators::get_by_id(&state.db, id).await {
            Ok(Some(ref op)) if op.ca_id != scope_ca => {
                return Err(AdminApiError::NotFound("operator not found".into()));
            }
            Ok(None) => {
                return Err(AdminApiError::NotFound("operator not found".into()));
            }
            Err(e) => {
                return Err(AdminApiError::Internal(format!(
                    "unlock_operator: db lookup for ca_scope check: {e}"
                )));
            }
            _ => {}
        }
    }

    match db::operators::unlock(&state.db, id).await {
        Ok(false) => Err(AdminApiError::NotFound("operator not found".into())),
        Ok(true) => {
            state
                .record_audit(
                    AuditEvent::success(AuditEventType::AdminAction)
                        .with_principal(&operator.name)
                        .with_detail(
                            json!({"action": "operator.unlock", "operator_id": id}).to_string(),
                        ),
                )
                .await;
            Ok(StatusCode::NO_CONTENT.into_response())
        }
        Err(e) => Err(AdminApiError::Internal(format!(
            "unlock_operator: db error: {e}"
        ))),
    }
}

/// `GET /admin/operators/{id}`
///
/// Show a single operator's details.
/// Requires: `administrator`.
pub async fn get_operator(
    operator: OperatorContext,
    State(state): State<Arc<AppState>>,
    Path(id): Path<i64>,
) -> Result<Response, AdminApiError> {
    match db::operators::get_by_id(&state.db, id).await {
        Ok(Some(r)) => {
            if let Some(scope_ca) = operator.ca_scope() {
                if r.ca_id != scope_ca {
                    return Err(AdminApiError::NotFound("operator not found".into()));
                }
            }
            Ok((
                StatusCode::OK,
                Json(json!({
                    "id": r.id,
                    "name": r.name,
                    "role": r.role,
                    "ca_id": r.ca_id,
                    "cert_fingerprint": r.cert_fingerprint,
                    "gssapi_principal": r.gssapi_principal,
                    "created_at": r.created_at,
                    "last_seen_at": r.last_seen_at,
                    "active": r.active != 0,
                    "failed_attempts": r.failed_attempts,
                    "locked_until": r.locked_until,
                })),
            )
                .into_response())
        }
        Ok(None) => Err(AdminApiError::NotFound("operator not found".into())),
        Err(e) => Err(AdminApiError::Internal(format!(
            "get_operator: db error: {e}"
        ))),
    }
}

/// `PUT /admin/operators/{id}`
///
/// Update operator fields (name, role, cert_fingerprint, gssapi_principal).
/// Only provided fields are updated.
/// Requires: `administrator`.
pub async fn put_operator(
    operator: OperatorContext,
    State(state): State<Arc<AppState>>,
    Path(id): Path<i64>,
    body: Bytes,
) -> Result<Response, AdminApiError> {
    #[derive(Deserialize)]
    struct PutOperatorPayload {
        name: Option<String>,
        role: Option<String>,
        cert_fingerprint: Option<String>,
        gssapi_principal: Option<String>,
        /// CA scope.  Empty string clears the scope (server-wide; rejected
        /// for `ca_ra`).  Omitting the field leaves the existing value
        /// unchanged.  CA-scoped operators cannot widen scope.
        ca_id: Option<String>,
    }

    let payload: PutOperatorPayload = serde_json::from_slice(&body)
        .map_err(|e| AdminApiError::BadRequest(format!("invalid JSON: {e}")))?;

    if let Some(ref r) = payload.role {
        match r.as_str() {
            "administrator" | "ca_operations" | "ca_ra" | "auditor" => {}
            _ => {
                return Err(AdminApiError::BadRequest(
                    "role must be administrator, ca_operations, ca_ra, or auditor".into(),
                ))
            }
        }
    }

    // Fetch the target operator up front — needed for CA-scope checks and ca_id
    // validation regardless of which fields are being changed.
    let target_op = match db::operators::get_by_id(&state.db, id).await {
        Ok(Some(op)) => op,
        Ok(None) => {
            return Err(AdminApiError::NotFound("operator not found".into()));
        }
        Err(e) => {
            return Err(AdminApiError::Internal(format!(
                "put_operator: db lookup: {e}"
            )));
        }
    };

    // CA-scoped operators can only modify operators scoped to the same CA.
    if let Some(scope_ca) = operator.ca_scope() {
        if target_op.ca_id != scope_ca {
            return Err(AdminApiError::NotFound("operator not found".into()));
        }
    }

    // When ca_id is supplied, validate it.
    let ca_id_update: Option<&str> = if let Some(ref cid) = payload.ca_id {
        // CA-scoped operators cannot widen scope.
        if let Some(scope_ca) = operator.ca_scope() {
            if cid.is_empty() || cid != scope_ca {
                return Err(AdminApiError::Forbidden(
                    "CA-scoped operator cannot change ca_id outside their own CA".into(),
                ));
            }
        }

        let target_role = payload.role.as_deref().unwrap_or(&target_op.role);

        if cid.is_empty() && target_role == "ca_ra" {
            return Err(AdminApiError::BadRequest(
                "ca_ra operators must have a non-empty ca_id".into(),
            ));
        }
        if !cid.is_empty() && !state.cas.contains_key(cid.as_str()) {
            return Err(AdminApiError::BadRequest(format!("unknown ca_id '{cid}'")));
        }
        Some(cid.as_str())
    } else if payload.role.as_deref() == Some("ca_ra") {
        return Err(AdminApiError::BadRequest(
            "ca_id is required when setting role to ca_ra".into(),
        ));
    } else if matches!(payload.role.as_deref(), Some("administrator" | "auditor")) {
        if operator.ca_scope().is_some() {
            return Err(AdminApiError::Forbidden(
                "CA-scoped operator cannot clear ca_id".into(),
            ));
        }
        Some("")
    } else {
        // ca_operations with no ca_id change, or no role change at all:
        // preserve the existing ca_id value.
        None
    };

    let now = crate::util::rfc3339_now();
    match db::operators::update(
        &state.db,
        id,
        db::operators::OperatorUpdateParams {
            name: payload.name.as_deref(),
            role: payload.role.as_deref(),
            cert_fingerprint: payload.cert_fingerprint.as_deref(),
            gssapi_principal: payload.gssapi_principal.as_deref(),
            ca_id: ca_id_update,
        },
        &now,
    )
    .await
    {
        Ok(true) => {
            // Role or CA scope may have changed — invalidate any live sessions for this operator.
            if let Some(sessions) = &state.admin_sessions {
                sessions.lock().await.retain(|_, s| s.operator_id != id);
            }
            state
                .record_audit(
                    AuditEvent::success(AuditEventType::AdminAction)
                        .with_principal(&operator.name)
                        .with_detail(
                            json!({"action": "operator.update", "operator_id": id}).to_string(),
                        ),
                )
                .await;
            Ok(StatusCode::NO_CONTENT.into_response())
        }
        Ok(false) => Err(AdminApiError::NotFound("operator not found".into())),
        Err(e) => Err(AdminApiError::Internal(format!(
            "put_operator: db error: {e}"
        ))),
    }
}
