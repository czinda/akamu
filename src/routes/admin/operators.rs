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
use crate::require_role;
use crate::state::AppState;

use super::super::unix_now;

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
) -> Response {
    require_role!(operator, state, Administrator);

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

    match db::operators::list(&state.db, limit, offset).await {
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
            (StatusCode::OK, Json(json!({"operators": list}))).into_response()
        }
        Err(e) => {
            tracing::error!(error = %e, "get_operators: db error");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"status": 500, "detail": "database error"})),
            )
                .into_response()
        }
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
) -> Response {
    require_role!(operator, state, Administrator);

    let payload: NewOperatorPayload = match serde_json::from_slice(&body) {
        Ok(p) => p,
        Err(e) => return (StatusCode::BAD_REQUEST, format!("JSON: {e}")).into_response(),
    };

    if payload.name.is_empty() {
        return (StatusCode::BAD_REQUEST, "name is required").into_response();
    }
    match payload.role.as_str() {
        "administrator" | "ca_operations" | "ca_ra" | "auditor" => {}
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                "role must be administrator, ca_operations, ca_ra, or auditor",
            )
                .into_response()
        }
    }
    if payload.cert_fingerprint.is_none() && payload.gssapi_principal.is_none() {
        return (
            StatusCode::BAD_REQUEST,
            "at least one of cert_fingerprint or gssapi_principal is required",
        )
            .into_response();
    }
    // Validate ca_id: only meaningful for ca_ra and ca_operations; must reference an existing CA.
    if !payload.ca_id.is_empty() {
        if payload.role != "ca_ra" && payload.role != "ca_operations" {
            return (
                StatusCode::BAD_REQUEST,
                "ca_id is only valid for the ca_ra and ca_operations roles",
            )
                .into_response();
        }
        if !state.cas.contains_key(payload.ca_id.as_str()) {
            return (
                StatusCode::BAD_REQUEST,
                format!("unknown ca_id '{}'", payload.ca_id),
            )
                .into_response();
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
                    tracing::error!("post_operators: operator not found after insert");
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(json!({"status": 500, "detail": "operator created but id lookup failed"})),
                    )
                        .into_response();
                }
                Err(e) => {
                    tracing::error!(error = %e, "post_operators: id lookup db error");
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(json!({"status": 500, "detail": "database error"})),
                    )
                        .into_response();
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
            (
                StatusCode::CREATED,
                Json(json!({"id": op_id, "name": payload.name, "created_at": now})),
            )
                .into_response()
        }
        Err(crate::error::AcmeError::Database(ref msg))
            if msg.contains("UNIQUE") || msg.contains("unique") || msg.contains("Duplicate") =>
        {
            (
                StatusCode::CONFLICT,
                "operator with this fingerprint or principal already exists",
            )
                .into_response()
        }
        Err(e) => {
            tracing::error!(error = %e, "post_operators: db error");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"status": 500, "detail": "database error"})),
            )
                .into_response()
        }
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
) -> Response {
    require_role!(operator, state, Administrator);

    let payload: PatchOperatorPayload = match serde_json::from_slice(&body) {
        Ok(p) => p,
        Err(e) => return (StatusCode::BAD_REQUEST, format!("JSON: {e}")).into_response(),
    };

    let now = crate::util::rfc3339_now();
    match db::operators::set_active(&state.db, id, payload.active, &now).await {
        Ok(0) => (
            StatusCode::NOT_FOUND,
            Json(json!({"status": 404, "detail": "operator not found"})),
        )
            .into_response(),
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
            StatusCode::NO_CONTENT.into_response()
        }
        Err(e) => {
            tracing::error!(error = %e, "patch_operator: db error");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"status": 500, "detail": "database error"})),
            )
                .into_response()
        }
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
) -> Response {
    require_role!(operator, state, Administrator);

    match db::operators::unlock(&state.db, id).await {
        Ok(false) => (
            StatusCode::NOT_FOUND,
            Json(json!({"status": 404, "detail": "operator not found"})),
        )
            .into_response(),
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
            StatusCode::NO_CONTENT.into_response()
        }
        Err(e) => {
            tracing::error!(error = %e, "unlock_operator: db error");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"status": 500, "detail": "database error"})),
            )
                .into_response()
        }
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
) -> Response {
    require_role!(operator, state, Administrator);

    match db::operators::get_by_id(&state.db, id).await {
        Ok(Some(r)) => (
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
            .into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json!({"status": 404, "detail": "operator not found"})),
        )
            .into_response(),
        Err(e) => {
            tracing::error!(error = %e, "get_operator: db error");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"status": 500, "detail": "database error"})),
            )
                .into_response()
        }
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
) -> Response {
    require_role!(operator, state, Administrator);

    #[derive(Deserialize)]
    struct PutOperatorPayload {
        name: Option<String>,
        role: Option<String>,
        cert_fingerprint: Option<String>,
        gssapi_principal: Option<String>,
        /// CA scope for `ca_ra` and `ca_operations` roles.  Empty string clears the
        /// scope (server-wide; rejected for `ca_ra`, allowed for `ca_operations`).
        /// Omitting the field leaves the existing value unchanged.
        ca_id: Option<String>,
    }

    let payload: PutOperatorPayload = match serde_json::from_slice(&body) {
        Ok(p) => p,
        Err(e) => return (StatusCode::BAD_REQUEST, format!("JSON: {e}")).into_response(),
    };

    let effective_role = payload.role.as_deref().unwrap_or("");
    if let Some(ref r) = payload.role {
        match r.as_str() {
            "administrator" | "ca_operations" | "ca_ra" | "auditor" => {}
            _ => {
                return (
                    StatusCode::BAD_REQUEST,
                    "role must be administrator, ca_operations, ca_ra, or auditor",
                )
                    .into_response()
            }
        }
    }

    // When ca_id is supplied, validate it.
    let ca_id_update: Option<&str> = if let Some(ref cid) = payload.ca_id {
        let target_role = if effective_role.is_empty() {
            // Role not being changed — we need to know the current role to validate.
            // Fetch the operator to determine its current role.
            match db::operators::get_by_id(&state.db, id).await {
                Ok(Some(ref op)) => {
                    if cid.is_empty() && op.role == "ca_ra" {
                        return (
                            StatusCode::BAD_REQUEST,
                            "ca_ra operators must have a non-empty ca_id",
                        )
                            .into_response();
                    }
                    if !cid.is_empty() && op.role != "ca_ra" && op.role != "ca_operations" {
                        return (
                            StatusCode::BAD_REQUEST,
                            "ca_id is only valid for the ca_ra and ca_operations roles",
                        )
                            .into_response();
                    }
                    op.role.clone()
                }
                Ok(None) => {
                    return (
                        StatusCode::NOT_FOUND,
                        Json(json!({"status": 404, "detail": "operator not found"})),
                    )
                        .into_response();
                }
                Err(e) => {
                    tracing::error!(error = %e, "put_operator: db lookup for ca_id validation");
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(json!({"status": 500, "detail": "database error"})),
                    )
                        .into_response();
                }
            }
        } else {
            effective_role.to_string()
        };

        if !cid.is_empty() && target_role != "ca_ra" && target_role != "ca_operations" {
            return (
                StatusCode::BAD_REQUEST,
                "ca_id is only valid for the ca_ra and ca_operations roles",
            )
                .into_response();
        }
        if cid.is_empty() && target_role == "ca_ra" {
            return (
                StatusCode::BAD_REQUEST,
                "ca_ra operators must have a non-empty ca_id",
            )
                .into_response();
        }
        if !cid.is_empty() && !state.cas.contains_key(cid.as_str()) {
            return (StatusCode::BAD_REQUEST, format!("unknown ca_id '{cid}'")).into_response();
        }
        Some(cid.as_str())
    } else if effective_role == "ca_ra" {
        // Role changing to ca_ra but no ca_id provided — require it.
        return (
            StatusCode::BAD_REQUEST,
            "ca_id is required when setting role to ca_ra",
        )
            .into_response();
    } else if matches!(effective_role, "administrator" | "auditor") {
        // Role changing to a role that never has CA scope — clear ca_id.
        Some("")
    } else {
        // ca_operations: ca_id is optional — preserve the existing value.
        // No role change: leave ca_id untouched.
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
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(false) => (
            StatusCode::NOT_FOUND,
            Json(json!({"status": 404, "detail": "operator not found"})),
        )
            .into_response(),
        Err(e) => {
            tracing::error!(error = %e, "put_operator: db error");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"status": 500, "detail": "database error"})),
            )
                .into_response()
        }
    }
}
