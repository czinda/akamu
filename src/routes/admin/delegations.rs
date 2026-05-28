//! Admin delegation management handlers (RFC 9115).

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
struct DelegationCreatePayload {
    account_id: String,
    csr_template: serde_json::Value,
    #[serde(default)]
    cname_map: Option<serde_json::Value>,
}

#[derive(Deserialize)]
struct DelegationUpdatePayload {
    csr_template: serde_json::Value,
    #[serde(default)]
    cname_map: Option<serde_json::Value>,
}

pub fn delegation_row_to_json(
    r: &crate::db::schema::DelegationRow,
) -> Result<serde_json::Value, String> {
    let csr_template = serde_json::from_str::<serde_json::Value>(&r.csr_template).map_err(|e| {
        tracing::error!(delegation_id = %r.id, "delegation csr_template is corrupt JSON: {e}");
        format!("corrupt csr_template for delegation '{}'", r.id)
    })?;
    Ok(json!({
        "id": r.id,
        "account_id": r.account_id,
        "csr_template": csr_template,
        "cname_map": r.cname_map.as_deref()
            .and_then(|s| serde_json::from_str::<serde_json::Value>(s).ok()),
        "created": r.created,
        "updated": r.updated,
    }))
}

/// `GET /admin/delegations`
///
/// List delegation objects with optional `?account_id=` filter.
/// Requires: any role.
pub async fn get_delegations(
    operator: OperatorContext,
    State(state): State<Arc<AppState>>,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> Response {
    require_role!(
        operator,
        state,
        Administrator | CaOperations | CaRa | Auditor
    );

    let limit: i64 = params
        .get("limit")
        .and_then(|v| v.parse().ok())
        .unwrap_or(100)
        .clamp(1, 1000);
    let offset: i64 = params
        .get("offset")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0)
        .max(0);
    let account_id = params.get("account_id").map(String::as_str);
    let ca_scope = operator.ca_scope();

    match tokio::try_join!(
        db::delegations::list(&state.db, account_id, ca_scope, limit, offset),
        db::delegations::count_list(&state.db, account_id, ca_scope),
    ) {
        Ok((rows, total)) => {
            let list_result: Result<Vec<serde_json::Value>, String> =
                rows.iter().map(delegation_row_to_json).collect();
            match list_result {
                Err(e) => {
                    tracing::error!(error = %e, "get_delegations: corrupt delegation row");
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(json!({"status": 500, "detail": "database contains corrupt delegation data"})),
                    )
                        .into_response()
                }
                Ok(list) => (
                    StatusCode::OK,
                    Json(json!({"delegations": list, "total": total, "limit": limit, "offset": offset})),
                )
                    .into_response(),
            }
        }
        Err(e) => {
            tracing::error!(error = %e, "get_delegations: db error");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"status": 500, "detail": "database error"})),
            )
                .into_response()
        }
    }
}

/// `POST /admin/delegations`
///
/// Create a delegation object for an account.
/// Requires: `administrator` or `ca_operations`.
pub async fn post_delegations(
    operator: OperatorContext,
    State(state): State<Arc<AppState>>,
    body: Bytes,
) -> Response {
    require_role!(operator, state, Administrator | CaOperations);

    let payload: DelegationCreatePayload = match serde_json::from_slice(&body) {
        Ok(p) => p,
        Err(e) => return (StatusCode::BAD_REQUEST, format!("JSON: {e}")).into_response(),
    };

    if payload.account_id.is_empty() {
        return (StatusCode::BAD_REQUEST, "account_id is required").into_response();
    }

    match db::accounts::get_by_id(&state.db, &payload.account_id).await {
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"status": 404, "detail": "account not found"})),
            )
                .into_response()
        }
        Err(e) => {
            tracing::error!(error = %e, "post_delegations: account lookup");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"status": 500, "detail": "database error"})),
            )
                .into_response();
        }
        Ok(Some(acct)) => {
            if operator
                .ca_scope()
                .is_some_and(|scope| !acct.ca_id.is_empty() && acct.ca_id != scope)
            {
                return (
                    StatusCode::FORBIDDEN,
                    Json(json!({"status": 403, "detail": "account does not belong to your CA scope"})),
                )
                    .into_response();
            }
        }
    }

    let csr_template_str = payload.csr_template.to_string();
    // Validate the CSR template syntax before storing it.
    if let Err(e) = serde_json::from_str::<crate::ca::csr_template::CsrTemplate>(&csr_template_str)
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"status": 400, "detail": format!("invalid csr_template: {e}")})),
        )
            .into_response();
    }
    let cname_map_str = payload.cname_map.as_ref().map(|v| v.to_string());
    let id = uuid::Uuid::new_v4().to_string();
    let now = unix_now();

    let row = crate::db::schema::DelegationRow {
        id: id.clone(),
        account_id: payload.account_id.clone(),
        csr_template: csr_template_str,
        cname_map: cname_map_str,
        created: now,
        updated: now,
    };

    match db::delegations::insert(&state.db, row).await {
        Ok(()) => {
            state
                .record_audit(
                    AuditEvent::success(AuditEventType::AdminAction)
                        .with_principal(&operator.name)
                        .with_subject(&id)
                        .with_detail(
                            json!({"action": "delegation.create", "account_id": payload.account_id})
                                .to_string(),
                        ),
                )
                .await;
            crdt_hooks::on_delegation_upsert(
                &state,
                &id,
                &payload.account_id,
                &payload.csr_template.to_string(),
                now,
                "",
            )
            .await;
            let location = format!("/admin/delegations/{id}");
            let mut resp = (
                StatusCode::CREATED,
                Json(json!({"id": id, "account_id": payload.account_id, "created": now})),
            )
                .into_response();
            if let Ok(v) = axum::http::HeaderValue::from_str(&location) {
                resp.headers_mut().insert(axum::http::header::LOCATION, v);
            }
            resp
        }
        Err(e) => {
            tracing::error!(error = %e, "post_delegations: db error");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"status": 500, "detail": "database error"})),
            )
                .into_response()
        }
    }
}

/// `GET /admin/delegations/{id}`
///
/// Fetch a single delegation object.
/// Requires: any role.
pub async fn get_delegation_admin(
    operator: OperatorContext,
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Response {
    require_role!(
        operator,
        state,
        Administrator | CaOperations | CaRa | Auditor
    );

    match db::delegations::get_by_id(&state.db, &id).await {
        Ok(Some(r)) => {
            if let Some(scope) = operator.ca_scope() {
                match db::accounts::get_by_id(&state.db, &r.account_id).await {
                    Ok(Some(acct)) if !acct.ca_id.is_empty() && acct.ca_id != scope => {
                        return (
                            StatusCode::NOT_FOUND,
                            Json(json!({"status": 404, "detail": "delegation not found"})),
                        )
                            .into_response();
                    }
                    Err(e) => {
                        tracing::error!(error = %e, "get_delegation_admin: scope check db error");
                        return (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            Json(json!({"status": 500, "detail": "database error"})),
                        )
                            .into_response();
                    }
                    _ => {}
                }
            }
            match delegation_row_to_json(&r) {
                Err(e) => {
                    tracing::error!(error = %e, delegation_id = %r.id, "get_delegation_admin: corrupt row");
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(json!({"status": 500, "detail": "database contains corrupt delegation data"})),
                    )
                        .into_response()
                }
                Ok(body) => (StatusCode::OK, Json(body)).into_response(),
            }
        }
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json!({"status": 404, "detail": "delegation not found"})),
        )
            .into_response(),
        Err(e) => {
            tracing::error!(error = %e, "get_delegation_admin: db error");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"status": 500, "detail": "database error"})),
            )
                .into_response()
        }
    }
}

/// `PUT /admin/delegations/{id}`
///
/// Replace the CSR template and optional CNAME map for a delegation.
/// Requires: `administrator` or `ca_operations`.
pub async fn put_delegation(
    operator: OperatorContext,
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    body: Bytes,
) -> Response {
    require_role!(operator, state, Administrator | CaOperations);

    let payload: DelegationUpdatePayload = match serde_json::from_slice(&body) {
        Ok(p) => p,
        Err(e) => return (StatusCode::BAD_REQUEST, format!("JSON: {e}")).into_response(),
    };

    if let Some(scope) = operator.ca_scope() {
        match db::delegations::get_by_id(&state.db, &id).await {
            Ok(None) => {
                return (
                    StatusCode::NOT_FOUND,
                    Json(json!({"status": 404, "detail": "delegation not found"})),
                )
                    .into_response();
            }
            Err(e) => {
                tracing::error!(error = %e, "put_delegation: scope fetch error");
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"status": 500, "detail": "database error"})),
                )
                    .into_response();
            }
            Ok(Some(dlg)) => match db::accounts::get_by_id(&state.db, &dlg.account_id).await {
                Ok(Some(acct)) if !acct.ca_id.is_empty() && acct.ca_id != scope => {
                    return (
                            StatusCode::FORBIDDEN,
                            Json(json!({"status": 403, "detail": "delegation does not belong to your CA scope"})),
                        )
                            .into_response();
                }
                Err(e) => {
                    tracing::error!(error = %e, "put_delegation: account scope check error");
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(json!({"status": 500, "detail": "database error"})),
                    )
                        .into_response();
                }
                _ => {}
            },
        }
    }

    let csr_template_str = payload.csr_template.to_string();
    // Validate the CSR template syntax before storing it.
    if let Err(e) = serde_json::from_str::<crate::ca::csr_template::CsrTemplate>(&csr_template_str)
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"status": 400, "detail": format!("invalid csr_template: {e}")})),
        )
            .into_response();
    }
    let cname_map_str = payload.cname_map.as_ref().map(|v| v.to_string());
    let now = unix_now();

    match db::delegations::update(
        &state.db,
        &id,
        &csr_template_str,
        cname_map_str.as_deref(),
        now,
    )
    .await
    {
        Ok(true) => {
            state
                .record_audit(
                    AuditEvent::success(AuditEventType::AdminAction)
                        .with_principal(&operator.name)
                        .with_subject(&id)
                        .with_detail("{\"action\":\"delegation.update\"}"),
                )
                .await;
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(false) => (
            StatusCode::NOT_FOUND,
            Json(json!({"status": 404, "detail": "delegation not found"})),
        )
            .into_response(),
        Err(e) => {
            tracing::error!(error = %e, "put_delegation: db error");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"status": 500, "detail": "database error"})),
            )
                .into_response()
        }
    }
}

/// `DELETE /admin/delegations/{id}`
///
/// Delete a delegation. Fails with 409 if any orders still reference it.
/// Requires: `administrator` or `ca_operations`.
pub async fn delete_delegation(
    operator: OperatorContext,
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Response {
    require_role!(operator, state, Administrator | CaOperations);

    if let Some(scope) = operator.ca_scope() {
        match db::delegations::get_by_id(&state.db, &id).await {
            Ok(None) => {
                return (
                    StatusCode::NOT_FOUND,
                    Json(json!({"status": 404, "detail": "delegation not found"})),
                )
                    .into_response();
            }
            Err(e) => {
                tracing::error!(error = %e, "delete_delegation: scope fetch error");
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"status": 500, "detail": "database error"})),
                )
                    .into_response();
            }
            Ok(Some(dlg)) => match db::accounts::get_by_id(&state.db, &dlg.account_id).await {
                Ok(Some(acct)) if !acct.ca_id.is_empty() && acct.ca_id != scope => {
                    return (
                            StatusCode::FORBIDDEN,
                            Json(json!({"status": 403, "detail": "delegation does not belong to your CA scope"})),
                        )
                            .into_response();
                }
                Err(e) => {
                    tracing::error!(error = %e, "delete_delegation: account scope check error");
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(json!({"status": 500, "detail": "database error"})),
                    )
                        .into_response();
                }
                _ => {}
            },
        }
    }

    match db::delegations::delete(&state.db, &id).await {
        Ok(true) => {
            state
                .record_audit(
                    AuditEvent::success(AuditEventType::AdminAction)
                        .with_principal(&operator.name)
                        .with_subject(&id)
                        .with_detail("{\"action\":\"delegation.delete\"}"),
                )
                .await;
            crdt_hooks::on_delegation_tombstone(&state, &id, unix_now()).await;
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(false) => (
            StatusCode::NOT_FOUND,
            Json(json!({"status": 404, "detail": "delegation not found"})),
        )
            .into_response(),
        Err(crate::error::AcmeError::Database(ref msg))
            if msg.contains("FOREIGN KEY") || msg.contains("foreign key") =>
        {
            (
                StatusCode::CONFLICT,
                Json(json!({"status": 409, "detail": "delegation is referenced by active orders"})),
            )
                .into_response()
        }
        Err(e) => {
            tracing::error!(error = %e, "delete_delegation: db error");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"status": 500, "detail": "database error"})),
            )
                .into_response()
        }
    }
}
