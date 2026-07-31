//! Admin account management handlers.

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
use super::grants_to_json;

#[derive(Deserialize)]
struct ProfileGrantsPayload {
    profile_grants: Option<Vec<String>>,
}

/// `GET /admin/account/{id}/profile-grants`
///
/// Returns `{"profile_grants":["p1","p2"]}` or `{"profile_grants":null}`.
/// Requires: any role.
pub async fn get_account_profile_grants(
    operator: OperatorContext,
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Response, AdminApiError> {
    if let Some(scope) = operator.ca_scope() {
        match db::accounts::get_by_id(&state.db, &id).await {
            Ok(Some(acct)) if !acct.ca_id.is_empty() && acct.ca_id != scope => {
                return Err(AdminApiError::NotFound("account not found".into()));
            }
            Ok(None) => {
                return Err(AdminApiError::NotFound("account not found".into()));
            }
            Err(e) => {
                return Err(AdminApiError::Internal(format!(
                    "get_account_profile_grants: scope check db error: {e}"
                )));
            }
            Ok(Some(_)) => {}
        }
    }

    match db::accounts::get_profile_grants(&state.db, &id).await {
        Err(e) => Err(AdminApiError::Internal(format!(
            "get_account_profile_grants: db error: {e}"
        ))),
        Ok(None) => Err(AdminApiError::NotFound("account not found".into())),
        Ok(Some(grants_json)) => {
            let grants: Option<Vec<String>> = grants_json.as_deref().and_then(|j| {
                serde_json::from_str(j)
                    .map_err(|e| {
                        tracing::warn!(
                            account_id = %id,
                            error = %e,
                            "profile_grants column contains malformed JSON; treating as no grants"
                        );
                    })
                    .ok()
            });
            Ok((StatusCode::OK, Json(json!({"profile_grants": grants}))).into_response())
        }
    }
}

/// `PUT /admin/account/{id}/profile-grants`
///
/// Replaces the account's grants entirely.
/// Requires: `administrator` or `ca_operations`.
pub async fn put_account_profile_grants(
    operator: OperatorContext,
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    body: Bytes,
) -> Result<Response, AdminApiError> {
    let payload: ProfileGrantsPayload = serde_json::from_slice(&body)
        .map_err(|e| AdminApiError::BadRequest(format!("JSON: {e}")))?;

    if let Some(scope) = operator.ca_scope() {
        match db::accounts::get_by_id(&state.db, &id).await {
            Ok(Some(acct)) if !acct.ca_id.is_empty() && acct.ca_id != scope => {
                return Err(AdminApiError::NotFound("account not found".into()));
            }
            Ok(None) => {
                return Err(AdminApiError::NotFound("account not found".into()));
            }
            Err(e) => {
                return Err(AdminApiError::Internal(format!(
                    "put_account_profile_grants: scope check db error: {e}"
                )));
            }
            Ok(Some(_)) => {}
        }
    }

    let now = unix_now();
    let grants_str = grants_to_json(payload.profile_grants).map_err(|e| {
        AdminApiError::Internal(format!("put_account_profile_grants: serialize grants: {e}"))
    })?;
    match db::accounts::set_profile_grants(&state.db, &id, grants_str.as_deref(), now).await {
        Err(e) => Err(AdminApiError::Internal(format!(
            "put_account_profile_grants: db error: {e}"
        ))),
        Ok(false) => Err(AdminApiError::NotFound(
            "account not found or deactivated".into(),
        )),
        Ok(true) => {
            state
                .record_audit(
                    AuditEvent::success(AuditEventType::AdminAction)
                        .with_principal(&operator.name)
                        .with_subject(&id)
                        .with_detail("{\"action\":\"account.grants.set\"}"),
                )
                .await;
            Ok(StatusCode::NO_CONTENT.into_response())
        }
    }
}

/// `DELETE /admin/account/{id}/profile-grants`
///
/// Clears all profile grants (sets to NULL — unrestricted).
/// Requires: `administrator`.
pub async fn delete_account_profile_grants(
    operator: OperatorContext,
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Response, AdminApiError> {
    let now = unix_now();
    match db::accounts::set_profile_grants(&state.db, &id, None, now).await {
        Err(e) => Err(AdminApiError::Internal(format!(
            "delete_account_profile_grants: db error: {e}"
        ))),
        Ok(false) => Err(AdminApiError::NotFound(
            "account not found or deactivated".into(),
        )),
        Ok(true) => {
            state
                .record_audit(
                    AuditEvent::success(AuditEventType::AdminAction)
                        .with_principal(&operator.name)
                        .with_subject(&id)
                        .with_detail("{\"action\":\"account.grants.clear\"}"),
                )
                .await;
            Ok(StatusCode::NO_CONTENT.into_response())
        }
    }
}

/// `GET /admin/accounts`
///
/// List accounts with optional status filter and pagination.
/// Requires: any role.
pub async fn get_accounts(
    operator: OperatorContext,
    State(state): State<Arc<AppState>>,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> Result<Response, AdminApiError> {
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
    let status = params.get("status").map(String::as_str);
    // Scoped operators are always restricted to their own CA; override any supplied ca_id.
    let ca_id = operator
        .ca_scope()
        .or_else(|| params.get("ca_id").map(String::as_str));

    match tokio::try_join!(
        db::accounts::list(&state.db, status, ca_id, limit, offset),
        db::accounts::count_list(&state.db, status, ca_id),
    ) {
        Ok((rows, total)) => {
            let accounts: Vec<_> = rows
                .into_iter()
                .map(|r| {
                    json!({
                        "id": r.id,
                        "status": r.status,
                        "contact": r.contact,
                        "jwk_thumbprint": r.jwk_thumbprint,
                        "created": r.created,
                        "updated": r.updated,
                        "profile_grants": r.profile_grants,
                    })
                })
                .collect();
            Ok((
                StatusCode::OK,
                Json(
                    json!({"accounts": accounts, "total": total, "limit": limit, "offset": offset}),
                ),
            )
                .into_response())
        }
        Err(e) => Err(AdminApiError::Internal(format!(
            "get_accounts: db error: {e}"
        ))),
    }
}

/// `GET /admin/account/{id}`
///
/// Show a single account's details.
/// Requires: any role.
pub async fn get_account(
    operator: OperatorContext,
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Response, AdminApiError> {
    match db::accounts::get_by_id(&state.db, &id).await {
        Ok(Some(r)) => {
            if operator
                .ca_scope()
                .is_some_and(|scope| !r.ca_id.is_empty() && r.ca_id != scope)
            {
                return Err(AdminApiError::NotFound("account not found".into()));
            }
            Ok((
                StatusCode::OK,
                Json(json!({
                    "id": r.id,
                    "status": r.status,
                    "contact": r.contact,
                    "jwk_thumbprint": r.jwk_thumbprint,
                    "created": r.created,
                    "updated": r.updated,
                    "profile_grants": r.profile_grants,
                })),
            )
                .into_response())
        }
        Ok(None) => Err(AdminApiError::NotFound("account not found".into())),
        Err(e) => Err(AdminApiError::Internal(format!(
            "get_account: db error: {e}"
        ))),
    }
}

/// `POST /admin/account/{id}/deactivate`
///
/// Admin-initiated account deactivation.
/// Requires: `administrator`.
pub async fn post_account_deactivate(
    operator: OperatorContext,
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Response, AdminApiError> {
    let now = unix_now();
    match db::accounts::update_status(&state.db, &id, "deactivated", now).await {
        Ok(true) => {
            // Evict the cached SPKI/status entry so a subsequent JWS from
            // this account is re-checked against the DB instead of
            // authenticating against a stale "valid" cache entry (the same
            // eviction the self-service deactivate and key-change paths
            // already perform).
            match state.spki_cache.write() {
                Ok(mut cache) => {
                    cache.remove(&id);
                }
                Err(e) => {
                    tracing::error!(
                        "spki_cache RwLock poisoned; evicting deactivated account under poison guard"
                    );
                    e.into_inner().remove(&id);
                }
            }
            state
                .record_audit(
                    AuditEvent::success(AuditEventType::AdminAction)
                        .with_principal(&operator.name)
                        .with_subject(&id)
                        .with_detail("{\"action\":\"account.deactivate\"}"),
                )
                .await;
            crdt_hooks::on_account_tombstone(&state, &id, now).await;
            Ok(StatusCode::NO_CONTENT.into_response())
        }
        Ok(false) => Err(AdminApiError::NotFound("account not found".into())),
        Err(e) => Err(AdminApiError::Internal(format!(
            "post_account_deactivate: db error: {e}"
        ))),
    }
}

/// `GET /admin/orders`
///
/// List orders with optional filters and pagination.
/// Requires: any role.
pub async fn get_orders(
    operator: OperatorContext,
    State(state): State<Arc<AppState>>,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> Result<Response, AdminApiError> {
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
    let status = params.get("status").map(String::as_str);
    // Scoped operators are always restricted to their own CA; override any supplied ca_id.
    let ca_id = operator
        .ca_scope()
        .or_else(|| params.get("ca_id").map(String::as_str));

    match tokio::try_join!(
        db::orders::list(&state.db, account_id, status, ca_id, limit, offset),
        db::orders::count_list(&state.db, account_id, status, ca_id),
    ) {
        Ok((rows, total)) => {
            let orders: Vec<_> = rows
                .into_iter()
                .map(|r| {
                    json!({
                        "id": r.id,
                        "account_id": r.account_id,
                        "status": r.status,
                        "identifiers": r.identifiers,
                        "certificate_id": r.certificate_id,
                        "profile": r.profile,
                        "created": r.created,
                        "updated": r.updated,
                        "expires": r.expires,
                    })
                })
                .collect();
            Ok((
                StatusCode::OK,
                Json(json!({"orders": orders, "total": total, "limit": limit, "offset": offset})),
            )
                .into_response())
        }
        Err(e) => Err(AdminApiError::Internal(format!(
            "get_orders: db error: {e}"
        ))),
    }
}

/// `GET /admin/orders/{id}`
///
/// Show a single order's details with authorization IDs.
/// Requires: any role.
pub async fn get_order(
    operator: OperatorContext,
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Response, AdminApiError> {
    match db::orders::get_with_authz_ids(&state.db, &id).await {
        Ok(Some((r, authz_ids))) => {
            if operator.ca_scope().is_some_and(|scope| r.ca_id != scope) {
                return Err(AdminApiError::NotFound("order not found".into()));
            }
            Ok((
                StatusCode::OK,
                Json(json!({
                    "id": r.id,
                    "account_id": r.account_id,
                    "status": r.status,
                    "identifiers": r.identifiers,
                    "certificate_id": r.certificate_id,
                    "profile": r.profile,
                    "created": r.created,
                    "updated": r.updated,
                    "expires": r.expires,
                    "not_before": r.not_before,
                    "not_after": r.not_after,
                    "replaces": r.replaces,
                    "authorization_ids": authz_ids,
                })),
            )
                .into_response())
        }
        Ok(None) => Err(AdminApiError::NotFound("order not found".into())),
        Err(e) => Err(AdminApiError::Internal(format!("get_order: db error: {e}"))),
    }
}
