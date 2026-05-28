//! Admin EAB key management handlers.

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
use crate::state::{AppState, OperatorRole};

use super::super::unix_now;
use super::grants_to_json;

#[derive(Deserialize)]
struct NewEabPayload {
    kid: String,
    hmac_key_b64u: String,
    #[serde(default)]
    profile_grants: Option<Vec<String>>,
    #[serde(default = "default_eab_alg")]
    alg: String,
    /// Override the operator that owns this key for web UI EAB login.
    /// Only `administrator` may set this; omit to default to the calling operator.
    #[serde(default)]
    for_operator_id: Option<i64>,
}

fn default_eab_alg() -> String {
    "sha256".to_owned()
}

/// `GET /admin/eab`
///
/// List EAB keys.  Query params:
///   `used=true|false` — filter by used status
///   `limit=N`        — max rows returned (default 200)
///   `offset=N`       — skip first N rows (default 0)
/// Requires: any role.
pub async fn get_eab(
    operator: OperatorContext,
    State(state): State<Arc<AppState>>,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> Response {
    require_role!(
        operator,
        state,
        Administrator | CaOperations | CaRa | Auditor
    );

    let used_filter = params.get("used").and_then(|v| match v.as_str() {
        "true" => Some(true),
        "false" => Some(false),
        _ => None,
    });
    let limit: i64 = params
        .get("limit")
        .and_then(|v| v.parse().ok())
        .unwrap_or(200)
        .clamp(1, 1000);
    let offset: i64 = params
        .get("offset")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0)
        .max(0);

    match tokio::try_join!(
        db::eab::list(&state.db, used_filter, limit, offset),
        db::eab::count_list(&state.db, used_filter),
    ) {
        Ok((rows, total)) => {
            let keys: Vec<_> = rows
                .into_iter()
                .map(|r| {
                    json!({
                        "kid": r.kid,
                        "created": r.created,
                        "used_at": r.used_at,
                        "profile_grants": r.profile_grants,
                        "alg": r.alg,
                        "bound_principal": r.bound_principal,
                        "created_by_operator_id": r.created_by_operator_id,
                    })
                })
                .collect();
            (
                StatusCode::OK,
                Json(json!({"eab_keys": keys, "total": total, "limit": limit, "offset": offset})),
            )
                .into_response()
        }
        Err(e) => {
            tracing::error!(error = %e, "get_eab: db error");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"status": 500, "detail": "database error"})),
            )
                .into_response()
        }
    }
}

/// `POST /admin/eab`
///
/// Provision a new EAB key, optionally with profile grants.
/// Requires: `administrator` or `ca_operations`.
///
/// `ca_ra` is intentionally excluded: EAB keys are server-global and not
/// bound to any CA, so a CA-scoped `ca_ra` operator could otherwise create
/// keys usable for account creation under any CA.
///
/// Scoped `ca_operations` operators are permitted to create EAB keys by
/// design — they have higher trust than `ca_ra` and need to pre-provision
/// keys for their CA's accounts.
pub async fn post_eab(
    operator: OperatorContext,
    State(state): State<Arc<AppState>>,
    body: Bytes,
) -> Response {
    require_role!(operator, state, Administrator | CaOperations);

    let payload: NewEabPayload = match serde_json::from_slice(&body) {
        Ok(p) => p,
        Err(e) => return (StatusCode::BAD_REQUEST, format!("JSON: {e}")).into_response(),
    };

    if payload.kid.is_empty() || payload.hmac_key_b64u.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            "kid and hmac_key_b64u are required",
        )
            .into_response();
    }

    if !matches!(payload.alg.as_str(), "sha256" | "sha384" | "sha512") {
        return (
            StatusCode::BAD_REQUEST,
            "alg must be one of: sha256, sha384, sha512",
        )
            .into_response();
    }

    // Resolve the owner operator: the caller may delegate to another operator,
    // but only administrators may do so (prevents ca_operations privilege escalation).
    let owner_operator_id = if let Some(target_id) = payload.for_operator_id {
        if operator.role != OperatorRole::Administrator {
            return (
                StatusCode::FORBIDDEN,
                Json(json!({"status": 403, "detail": "only administrators may create EAB keys for other operators"})),
            )
                .into_response();
        }
        match db::operators::get_by_id(&state.db, target_id).await {
            Ok(Some(_)) => target_id,
            Ok(None) => {
                return (
                    StatusCode::NOT_FOUND,
                    Json(json!({"status": 404, "detail": "target operator not found"})),
                )
                    .into_response();
            }
            Err(e) => {
                tracing::error!(error = %e, operator_id = target_id, "post_eab: operator lookup failed");
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
        }
    } else {
        operator.operator_id
    };

    let now = unix_now();
    let grants_str = match grants_to_json(payload.profile_grants) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(error = %e, "post_eab: serialize grants");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"status": 500, "detail": "internal error"})),
            )
                .into_response();
        }
    };
    match db::eab::insert_with_grants(
        &state.db,
        &payload.kid,
        &payload.hmac_key_b64u,
        grants_str.as_deref(),
        Some(owner_operator_id),
        &payload.alg,
        now,
    )
    .await
    {
        Ok(()) => {
            state
                .record_audit(
                    AuditEvent::success(AuditEventType::AdminAction)
                        .with_principal(&operator.name)
                        .with_subject(&payload.kid)
                        .with_detail("{\"action\":\"eab.create\"}"),
                )
                .await;
            crdt_hooks::on_eab_key_set(
                &state,
                &payload.kid,
                &payload.hmac_key_b64u,
                now,
                None,
                grants_str,
            )
            .await;
            (
                StatusCode::CREATED,
                Json(json!({"kid": payload.kid, "created": now, "alg": payload.alg})),
            )
                .into_response()
        }
        Err(crate::error::AcmeError::Database(ref msg))
            if msg.contains("UNIQUE") || msg.contains("unique") || msg.contains("Duplicate") =>
        {
            (
                StatusCode::CONFLICT,
                format!("EAB key '{}' already exists", payload.kid),
            )
                .into_response()
        }
        Err(e) => {
            tracing::error!(error = %e, kid = %payload.kid, "post_eab: db error");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"status": 500, "detail": "database error"})),
            )
                .into_response()
        }
    }
}

/// `DELETE /admin/eab/{kid}`
///
/// Mark an EAB key as deactivated (deleted from the table).
/// Requires: `administrator` or `ca_operations`.
pub async fn delete_eab(
    operator: OperatorContext,
    State(state): State<Arc<AppState>>,
    Path(kid): Path<String>,
) -> Response {
    require_role!(operator, state, Administrator | CaOperations);

    match db::eab::delete(&state.db, &kid).await {
        Ok(0) => (
            StatusCode::NOT_FOUND,
            Json(json!({"status": 404, "detail": "EAB key not found"})),
        )
            .into_response(),
        Ok(_) => {
            state
                .record_audit(
                    AuditEvent::success(AuditEventType::AdminAction)
                        .with_principal(&operator.name)
                        .with_subject(&kid)
                        .with_detail("{\"action\":\"eab.delete\"}"),
                )
                .await;
            StatusCode::NO_CONTENT.into_response()
        }
        Err(e) => {
            tracing::error!(error = %e, "delete_eab: db error");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"status": 500, "detail": "database error"})),
            )
                .into_response()
        }
    }
}

/// `GET /admin/eab/{kid}`
///
/// Show a single EAB key's details.
/// Requires: any role.
pub async fn get_eab_key(
    operator: OperatorContext,
    State(state): State<Arc<AppState>>,
    Path(kid): Path<String>,
) -> Response {
    require_role!(
        operator,
        state,
        Administrator | CaOperations | CaRa | Auditor
    );

    match db::eab::get_by_kid(&state.db, &kid).await {
        Ok(Some(r)) => (
            StatusCode::OK,
            Json(json!({
                "kid": r.kid,
                "created": r.created,
                "used_at": r.used_at,
                "profile_grants": r.profile_grants,
                "alg": r.alg,
            })),
        )
            .into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json!({"status": 404, "detail": "EAB key not found"})),
        )
            .into_response(),
        Err(e) => {
            tracing::error!(error = %e, "get_eab_key: db error");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"status": 500, "detail": "database error"})),
            )
                .into_response()
        }
    }
}
