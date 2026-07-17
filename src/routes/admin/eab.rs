//! Admin EAB key management handlers.

use std::sync::Arc;

use base64::Engine as _;

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
    #[serde(default)]
    kid: Option<String>,
    #[serde(default)]
    hmac_key_b64u: Option<String>,
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

    if !matches!(payload.alg.as_str(), "sha256" | "sha384" | "sha512") {
        return (
            StatusCode::BAD_REQUEST,
            "alg must be one of: sha256, sha384, sha512",
        )
            .into_response();
    }

    // Resolve the owner operator: the caller may delegate to another operator,
    // but only administrators may do so (prevents ca_operations privilege escalation).
    // Also capture gssapi_principal for deterministic EAB derivation.
    let (owner_operator_id, owner_principal) = if let Some(target_id) = payload.for_operator_id {
        if operator.role != OperatorRole::Administrator {
            return (
                StatusCode::FORBIDDEN,
                Json(json!({"status": 403, "detail": "only administrators may create EAB keys for other operators"})),
            )
                .into_response();
        }
        match db::operators::get_by_id(&state.db, target_id).await {
            Ok(Some(op)) if op.active == 1 => (op.id, op.gssapi_principal),
            Ok(Some(_)) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({"status": 400, "detail": "target operator is not active"})),
                )
                    .into_response();
            }
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
        // Self-ownership: look up the calling operator's principal.
        match db::operators::get_by_id(&state.db, operator.operator_id).await {
            Ok(Some(op)) => (op.id, op.gssapi_principal),
            Ok(None) => (operator.operator_id, None),
            Err(e) => {
                tracing::error!(error = %e, "post_eab: owner operator lookup failed");
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
        }
    };

    let caller_supplied_kid = matches!(payload.kid, Some(ref k) if !k.is_empty());
    let caller_supplied_key = matches!(payload.hmac_key_b64u, Some(ref k) if !k.is_empty());

    // When the owner has a GSSAPI principal and eab_master_secret is configured,
    // derive deterministic kid/hmac_key so that both the mTLS admin path and the
    // GSSAPI /acme/eab path produce identical credentials for the same principal.
    let (kid, hmac_key_b64u, bound_principal, derived) =
        if !caller_supplied_kid && !caller_supplied_key {
            if let (Some(ref principal), Some(ref master)) =
                (&owner_principal, &state.eab_master_secret)
            {
                match crate::eab_derivation::derive_eab_credentials(master, principal) {
                    Ok((k, h)) => (k, h, Some(principal.as_str()), true),
                    Err(e) => {
                        tracing::error!(error = %e, "post_eab: EAB credential derivation failed");
                        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
                    }
                }
            } else {
                let kid = {
                    let mut buf = [0u8; 16];
                    if let Err(e) = native_ossl::rand::Rand::fill(&mut buf) {
                        tracing::error!(error = %e, "post_eab: random kid generation failed");
                        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
                    }
                    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(buf)
                };
                let hmac_key = {
                    let mut buf = [0u8; 32];
                    if let Err(e) = native_ossl::rand::Rand::fill(&mut buf) {
                        tracing::error!(error = %e, "post_eab: random hmac_key generation failed");
                        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
                    }
                    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(buf)
                };
                (kid, hmac_key, None, false)
            }
        } else {
            let kid = match payload.kid {
                Some(ref k) if !k.is_empty() => k.clone(),
                _ => {
                    let mut buf = [0u8; 16];
                    if let Err(e) = native_ossl::rand::Rand::fill(&mut buf) {
                        tracing::error!(error = %e, "post_eab: random kid generation failed");
                        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
                    }
                    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(buf)
                }
            };
            let hmac_key = match payload.hmac_key_b64u {
                Some(ref k) if !k.is_empty() => k.clone(),
                _ => {
                    let mut buf = [0u8; 32];
                    if let Err(e) = native_ossl::rand::Rand::fill(&mut buf) {
                        tracing::error!(error = %e, "post_eab: random hmac_key generation failed");
                        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
                    }
                    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(buf)
                }
            };
            (kid, hmac_key, None, false)
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

    if derived {
        // Derived credentials: use idempotent insert since the same principal
        // always yields the same kid.
        let eab_params = db::eab::EabGrantParams {
            kid: &kid,
            hmac_key_b64u: &hmac_key_b64u,
            profile_grants: grants_str.as_deref(),
            created_by_operator_id: Some(owner_operator_id),
            alg: &payload.alg,
            now,
            bound_principal,
        };
        let inserted = match db::eab::insert_if_absent_with_grants(&state.db, &eab_params).await {
            Ok(inserted) => inserted,
            Err(e) => {
                tracing::error!(error = %e, kid = %kid, "post_eab: db error");
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"status": 500, "detail": "database error"})),
                )
                    .into_response();
            }
        };

        // Check if the key was already consumed by a prior account registration.
        match db::eab::get_by_kid(&state.db, &kid).await {
            Ok(Some(row)) if row.used_at.is_some() => {
                return (
                    StatusCode::CONFLICT,
                    Json(json!({
                        "status": 409,
                        "detail": format!(
                            "EAB credentials for principal '{}' have already been consumed",
                            bound_principal.unwrap_or("unknown")
                        )
                    })),
                )
                    .into_response();
            }
            Ok(Some(_)) => {}
            Ok(None) => {
                tracing::error!(kid = %kid, "post_eab: EAB key vanished after insert");
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
            Err(e) => {
                tracing::error!(error = %e, "post_eab: EAB key lookup after insert failed");
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
        }

        state
            .record_audit(
                AuditEvent::success(AuditEventType::AdminAction)
                    .with_principal(&operator.name)
                    .with_subject(&kid)
                    .with_detail("{\"action\":\"eab.create\"}"),
            )
            .await;
        if inserted {
            crdt_hooks::on_eab_key_set(&state, &kid, &hmac_key_b64u, now, None, grants_str).await;
        }
        (
            StatusCode::OK,
            Json(json!({"kid": kid, "hmac_key_b64u": hmac_key_b64u, "created": now, "alg": payload.alg})),
        )
            .into_response()
    } else {
        let eab_params = db::eab::EabGrantParams {
            kid: &kid,
            hmac_key_b64u: &hmac_key_b64u,
            profile_grants: grants_str.as_deref(),
            created_by_operator_id: Some(owner_operator_id),
            alg: &payload.alg,
            now,
            bound_principal,
        };
        match db::eab::insert_with_grants(&state.db, &eab_params).await {
            Ok(()) => {
                state
                    .record_audit(
                        AuditEvent::success(AuditEventType::AdminAction)
                            .with_principal(&operator.name)
                            .with_subject(&kid)
                            .with_detail("{\"action\":\"eab.create\"}"),
                    )
                    .await;
                crdt_hooks::on_eab_key_set(&state, &kid, &hmac_key_b64u, now, None, grants_str)
                    .await;
                (
                    StatusCode::CREATED,
                    Json(json!({"kid": kid, "hmac_key_b64u": hmac_key_b64u, "created": now, "alg": payload.alg})),
                )
                    .into_response()
            }
            Err(crate::error::AcmeError::Database(ref msg))
                if msg.contains("UNIQUE")
                    || msg.contains("unique")
                    || msg.contains("Duplicate") =>
            {
                (
                    StatusCode::CONFLICT,
                    format!("EAB key '{kid}' already exists"),
                )
                    .into_response()
            }
            Err(e) => {
                tracing::error!(error = %e, kid = %kid, "post_eab: db error");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"status": 500, "detail": "database error"})),
                )
                    .into_response()
            }
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
                "bound_principal": r.bound_principal,
                "created_by_operator_id": r.created_by_operator_id,
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
