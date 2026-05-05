//! Admin API endpoints — `/admin/…`
//!
//! All routes require operator authentication via mTLS client certificate or
//! GSSAPI/Kerberos session token (see `crate::admin::auth`).  When the `[admin]`
//! section is absent the routes return 404.
//!
//! # Route → role matrix
//!
//! | Route | administrator | ca_operations | ca_ra | auditor |
//! |-------|:---:|:---:|:---:|:---:|
//! | `POST /admin/session` | ✓ | ✓ | ✓ | ✓ |
//! | `DELETE /admin/session` | ✓ | ✓ | ✓ | ✓ |
//! | `GET /admin/operators` | ✓ | | | |
//! | `POST /admin/operators` | ✓ | | | |
//! | `GET /admin/operators/{id}` | ✓ | | | |
//! | `PUT /admin/operators/{id}` | ✓ | | | |
//! | `PATCH /admin/operators/{id}` | ✓ | | | |
//! | `POST /admin/operators/{id}/unlock` | ✓ | | | |
//! | `GET /admin/audit` | ✓ | | | ✓ |
//! | `GET /admin/certs` | ✓ | ✓ | | ✓ |
//! | `GET /admin/certs/{id}` | ✓ | ✓ | | ✓ |
//! | `GET /admin/certs/{id}/download` | ✓ | ✓ | | |
//! | `GET /admin/profiles` | ✓ | ✓ | ✓ | ✓ |
//! | `POST /admin/profiles` | ✓ | | | |
//! | `PUT /admin/profiles/{id}` | ✓ | | | |
//! | `DELETE /admin/profiles/{id}` | ✓ | | | |
//! | `GET /admin/accounts` | ✓ | ✓ | ✓ | ✓ |
//! | `GET /admin/account/{id}` | ✓ | ✓ | ✓ | ✓ |
//! | `POST /admin/account/{id}/deactivate` | ✓ | | | |
//! | `GET /admin/account/{id}/profile-grants` | ✓ | ✓ | ✓ | ✓ |
//! | `PUT /admin/account/{id}/profile-grants` | ✓ | ✓ | | |
//! | `DELETE /admin/account/{id}/profile-grants` | ✓ | | | |
//! | `POST /admin/eab` | ✓ | ✓ | ✓ | |
//! | `GET /admin/eab/{kid}` | ✓ | ✓ | ✓ | ✓ |
//! | `DELETE /admin/eab/{kid}` | ✓ | ✓ | | |
//! | `GET /admin/eab` | ✓ | ✓ | ✓ | ✓ |
//! | `GET /admin/orders` | ✓ | ✓ | ✓ | ✓ |
//! | `GET /admin/orders/{id}` | ✓ | ✓ | ✓ | ✓ |
//! | `GET /admin/config` | ✓ | | | |
//! | `POST /admin/crl/force` | ✓ | ✓ | | |
//! | `POST /admin/revoke` | ✓ | ✓ | ✓ | |
//! | `GET /admin/stats` | ✓ | ✓ | ✓ | ✓ |
//! | `GET /admin/cas` | ✓ | ✓ | | |
//! | `GET /admin/cas/{id}` | ✓ | ✓ | | |
//! | `GET /admin/cas/{id}/cert` | ✓ | ✓ | | |
//! | `POST /admin/ca/{id}/crl/force` | ✓ | ✓ | | |
//! | `POST /admin/ca/{id}/cross-sign` | ✓ | ✓ | | |
//! | `GET /admin/cross-certs` | ✓ | ✓ | | ✓ |
//! | `GET /admin/cross-certs/{id}` | ✓ | ✓ | | ✓ |

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;

use crate::require_role;
use serde_json::json;

use crate::admin::auth::OperatorContext;
use crate::audit::{AuditEvent, AuditEventType};
use crate::db;
use crate::state::AppState;
use synta_certificate::der_to_pem;

use super::unix_now;

// ── Payload types ─────────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct ProfileGrantsPayload {
    profile_grants: Option<Vec<String>>,
}

#[derive(Deserialize)]
struct NewEabPayload {
    kid: String,
    hmac_key_b64u: String,
    #[serde(default)]
    profile_grants: Option<Vec<String>>,
}

#[derive(Deserialize)]
struct NewOperatorPayload {
    name: String,
    role: String,
    cert_fingerprint: Option<String>,
    gssapi_principal: Option<String>,
}

#[derive(Deserialize)]
struct PatchOperatorPayload {
    /// `true` to activate, `false` to deactivate.
    active: bool,
}

#[derive(Deserialize)]
struct RevokePayload {
    /// Certificate ID (UUID).
    cert_id: String,
    /// Revocation reason code (0–10).  Default 0 (unspecified).
    #[serde(default)]
    reason: u8,
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn grants_to_json(grants: Option<Vec<String>>) -> Result<Option<String>, String> {
    match grants {
        None => Ok(None),
        Some(ref vec) if vec.is_empty() => Ok(None),
        Some(ref vec) => serde_json::to_string(vec)
            .map(Some)
            .map_err(|e| format!("serialize profile_grants: {e}")),
    }
}

// ── Operator management ───────────────────────────────────────────────────────

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

    let now = crate::util::rfc3339_now();
    let result = db::operators::insert(
        &state.db,
        &payload.name,
        &payload.role,
        payload.cert_fingerprint.as_deref(),
        payload.gssapi_principal.as_deref(),
        &now,
    )
    .await;

    match result {
        Ok(()) => {
            state
                .record_audit(
                    AuditEvent::success(AuditEventType::AdminAction)
                        .with_principal(&operator.name)
                        .with_detail(
                            json!({"action": "operator.create", "name": payload.name}).to_string(),
                        ),
                )
                .await;
            (
                StatusCode::CREATED,
                Json(json!({"name": payload.name, "created_at": now})),
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

// ── Audit log query ───────────────────────────────────────────────────────────

/// `GET /admin/audit`
///
/// Query the audit event log with optional filters.
///
/// Query params: `type`, `subject`, `from`, `until`, `outcome`, `limit` (≤1000), `offset`.
/// Requires: `administrator` or `auditor`.
pub async fn get_audit(
    operator: OperatorContext,
    State(state): State<Arc<AppState>>,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> Response {
    require_role!(operator, state, Administrator | Auditor);

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

    let q = db::audit::AuditQuery {
        event_type: params.get("type").map(String::as_str),
        subject: params.get("subject").map(String::as_str),
        from: params.get("from").map(String::as_str),
        until: params.get("until").map(String::as_str),
        outcome: params.get("outcome").map(String::as_str),
        limit,
        offset,
    };

    match db::audit::query(&state.db, &q).await {
        Ok(rows) => {
            let events: Vec<_> = rows
                .into_iter()
                .map(|r| {
                    json!({
                        "id": r.id,
                        "occurred_at": r.occurred_at,
                        "event_type": r.event_type,
                        "subject": r.subject,
                        "principal": r.principal,
                        "outcome": r.outcome,
                        "detail": r.detail,
                    })
                })
                .collect();
            (
                StatusCode::OK,
                Json(json!({"events": events, "limit": limit, "offset": offset})),
            )
                .into_response()
        }
        Err(e) => {
            tracing::error!(error = %e, "get_audit: db error");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"status": 500, "detail": "database error"})),
            )
                .into_response()
        }
    }
}

// ── Certificate search ────────────────────────────────────────────────────────

/// `GET /admin/certs`
///
/// Search the certificate table.  Query params: `serial`, `account_id`,
/// `after` (RFC 3339), `before` (RFC 3339), `status` (active|revoked),
/// `limit` (≤1000), `offset`.
/// Requires: `administrator`, `ca_operations`, or `auditor`.
pub async fn get_certs(
    operator: OperatorContext,
    State(state): State<Arc<AppState>>,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> Response {
    require_role!(operator, state, Administrator | CaOperations | Auditor);

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

    let serial = params.get("serial").map(String::as_str);
    let account_id = params.get("account_id").map(String::as_str);
    let status = params.get("status").map(String::as_str);
    let subject_dn = params.get("subject").map(String::as_str);
    let ca_id = params.get("ca_id").map(String::as_str);

    let result = db::certs::search(
        &state.db, serial, account_id, status, subject_dn, ca_id, limit, offset,
    )
    .await;

    match result {
        Ok(rows) => {
            let certs: Vec<_> = rows
                .into_iter()
                .map(|r| {
                    json!({
                        "id": r.id,
                        "account_id": r.account_id,
                        "serial_number": r.serial_number,
                        "subject_dn": r.subject_dn,
                        "status": r.status,
                        "not_before": r.not_before,
                        "not_after": r.not_after,
                        "revoked_at": r.revoked_at,
                        "revocation_reason": r.revocation_reason,
                    })
                })
                .collect();
            (
                StatusCode::OK,
                Json(json!({"certs": certs, "limit": limit, "offset": offset})),
            )
                .into_response()
        }
        Err(e) => {
            tracing::error!(error = %e, "get_certs: db error");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"status": 500, "detail": "database error"})),
            )
                .into_response()
        }
    }
}

// ── Account profile grants ────────────────────────────────────────────────────

/// `GET /admin/account/{id}/profile-grants`
///
/// Returns `{"profile_grants":["p1","p2"]}` or `{"profile_grants":null}`.
/// Requires: any role.
pub async fn get_account_profile_grants(
    operator: OperatorContext,
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Response {
    require_role!(
        operator,
        state,
        Administrator | CaOperations | CaRa | Auditor
    );

    match db::accounts::get_profile_grants(&state.db, &id).await {
        Err(e) => {
            tracing::error!(error = %e, "get_account_profile_grants: db error");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"status": 500, "detail": "database error"})),
            )
                .into_response()
        }
        Ok(None) => (StatusCode::NOT_FOUND, "account not found").into_response(),
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
            (StatusCode::OK, Json(json!({"profile_grants": grants}))).into_response()
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
) -> Response {
    require_role!(operator, state, Administrator | CaOperations);

    let payload: ProfileGrantsPayload = match serde_json::from_slice(&body) {
        Ok(p) => p,
        Err(e) => return (StatusCode::BAD_REQUEST, format!("JSON: {e}")).into_response(),
    };

    let now = unix_now();
    let grants_str = match grants_to_json(payload.profile_grants) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(error = %e, "put_account_profile_grants: serialize grants");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"status": 500, "detail": "internal error"})),
            )
                .into_response();
        }
    };
    match db::accounts::set_profile_grants(&state.db, &id, grants_str.as_deref(), now).await {
        Err(e) => {
            tracing::error!(error = %e, "put_account_profile_grants: db error");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"status": 500, "detail": "database error"})),
            )
                .into_response()
        }
        Ok(false) => (StatusCode::NOT_FOUND, "account not found or deactivated").into_response(),
        Ok(true) => {
            state
                .record_audit(
                    AuditEvent::success(AuditEventType::AdminAction)
                        .with_principal(&operator.name)
                        .with_subject(&id)
                        .with_detail("{\"action\":\"account.grants.set\"}"),
                )
                .await;
            StatusCode::NO_CONTENT.into_response()
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
) -> Response {
    require_role!(operator, state, Administrator);

    let now = unix_now();
    match db::accounts::set_profile_grants(&state.db, &id, None, now).await {
        Err(e) => {
            tracing::error!(error = %e, "delete_account_profile_grants: db error");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"status": 500, "detail": "database error"})),
            )
                .into_response()
        }
        Ok(false) => (StatusCode::NOT_FOUND, "account not found or deactivated").into_response(),
        Ok(true) => {
            state
                .record_audit(
                    AuditEvent::success(AuditEventType::AdminAction)
                        .with_principal(&operator.name)
                        .with_subject(&id)
                        .with_detail("{\"action\":\"account.grants.clear\"}"),
                )
                .await;
            StatusCode::NO_CONTENT.into_response()
        }
    }
}

// ── EAB key management ────────────────────────────────────────────────────────

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

    match db::eab::list(&state.db, used_filter, limit, offset).await {
        Ok(rows) => {
            let keys: Vec<_> = rows
                .into_iter()
                .map(|r| {
                    json!({
                        "kid": r.kid,
                        "created": r.created,
                        "used_at": r.used_at,
                        "profile_grants": r.profile_grants,
                    })
                })
                .collect();
            (StatusCode::OK, Json(json!({"eab_keys": keys}))).into_response()
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
/// Requires: `administrator`, `ca_operations`, or `ca_ra`.
pub async fn post_eab(
    operator: OperatorContext,
    State(state): State<Arc<AppState>>,
    body: Bytes,
) -> Response {
    require_role!(operator, state, Administrator | CaOperations | CaRa);

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
            (
                StatusCode::CREATED,
                Json(json!({"kid": payload.kid, "created": now})),
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

// ── CRL + revoke ──────────────────────────────────────────────────────────────

/// `POST /admin/crl/force`
///
/// Force immediate CRL regeneration (invalidates the cached CRL).
/// Requires: `administrator` or `ca_operations`.
pub async fn post_crl_force(
    operator: OperatorContext,
    State(state): State<Arc<AppState>>,
) -> Response {
    require_role!(operator, state, Administrator | CaOperations);

    // Drop all CRL caches; the next GET /ca/crl (per CA) will regenerate each.
    for cache in state.crl_caches.values() {
        *cache.lock().unwrap_or_else(|e| e.into_inner()) = None;
    }

    state
        .record_audit(
            AuditEvent::success(AuditEventType::CrlGenerate)
                .with_principal(&operator.name)
                .with_detail("{\"action\":\"crl.force\"}"),
        )
        .await;
    StatusCode::NO_CONTENT.into_response()
}

/// `POST /admin/revoke`
///
/// Revoke a certificate by ID.
/// Requires: `administrator`, `ca_operations`, or `ca_ra`.
pub async fn post_revoke(
    operator: OperatorContext,
    State(state): State<Arc<AppState>>,
    body: Bytes,
) -> Response {
    require_role!(operator, state, Administrator | CaOperations | CaRa);

    let payload: RevokePayload = match serde_json::from_slice(&body) {
        Ok(p) => p,
        Err(e) => return (StatusCode::BAD_REQUEST, format!("JSON: {e}")).into_response(),
    };

    // RFC 5280 §5.3.1: valid reason codes are 0–10, excluding 7 (unused).
    if payload.reason == 7 || payload.reason > 10 {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "status": 400,
                "detail": "revocation reason must be 0–10 excluding 7 (RFC 5280 §5.3.1)",
            })),
        )
            .into_response();
    }

    let now = unix_now();
    match db::certs::revoke(
        &state.db,
        &payload.cert_id,
        Some(payload.reason as i64),
        now,
    )
    .await
    {
        Ok(true) => {
            // Look up the cert's CA and invalidate only that CA's CRL cache.
            if let Ok(Some(cert)) = db::certs::get_by_id(&state.db, &payload.cert_id).await {
                state.invalidate_crl_cache(&cert.ca_id);
            } else {
                // Cert row missing (shouldn't happen after a successful revoke) —
                // fall back to invalidating all caches.
                for cache in state.crl_caches.values() {
                    *cache.lock().unwrap_or_else(|e| e.into_inner()) = None;
                }
            }
            state
                .record_audit(
                    AuditEvent::success(AuditEventType::CertRevoke)
                        .with_principal(&operator.name)
                        .with_subject(&payload.cert_id)
                        .with_detail(
                            json!({"action": "admin.revoke", "reason": payload.reason}).to_string(),
                        ),
                )
                .await;
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(false) => (
            StatusCode::NOT_FOUND,
            "certificate not found or already revoked",
        )
            .into_response(),
        Err(e) => {
            tracing::error!(error = %e, "post_revoke: db error");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"status": 500, "detail": "database error"})),
            )
                .into_response()
        }
    }
}

// ── Profiles ─────────────────────────────────────────────────────────────

/// `GET /admin/profiles`
///
/// List all loaded certificate profiles with their parameters.
/// Requires: any role.
pub async fn get_profiles(
    operator: OperatorContext,
    State(state): State<Arc<AppState>>,
) -> Response {
    require_role!(
        operator,
        state,
        Administrator | CaOperations | CaRa | Auditor
    );

    let profiles = state.profiles.all_profiles();
    let mut list: Vec<serde_json::Value> = profiles
        .iter()
        .map(|(id, description)| {
            let mut entry = json!({
                "id": id,
                "description": description,
            });
            if let Some(params) = state.profiles.resolve(id) {
                entry["validity_days"] = json!(params.validity_days);
                entry["hash_alg"] = json!(params.hash_alg);
                entry["extended_key_usages"] = json!(params.extended_key_usages);
                entry["issue_as_mtc"] = json!(params.issue_as_mtc);
            }
            entry
        })
        .collect();
    list.sort_by(|a, b| a["id"].as_str().cmp(&b["id"].as_str()));

    (StatusCode::OK, Json(json!({"profiles": list}))).into_response()
}

/// JSON payload for `POST /admin/profiles` and `PUT /admin/profiles/{id}`.
#[derive(Deserialize)]
struct ProfilePayload {
    #[serde(default)]
    description: String,
    #[serde(default = "default_profile_validity_days")]
    validity_days: u32,
    #[serde(default = "default_profile_hash_alg")]
    hash_alg: String,
    #[serde(default)]
    key_usage_bits: u16,
    #[serde(default)]
    extended_key_usages: Vec<String>,
    #[serde(default)]
    crl_url: Option<String>,
    #[serde(default)]
    ocsp_url: Option<String>,
    #[serde(default)]
    allowed_key_types: Vec<String>,
    #[serde(default)]
    certificate_policies: Vec<(String, Option<String>)>,
    #[serde(default)]
    issue_as_mtc: bool,
    #[serde(default)]
    allowed_identifier_patterns: Vec<String>,
    #[serde(default = "default_true")]
    identifier_match_all: bool,
    #[serde(default)]
    auth_hook: Option<String>,
    #[serde(default = "default_auth_hook_timeout")]
    auth_hook_timeout_secs: u64,
    #[serde(default)]
    require_account_grant: bool,
    #[serde(default)]
    ca_ids: Vec<String>,
}

fn default_profile_validity_days() -> u32 {
    90
}
fn default_profile_hash_alg() -> String {
    "sha256".to_string()
}
fn default_true() -> bool {
    true
}
fn default_auth_hook_timeout() -> u64 {
    30
}

impl ProfilePayload {
    fn into_params(self) -> crate::profiles::CertificateParameters {
        crate::profiles::CertificateParameters {
            validity_days: self.validity_days,
            hash_alg: self.hash_alg,
            key_usage_bits: self.key_usage_bits,
            extended_key_usages: self.extended_key_usages,
            crl_url: self.crl_url,
            ocsp_url: self.ocsp_url,
            allowed_key_types: self.allowed_key_types,
            certificate_policies: self.certificate_policies,
            issue_as_mtc: self.issue_as_mtc,
            allowed_identifier_patterns: self.allowed_identifier_patterns,
            identifier_match_all: self.identifier_match_all,
            auth_hook: self.auth_hook,
            auth_hook_timeout_secs: self.auth_hook_timeout_secs,
            require_account_grant: self.require_account_grant,
            ca_ids: self.ca_ids,
        }
    }
}

/// JSON payload for `POST /admin/profiles` (creation includes the profile ID).
#[derive(Deserialize)]
struct ProfileCreatePayload {
    id: String,
    #[serde(flatten)]
    inner: ProfilePayload,
}

/// `POST /admin/profiles`
///
/// Add a new certificate profile to the runtime cache (FPT_NPE_EXT.1).
/// Requires: `administrator`.
pub async fn post_profiles(
    operator: OperatorContext,
    State(state): State<Arc<AppState>>,
    body: Bytes,
) -> Response {
    require_role!(operator, state, Administrator);

    let payload: ProfileCreatePayload = match serde_json::from_slice(&body) {
        Ok(p) => p,
        Err(e) => return (StatusCode::BAD_REQUEST, format!("JSON: {e}")).into_response(),
    };

    if payload.id.is_empty() {
        return (StatusCode::BAD_REQUEST, "id is required").into_response();
    }

    let id = payload.id.clone();
    let desc = payload.inner.description.clone();
    if state
        .profiles
        .add_profile(id.clone(), desc.clone(), payload.inner.into_params())
    {
        state
            .record_audit(
                AuditEvent::success(AuditEventType::AdminAction)
                    .with_principal(&operator.name)
                    .with_detail(json!({"action": "profile.create", "id": id}).to_string()),
            )
            .await;
        (
            StatusCode::CREATED,
            Json(json!({"id": id, "description": desc})),
        )
            .into_response()
    } else {
        (
            StatusCode::CONFLICT,
            Json(json!({"status": 409, "detail": "profile already exists"})),
        )
            .into_response()
    }
}

/// `PUT /admin/profiles/{id}`
///
/// Replace an existing certificate profile in the runtime cache (FPT_NPE_EXT.1).
/// Requires: `administrator`.
pub async fn put_profile(
    operator: OperatorContext,
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    body: Bytes,
) -> Response {
    require_role!(operator, state, Administrator);

    let payload: ProfilePayload = match serde_json::from_slice(&body) {
        Ok(p) => p,
        Err(e) => return (StatusCode::BAD_REQUEST, format!("JSON: {e}")).into_response(),
    };

    let desc = payload.description.clone();
    if state
        .profiles
        .update_profile(&id, desc, payload.into_params())
    {
        state
            .record_audit(
                AuditEvent::success(AuditEventType::AdminAction)
                    .with_principal(&operator.name)
                    .with_detail(json!({"action": "profile.update", "id": id}).to_string()),
            )
            .await;
        StatusCode::NO_CONTENT.into_response()
    } else {
        (
            StatusCode::NOT_FOUND,
            Json(json!({"status": 404, "detail": "profile not found"})),
        )
            .into_response()
    }
}

/// `DELETE /admin/profiles/{id}`
///
/// Remove a certificate profile from the runtime cache (FPT_NPE_EXT.1).
/// Requires: `administrator`.
pub async fn delete_profile(
    operator: OperatorContext,
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Response {
    require_role!(operator, state, Administrator);

    if state.profiles.remove_profile(&id) {
        state
            .record_audit(
                AuditEvent::success(AuditEventType::AdminAction)
                    .with_principal(&operator.name)
                    .with_detail(json!({"action": "profile.delete", "id": id}).to_string()),
            )
            .await;
        StatusCode::NO_CONTENT.into_response()
    } else {
        (
            StatusCode::NOT_FOUND,
            Json(json!({"status": 404, "detail": "profile not found"})),
        )
            .into_response()
    }
}

// ── Accounts ─────────────────────────────────────────────────────────────

/// `GET /admin/accounts`
///
/// List accounts with optional status filter and pagination.
/// Requires: any role.
pub async fn get_accounts(
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
    let status = params.get("status").map(String::as_str);
    let ca_id = params.get("ca_id").map(String::as_str);

    match db::accounts::list(&state.db, status, ca_id, limit, offset).await {
        Ok(rows) => {
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
            (
                StatusCode::OK,
                Json(json!({"accounts": accounts, "limit": limit, "offset": offset})),
            )
                .into_response()
        }
        Err(e) => {
            tracing::error!(error = %e, "get_accounts: db error");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"status": 500, "detail": "database error"})),
            )
                .into_response()
        }
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
) -> Response {
    require_role!(
        operator,
        state,
        Administrator | CaOperations | CaRa | Auditor
    );

    match db::accounts::get_by_id(&state.db, &id).await {
        Ok(Some(r)) => (
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
            .into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json!({"status": 404, "detail": "account not found"})),
        )
            .into_response(),
        Err(e) => {
            tracing::error!(error = %e, "get_account: db error");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"status": 500, "detail": "database error"})),
            )
                .into_response()
        }
    }
}

// ── Certificate detail + download ────────────────────────────────────────

/// `GET /admin/certs/{id}`
///
/// Show a single certificate's metadata (no PEM/DER blobs).
/// Requires: `administrator`, `ca_operations`, or `auditor`.
pub async fn get_cert(
    operator: OperatorContext,
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Response {
    require_role!(operator, state, Administrator | CaOperations | Auditor);

    match db::certs::get_by_id(&state.db, &id).await {
        Ok(Some(r)) => (
            StatusCode::OK,
            Json(json!({
                "id": r.id,
                "order_id": r.order_id,
                "account_id": r.account_id,
                "serial_number": r.serial_number,
                "status": r.status,
                "not_before": r.not_before,
                "not_after": r.not_after,
                "revoked_at": r.revoked_at,
                "revocation_reason": r.revocation_reason,
                "mtc_log_index": r.mtc_log_index,
                "created": r.created,
                "suggested_window_start": r.suggested_window_start,
                "suggested_window_end": r.suggested_window_end,
                "replaced_by": r.replaced_by,
            })),
        )
            .into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json!({"status": 404, "detail": "certificate not found"})),
        )
            .into_response(),
        Err(e) => {
            tracing::error!(error = %e, "get_cert: db error");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"status": 500, "detail": "database error"})),
            )
                .into_response()
        }
    }
}

/// `GET /admin/certs/{id}/download`
///
/// Download a certificate as PEM (default) or DER.
/// Query params: `format=pem` (default) or `format=der`.
/// Requires: `administrator` or `ca_operations`.
pub async fn get_cert_download(
    operator: OperatorContext,
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> Response {
    require_role!(operator, state, Administrator | CaOperations);

    let format = params.get("format").map(String::as_str).unwrap_or("pem");

    match db::certs::get_by_id(&state.db, &id).await {
        Ok(Some(r)) => match format {
            "der" => (
                StatusCode::OK,
                [("content-type", "application/pkix-cert")],
                r.der,
            )
                .into_response(),
            _ => (
                StatusCode::OK,
                [("content-type", "application/pem-certificate-chain")],
                r.pem,
            )
                .into_response(),
        },
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json!({"status": 404, "detail": "certificate not found"})),
        )
            .into_response(),
        Err(e) => {
            tracing::error!(error = %e, "get_cert_download: db error");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"status": 500, "detail": "database error"})),
            )
                .into_response()
        }
    }
}

// ── Operator detail ─────────────────────────────────────────────────────

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
    }

    let payload: PutOperatorPayload = match serde_json::from_slice(&body) {
        Ok(p) => p,
        Err(e) => return (StatusCode::BAD_REQUEST, format!("JSON: {e}")).into_response(),
    };

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

    let now = crate::util::rfc3339_now();
    match db::operators::update(
        &state.db,
        id,
        payload.name.as_deref(),
        payload.role.as_deref(),
        payload.cert_fingerprint.as_deref(),
        payload.gssapi_principal.as_deref(),
        &now,
    )
    .await
    {
        Ok(true) => {
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

// ── Orders ──────────────────────────────────────────────────────────────

/// `GET /admin/orders`
///
/// List orders with optional filters and pagination.
/// Requires: any role.
pub async fn get_orders(
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
    let status = params.get("status").map(String::as_str);
    let ca_id = params.get("ca_id").map(String::as_str);

    match db::orders::list(&state.db, account_id, status, ca_id, limit, offset).await {
        Ok(rows) => {
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
            (
                StatusCode::OK,
                Json(json!({"orders": orders, "limit": limit, "offset": offset})),
            )
                .into_response()
        }
        Err(e) => {
            tracing::error!(error = %e, "get_orders: db error");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"status": 500, "detail": "database error"})),
            )
                .into_response()
        }
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
) -> Response {
    require_role!(
        operator,
        state,
        Administrator | CaOperations | CaRa | Auditor
    );

    match db::orders::get_with_authz_ids(&state.db, &id).await {
        Ok(Some((r, authz_ids))) => (
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
            .into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json!({"status": 404, "detail": "order not found"})),
        )
            .into_response(),
        Err(e) => {
            tracing::error!(error = %e, "get_order: db error");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"status": 500, "detail": "database error"})),
            )
                .into_response()
        }
    }
}

// ── Account deactivation ────────────────────────────────────────────────

/// `POST /admin/account/{id}/deactivate`
///
/// Admin-initiated account deactivation.
/// Requires: `administrator`.
pub async fn post_account_deactivate(
    operator: OperatorContext,
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Response {
    require_role!(operator, state, Administrator);

    let now = unix_now();
    match db::accounts::update_status(&state.db, &id, "deactivated", now).await {
        Ok(true) => {
            state
                .record_audit(
                    AuditEvent::success(AuditEventType::AdminAction)
                        .with_principal(&operator.name)
                        .with_subject(&id)
                        .with_detail("{\"action\":\"account.deactivate\"}"),
                )
                .await;
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(false) => (StatusCode::NOT_FOUND, "account not found").into_response(),
        Err(e) => {
            tracing::error!(error = %e, "post_account_deactivate: db error");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"status": 500, "detail": "database error"})),
            )
                .into_response()
        }
    }
}

// ── EAB key detail ──────────────────────────────────────────────────────

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

// ── Server config ────────────────────────────────────────────────────────

/// `GET /admin/config`
///
/// Show redacted server configuration.
/// Requires: `administrator`.
pub async fn get_config(operator: OperatorContext, State(state): State<Arc<AppState>>) -> Response {
    require_role!(operator, state, Administrator);

    let cfg = &state.config;
    let cas: Vec<_> = state
        .cas
        .values()
        .map(|ca| {
            json!({
                "id": ca.id,
                "is_default": ca.id == state.default_ca_id.as_str(),
                "crl_url": ca.crl_url,
                "ocsp_url": ca.ocsp_url,
            })
        })
        .collect();
    (
        StatusCode::OK,
        Json(json!({
            "base_url": cfg.base_url,
            "db_url": "***",
            "mtc_enabled": state.mtc.is_enabled(),
            "caa_identities": cfg.server.caa_identities,
            "validate_dnssec": cfg.server.validate_dnssec,
            "cas": cas,
        })),
    )
        .into_response()
}

// ── CA management ─────────────────────────────────────────────────────────────

/// `GET /admin/cas`
///
/// List all configured CAs.
/// Requires: `administrator`.
pub async fn get_cas(operator: OperatorContext, State(state): State<Arc<AppState>>) -> Response {
    require_role!(operator, state, Administrator | CaOperations);

    let cas: Vec<_> = state
        .cas
        .values()
        .map(|ca| {
            let cfg = state
                .config
                .cas
                .iter()
                .find(|c| c.id == ca.id);
            json!({
                "id": ca.id,
                "is_default": ca.id == state.default_ca_id.as_str(),
                "key_type": cfg.map(|c| c.key_type.as_str()).unwrap_or("unknown"),
                "hash_alg": ca.hash_alg,
                "crl_url": ca.crl_url,
                "ocsp_url": ca.ocsp_url,
            })
        })
        .collect();

    (StatusCode::OK, Json(json!({ "cas": cas }))).into_response()
}

/// `GET /admin/cas/{id}`
///
/// Show details for a single CA, including the CA certificate PEM.
/// Requires: `administrator` or `ca_operations`.
pub async fn get_ca(
    operator: OperatorContext,
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Response {
    require_role!(operator, state, Administrator | CaOperations);

    let Some(ca) = state.get_ca(&id) else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({"status": 404, "detail": "CA not found"})),
        )
            .into_response();
    };

    let cfg = state.config.cas.iter().find(|c| c.id == ca.id);
    let cert_pem =
        String::from_utf8(der_to_pem("CERTIFICATE", &ca.cert_der))
            .unwrap_or_default();

    (
        StatusCode::OK,
        Json(json!({
            "id": ca.id,
            "is_default": ca.id == state.default_ca_id.as_str(),
            "key_type": cfg.map(|c| c.key_type.as_str()).unwrap_or("unknown"),
            "hash_alg": ca.hash_alg,
            "validity_days": ca.validity_days,
            "crl_url": ca.crl_url,
            "ocsp_url": ca.ocsp_url,
            "caa_identities": ca.caa_identities,
            "cert_pem": cert_pem,
        })),
    )
        .into_response()
}

/// `GET /admin/cas/{id}/cert`
///
/// Download the CA certificate as PEM text.
/// Requires: `administrator` or `ca_operations`.
pub async fn get_ca_cert(
    operator: OperatorContext,
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Response {
    require_role!(operator, state, Administrator | CaOperations);

    let Some(ca) = state.get_ca(&id) else {
        return (StatusCode::NOT_FOUND, "CA not found").into_response();
    };

    let cert_pem =
        String::from_utf8(der_to_pem("CERTIFICATE", &ca.cert_der))
            .unwrap_or_default();

    (
        StatusCode::OK,
        [("content-type", "application/x-pem-file")],
        cert_pem,
    )
        .into_response()
}

/// `POST /admin/ca/{id}/crl/force`
///
/// Invalidate the CRL cache for a single CA, causing the next CRL request to
/// regenerate it.  Use `/admin/crl/force` to invalidate all CA caches at once.
/// Requires: `administrator` or `ca_operations`.
pub async fn post_ca_crl_force(
    operator: OperatorContext,
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Response {
    require_role!(operator, state, Administrator | CaOperations);

    if state.get_ca(&id).is_none() {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({"status": 404, "detail": "CA not found"})),
        )
            .into_response();
    }

    state.invalidate_crl_cache(&id);

    state
        .record_audit(
            AuditEvent::success(AuditEventType::CrlGenerate)
                .with_principal(&operator.name)
                .with_detail(serde_json::json!({"action": "crl.force", "ca_id": id}).to_string()),
        )
        .await;

    StatusCode::NO_CONTENT.into_response()
}

// ── Cross-signing ─────────────────────────────────────────────────────────────

/// Request body for `POST /admin/ca/{id}/cross-sign`.
///
/// Exactly one of `subject_ca_id` or `subject_cert_pem` must be supplied.
#[derive(Deserialize)]
pub(super) struct CrossSignPayload {
    /// Same-server CA whose certificate will become the cross-cert subject.
    subject_ca_id: Option<String>,
    /// PEM-encoded certificate of an external CA to cross-sign.
    subject_cert_pem: Option<String>,
    /// Validity of the cross-certificate in years (default: 5).
    #[serde(default = "default_cross_sign_validity")]
    validity_years: u32,
}

fn default_cross_sign_validity() -> u32 {
    5
}

/// `POST /admin/ca/{id}/cross-sign`
///
/// Issue a cross-certificate: the CA identified by `{id}` signs a CA
/// certificate for the subject specified in the request body.
/// Requires: administrator or ca_operations.
pub async fn post_ca_cross_sign(
    operator: OperatorContext,
    State(state): State<Arc<AppState>>,
    Path(issuer_id): Path<String>,
    Json(payload): Json<CrossSignPayload>,
) -> Response {
    require_role!(operator, state, Administrator | CaOperations);

    // Resolve the issuer CA.
    let issuer_ca = match state.get_ca(&issuer_id) {
        Some(ca) => ca.clone(),
        None => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"status": 404, "detail": "issuer CA not found"})),
            )
                .into_response();
        }
    };

    // Resolve the subject cert DER from either field.
    let subject_cert_der = match (&payload.subject_ca_id, &payload.subject_cert_pem) {
        (Some(subj_id), None) => {
            match state.get_ca(subj_id) {
                Some(ca) => ca.cert_der.clone(),
                None => {
                    return (
                        StatusCode::NOT_FOUND,
                        Json(json!({"status": 404, "detail": "subject CA not found"})),
                    )
                        .into_response();
                }
            }
        }
        (None, Some(pem)) => {
            let ders = synta_certificate::pem_to_der(pem.as_bytes());
            match ders.into_iter().next() {
                Some(d) => d,
                None => {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(json!({"status": 400, "detail": "subject_cert_pem contains no valid PEM block"})),
                    )
                        .into_response();
                }
            }
        }
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"status": 400, "detail": "exactly one of subject_ca_id or subject_cert_pem must be provided"})),
            )
                .into_response();
        }
    };

    let issued = match crate::ca::issue::issue_ca_cert(
        &issuer_ca,
        &subject_cert_der,
        payload.validity_years,
    ) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error = %e, "cross-sign issuance failed");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    let id = uuid::Uuid::new_v4().to_string();
    let now = unix_now();
    let row = crate::db::schema::CrossCertRow {
        id: id.clone(),
        issuer_ca_id: issuer_id.clone(),
        subject_ca_id: payload.subject_ca_id.clone(),
        subject_dn: issued.subject_dn.clone(),
        subject_spki: issued.subject_spki_der,
        cross_cert_der: issued.cert_der,
        cross_cert_pem: issued.cert_pem.clone(),
        not_before: issued.not_before,
        not_after: issued.not_after,
        serial_number: issued.serial_hex.clone(),
        created: now,
    };

    if let Err(e) = db::cross_certs::insert(&state.db, &row).await {
        tracing::error!(error = %e, "failed to store cross-cert");
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }

    state
        .record_audit(
            AuditEvent::success(AuditEventType::CrossSignIssue)
                .with_principal(&operator.name)
                .with_subject(&id)
                .with_detail(
                    serde_json::json!({
                        "issuer_ca_id": issuer_id,
                        "subject_ca_id": payload.subject_ca_id,
                        "serial": issued.serial_hex,
                        "validity_years": payload.validity_years,
                    })
                    .to_string(),
                ),
        )
        .await;

    (
        StatusCode::CREATED,
        Json(json!({
            "id": id,
            "issuer_ca_id": issuer_id,
            "subject_ca_id": payload.subject_ca_id,
            "subject_dn": issued.subject_dn,
            "serial_number": issued.serial_hex,
            "not_before": issued.not_before,
            "not_after": issued.not_after,
            "cross_cert_pem": row.cross_cert_pem,
            "created": now,
        })),
    )
        .into_response()
}

/// `GET /admin/cross-certs`
///
/// List cross-certificates.  Optional query parameters:
/// - `issuer_ca_id` — filter by issuing CA
/// - `subject_ca_id` — filter by subject CA
/// - `limit` (default 100), `offset` (default 0)
///
/// Requires: administrator, ca_operations, or auditor.
pub async fn get_cross_certs(
    operator: OperatorContext,
    State(state): State<Arc<AppState>>,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> Response {
    require_role!(operator, state, Administrator | CaOperations | Auditor);

    let issuer_ca_id = params.get("issuer_ca_id").map(String::as_str);
    let subject_ca_id = params.get("subject_ca_id").map(String::as_str);
    let limit: i64 = params
        .get("limit")
        .and_then(|v| v.parse().ok())
        .unwrap_or(100)
        .min(1000);
    let offset: i64 = params
        .get("offset")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);

    let rows = match db::cross_certs::list(&state.db, issuer_ca_id, subject_ca_id, limit, offset)
        .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(error = %e, "get_cross_certs DB query failed");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    let items: Vec<_> = rows
        .into_iter()
        .map(|r| {
            json!({
                "id": r.id,
                "issuer_ca_id": r.issuer_ca_id,
                "subject_ca_id": r.subject_ca_id,
                "subject_dn": r.subject_dn,
                "serial_number": r.serial_number,
                "not_before": r.not_before,
                "not_after": r.not_after,
                "created": r.created,
            })
        })
        .collect();

    (StatusCode::OK, Json(json!({ "cross_certs": items }))).into_response()
}

/// `GET /admin/cross-certs/{id}`
///
/// Retrieve a single cross-certificate by ID, including its PEM.
/// Requires: administrator, ca_operations, or auditor.
pub async fn get_cross_cert(
    operator: OperatorContext,
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Response {
    require_role!(operator, state, Administrator | CaOperations | Auditor);

    let row = match db::cross_certs::get_by_id(&state.db, &id).await {
        Ok(Some(r)) => r,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"status": 404, "detail": "cross-cert not found"})),
            )
                .into_response();
        }
        Err(e) => {
            tracing::error!(error = %e, "get_cross_cert DB query failed");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    (
        StatusCode::OK,
        Json(json!({
            "id": row.id,
            "issuer_ca_id": row.issuer_ca_id,
            "subject_ca_id": row.subject_ca_id,
            "subject_dn": row.subject_dn,
            "serial_number": row.serial_number,
            "not_before": row.not_before,
            "not_after": row.not_after,
            "cross_cert_pem": row.cross_cert_pem,
            "created": row.created,
        })),
    )
        .into_response()
}

// ── Statistics ────────────────────────────────────────────────────────────────

/// `GET /admin/stats`
///
/// Returns live server statistics.  Requires: any role.
pub async fn get_stats(operator: OperatorContext, State(state): State<Arc<AppState>>) -> Response {
    require_role!(
        operator,
        state,
        Administrator | CaOperations | CaRa | Auditor
    );

    let uptime_secs = state.startup_time.elapsed().as_secs();

    let counts = match db::stats::summary(&state.db).await {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error = %e, "stats DB query failed");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    let server_version = env!("CARGO_PKG_VERSION");

    (
        StatusCode::OK,
        Json(json!({
            "server_version": server_version,
            "uptime_secs": uptime_secs,
            "accounts": {
                "total": counts.account_total,
                "active": counts.account_active,
            },
            "certs": {
                "total": counts.cert_total,
                "active": counts.cert_active,
                "revoked": counts.cert_revoked,
            },
            "eab_keys": {
                "total": counts.eab_total,
                "used": counts.eab_used,
                "unused": counts.eab_total - counts.eab_used,
            },
            "audit_events": {
                "total": counts.audit_total,
            },
        })),
    )
        .into_response()
}
