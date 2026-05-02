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
//! | `PATCH /admin/operators/{id}` | ✓ | | | |
//! | `GET /admin/audit` | ✓ | | | ✓ |
//! | `GET /admin/certs` | ✓ | ✓ | | ✓ |
//! | `GET /admin/account/{id}/profile-grants` | ✓ | ✓ | ✓ | ✓ |
//! | `PUT /admin/account/{id}/profile-grants` | ✓ | ✓ | | |
//! | `DELETE /admin/account/{id}/profile-grants` | ✓ | | | |
//! | `POST /admin/eab` | ✓ | ✓ | ✓ | |
//! | `DELETE /admin/eab/{kid}` | ✓ | ✓ | | |
//! | `GET /admin/eab` | ✓ | ✓ | ✓ | ✓ |
//! | `POST /admin/crl/force` | ✓ | ✓ | | |
//! | `POST /admin/revoke` | ✓ | ✓ | ✓ | |
//! | `GET /admin/stats` | ✓ | ✓ | ✓ | ✓ |

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

use super::unix_now;

// ── Shared guard ──────────────────────────────────────────────────────────────

/// Return 404 early when `[admin]` is absent.  All admin handlers call this
/// before accessing the operator context.
fn admin_configured(state: &AppState) -> Result<(), Response> {
    if state.config.admin.is_none() {
        return Err((StatusCode::NOT_FOUND, "admin API is not configured").into_response());
    }
    Ok(())
}

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

fn grants_to_json(grants: Option<Vec<String>>) -> Option<String> {
    match grants {
        None => None,
        Some(ref vec) if vec.is_empty() => None,
        Some(ref vec) => serde_json::to_string(vec).ok(),
    }
}

fn now_rfc3339() -> String {
    let unix = unix_now();
    let gt = synta::GeneralizedTime::from_unix(unix)
        .unwrap_or_else(|| synta::GeneralizedTime::from_unix(0).unwrap());
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        gt.year, gt.month, gt.day, gt.hour, gt.minute, gt.second
    )
}

// ── Operator management ───────────────────────────────────────────────────────

/// `GET /admin/operators`
///
/// List all operators (active and inactive).
/// Requires: `administrator`.
pub async fn get_operators(
    operator: OperatorContext,
    State(state): State<Arc<AppState>>,
) -> Response {
    if let Err(r) = admin_configured(&state) {
        return r;
    }
    require_role!(operator, Administrator);

    match db::operators::list(&state.db).await {
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
                    })
                })
                .collect();
            (StatusCode::OK, Json(json!({"operators": list}))).into_response()
        }
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
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
    if let Err(r) = admin_configured(&state) {
        return r;
    }
    require_role!(operator, Administrator);

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

    let now = now_rfc3339();
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
            crate::audit::record_or_log(
                &state.db,
                &state.audit,
                &state.audit_policy,
                AuditEvent::success(AuditEventType::AdminAction)
                    .with_principal(&operator.name)
                    .with_detail(&format!(
                        "{{\"action\":\"operator.create\",\"name\":\"{}\"}}",
                        payload.name
                    )),
            )
            .await;
            (StatusCode::CREATED, Json(json!({"name": payload.name, "created_at": now}))).into_response()
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
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
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
    if let Err(r) = admin_configured(&state) {
        return r;
    }
    require_role!(operator, Administrator);

    let payload: PatchOperatorPayload = match serde_json::from_slice(&body) {
        Ok(p) => p,
        Err(e) => return (StatusCode::BAD_REQUEST, format!("JSON: {e}")).into_response(),
    };

    let now = now_rfc3339();
    match db::operators::set_active(&state.db, id, payload.active, &now).await {
        Ok(0) => (StatusCode::NOT_FOUND, Json(json!({"status": 404, "detail": "operator not found"}))).into_response(),
        Ok(_) => {
            let action = if payload.active {
                "operator.activate"
            } else {
                "operator.deactivate"
            };
            // Revoked operators must not retain live session tokens.
            if !payload.active {
                if let Some(sessions) = &state.admin_sessions {
                    sessions
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .retain(|_, s| s.operator_id != id);
                }
            }
            crate::audit::record_or_log(
                &state.db,
                &state.audit,
                &state.audit_policy,
                AuditEvent::success(AuditEventType::AdminAction)
                    .with_principal(&operator.name)
                    .with_detail(&format!(
                        "{{\"action\":\"{action}\",\"operator_id\":{id}}}"
                    )),
            )
            .await;
            StatusCode::NO_CONTENT.into_response()
        }
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
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
    if let Err(r) = admin_configured(&state) {
        return r;
    }
    require_role!(operator, Administrator | Auditor);

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
            (StatusCode::OK, Json(json!({"events": events, "limit": limit, "offset": offset})))
                .into_response()
        }
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
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
    if let Err(r) = admin_configured(&state) {
        return r;
    }
    require_role!(operator, Administrator | CaOperations | Auditor);

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

    // Build a simple query using the IS NULL OR col = ? pattern for optional params.
    let serial = params.get("serial").map(String::as_str);
    let account_id = params.get("account_id").map(String::as_str);
    let status = params.get("status").map(String::as_str);

    let result = sqlx::query_as::<_, crate::db::schema::CertificateRow>(
        "SELECT id, order_id, account_id, serial_number, status, der, pem, \
                not_before, not_after, revoked_at, revocation_reason, mtc_log_index, created, \
                suggested_window_start, suggested_window_end, replaced_by \
         FROM certificates \
         WHERE (? IS NULL OR serial_number = ?) \
           AND (? IS NULL OR account_id = ?) \
           AND (? IS NULL OR status = ?) \
         ORDER BY created DESC \
         LIMIT ? OFFSET ?",
    )
    .bind(serial)
    .bind(serial)
    .bind(account_id)
    .bind(account_id)
    .bind(status)
    .bind(status)
    .bind(limit)
    .bind(offset)
    .fetch_all(&state.db)
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
                        "status": r.status,
                        "not_before": r.not_before,
                        "not_after": r.not_after,
                        "revoked_at": r.revoked_at,
                        "revocation_reason": r.revocation_reason,
                    })
                })
                .collect();
            (StatusCode::OK, Json(json!({"certs": certs, "limit": limit, "offset": offset})))
                .into_response()
        }
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
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
    if let Err(r) = admin_configured(&state) {
        return r;
    }
    let _ = operator; // any role allowed

    match db::accounts::get_profile_grants(&state.db, &id).await {
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        Ok(None) => (StatusCode::NOT_FOUND, "account not found").into_response(),
        Ok(Some(grants_json)) => {
            let grants: Option<Vec<String>> = grants_json
                .as_deref()
                .and_then(|j| serde_json::from_str(j).ok());
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
    if let Err(r) = admin_configured(&state) {
        return r;
    }
    require_role!(operator, Administrator | CaOperations);

    let payload: ProfileGrantsPayload = match serde_json::from_slice(&body) {
        Ok(p) => p,
        Err(e) => return (StatusCode::BAD_REQUEST, format!("JSON: {e}")).into_response(),
    };

    let now = unix_now();
    let grants_str = grants_to_json(payload.profile_grants);
    match db::accounts::set_profile_grants(&state.db, &id, grants_str.as_deref(), now).await {
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        Ok(false) => (StatusCode::NOT_FOUND, "account not found or deactivated").into_response(),
        Ok(true) => {
            crate::audit::record_or_log(
                &state.db,
                &state.audit,
                &state.audit_policy,
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
    if let Err(r) = admin_configured(&state) {
        return r;
    }
    require_role!(operator, Administrator);

    let now = unix_now();
    match db::accounts::set_profile_grants(&state.db, &id, None, now).await {
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        Ok(false) => (StatusCode::NOT_FOUND, "account not found or deactivated").into_response(),
        Ok(true) => {
            crate::audit::record_or_log(
                &state.db,
                &state.audit,
                &state.audit_policy,
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
    if let Err(r) = admin_configured(&state) {
        return r;
    }
    let _ = operator; // any role

    let used_filter = params.get("used").and_then(|v| match v.as_str() {
        "true" => Some(true),
        "false" => Some(false),
        _ => None,
    });
    let limit: i64 = params
        .get("limit")
        .and_then(|v| v.parse().ok())
        .unwrap_or(200);
    let offset: i64 = params
        .get("offset")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);

    let mut sql = "SELECT kid, hmac_key_b64u, created, used_at, profile_grants \
                   FROM eab_keys"
        .to_string();
    match used_filter {
        Some(true) => sql.push_str(" WHERE used_at IS NOT NULL"),
        Some(false) => sql.push_str(" WHERE used_at IS NULL"),
        None => {}
    }
    sql.push_str(" ORDER BY created DESC LIMIT ? OFFSET ?");

    let rows = sqlx::query_as::<_, db::eab::EabKeyRow>(&sql)
        .bind(limit)
        .bind(offset)
        .fetch_all(&state.db)
        .await;

    match rows {
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
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
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
    if let Err(r) = admin_configured(&state) {
        return r;
    }
    require_role!(operator, Administrator | CaOperations | CaRa);

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
    let grants_str = grants_to_json(payload.profile_grants);
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
            crate::audit::record_or_log(
                &state.db,
                &state.audit,
                &state.audit_policy,
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
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
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
    if let Err(r) = admin_configured(&state) {
        return r;
    }
    require_role!(operator, Administrator | CaOperations);

    match db::eab::delete(&state.db, &kid).await {
        Ok(0) => (StatusCode::NOT_FOUND, Json(json!({"status": 404, "detail": "EAB key not found"}))).into_response(),
        Ok(_) => {
            crate::audit::record_or_log(
                &state.db,
                &state.audit,
                &state.audit_policy,
                AuditEvent::success(AuditEventType::AdminAction)
                    .with_principal(&operator.name)
                    .with_subject(&kid)
                    .with_detail("{\"action\":\"eab.delete\"}"),
            )
            .await;
            StatusCode::NO_CONTENT.into_response()
        }
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
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
    if let Err(r) = admin_configured(&state) {
        return r;
    }
    require_role!(operator, Administrator | CaOperations);

    // Drop the cached CRL; the next GET /ca/crl will regenerate it.
    *state.crl_cache.lock().unwrap_or_else(|e| e.into_inner()) = None;

    crate::audit::record_or_log(
        &state.db,
        &state.audit,
        &state.audit_policy,
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
    if let Err(r) = admin_configured(&state) {
        return r;
    }
    require_role!(operator, Administrator | CaOperations | CaRa);

    let payload: RevokePayload = match serde_json::from_slice(&body) {
        Ok(p) => p,
        Err(e) => return (StatusCode::BAD_REQUEST, format!("JSON: {e}")).into_response(),
    };

    let now = unix_now();
    match db::certs::revoke(&state.db, &payload.cert_id, Some(payload.reason as i64), now).await {
        Ok(true) => {
            // Invalidate CRL cache.
            *state.crl_cache.lock().unwrap_or_else(|e| e.into_inner()) = None;
            crate::audit::record_or_log(
                &state.db,
                &state.audit,
                &state.audit_policy,
                AuditEvent::success(AuditEventType::CertRevoke)
                    .with_principal(&operator.name)
                    .with_subject(&payload.cert_id)
                    .with_detail(&format!(
                        "{{\"action\":\"admin.revoke\",\"reason\":{}}}",
                        payload.reason
                    )),
            )
            .await;
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(false) => (StatusCode::NOT_FOUND, "certificate not found or already revoked").into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

// ── Statistics ────────────────────────────────────────────────────────────────

/// `GET /admin/stats`
///
/// Returns live server statistics.  Requires: any role.
pub async fn get_stats(
    operator: OperatorContext,
    State(state): State<Arc<AppState>>,
) -> Response {
    if let Err(r) = admin_configured(&state) {
        return r;
    }
    let _ = operator;

    let uptime_secs = state.startup_time.elapsed().as_secs();

    // Gather counts from the DB.
    let account_total: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM accounts")
        .fetch_one(&state.db)
        .await
        .unwrap_or((0,));
    let account_active: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM accounts WHERE status = 'valid'")
            .fetch_one(&state.db)
            .await
            .unwrap_or((0,));
    let cert_total: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM certificates")
        .fetch_one(&state.db)
        .await
        .unwrap_or((0,));
    let cert_active: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM certificates WHERE status = 'valid'")
            .fetch_one(&state.db)
            .await
            .unwrap_or((0,));
    let cert_revoked: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM certificates WHERE status = 'revoked'")
            .fetch_one(&state.db)
            .await
            .unwrap_or((0,));
    let eab_total: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM eab_keys")
        .fetch_one(&state.db)
        .await
        .unwrap_or((0,));
    let eab_used: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM eab_keys WHERE used_at IS NOT NULL")
            .fetch_one(&state.db)
            .await
            .unwrap_or((0,));
    let audit_total: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM audit_events")
        .fetch_one(&state.db)
        .await
        .unwrap_or((0,));

    let server_version = env!("CARGO_PKG_VERSION");

    (
        StatusCode::OK,
        Json(json!({
            "server_version": server_version,
            "uptime_secs": uptime_secs,
            "accounts": {
                "total": account_total.0,
                "active": account_active.0,
            },
            "certs": {
                "total": cert_total.0,
                "active": cert_active.0,
                "revoked": cert_revoked.0,
            },
            "eab_keys": {
                "total": eab_total.0,
                "used": eab_used.0,
                "unused": eab_total.0 - eab_used.0,
            },
            "audit_events": {
                "total": audit_total.0,
            },
        })),
    )
        .into_response()
}
