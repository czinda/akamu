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
//! | `GET /admin/delegations` | ✓ | ✓ | ✓ | ✓ |
//! | `POST /admin/delegations` | ✓ | ✓ | | |
//! | `GET /admin/delegations/{id}` | ✓ | ✓ | ✓ | ✓ |
//! | `PUT /admin/delegations/{id}` | ✓ | ✓ | | |
//! | `DELETE /admin/delegations/{id}` | ✓ | ✓ | | |

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
use crate::state::{AppState, OperatorRole};
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
    #[serde(default = "default_eab_alg")]
    alg: String,
}

fn default_eab_alg() -> String {
    "sha256".to_owned()
}

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

    match tokio::try_join!(
        db::audit::query(&state.db, &q),
        db::audit::count_filtered(&state.db, &q),
    ) {
        Ok((rows, total)) => {
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
                Json(json!({"events": events, "total": total, "limit": limit, "offset": offset})),
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
/// Search the certificate table.  Query params: `serial`, `subject`,
/// `account_id`, `after` (RFC 3339), `before` (RFC 3339),
/// `status` (active|revoked), `ca_id`, `limit` (≤1000), `offset`.
/// Requires: `administrator`, `ca_operations`, `ca_ra`, or `auditor`.
pub async fn get_certs(
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

    let serial = params.get("serial").map(String::as_str);
    let account_id = params.get("account_id").map(String::as_str);
    let status = params.get("status").map(String::as_str);
    let subject_dn = params.get("subject").map(String::as_str);
    // Scoped operators are always restricted to their own CA; override any supplied ca_id.
    let ca_id = operator
        .ca_scope()
        .or_else(|| params.get("ca_id").map(String::as_str));

    let search_params = db::certs::CertSearchParams {
        serial,
        account_id,
        status,
        subject_dn,
        ca_id,
        limit,
        offset,
    };
    let count_params = db::certs::CertSearchParams {
        serial: search_params.serial,
        account_id: search_params.account_id,
        status: search_params.status,
        subject_dn: search_params.subject_dn,
        ca_id: search_params.ca_id,
        limit,
        offset,
    };

    match tokio::try_join!(
        db::certs::search(&state.db, search_params),
        db::certs::count_search(&state.db, count_params),
    ) {
        Ok((rows, total)) => {
            let certs: Vec<_> = rows
                .into_iter()
                .map(|r| {
                    json!({
                        "id": r.id,
                        "order_id": r.order_id,
                        "account_id": r.account_id,
                        "ca_id": r.ca_id,
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
                Json(json!({"certs": certs, "total": total, "limit": limit, "offset": offset})),
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

    if let Some(scope) = operator.ca_scope() {
        match db::accounts::get_by_id(&state.db, &id).await {
            Ok(Some(acct)) if !acct.ca_id.is_empty() && acct.ca_id != scope => {
                return (
                    StatusCode::NOT_FOUND,
                    Json(json!({"status": 404, "detail": "account not found"})),
                )
                    .into_response();
            }
            Ok(None) => {
                return (
                    StatusCode::NOT_FOUND,
                    Json(json!({"status": 404, "detail": "account not found"})),
                )
                    .into_response();
            }
            Err(e) => {
                tracing::error!(error = %e, "put_account_profile_grants: scope check db error");
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"status": 500, "detail": "database error"})),
                )
                    .into_response();
            }
            Ok(Some(_)) => {}
        }
    }

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
/// bound to any CA, so a CA-scoped operator could otherwise create keys
/// usable for account creation under any CA.
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
        Some(operator.operator_id),
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

    // Drop CRL caches for the operator's scope (or all CAs for server-wide operators).
    // The next GET /ca/{id}/crl will regenerate each invalidated cache.
    if let Some(scope) = operator.ca_scope() {
        state.invalidate_crl_cache(scope);
    } else {
        for cache in state.crl_caches.values() {
            *cache.lock().unwrap_or_else(|e| {
                tracing::error!("CRL cache mutex poisoned — recovering and invalidating");
                e.into_inner()
            }) = None;
        }
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

    // ca_ra operators must always have a CA scope — an empty ca_id is a
    // misconfiguration that would grant server-wide revocation authority.
    if operator.role == OperatorRole::CaRa && operator.ca_id.is_empty() {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"status": 403, "detail": "ca_ra operator has no CA scope configured"})),
        )
            .into_response();
    }

    // CA-scoped operators may only revoke certificates from their own CA.
    if let Some(scope) = operator.ca_scope() {
        match db::certs::get_by_id(&state.db, &payload.cert_id).await {
            Ok(Some(cert)) if cert.ca_id != scope => {
                return (
                    StatusCode::FORBIDDEN,
                    "certificate does not belong to your CA scope",
                )
                    .into_response();
            }
            Ok(None) => {
                return (StatusCode::NOT_FOUND, "certificate not found").into_response();
            }
            Err(e) => {
                tracing::error!(error = %e, "post_revoke: CA scope check db error");
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"status": 500, "detail": "database error"})),
                )
                    .into_response();
            }
            Ok(Some(_)) => {} // cert.ca_id == operator.ca_id — permitted
        }
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
                    *cache.lock().unwrap_or_else(|e| {
                        tracing::error!("CRL cache mutex poisoned — recovering and invalidating");
                        e.into_inner()
                    }) = None;
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

/// `GET /admin/profiles/{id}`
///
/// Return a single certificate profile by ID.
/// Requires: any role.
pub async fn get_profile(
    operator: OperatorContext,
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Response {
    require_role!(
        operator,
        state,
        Administrator | CaOperations | CaRa | Auditor
    );

    let descriptions = state.profiles.all_profiles();
    match (descriptions.get(&id), state.profiles.resolve(&id)) {
        (Some(description), Some(params)) => (
            StatusCode::OK,
            Json(json!({
                "id": id,
                "description": description,
                "validity_days": params.validity_days,
                "hash_alg": params.hash_alg,
                "key_usage_bits": params.key_usage_bits,
                "extended_key_usages": params.extended_key_usages,
                "crl_url": params.crl_url,
                "ocsp_url": params.ocsp_url,
                "allowed_key_types": params.allowed_key_types,
                "certificate_policies": params.certificate_policies,
                "issue_as_mtc": params.issue_as_mtc,
                "allowed_identifier_patterns": params.allowed_identifier_patterns,
                "identifier_match_all": params.identifier_match_all,
                "auth_hook": params.auth_hook,
                "auth_hook_timeout_secs": params.auth_hook_timeout_secs,
                "require_account_grant": params.require_account_grant,
                "ca_ids": params.ca_ids,
            })),
        )
            .into_response(),
        _ => (
            StatusCode::NOT_FOUND,
            Json(json!({"status": 404, "detail": "profile not found"})),
        )
            .into_response(),
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
            (
                StatusCode::OK,
                Json(
                    json!({"accounts": accounts, "total": total, "limit": limit, "offset": offset}),
                ),
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
        Ok(Some(r)) => {
            if operator
                .ca_scope()
                .is_some_and(|scope| !r.ca_id.is_empty() && r.ca_id != scope)
            {
                return (
                    StatusCode::NOT_FOUND,
                    Json(json!({"status": 404, "detail": "account not found"})),
                )
                    .into_response();
            }
            (
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
                .into_response()
        }
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

/// Produce an openssl-style text description of a DER-encoded certificate.
fn describe_cert_der(der: &[u8]) -> Option<String> {
    use std::fmt::Write as FmtWrite;
    use synta::{Decoder, Encoding};
    use synta_certificate::{
        decode_extensions, decode_public_key_info, extension_oid_name, format_dn,
        format_extension_value, identify_public_key_algorithm, identify_signature_algorithm,
        Certificate, PublicKeyInfo, Time,
    };

    let mut decoder = Decoder::new(der, Encoding::Der);
    let cert: Certificate = decoder.decode().ok()?;
    let tbs = &cert.tbs_certificate;
    let mut out = String::new();

    let version = tbs
        .version
        .as_ref()
        .and_then(|v| v.as_i64().ok())
        .map(|v| v + 1)
        .unwrap_or(1);

    let _ = writeln!(out, "Certificate:");
    let _ = writeln!(out, "    Data:");
    let _ = writeln!(out, "        Version: {} (0x{:x})", version, version - 1);

    let serial_bytes = tbs.serial_number.as_bytes();
    if serial_bytes.len() <= 8 {
        let mut val: u64 = 0;
        for b in serial_bytes {
            val = (val << 8) | (*b as u64);
        }
        let _ = writeln!(out, "        Serial Number: {} (0x{:x})", val, val);
    } else {
        let hex = serial_bytes
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join(":");
        let _ = writeln!(out, "        Serial Number: {}", hex);
    }

    let sig_alg = identify_signature_algorithm(&tbs.signature.algorithm);
    let _ = writeln!(out, "        Signature Algorithm: {}", sig_alg);
    let _ = writeln!(out, "        Issuer: {}", format_dn(tbs.issuer.as_bytes()));
    let _ = writeln!(out, "        Validity");

    fn fmt_time(t: &Time) -> String {
        const M: [&str; 12] = [
            "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
        ];
        match t {
            Time::UtcTime(u) => format!(
                "{} {:2} {:02}:{:02}:{:02} {} GMT",
                M.get((u.month - 1) as usize).unwrap_or(&"???"),
                u.day,
                u.hour,
                u.minute,
                u.second,
                u.year,
            ),
            Time::GeneralTime(g) => format!(
                "{} {:2} {:02}:{:02}:{:02} {} GMT",
                M.get((g.month - 1) as usize).unwrap_or(&"???"),
                g.day,
                g.hour,
                g.minute,
                g.second,
                g.year,
            ),
        }
    }

    let _ = writeln!(
        out,
        "            Not Before: {}",
        fmt_time(&tbs.validity.not_before)
    );
    let _ = writeln!(
        out,
        "            Not After : {}",
        fmt_time(&tbs.validity.not_after)
    );
    let _ = writeln!(
        out,
        "        Subject: {}",
        format_dn(tbs.subject.as_bytes())
    );

    let spki = &tbs.subject_public_key_info;
    let pub_alg = identify_public_key_algorithm(&spki.algorithm.algorithm).unwrap_or("unknown");
    let _ = writeln!(out, "        Subject Public Key Info:");
    let _ = writeln!(out, "            Public Key Algorithm: {}", pub_alg);

    fn write_hex(out: &mut String, data: &[u8], per_line: usize, indent: usize) {
        let pad = " ".repeat(indent);
        let chunks: Vec<_> = data.chunks(per_line).collect();
        for (i, chunk) in chunks.iter().enumerate() {
            let _ = write!(out, "{}", pad);
            for (j, b) in chunk.iter().enumerate() {
                if j > 0 {
                    let _ = write!(out, ":");
                }
                let _ = write!(out, "{:02x}", b);
            }
            if i < chunks.len() - 1 {
                let _ = write!(out, ":");
            }
            let _ = writeln!(out);
        }
    }

    match decode_public_key_info(
        &spki.algorithm.algorithm,
        spki.algorithm.parameters.as_ref(),
        spki.subject_public_key.as_bytes(),
        spki.subject_public_key.bit_len(),
    ) {
        PublicKeyInfo::Rsa {
            modulus,
            exponent,
            bit_count,
        } => {
            let _ = writeln!(out, "                Public-Key: ({} bit)", bit_count);
            let _ = writeln!(out, "                Modulus:");
            write_hex(&mut out, &modulus, 15, 20);
            let _ = writeln!(
                out,
                "                Exponent: {} (0x{:x})",
                exponent, exponent
            );
        }
        PublicKeyInfo::Ec {
            key_bytes,
            bit_count,
            curve_short_name,
            curve_nist_name,
            curve_oid_str,
        } => {
            let _ = writeln!(out, "                Public-Key: ({} bit)", bit_count);
            let _ = writeln!(out, "                pub:");
            write_hex(&mut out, &key_bytes, 15, 20);
            let name = curve_short_name.map(str::to_owned).unwrap_or(curve_oid_str);
            let _ = writeln!(out, "                ASN1 OID: {}", name);
            if let Some(nist) = curve_nist_name {
                let _ = writeln!(out, "                NIST CURVE: {}", nist);
            }
        }
        PublicKeyInfo::Unknown {
            key_bytes,
            bit_count,
            ..
        } => {
            let _ = writeln!(out, "                Public-Key: ({} bit)", bit_count);
            let _ = writeln!(out, "                pub:");
            write_hex(&mut out, &key_bytes, 15, 20);
        }
    }

    if let Some(exts_raw) = &tbs.extensions {
        let exts = decode_extensions(exts_raw.as_bytes());
        if !exts.is_empty() {
            let _ = writeln!(out, "        X509v3 extensions:");
            for ext in &exts {
                let name = extension_oid_name(&ext.extn_id);
                let critical = ext.critical.map(bool::from).unwrap_or(false);
                if critical {
                    let _ = writeln!(out, "            {}: critical", name);
                } else {
                    let _ = writeln!(out, "            {}:", name);
                }
                if let Some(val) = format_extension_value(ext) {
                    let _ = writeln!(out, "                {}", val);
                }
            }
        }
    }

    let _ = writeln!(out, "    Signature Algorithm: {}", sig_alg);
    let _ = writeln!(out, "    Signature Value:");
    write_hex(&mut out, cert.signature_value.as_bytes(), 18, 8);

    Some(out)
}

/// `GET /admin/certs/{id}`
///
/// Show a single certificate's metadata (no PEM/DER blobs).
/// Requires: `administrator`, `ca_operations`, or `auditor`.
pub async fn get_cert(
    operator: OperatorContext,
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Response {
    require_role!(
        operator,
        state,
        Administrator | CaOperations | CaRa | Auditor
    );

    match db::certs::get_by_id(&state.db, &id).await {
        Ok(Some(r)) => {
            // Scoped operators may only view certificates from their own CA.
            if operator.ca_scope().is_some_and(|scope| r.ca_id != scope) {
                return (
                    StatusCode::NOT_FOUND,
                    Json(json!({"status": 404, "detail": "certificate not found"})),
                )
                    .into_response();
            }
            (
                StatusCode::OK,
                Json(json!({
                    "id": r.id,
                    "order_id": r.order_id,
                    "account_id": r.account_id,
                    "ca_id": r.ca_id,
                    "serial_number": r.serial_number,
                    "subject_dn": r.subject_dn,
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
                    "cert_text": describe_cert_der(&r.der),
                })),
            )
                .into_response()
        }
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
    require_role!(operator, state, Administrator | CaOperations | CaRa);

    let format = params.get("format").map(String::as_str).unwrap_or("pem");

    match db::certs::get_by_id(&state.db, &id).await {
        Ok(Some(r)) => {
            // Scoped operators may only download certificates from their own CA.
            if operator.ca_scope().is_some_and(|scope| r.ca_id != scope) {
                return (
                    StatusCode::NOT_FOUND,
                    Json(json!({"status": 404, "detail": "certificate not found"})),
                )
                    .into_response();
            }
            match format {
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
            }
        }
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
            (
                StatusCode::OK,
                Json(json!({"orders": orders, "total": total, "limit": limit, "offset": offset})),
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
        Ok(Some((r, authz_ids))) => {
            if operator.ca_scope().is_some_and(|scope| r.ca_id != scope) {
                return (
                    StatusCode::NOT_FOUND,
                    Json(json!({"status": 404, "detail": "order not found"})),
                )
                    .into_response();
            }
            (
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
                .into_response()
        }
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

    let scope = operator.ca_scope();
    let cas: Vec<_> = state
        .cas
        .values()
        .filter(|ca| scope.is_none_or(|s| ca.id == s))
        .map(|ca| {
            json!({
                "id": ca.id,
                "is_default": ca.id == state.default_ca_id.as_str(),
                "key_type": ca.key_type,
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

    if operator.ca_scope().is_some_and(|scope| id != scope) {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({"status": 404, "detail": "CA not found"})),
        )
            .into_response();
    }

    let Some(ca) = state.get_ca(&id) else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({"status": 404, "detail": "CA not found"})),
        )
            .into_response();
    };

    let cert_pem = match String::from_utf8(der_to_pem("CERTIFICATE", &ca.cert_der)) {
        Ok(p) => p,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"status": 500, "detail": "failed to encode CA certificate"})),
            )
                .into_response();
        }
    };

    (
        StatusCode::OK,
        Json(json!({
            "id": ca.id,
            "is_default": ca.id == state.default_ca_id.as_str(),
            "key_type": ca.key_type,
            "hash_alg": ca.hash_alg,
            "validity_days": ca.validity_days,
            "crl_url": ca.crl_url,
            "ocsp_url": ca.ocsp_url,
            "caa_identities": ca.caa_identities,
            "cert_pem": cert_pem,
            "cert_text": describe_cert_der(&ca.cert_der),
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

    if operator.ca_scope().is_some_and(|scope| id != scope) {
        return (StatusCode::NOT_FOUND, "CA not found").into_response();
    }

    let Some(ca) = state.get_ca(&id) else {
        return (StatusCode::NOT_FOUND, "CA not found").into_response();
    };

    let cert_pem = match String::from_utf8(der_to_pem("CERTIFICATE", &ca.cert_der)) {
        Ok(p) => p,
        Err(e) => {
            tracing::error!(ca_id = %id, error = %e, "CA cert DER→PEM produced non-UTF-8 bytes");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"status": 500, "detail": "failed to encode CA certificate as PEM"})),
            )
                .into_response();
        }
    };

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

    if operator.ca_scope().is_some_and(|scope| id != scope) {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({"status": 404, "detail": "CA not found"})),
        )
            .into_response();
    }

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

/// The subject for a cross-sign request: either a same-server CA by ID, or an
/// external CA supplied as a PEM certificate block.  Exactly one variant must
/// be present; serde rejects JSON with neither or both keys.
#[derive(Deserialize)]
#[serde(untagged)]
pub enum CrossSignSubject {
    /// Same-server CA whose certificate will become the cross-cert subject.
    SameServer { subject_ca_id: String },
    /// PEM-encoded certificate of an external CA to cross-sign.
    External { subject_cert_pem: String },
}

/// Request body for `POST /admin/ca/{id}/cross-sign`.
#[derive(Deserialize)]
pub struct CrossSignPayload {
    #[serde(flatten)]
    subject: CrossSignSubject,
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

    // Validate validity_years before doing any CA lookups.
    if payload.validity_years == 0 || payload.validity_years > 50 {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"status": 400, "detail": "validity_years must be between 1 and 50"})),
        )
            .into_response();
    }

    if operator.ca_scope().is_some_and(|scope| issuer_id != scope) {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({"status": 404, "detail": "issuer CA not found"})),
        )
            .into_response();
    }

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

    // Resolve the subject cert DER and the subject_ca_id for audit/response.
    let (subject_cert_der, subject_ca_id) = match &payload.subject {
        CrossSignSubject::SameServer { subject_ca_id } => {
            if subject_ca_id == &issuer_id {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(
                        json!({"status": 400, "detail": "issuer and subject CA must be different"}),
                    ),
                )
                    .into_response();
            }
            match state.get_ca(subject_ca_id) {
                Some(ca) => (ca.cert_der.clone(), Some(subject_ca_id.clone())),
                None => {
                    return (
                        StatusCode::NOT_FOUND,
                        Json(json!({"status": 404, "detail": "subject CA not found"})),
                    )
                        .into_response();
                }
            }
        }
        CrossSignSubject::External { subject_cert_pem } => {
            // Require a "CERTIFICATE" label so operators don't accidentally submit a CSR or key.
            let blocks = synta_certificate::pem_blocks(subject_cert_pem.as_bytes());
            let der = match blocks.into_iter().find(|(label, _)| label == "CERTIFICATE") {
                Some((_, d)) => d,
                None => {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(json!({"status": 400, "detail": "subject_cert_pem must contain a CERTIFICATE PEM block"})),
                    )
                        .into_response();
                }
            };
            // Verify the external cert is a valid CA certificate (BasicConstraints.cA=TRUE).
            let now = crate::util::unix_now();
            if let Err(e) = crate::ca::issue::check_is_ca_cert(&der, now) {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({"status": 400, "detail": e.to_string()})),
                )
                    .into_response();
            }
            (der, None)
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
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"status": 500, "detail": "cross-certificate issuance failed"})),
            )
                .into_response();
        }
    };

    let id = uuid::Uuid::new_v4().to_string();
    let now = unix_now();
    let row = crate::db::schema::CrossCertRow {
        id: id.clone(),
        issuer_ca_id: issuer_id.clone(),
        subject_ca_id: subject_ca_id.clone(),
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
        state
            .record_audit(
                AuditEvent::failure(AuditEventType::CrossSignIssue)
                    .with_principal(&operator.name)
                    .with_detail(format!("DB insert failed: {e}; issuer={issuer_id}")),
            )
            .await;
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"status": 500, "detail": "failed to persist cross-certificate"})),
        )
            .into_response();
    }

    state
        .record_audit(
            AuditEvent::success(AuditEventType::CrossSignIssue)
                .with_principal(&operator.name)
                .with_subject(&id)
                .with_detail(
                    serde_json::json!({
                        "issuer_ca_id": issuer_id,
                        "subject_ca_id": subject_ca_id,
                        "subject_dn": issued.subject_dn,
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
            "subject_ca_id": subject_ca_id,
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
/// Query parameters for `GET /admin/cross-certs`.
#[derive(Deserialize, Default)]
pub struct CrossCertsQuery {
    /// Filter by issuing CA ID.
    pub issuer_ca_id: Option<String>,
    /// Filter by subject CA ID.
    pub subject_ca_id: Option<String>,
    /// Maximum number of results to return (1–1000, default 100).
    #[serde(default = "default_cross_certs_limit")]
    pub limit: i64,
    /// Pagination offset (default 0).
    #[serde(default)]
    pub offset: i64,
}

fn default_cross_certs_limit() -> i64 {
    100
}

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
    axum::extract::Query(params): axum::extract::Query<CrossCertsQuery>,
) -> Response {
    require_role!(operator, state, Administrator | CaOperations | Auditor);

    // Scoped operators may only see cross-certs they issued.
    let issuer_ca_id = operator.ca_scope().or(params.issuer_ca_id.as_deref());
    let subject_ca_id = params.subject_ca_id.as_deref();
    let limit = params.limit.clamp(1, 1000);
    let offset = params.offset.max(0);

    match tokio::try_join!(
        db::cross_certs::list(&state.db, issuer_ca_id, subject_ca_id, limit, offset),
        db::cross_certs::count_list(&state.db, issuer_ca_id, subject_ca_id),
    ) {
        Ok((rows, total)) => {
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
            (StatusCode::OK, Json(json!({ "cross_certs": items, "total": total, "limit": limit, "offset": offset }))).into_response()
        }
        Err(e) => {
            tracing::error!(error = %e, "get_cross_certs DB query failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"status": 500, "detail": "failed to query cross-certificates"})),
            )
                .into_response()
        }
    }
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
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"status": 500, "detail": "failed to query cross-certificate"})),
            )
                .into_response();
        }
    };

    // Scoped operators may only see cross-certs issued by their CA.
    if operator
        .ca_scope()
        .is_some_and(|scope| row.issuer_ca_id != scope)
    {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({"status": 404, "detail": "cross-cert not found"})),
        )
            .into_response();
    }

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
            "cert_text": describe_cert_der(&row.cross_cert_der),
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

    let ca_scope = operator.ca_scope();

    let counts = match db::stats::summary(&state.db, ca_scope).await {
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
            "ca_scope": ca_scope,
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
                "bound": counts.eab_bound,
                "free": counts.eab_total - counts.eab_used - counts.eab_bound,
            },
            "audit_events": {
                "total": counts.audit_total,
            },
        })),
    )
        .into_response()
}

// ── Delegations (RFC 9115) ────────────────────────────────────────────────────

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

fn delegation_row_to_json(r: &crate::db::schema::DelegationRow) -> serde_json::Value {
    let csr_template = match serde_json::from_str::<serde_json::Value>(&r.csr_template) {
        Ok(v) => v,
        Err(e) => {
            tracing::error!(
                delegation_id = %r.id,
                "delegation csr_template is corrupt JSON: {e}"
            );
            serde_json::Value::Null
        }
    };
    json!({
        "id": r.id,
        "account_id": r.account_id,
        "csr_template": csr_template,
        "cname_map": r.cname_map.as_deref()
            .and_then(|s| serde_json::from_str::<serde_json::Value>(s).ok()),
        "created": r.created,
        "updated": r.updated,
    })
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
        db::delegations::list(&state.db_ro, account_id, ca_scope, limit, offset),
        db::delegations::count_list(&state.db_ro, account_id, ca_scope),
    ) {
        Ok((rows, total)) => {
            let list: Vec<serde_json::Value> = rows.iter().map(delegation_row_to_json).collect();
            (
                StatusCode::OK,
                Json(
                    json!({"delegations": list, "total": total, "limit": limit, "offset": offset}),
                ),
            )
                .into_response()
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

    match db::delegations::get_by_id(&state.db_ro, &id).await {
        Ok(Some(r)) => {
            if let Some(scope) = operator.ca_scope() {
                match db::accounts::get_by_id(&state.db_ro, &r.account_id).await {
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
            (StatusCode::OK, Json(delegation_row_to_json(&r))).into_response()
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
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(false) => (
            StatusCode::NOT_FOUND,
            Json(json!({"status": 404, "detail": "delegation not found"})),
        )
            .into_response(),
        Err(crate::error::AcmeError::Database(ref msg))
            if msg.contains("FOREIGN KEY")
                || msg.contains("foreign key")
                || msg.contains("constraint") =>
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
