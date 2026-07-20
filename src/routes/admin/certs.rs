//! Admin certificate search, detail, download, revocation, and CRL handlers.

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
use super::describe_cert_der;

#[derive(Deserialize)]
struct RevokePayload {
    /// Certificate ID (UUID).
    cert_id: String,
    /// Revocation reason code (0–10).  Default 0 (unspecified).
    #[serde(default)]
    reason: u8,
}

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
    // We check the role explicitly: ca_scope().is_none() would also match
    // administrator/auditor, who are legitimately server-wide.
    if operator.role == OperatorRole::CaRa && operator.ca_id.is_empty() {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"status": 403, "detail": "ca_ra operator has no CA scope configured"})),
        )
            .into_response();
    }

    let now = unix_now();
    match db::certs::revoke(
        &state.db,
        &payload.cert_id,
        Some(payload.reason as i64),
        now,
        operator.ca_scope(),
    )
    .await
    {
        Ok(true) => {
            // Look up the cert's CA and invalidate only that CA's CRL cache.
            let cert_ca_id = if let Ok(Some(cert)) =
                db::certs::get_by_id(&state.db, &payload.cert_id).await
            {
                let ca_id = cert.ca_id.clone();
                state.invalidate_crl_cache(&cert.ca_id);
                if let Some(idx) = cert.mtc_log_index {
                    if let Err(e) =
                        db::revoked_ranges::insert(&state.db, &ca_id, idx, idx, now).await
                    {
                        tracing::error!(
                            error = %e,
                            cert_id = %payload.cert_id,
                            ca_id = %ca_id,
                            log_index = idx,
                            "failed to insert MTC revoked range on admin revoke"
                        );
                    }
                }
                ca_id
            } else {
                // Cert row missing (shouldn't happen after a successful revoke) —
                // fall back to invalidating all caches.
                for cache in state.crl_caches.values() {
                    *cache.lock().unwrap_or_else(|e| {
                        tracing::error!("CRL cache mutex poisoned — recovering and invalidating");
                        e.into_inner()
                    }) = None;
                }
                String::new()
            };
            state
                .record_audit(
                    AuditEvent::success(AuditEventType::CertRevoke)
                        .with_principal(&operator.name)
                        .with_subject(&payload.cert_id)
                        .with_detail(
                            json!({"action": "admin.revoke", "reason": payload.reason, "ca_id": cert_ca_id})
                                .to_string(),
                        ),
                )
                .await;
            crdt_hooks::on_cert_tombstone(&state, &payload.cert_id, now).await;
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
