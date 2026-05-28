//! Admin CA management handlers.

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;
use serde_json::json;
use synta_certificate::der_to_pem;

use crate::admin::auth::OperatorContext;
use crate::audit::{AuditEvent, AuditEventType};
use crate::db;
use crate::require_role;
use crate::state::AppState;

use super::super::unix_now;
use super::describe_cert_der;

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
