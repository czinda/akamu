//! Certificate download — RFC 8555 §7.4.2
//!
//! GET  /acme/cert/{id}  — unauthenticated (for simple HTTP clients)
//! POST /acme/cert/{id}  — POST-as-GET (RFC 8555 §6.3); required by ACME clients
//!                         that send all requests as authenticated POSTs.

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};

use crate::db;
use crate::error::AcmeError;
use crate::state::AppState;

use super::{acme_prefix, parse_jws, CaId};

/// Serve the certificate chain as PEM (unauthenticated GET).
pub async fn download_cert(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Response, AcmeError> {
    let cert = db::certs::get_by_id(&state.db_ro, &id)
        .await?
        .ok_or(AcmeError::NotFound)?;
    Ok(cert_pem_response(cert))
}

/// POST-as-GET handler for certificate download (RFC 8555 §6.3 + §7.4.2).
///
/// The JWS must have an empty payload (`""`).  The account that owns the order
/// linked to this certificate must match the `kid` in the JWS header — or any
/// authenticated account may download (some servers allow this; we require the
/// account to match the order for consistency with the rest of the API).
pub async fn download_cert_post(
    State(state): State<Arc<AppState>>,
    ca_id: CaId,
    Path(id): Path<String>,
    body: Bytes,
) -> Result<Response, AcmeError> {
    let pfx = acme_prefix(&state.config.base_url, &ca_id.0, &state.default_ca_id);
    let url = format!("{pfx}/cert/{id}");
    let ctx = parse_jws(&state, body, &url).await?;

    // POST-as-GET must have an empty payload.
    if !ctx.payload.is_empty() {
        return Err(AcmeError::BadRequest(
            "certificate download: payload must be empty (POST-as-GET)".into(),
        ));
    }

    // Verify the requesting account owns the order linked to this certificate.
    let account_id = ctx
        .account_id
        .ok_or_else(|| AcmeError::Unauthorized("kid required".into()))?;

    let cert = db::certs::get_by_id(&state.db_ro, &id)
        .await?
        .ok_or(AcmeError::NotFound)?;

    // RFC 9115 §2.3.5: when the order's allow_cert_get flag is set, any
    // authenticated account may download the certificate (not just the owner).
    // Use the write pool to avoid replication-lag races where a newly-created
    // delegation order's allow_cert_get hasn't propagated to the read replica.
    let allow_cert_get = db::orders::get_by_id(&state.db, &cert.order_id)
        .await?
        .is_some_and(|o| o.allow_cert_get != 0);

    if !allow_cert_get && cert.account_id != account_id {
        return Err(AcmeError::Unauthorized(
            "certificate belongs to a different account".into(),
        ));
    }

    Ok(cert_pem_response(cert))
}

fn cert_pem_response(cert: crate::db::schema::CertificateRow) -> Response {
    if cert
        .pem
        .starts_with("-----BEGIN STANDALONE MTC CERTIFICATE-----")
    {
        // MTC StandaloneCertificate — serve the raw DER stored in the `der` column.
        let mut resp = (StatusCode::OK, cert.der).into_response();
        resp.headers_mut().insert(
            axum::http::header::CONTENT_TYPE,
            HeaderValue::from_static("application/pkix-cert"),
        );
        return resp;
    }
    let mut resp = (StatusCode::OK, cert.pem.into_bytes()).into_response();
    resp.headers_mut().insert(
        axum::http::header::CONTENT_TYPE,
        HeaderValue::from_static("application/pem-certificate-chain"),
    );
    resp
}
