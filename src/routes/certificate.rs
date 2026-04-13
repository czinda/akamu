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

use super::parse_jws;

/// Serve the certificate chain as PEM (unauthenticated GET).
pub async fn download_cert(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Response, AcmeError> {
    serve_cert_pem(&state, &id).await
}

/// POST-as-GET handler for certificate download (RFC 8555 §6.3 + §7.4.2).
///
/// The JWS must have an empty payload (`""`).  The account that owns the order
/// linked to this certificate must match the `kid` in the JWS header — or any
/// authenticated account may download (some servers allow this; we require the
/// account to match the order for consistency with the rest of the API).
pub async fn download_cert_post(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    body: Bytes,
) -> Result<Response, AcmeError> {
    let url = format!("{}/acme/cert/{}", state.config.base_url, id);
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

    let mut conn = state.db.acquire().await?;
    let cert = db::certs::get_by_id(&mut *conn, &id)
        .await?
        .ok_or(AcmeError::NotFound)?;

    if cert.account_id != account_id {
        return Err(AcmeError::Unauthorized(
            "certificate belongs to a different account".into(),
        ));
    }
    // Use the already-fetched cert directly; calling serve_cert_pem would deadlock
    // because conn still holds the mutex and serve_cert_pem also calls acquire().
    drop(conn);
    let mut resp = (StatusCode::OK, cert.pem.into_bytes()).into_response();
    resp.headers_mut().insert(
        axum::http::header::CONTENT_TYPE,
        HeaderValue::from_static("application/pem-certificate-chain"),
    );
    Ok(resp)
}

async fn serve_cert_pem(state: &AppState, id: &str) -> Result<Response, AcmeError> {
    let mut conn = state.db.acquire().await?;
    let cert = db::certs::get_by_id(&mut *conn, id)
        .await?
        .ok_or(AcmeError::NotFound)?;

    let mut resp = (StatusCode::OK, cert.pem.into_bytes()).into_response();
    resp.headers_mut().insert(
        axum::http::header::CONTENT_TYPE,
        HeaderValue::from_static("application/pem-certificate-chain"),
    );
    Ok(resp)
}
