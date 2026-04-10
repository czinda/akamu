//! GET /acme/cert/{id} — RFC 8555 §7.4.2

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::{HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};

use crate::db;
use crate::error::AcmeError;
use crate::state::AppState;

pub async fn download_cert(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Response, AcmeError> {
    let cert = db::certs::get_by_id(&state.db, &id)
        .await?
        .ok_or(AcmeError::NotFound)?;

    let mut resp = (StatusCode::OK, cert.pem.into_bytes()).into_response();
    resp.headers_mut().insert(
        axum::http::header::CONTENT_TYPE,
        HeaderValue::from_static("application/pem-certificate-chain"),
    );
    Ok(resp)
}
