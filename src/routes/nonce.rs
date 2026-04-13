//! HEAD /acme/new-nonce and GET /acme/new-nonce — RFC 8555 §7.2

use std::sync::Arc;

use axum::extract::State;
use axum::http::{HeaderName, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};

use crate::error::AcmeError;
use crate::state::AppState;

use super::new_nonce;

pub async fn new_nonce_head(State(state): State<Arc<AppState>>) -> Result<Response, AcmeError> {
    nonce_response(&state, StatusCode::OK)
}

pub async fn new_nonce_get(State(state): State<Arc<AppState>>) -> Result<Response, AcmeError> {
    nonce_response(&state, StatusCode::NO_CONTENT)
}

fn nonce_response(state: &AppState, status: StatusCode) -> Result<Response, AcmeError> {
    let nonce = new_nonce(state)?;
    let mut resp = status.into_response();
    resp.headers_mut().insert(
        HeaderName::from_static("replay-nonce"),
        HeaderValue::from_str(&nonce).unwrap(),
    );
    resp.headers_mut().insert(
        axum::http::header::CACHE_CONTROL,
        HeaderValue::from_static("no-store"),
    );
    Ok(resp)
}
