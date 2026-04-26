pub mod sign;

use std::sync::Arc;

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Router,
};

use crate::state::AppState;

/// Build the Axum router.
///
/// Routes:
/// - `POST /sign`  — MTC cosigner endpoint (§6.2).
/// - `GET  /.well-known/acme-challenge/:token` — ACME http-01 challenge server.
pub fn build_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/sign", post(sign::post_sign))
        .route(
            "/.well-known/acme-challenge/:token",
            get(acme_challenge_handler),
        )
        .with_state(state)
}

async fn acme_challenge_handler(
    Path(token): Path<String>,
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    let guard = state.challenge_tokens.read().unwrap();
    match guard.get(&token) {
        Some(key_auth) => (StatusCode::OK, key_auth.clone()).into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}
