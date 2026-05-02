pub mod sign;

use std::sync::Arc;

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Router,
};

use crate::admin;
use crate::state::AppState;

/// Build the Axum router.
///
/// Routes:
/// - `POST /sign`  — MTC cosigner endpoint (§6.2).
/// - `GET  /.well-known/acme-challenge/:token` — ACME http-01 challenge server.
/// - `POST /admin/session`   — authenticate, returns session token.
/// - `DELETE /admin/session` — invalidate current session.
/// - `GET  /admin/status`    — liveness check.
/// - `GET  /admin/stats`     — signing statistics.
/// - `GET  /admin/config`    — redacted config (administrator only).
pub fn build_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/sign", post(sign::post_sign))
        .route(
            "/.well-known/acme-challenge/{token}",
            get(acme_challenge_handler),
        )
        .route(
            "/admin/session",
            post(admin::post_session).delete(admin::delete_session),
        )
        .route("/admin/status", get(admin::get_status))
        .route("/admin/stats", get(admin::get_stats))
        .route("/admin/config", get(admin::get_config))
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
