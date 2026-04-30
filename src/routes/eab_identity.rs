//! GET /acme/eab — return the authenticated principal for the caller.
//!
//! This is a stub that exercises the full proxy-header + GSSAPI authentication
//! stack. EAB key derivation (HKDF) will be added as a follow-up.

use std::sync::Arc;

use axum::extract::State;
use axum::response::IntoResponse;
use axum::Json;

use crate::extract::RemoteUser;
use crate::state::AppState;

pub async fn get_eab_identity(
    State(_state): State<Arc<AppState>>,
    RemoteUser(principal): RemoteUser,
) -> impl IntoResponse {
    Json(serde_json::json!({ "principal": principal }))
}
