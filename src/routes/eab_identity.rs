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

/// Return the Kerberos / proxy-authenticated principal name for the caller.
///
/// The caller must authenticate via one of the configured mechanisms:
///
/// - **Proxy mode** — a trusted reverse proxy sets `X-Remote-User` after
///   completing SPNEGO on behalf of the client.
/// - **Standalone GSSAPI** — the client sends `Authorization: Negotiate
///   <base64>` directly and akamu validates the token.
///
/// # Response
///
/// `200 OK` with a JSON body:
///
/// ```json
/// { "principal": "user@REALM" }
/// ```
///
/// # Planned follow-up
///
/// EAB HMAC key derivation (HKDF from a per-deployment master secret keyed by
/// the principal name) is not yet implemented.  The current response is
/// informational only and does not constitute an EAB key.
pub async fn get_eab_identity(
    State(_state): State<Arc<AppState>>,
    RemoteUser(principal): RemoteUser,
) -> impl IntoResponse {
    Json(serde_json::json!({ "principal": principal }))
}
