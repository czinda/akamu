//! Admin API endpoints — `/admin/…`
//!
//! All routes require an `Authorization: Bearer <token>` header whose value
//! matches `[admin].bearer_token` in the server configuration.  When the
//! `[admin]` section is absent the routes return 404 (they are never
//! registered in the router).
//!
//! # Account profile grants
//!
//! `GET    /admin/account/{id}/profile-grants` — read current grants.
//! `PUT    /admin/account/{id}/profile-grants` — replace grants (full override).
//! `DELETE /admin/account/{id}/profile-grants` — clear all grants.
//!
//! Grant payloads use `{"profile_grants": ["p1","p2"]}`.  `null` or absent
//! means no restriction (account may request any profile).
//!
//! # EAB key provisioning
//!
//! `POST /admin/eab` — provision a new EAB key, optionally pre-loading it
//! with profile grants that will be copied to the account at creation time.

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;
use serde_json::json;

use crate::db;
use crate::state::AppState;

use super::unix_now;

// ── Bearer token guard ────────────────────────────────────────────────────────

fn require_admin_auth(state: &AppState, headers: &HeaderMap) -> Result<(), Box<Response>> {
    let Some(ref admin_cfg) = state.config.admin else {
        return Err(Box::new(
            (StatusCode::NOT_FOUND, "admin API is not configured").into_response(),
        ));
    };

    let auth = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if auth == format!("Bearer {}", admin_cfg.bearer_token) {
        Ok(())
    } else if auth.is_empty() {
        Err(Box::new(
            (StatusCode::UNAUTHORIZED, "Authorization header required").into_response(),
        ))
    } else {
        Err(Box::new(
            (StatusCode::FORBIDDEN, "Invalid admin token").into_response(),
        ))
    }
}

// ── Payload types ─────────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct ProfileGrantsPayload {
    profile_grants: Option<Vec<String>>,
}

#[derive(Deserialize)]
struct NewEabPayload {
    kid: String,
    hmac_key_b64u: String,
    #[serde(default)]
    profile_grants: Option<Vec<String>>,
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn grants_to_json(grants: Option<Vec<String>>) -> Option<String> {
    match grants {
        None => None,
        Some(ref vec) if vec.is_empty() => None,
        Some(ref vec) => serde_json::to_string(vec).ok(),
    }
}

// ── Account profile grants ────────────────────────────────────────────────────

/// `GET /admin/account/{id}/profile-grants`
///
/// Returns `{"profile_grants":["p1","p2"]}` or `{"profile_grants":null}`.
/// 404 when the account does not exist.
pub async fn get_account_profile_grants(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    if let Err(r) = require_admin_auth(&state, &headers) {
        return *r;
    }

    match db::accounts::get_profile_grants(&state.db, &id).await {
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        Ok(None) => (StatusCode::NOT_FOUND, "account not found").into_response(),
        Ok(Some(grants_json)) => {
            let grants: Option<Vec<String>> = grants_json
                .as_deref()
                .and_then(|j| serde_json::from_str(j).ok());
            (StatusCode::OK, Json(json!({"profile_grants": grants}))).into_response()
        }
    }
}

/// `PUT /admin/account/{id}/profile-grants`
///
/// Body: `{"profile_grants":["p1","p2"]}` or `{"profile_grants":null}`.
/// Replaces the account's grants entirely.  204 on success, 404 when not found.
pub async fn put_account_profile_grants(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if let Err(r) = require_admin_auth(&state, &headers) {
        return *r;
    }

    let payload: ProfileGrantsPayload = match serde_json::from_slice(&body) {
        Ok(p) => p,
        Err(e) => return (StatusCode::BAD_REQUEST, format!("JSON: {e}")).into_response(),
    };

    let now = unix_now();
    let grants_str = grants_to_json(payload.profile_grants);
    match db::accounts::set_profile_grants(&state.db, &id, grants_str.as_deref(), now).await {
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        Ok(false) => (StatusCode::NOT_FOUND, "account not found or deactivated").into_response(),
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
    }
}

/// `DELETE /admin/account/{id}/profile-grants`
///
/// Clears all profile grants (sets to NULL — unrestricted).
/// 204 on success, 404 when not found.
pub async fn delete_account_profile_grants(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    if let Err(r) = require_admin_auth(&state, &headers) {
        return *r;
    }

    let now = unix_now();
    match db::accounts::set_profile_grants(&state.db, &id, None, now).await {
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        Ok(false) => (StatusCode::NOT_FOUND, "account not found or deactivated").into_response(),
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
    }
}

// ── EAB key provisioning ──────────────────────────────────────────────────────

/// `POST /admin/eab`
///
/// Provision a new EAB key, optionally with profile grants.
///
/// ```json
/// {"kid":"key-id","hmac_key_b64u":"<base64url>","profile_grants":["p1"]}
/// ```
///
/// `profile_grants` is optional; `null` or absent = no restriction.
/// 201 on success, 409 when the `kid` already exists.
pub async fn post_eab(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if let Err(r) = require_admin_auth(&state, &headers) {
        return *r;
    }

    let payload: NewEabPayload = match serde_json::from_slice(&body) {
        Ok(p) => p,
        Err(e) => return (StatusCode::BAD_REQUEST, format!("JSON: {e}")).into_response(),
    };

    if payload.kid.is_empty() || payload.hmac_key_b64u.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            "kid and hmac_key_b64u are required",
        )
            .into_response();
    }

    let now = unix_now();
    let grants_str = grants_to_json(payload.profile_grants);
    match db::eab::insert_with_grants(
        &state.db,
        &payload.kid,
        &payload.hmac_key_b64u,
        grants_str.as_deref(),
        now,
    )
    .await
    {
        Ok(()) => (
            StatusCode::CREATED,
            Json(json!({"kid": payload.kid, "created": now})),
        )
            .into_response(),
        Err(crate::error::AcmeError::Database(ref msg))
            if msg.contains("UNIQUE") || msg.contains("unique") || msg.contains("Duplicate") =>
        {
            (
                StatusCode::CONFLICT,
                format!("EAB key '{}' already exists", payload.kid),
            )
                .into_response()
        }
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}
