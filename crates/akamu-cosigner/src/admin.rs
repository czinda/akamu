//! Admin routes and operator authentication for akamu-cosigner.
//!
//! Operators are identified by client certificate fingerprint, as registered in
//! `[[admin.operators]]` in the cosigner TOML config.  A successful
//! authentication issues an in-memory session token with configurable TTL.
//!
//! GSSAPI / Kerberos authentication is not currently implemented in the
//! cosigner.  Operators must authenticate via mTLS client certificates.
//!
//! Routes:
//!   POST   /admin/session  — authenticate, returns session token
//!   DELETE /admin/session  — invalidate current session
//!   GET    /admin/status   — server liveness (all roles)
//!   GET    /admin/stats    — signing statistics (all roles)
//!   GET    /admin/config   — redacted config view (administrator only)

use std::sync::Arc;

use axum::extract::{FromRef, State};
use axum::http::request::Parts;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;

use crate::config::CosignerRole;
use crate::state::{AppState, CosignerSession};

// ── PeerClientCert extension (injected by TLS accept loop) ───────────────────

pub use akamu::admin::auth::PeerClientCert;

// ── Token and fingerprint helpers ─────────────────────────────────────────────

// ── Session management ────────────────────────────────────────────────────────

pub async fn create_session(
    state: &AppState,
    name: &str,
    role: CosignerRole,
    operator_id: i64,
) -> Result<String, String> {
    let token = akamu::admin::auth::generate_token()?;
    let now = std::time::Instant::now();
    let mut sessions = state.admin_sessions.lock().await;
    // Evict oldest session if cap reached.
    const SESSION_CAP: usize = 1000;
    if sessions.len() >= SESSION_CAP {
        if let Some(oldest_key) = sessions
            .iter()
            .min_by_key(|(_, s)| s.last_active_at)
            .map(|(k, _)| k.clone())
        {
            sessions.remove(&oldest_key);
        }
    }
    sessions.insert(
        token.clone(),
        CosignerSession {
            name: name.to_string(),
            role,
            operator_id,
            created_at: now,
            last_active_at: now,
        },
    );
    Ok(token)
}

pub async fn lookup_session(state: &AppState, token: &str) -> Option<(String, CosignerRole, i64)> {
    let ttl = std::time::Duration::from_secs(state.admin_session_ttl_secs);
    let now = std::time::Instant::now();
    let mut sessions = state.admin_sessions.lock().await;
    sessions.retain(|_, s| now.duration_since(s.last_active_at) < ttl);
    let key = akamu::admin::auth::find_session_token(&sessions, token)?;
    let s = sessions.get_mut(&key)?;
    s.last_active_at = now;
    Some((s.name.clone(), s.role.clone(), s.operator_id))
}

pub async fn invalidate_session(state: &AppState, token: &str) {
    state.admin_sessions.lock().await.remove(token);
}

// ── OperatorContext extractor ─────────────────────────────────────────────────

/// Authenticated operator extracted from the request.
pub struct OperatorContext {
    pub name: String,
    pub role: CosignerRole,
    /// Position of the operator in `AppState::admin_operators` (0-based, cast to i64).
    pub operator_id: i64,
    pub session_token: Option<String>,
}

impl<S> axum::extract::FromRequestParts<S> for OperatorContext
where
    S: Send + Sync,
    Arc<AppState>: FromRef<S>,
{
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Response> {
        let app_state = Arc::<AppState>::from_ref(state);

        // Path 1: Bearer session token.
        if let Some(auth) = parts.headers.get(axum::http::header::AUTHORIZATION) {
            if let Ok(s) = auth.to_str() {
                if let Some(token) = s.strip_prefix("Bearer ") {
                    if let Some((name, role, operator_id)) = lookup_session(&app_state, token).await
                    {
                        tracing::info!(operator = %name, role = %role, "cosigner admin: bearer token accepted");
                        return Ok(OperatorContext {
                            name,
                            role,
                            operator_id,
                            session_token: Some(token.to_string()),
                        });
                    }
                    tracing::warn!("cosigner admin: bearer token invalid or expired");
                    return Err(
                        (StatusCode::UNAUTHORIZED, "session expired or invalid").into_response()
                    );
                }
            }
        }

        // Path 2: mTLS client certificate fingerprint.
        if let Some(ext) = parts.extensions.get::<PeerClientCert>() {
            let fp = akamu::util::sha256_hex(&ext.0).map_err(|e| {
                tracing::error!(error = %e, "cosigner admin: fingerprint computation failed");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("fingerprint: {e}"),
                )
                    .into_response()
            })?;
            if let Some((idx, op)) = app_state
                .admin_operators
                .iter()
                .enumerate()
                .find(|(_, o)| o.cert_fingerprint.as_deref() == Some(&fp))
            {
                let operator_id = idx as i64;
                let token = create_session(&app_state, &op.name, op.role, operator_id)
                    .await
                    .map_err(|e| {
                        tracing::error!(error = %e, "cosigner admin: session creation failed");
                        (StatusCode::INTERNAL_SERVER_ERROR, format!("session: {e}")).into_response()
                    })?;
                tracing::info!(operator = %op.name, role = %op.role, "cosigner admin: mTLS cert accepted, session created");
                return Ok(OperatorContext {
                    name: op.name.clone(),
                    role: op.role.clone(),
                    operator_id,
                    session_token: Some(token),
                });
            }
            // Cert presented but not registered.
            tracing::warn!(fingerprint = %fp, "cosigner admin: mTLS cert not registered as operator");
            return Err((
                StatusCode::UNAUTHORIZED,
                "client certificate not registered as operator",
            )
                .into_response());
        }

        tracing::warn!("cosigner admin: request with no authentication");
        Err((
            StatusCode::UNAUTHORIZED,
            "authentication required (Bearer token or mTLS)",
        )
            .into_response())
    }
}

// ── Route helpers ─────────────────────────────────────────────────────────────

fn forbidden(detail: &str) -> Response {
    (
        StatusCode::FORBIDDEN,
        Json(json!({
            "status": 403,
            "detail": detail,
        })),
    )
        .into_response()
}

// ── Route handlers ────────────────────────────────────────────────────────────

/// `POST /admin/session`
///
/// Authenticate and return a session token.  The operator is identified via
/// the `OperatorContext` extractor (mTLS cert or session token).
pub async fn post_session(
    operator: OperatorContext,
    State(state): State<Arc<AppState>>,
) -> Response {
    let ttl_secs = state.admin_session_ttl_secs;
    let expires_unix = crate::util::unix_now() + ttl_secs as i64;
    let gt = synta::GeneralizedTime::from_unix(expires_unix).unwrap_or_else(|| {
        tracing::warn!("expires_unix out of GeneralizedTime range; falling back to epoch");
        synta::GeneralizedTime::from_unix(0).unwrap()
    });
    let expires_at = format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        gt.year, gt.month, gt.day, gt.hour, gt.minute, gt.second
    );
    let token = operator.session_token.unwrap_or_default();
    (
        StatusCode::OK,
        Json(json!({
            "session_token": token,
            "role": operator.role.as_str(),
            "expires_at": expires_at,
        })),
    )
        .into_response()
}

/// `DELETE /admin/session`
///
/// Invalidate the current session token.
pub async fn delete_session(
    operator: OperatorContext,
    State(state): State<Arc<AppState>>,
) -> Response {
    if let Some(token) = &operator.session_token {
        invalidate_session(&state, token).await;
    }
    StatusCode::NO_CONTENT.into_response()
}

/// `GET /admin/status`
///
/// Simple liveness check.  All authenticated operators may call this.
pub async fn get_status(
    _operator: OperatorContext,
    State(state): State<Arc<AppState>>,
) -> Response {
    let uptime_secs = state.startup_time.elapsed().as_secs();
    (
        StatusCode::OK,
        Json(json!({
            "status": "ok",
            "uptime_secs": uptime_secs,
        })),
    )
        .into_response()
}

/// `GET /admin/stats`
///
/// Signing statistics.  All authenticated operators may call this.
pub async fn get_stats(_operator: OperatorContext, State(state): State<Arc<AppState>>) -> Response {
    let uptime_secs = state.startup_time.elapsed().as_secs();
    let (checkpoints_signed, last_checkpoint_at) = {
        let stats = state
            .signing_stats
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let ts_str = stats
            .1
            .and_then(|ts| synta::GeneralizedTime::from_unix(ts))
            .map(|gt| {
                format!(
                    "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
                    gt.year, gt.month, gt.day, gt.hour, gt.minute, gt.second
                )
            })
            .unwrap_or_default();
        (stats.0, ts_str)
    };
    (
        StatusCode::OK,
        Json(json!({
            "uptime_secs": uptime_secs,
            "checkpoints_signed": checkpoints_signed,
            "last_checkpoint_at": last_checkpoint_at,
        })),
    )
        .into_response()
}

/// `GET /admin/config`
///
/// Returns a redacted view of the cosigner configuration.
/// Only accessible to the `administrator` role.
pub async fn get_config(operator: OperatorContext, State(state): State<Arc<AppState>>) -> Response {
    if operator.role != CosignerRole::Administrator {
        return forbidden("administrator role required");
    }
    let operator_names: Vec<_> = state
        .admin_operators
        .iter()
        .map(|o| json!({"name": o.name, "role": o.role.as_str()}))
        .collect();
    (
        StatusCode::OK,
        Json(json!({
            "operators": operator_names,
            "session_ttl_secs": state.admin_session_ttl_secs,
        })),
    )
        .into_response()
}
