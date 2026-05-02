//! Admin routes and operator authentication for akamu-cosigner.
//!
//! Operators are identified by client certificate fingerprint or (optionally)
//! GSSAPI Kerberos principal, as registered in `[[admin.operators]]` in the
//! cosigner TOML config.  A successful authentication issues an in-memory
//! session token with configurable TTL.
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

use crate::state::{AppState, CosignerSession};

// ── PeerClientCert extension (injected by TLS accept loop) ───────────────────

/// DER-encoded client certificate leaf, injected into request extensions by
/// the TLS accept loop when the client presents a certificate.
#[derive(Clone)]
pub struct PeerClientCert(pub Vec<u8>);

// ── Token and fingerprint helpers ─────────────────────────────────────────────

pub fn generate_token() -> Result<String, String> {
    let mut bytes = [0u8; 32];
    getrandom::getrandom(&mut bytes).map_err(|e| format!("getrandom: {e}"))?;
    Ok(native_ossl::util::hex_encode(&bytes))
}

pub fn sha256_hex(data: &[u8]) -> Result<String, String> {
    use native_ossl::digest::DigestAlg;
    let alg = DigestAlg::fetch(c"SHA2-256", None).map_err(|e| format!("DigestAlg: {e}"))?;
    let mut ctx = alg.new_context().map_err(|e| format!("DigestCtx: {e}"))?;
    ctx.update(data).map_err(|e| format!("update: {e}"))?;
    let mut out = [0u8; 32];
    ctx.finish(&mut out).map_err(|e| format!("finish: {e}"))?;
    Ok(native_ossl::util::hex_encode(&out))
}

// ── Session management ────────────────────────────────────────────────────────

pub fn create_session(state: &AppState, name: &str, role: &str) -> Result<String, String> {
    let token = generate_token()?;
    let now = std::time::Instant::now();
    let mut sessions = state.admin_sessions.lock().unwrap();
    sessions.insert(
        token.clone(),
        CosignerSession {
            name: name.to_string(),
            role: role.to_string(),
            created_at: now,
            last_active_at: now,
        },
    );
    Ok(token)
}

pub fn lookup_session(state: &AppState, token: &str) -> Option<(String, String)> {
    let ttl = std::time::Duration::from_secs(state.admin_session_ttl_secs);
    let now = std::time::Instant::now();
    let mut sessions = state.admin_sessions.lock().unwrap();
    // Sweep sessions that have been idle longer than the TTL.
    sessions.retain(|_, s| now.duration_since(s.last_active_at) < ttl);
    if let Some(s) = sessions.get_mut(token) {
        s.last_active_at = now;
        return Some((s.name.clone(), s.role.clone()));
    }
    None
}

pub fn invalidate_session(state: &AppState, token: &str) {
    state.admin_sessions.lock().unwrap().remove(token);
}

// ── OperatorContext extractor ─────────────────────────────────────────────────

/// Authenticated operator extracted from the request.
pub struct OperatorContext {
    pub name: String,
    pub role: String,
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
                    if let Some((name, role)) = lookup_session(&app_state, token) {
                        return Ok(OperatorContext {
                            name,
                            role,
                            session_token: Some(token.to_string()),
                        });
                    }
                    return Err((StatusCode::UNAUTHORIZED, "session expired or invalid").into_response());
                }
            }
        }

        // Path 2: mTLS client certificate fingerprint.
        if let Some(ext) = parts.extensions.get::<PeerClientCert>() {
            let fp = sha256_hex(&ext.0).map_err(|e| {
                (StatusCode::INTERNAL_SERVER_ERROR, format!("fingerprint: {e}")).into_response()
            })?;
            if let Some(op) = app_state
                .admin_operators
                .iter()
                .find(|o| o.cert_fingerprint.as_deref() == Some(&fp))
            {
                let token = create_session(&app_state, &op.name, &op.role).map_err(|e| {
                    (StatusCode::INTERNAL_SERVER_ERROR, format!("session: {e}")).into_response()
                })?;
                return Ok(OperatorContext {
                    name: op.name.clone(),
                    role: op.role.clone(),
                    session_token: Some(token),
                });
            }
            // Cert presented but not registered.
            return Err((StatusCode::UNAUTHORIZED, "client certificate not registered as operator").into_response());
        }

        Err((StatusCode::UNAUTHORIZED, "authentication required (Bearer token or mTLS)").into_response())
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
    let gt = synta::GeneralizedTime::from_unix(expires_unix)
        .unwrap_or_else(|| synta::GeneralizedTime::from_unix(0).unwrap());
    let expires_at = format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        gt.year, gt.month, gt.day, gt.hour, gt.minute, gt.second
    );
    let token = operator.session_token.unwrap_or_default();
    (
        StatusCode::OK,
        Json(json!({
            "session_token": token,
            "role": operator.role,
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
        invalidate_session(&state, token);
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
pub async fn get_stats(
    _operator: OperatorContext,
    State(state): State<Arc<AppState>>,
) -> Response {
    let uptime_secs = state.startup_time.elapsed().as_secs();
    let checkpoints_signed = state
        .checkpoints_signed
        .load(std::sync::atomic::Ordering::Relaxed);
    let last_checkpoint_at = state
        .last_checkpoint_at
        .lock()
        .unwrap()
        .map(|ts| {
            synta::GeneralizedTime::from_unix(ts)
                .map(|gt| {
                    format!(
                        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
                        gt.year, gt.month, gt.day, gt.hour, gt.minute, gt.second
                    )
                })
                .unwrap_or_else(|| "1970-01-01T00:00:00Z".to_string())
        })
        .unwrap_or_default();
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
/// Restricted to `administrator` role.
pub async fn get_config(
    operator: OperatorContext,
    State(state): State<Arc<AppState>>,
) -> Response {
    if operator.role != "administrator" {
        return forbidden("administrator role required");
    }
    let operator_names: Vec<_> = state
        .admin_operators
        .iter()
        .map(|o| json!({"name": o.name, "role": o.role}))
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
