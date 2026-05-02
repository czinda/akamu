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

pub async fn create_session(state: &AppState, name: &str, role: &str) -> Result<String, String> {
    let token = generate_token()?;
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
            role: role.to_string(),
            created_at: now,
            last_active_at: now,
        },
    );
    Ok(token)
}

pub async fn lookup_session(state: &AppState, token: &str) -> Option<(String, String)> {
    use subtle::ConstantTimeEq as _;
    let ttl = std::time::Duration::from_secs(state.admin_session_ttl_secs);
    let now = std::time::Instant::now();
    let mut sessions = state.admin_sessions.lock().await;
    // Sweep sessions that have been idle longer than the TTL.
    sessions.retain(|_, s| now.duration_since(s.last_active_at) < ttl);
    // Constant-time scan: compare every key so iteration time is independent
    // of where the matching entry is, preventing timing-based token guessing.
    let token_bytes = token.as_bytes();
    let found_key = sessions
        .keys()
        .find(|k| {
            let kb = k.as_bytes();
            kb.len() == token_bytes.len() && kb.ct_eq(token_bytes).into()
        })
        .cloned();
    let key = found_key?;
    let s = sessions.get_mut(&key)?;
    s.last_active_at = now;
    Some((s.name.clone(), s.role.clone()))
}

pub async fn invalidate_session(state: &AppState, token: &str) {
    state.admin_sessions.lock().await.remove(token);
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
                    if let Some((name, role)) = lookup_session(&app_state, token).await {
                        tracing::info!(operator = %name, role = %role, "cosigner admin: bearer token accepted");
                        return Ok(OperatorContext {
                            name,
                            role,
                            session_token: Some(token.to_string()),
                        });
                    }
                    tracing::warn!("cosigner admin: bearer token invalid or expired");
                    return Err((StatusCode::UNAUTHORIZED, "session expired or invalid").into_response());
                }
            }
        }

        // Path 2: mTLS client certificate fingerprint.
        if let Some(ext) = parts.extensions.get::<PeerClientCert>() {
            let fp = sha256_hex(&ext.0).map_err(|e| {
                tracing::error!(error = %e, "cosigner admin: fingerprint computation failed");
                (StatusCode::INTERNAL_SERVER_ERROR, format!("fingerprint: {e}")).into_response()
            })?;
            if let Some(op) = app_state
                .admin_operators
                .iter()
                .find(|o| o.cert_fingerprint.as_deref() == Some(&fp))
            {
                let token = create_session(&app_state, &op.name, &op.role).await.map_err(|e| {
                    tracing::error!(error = %e, "cosigner admin: session creation failed");
                    (StatusCode::INTERNAL_SERVER_ERROR, format!("session: {e}")).into_response()
                })?;
                tracing::info!(operator = %op.name, role = %op.role, "cosigner admin: mTLS cert accepted, session created");
                return Ok(OperatorContext {
                    name: op.name.clone(),
                    role: op.role.clone(),
                    session_token: Some(token),
                });
            }
            // Cert presented but not registered.
            tracing::warn!(fingerprint = %fp, "cosigner admin: mTLS cert not registered as operator");
            return Err((StatusCode::UNAUTHORIZED, "client certificate not registered as operator").into_response());
        }

        tracing::warn!("cosigner admin: request with no authentication");
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
pub async fn get_stats(
    _operator: OperatorContext,
    State(state): State<Arc<AppState>>,
) -> Response {
    let uptime_secs = state.startup_time.elapsed().as_secs();
    let (checkpoints_signed, last_checkpoint_at) = {
        let stats = state.signing_stats.lock().unwrap_or_else(|e| e.into_inner());
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex, RwLock};
    use std::time::Instant;

    use axum::body::Body;
    use axum::http::{header, Method, Request, StatusCode};
    use tower::ServiceExt;

    use synta_certificate::BackendPrivateKey;

    use crate::routes::build_router;
    use crate::state::CosignerSession;

    fn build_state() -> Arc<AppState> {
        let signing_key = BackendPrivateKey::generate_ec("P-256").unwrap();
        Arc::new(AppState {
            signing_key,
            hash_alg: "sha256".to_string(),
            // DER fields are unused by admin routes; use empty stubs.
            sig_alg_der: vec![],
            cosigner_hash_alg_der: vec![],
            cosigner_spki_der: vec![],
            challenge_tokens: Arc::new(RwLock::new(HashMap::new())),
            admin_operators: vec![],
            admin_sessions: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            admin_session_ttl_secs: 3600,
            startup_time: Instant::now(),
            signing_stats: Arc::new(Mutex::new((0, None))),
        })
    }

    async fn seed_session(state: &Arc<AppState>, token: &str, role: &str) {
        state.admin_sessions.lock().await.insert(
            token.to_string(),
            CosignerSession {
                name: "test-op".to_string(),
                role: role.to_string(),
                created_at: Instant::now(),
                last_active_at: Instant::now(),
            },
        );
    }

    async fn get_with_bearer(router: &axum::Router, path: &str, token: &str) -> axum::response::Response {
        let req = Request::builder()
            .method(Method::GET)
            .uri(path)
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap();
        router.clone().oneshot(req).await.unwrap()
    }

    #[tokio::test]
    async fn get_status_returns_ok() {
        let state = build_state();
        let router = build_router(Arc::clone(&state));
        seed_session(&state, "tok-status", "auditor").await;

        let resp = get_with_bearer(&router, "/admin/status", "tok-status").await;
        assert_eq!(resp.status(), StatusCode::OK, "GET /admin/status must return 200");

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["status"], "ok", "status field must be \"ok\"");
        assert!(json["uptime_secs"].is_u64(), "uptime_secs must be a number");
    }

    #[tokio::test]
    async fn get_stats_returns_counters() {
        let state = build_state();
        let router = build_router(Arc::clone(&state));
        seed_session(&state, "tok-stats", "auditor").await;

        let resp = get_with_bearer(&router, "/admin/stats", "tok-stats").await;
        assert_eq!(resp.status(), StatusCode::OK, "GET /admin/stats must return 200");

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(json["uptime_secs"].is_u64(), "uptime_secs must be present");
        assert!(json["checkpoints_signed"].is_u64(), "checkpoints_signed must be present");
        assert_eq!(json["checkpoints_signed"], 0, "fresh server must have 0 checkpoints signed");
    }

    #[tokio::test]
    async fn post_session_with_bearer_returns_token() {
        let state = build_state();
        let router = build_router(Arc::clone(&state));
        seed_session(&state, "tok-session", "administrator").await;

        let req = Request::builder()
            .method(Method::POST)
            .uri("/admin/session")
            .header(header::AUTHORIZATION, "Bearer tok-session")
            .body(Body::empty())
            .unwrap();
        let resp = router.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "POST /admin/session must return 200");

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["session_token"], "tok-session", "session_token in body must match Bearer token");
        assert_eq!(json["role"], "administrator", "role in body must match session role");
        assert!(json["expires_at"].is_string(), "expires_at must be a string");
    }

    #[tokio::test]
    async fn unauthenticated_request_returns_401() {
        let state = build_state();
        let router = build_router(Arc::clone(&state));

        let req = Request::builder()
            .method(Method::GET)
            .uri("/admin/status")
            .body(Body::empty())
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "unauthenticated request must return 401");
    }
}
