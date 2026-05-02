//! Operator authentication and session management for the admin interface.
//!
//! # Three authentication paths
//!
//! 1. **`Authorization: Bearer <token>`** — looks up the token in the in-memory
//!    session store, updates `last_active_at`, and returns the cached context.
//!
//! 2. **mTLS client certificate** — reads the `PeerClientCert` request extension
//!    (injected by the admin TLS accept loop), computes SHA-256 of the DER bytes,
//!    looks up the fingerprint in the `operators` table, and issues a session token
//!    for future requests.
//!
//! 3. **`Authorization: Negotiate <token>`** (GSSAPI/Kerberos) — validates the
//!    SPNEGO token via `gss_accept_sec_context`, extracts the Kerberos principal,
//!    looks up `operators.gssapi_principal`, and issues a session token.
//!
//! # Session tokens
//!
//! 32 random bytes, hex-encoded (64 chars).  Stored in `AppState::admin_sessions`
//! with an Instant timestamp.  TTL is `[admin].session_ttl_secs` (default 1 h).
//! Expired sessions are swept on every lookup.

use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::{FromRef, FromRequestParts};
use axum::http::request::Parts;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use serde_json::json;

use crate::audit::{AuditEvent, AuditEventType};
use crate::db;
use crate::state::{AdminAuthMethod, AdminSession, AppState, OperatorRole};

// ── PeerClientCert extension ──────────────────────────────────────────────────

/// DER-encoded leaf client certificate injected into request extensions by the
/// admin TLS accept loop.  Absent when the admin listener has no client-cert
/// requirement or the client presented no certificate.
#[derive(Clone)]
pub struct PeerClientCert(pub Vec<u8>);

// ── Session token generation ──────────────────────────────────────────────────

/// Generate a cryptographically random 32-byte hex-encoded session token.
fn generate_token() -> Result<String, crate::error::AcmeError> {
    let mut bytes = [0u8; 32];
    getrandom::getrandom(&mut bytes)
        .map_err(|e| crate::error::AcmeError::Internal(format!("getrandom: {e}")))?;
    Ok(native_ossl::util::hex_encode(bytes))
}

// ── SHA-256 fingerprint ───────────────────────────────────────────────────────

/// Compute the SHA-256 fingerprint of DER bytes and return it as a lowercase
/// hex string.
fn sha256_hex(data: &[u8]) -> Result<String, crate::error::AcmeError> {
    let alg = native_ossl::digest::DigestAlg::fetch(c"SHA2-256", None)
        .map_err(|e| crate::error::AcmeError::Internal(format!("SHA2-256 fetch: {e}")))?;
    let mut ctx = alg
        .new_context()
        .map_err(|e| crate::error::AcmeError::Internal(format!("digest context: {e}")))?;
    ctx.update(data)
        .map_err(|e| crate::error::AcmeError::Internal(format!("digest update: {e}")))?;
    let mut out = [0u8; 32];
    ctx.finish(&mut out)
        .map_err(|e| crate::error::AcmeError::Internal(format!("digest finish: {e}")))?;
    Ok(native_ossl::util::hex_encode(out))
}

// ── Session store helpers ─────────────────────────────────────────────────────

/// Create a new session for `operator_id` and return the token.
pub async fn create_session(
    state: &AppState,
    operator_id: i64,
    name: String,
    role: OperatorRole,
    auth_method: AdminAuthMethod,
) -> Result<String, crate::error::AcmeError> {
    let token = generate_token()?;
    let session = AdminSession {
        operator_id,
        name,
        role,
        created_at: Instant::now(),
        last_active_at: Instant::now(),
        auth_method,
    };
    let store = state
        .admin_sessions
        .as_ref()
        .ok_or_else(|| crate::error::AcmeError::Internal("admin sessions store not initialised".into()))?;
    let mut map = store.lock().await;
    // Sweep expired entries while we hold the lock.
    let ttl = Duration::from_secs(
        state
            .config
            .admin
            .as_ref()
            .map(|a| a.session_ttl_secs)
            .unwrap_or(3600),
    );
    map.retain(|_, s| s.last_active_at.elapsed() < ttl);
    // Evict oldest session if cap reached (prevents unbounded growth under
    // adversarial mTLS or GSSAPI authentication floods).
    const SESSION_CAP: usize = 1000;
    if map.len() >= SESSION_CAP {
        if let Some(oldest_key) = map
            .iter()
            .min_by_key(|(_, s)| s.last_active_at)
            .map(|(k, _)| k.clone())
        {
            map.remove(&oldest_key);
        }
    }
    map.insert(token.clone(), session);
    Ok(token)
}

/// Look up a session by token.  Sweeps expired entries; updates `last_active_at`
/// on a hit.  Returns `None` when the token is absent or expired.
///
/// Token comparison uses `subtle::ConstantTimeEq` to prevent timing side-channels
/// that could leak information about valid vs. invalid token prefixes.
async fn lookup_session(state: &AppState, token: &str) -> Option<(i64, String, OperatorRole, AdminAuthMethod)> {
    use subtle::ConstantTimeEq as _;
    let store = state.admin_sessions.as_ref()?;
    let ttl = Duration::from_secs(
        state
            .config
            .admin
            .as_ref()
            .map(|a| a.session_ttl_secs)
            .unwrap_or(3600),
    );
    let mut map = store.lock().await;
    map.retain(|_, s| s.last_active_at.elapsed() < ttl);
    let token_bytes = token.as_bytes();
    // Scan all entries so the iteration time is independent of position.
    let found_key = map
        .keys()
        .find(|k| {
            let kb = k.as_bytes();
            kb.len() == token_bytes.len() && kb.ct_eq(token_bytes).into()
        })
        .cloned();
    let key = found_key?;
    let session = map.get_mut(&key)?;
    session.last_active_at = Instant::now();
    Some((session.operator_id, session.name.clone(), session.role, session.auth_method))
}

/// Remove a session token from the store.  No-op if the token is unknown.
pub async fn invalidate_session(state: &AppState, token: &str) {
    if let Some(ref store) = state.admin_sessions {
        store.lock().await.remove(token);
    }
}

// ── OperatorContext extractor ─────────────────────────────────────────────────

/// Authenticated admin operator context, extracted from request parts.
///
/// Used as an axum extractor on admin routes.  On success, the caller receives
/// the operator's role and identity.  On failure, returns the appropriate HTTP
/// response (401 / 403 / 404).
#[derive(Clone)]
pub struct OperatorContext {
    pub operator_id: i64,
    pub name: String,
    pub role: OperatorRole,
    pub auth_method: AdminAuthMethod,
    /// The session token for this request (used by DELETE /admin/session).
    pub session_token: Option<String>,
}

impl<S> FromRequestParts<S> for OperatorContext
where
    S: Send + Sync,
    Arc<AppState>: FromRef<S>,
{
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Response> {
        let app = Arc::<AppState>::from_ref(state);

        // Admin must be configured.
        if app.config.admin.is_none() {
            return Err((StatusCode::NOT_FOUND, "admin API is not configured").into_response());
        }

        // Halt-flag check (FAU_STG.4 overflow or FAU_ARP.1 alarm).
        if app
            .audit
            .should_halt
            .load(std::sync::atomic::Ordering::Acquire)
        {
            return Err((
                StatusCode::SERVICE_UNAVAILABLE,
                "server halted: audit overflow or security alarm",
            )
                .into_response());
        }

        let auth_header = parts
            .headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();

        // ── Path 1: Bearer session token ──────────────────────────────────────
        if let Some(token) = auth_header.strip_prefix("Bearer ") {
            if let Some((id, name, role, method)) = lookup_session(&app, token).await {
                return Ok(OperatorContext {
                    operator_id: id,
                    name,
                    role,
                    auth_method: method,
                    session_token: Some(token.to_string()),
                });
            }
            // Token not found or expired.
            return Err((
                StatusCode::UNAUTHORIZED,
                "session token expired or invalid; please re-authenticate",
            )
                .into_response());
        }

        // ── Path 2: mTLS client certificate ──────────────────────────────────
        if let Some(PeerClientCert(der)) = parts.extensions.get::<PeerClientCert>() {
            let fingerprint = sha256_hex(der).map_err(|e| {
                tracing::error!(error = %e, "cert fingerprint computation failed");
                StatusCode::INTERNAL_SERVER_ERROR.into_response()
            })?;
            match db::operators::get_by_fingerprint(&app.db, &fingerprint).await {
                Ok(Some(op)) => {
                    let role = op.role.parse::<OperatorRole>().map_err(|_| {
                        tracing::error!(role = %op.role, "operator has unknown role");
                        StatusCode::INTERNAL_SERVER_ERROR.into_response()
                    })?;
                    // Issue a session token for subsequent requests.
                    let token =
                        create_session(&app, op.id, op.name.clone(), role, AdminAuthMethod::Cert)
                            .await
                            .map_err(|e| {
                                tracing::error!(error = %e, "session creation failed");
                                StatusCode::INTERNAL_SERVER_ERROR.into_response()
                            })?;
                    // Update last_seen_at in the DB (best-effort; ignore errors).
                    let ts = crate::util::unix_now();
                    let ts_str = {
                        let gt = synta::GeneralizedTime::from_unix(ts)
                            .unwrap_or_else(|| synta::GeneralizedTime::from_unix(0).unwrap());
                        format!(
                            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
                            gt.year, gt.month, gt.day, gt.hour, gt.minute, gt.second
                        )
                    };
                    let _ = db::operators::update_last_seen(&app.db, op.id, &ts_str).await;
                    // Record audit event (best-effort).
                    crate::audit::record_or_log(
                        &app.db,
                        &app.audit,
                        &app.audit_policy,
                        AuditEvent::success(AuditEventType::AdminLogin)
                            .with_principal(&op.name)
                            .with_detail("{\"method\":\"cert\"}"),
                    )
                    .await;
                    // Attach the new session token as a response extension so
                    // the admin router middleware can forward it in the
                    // `X-Session-Token` response header.
                    parts.extensions.insert(NewSessionToken(token.clone()));
                    return Ok(OperatorContext {
                        operator_id: op.id,
                        name: op.name,
                        role,
                        auth_method: AdminAuthMethod::Cert,
                        session_token: Some(token),
                    });
                }
                Ok(None) => {
                    crate::audit::record_or_log(
                        &app.db,
                        &app.audit,
                        &app.audit_policy,
                        AuditEvent::failure(AuditEventType::AdminLogin)
                            .with_detail("{\"method\":\"cert\",\"reason\":\"fingerprint not found\"}"),
                    )
                    .await;
                    return Err((StatusCode::FORBIDDEN, "client certificate not recognized").into_response());
                }
                Err(e) => {
                    tracing::error!(error = %e, "operator DB lookup failed");
                    return Err(StatusCode::INTERNAL_SERVER_ERROR.into_response());
                }
            }
        }

        // ── Path 3: GSSAPI/SPNEGO ─────────────────────────────────────────────
        if let Some(neg_token) = auth_header.strip_prefix("Negotiate ") {
            return authenticate_gssapi(&app, neg_token, parts).await;
        }

        // No usable credentials.
        if app.gss_cred.is_some()
            || app
                .config
                .admin
                .as_ref()
                .map(|a| a.gssapi.is_some())
                .unwrap_or(false)
        {
            // Prompt for Negotiate.
            let mut resp = (
                StatusCode::UNAUTHORIZED,
                "Authentication required: Bearer token, mTLS certificate, or Negotiate",
            )
                .into_response();
            resp.headers_mut().insert(
                axum::http::header::WWW_AUTHENTICATE,
                axum::http::HeaderValue::from_static("Negotiate"),
            );
            return Err(resp);
        }

        Err((
            StatusCode::UNAUTHORIZED,
            "Authentication required: Bearer token or mTLS client certificate",
        )
            .into_response())
    }
}

/// Marker extension set by the `OperatorContext` extractor when a new session
/// token is issued (cert or GSSAPI path).  Admin route middleware reads this
/// and injects it into the response as `X-Session-Token`.
#[derive(Clone)]
pub struct NewSessionToken(pub String);

/// Optional GSSAPI out-token (base64-encoded) to be returned in a
/// `WWW-Authenticate: Negotiate <token>` response header.
#[derive(Clone)]
pub struct GssapiOutToken(pub String);

// ── GSSAPI path ───────────────────────────────────────────────────────────────

async fn authenticate_gssapi(
    app: &Arc<AppState>,
    negotiate_token: &str,
    parts: &mut Parts,
) -> Result<OperatorContext, Response> {
    // Decode the base64 SPNEGO token.
    let token_bytes = URL_SAFE_NO_PAD
        .decode(negotiate_token)
        .or_else(|_| base64::engine::general_purpose::STANDARD.decode(negotiate_token))
        .map_err(|_| {
            (StatusCode::BAD_REQUEST, "invalid base64 in Negotiate token").into_response()
        })?;

    if token_bytes.len() > 128 * 1024 {
        return Err((StatusCode::BAD_REQUEST, "Negotiate token exceeds size limit").into_response());
    }

    // Use the admin-specific GSSAPI credential if configured, otherwise fall
    // back to the server-wide credential (`app.gss_cred`).
    let gss_cred = app.gss_cred.as_ref().ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            "GSSAPI not configured for admin interface",
        )
            .into_response()
    })?;

    // Channel binding: read from request extensions (injected by TLS accept loop).
    let channel_bindings = parts
        .extensions
        .get::<crate::tls::channel_binding::TlsServerEndpointBinding>()
        .map(|b| b.0.clone());

    // Use spawn_blocking so the synchronous GSSAPI FFI call does not block the
    // tokio executor thread.  block_in_place would panic on the single-thread
    // runtime used by #[tokio::test].
    let cred = Arc::clone(gss_cred);
    let token_bytes_owned = token_bytes.to_vec();
    let channel_bindings_owned = channel_bindings.map(|b| b.to_vec());
    let result = tokio::task::spawn_blocking(move || {
        akamu_gssapi::accept_token(
            &cred,
            &token_bytes_owned,
            channel_bindings_owned.as_deref(),
        )
    })
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "GSSAPI spawn_blocking panicked");
        StatusCode::INTERNAL_SERVER_ERROR.into_response()
    })?;

    let (out_token, principal) = match result {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(error = %e, "admin GSSAPI authentication failed");
            crate::audit::record_or_log(
                &app.db,
                &app.audit,
                &app.audit_policy,
                AuditEvent::failure(AuditEventType::AdminLogin)
                    .with_detail("{\"method\":\"gssapi\",\"reason\":\"token rejected\"}"),
            )
            .await;
            return Err((StatusCode::FORBIDDEN, "GSSAPI authentication failed").into_response());
        }
    };

    // Look up the principal in the operators table.
    match db::operators::get_by_principal(&app.db, &principal).await {
        Ok(Some(op)) => {
            let role = op.role.parse::<OperatorRole>().map_err(|_| {
                tracing::error!(role = %op.role, "operator has unknown role");
                StatusCode::INTERNAL_SERVER_ERROR.into_response()
            })?;
            let token = create_session(app, op.id, op.name.clone(), role, AdminAuthMethod::Gssapi)
                .await
                .map_err(|e| {
                    tracing::error!(error = %e, "session creation failed");
                    StatusCode::INTERNAL_SERVER_ERROR.into_response()
                })?;
            let ts = crate::util::unix_now();
            let ts_str = {
                let gt = synta::GeneralizedTime::from_unix(ts)
                    .unwrap_or_else(|| synta::GeneralizedTime::from_unix(0).unwrap());
                format!(
                    "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
                    gt.year, gt.month, gt.day, gt.hour, gt.minute, gt.second
                )
            };
            let _ = db::operators::update_last_seen(&app.db, op.id, &ts_str).await;
            crate::audit::record_or_log(
                &app.db,
                &app.audit,
                &app.audit_policy,
                AuditEvent::success(AuditEventType::AdminLogin)
                    .with_principal(&op.name)
                    .with_detail("{\"method\":\"gssapi\"}"),
            )
            .await;
            parts.extensions.insert(NewSessionToken(token.clone()));
            if !out_token.is_empty() {
                let encoded = base64::engine::general_purpose::STANDARD.encode(&out_token);
                parts.extensions.insert(GssapiOutToken(encoded));
            }
            Ok(OperatorContext {
                operator_id: op.id,
                name: op.name,
                role,
                auth_method: AdminAuthMethod::Gssapi,
                session_token: Some(token),
            })
        }
        Ok(None) => {
            tracing::warn!(principal = %principal, "GSSAPI principal not registered as operator");
            crate::audit::record_or_log(
                &app.db,
                &app.audit,
                &app.audit_policy,
                AuditEvent::failure(AuditEventType::AdminLogin)
                    .with_principal(&principal)
                    .with_detail("{\"method\":\"gssapi\",\"reason\":\"principal not registered\"}"),
            )
            .await;
            Err((StatusCode::FORBIDDEN, "Kerberos principal is not a registered operator").into_response())
        }
        Err(e) => {
            tracing::error!(error = %e, "operator DB lookup failed");
            Err(StatusCode::INTERNAL_SERVER_ERROR.into_response())
        }
    }
}

// ── Session endpoint handlers ─────────────────────────────────────────────────

/// `POST /admin/session`
///
/// Authenticate and obtain a session token.  The request must carry one of:
/// - `Authorization: Bearer <existing-token>` (refresh)
/// - mTLS client certificate (via `PeerClientCert` extension)
/// - `Authorization: Negotiate <token>` (GSSAPI)
///
/// Returns:
/// ```json
/// {"session_token": "...", "role": "auditor", "expires_at": "2026-…"}
/// ```
pub async fn post_session(
    operator: OperatorContext,
    axum::extract::State(state): axum::extract::State<Arc<AppState>>,
    gssapi_out: Option<axum::extract::Extension<GssapiOutToken>>,
) -> axum::response::Response {
    let ttl_secs = state
        .config
        .admin
        .as_ref()
        .map(|a| a.session_ttl_secs)
        .unwrap_or(3600);

    let expires_unix = crate::util::unix_now() + ttl_secs as i64;
    let gt = synta::GeneralizedTime::from_unix(expires_unix)
        .unwrap_or_else(|| synta::GeneralizedTime::from_unix(0).unwrap());
    let expires_at = format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        gt.year, gt.month, gt.day, gt.hour, gt.minute, gt.second
    );

    let token = operator.session_token.as_deref().unwrap_or("");
    let mut resp = (
        StatusCode::OK,
        axum::Json(json!({
            "session_token": token,
            "role": operator.role.as_str(),
            "expires_at": expires_at,
        })),
    )
        .into_response();

    if !token.is_empty() {
        if let Ok(hv) = axum::http::HeaderValue::from_str(token) {
            resp.headers_mut().insert("X-Session-Token", hv);
        }
    }
    if let Some(axum::extract::Extension(GssapiOutToken(b64))) = gssapi_out {
        let negotiate = format!("Negotiate {b64}");
        if let Ok(hv) = axum::http::HeaderValue::from_str(&negotiate) {
            resp.headers_mut().insert("WWW-Authenticate", hv);
        }
    }
    resp
}

/// `DELETE /admin/session`
///
/// Invalidate the current session token.
pub async fn delete_session(
    operator: OperatorContext,
    axum::extract::State(state): axum::extract::State<Arc<AppState>>,
) -> impl axum::response::IntoResponse {
    if let Some(token) = &operator.session_token {
        invalidate_session(&state, token).await;
    }
    crate::audit::record_or_log(
        &state.db,
        &state.audit,
        &state.audit_policy,
        AuditEvent::success(AuditEventType::AdminLogout).with_principal(&operator.name),
    )
    .await;
    StatusCode::NO_CONTENT
}

// ── Role enforcement macro ────────────────────────────────────────────────────

/// Return a 403 response if `$ctx.role` is not one of the listed `OperatorRole`
/// variants.
///
/// Usage: `require_role!(ctx, Administrator | CaOperations);`
#[macro_export]
macro_rules! require_role {
    ($ctx:expr, $($role:ident)|+) => {{
        let allowed = false $(|| $ctx.role == $crate::state::OperatorRole::$role)+;
        if !allowed {
            return (
                axum::http::StatusCode::FORBIDDEN,
                axum::Json(serde_json::json!({
                    "status": 403,
                    "detail": "insufficient role for this operation",
                })),
            ).into_response();
        }
    }};
}
