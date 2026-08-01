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

mod eab;
mod gssapi;
mod mtls;
mod session;

use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::{FromRef, FromRequestParts};
use axum::http::request::Parts;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::json;

use crate::audit::{AuditEvent, AuditEventType};
use crate::db;
use crate::state::{AdminAuthMethod, AppState, OperatorRole};

pub use eab::post_session_eab;
pub use gssapi::GssapiOutToken;
pub use mtls::PeerClientCert;
pub use session::invalidate_session;

use gssapi::authenticate_gssapi;
use mtls::{extract_proxy_cert, has_proxy_cert_header};
use session::{create_session, lookup_session, SessionLookup};

// ── Lockout helpers (FIA_AFL.1) ───────────────────────────────────────────────

/// Check whether `op` is currently locked and return a 403 error response if so.
#[allow(clippy::result_large_err)]
pub(super) fn check_lockout(op: &db::operators::OperatorRow) -> Result<(), Response> {
    let now = crate::util::rfc3339_now();
    if db::operators::is_locked(op, &now) {
        Err((
            StatusCode::FORBIDDEN,
            axum::Json(json!({
                "error": "account_locked",
                "message": "operator account locked due to repeated authentication failures; \
                            contact an administrator to unlock"
            })),
        )
            .into_response())
    } else {
        Ok(())
    }
}

/// Check and record a rate-limited event for `ip` against the shared
/// `admin_auth_limiter` map, using a rolling 5-minute window. Returns
/// `Ok(())` when the event is within `rate_limit` and has been recorded;
/// `Err(attempts)` when the limit was already reached (the caller should
/// reject the request), with `attempts` being the count in the current
/// window for logging.
///
/// Shared by the credential-presentation gate in `resolve_operator_context`
/// (mTLS cert / GSSAPI Negotiate) and the EAB web UI login endpoint — both
/// rate-limit new credential presentations from the same per-IP map, but
/// build different responses and audit differently on rejection, so only
/// this mechanical count-and-record core is shared.
pub(super) async fn check_rate_limit(
    limiter: &crate::state::AdminAuthLimiter,
    ip: std::net::IpAddr,
    rate_limit: u32,
) -> Result<(), usize> {
    let now = Instant::now();
    let cutoff = now - Duration::from_secs(300);
    let mut map = limiter.lock().await;
    let times = map.entry(ip).or_default();
    times.retain(|&t| t >= cutoff);
    if times.len() as u32 >= rate_limit {
        return Err(times.len());
    }
    times.push_back(now);
    // Periodic sweep to prevent unbounded map growth under many source IPs.
    if map.len() > 500 {
        map.retain(|_, v| !v.is_empty());
    }
    Ok(())
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
    /// CA scope for `ca_ra` and `ca_operations` operators.  Empty string means server-wide.
    pub ca_id: String,
    pub auth_method: AdminAuthMethod,
    /// The session token for this request (used by DELETE /admin/session).
    pub session_token: Option<String>,
}

impl OperatorContext {
    /// Returns `Some(ca_id)` when this operator is scoped to a specific CA,
    /// `None` when they have server-wide access.
    ///
    /// All roles support optional CA scoping.  `ca_ra` requires a non-empty
    /// `ca_id`; all other roles treat it as optional (empty = server-wide).
    ///
    /// This is the single authoritative point for CA-scope enforcement.  All route
    /// handlers that restrict visibility to a specific CA MUST call this method.
    pub fn ca_scope(&self) -> Option<&str> {
        if self.ca_id.is_empty() {
            None
        } else {
            Some(&self.ca_id)
        }
    }
}

impl<S> FromRequestParts<S> for OperatorContext
where
    S: Send + Sync,
    Arc<AppState>: FromRef<S>,
{
    type Rejection = Response;

    /// If `admin_rbac_gate` (src/routes/admin/rbac.rs) already resolved this
    /// request's operator and inserted it into the request extensions, reuse
    /// that instead of re-running credential resolution: several of the auth
    /// paths below have side effects (session creation, rate-limit
    /// bookkeeping, audit events) that must not fire twice for one request.
    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Response> {
        if let Some(ctx) = parts.extensions.get::<OperatorContext>() {
            return Ok(ctx.clone());
        }
        let app = Arc::<AppState>::from_ref(state);
        resolve_operator_context(parts, &app).await
    }
}

/// Resolve the authenticated operator for this request via Bearer session
/// token, mTLS/proxy client certificate, or GSSAPI/SPNEGO — in that order.
///
/// Factored out of the `OperatorContext` extractor so `admin_rbac_gate` can
/// call it directly, exactly once per request.
pub(crate) async fn resolve_operator_context(
    parts: &mut Parts,
    app: &Arc<AppState>,
) -> Result<OperatorContext, Response> {
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

    // ── Auth rate limit (FAU_STG.4 / FAU_ARP.1 self-DoS guard) ───────────
    // Count new credential presentations (mTLS cert or GSSAPI Negotiate
    // token) from each source IP in a rolling 5-minute window.  Bearer
    // token reuse is not counted: it is a cheap in-memory lookup that does
    // not emit an audit event on failure.  When the per-IP limit is
    // exceeded we return 429 without recording an audit event, preventing
    // a flood of AdminLogin failures from filling the audit log and
    // triggering the FAU_STG.4 Halt policy or the FAU_ARP.1 alarm.
    let is_credential_presentation = parts.extensions.get::<PeerClientCert>().is_some()
        || has_proxy_cert_header(parts, &app.config)
        || auth_header.starts_with("Negotiate ");
    if let (true, Some(peer_addr), Some(limiter)) = (
        is_credential_presentation,
        parts
            .extensions
            .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>(),
        app.admin_auth_limiter.as_ref(),
    ) {
        let ip = peer_addr.0.ip();
        let rate_limit = app
            .config
            .admin
            .as_ref()
            .map(|a| a.auth_rate_limit)
            .unwrap_or(20);
        if let Err(attempts) = check_rate_limit(limiter, ip, rate_limit).await {
            tracing::warn!(
                ip = %ip,
                attempts,
                limit = rate_limit,
                "admin auth rate limit exceeded"
            );
            return Err((
                StatusCode::TOO_MANY_REQUESTS,
                "authentication rate limit exceeded; try again later",
            )
                .into_response());
        }
    } else if is_credential_presentation {
        static WARN_ONCE: std::sync::Once = std::sync::Once::new();
        WARN_ONCE.call_once(|| {
            tracing::warn!(
                "admin auth rate limiter inactive: ConnectInfo not available \
                     (reverse proxy?) or limiter not configured"
            );
        });
    }

    // ── Path 1: Bearer session token ──────────────────────────────────────
    if let Some(token) = auth_header.strip_prefix("Bearer ") {
        match lookup_session(app, token).await {
            SessionLookup::Active(id, name, role, ca_id, method) => {
                return Ok(OperatorContext {
                    operator_id: id,
                    name,
                    role,
                    ca_id,
                    auth_method: method,
                    session_token: Some(token.to_string()),
                });
            }
            SessionLookup::Locked => {
                return Err((
                    StatusCode::LOCKED,
                    axum::Json(serde_json::json!({
                        "error": "session_locked",
                        "message": "session locked due to inactivity; re-authenticate"
                    })),
                )
                    .into_response());
            }
            SessionLookup::NotFound => {
                return Err((
                    StatusCode::UNAUTHORIZED,
                    "session token expired or invalid; please re-authenticate",
                )
                    .into_response());
            }
        }
    }

    // ── Path 2: Client certificate (direct mTLS or proxy-forwarded) ────
    let (cert_der, cert_method) =
        if let Some(PeerClientCert(der)) = parts.extensions.get::<PeerClientCert>() {
            (Some(der.clone()), AdminAuthMethod::Cert)
        } else if let Some(proxy_cfg) = app
            .config
            .admin
            .as_ref()
            .and_then(|a| a.proxy_auth.as_ref())
        {
            match extract_proxy_cert(parts, proxy_cfg)? {
                Some(der) => (Some(der), AdminAuthMethod::CertProxy),
                None => (None, AdminAuthMethod::Cert),
            }
        } else {
            (None, AdminAuthMethod::Cert)
        };

    if let Some(der) = cert_der {
        let method_str = cert_method.as_str();
        let fingerprint = crate::util::sha256_hex(&der).map_err(|e| {
            tracing::error!(error = %e, "cert fingerprint computation failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        })?;
        match db::operators::get_by_fingerprint(&app.db, &fingerprint).await {
            Ok(Some(op)) => {
                check_lockout(&op)?;
                let role = op.role.parse::<OperatorRole>().map_err(|_| {
                    tracing::error!(role = %op.role, "operator has unknown role");
                    StatusCode::INTERNAL_SERVER_ERROR.into_response()
                })?;
                if let Err(e) = db::operators::reset_failed(&app.db, op.id).await {
                    tracing::warn!(error = %e, operator_id = op.id, "failed to reset auth failure counter");
                }
                let token = create_session(
                    app,
                    op.id,
                    op.name.clone(),
                    role,
                    op.ca_id.clone(),
                    cert_method,
                )
                .await
                .map_err(|e| {
                    tracing::error!(error = %e, "session creation failed");
                    StatusCode::INTERNAL_SERVER_ERROR.into_response()
                })?;
                let ts_str = crate::util::rfc3339_now();
                if let Err(e) = db::operators::update_last_seen(&app.db, op.id, &ts_str).await {
                    tracing::warn!(error = %e, operator_id = op.id, "failed to update last_seen_at");
                }
                let session_prefix = token.get(..8).unwrap_or(&token);
                app.record_audit(
                        AuditEvent::success(AuditEventType::AdminLogin)
                            .with_principal(&op.name)
                            .with_detail(serde_json::json!({"method":method_str,"session_prefix":session_prefix}).to_string()),
                    )
                    .await;
                return Ok(OperatorContext {
                    operator_id: op.id,
                    name: op.name,
                    role,
                    ca_id: op.ca_id,
                    auth_method: cert_method,
                    session_token: Some(token),
                });
            }
            Ok(None) => {
                app.record_audit(AuditEvent::failure(AuditEventType::AdminLogin).with_detail(
                    json!({"method": method_str, "reason": "fingerprint not found"}).to_string(),
                ))
                .await;
                return Err(
                    (StatusCode::FORBIDDEN, "client certificate not recognized").into_response()
                );
            }
            Err(e) => {
                tracing::error!(error = %e, "operator DB lookup failed");
                return Err(StatusCode::INTERNAL_SERVER_ERROR.into_response());
            }
        }
    }

    // ── Path 3: GSSAPI/SPNEGO ─────────────────────────────────────────────
    if let Some(neg_token) = auth_header.strip_prefix("Negotiate ") {
        return authenticate_gssapi(app, neg_token, parts).await;
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
    let expires_at = crate::util::unix_to_rfc3339(expires_unix);

    let token = operator.session_token.as_deref().unwrap_or("");
    let mut resp = (
        StatusCode::OK,
        axum::Json(json!({
            "session_token": token,
            "role": operator.role.as_str(),
            "operator": operator.name,
            "expires_at": expires_at,
        })),
    )
        .into_response();

    if let Some(axum::extract::Extension(GssapiOutToken(b64))) = gssapi_out {
        let negotiate = format!("Negotiate {b64}");
        match axum::http::HeaderValue::from_str(&negotiate) {
            Ok(hv) => {
                resp.headers_mut().insert("WWW-Authenticate", hv);
            }
            Err(e) => {
                tracing::error!(error = %e, "failed to build GSSAPI mutual-auth WWW-Authenticate header");
            }
        }
    }

    // Set an HttpOnly session cookie so browser-side code can also use it.
    let cookie =
        format!("session={token}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age={ttl_secs}");
    match axum::http::HeaderValue::from_str(&cookie) {
        Ok(hv) => {
            resp.headers_mut().insert("Set-Cookie", hv);
        }
        Err(e) => {
            tracing::error!(error = %e, "failed to build Set-Cookie header for admin session");
        }
    }
    resp
}

/// `DELETE /admin/session`
///
/// Invalidate the current session token and clear the session cookie.
pub async fn delete_session(
    operator: OperatorContext,
    axum::extract::State(state): axum::extract::State<Arc<AppState>>,
) -> axum::response::Response {
    if let Some(token) = &operator.session_token {
        invalidate_session(&state, token).await;
    }
    state
        .record_audit(
            AuditEvent::success(AuditEventType::AdminLogout).with_principal(&operator.name),
        )
        .await;
    // Expire the session cookie that was set on login so that the browser does
    // not retain a stale credential after logout.
    let mut resp = StatusCode::NO_CONTENT.into_response();
    resp.headers_mut().insert(
        "Set-Cookie",
        axum::http::HeaderValue::from_static(
            "session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0",
        ),
    );
    resp
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::AdminAuthMethod;

    fn ctx(role: OperatorRole, ca_id: &str) -> OperatorContext {
        OperatorContext {
            operator_id: 1,
            name: "test".into(),
            role,
            ca_id: ca_id.to_string(),
            auth_method: AdminAuthMethod::Eab,
            session_token: None,
        }
    }

    #[test]
    fn ca_scope_empty_returns_none() {
        assert_eq!(ctx(OperatorRole::CaOperations, "").ca_scope(), None);
    }

    #[test]
    fn ca_scope_nonempty_returns_some() {
        assert_eq!(ctx(OperatorRole::CaRa, "rsa").ca_scope(), Some("rsa"));
    }

    #[test]
    fn administrator_with_empty_ca_id_returns_none() {
        assert_eq!(ctx(OperatorRole::Administrator, "").ca_scope(), None);
    }

    #[test]
    fn auditor_with_empty_ca_id_returns_none() {
        assert_eq!(ctx(OperatorRole::Auditor, "").ca_scope(), None);
    }

    #[test]
    fn ca_operations_scoped_returns_some() {
        assert_eq!(
            ctx(OperatorRole::CaOperations, "primary").ca_scope(),
            Some("primary")
        );
    }
}
