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
use synta_certificate::HmacProvider as _;

use crate::audit::{AuditEvent, AuditEventType};
use crate::config::{AdminProxyAuthConfig, ProxyHeaderFormat};
use crate::db;
use crate::state::{AdminAuthMethod, AdminSession, AppState, OperatorRole};

// ── Lockout helpers (FIA_AFL.1) ───────────────────────────────────────────────

/// Check whether `op` is currently locked and return a 403 error response if so.
#[allow(clippy::result_large_err)]
fn check_lockout(op: &db::operators::OperatorRow) -> Result<(), Response> {
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

// ── PeerClientCert extension ──────────────────────────────────────────────────

/// DER-encoded leaf client certificate injected into request extensions by the
/// admin TLS accept loop.  Absent when the admin listener has no client-cert
/// requirement or the client presented no certificate.
#[derive(Clone)]
pub struct PeerClientCert(pub Vec<u8>);

// ── Session token generation ──────────────────────────────────────────────────

/// Generate a cryptographically random 32-byte hex-encoded session token.
pub fn generate_token() -> Result<String, String> {
    let mut bytes = [0u8; 32];
    native_ossl::rand::Rand::fill(&mut bytes).map_err(|e| format!("getrandom: {e}"))?;
    Ok(native_ossl::util::hex_encode(bytes))
}

// ── Session store helpers ─────────────────────────────────────────────────────

/// Constant-time lookup of `token` among the keys of `map`.
///
/// Uses `subtle::ConstantTimeEq` to prevent timing side-channels.  Residual:
/// `find()` short-circuits on the first match, leaking the map position.
/// HashMap iteration order is randomised by the std hasher; this residual is
/// accepted.
pub fn find_session_token<V>(
    map: &std::collections::HashMap<String, V>,
    token: &str,
) -> Option<String> {
    use subtle::ConstantTimeEq as _;
    let token_bytes = token.as_bytes();
    map.keys()
        .find(|k| {
            let kb = k.as_bytes();
            kb.len() == token_bytes.len() && kb.ct_eq(token_bytes).into()
        })
        .cloned()
}

/// Create a new session for `operator_id` and return the token.
pub async fn create_session(
    state: &AppState,
    operator_id: i64,
    name: String,
    role: OperatorRole,
    ca_id: String,
    auth_method: AdminAuthMethod,
) -> Result<String, crate::error::AcmeError> {
    let token = generate_token().map_err(crate::error::AcmeError::Internal)?;
    let session = AdminSession {
        operator_id,
        name: akamu_util::SecretBuffer::from_string(name),
        role,
        ca_id,
        created_at: Instant::now(),
        last_active_at: Instant::now(),
        auth_method,
    };
    let store = state.admin_sessions.as_ref().ok_or_else(|| {
        crate::error::AcmeError::Internal("admin sessions store not initialised".into())
    })?;
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

/// Result of a session token lookup.
enum SessionLookup {
    /// Session is valid and active; contains operator details.
    Active(i64, String, OperatorRole, String, AdminAuthMethod),
    /// Session exists but is locked due to inactivity (FTA_SSL_EXT.1).
    Locked,
    /// Token is absent, expired, or invalid.
    NotFound,
}

/// Look up a session by token.  Sweeps expired entries; updates `last_active_at`
/// on a hit.  Returns [`SessionLookup::Locked`] when the session is idle longer
/// than `session_lock_secs` but has not yet reached `session_ttl_secs`.
async fn lookup_session(state: &AppState, token: &str) -> SessionLookup {
    let store = match state.admin_sessions.as_ref() {
        Some(s) => s,
        None => return SessionLookup::NotFound,
    };
    let admin = state.config.admin.as_ref();
    let ttl = Duration::from_secs(admin.map(|a| a.session_ttl_secs).unwrap_or(3600));
    let lock_secs = admin.map(|a| a.session_lock_secs).unwrap_or(900);
    let lock_threshold = Duration::from_secs(lock_secs);

    let mut map = store.lock().await;
    map.retain(|_, s| s.last_active_at.elapsed() < ttl);
    let key = match find_session_token(&map, token) {
        Some(k) => k,
        None => return SessionLookup::NotFound,
    };
    let session = match map.get_mut(&key) {
        Some(s) => s,
        None => return SessionLookup::NotFound,
    };

    if session.last_active_at.elapsed() >= lock_threshold {
        return SessionLookup::Locked;
    }

    session.last_active_at = Instant::now();
    SessionLookup::Active(
        session.operator_id,
        session.name.to_string_lossy(),
        session.role,
        session.ca_id.clone(),
        session.auth_method,
    )
}

/// Remove a session token from the store.  No-op if the token is unknown.
pub async fn invalidate_session(state: &AppState, token: &str) {
    if let Some(ref store) = state.admin_sessions {
        store.lock().await.remove(token);
    }
}

// ── Proxy-forwarded client certificate helpers ──────────────────────────────

/// Extract the `Cert=` value from an Envoy XFCC header.
///
/// XFCC format: elements separated by `,`, key-value pairs within each
/// element separated by `;`, key and value joined by `=`.  Values may be
/// double-quoted (and quoted values may contain commas/semicolons).
/// We take the **last** element (nearest proxy).
fn parse_xfcc_cert(header_value: &str) -> Option<String> {
    let elements = split_xfcc_elements(header_value);
    let last_element = elements.last()?;
    for pair in split_xfcc_pairs(last_element) {
        let pair = pair.trim();
        if let Some((key, value)) = pair.split_once('=') {
            if key.trim().eq_ignore_ascii_case("Cert") {
                let v = value.trim();
                let v = v
                    .strip_prefix('"')
                    .and_then(|s| s.strip_suffix('"'))
                    .unwrap_or(v);
                return Some(v.to_owned());
            }
        }
    }
    None
}

/// Split XFCC header into elements on `,`, respecting double-quoted values.
fn split_xfcc_elements(s: &str) -> Vec<String> {
    split_respecting_quotes(s, ',')
}

/// Split a single XFCC element into key-value pairs on `;`, respecting quotes.
fn split_xfcc_pairs(s: &str) -> Vec<String> {
    split_respecting_quotes(s, ';')
}

fn split_respecting_quotes(s: &str, delimiter: char) -> Vec<String> {
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    for ch in s.chars() {
        if ch == '"' {
            in_quotes = !in_quotes;
            current.push(ch);
        } else if ch == delimiter && !in_quotes {
            parts.push(std::mem::take(&mut current));
        } else {
            current.push(ch);
        }
    }
    parts.push(current);
    parts
}

/// Maximum size of a proxy-forwarded certificate header (64 KiB).
const MAX_PROXY_CERT_HEADER_LEN: usize = 64 * 1024;

/// Try to extract a DER-encoded client certificate from a proxy-forwarded
/// header.  Returns `Ok(None)` when no cert is available (peer untrusted or
/// header absent).  Returns `Err(400)` when the header is present but
/// malformed.
#[allow(clippy::result_large_err)]
fn extract_proxy_cert(
    parts: &Parts,
    proxy_cfg: &AdminProxyAuthConfig,
) -> Result<Option<Vec<u8>>, Response> {
    let peer_addr = match parts
        .extensions
        .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
    {
        Some(ci) => ci.0,
        None => {
            tracing::warn!("proxy cert auth: ConnectInfo absent from request extensions");
            return Ok(None);
        }
    };

    if !proxy_cfg.trusted_proxies.contains(&peer_addr.ip()) {
        return Ok(None);
    }

    let fmt = proxy_cfg.header_format;
    let header_name = fmt.header_name();

    let hdr = match parts.headers.get(header_name) {
        Some(v) => v,
        None => return Ok(None),
    };
    let hdr_str = hdr.to_str().map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            format!("{header_name} header is not valid UTF-8"),
        )
            .into_response()
    })?;
    if hdr_str.len() > MAX_PROXY_CERT_HEADER_LEN {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("{header_name} header exceeds size limit"),
        )
            .into_response());
    }

    let pem_value = if fmt == ProxyHeaderFormat::Xfcc {
        match parse_xfcc_cert(hdr_str) {
            Some(v) => std::borrow::Cow::Owned(v),
            None => return Ok(None),
        }
    } else {
        std::borrow::Cow::Borrowed(hdr_str)
    };

    let decoded = percent_encoding::percent_decode_str(&pem_value)
        .decode_utf8()
        .map_err(|_| {
            (
                StatusCode::BAD_REQUEST,
                format!("{header_name}: URL-decoded value is not valid UTF-8"),
            )
                .into_response()
        })?;
    let der = synta_certificate::pem_to_der(decoded.as_bytes())
        .into_iter()
        .next()
        .ok_or_else(|| {
            (
                StatusCode::BAD_REQUEST,
                format!("{header_name}: no PEM certificate found"),
            )
                .into_response()
        })?;
    Ok(Some(der))
}

/// Cheap check: does a proxy cert header exist and is the peer trusted?
/// Used for rate-limiting without full parsing.
fn has_proxy_cert_header(parts: &Parts, config: &crate::config::Config) -> bool {
    let proxy_cfg = match config.admin.as_ref().and_then(|a| a.proxy_auth.as_ref()) {
        Some(p) => p,
        None => return false,
    };
    let peer_addr = match parts
        .extensions
        .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
    {
        Some(ci) => ci.0,
        None => return false,
    };
    if !proxy_cfg.trusted_proxies.contains(&peer_addr.ip()) {
        return false;
    }
    parts
        .headers
        .contains_key(proxy_cfg.header_format.header_name())
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
    /// Meaningful for `ca_ra` (always scoped) and `ca_operations` (optionally scoped).
    /// `administrator` and `auditor` always return `None` (they are server-wide by design).
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
            let now = Instant::now();
            let cutoff = now - Duration::from_secs(300);
            let mut map = limiter.lock().await;
            let times = map.entry(ip).or_default();
            times.retain(|&t| t >= cutoff);
            if times.len() as u32 >= rate_limit {
                tracing::warn!(
                    ip = %ip,
                    attempts = times.len(),
                    limit = rate_limit,
                    "admin auth rate limit exceeded"
                );
                return Err((
                    StatusCode::TOO_MANY_REQUESTS,
                    "authentication rate limit exceeded; try again later",
                )
                    .into_response());
            }
            times.push_back(now);
            // Periodic sweep to prevent unbounded map growth under many source IPs.
            if map.len() > 500 {
                map.retain(|_, v| !v.is_empty());
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
            match lookup_session(&app, token).await {
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
                        &app,
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
                    app.record_audit(
                        AuditEvent::failure(AuditEventType::AdminLogin).with_detail(
                            json!({"method": method_str, "reason": "fingerprint not found"})
                                .to_string(),
                        ),
                    )
                    .await;
                    return Err((StatusCode::FORBIDDEN, "client certificate not recognized")
                        .into_response());
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
    // Reject oversized tokens before allocating for the base64 decode.
    // 128 KiB decoded ≈ 175 KiB base64-encoded (4/3 ratio + padding).
    const MAX_NEGOTIATE_DECODED: usize = 128 * 1024;
    const MAX_NEGOTIATE_ENCODED: usize = MAX_NEGOTIATE_DECODED * 4 / 3 + 4;
    if negotiate_token.len() > MAX_NEGOTIATE_ENCODED {
        return Err((
            StatusCode::BAD_REQUEST,
            "Negotiate token exceeds size limit",
        )
            .into_response());
    }

    // Decode the base64 SPNEGO token.
    let token_bytes = URL_SAFE_NO_PAD
        .decode(negotiate_token)
        .or_else(|_| base64::engine::general_purpose::STANDARD.decode(negotiate_token))
        .map_err(|_| {
            (StatusCode::BAD_REQUEST, "invalid base64 in Negotiate token").into_response()
        })?;

    // Use the admin-specific GSSAPI credential if configured, otherwise fall
    // back to the server-wide credential (`app.gss_cred`).
    let gss_cred = app
        .admin_gss_cred
        .as_ref()
        .or(app.gss_cred.as_ref())
        .ok_or_else(|| {
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
        akamu_gssapi::accept_token(&cred, &token_bytes_owned, channel_bindings_owned.as_deref())
    })
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "GSSAPI spawn_blocking panicked");
        StatusCode::INTERNAL_SERVER_ERROR.into_response()
    })?;

    let (out_token, principal) = match result {
        Ok(akamu_gssapi::AcceptStep::Complete {
            out_token,
            principal,
        }) => (out_token, principal),
        Ok(akamu_gssapi::AcceptStep::Continue { out_token, ctx: _ }) => {
            // Mechanism needs another round-trip.  Return 401 with the continuation
            // token; the client will re-send and a fresh context will be started.
            let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&out_token);
            let mut resp = (StatusCode::UNAUTHORIZED, "").into_response();
            let negotiate = format!("Negotiate {b64}");
            match axum::http::HeaderValue::from_str(&negotiate) {
                Ok(hv) => {
                    resp.headers_mut()
                        .insert(axum::http::header::WWW_AUTHENTICATE, hv);
                }
                Err(e) => {
                    tracing::error!(error = %e, "failed to build GSSAPI continuation WWW-Authenticate header");
                }
            }
            return Err(resp);
        }
        Err(e) => {
            tracing::warn!(error = %e, "admin GSSAPI authentication failed");
            app.record_audit(
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
            check_lockout(&op)?;
            let role = op.role.parse::<OperatorRole>().map_err(|_| {
                tracing::error!(role = %op.role, "operator has unknown role");
                StatusCode::INTERNAL_SERVER_ERROR.into_response()
            })?;
            // Successful auth — reset failure counter (FIA_AFL.1).
            if let Err(e) = db::operators::reset_failed(&app.db, op.id).await {
                tracing::warn!(error = %e, operator_id = op.id, "failed to reset auth failure counter");
            }
            let token = create_session(
                app,
                op.id,
                op.name.clone(),
                role,
                op.ca_id.clone(),
                AdminAuthMethod::Gssapi,
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
                    .with_detail(
                        serde_json::json!({"method":"gssapi","session_prefix":session_prefix})
                            .to_string(),
                    ),
            )
            .await;
            if !out_token.is_empty() {
                let encoded = base64::engine::general_purpose::STANDARD.encode(&out_token);
                parts.extensions.insert(GssapiOutToken(encoded));
            }
            Ok(OperatorContext {
                operator_id: op.id,
                name: op.name,
                role,
                ca_id: op.ca_id,
                auth_method: AdminAuthMethod::Gssapi,
                session_token: Some(token),
            })
        }
        Ok(None) => {
            tracing::warn!(principal = %principal, "GSSAPI principal not registered as operator");
            app.record_audit(
                AuditEvent::failure(AuditEventType::AdminLogin)
                    .with_principal(&principal)
                    .with_detail("{\"method\":\"gssapi\",\"reason\":\"principal not registered\"}"),
            )
            .await;
            Err((
                StatusCode::FORBIDDEN,
                "Kerberos principal is not a registered operator",
            )
                .into_response())
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

/// `POST /admin/session/eab`
///
/// Authenticate using an EAB kid + HMAC-SHA256 signature (web UI secondary login).
///
/// Request body:
/// ```json
/// {"kid": "…", "timestamp": 1234567890, "signature": "<base64url(HMAC-SHA256(kid.timestamp))>"}
/// ```
///
/// The message authenticated is `kid + "." + timestamp_as_decimal_string`.
/// Replay window: ±60 seconds; duplicate `(kid, timestamp)` pairs within that
/// window are rejected by an in-memory nonce cache.  The EAB key must have been
/// provisioned via the admin API (so that `created_by_operator_id` is known);
/// config-file keys are rejected with 403.
pub async fn post_session_eab(
    axum::extract::State(state): axum::extract::State<Arc<AppState>>,
    req: axum::extract::Request,
) -> axum::response::Response {
    use axum::extract::FromRequest as _;
    use synta_certificate::default_hmac_provider;

    if state.config.admin.is_none() {
        return StatusCode::NOT_FOUND.into_response();
    }

    let peer_ip = req
        .extensions()
        .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
        .map(|c| c.0.ip());

    let axum::extract::Json(payload) =
        match axum::extract::Json::<serde_json::Value>::from_request(req, &state).await {
            Ok(j) => j,
            Err(e) => {
                return (
                    StatusCode::BAD_REQUEST,
                    axum::Json(json!({"status": 400, "detail": e.to_string()})),
                )
                    .into_response()
            }
        };

    // ── Per-IP rate limiting (FIA_AFL.1 / FAU_ARP.1 self-DoS guard) ──────────
    if let (Some(ip_addr), Some(limiter)) = (peer_ip, state.admin_auth_limiter.as_ref()) {
        let rate_limit = state
            .config
            .admin
            .as_ref()
            .map(|a| a.auth_rate_limit)
            .unwrap_or(20);
        let now_i = Instant::now();
        let cutoff = now_i - Duration::from_secs(300);
        let mut map = limiter.lock().await;
        let times = map.entry(ip_addr).or_default();
        times.retain(|&t| t >= cutoff);
        if times.len() as u32 >= rate_limit {
            tracing::warn!(
                ip = %ip_addr,
                attempts = times.len(),
                limit = rate_limit,
                "EAB session auth rate limit exceeded"
            );
            state
                .record_audit(
                    AuditEvent::failure(AuditEventType::AdminLogin)
                        .with_detail("{\"method\":\"eab\",\"reason\":\"rate limit exceeded\"}"),
                )
                .await;
            return (
                StatusCode::TOO_MANY_REQUESTS,
                axum::Json(json!({"status": 429, "detail": "authentication rate limit exceeded; try again later"})),
            )
                .into_response();
        }
        times.push_back(now_i);
        if map.len() > 500 {
            map.retain(|_, v| !v.is_empty());
        }
    }

    let kid = match payload.get("kid").and_then(|v| v.as_str()) {
        Some(k) if !k.is_empty() => k.to_owned(),
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                axum::Json(json!({"status": 400, "detail": "kid is required"})),
            )
                .into_response();
        }
    };
    let timestamp = match payload.get("timestamp").and_then(|v| v.as_i64()) {
        Some(t) => t,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                axum::Json(json!({"status": 400, "detail": "timestamp (integer) is required"})),
            )
                .into_response();
        }
    };
    let signature_b64 = match payload.get("signature").and_then(|v| v.as_str()) {
        Some(s) if !s.is_empty() => s.to_owned(),
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                axum::Json(json!({"status": 400, "detail": "signature is required"})),
            )
                .into_response();
        }
    };

    // Replay window: ±60 seconds.
    let now = crate::util::unix_now();
    if (now - timestamp).abs() > 60 {
        return (
            StatusCode::UNAUTHORIZED,
            axum::Json(json!({
                "status": 401,
                "detail": "timestamp must be within 60 seconds of server time"
            })),
        )
            .into_response();
    }

    // Anti-replay: atomically check-and-reserve the (kid, timestamp) slot.
    // Inserting the sentinel inside the lock prevents a TOCTOU race where two
    // concurrent requests both pass the contains_key check before either commits.
    // On HMAC failure the slot is released so the client can retry; on all other
    // failures the slot remains reserved (those paths are not retryable anyway).
    const EAB_NONCE_CAP: usize = 10_000;
    let nonce_key = format!("{kid}.{timestamp}");
    if let Some(ref nonce_store) = state.eab_session_nonces {
        let mut store = nonce_store.lock().await;
        store.retain(|_, ts| (now - *ts).abs() <= 120);
        if store.contains_key(&nonce_key) {
            return (
                StatusCode::UNAUTHORIZED,
                axum::Json(json!({"status": 401, "detail": "replay detected"})),
            )
                .into_response();
        }
        if store.len() >= EAB_NONCE_CAP {
            let mut pairs: Vec<(String, i64)> = store.drain().collect();
            pairs.sort_unstable_by_key(|p| std::cmp::Reverse(p.1)); // newest first
            pairs.truncate(EAB_NONCE_CAP / 2);
            *store = pairs.into_iter().collect();
        }
        store.insert(nonce_key.clone(), now);
    }

    // Look up the EAB key.
    let eab_row = match db::eab::get_by_kid(&state.db, &kid).await {
        Ok(Some(r)) => r,
        Ok(None) => {
            state
                .record_audit(
                    AuditEvent::failure(AuditEventType::AdminLogin)
                        .with_detail("{\"method\":\"eab\",\"reason\":\"kid not found\"}"),
                )
                .await;
            return (
                StatusCode::UNAUTHORIZED,
                axum::Json(json!({"status": 401, "detail": "authentication failed"})),
            )
                .into_response();
        }
        Err(e) => {
            tracing::error!(error = %e, "post_session_eab: EAB key lookup failed");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    // Resolve operator before HMAC verify so failures can be counted toward lockout.
    enum OperatorSource {
        ById(i64),
        ByPrincipal(String),
    }
    let op_source = match (
        eab_row.created_by_operator_id,
        eab_row.bound_principal.clone(),
    ) {
        (Some(id), _) => OperatorSource::ById(id),
        (None, Some(principal)) => OperatorSource::ByPrincipal(principal),
        (None, None) => {
            state
                .record_audit(
                    AuditEvent::failure(AuditEventType::AdminLogin)
                        .with_detail("{\"method\":\"eab\",\"reason\":\"no operator owner\"}"),
                )
                .await;
            return (
                StatusCode::FORBIDDEN,
                "EAB key has no operator association and cannot be used for web UI login",
            )
                .into_response();
        }
    };

    // Look up the owning operator before HMAC verify so failures count toward lockout.
    let op = match op_source {
        OperatorSource::ById(id) => match db::operators::get_by_id(&state.db, id).await {
            Ok(Some(op)) => op,
            Ok(None) => {
                tracing::warn!(kid = %kid, operator_id = id, "EAB key owner operator not found");
                return (StatusCode::FORBIDDEN, "EAB key owner operator not found").into_response();
            }
            Err(e) => {
                tracing::error!(error = %e, "post_session_eab: operator lookup by id failed");
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
        },
        OperatorSource::ByPrincipal(ref principal) => {
            match db::operators::get_by_principal(&state.db, principal).await {
                Ok(Some(op)) => op,
                Ok(None) => {
                    tracing::warn!(
                        kid = %kid,
                        principal = %principal,
                        "EAB key bound principal has no matching operator"
                    );
                    return (
                        StatusCode::FORBIDDEN,
                        "EAB key principal is not registered as an operator",
                    )
                        .into_response();
                }
                Err(e) => {
                    tracing::error!(
                        error = %e,
                        "post_session_eab: operator lookup by principal failed"
                    );
                    return StatusCode::INTERNAL_SERVER_ERROR.into_response();
                }
            }
        }
    };

    // Check account status before HMAC computation so a locked-out operator cannot
    // probe HMAC key validity by observing response-code differences (timing oracle).
    if op.active == 0 {
        return (StatusCode::FORBIDDEN, "operator account is not active").into_response();
    }
    if let Err(resp) = check_lockout(&op) {
        return resp;
    }

    // Decode the HMAC key and the provided signature.
    let hmac_key = match URL_SAFE_NO_PAD.decode(&eab_row.hmac_key_b64u) {
        Ok(k) => k,
        Err(_) => {
            tracing::error!(kid = %kid, "EAB key: base64url decode failed");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };
    let sig_bytes = match URL_SAFE_NO_PAD
        .decode(&signature_b64)
        .or_else(|_| base64::engine::general_purpose::STANDARD.decode(&signature_b64))
    {
        Ok(b) => b,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                axum::Json(json!({"status": 400, "detail": "signature is not valid base64url"})),
            )
                .into_response();
        }
    };

    // The web UI EAB login always computes HMAC-SHA256 regardless of the key's
    // configured algorithm; reject non-sha256 keys early with a clear 400 rather
    // than letting the HMAC verify silently fail.
    let hash_alg = eab_row.alg.as_str();
    if hash_alg != "sha256" {
        if !matches!(hash_alg, "sha384" | "sha512") {
            tracing::error!(kid = %kid, alg = %hash_alg, "EAB key has unrecognised algorithm");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
        return (
            StatusCode::BAD_REQUEST,
            axum::Json(json!({"status": 400, "detail": "EAB web UI login only supports sha256 keys; this key uses a different algorithm"})),
        )
            .into_response();
    }

    // Message: "kid.timestamp"
    let message = format!("{kid}.{timestamp}");
    if default_hmac_provider()
        .hmac_verify(hash_alg, &hmac_key, message.as_bytes(), &sig_bytes)
        .is_err()
    {
        let admin_cfg = state.config.admin.as_ref();
        let max_attempts = admin_cfg.map(|a| a.max_failed_auth).unwrap_or(5);
        let lock_secs = admin_cfg.map(|a| a.lockout_duration_secs).unwrap_or(900) as i64;
        let lock_until = crate::util::unix_to_rfc3339(crate::util::unix_now() + lock_secs);
        if let Err(e) =
            db::operators::increment_failed(&state.db, op.id, max_attempts, &lock_until).await
        {
            tracing::warn!(error = %e, operator_id = op.id, "failed to record failed EAB attempt");
        }
        // Release the reserved nonce slot so the client can retry with a correct signature.
        if let Some(ref nonce_store) = state.eab_session_nonces {
            nonce_store.lock().await.remove(&nonce_key);
        }
        state
            .record_audit(
                AuditEvent::failure(AuditEventType::AdminLogin)
                    .with_detail("{\"method\":\"eab\",\"reason\":\"hmac verify failed\"}"),
            )
            .await;
        return (
            StatusCode::UNAUTHORIZED,
            axum::Json(json!({"status": 401, "detail": "authentication failed"})),
        )
            .into_response();
    }

    let role = match op.role.parse::<OperatorRole>() {
        Ok(r) => r,
        Err(_) => {
            tracing::error!(role = %op.role, "EAB operator has unknown role");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    let token = match create_session(
        &state,
        op.id,
        op.name.clone(),
        role,
        op.ca_id.clone(),
        AdminAuthMethod::Eab,
    )
    .await
    {
        Ok(t) => t,
        Err(e) => {
            tracing::error!(error = %e, "EAB session creation failed");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    let ts_str = crate::util::rfc3339_now();
    if let Err(e) = db::operators::reset_failed(&state.db, op.id).await {
        tracing::warn!(error = %e, operator_id = op.id, "failed to reset failed_attempts after EAB login");
    }
    if let Err(e) = db::operators::update_last_seen(&state.db, op.id, &ts_str).await {
        tracing::warn!(error = %e, operator_id = op.id, "failed to update last_seen_at");
    }
    let session_prefix = token.get(..8).unwrap_or(&token);
    state
        .record_audit(
            AuditEvent::success(AuditEventType::AdminLogin)
                .with_principal(&op.name)
                .with_detail(
                    serde_json::json!({
                        "method": "eab",
                        "kid": kid,
                        "session_prefix": session_prefix,
                    })
                    .to_string(),
                ),
        )
        .await;

    let admin = state.config.admin.as_ref();
    let ttl_secs = admin.map(|a| a.session_ttl_secs).unwrap_or(3600);
    let expires_unix = crate::util::unix_now() + ttl_secs as i64;
    let expires_at = crate::util::unix_to_rfc3339(expires_unix);

    let cookie =
        format!("session={token}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age={ttl_secs}");
    let mut resp = (
        StatusCode::OK,
        axum::Json(json!({
            "session_token": token,
            "role": role.as_str(),
            "operator": op.name,
            "expires_at": expires_at,
        })),
    )
        .into_response();
    if let Ok(hv) = axum::http::HeaderValue::from_str(&cookie) {
        resp.headers_mut().insert("Set-Cookie", hv);
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

/// Return a 403 response if `$ctx.role` is not one of the listed `OperatorRole`
/// variants.  Emits an `AdminAction` failure audit event before returning.
///
/// Usage: `require_role!(ctx, state, Administrator | CaOperations);`
#[macro_export]
macro_rules! require_role {
    ($ctx:expr, $state:expr, $($role:ident)|+) => {{
        let allowed = false $(|| $ctx.role == $crate::state::OperatorRole::$role)+;
        if !allowed {
            let required = concat!($(stringify!($role), " | "),+);
            let required = required.trim_end_matches(" | ");
            $state
                .record_audit(
                    $crate::audit::AuditEvent::failure($crate::audit::AuditEventType::AdminAction)
                        .with_principal($ctx.name.clone())
                        .with_detail(serde_json::json!({
                            "error": "insufficient role",
                            "required": required,
                            "actual": $ctx.role.as_str(),
                        }).to_string()),
                )
                .await;
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

// ── Role enforcement macro ────────────────────────────────────────────────────

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

    #[test]
    fn parse_xfcc_cert_basic() {
        let hdr = "Cert=ABCD";
        assert_eq!(super::parse_xfcc_cert(hdr), Some("ABCD".to_string()));
    }

    #[test]
    fn parse_xfcc_cert_quoted() {
        let hdr = r#"Cert="ABCD""#;
        assert_eq!(super::parse_xfcc_cert(hdr), Some("ABCD".to_string()));
    }

    #[test]
    fn parse_xfcc_cert_multi_element_takes_last() {
        let hdr = "Cert=FIRST,Cert=SECOND";
        assert_eq!(super::parse_xfcc_cert(hdr), Some("SECOND".to_string()));
    }

    #[test]
    fn parse_xfcc_cert_with_other_fields() {
        let hdr = "By=spiffe://foo;Hash=abc123;Cert=MYCERT;Subject=\"CN=test\"";
        assert_eq!(super::parse_xfcc_cert(hdr), Some("MYCERT".to_string()));
    }

    #[test]
    fn parse_xfcc_cert_missing_cert_key() {
        let hdr = "By=spiffe://foo;Hash=abc123";
        assert_eq!(super::parse_xfcc_cert(hdr), None);
    }

    #[test]
    fn parse_xfcc_cert_empty() {
        assert_eq!(super::parse_xfcc_cert(""), None);
    }

    #[test]
    fn parse_xfcc_cert_quoted_comma_in_subject() {
        let hdr = r#"Subject="O=Corp, Inc.";Cert=MYCERT"#;
        assert_eq!(super::parse_xfcc_cert(hdr), Some("MYCERT".to_string()));
    }

    #[test]
    fn parse_xfcc_cert_case_insensitive() {
        let hdr = "cert=ABCD";
        assert_eq!(super::parse_xfcc_cert(hdr), Some("ABCD".to_string()));
    }

    #[test]
    fn parse_xfcc_cert_quoted_semicolon_in_value() {
        let hdr = r#"Subject="CN=a;b";Cert=MYCERT"#;
        assert_eq!(super::parse_xfcc_cert(hdr), Some("MYCERT".to_string()));
    }
}
