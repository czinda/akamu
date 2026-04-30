//! Axum extractors for authenticated request context.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::{ConnectInfo, FromRef, FromRequestParts};
use axum::http::request::Parts;
use axum::http::{HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use base64::Engine as _;

use crate::state::AppState;

// ── RemoteUser ────────────────────────────────────────────────────────────────

/// Authenticated remote principal extracted from either a trusted proxy header
/// or a standalone GSSAPI/SPNEGO token exchange.
///
/// # Proxy mode
///
/// When the connecting IP is listed in `[server] trusted_proxies`, the value of
/// the `X-Remote-User` request header is accepted as the authenticated principal.
/// Requests from untrusted IPs never have the header honoured.
///
/// # Standalone GSSAPI mode
///
/// When `[server.gssapi]` is configured, an `Authorization: Negotiate <token>`
/// header is validated via `gss_accept_sec_context`.  The client must obtain a
/// service ticket for the configured HTTP service principal beforehand.
///
/// If neither source is configured or the credentials are absent/invalid, the
/// extractor returns an appropriate HTTP error response.
///
/// # HTTP responses on failure
///
/// | Condition | Status | Body |
/// |-----------|--------|------|
/// | Trusted proxy, header absent or empty | 401 | `X-Remote-User header required` |
/// | GSSAPI configured, no `Authorization` header | 401 | `WWW-Authenticate: Negotiate` challenge |
/// | GSSAPI configured, token invalid or expired | 403 | `GSSAPI authentication failed` |
/// | Neither mechanism configured | 403 | configuration error message |
pub struct RemoteUser(pub String);

impl<S> FromRequestParts<S> for RemoteUser
where
    S: Send + Sync,
    Arc<AppState>: FromRef<S>,
{
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Response> {
        let app = Arc::<AppState>::from_ref(state);

        // ── Proxy path ────────────────────────────────────────────────────────
        if !app.config.server.trusted_proxies.is_empty() {
            if let Some(ConnectInfo(peer)) = parts.extensions.get::<ConnectInfo<SocketAddr>>() {
                let peer_ip = peer.ip();
                // Map IPv4-mapped IPv6 addresses (::ffff:a.b.c.d) to plain IPv4
                // so they match IPv4 CIDR entries in trusted_proxies.
                let peer_ip = match peer_ip {
                    std::net::IpAddr::V6(v6) => {
                        v6.to_ipv4_mapped()
                            .map(std::net::IpAddr::V4)
                            .unwrap_or(std::net::IpAddr::V6(v6))
                    }
                    v4 => v4,
                };
                let trusted = app
                    .config
                    .server
                    .trusted_proxies
                    .iter()
                    .any(|net| net.contains(&peer_ip));
                if trusted {
                    return match parts
                        .headers
                        .get("x-remote-user")
                        .and_then(|v| v.to_str().ok())
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                    {
                        Some(user) => Ok(RemoteUser(user.to_owned())),
                        None => Err(unauthorized("X-Remote-User header required")),
                    };
                }
            }
        }

        // ── Standalone GSSAPI path ────────────────────────────────────────────
        if let Some(ref cred) = app.gss_cred {
            return negotiate(parts, cred);
        }

        // Neither proxy headers nor GSSAPI is configured.
        Err((
            StatusCode::FORBIDDEN,
            "no authentication mechanism configured for this endpoint",
        )
            .into_response())
    }
}

// ── SPNEGO helpers ────────────────────────────────────────────────────────────

/// Attempt SPNEGO token validation from `Authorization: Negotiate <base64>`.
///
/// Returns the authenticated principal on success, or an HTTP response (401
/// challenge or 403 rejection) on failure.
fn negotiate(
    parts: &mut Parts,
    cred: &akamu_gssapi::GssServerCred,
) -> Result<RemoteUser, Response> {
    let auth = parts
        .headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    // No Authorization header — send a standard SPNEGO challenge.
    if auth.is_empty() {
        return Err(negotiate_challenge());
    }

    let token_b64 = match auth.strip_prefix("Negotiate ") {
        Some(t) => t,
        None => return Err(negotiate_challenge()),
    };

    let token = match base64::engine::general_purpose::STANDARD.decode(token_b64) {
        Ok(t) => t,
        Err(_) => {
            return Err((StatusCode::BAD_REQUEST, "malformed Negotiate token").into_response())
        }
    };

    match akamu_gssapi::accept_token(cred, &token) {
        Ok((out_token, principal)) => {
            // Attach the mutual-auth response token to the *request* extensions so
            // the route handler can forward it via WWW-Authenticate if desired.
            // For the stub EAB endpoint we don't strictly need this, but it allows
            // the infrastructure to support mutual authentication later.
            if !out_token.is_empty() {
                let encoded = base64::engine::general_purpose::STANDARD.encode(&out_token);
                let hv = HeaderValue::from_str(&format!("Negotiate {encoded}"))
                    .unwrap_or_else(|_| HeaderValue::from_static("Negotiate"));
                parts.extensions.insert(NegotiateResponse(hv));
            }
            Ok(RemoteUser(principal))
        }
        Err(e) => {
            tracing::debug!("GSSAPI accept_token failed: {e}");
            Err((StatusCode::FORBIDDEN, "GSSAPI authentication failed").into_response())
        }
    }
}

/// Request extension carrying the optional mutual-auth token from a successful
/// SPNEGO exchange.
///
/// When `gss_accept_sec_context` produces an output token (i.e. the client
/// requested mutual authentication), this extension is inserted into the
/// request's extension map.  Route handlers that wish to return the token to
/// the client can read it and emit a `WWW-Authenticate: Negotiate <base64>`
/// response header.
///
/// The inner [`HeaderValue`] is already formatted as `"Negotiate <base64>"` and
/// can be inserted directly into the response headers.
#[derive(Clone)]
pub struct NegotiateResponse(pub HeaderValue);

/// Build a `401 Unauthorized` response with a `WWW-Authenticate: Negotiate`
/// header, prompting the client to begin a SPNEGO exchange.
fn negotiate_challenge() -> Response {
    let mut resp = (StatusCode::UNAUTHORIZED, "").into_response();
    resp.headers_mut()
        .insert("WWW-Authenticate", HeaderValue::from_static("Negotiate"));
    resp
}

/// Build a plain `401 Unauthorized` response with a text body.
fn unauthorized(msg: &'static str) -> Response {
    (StatusCode::UNAUTHORIZED, msg).into_response()
}
