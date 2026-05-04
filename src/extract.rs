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
/// | GSSAPI token exceeds 128 KiB | 400 | `Negotiate token exceeds size limit` |
/// | GSSAPI configured, token invalid or expired | 403 | `GSSAPI authentication failed` |
/// | GSSAPI context lacks `GSS_C_REPLAY_FLAG` | 403 | `GSSAPI authentication failed` |
/// | Neither mechanism configured | 404 | `no authentication mechanism configured for this endpoint` |
/// | `trusted_proxies` set but `ConnectInfo` absent | 500 | server misconfiguration message |
pub struct RemoteUser(pub String);

impl<S> FromRequestParts<S> for RemoteUser
where
    S: Send + Sync,
    Arc<AppState>: FromRef<S>,
{
    type Rejection = Response;

    #[allow(clippy::result_large_err)]
    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Response> {
        let app = Arc::<AppState>::from_ref(state);

        // ── Proxy path ────────────────────────────────────────────────────────
        if !app.config.server.trusted_proxies.is_empty() {
            let Some(ConnectInfo(peer)) = parts.extensions.get::<ConnectInfo<SocketAddr>>() else {
                tracing::warn!(
                    "trusted_proxies is configured but ConnectInfo is absent from request \
                     extensions; router may not be wired with into_make_service_with_connect_info"
                );
                return Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "server misconfiguration: peer address unavailable",
                )
                    .into_response());
            };
            {
                let peer_ip = peer.ip();
                // Map IPv4-mapped IPv6 addresses (::ffff:a.b.c.d) to plain IPv4
                // so they match IPv4 CIDR entries in trusted_proxies.
                let peer_ip = match peer_ip {
                    std::net::IpAddr::V6(v6) => v6
                        .to_ipv4_mapped()
                        .map(std::net::IpAddr::V4)
                        .unwrap_or(std::net::IpAddr::V6(v6)),
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
            // accept_token invokes gss_accept_sec_context, a blocking C FFI call
            // that may perform KDC network I/O.  block_in_place keeps the work on
            // the current Tokio thread without consuming a spawn_blocking slot, and
            // avoids parking the executor while the FFI call is in progress.
            return tokio::task::block_in_place(|| negotiate(parts, cred));
        }

        // Neither proxy headers nor GSSAPI is configured.
        Err((
            StatusCode::NOT_FOUND,
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
#[allow(clippy::result_large_err)]
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

    // RFC 7235 §2.1 / RFC 4559 §3: auth-scheme is case-insensitive.
    let token_b64 = if auth.len() > 10 && auth[..10].eq_ignore_ascii_case("Negotiate ") {
        &auth[10..]
    } else {
        return Err(negotiate_challenge());
    };

    let token = match base64::engine::general_purpose::STANDARD.decode(token_b64) {
        Ok(t) => t,
        Err(_) => {
            return Err((StatusCode::BAD_REQUEST, "malformed Negotiate token").into_response())
        }
    };

    const MAX_NEGOTIATE_TOKEN_BYTES: usize = 128 * 1024;
    if token.len() > MAX_NEGOTIATE_TOKEN_BYTES {
        return Err((
            StatusCode::BAD_REQUEST,
            "Negotiate token exceeds size limit",
        )
            .into_response());
    }

    let binding: Option<&[u8]> = parts
        .extensions
        .get::<crate::tls::channel_binding::TlsServerEndpointBinding>()
        .map(|b| b.0.as_slice());

    match akamu_gssapi::accept_token(cred, &token, binding) {
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
            tracing::warn!("GSSAPI accept_token failed: {e}");
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
