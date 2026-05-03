//! http-01 challenge validation (RFC 8555 §8.3).
//!
//! Fetches `http://{domain}/.well-known/acme-challenge/{token}` and verifies
//! that the response body (trimmed) equals the key authorization string.
//! Up to 10 HTTP redirects are followed, including redirects to HTTPS targets.

use http_body_util::{BodyExt, Limited};
use hyper::header::LOCATION;
use hyper::Uri;

use crate::error::AcmeError;
use crate::state::ValidationClient;

/// Maximum number of 3xx redirects to follow before giving up.
const MAX_REDIRECTS: usize = 10;

/// Returns `true` when `ip` is a private, loopback, link-local, or otherwise
/// non-globally-routable address that must not be reached via a redirect.
fn is_blocked_ip(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => {
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
        }
        std::net::IpAddr::V6(v6) => {
            if v6.is_loopback() || v6.is_unspecified() {
                return true;
            }
            let segs = v6.segments();
            // Link-local fe80::/10
            if (segs[0] & 0xffc0) == 0xfe80 {
                return true;
            }
            // Unique local fc00::/7
            if (segs[0] & 0xfe00) == 0xfc00 {
                return true;
            }
            // IPv4-mapped ::ffff:0:0/96 — inherit IPv4 classification
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_blocked_ip(std::net::IpAddr::V4(v4));
            }
            false
        }
    }
}

/// Resolve `host` and reject it when any address is private/loopback, unless
/// `allow_private_ips` is set (test environments only).
///
/// `host` may be a bare hostname, an IPv4 literal, or an IPv6 literal
/// enclosed in `[`…`]` as it appears in a URI authority.
async fn check_redirect_host(
    host: &str,
    allow_private_ips: bool,
    from_url: &str,
) -> Result<(), AcmeError> {
    if allow_private_ips {
        return Ok(());
    }
    // Strip IPv6 brackets added by URI formatting.
    let clean = host.trim_start_matches('[').trim_end_matches(']');

    // Try an IP literal first — no DNS needed.
    if let Ok(ip) = clean.parse::<std::net::IpAddr>() {
        if is_blocked_ip(ip) {
            return Err(AcmeError::IncorrectResponse(format!(
                "http-01: redirect from '{from_url}' targets blocked IP address {ip}"
            )));
        }
        return Ok(());
    }

    // Hostname — resolve and check every returned address.
    let addrs = tokio::net::lookup_host((clean, 80u16))
        .await
        .map_err(|e| AcmeError::Connection(format!("http-01: DNS lookup for '{clean}': {e}")))?;
    for addr in addrs {
        if is_blocked_ip(addr.ip()) {
            return Err(AcmeError::IncorrectResponse(format!(
                "http-01: redirect from '{from_url}' resolves to blocked address {} ('{clean}')",
                addr.ip()
            )));
        }
    }
    Ok(())
}

/// Validate an http-01 challenge.
///
/// * `domain`            — the identifier value (DNS name or IP address literal).
/// * `token`             — the challenge token stored in the database.
/// * `key_auth`          — `{token}.{jwk_thumbprint}` (expected response body).
/// * `port`              — TCP port to connect to (RFC 8555 §8.3 requires 80; override for testing).
/// * `allow_private_ips` — when `false`, both the initial target and any
///   redirect targets are checked against `is_blocked_ip`; RFC-1918, loopback,
///   and link-local addresses are rejected (SSRF guard).  Set to `true` only
///   in isolated test environments.
/// * `client`            — shared hyper client; reusing it avoids a TCP handshake per validation.
pub async fn validate(
    domain: &str,
    token: &str,
    key_auth: &str,
    port: u16,
    allow_private_ips: bool,
    client: &ValidationClient,
) -> Result<(), AcmeError> {
    // RFC 3986 §3.2.2: IPv6 literals must be enclosed in brackets when used
    // as a host in a URL.  An IPv6 address contains ':', so detect it that way.
    let host = if domain.contains(':') {
        format!("[{domain}]")
    } else {
        domain.to_string()
    };
    let url = if port == 80 {
        format!("http://{}/.well-known/acme-challenge/{}", host, token)
    } else {
        format!(
            "http://{}:{}/.well-known/acme-challenge/{}",
            host, port, token
        )
    };
    let mut uri: Uri = url
        .parse()
        .map_err(|e| AcmeError::Connection(format!("invalid http-01 URL '{url}': {e}")))?;

    // SSRF guard: check the initial target before making any connection.
    // check_redirect_host handles both IP literals and hostname resolution.
    if let Some(host) = uri.host() {
        check_redirect_host(host, allow_private_ips, &url).await?;
    }

    for _ in 0..=MAX_REDIRECTS {
        let current_url = uri.to_string();
        let resp = client
            .get(uri.clone())
            .await
            .map_err(|e| AcmeError::Connection(format!("http-01 GET '{current_url}': {e}")))?;

        let status = resp.status();

        if status.is_redirection() {
            let location = resp
                .headers()
                .get(LOCATION)
                .and_then(|v| v.to_str().ok())
                .ok_or_else(|| {
                    AcmeError::IncorrectResponse(format!(
                        "http-01: redirect from '{current_url}' has no valid Location header"
                    ))
                })?;

            // Resolve relative redirects against the current URI.
            let next: Uri = if location.starts_with("http://") || location.starts_with("https://") {
                location.parse().map_err(|e| {
                    AcmeError::IncorrectResponse(format!(
                        "http-01: invalid Location '{location}': {e}"
                    ))
                })?
            } else {
                // Relative reference — reconstruct using current authority + scheme.
                let authority = uri.authority().map(|a| a.as_str()).unwrap_or_default();
                let scheme = uri.scheme_str().unwrap_or("http");
                format!("{scheme}://{authority}{location}")
                    .parse()
                    .map_err(|e| {
                        AcmeError::IncorrectResponse(format!(
                            "http-01: invalid relative Location '{location}': {e}"
                        ))
                    })?
            };

            let scheme = next.scheme_str().unwrap_or("");
            if scheme != "http" && scheme != "https" {
                return Err(AcmeError::IncorrectResponse(format!(
                    "http-01: redirect target '{next}' uses unsupported scheme '{scheme}'"
                )));
            }

            // SSRF guard: reject redirects to private/loopback addresses.
            if let Some(host) = next.host() {
                check_redirect_host(host, allow_private_ips, &current_url).await?;
            }

            uri = next;
            continue;
        }

        if !status.is_success() {
            return Err(AcmeError::IncorrectResponse(format!(
                "http-01: server returned HTTP {status} for '{current_url}'"
            )));
        }

        // Key authorizations are < 200 bytes; 1 MiB is generous while still
        // bounding memory per validation attempt.  Limited aborts streaming as
        // soon as the limit is exceeded so a hostile server cannot force a full
        // allocation before the check fires.
        const MAX_BODY: usize = 1_048_576;
        let body_bytes = Limited::new(resp.into_body(), MAX_BODY)
            .collect()
            .await
            .map_err(|e| {
                // LengthLimitError is returned when the limit is hit.
                if e.is::<http_body_util::LengthLimitError>() {
                    AcmeError::IncorrectResponse(format!(
                        "http-01: response body exceeds {MAX_BODY} bytes for '{current_url}'"
                    ))
                } else {
                    AcmeError::Connection(format!("http-01 body read from '{current_url}': {e}"))
                }
            })?
            .to_bytes();

        let body = std::str::from_utf8(&body_bytes)
            .map_err(|_| AcmeError::IncorrectResponse("http-01: body is not valid UTF-8".into()))?
            .trim();

        if body != key_auth {
            return Err(AcmeError::IncorrectResponse(format!(
                "http-01: key authorization mismatch for '{current_url}'"
            )));
        }

        return Ok(());
    }

    Err(AcmeError::IncorrectResponse(format!(
        "http-01: exceeded {MAX_REDIRECTS} redirects starting from '{url}'"
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{http::StatusCode, routing::get, Router};
    use hyper_rustls::HttpsConnectorBuilder;
    use hyper_util::client::legacy::connect::HttpConnector;
    use hyper_util::client::legacy::Client;
    use hyper_util::rt::TokioExecutor;
    use tokio::net::TcpListener;

    fn test_client() -> crate::state::ValidationClient {
        let https = HttpsConnectorBuilder::new()
            .with_native_roots()
            .expect("native roots")
            .https_or_http()
            .enable_http1()
            .build();
        Client::builder(TokioExecutor::new()).build(https)
    }

    /// Start a local HTTP server with the given router and return its address.
    async fn start_server(router: Router) -> std::net::SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, router).await.ok();
        });
        addr
    }

    #[tokio::test]
    async fn validate_fails_for_unreachable_domain() {
        // Port 80 on a guaranteed-unreachable host should fail with a Connection error.
        let result = validate(
            "acme-test-nonexistent-host.invalid",
            "token",
            "key.auth",
            80,
            false,
            &test_client(),
        )
        .await;
        assert!(result.is_err(), "expected connection error");
        match result.unwrap_err() {
            AcmeError::Connection(_) => {}
            other => panic!("expected Connection error, got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn validate_success_with_correct_key_auth() {
        let addr = start_server(Router::new().route(
            "/.well-known/acme-challenge/mytoken",
            get(|| async { "mytoken.thumbprint" }),
        ))
        .await;
        let result = validate(
            "127.0.0.1",
            "mytoken",
            "mytoken.thumbprint",
            addr.port(),
            true, // test server is on loopback
            &test_client(),
        )
        .await;
        assert!(result.is_ok(), "expected Ok(()), got: {result:?}");
    }

    #[tokio::test]
    async fn validate_non_200_returns_error() {
        let addr = start_server(Router::new().route(
            "/.well-known/acme-challenge/token",
            get(|| async { StatusCode::NOT_FOUND }),
        ))
        .await;
        let result = validate(
            "127.0.0.1",
            "token",
            "expected",
            addr.port(),
            true, // test server is on loopback
            &test_client(),
        )
        .await;
        assert!(
            matches!(result, Err(AcmeError::IncorrectResponse(_))),
            "expected IncorrectResponse, got: {result:?}"
        );
    }

    #[tokio::test]
    async fn validate_body_too_large_returns_error() {
        let addr = start_server(Router::new().route(
            "/.well-known/acme-challenge/token",
            get(|| async { "x".repeat(8193) }),
        ))
        .await;
        let result = validate(
            "127.0.0.1",
            "token",
            "expected",
            addr.port(),
            true, // test server is on loopback
            &test_client(),
        )
        .await;
        assert!(
            matches!(result, Err(AcmeError::IncorrectResponse(_))),
            "expected IncorrectResponse for oversized body, got: {result:?}"
        );
    }

    #[tokio::test]
    async fn validate_key_auth_mismatch_returns_error() {
        let addr = start_server(Router::new().route(
            "/.well-known/acme-challenge/token",
            get(|| async { "wrong-auth" }),
        ))
        .await;
        let result = validate(
            "127.0.0.1",
            "token",
            "correct-auth",
            addr.port(),
            true, // test server is on loopback
            &test_client(),
        )
        .await;
        assert!(
            matches!(result, Err(AcmeError::IncorrectResponse(_))),
            "expected IncorrectResponse for mismatch, got: {result:?}"
        );
    }

    #[tokio::test]
    async fn validate_blocks_private_ip_initial_target() {
        // Direct connection to a private IP (not via redirect) must be blocked.
        let result = validate(
            "192.168.1.1",
            "token",
            "key",
            80,
            false, // SSRF guard enabled
            &test_client(),
        )
        .await;
        assert!(
            matches!(result, Err(AcmeError::IncorrectResponse(_))),
            "expected IncorrectResponse for private-IP initial target, got: {result:?}"
        );
    }

    #[tokio::test]
    async fn validate_follows_redirect_to_final_response() {
        // Server A: issues 302 → Server B; Server B: serves the key auth.
        let target_addr = start_server(Router::new().route(
            "/.well-known/acme-challenge/redir-token",
            get(|| async { "redir-token.thumbprint" }),
        ))
        .await;

        let target_port = target_addr.port();
        let redirect_router = Router::new().route(
            "/.well-known/acme-challenge/redir-token",
            get(move || async move {
                let location = format!(
                    "http://127.0.0.1:{}/.well-known/acme-challenge/redir-token",
                    target_port
                );
                (
                    StatusCode::FOUND,
                    [(axum::http::header::LOCATION, location)],
                )
            }),
        );
        let redirect_addr = start_server(redirect_router).await;

        let result = validate(
            "127.0.0.1",
            "redir-token",
            "redir-token.thumbprint",
            redirect_addr.port(),
            true, // test servers are on loopback
            &test_client(),
        )
        .await;
        assert!(
            result.is_ok(),
            "expected Ok after redirect, got: {result:?}"
        );
    }

    #[tokio::test]
    async fn validate_too_many_redirects_returns_error() {
        // Server that always redirects to itself → loop.
        let addr_holder: std::sync::Arc<tokio::sync::Mutex<Option<u16>>> =
            std::sync::Arc::new(tokio::sync::Mutex::new(None));
        let addr_holder2 = addr_holder.clone();

        let router = Router::new().route(
            "/.well-known/acme-challenge/loop-token",
            get(move || {
                let holder = addr_holder2.clone();
                async move {
                    let port = holder.lock().await.unwrap_or(80);
                    let location = format!(
                        "http://127.0.0.1:{}/.well-known/acme-challenge/loop-token",
                        port
                    );
                    (
                        StatusCode::FOUND,
                        [(axum::http::header::LOCATION, location)],
                    )
                }
            }),
        );
        let addr = start_server(router).await;
        *addr_holder.lock().await = Some(addr.port());

        let result = validate(
            "127.0.0.1",
            "loop-token",
            "key",
            addr.port(),
            true, // test server is on loopback
            &test_client(),
        )
        .await;
        assert!(
            matches!(result, Err(AcmeError::IncorrectResponse(_))),
            "expected IncorrectResponse for redirect loop, got: {result:?}"
        );
    }

    #[tokio::test]
    async fn validate_blocks_redirect_to_private_ip() {
        // The initial domain is 127.0.0.1; with the SSRF guard enabled the initial
        // IP check fires before any connection is made.  The assertion verifies
        // that a private-IP target (whether initial or redirect) is rejected.
        let addr = start_server(Router::new().route(
            "/.well-known/acme-challenge/token",
            get(|| async {
                (
                    StatusCode::FOUND,
                    [(
                        axum::http::header::LOCATION,
                        "http://169.254.169.254/latest/meta-data/",
                    )],
                )
            }),
        ))
        .await;

        let result = validate(
            "127.0.0.1",
            "token",
            "key",
            addr.port(),
            false, // SSRF guard enabled — blocks both initial and redirect targets
            &test_client(),
        )
        .await;
        assert!(
            matches!(result, Err(AcmeError::IncorrectResponse(_))),
            "expected IncorrectResponse for private-IP target, got: {result:?}"
        );
    }

    #[tokio::test]
    async fn validate_allows_private_ip_redirect_when_configured() {
        // Same setup but allow_private_ips=true (test-only override).
        let target_addr = start_server(Router::new().route(
            "/.well-known/acme-challenge/token",
            get(|| async { "token.thumbprint" }),
        ))
        .await;
        let target_port = target_addr.port();
        let redirect_addr = start_server(Router::new().route(
            "/.well-known/acme-challenge/token",
            get(move || async move {
                (
                    StatusCode::FOUND,
                    [(
                        axum::http::header::LOCATION,
                        format!(
                            "http://127.0.0.1:{}/.well-known/acme-challenge/token",
                            target_port
                        ),
                    )],
                )
            }),
        ))
        .await;
        let result = validate(
            "127.0.0.1",
            "token",
            "token.thumbprint",
            redirect_addr.port(),
            true, // private IPs allowed
            &test_client(),
        )
        .await;
        assert!(
            result.is_ok(),
            "expected Ok when allow_private_ips=true, got: {result:?}"
        );
    }

    #[allow(dead_code)]
    fn _uses_http_connector(_: HttpConnector) {}
}
