//! http-01 challenge validation (RFC 8555 §8.3).
//!
//! Fetches `http://{domain}/.well-known/acme-challenge/{token}` and verifies
//! that the response body (trimmed) equals the key authorization string.

use http_body_util::BodyExt;
use hyper::Uri;

use crate::error::AcmeError;
use crate::state::ValidationClient;

/// Validate an http-01 challenge.
///
/// * `domain`   — the identifier value (DNS name or IP address literal).
/// * `token`    — the challenge token stored in the database.
/// * `key_auth` — `{token}.{jwk_thumbprint}` (expected response body).
/// * `port`     — TCP port to connect to (RFC 8555 §8.3 requires 80; override for testing).
/// * `client`   — shared hyper client; reusing it avoids a TCP handshake per validation.
pub async fn validate(
    domain: &str,
    token: &str,
    key_auth: &str,
    port: u16,
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
    let uri: Uri = url
        .parse()
        .map_err(|e| AcmeError::Connection(format!("invalid http-01 URL '{url}': {e}")))?;

    let resp = client
        .get(uri)
        .await
        .map_err(|e| AcmeError::Connection(format!("http-01 GET '{url}': {e}")))?;

    let status = resp.status();
    if !status.is_success() {
        return Err(AcmeError::IncorrectResponse(format!(
            "http-01: server returned HTTP {status} for '{url}'"
        )));
    }

    // Cap response body to prevent memory abuse.
    const MAX_BODY: usize = 8192;
    let body_bytes = resp
        .into_body()
        .collect()
        .await
        .map_err(|e| AcmeError::Connection(format!("http-01 body read from '{url}': {e}")))?
        .to_bytes();

    if body_bytes.len() > MAX_BODY {
        return Err(AcmeError::IncorrectResponse(format!(
            "http-01: response body too large ({} bytes)",
            body_bytes.len()
        )));
    }

    let body = std::str::from_utf8(&body_bytes)
        .map_err(|_| AcmeError::IncorrectResponse("http-01: body is not valid UTF-8".into()))?
        .trim();

    if body != key_auth {
        return Err(AcmeError::IncorrectResponse(format!(
            "http-01: key authorization mismatch for '{url}'"
        )));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{http::StatusCode, routing::get, Router};
    use hyper_util::client::legacy::Client;
    use hyper_util::rt::TokioExecutor;
    use tokio::net::TcpListener;

    fn test_client() -> crate::state::ValidationClient {
        Client::builder(TokioExecutor::new())
            .build_http::<http_body_util::Empty<hyper::body::Bytes>>()
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
            &test_client(),
        )
        .await;
        assert!(
            matches!(result, Err(AcmeError::IncorrectResponse(_))),
            "expected IncorrectResponse for mismatch, got: {result:?}"
        );
    }
}
