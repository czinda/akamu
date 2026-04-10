//! http-01 challenge validation (RFC 8555 §8.3).
//!
//! Fetches `http://{domain}/.well-known/acme-challenge/{token}` and verifies
//! that the response body (trimmed) equals the key authorization string.

use http_body_util::BodyExt;
use hyper::Uri;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;

use crate::error::AcmeError;

/// Validate an http-01 challenge.
///
/// * `domain`   — the identifier value (DNS name or IP address literal).
/// * `token`    — the challenge token stored in the database.
/// * `key_auth` — `{token}.{jwk_thumbprint}` (expected response body).
pub async fn validate(domain: &str, token: &str, key_auth: &str) -> Result<(), AcmeError> {
    let url = format!(
        "http://{}/.well-known/acme-challenge/{}",
        domain, token
    );
    let uri: Uri = url
        .parse()
        .map_err(|e| AcmeError::Connection(format!("invalid http-01 URL '{url}': {e}")))?;

    // hyper is already a transitive dependency via axum; re-use it here so we
    // don't pull in an extra HTTP client library.
    let client = Client::builder(TokioExecutor::new())
        .build_http::<http_body_util::Empty<hyper::body::Bytes>>();

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
            "http-01: response body too large ({} bytes)", body_bytes.len()
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
    use axum::{Router, routing::get, http::StatusCode};
    use tokio::net::TcpListener;

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
        // Port 80 on localhost:0 or a guaranteed-unreachable host should fail with Connection error.
        let result = validate("acme-test-nonexistent-host.invalid", "token", "key.auth").await;
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
        )).await;
        let domain = format!("127.0.0.1:{}", addr.port());
        let result = validate(&domain, "mytoken", "mytoken.thumbprint").await;
        assert!(result.is_ok(), "expected Ok(()), got: {result:?}");
    }

    #[tokio::test]
    async fn validate_non_200_returns_error() {
        let addr = start_server(Router::new().route(
            "/.well-known/acme-challenge/token",
            get(|| async { StatusCode::NOT_FOUND }),
        )).await;
        let domain = format!("127.0.0.1:{}", addr.port());
        let result = validate(&domain, "token", "expected").await;
        assert!(matches!(result, Err(AcmeError::IncorrectResponse(_))),
            "expected IncorrectResponse, got: {result:?}");
    }

    #[tokio::test]
    async fn validate_body_too_large_returns_error() {
        let addr = start_server(Router::new().route(
            "/.well-known/acme-challenge/token",
            get(|| async { "x".repeat(8193) }),
        )).await;
        let domain = format!("127.0.0.1:{}", addr.port());
        let result = validate(&domain, "token", "expected").await;
        assert!(matches!(result, Err(AcmeError::IncorrectResponse(_))),
            "expected IncorrectResponse for oversized body, got: {result:?}");
    }

    #[tokio::test]
    async fn validate_key_auth_mismatch_returns_error() {
        let addr = start_server(Router::new().route(
            "/.well-known/acme-challenge/token",
            get(|| async { "wrong-auth" }),
        )).await;
        let domain = format!("127.0.0.1:{}", addr.port());
        let result = validate(&domain, "token", "correct-auth").await;
        assert!(matches!(result, Err(AcmeError::IncorrectResponse(_))),
            "expected IncorrectResponse for mismatch, got: {result:?}");
    }
}
