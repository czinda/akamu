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
