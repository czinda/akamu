//! GSSAPI-authenticated fetch of EAB identity from the server.
//!
//! Sends `Authorization: Negotiate <base64-token>` to `GET /acme/eab` and
//! parses the JSON response into a [`GssapiEabResult`].

use base64::{engine::general_purpose::STANDARD, Engine};
use http_body_util::{BodyExt, Empty};
use hyper::{body::Bytes, Request};
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::{client::legacy::Client, rt::TokioExecutor};

use crate::error::ClientError;

/// Result returned by a successful GSSAPI EAB identity fetch.
pub struct GssapiEabResult {
    /// Authenticated Kerberos principal (e.g. `"host/client.example.com@REALM"`).
    pub principal: String,
    /// EAB key identifier (present when the server has `eab_master_secret` configured).
    pub kid: Option<String>,
    /// Base64url-encoded HMAC key (present together with `kid`).
    pub hmac_key: Option<String>,
    /// HMAC algorithm, e.g. `"HS256"` (present together with `kid`).
    pub alg: Option<String>,
}

/// Fetch EAB identity from `eab_url` using GSSAPI authentication.
///
/// `keytab_file` is the path to a keytab containing an initiator credential.
/// The target service name `HTTP@<hostname>` is derived from `eab_url`.
///
/// This function is async but uses `tokio::task::block_in_place` internally for
/// the blocking `gss_init_sec_context` FFI call.
pub async fn fetch_eab_via_gssapi(
    eab_url: &str,
    keytab_file: &str,
) -> Result<GssapiEabResult, ClientError> {
    let cred = akamu_gssapi::GssClientCred::from_keytab(keytab_file)
        .map_err(|e| ClientError::Gssapi(e.to_string()))?;

    let target = derive_service_name(eab_url)?;

    let token = tokio::task::spawn_blocking(move || akamu_gssapi::init_token(&cred, &target, None))
        .await
        .map_err(|e| ClientError::Http(format!("GSSAPI task join: {e}")))?
        .map_err(|e| ClientError::Gssapi(e.to_string()))?;

    let token_b64 = STANDARD.encode(&token);

    let https = HttpsConnectorBuilder::new()
        .with_provider_and_native_roots(rustls_native_ossl::default_provider())
        .map_err(|e| ClientError::Http(format!("TLS root certs: {e}")))?
        .https_or_http()
        .enable_http1()
        .build();
    let http = Client::builder(TokioExecutor::new()).build::<_, Empty<Bytes>>(https);

    let req = Request::builder()
        .method("GET")
        .uri(eab_url)
        .header("Authorization", format!("Negotiate {token_b64}"))
        .body(Empty::new())
        .map_err(|e| ClientError::Http(format!("request build: {e}")))?;

    let resp = http
        .request(req)
        .await
        .map_err(|e| ClientError::Http(format!("GET {eab_url}: {e}")))?;

    let status = resp.status();
    let body_bytes = resp
        .into_body()
        .collect()
        .await
        .map_err(|e| ClientError::Http(format!("read body: {e}")))?
        .to_bytes();

    if !status.is_success() {
        let body = String::from_utf8_lossy(&body_bytes);
        return Err(ClientError::Http(format!(
            "GET {eab_url}: HTTP {status}: {body}"
        )));
    }

    let json: serde_json::Value = serde_json::from_slice(&body_bytes)
        .map_err(|e| ClientError::Http(format!("parse EAB response: {e}")))?;

    let principal = json["principal"]
        .as_str()
        .ok_or_else(|| ClientError::Http("EAB response missing 'principal' field".into()))?
        .to_owned();

    let kid = json["kid"].as_str().map(str::to_owned);
    let hmac_key = json["hmac_key"].as_str().map(str::to_owned);
    let alg = json["alg"].as_str().map(str::to_owned);

    Ok(GssapiEabResult {
        principal,
        kid,
        hmac_key,
        alg,
    })
}

/// Derive `HTTP@<hostname>` from a URL by stripping scheme, path, and port.
fn derive_service_name(url: &str) -> Result<String, ClientError> {
    let without_scheme = url.split_once("://").map(|(_, rest)| rest).unwrap_or(url);
    let host = without_scheme
        .split('/')
        .next()
        .and_then(|h| h.split(':').next())
        .filter(|h| !h.is_empty())
        .ok_or_else(|| ClientError::Http(format!("cannot extract hostname from '{url}'")))?;
    Ok(format!("HTTP@{host}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_service_name_strips_path_and_port() {
        assert_eq!(
            derive_service_name("https://acme.example.com/acme/eab").unwrap(),
            "HTTP@acme.example.com"
        );
        assert_eq!(
            derive_service_name("https://acme.example.com:8443/acme/eab").unwrap(),
            "HTTP@acme.example.com"
        );
        assert_eq!(
            derive_service_name("http://localhost:8080/acme/eab").unwrap(),
            "HTTP@localhost"
        );
    }

    #[test]
    fn derive_service_name_no_scheme() {
        assert_eq!(
            derive_service_name("acme.example.com/acme/eab").unwrap(),
            "HTTP@acme.example.com"
        );
    }

    #[test]
    fn derive_service_name_empty_host_is_error() {
        assert!(derive_service_name("https:///acme/eab").is_err());
    }
}
