//! `AcmeClient` — directory-aware ACME HTTP client.
//!
//! Wraps hyper to speak the ACME protocol (RFC 8555), including:
//! - directory discovery
//! - nonce management (threaded between requests, HEAD /new-nonce on miss)
//! - JWS signing via `akamu_jose::JwsFlattened::sign()`
//! - account registration (with optional EAB)
//! - account lookup without creation (RFC 8555 §7.3.1)
//! - account state retrieval and contact updates (RFC 8555 §7.3.2)
//! - account deactivation (RFC 8555 §7.3.7)
//! - order lifecycle: new-order, get-authz, trigger-challenge, poll, finalize, download
//! - STAR order lifecycle: new-star-order, cancel, get/download rolling certificate (RFC 8739)

mod account;
mod order;
mod revoke;
mod star;

pub use revoke::rfc9447_fingerprint;

use std::sync::Arc;

use http_body_util::{BodyExt, Full};
use hyper::{
    body::Bytes,
    header::{CONTENT_TYPE, LOCATION},
    HeaderMap, Method, Request, StatusCode,
};
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::{client::legacy::Client, rt::TokioExecutor};
use serde_json::Value;

use akamu_jose::{JwsFlattened, JwsKeyRef};

use crate::{account::Account, error::ClientError, unix::unix_dispatch};

type HyperClient = Client<hyper_rustls::HttpsConnector<HttpConnector>, Full<Bytes>>;

// ── TLS certificate debug logging ─────────────────────────────────────────────

/// Log key fields of an X.509 certificate at `debug` level.
///
/// Called for CA certs loaded via `--server-ca` and for the server cert during
/// the TLS handshake when the tracing subscriber is at `debug` level.
fn log_x509(label: &str, cert: &native_ossl::x509::X509) {
    use native_ossl::x509::nid_to_long_name;

    let subject = cert
        .subject_name()
        .to_string()
        .unwrap_or_else(|| "<parse error>".into());
    let issuer = cert
        .issuer_name()
        .to_string()
        .unwrap_or_else(|| "<parse error>".into());
    let not_before = cert.not_before_str().unwrap_or_else(|| "<unknown>".into());
    let not_after = cert.not_after_str().unwrap_or_else(|| "<unknown>".into());
    let sig_alg = cert
        .signature_info()
        .ok()
        .and_then(|si| nid_to_long_name(si.pk_nid))
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "<unknown>".into());
    tracing::debug!(
        "{label}: subject={subject:?} issuer={issuer:?} \
         not_before={not_before} not_after={not_after} sig_alg={sig_alg}"
    );
}

/// `CertChainVerifier` that logs certificate details before delegating to
/// the inner `MtcAwareChainVerifier`.  Logging is at `debug` level so it is
/// a no-op unless the tracing subscriber is configured at that level.
#[derive(Debug)]
struct LoggingChainVerifier {
    inner: crate::tls_verify::MtcAwareChainVerifier,
}

impl rustls_native_ossl::cert_verifier::CertChainVerifier for LoggingChainVerifier {
    fn verify_chain(
        &self,
        end_entity: &native_ossl::x509::X509,
        intermediates: &[native_ossl::x509::X509],
        server_name: Option<&rustls::pki_types::ServerName<'_>>,
        now: rustls::pki_types::UnixTime,
    ) -> Result<(), rustls::Error> {
        log_x509("server certificate", end_entity);
        for (i, cert) in intermediates.iter().enumerate() {
            log_x509(&format!("intermediate certificate [{i}]"), cert);
        }
        self.inner
            .verify_chain(end_entity, intermediates, server_name, now)
    }
}

/// Directory-aware ACME client.
///
/// Constructed with `AcmeClient::new()`, which fetches and caches the
/// directory document.  All operations require a [`tokio`] runtime.
pub struct AcmeClient {
    http: HyperClient,
    cached_nonce: tokio::sync::Mutex<Option<String>>,
    new_nonce_url: String,
    pub(crate) new_account_url: String,
    pub(crate) new_order_url: String,
    pub(crate) revoke_cert_url: String,
    pub(crate) key_change_url: String,
    pub(crate) renewal_info_url: Option<String>,
}

impl AcmeClient {
    /// Construct a client that accepts both HTTP and HTTPS directory URLs.
    ///
    /// Use this only for local / test servers (e.g. `http://127.0.0.1:…`).
    /// For production ACME servers prefer [`AcmeClient::new_https_only`].
    pub async fn new(directory_url: &str) -> Result<Self, ClientError> {
        let https = HttpsConnectorBuilder::new()
            .with_provider_and_native_roots(rustls_native_ossl::default_provider())
            .map_err(|e| ClientError::Http(format!("TLS root certs: {e}")))?
            .https_or_http()
            .enable_http1()
            .build();
        let http = Client::builder(TokioExecutor::new()).build(https);
        Self::new_with_client(http, directory_url).await
    }

    /// Construct a client that trusts the system CA store PLUS an extra PEM CA cert.
    ///
    /// Use when the ACME server uses a private CA that is not in the system trust store
    /// (e.g. a local demo or staging server).  All other trust behaviour matches
    /// [`AcmeClient::new`]: both HTTP and HTTPS directory URLs are accepted.
    ///
    /// Chain validation is performed by `OsslServerCertVerifier` (OpenSSL
    /// `X509_verify_cert`) so ML-DSA-signed server certificates are accepted
    /// when OpenSSL 3.3+ with PQ support is installed.
    pub async fn new_with_extra_root(
        directory_url: &str,
        ca_cert_pem: &[u8],
    ) -> Result<Self, ClientError> {
        use rustls::pki_types::CertificateDer;
        use rustls_native_ossl::cert_verifier::OsslServerCertVerifier;

        // Parse caller-supplied PEM CA cert.
        let extra_ders = synta_certificate::pem_to_der(ca_cert_pem);
        if extra_ders.is_empty() {
            return Err(ClientError::Http(
                "--server-ca: PEM file contains no certificate block".into(),
            ));
        }

        // Log extra CA details at debug level (active when -v is passed).
        for (i, der) in extra_ders.iter().enumerate() {
            if let Ok(cert) = native_ossl::x509::X509::from_der(der) {
                log_x509(&format!("CA certificate [{i}]"), &cert);
            }
        }

        // Build the full CA set: system certs + the extra CA.
        // LoggingChainVerifier wraps OsslChainVerifier so server cert details
        // are logged at debug level during the TLS handshake.
        let native = rustls_native_certs::load_native_certs();
        for err in &native.errors {
            tracing::warn!("native cert loading error: {err}");
        }
        let mut all_ca_ders: Vec<CertificateDer<'_>> = native
            .certs
            .iter()
            .map(|c| CertificateDer::from(c.as_ref()))
            .collect();
        for der in &extra_ders {
            all_ca_ders.push(CertificateDer::from(der.as_slice()));
        }

        let chain_verifier = crate::tls_verify::MtcAwareChainVerifier::new(&all_ca_ders)
            .map_err(|e| ClientError::Http(format!("build server-CA verifier: {e}")))?;
        let logging_verifier = Arc::new(LoggingChainVerifier {
            inner: chain_verifier,
        });
        let verifier = OsslServerCertVerifier::builder_with_verifier(logging_verifier).build();

        let config = rustls::ClientConfig::builder_with_provider(
            rustls_native_ossl::default_provider().into(),
        )
        .with_safe_default_protocol_versions()
        .map_err(|e| ClientError::Http(format!("TLS protocol versions: {e}")))?
        .dangerous()
        .with_custom_certificate_verifier(std::sync::Arc::new(verifier))
        .with_no_client_auth();

        let https = HttpsConnectorBuilder::new()
            .with_tls_config(config)
            .https_or_http()
            .enable_http1()
            .build();
        let http = Client::builder(TokioExecutor::new()).build(https);
        Self::new_with_client(http, directory_url).await
    }

    /// Construct a client that only accepts HTTPS directory URLs.
    ///
    /// Use this for delegation upstream servers and any production ACME CA.
    /// Plain-HTTP URLs are rejected by the connector before any data is sent.
    pub async fn new_https_only(directory_url: &str) -> Result<Self, ClientError> {
        let https = HttpsConnectorBuilder::new()
            .with_provider_and_native_roots(rustls_native_ossl::default_provider())
            .map_err(|e| ClientError::Http(format!("TLS root certs: {e}")))?
            .https_only()
            .enable_http1()
            .build();
        let http = Client::builder(TokioExecutor::new()).build(https);
        Self::new_with_client(http, directory_url).await
    }

    async fn new_with_client(
        http: Client<hyper_rustls::HttpsConnector<HttpConnector>, http_body_util::Full<Bytes>>,
        directory_url: &str,
    ) -> Result<Self, ClientError> {
        let dir = get_json(&http, directory_url).await?;

        let new_nonce_url = dir["newNonce"]
            .as_str()
            .ok_or_else(|| ClientError::Http("directory missing newNonce".into()))?
            .to_string();
        let new_account_url = dir["newAccount"]
            .as_str()
            .ok_or_else(|| ClientError::Http("directory missing newAccount".into()))?
            .to_string();
        let new_order_url = dir["newOrder"]
            .as_str()
            .ok_or_else(|| ClientError::Http("directory missing newOrder".into()))?
            .to_string();
        let revoke_cert_url = dir["revokeCert"]
            .as_str()
            .ok_or_else(|| ClientError::Http("directory missing revokeCert".into()))?
            .to_string();
        let key_change_url = dir["keyChange"]
            .as_str()
            .ok_or_else(|| ClientError::Http("directory missing keyChange".into()))?
            .to_string();
        let renewal_info_url = dir["renewalInfo"].as_str().map(String::from);

        Ok(AcmeClient {
            http,
            cached_nonce: tokio::sync::Mutex::new(None),
            new_nonce_url,
            new_account_url,
            new_order_url,
            revoke_cert_url,
            key_change_url,
            renewal_info_url,
        })
    }

    // ── Internal transport dispatch ───────────────────────────────────────────

    /// Send an HTTP request, routing `http+unix://` URIs to a Unix domain socket
    /// and all other URIs through the TLS client.
    ///
    /// Returns `(status, headers, body_bytes)`.
    pub(crate) async fn http_dispatch(
        &self,
        req: Request<Full<Bytes>>,
    ) -> Result<(StatusCode, HeaderMap, Vec<u8>), ClientError> {
        if req.uri().scheme_str() == Some("http+unix") {
            return unix_dispatch(req).await;
        }
        let resp = self
            .http
            .request(req)
            .await
            .map_err(|e| ClientError::Http(format!("request: {e}")))?;
        let status = resp.status();
        let headers = resp.headers().clone();
        let raw = resp
            .into_body()
            .collect()
            .await
            .map_err(|e| ClientError::Http(format!("read body: {e}")))?
            .to_bytes()
            .to_vec();
        Ok((status, headers, raw))
    }

    // ── Internal signing helpers ───────────────────────────────────────────────

    /// POST with the account URL as `kid`, with badNonce retry (max 5 attempts).
    pub(crate) async fn post_kid(
        &self,
        acct: &Account,
        url: &str,
        payload: Option<&[u8]>,
    ) -> Result<(StatusCode, Value, HeaderMap), ClientError> {
        for attempt in 0..5_u8 {
            let nonce = self.fetch_nonce().await?;
            let key_ref = JwsKeyRef::Kid {
                kid: acct.url.clone(),
            };
            let jws = JwsFlattened::sign(
                acct.key.private_key(),
                acct.key.alg(),
                &nonce,
                url,
                key_ref,
                payload,
            )?;
            let jws_value = serde_json::to_value(&jws)
                .map_err(|e| ClientError::Jose(akamu_jose::JoseError::Json(e)))?;
            let (status, body, headers) = self.post_jws_once(url, &jws_value).await?;
            if body["type"].as_str() == Some("urn:ietf:params:acme:error:badNonce") {
                if attempt == 4 {
                    return Err(ClientError::Http(
                        "badNonce retry limit exceeded".to_string(),
                    ));
                }
                *self.cached_nonce.lock().await = None;
                continue;
            }
            return Ok((status, body, headers));
        }
        unreachable!()
    }

    /// Like `post_kid` but returns raw bytes instead of JSON (for PEM download).
    pub(crate) async fn post_kid_raw(
        &self,
        acct: &Account,
        url: &str,
        payload: Option<&[u8]>,
    ) -> Result<(StatusCode, HeaderMap, Vec<u8>), ClientError> {
        for attempt in 0..5_u8 {
            let nonce = self.fetch_nonce().await?;
            let key_ref = JwsKeyRef::Kid {
                kid: acct.url.clone(),
            };
            let jws = JwsFlattened::sign(
                acct.key.private_key(),
                acct.key.alg(),
                &nonce,
                url,
                key_ref,
                payload,
            )?;
            let jws_bytes = serde_json::to_vec(&jws)
                .map_err(|e| ClientError::Jose(akamu_jose::JoseError::Json(e)))?;
            let (status, headers, body_bytes) = self.http_post_raw(url, jws_bytes).await?;
            // Check for badNonce in raw response.
            if let Ok(json) = serde_json::from_slice::<Value>(&body_bytes) {
                if json["type"].as_str() == Some("urn:ietf:params:acme:error:badNonce") {
                    if attempt == 4 {
                        return Err(ClientError::Http(
                            "badNonce retry limit exceeded".to_string(),
                        ));
                    }
                    *self.cached_nonce.lock().await = None;
                    continue;
                }
            }
            return Ok((status, headers, body_bytes));
        }
        unreachable!()
    }

    /// Low-level: POST a pre-serialised JWS body, return (status, parsed JSON, headers).
    /// Does NOT perform badNonce retry — callers handle that.
    pub(crate) async fn post_jws_once(
        &self,
        url: &str,
        body: &Value,
    ) -> Result<(StatusCode, Value, HeaderMap), ClientError> {
        let body_bytes = serde_json::to_vec(body)
            .map_err(|e| ClientError::Jose(akamu_jose::JoseError::Json(e)))?;
        let (status, headers, raw) = self.http_post_raw(url, body_bytes).await?;
        let json = if raw.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&raw)
                .map_err(|e| ClientError::Http(format!("response body is not valid JSON: {e}")))?
        };
        Ok((status, json, headers))
    }

    /// Send an HTTP POST with `Content-Type: application/jose+json`.
    /// Caches the `Replay-Nonce` from the response for the next request.
    pub(crate) async fn http_post_raw(
        &self,
        url: &str,
        body_bytes: Vec<u8>,
    ) -> Result<(StatusCode, HeaderMap, Vec<u8>), ClientError> {
        let req = Request::builder()
            .method(Method::POST)
            .uri(url)
            .header(CONTENT_TYPE, "application/jose+json")
            .body(Full::<Bytes>::new(Bytes::from(body_bytes)))
            .map_err(|e| ClientError::Http(format!("build request: {e}")))?;

        let (status, headers, raw) = self.http_dispatch(req).await?;
        // Cache the nonce from the response for the next request.
        match nonce_from_headers(&headers) {
            Ok(nonce) => {
                *self.cached_nonce.lock().await = Some(nonce);
            }
            Err(_) => {
                tracing::debug!(url, "POST response missing Replay-Nonce header");
            }
        }
        Ok((status, headers, raw))
    }

    /// Return a nonce: use the cached one if available, otherwise HEAD /new-nonce.
    pub(crate) async fn fetch_nonce(&self) -> Result<String, ClientError> {
        // Return cached nonce if available.
        {
            let mut guard = self.cached_nonce.lock().await;
            if let Some(nonce) = guard.take() {
                return Ok(nonce);
            }
        }
        // Fall back to HEAD /new-nonce.
        let req = Request::builder()
            .method(Method::HEAD)
            .uri(&self.new_nonce_url)
            .body(Full::<Bytes>::new(Bytes::new()))
            .map_err(|e| ClientError::Http(format!("build nonce request: {e}")))?;
        let (status, headers, _) = self.http_dispatch(req).await?;
        nonce_from_headers(&headers).map_err(|_| {
            ClientError::Http(format!(
                "HEAD {url} returned {status} without Replay-Nonce header \
                 (check that the server base_url in its config includes the correct host and port)",
                url = self.new_nonce_url,
            ))
        })
    }
}

// ── Utility functions ─────────────────────────────────────────────────────────

/// GET a URL and parse the response body as JSON.
/// Handles both regular HTTP(S) and `http+unix://` URLs.
async fn get_json(http: &HyperClient, url: &str) -> Result<Value, ClientError> {
    let req = Request::builder()
        .method(Method::GET)
        .uri(url)
        .body(Full::<Bytes>::new(Bytes::new()))
        .map_err(|e| ClientError::Http(format!("build GET request: {e}")))?;

    let (status, _, raw) = if url.starts_with("http+unix://") {
        unix_dispatch(req).await?
    } else {
        let resp = http
            .request(req)
            .await
            .map_err(|e| ClientError::Http(format!("GET {url}: {e}")))?;
        let status = resp.status();
        let headers = resp.headers().clone();
        let raw = resp
            .into_body()
            .collect()
            .await
            .map_err(|e| ClientError::Http(format!("read body: {e}")))?
            .to_bytes()
            .to_vec();
        (status, headers, raw)
    };

    if !status.is_success() {
        return Err(ClientError::Http(format!("GET {url}: {status}")));
    }

    serde_json::from_slice(&raw)
        .map_err(|e| ClientError::Http(format!("parse directory JSON: {e}")))
}

pub(crate) fn location_hdr(headers: &HeaderMap) -> Result<String, ClientError> {
    headers
        .get(LOCATION)
        .and_then(|v: &hyper::header::HeaderValue| v.to_str().ok())
        .map(String::from)
        .ok_or_else(|| ClientError::Http("missing Location header".into()))
}

pub(crate) fn nonce_from_headers(headers: &HeaderMap) -> Result<String, ClientError> {
    headers
        .get("replay-nonce")
        .and_then(|v| v.to_str().ok())
        .map(String::from)
        .ok_or_else(|| ClientError::Http("missing Replay-Nonce header".into()))
}

pub(crate) fn acme_error(body: &Value, status: StatusCode, op: &str) -> ClientError {
    let acme_type = body["type"].as_str().unwrap_or("about:blank").to_string();
    let detail = body["detail"]
        .as_str()
        .map(String::from)
        .unwrap_or_else(|| body.to_string());
    if acme_type != "about:blank" {
        ClientError::Acme { acme_type, detail }
    } else {
        ClientError::Http(format!("{op} {status}: {detail}"))
    }
}
