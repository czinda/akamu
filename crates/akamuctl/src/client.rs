//! Admin HTTP client with mTLS, GSSAPI, and session token support.

use std::sync::Arc;

use base64::Engine as _;
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::{Method, Request, StatusCode};
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use rustls::ClientConfig;
use serde_json::Value;

use crate::config::SessionCache;
use crate::error::CtlError;

pub type HttpsClient = Client<
    hyper_rustls::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>,
    Full<Bytes>,
>;

/// Build a rustls ClientConfig with optional mTLS client cert.
///
/// Uses `rustls_native_ossl` as both the crypto provider and the server
/// certificate verifier so that ML-DSA / composite post-quantum cert chains
/// are verified through OpenSSL rather than the webpki verifier (which does
/// not support ML-DSA).
pub fn build_tls_config(
    ca_cert_pem: Option<&[u8]>,
    cert_pem: Option<&[u8]>,
    key_pem: Option<&[u8]>,
) -> Result<ClientConfig, CtlError> {
    use rustls_native_ossl::cert_verifier::OsslServerCertVerifier;

    let provider = Arc::new(rustls_native_ossl::default_provider());

    let ca_cert_ders: Vec<rustls_pki_types::CertificateDer<'static>> =
        if let Some(pem) = ca_cert_pem {
            let ders = synta_certificate::pem_to_der(pem);
            if ders.is_empty() {
                return Err(CtlError::Config(
                    "ca_cert PEM contains no certificates".into(),
                ));
            }
            ders.into_iter()
                .map(rustls_pki_types::CertificateDer::from)
                .collect()
        } else {
            let native_certs = rustls_native_certs::load_native_certs();
            if !native_certs.errors.is_empty() {
                eprintln!(
                    "warning: {} native certificate(s) failed to load",
                    native_certs.errors.len()
                );
                for e in &native_certs.errors {
                    eprintln!("  {e}");
                }
            }
            native_certs.certs
        };

    let chain_verifier = Arc::new(
        akamu_client::tls_verify::MtcAwareChainVerifier::new(&ca_cert_ders)
            .map_err(|e| CtlError::Tls(format!("build server-CA verifier: {e}")))?,
    );
    let verifier = Arc::new(OsslServerCertVerifier::builder_with_verifier(chain_verifier).build());

    let builder = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| CtlError::Tls(format!("TLS protocol versions: {e}")))?
        .dangerous()
        .with_custom_certificate_verifier(verifier);

    if let (Some(cert_pem), Some(key_pem)) = (cert_pem, key_pem) {
        let cert_ders: Vec<rustls_pki_types::CertificateDer<'static>> =
            synta_certificate::pem_to_der(cert_pem)
                .into_iter()
                .map(rustls_pki_types::CertificateDer::from)
                .collect();
        if cert_ders.is_empty() {
            return Err(CtlError::Config(
                "cert_file PEM contains no certificates".into(),
            ));
        }
        let key_ders = synta_certificate::pem_to_der(key_pem);
        let key_der = key_ders
            .into_iter()
            .next()
            .ok_or_else(|| CtlError::Config("key_file PEM contains no keys".into()))?;
        let private_key = rustls_pki_types::PrivateKeyDer::try_from(key_der)
            .map_err(|e| CtlError::Config(format!("parse private key: {e}")))?;
        builder
            .with_client_auth_cert(cert_ders, private_key)
            .map_err(|e| CtlError::Tls(format!("client auth cert: {e}")))
    } else {
        Ok(builder.with_no_client_auth())
    }
}

fn build_https_client(tls_config: ClientConfig) -> HttpsClient {
    let connector = hyper_rustls::HttpsConnectorBuilder::new()
        .with_tls_config(tls_config)
        .https_or_http()
        .enable_http1()
        .build();
    Client::builder(TokioExecutor::new()).build(connector)
}

// ── AdminClient ───────────────────────────────────────────────────────────────

/// HTTP client for the akamu admin API.
///
/// Handles session token caching, re-authentication on expiry, and
/// serialisation of JSON request/response bodies.
pub struct AdminClient {
    base_url: String,
    client: HttpsClient,
    session_cache: Arc<std::sync::Mutex<SessionCache>>,
    is_cosigner: bool,
    /// When set, `session_token()` sends `Authorization: Negotiate` using the
    /// ambient Kerberos ccache rather than relying on the mTLS client certificate.
    gssapi_service: Option<String>,
}

impl AdminClient {
    /// Build a new client for the given server or cosigner URL.
    pub fn new(
        base_url: String,
        ca_cert_pem: Option<Vec<u8>>,
        cert_pem: Option<Vec<u8>>,
        key_pem: Option<Vec<u8>>,
        session_cache: Arc<std::sync::Mutex<SessionCache>>,
        is_cosigner: bool,
        gssapi_service: Option<String>,
    ) -> Result<Self, CtlError> {
        let tls_config = build_tls_config(
            ca_cert_pem.as_deref(),
            cert_pem.as_deref(),
            key_pem.as_deref(),
        )?;
        let client = build_https_client(tls_config);
        Ok(AdminClient {
            base_url,
            client,
            session_cache,
            is_cosigner,
            gssapi_service,
        })
    }

    /// Return the cached session token or authenticate to get a new one.
    async fn session_token(&self) -> Result<String, CtlError> {
        let cached = self
            .session_cache
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get_valid_token(&self.base_url, self.is_cosigner);
        if let Some(token) = cached {
            return Ok(token);
        }

        // POST /admin/session — mTLS cert or GSSAPI Negotiate authenticates the operator.
        let session_resp = if let Some(ref spn) = self.gssapi_service {
            // GSSAPI multi-round-trip loop: step → send → check for server token → repeat.
            let cred = akamu_gssapi::GssClientCred::ambient()
                .map_err(|e| {
                    CtlError::Auth(format!(
                        "GSSAPI ccache: {e}\n\nhint: run 'kinit' to obtain a Kerberos ticket, then retry"
                    ))
                })?;
            let mut ctx = akamu_gssapi::GssClientContext::new(spn)
                .map_err(|e| CtlError::Auth(format!("GSSAPI context for '{spn}': {e}")))?;
            let mut server_token: Option<Vec<u8>> = None;
            loop {
                let (token_bytes, _complete) = ctx
                    .step(&cred, server_token.as_deref(), None)
                    .map_err(|e| {
                        CtlError::Auth(format!(
                            "GSSAPI authentication failed for '{spn}': {e}\n\n\
                             hint: your Kerberos credentials may have expired; \
                             run 'kinit' to renew them, then retry"
                        ))
                    })?;
                let negotiate_hdr = format!(
                    "Negotiate {}",
                    base64::engine::general_purpose::STANDARD.encode(&token_bytes)
                );
                let resp = self
                    .raw_request(
                        Method::POST,
                        "/admin/session",
                        None,
                        None,
                        Some(&negotiate_hdr),
                    )
                    .await?;
                if resp.status == StatusCode::OK {
                    break resp;
                }
                // 401 with a server-side GSSAPI token — continue the exchange.
                if resp.status == StatusCode::UNAUTHORIZED {
                    if let Some(www) = &resp.www_authenticate {
                        if let Some(b64) = www.strip_prefix("Negotiate ") {
                            server_token = Some(
                                base64::engine::general_purpose::STANDARD
                                    .decode(b64.trim())
                                    .map_err(|e| {
                                        CtlError::Auth(format!("decode server GSSAPI token: {e}"))
                                    })?,
                            );
                            continue;
                        }
                    }
                }
                return Err(CtlError::Auth(format!(
                    "POST /admin/session returned {}",
                    resp.status
                )));
            }
        } else {
            // mTLS path — single request; the client certificate authenticates.
            let resp = self
                .raw_request(Method::POST, "/admin/session", None, None, None)
                .await?;
            if resp.status != StatusCode::OK {
                return Err(CtlError::Auth(format!(
                    "POST /admin/session returned {}",
                    resp.status
                )));
            }
            resp
        };

        let body: Value = serde_json::from_str(&session_resp.body_text())
            .map_err(|e| CtlError::Api(format!("session JSON: {e}")))?;
        let token = body["session_token"]
            .as_str()
            .ok_or_else(|| CtlError::Api("no session_token in response".into()))?
            .to_string();
        let expires_at = body["expires_at"]
            .as_str()
            .ok_or_else(|| CtlError::Api("no expires_at in session response".into()))?
            .to_string();

        // Cache the new token.
        let entry = crate::config::SessionEntry {
            url: self.base_url.clone(),
            token: token.clone(),
            expires_at,
        };
        {
            let mut cache = self.session_cache.lock().unwrap_or_else(|e| e.into_inner());
            if self.is_cosigner {
                cache.cosigner = Some(entry);
            } else {
                cache.server = Some(entry);
            }
            if let Err(e) = cache.save() {
                eprintln!("warning: failed to save session cache: {e}");
            }
        }
        Ok(token)
    }

    /// Make a bearer-authenticated request, retrying once on 401 or 423.
    ///
    /// A 401 means the server rejected the cached session token (e.g. the
    /// server restarted and its in-memory session store was cleared, or the
    /// server-side sliding-window TTL elapsed before the client-side
    /// `expires_at` timestamp).  A 423 means the session was locked due to
    /// inactivity (FTA_SSL_EXT.1) and requires re-authentication.  In both
    /// cases we clear the local cache and reauthenticate transparently so the
    /// caller does not need to remove `session.json` by hand.
    async fn authed(
        &self,
        method: Method,
        path: &str,
        body: Option<&str>,
    ) -> Result<RawResponse, CtlError> {
        let token = self.session_token().await?;
        let resp = self
            .raw_request(method.clone(), path, Some(&token), body, None)
            .await?;
        if resp.status != StatusCode::UNAUTHORIZED && resp.status != StatusCode::LOCKED {
            return Ok(resp);
        }
        // Cached token rejected or locked — evict it and reauthenticate once.
        self.clear_session();
        let token = self.session_token().await?;
        self.raw_request(method, path, Some(&token), body, None)
            .await
    }

    /// Make an authenticated GET request; returns parsed JSON.
    pub async fn get(&self, path: &str) -> Result<Value, CtlError> {
        let resp = self.authed(Method::GET, path, None).await?;
        check_status(&resp)?;
        parse_json(&resp.body_text())
    }

    /// Make an authenticated GET request; returns the raw response body as text.
    ///
    /// Use this for endpoints that return non-JSON content (e.g. PEM files).
    pub async fn get_text(&self, path: &str) -> Result<String, CtlError> {
        let resp = self.authed(Method::GET, path, None).await?;
        check_status(&resp)?;
        Ok(resp.body_text())
    }

    /// Make an authenticated GET request; returns raw bytes.
    ///
    /// Use this for endpoints that return binary content (e.g. DER certificates).
    pub async fn get_bytes(&self, path: &str) -> Result<Vec<u8>, CtlError> {
        let resp = self.authed(Method::GET, path, None).await?;
        check_status(&resp)?;
        Ok(resp.raw_bytes)
    }

    /// Make an authenticated POST request with no body; ignores the response.
    ///
    /// Use this for action endpoints that return 204 No Content.
    pub async fn post_action(&self, path: &str) -> Result<(), CtlError> {
        let resp = self.authed(Method::POST, path, None).await?;
        if resp.status == StatusCode::NO_CONTENT || resp.status.is_success() {
            return Ok(());
        }
        Err(CtlError::Api(format!(
            "POST {path} returned {}: {}",
            resp.status,
            resp.body_text()
        )))
    }

    /// Make an authenticated POST request with optional JSON body.
    pub async fn post(&self, path: &str, body: Option<&Value>) -> Result<Value, CtlError> {
        let body_str = body.map(|v| v.to_string());
        let resp = self.authed(Method::POST, path, body_str.as_deref()).await?;
        check_status(&resp)?;
        parse_json(&resp.body_text())
    }

    /// Make an authenticated PUT request with JSON body.
    pub async fn put(&self, path: &str, body: &Value) -> Result<Value, CtlError> {
        let body_str = body.to_string();
        let resp = self.authed(Method::PUT, path, Some(&body_str)).await?;
        check_status(&resp)?;
        parse_json(&resp.body_text())
    }

    /// Make an authenticated DELETE request.
    pub async fn delete(&self, path: &str) -> Result<(), CtlError> {
        let resp = self.authed(Method::DELETE, path, None).await?;
        if resp.status == StatusCode::NO_CONTENT || resp.status.is_success() {
            return Ok(());
        }
        Err(CtlError::Api(format!(
            "DELETE {path} returned {}: {}",
            resp.status,
            resp.body_text()
        )))
    }

    /// Make an authenticated PATCH request with JSON body.
    pub async fn patch(&self, path: &str, body: &Value) -> Result<Value, CtlError> {
        let body_str = body.to_string();
        let resp = self.authed(Method::PATCH, path, Some(&body_str)).await?;
        check_status(&resp)?;
        parse_json(&resp.body_text())
    }

    /// Invalidate the local session cache entry.
    pub fn clear_session(&self) {
        let mut cache = self.session_cache.lock().unwrap_or_else(|e| e.into_inner());
        if self.is_cosigner {
            cache.cosigner = None;
        } else {
            cache.server = None;
        }
        if let Err(e) = cache.save() {
            eprintln!("warning: failed to save session cache: {e}");
        }
    }

    async fn raw_request(
        &self,
        method: Method,
        path: &str,
        bearer_token: Option<&str>,
        body: Option<&str>,
        auth_header: Option<&str>,
    ) -> Result<RawResponse, CtlError> {
        let url = format!("{}{}", self.base_url.trim_end_matches('/'), path);

        let mut req_builder = Request::builder()
            .method(method)
            .uri(&url)
            .header("accept", "application/json");
        if let Some(token) = bearer_token {
            req_builder = req_builder.header("authorization", format!("Bearer {token}"));
        } else if let Some(hdr) = auth_header {
            req_builder = req_builder.header("authorization", hdr);
        }
        let body_bytes: Bytes = if let Some(json) = body {
            req_builder = req_builder.header("content-type", "application/json");
            Bytes::copy_from_slice(json.as_bytes())
        } else {
            Bytes::new()
        };
        let req = req_builder
            .body(Full::new(body_bytes))
            .map_err(|e| CtlError::Http(format!("build request: {e}")))?;

        let (status, resp_headers, resp_bytes) = if url.starts_with("http+unix://") {
            akamu_client::unix::unix_dispatch(req)
                .await
                .map_err(|e| CtlError::Http(e.to_string()))?
        } else {
            let resp = self
                .client
                .request(req)
                .await
                .map_err(|e| CtlError::Http(format!("{url}: {e}")))?;
            let status = resp.status();
            let headers = resp.headers().clone();
            let bytes = resp
                .into_body()
                .collect()
                .await
                .map_err(|e| CtlError::Http(format!("read body: {e}")))?
                .to_bytes()
                .to_vec();
            (status, headers, bytes)
        };

        let www_authenticate = resp_headers
            .get("www-authenticate")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        Ok(RawResponse {
            status,
            raw_bytes: resp_bytes,
            www_authenticate,
        })
    }
}

struct RawResponse {
    status: StatusCode,
    raw_bytes: Vec<u8>,
    www_authenticate: Option<String>,
}

impl RawResponse {
    fn body_text(&self) -> String {
        String::from_utf8_lossy(&self.raw_bytes).into_owned()
    }
}

fn check_status(resp: &RawResponse) -> Result<(), CtlError> {
    if resp.status.is_success() {
        return Ok(());
    }
    Err(CtlError::Api(format!(
        "HTTP {}: {}",
        resp.status,
        resp.body_text()
    )))
}

fn parse_json(body: &str) -> Result<Value, CtlError> {
    if body.is_empty() {
        return Ok(Value::Null);
    }
    serde_json::from_str(body).map_err(|e| CtlError::Api(format!("JSON parse: {e}: {body}")))
}
