//! `AcmeClient` — directory-aware ACME HTTP client.
//!
//! Wraps hyper to speak the ACME protocol (RFC 8555), including:
//! - directory discovery
//! - nonce management (threaded between requests, HEAD /new-nonce on miss)
//! - JWS signing via `akamu_jose::JwsFlattened::sign()`
//! - account registration (with optional EAB)
//! - account deactivation (RFC 8555 §7.3.7)
//! - order lifecycle: new-order, get-authz, trigger-challenge, poll, finalize, download

use std::sync::Arc;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
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
use tokio::time::{sleep, Duration};

use akamu_jose::{JwsFlattened, JwsKeyRef};

use crate::{
    account::{Account, AccountKey},
    eab::create_eab_jws,
    error::ClientError,
    types::{AccountOptions, Authorization, Challenge, Identifier, Order},
};

type HyperClient = Client<hyper_rustls::HttpsConnector<HttpConnector>, Full<Bytes>>;

/// Directory-aware ACME client.
///
/// Constructed with `AcmeClient::new()`, which fetches and caches the
/// directory document.  All operations require a [`tokio`] runtime.
pub struct AcmeClient {
    http: HyperClient,
    cached_nonce: tokio::sync::Mutex<Option<String>>,
    new_nonce_url: String,
    new_account_url: String,
    new_order_url: String,
    revoke_cert_url: String,
    key_change_url: String,
    renewal_info_url: Option<String>,
}

impl AcmeClient {
    /// Construct a client by fetching the ACME directory.
    pub async fn new(directory_url: &str) -> Result<Self, ClientError> {
        let https = HttpsConnectorBuilder::new()
            .with_native_roots()
            .map_err(|e| ClientError::Http(format!("TLS root certs: {e}")))?
            .https_or_http()
            .enable_http1()
            .build();
        let http = Client::builder(TokioExecutor::new()).build(https);
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

    // ── Account ───────────────────────────────────────────────────────────────

    /// Register a new ACME account.
    ///
    /// When `opts.eab` is `Some`, includes an `externalAccountBinding` JWS in
    /// the request body (RFC 8555 §7.3.4).
    ///
    /// On success, returns an `Account` whose embedded key signs all subsequent
    /// requests.
    pub async fn new_account(
        &self,
        key: Arc<AccountKey>,
        opts: &AccountOptions<'_>,
    ) -> Result<Account, ClientError> {
        let url = &self.new_account_url;

        // Build the new-account payload.
        let mut payload = serde_json::json!({
            "termsOfServiceAgreed": opts.agree_tos,
            "contact": opts.contacts,
        });

        // Optionally attach EAB (RFC 8555 §7.3.4).
        if let Some(eab_opts) = &opts.eab {
            let eab_jws = create_eab_jws(
                eab_opts.kid,
                url,
                eab_opts.alg,
                eab_opts.hmac_key,
                key.public_jwk(),
            )?;
            payload["externalAccountBinding"] = eab_jws;
        }

        let payload_str = payload.to_string();

        // Retry loop for badNonce.
        let (status, body, headers) = loop {
            let nonce = self.fetch_nonce().await?;
            let key_ref = JwsKeyRef::Jwk {
                jwk: key.public_jwk().clone(),
            };
            let jws = JwsFlattened::sign(
                key.private_key(),
                key.alg(),
                &nonce,
                url,
                key_ref,
                Some(payload_str.as_bytes()),
            )?;
            let jws_value = serde_json::to_value(&jws)
                .map_err(|e| ClientError::Jose(akamu_jose::JoseError::Json(e)))?;
            let (status, body, headers) = self.post_jws_once(url, &jws_value).await?;
            if body["type"].as_str() == Some("urn:ietf:params:acme:error:badNonce") {
                *self.cached_nonce.lock().await = None;
                continue;
            }
            break (status, body, headers);
        };

        if status != StatusCode::CREATED {
            return Err(acme_error(&body, status, "new-account"));
        }

        let account_url = location_hdr(&headers)?;
        let contacts = body["contact"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();
        let account_status = body["status"].as_str().unwrap_or("valid").to_string();

        Ok(Account::new(account_url, account_status, contacts, key))
    }

    /// Deactivate an account (RFC 8555 §7.3.7).
    ///
    /// Posts `{"status":"deactivated"}` to the account URL.  After this call,
    /// the account can no longer sign orders.
    pub async fn deactivate_account(&self, acct: &Account) -> Result<(), ClientError> {
        let url = &acct.url;
        let payload = serde_json::json!({"status": "deactivated"});

        let (status, body, _) = self
            .post_kid(acct, url, Some(payload.to_string().as_bytes()))
            .await?;
        if status != StatusCode::OK {
            return Err(acme_error(&body, status, "deactivate-account"));
        }
        Ok(())
    }

    // ── Order lifecycle ───────────────────────────────────────────────────────

    /// Place a new order for the given identifiers.
    pub async fn new_order(
        &self,
        acct: &Account,
        ids: &[Identifier],
    ) -> Result<Order, ClientError> {
        let url = &self.new_order_url;
        let payload = serde_json::json!({ "identifiers": ids });

        let (status, body, headers) = self
            .post_kid(acct, url, Some(payload.to_string().as_bytes()))
            .await?;
        if status != StatusCode::CREATED {
            return Err(acme_error(&body, status, "new-order"));
        }

        let order_url = location_hdr(&headers)?;
        parse_order(&body, order_url)
    }

    /// Fetch an authorization object by URL (POST-as-GET).
    pub async fn get_authorization(
        &self,
        acct: &Account,
        url: &str,
    ) -> Result<Authorization, ClientError> {
        let (status, body, _) = self.post_kid(acct, url, None).await?;
        if status != StatusCode::OK {
            return Err(acme_error(&body, status, "get-authorization"));
        }
        serde_json::from_value(body)
            .map_err(|e| ClientError::Http(format!("parse authorization: {e}")))
    }

    /// Trigger a challenge (POST empty JSON object `{}` to the challenge URL).
    pub async fn trigger_challenge(
        &self,
        acct: &Account,
        challenge: &Challenge,
    ) -> Result<(), ClientError> {
        let url = &challenge.url;
        let payload = b"{}";

        let (status, body, _) = self.post_kid(acct, url, Some(payload)).await?;
        if status != StatusCode::OK {
            return Err(acme_error(&body, status, "trigger-challenge"));
        }
        Ok(())
    }

    /// Poll an order URL until status is `"ready"` or `"valid"`.
    ///
    /// Polls with exponential backoff (1 ms → doubles → cap 2 s), timeout 30 s.
    pub async fn poll_order(&self, acct: &Account, order_url: &str) -> Result<Order, ClientError> {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        let mut delay_ms: u64 = 1;

        loop {
            sleep(Duration::from_millis(delay_ms)).await;
            delay_ms = (delay_ms * 2).min(2000);

            if tokio::time::Instant::now() > deadline {
                return Err(ClientError::Http("timed out polling order".into()));
            }

            let (_, body, _) = self.post_kid(acct, order_url, None).await?;

            match body["status"].as_str() {
                Some("ready") | Some("valid") => return parse_order(&body, order_url.to_owned()),
                Some("invalid") => {
                    return Err(ClientError::Http(format!(
                        "order invalid: {}",
                        body["error"]
                    )))
                }
                _ => continue,
            }
        }
    }

    /// Finalize an order by posting the DER-encoded CSR.
    ///
    /// Returns the updated order (which should have `status: "valid"` and a
    /// `certificate` URL if the server finalizes synchronously).  If not, call
    /// `poll_order()` to wait.
    pub async fn finalize(
        &self,
        acct: &Account,
        order: &Order,
        csr_der: &[u8],
    ) -> Result<Order, ClientError> {
        let csr_b64 = URL_SAFE_NO_PAD.encode(csr_der);
        let payload = serde_json::json!({ "csr": csr_b64 });

        let (status, body, _) = self
            .post_kid(acct, &order.finalize, Some(payload.to_string().as_bytes()))
            .await?;
        if status != StatusCode::OK {
            return Err(acme_error(&body, status, "finalize"));
        }
        parse_order(&body, order.url.clone())
    }

    /// Download the issued certificate (POST-as-GET the certificate URL).
    ///
    /// Returns the PEM-encoded certificate chain bytes.
    pub async fn download_certificate(
        &self,
        acct: &Account,
        cert_url: &str,
    ) -> Result<Vec<u8>, ClientError> {
        let (status, _, raw) = self.post_kid_raw(acct, cert_url, None).await?;
        if status != StatusCode::OK {
            return Err(ClientError::Http(format!("download-certificate: {status}")));
        }
        Ok(raw)
    }

    // ── Internal signing helpers ───────────────────────────────────────────────

    /// POST with the account URL as `kid`, with badNonce retry.
    async fn post_kid(
        &self,
        acct: &Account,
        url: &str,
        payload: Option<&[u8]>,
    ) -> Result<(StatusCode, Value, HeaderMap), ClientError> {
        loop {
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
                *self.cached_nonce.lock().await = None;
                continue;
            }
            return Ok((status, body, headers));
        }
    }

    /// Like `post_kid` but returns raw bytes instead of JSON (for PEM download).
    async fn post_kid_raw(
        &self,
        acct: &Account,
        url: &str,
        payload: Option<&[u8]>,
    ) -> Result<(StatusCode, HeaderMap, Vec<u8>), ClientError> {
        loop {
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
                    *self.cached_nonce.lock().await = None;
                    continue;
                }
            }
            return Ok((status, headers, body_bytes));
        }
    }

    /// Low-level: POST a pre-serialised JWS body, return (status, parsed JSON, headers).
    /// Does NOT perform badNonce retry — callers handle that.
    async fn post_jws_once(
        &self,
        url: &str,
        body: &Value,
    ) -> Result<(StatusCode, Value, HeaderMap), ClientError> {
        let body_bytes = serde_json::to_vec(body)
            .map_err(|e| ClientError::Jose(akamu_jose::JoseError::Json(e)))?;
        let (status, headers, raw) = self.http_post_raw(url, body_bytes).await?;
        let json = serde_json::from_slice(&raw).unwrap_or(Value::Null);
        Ok((status, json, headers))
    }

    /// Send an HTTP POST with `Content-Type: application/jose+json`.
    /// Caches the `Replay-Nonce` from the response for the next request.
    async fn http_post_raw(
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

        let resp = self
            .http
            .request(req)
            .await
            .map_err(|e| ClientError::Http(format!("HTTP POST: {e}")))?;

        let status = resp.status();
        let headers = resp.headers().clone();
        // Cache the nonce from the response for the next request.
        if let Ok(nonce) = nonce_from_headers(&headers) {
            *self.cached_nonce.lock().await = Some(nonce);
        }
        let raw = resp
            .into_body()
            .collect()
            .await
            .map_err(|e| ClientError::Http(format!("read body: {e}")))?
            .to_bytes()
            .to_vec();

        Ok((status, headers, raw))
    }

    /// Return a nonce: use the cached one if available, otherwise HEAD /new-nonce.
    async fn fetch_nonce(&self) -> Result<String, ClientError> {
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
        let resp = self
            .http
            .request(req)
            .await
            .map_err(|e| ClientError::Http(format!("HEAD new-nonce: {e}")))?;
        nonce_from_headers(resp.headers())
    }
}

// ── Utility functions ─────────────────────────────────────────────────────────

/// GET a URL and parse the response body as JSON.
async fn get_json(http: &HyperClient, url: &str) -> Result<Value, ClientError> {
    let req = Request::builder()
        .method(Method::GET)
        .uri(url)
        .body(Full::<Bytes>::new(Bytes::new()))
        .map_err(|e| ClientError::Http(format!("build GET request: {e}")))?;

    let resp = http
        .request(req)
        .await
        .map_err(|e| ClientError::Http(format!("GET {url}: {e}")))?;

    if !resp.status().is_success() {
        return Err(ClientError::Http(format!("GET {url}: {}", resp.status())));
    }

    let raw = resp
        .into_body()
        .collect()
        .await
        .map_err(|e| ClientError::Http(format!("read body: {e}")))?
        .to_bytes();

    serde_json::from_slice(&raw)
        .map_err(|e| ClientError::Http(format!("parse directory JSON: {e}")))
}

fn location_hdr(headers: &HeaderMap) -> Result<String, ClientError> {
    headers
        .get(LOCATION)
        .and_then(|v: &hyper::header::HeaderValue| v.to_str().ok())
        .map(String::from)
        .ok_or_else(|| ClientError::Http("missing Location header".into()))
}

fn nonce_from_headers(headers: &HeaderMap) -> Result<String, ClientError> {
    headers
        .get("replay-nonce")
        .and_then(|v| v.to_str().ok())
        .map(String::from)
        .ok_or_else(|| ClientError::Http("missing Replay-Nonce header".into()))
}

fn acme_error(body: &Value, status: StatusCode, op: &str) -> ClientError {
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

fn parse_order(body: &Value, url: String) -> Result<Order, ClientError> {
    let status = body["status"].as_str().unwrap_or("pending").to_string();
    let finalize = body["finalize"]
        .as_str()
        .ok_or_else(|| ClientError::Http("order missing finalize URL".into()))?
        .to_string();
    let authorizations = body["authorizations"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    let certificate = body["certificate"].as_str().map(String::from);
    let identifiers = body["identifiers"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|v| serde_json::from_value(v.clone()).ok())
                .collect()
        })
        .unwrap_or_default();

    Ok(Order {
        status,
        url,
        finalize,
        authorizations,
        certificate,
        identifiers,
    })
}
