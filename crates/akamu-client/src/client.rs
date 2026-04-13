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
    types::{
        AccountOptions, Authorization, Challenge, Identifier, Order, RenewalInfo, StarOrder,
        StarOrderParams,
    },
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
        let contacts = extract_contacts(&body);
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

    /// Look up an existing account by key without creating one (RFC 8555 §7.3.1).
    ///
    /// Returns `Err(ClientError::Acme { acme_type: "urn:ietf:params:acme:error:accountDoesNotExist", .. })`
    /// if no account exists for this key.
    pub async fn find_account(&self, key: Arc<AccountKey>) -> Result<Account, ClientError> {
        let url = &self.new_account_url;
        let payload = serde_json::json!({ "onlyReturnExisting": true });
        let payload_str = payload.to_string();

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

        if status != StatusCode::OK {
            return Err(acme_error(&body, status, "find-account"));
        }
        let account_url = location_hdr(&headers)?;
        let contacts = extract_contacts(&body);
        let account_status = body["status"].as_str().unwrap_or("valid").to_string();
        Ok(Account::new(account_url, account_status, contacts, key))
    }

    /// Fetch the current account state from the server (RFC 8555 §7.3.2).
    pub async fn get_account(&self, acct: &Account) -> Result<Account, ClientError> {
        let (status, body, headers) = self.post_kid(acct, &acct.url, None).await?;
        if status != StatusCode::OK {
            return Err(acme_error(&body, status, "get-account"));
        }
        let account_url = headers
            .get(hyper::header::LOCATION)
            .and_then(|v| v.to_str().ok())
            .map(String::from)
            .unwrap_or_else(|| acct.url.clone());
        let contacts = extract_contacts(&body);
        let account_status = body["status"].as_str().unwrap_or("valid").to_string();
        Ok(Account::new(
            account_url,
            account_status,
            contacts,
            Arc::clone(&acct.key),
        ))
    }

    /// Update account contacts (RFC 8555 §7.3.2).
    ///
    /// Returns the updated account.
    pub async fn update_account(
        &self,
        acct: &Account,
        contacts: &[&str],
    ) -> Result<Account, ClientError> {
        let payload = serde_json::json!({ "contact": contacts });
        let (status, body, _) = self
            .post_kid(acct, &acct.url, Some(payload.to_string().as_bytes()))
            .await?;
        if status != StatusCode::OK {
            return Err(acme_error(&body, status, "update-account"));
        }
        let updated_contacts = extract_contacts(&body);
        let account_status = body["status"].as_str().unwrap_or("valid").to_string();
        Ok(Account::new(
            acct.url.clone(),
            account_status,
            updated_contacts,
            Arc::clone(&acct.key),
        ))
    }

    /// Roll over the account key (RFC 8555 §7.3.5).
    ///
    /// The server atomically replaces the account key. After this call, `acct`
    /// is no longer usable — use the returned `Account` (which holds `new_key`)
    /// for all subsequent operations.
    pub async fn key_change(
        &self,
        acct: &Account,
        new_key: Arc<AccountKey>,
    ) -> Result<Account, ClientError> {
        let url = &self.key_change_url;

        // Inner JWS: signed with the new key (jwk), url = key-change endpoint.
        // Payload: {"account": "<account_url>", "oldKey": <serialised old JWK>}
        let inner_nonce = self.fetch_nonce().await?;
        let old_jwk_json = serde_json::to_value(acct.key.public_jwk())
            .map_err(|e| ClientError::Jose(akamu_jose::JoseError::Json(e)))?;
        let inner_payload = serde_json::json!({
            "account": acct.url,
            "oldKey": old_jwk_json,
        });
        let inner_key_ref = JwsKeyRef::Jwk {
            jwk: new_key.public_jwk().clone(),
        };
        let inner_jws = JwsFlattened::sign(
            new_key.private_key(),
            new_key.alg(),
            &inner_nonce,
            url,
            inner_key_ref,
            Some(inner_payload.to_string().as_bytes()),
        )?;
        let inner_jws_value = serde_json::to_value(&inner_jws)
            .map_err(|e| ClientError::Jose(akamu_jose::JoseError::Json(e)))?;

        // Outer JWS: signed with the old account key (kid = account URL).
        // The outer payload is the serialised inner JWS object.
        // post_kid handles the outer nonce and badNonce retry internally.
        let (status, body, _) = self
            .post_kid(acct, url, Some(inner_jws_value.to_string().as_bytes()))
            .await?;
        if status != StatusCode::OK {
            return Err(acme_error(&body, status, "key-change"));
        }

        let contacts = extract_contacts(&body);
        let account_status = body["status"].as_str().unwrap_or("valid").to_string();
        Ok(Account::new(
            acct.url.clone(),
            account_status,
            contacts,
            new_key,
        ))
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

    /// Trigger an onion-csr-01 challenge (RFC 9799 §3.2).
    ///
    /// Posts `{"csr": "<base64url DER>"}` to the challenge URL and returns
    /// the updated [`Challenge`] object from the server response.
    pub async fn trigger_challenge_onion(
        &self,
        acct: &Account,
        url: &str,
        csr_der: &[u8],
    ) -> Result<Challenge, ClientError> {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine as _;
        let csr_b64 = URL_SAFE_NO_PAD.encode(csr_der);
        let payload = serde_json::json!({"csr": csr_b64});
        let body_bytes =
            serde_json::to_vec(&payload).map_err(|e| ClientError::Http(format!("JSON: {e}")))?;

        let (status, body, _) = self.post_kid(acct, url, Some(&body_bytes)).await?;
        if status != StatusCode::OK {
            return Err(acme_error(&body, status, "trigger-challenge-onion"));
        }
        serde_json::from_value(body).map_err(|e| ClientError::Http(format!("parse challenge: {e}")))
    }

    /// Poll an order URL until status is `"ready"` or `"valid"`.
    ///
    /// Polls with exponential backoff (1 ms → doubles → cap 2 s), timeout 30 s.
    /// Respects the `Retry-After` header from the server when present.
    pub async fn poll_order(&self, acct: &Account, order_url: &str) -> Result<Order, ClientError> {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        let mut delay_ms: u64 = 1;

        loop {
            sleep(Duration::from_millis(delay_ms)).await;

            if tokio::time::Instant::now() > deadline {
                return Err(ClientError::Http("timed out polling order".into()));
            }

            let (_, body, headers) = self.post_kid(acct, order_url, None).await?;

            match body["status"].as_str() {
                Some("ready") | Some("valid") => return parse_order(&body, order_url.to_owned()),
                Some("invalid") => {
                    return Err(ClientError::Http(format!(
                        "order invalid: {}",
                        body["error"]
                    )))
                }
                _ => {}
            }

            // Use Retry-After if the server sent one, otherwise use exponential backoff.
            let retry_after = headers
                .get("retry-after")
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.parse::<u64>().ok());
            let sleep_ms = retry_after.map(|s| s * 1000).unwrap_or(delay_ms);
            sleep(Duration::from_millis(sleep_ms)).await;
            // Only advance the backoff counter when Retry-After was absent.
            if retry_after.is_none() {
                delay_ms = (delay_ms * 2).min(2000);
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

    /// Fetch renewal information for a certificate (RFC 9773 ARI).
    ///
    /// `cert_pem` is the PEM-encoded certificate chain (as returned by
    /// `download_certificate()`). Only the first certificate (end-entity) is used.
    ///
    /// Returns `Err` if the server does not advertise an ARI endpoint.
    pub async fn get_renewal_info(&self, cert_pem: &[u8]) -> Result<RenewalInfo, ClientError> {
        use synta::{Decoder, Encoding};
        use synta_certificate::oids;
        use synta_certificate::owned::Certificate;

        let renewal_info_url = self.renewal_info_url.as_deref().ok_or_else(|| {
            ClientError::Http("server does not support ARI (no renewalInfo in directory)".into())
        })?;

        // Parse the end-entity certificate.
        let cert_ders = synta_certificate::pem_to_der(cert_pem);
        let cert_der = cert_ders
            .into_iter()
            .next()
            .ok_or_else(|| ClientError::Crypto("no certificate found in PEM".into()))?;

        let cert: Certificate = {
            let mut dec = Decoder::new(&cert_der, Encoding::Der);
            dec.decode()
                .map_err(|e| ClientError::Crypto(format!("cert parse: {e}")))?
        };

        // Extract serial bytes.
        let serial_bytes = cert.tbs_certificate.serial_number.as_bytes().to_vec();

        // Extract AKI key identifier bytes.
        let extensions = cert
            .tbs_certificate
            .extensions
            .as_ref()
            .ok_or_else(|| ClientError::Crypto("certificate has no extensions".into()))?;
        let aki_ext = extensions
            .iter()
            .find(|e| e.extn_id.components() == oids::AUTHORITY_KEY_IDENTIFIER)
            .ok_or_else(|| ClientError::Crypto("certificate missing AKI extension".into()))?;
        let aki_bytes = aki_key_id_bytes(aki_ext.extn_value.as_bytes())
            .ok_or_else(|| ClientError::Crypto("could not parse AKI key identifier".into()))?;

        // Build cert-id and fetch.
        let cert_id = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(&aki_bytes),
            URL_SAFE_NO_PAD.encode(&serial_bytes),
        );
        let url = format!("{}/{}", renewal_info_url.trim_end_matches('/'), cert_id);

        let req = hyper::Request::builder()
            .method(hyper::Method::GET)
            .uri(&url)
            .body(http_body_util::Full::<hyper::body::Bytes>::new(
                hyper::body::Bytes::new(),
            ))
            .map_err(|e| ClientError::Http(format!("build ARI request: {e}")))?;
        let resp = self
            .http
            .request(req)
            .await
            .map_err(|e| ClientError::Http(format!("GET {url}: {e}")))?;
        let status = resp.status();
        let retry_after_secs = resp
            .headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<u64>().ok());
        let raw = resp
            .into_body()
            .collect()
            .await
            .map_err(|e| ClientError::Http(format!("read ARI body: {e}")))?
            .to_bytes();
        if !status.is_success() {
            return Err(ClientError::Http(format!("get-renewal-info {status}")));
        }
        let body: serde_json::Value = serde_json::from_slice(&raw)
            .map_err(|e| ClientError::Http(format!("parse ARI JSON: {e}")))?;
        let window_start = body["suggestedWindow"]["start"]
            .as_str()
            .ok_or_else(|| ClientError::Http("ARI missing suggestedWindow.start".into()))?
            .to_string();
        let window_end = body["suggestedWindow"]["end"]
            .as_str()
            .ok_or_else(|| ClientError::Http("ARI missing suggestedWindow.end".into()))?
            .to_string();
        Ok(RenewalInfo {
            window_start,
            window_end,
            retry_after_secs,
        })
    }

    /// Revoke a certificate using the account key (RFC 8555 §7.6).
    ///
    /// `cert_der` is the DER-encoded end-entity certificate (not the PEM bundle).
    /// `reason` is an optional CRL reason code (0–10, excluding 7).
    pub async fn revoke_certificate(
        &self,
        acct: &Account,
        cert_der: &[u8],
        reason: Option<u8>,
    ) -> Result<(), ClientError> {
        let cert_b64 = URL_SAFE_NO_PAD.encode(cert_der);
        let mut payload = serde_json::json!({ "certificate": cert_b64 });
        if let Some(r) = reason {
            payload["reason"] = serde_json::json!(r);
        }
        let url = self.revoke_cert_url.clone();
        let (status, body, _) = self
            .post_kid(acct, &url, Some(payload.to_string().as_bytes()))
            .await?;
        if status != StatusCode::OK {
            return Err(acme_error(&body, status, "revoke-cert"));
        }
        Ok(())
    }

    /// Revoke a certificate using the certificate's own private key (RFC 8555 §7.6).
    ///
    /// Use this when the account key is unavailable but the cert's private key is known.
    pub async fn revoke_certificate_with_cert_key(
        &self,
        cert_key: &AccountKey,
        cert_der: &[u8],
        reason: Option<u8>,
    ) -> Result<(), ClientError> {
        let nonce = self.fetch_nonce().await?;
        let url = &self.revoke_cert_url;
        let cert_b64 = URL_SAFE_NO_PAD.encode(cert_der);
        let mut payload = serde_json::json!({ "certificate": cert_b64 });
        if let Some(r) = reason {
            payload["reason"] = serde_json::json!(r);
        }
        let key_ref = JwsKeyRef::Jwk {
            jwk: cert_key.public_jwk().clone(),
        };
        let jws = JwsFlattened::sign(
            cert_key.private_key(),
            cert_key.alg(),
            &nonce,
            url,
            key_ref,
            Some(payload.to_string().as_bytes()),
        )?;
        let jws_value = serde_json::to_value(&jws)
            .map_err(|e| ClientError::Jose(akamu_jose::JoseError::Json(e)))?;
        let (status, body, _) = self.post_jws_once(url, &jws_value).await?;
        if status != StatusCode::OK {
            return Err(acme_error(&body, status, "revoke-cert"));
        }
        Ok(())
    }

    // ── STAR order lifecycle (RFC 8739) ──────────────────────────────────────────

    /// Place a new STAR (Short-Term, Automatically Renewed) order (RFC 8739 §3).
    ///
    /// Returns a `StarOrder` with status `"pending"`.  The caller must still
    /// complete the normal challenge/finalize flow; after finalization the
    /// server will populate `star_certificate`.
    ///
    /// If the server does not support STAR, it will return an ACME error response
    /// (typically `urn:ietf:params:acme:error:malformed` or a 4xx HTTP status),
    /// which is surfaced as `Err(ClientError::Acme { .. })` or
    /// `Err(ClientError::Http { .. })`.  Check the directory for `autoRenewal` in
    /// `meta` before calling this method if STAR support cannot be assumed.
    pub async fn new_star_order(
        &self,
        acct: &Account,
        params: &StarOrderParams<'_>,
    ) -> Result<StarOrder, ClientError> {
        let url = &self.new_order_url;

        let mut auto_renewal = serde_json::json!({
            "end-date":  params.end_date,
            "lifetime":  params.lifetime_secs,
        });
        if let Some(sd) = params.start_date {
            auto_renewal["start-date"] = serde_json::json!(sd);
        }
        if params.lifetime_adjust_secs > 0 {
            auto_renewal["lifetime-adjust"] = serde_json::json!(params.lifetime_adjust_secs);
        }
        if params.allow_certificate_get {
            auto_renewal["allow-certificate-get"] = serde_json::json!(true);
        }

        let payload = serde_json::json!({
            "identifiers":   params.identifiers,
            "auto-renewal":  auto_renewal,
        });

        let (status, body, headers) = self
            .post_kid(acct, url, Some(payload.to_string().as_bytes()))
            .await?;
        if status != StatusCode::CREATED {
            return Err(acme_error(&body, status, "new-star-order"));
        }

        let order_url = location_hdr(&headers)?;
        parse_star_order(&body, order_url)
    }

    /// Cancel a STAR order (RFC 8739 §3.3).
    ///
    /// Posts `{"status":"canceled"}` to the order URL.  After cancellation the
    /// `star-certificate` endpoint returns HTTP 403.
    pub async fn cancel_star_order(
        &self,
        acct: &Account,
        order_url: &str,
    ) -> Result<(), ClientError> {
        let payload = serde_json::json!({"status": "canceled"});
        let (status, body, _) = self
            .post_kid(acct, order_url, Some(payload.to_string().as_bytes()))
            .await?;
        if status != StatusCode::OK {
            return Err(acme_error(&body, status, "cancel-star-order"));
        }
        Ok(())
    }

    /// Download the current rolling STAR certificate via an unauthenticated GET.
    ///
    /// Only works when the order was created with `allow_certificate_get: true`
    /// and the server has `star_allow_certificate_get` enabled.
    /// Returns the PEM-encoded certificate chain bytes.
    pub async fn get_star_certificate(&self, star_cert_url: &str) -> Result<Vec<u8>, ClientError> {
        let req = Request::builder()
            .method(Method::GET)
            .uri(star_cert_url)
            .body(Full::<Bytes>::new(Bytes::new()))
            .map_err(|e| ClientError::Http(format!("build star-cert request: {e}")))?;
        let resp = self
            .http
            .request(req)
            .await
            .map_err(|e| ClientError::Http(format!("GET {star_cert_url}: {e}")))?;
        let status = resp.status();
        let raw = resp
            .into_body()
            .collect()
            .await
            .map_err(|e| ClientError::Http(format!("read star-cert body: {e}")))?
            .to_bytes()
            .to_vec();
        if !status.is_success() {
            return Err(ClientError::Http(format!(
                "get-star-certificate {status}: {}",
                String::from_utf8_lossy(&raw)
            )));
        }
        Ok(raw)
    }

    /// Download the current rolling STAR certificate via an authenticated POST-as-GET.
    ///
    /// Use this when `allow-certificate-get` was not requested or when authenticated
    /// access is required.  Returns the PEM-encoded certificate chain bytes.
    pub async fn download_star_certificate(
        &self,
        acct: &Account,
        star_cert_url: &str,
    ) -> Result<Vec<u8>, ClientError> {
        let (status, _, raw) = self.post_kid_raw(acct, star_cert_url, None).await?;
        if status != StatusCode::OK {
            return Err(ClientError::Http(format!(
                "download-star-certificate: {status}"
            )));
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

fn extract_contacts(body: &Value) -> Vec<String> {
    body["contact"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default()
}

fn parse_star_order(body: &Value, url: String) -> Result<StarOrder, ClientError> {
    let status = body["status"].as_str().unwrap_or("pending").to_string();
    let finalize = body["finalize"]
        .as_str()
        .ok_or_else(|| ClientError::Http("STAR order missing finalize URL".into()))?
        .to_string();
    let authorizations = body["authorizations"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    let star_certificate = body["star-certificate"].as_str().map(String::from);

    Ok(StarOrder {
        status,
        url,
        finalize,
        authorizations,
        star_certificate,
    })
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

/// Extract the raw key-identifier bytes from a DER-encoded AKI extension value.
///
/// The AKI extension value (the content of the OCTET STRING wrapper in the
/// `Extension.extnValue` field) has the structure:
/// ```text
/// SEQUENCE {
///   [0] IMPLICIT PRIMITIVE (keyIdentifier), length N
///     <N bytes>  -- the raw SHA-1 hash
/// }
/// ```
fn aki_key_id_bytes(ext_value: &[u8]) -> Option<Vec<u8>> {
    // Skip SEQUENCE (tag 0x30 + length).
    if ext_value.len() < 4 || ext_value[0] != 0x30 {
        return None;
    }
    let content_start = if ext_value[1] & 0x80 == 0 {
        2
    } else {
        2 + (ext_value[1] & 0x7f) as usize
    };
    let content = ext_value.get(content_start..)?;
    // [0] IMPLICIT tag = 0x80
    if content.is_empty() || content[0] != 0x80 {
        return None;
    }
    let len = *content.get(1)? as usize;
    content.get(2..2 + len).map(<[u8]>::to_vec)
}
