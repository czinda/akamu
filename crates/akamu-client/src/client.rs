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
    unix::unix_dispatch,
};

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
/// the inner `OsslChainVerifier`.  Logging is at `debug` level so it is
/// a no-op unless the tracing subscriber is configured at that level.
#[derive(Debug)]
struct LoggingChainVerifier {
    inner: rustls_native_ossl::cert_verifier::OsslChainVerifier,
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
    new_account_url: String,
    new_order_url: String,
    revoke_cert_url: String,
    key_change_url: String,
    renewal_info_url: Option<String>,
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
        let mut all_ca_ders: Vec<CertificateDer<'_>> = native
            .certs
            .iter()
            .map(|c| CertificateDer::from(c.as_ref()))
            .collect();
        for der in &extra_ders {
            all_ca_ders.push(CertificateDer::from(der.as_slice()));
        }

        let chain_verifier =
            rustls_native_ossl::cert_verifier::OsslChainVerifier::new(&all_ca_ders)
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

        // Retry loop for badNonce (max 5 attempts).
        let mut last_result = None;
        for attempt in 0..5_u8 {
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
                if attempt == 4 {
                    return Err(ClientError::Http(
                        "badNonce retry limit exceeded".to_string(),
                    ));
                }
                *self.cached_nonce.lock().await = None;
                continue;
            }
            last_result = Some((status, body, headers));
            break;
        }
        let (status, body, headers) =
            last_result.expect("loop always sets last_result before break");

        // RFC 8555 §7.3.1: 201 = new account, 200 = existing account returned.
        if status != StatusCode::CREATED && status != StatusCode::OK {
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

        let mut last_result = None;
        for attempt in 0..5_u8 {
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
                if attempt == 4 {
                    return Err(ClientError::Http(
                        "badNonce retry limit exceeded".to_string(),
                    ));
                }
                *self.cached_nonce.lock().await = None;
                continue;
            }
            last_result = Some((status, body, headers));
            break;
        }
        let (status, body, headers) =
            last_result.expect("loop always sets last_result before break");

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
        let account_status = body["status"]
            .as_str()
            .ok_or_else(|| ClientError::Http("key-change response missing 'status' field".into()))?
            .to_string();
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
        self.new_order_with_profile(acct, ids, None).await
    }

    /// Place a new order with an optional profile identifier (draft-aaron-acme-profiles-01).
    pub async fn new_order_with_profile(
        &self,
        acct: &Account,
        ids: &[Identifier],
        profile: Option<&str>,
    ) -> Result<Order, ClientError> {
        let url = &self.new_order_url;
        let mut payload = serde_json::json!({ "identifiers": ids });
        if let Some(p) = profile {
            payload["profile"] = serde_json::json!(p);
        }

        let payload_bytes = serde_json::to_vec(&payload)
            .map_err(|e| ClientError::Http(format!("serialize new-order payload: {e}")))?;
        let (status, body, headers) = self.post_kid(acct, url, Some(&payload_bytes)).await?;
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
    /// Respond to a `tkauth-01` challenge with an authority token.
    ///
    /// Posts `{"tkauth": authority_token}` to the challenge URL, triggering
    /// server-side validation per RFC 9447.
    pub async fn trigger_challenge_tkauth(
        &self,
        acct: &Account,
        url: &str,
        authority_token: &str,
    ) -> Result<Challenge, ClientError> {
        let payload = serde_json::json!({"tkauth": authority_token});
        let body_bytes =
            serde_json::to_vec(&payload).map_err(|e| ClientError::Http(format!("JSON: {e}")))?;
        let (status, body, _) = self.post_kid(acct, url, Some(&body_bytes)).await?;
        if status != StatusCode::OK {
            return Err(acme_error(&body, status, "trigger-challenge-tkauth"));
        }
        serde_json::from_value(body).map_err(|e| ClientError::Http(format!("parse challenge: {e}")))
    }

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
                    let detail = if body["error"].is_null() {
                        "challenge validation failed (check challenge errors on the authorization)"
                            .to_string()
                    } else {
                        body["error"].to_string()
                    };
                    return Err(ClientError::Http(format!("order invalid: {detail}")));
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
    /// `cert_bytes` is either a PEM-encoded certificate chain or a raw
    /// DER-encoded certificate (including MTC `StandaloneCertificate` objects).
    /// Only the first (end-entity) certificate is used.
    ///
    /// Both X.509 `Certificate` and MTC `StandaloneCertificate` encode
    /// `TBSCertificate` as their first SEQUENCE field, so ARI cert-id
    /// construction works for either format.
    ///
    /// Returns `Err` if the server does not advertise an ARI endpoint.
    pub async fn get_renewal_info(&self, cert_bytes: &[u8]) -> Result<RenewalInfo, ClientError> {
        let renewal_info_url = self.renewal_info_url.as_deref().ok_or_else(|| {
            ClientError::Http("server does not support ARI (no renewalInfo in directory)".into())
        })?;

        let (serial_bytes, aki_bytes) = cert_id_from_bytes(cert_bytes)?;

        // Build cert-id and fetch.
        let cert_id = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(&aki_bytes),
            URL_SAFE_NO_PAD.encode(&serial_bytes),
        );
        let url = format!("{}/{}", renewal_info_url.trim_end_matches('/'), cert_id);

        let req = Request::builder()
            .method(Method::GET)
            .uri(&url)
            .body(Full::<Bytes>::new(Bytes::new()))
            .map_err(|e| ClientError::Http(format!("build ARI request: {e}")))?;
        let (status, headers, raw) = self.http_dispatch(req).await?;
        let retry_after_secs = headers
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<u64>().ok());
        let raw = hyper::body::Bytes::from(raw);
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
        let url = &self.revoke_cert_url;
        let cert_b64 = URL_SAFE_NO_PAD.encode(cert_der);
        let mut payload_obj = serde_json::json!({ "certificate": cert_b64 });
        if let Some(r) = reason {
            payload_obj["reason"] = serde_json::json!(r);
        }
        let payload_str = payload_obj.to_string();

        for attempt in 0..5_u8 {
            let nonce = self.fetch_nonce().await?;
            let key_ref = JwsKeyRef::Jwk {
                jwk: cert_key.public_jwk().clone(),
            };
            let jws = JwsFlattened::sign(
                cert_key.private_key(),
                cert_key.alg(),
                &nonce,
                url,
                key_ref,
                Some(payload_str.as_bytes()),
            )?;
            let jws_value = serde_json::to_value(&jws)
                .map_err(|e| ClientError::Jose(akamu_jose::JoseError::Json(e)))?;
            let (status, body, _) = self.post_jws_once(url, &jws_value).await?;
            if body["type"].as_str() == Some("urn:ietf:params:acme:error:badNonce") {
                if attempt == 4 {
                    return Err(ClientError::Http(
                        "badNonce retry limit exceeded".to_string(),
                    ));
                }
                *self.cached_nonce.lock().await = None;
                continue;
            }
            if status != StatusCode::OK {
                return Err(acme_error(&body, status, "revoke-cert"));
            }
            return Ok(());
        }
        unreachable!()
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
        let (status, _, raw) = self.http_dispatch(req).await?;
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

    // ── Internal transport dispatch ───────────────────────────────────────────

    /// Send an HTTP request, routing `http+unix://` URIs to a Unix domain socket
    /// and all other URIs through the TLS client.
    ///
    /// Returns `(status, headers, body_bytes)`.
    async fn http_dispatch(
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
    async fn post_kid(
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
    async fn post_kid_raw(
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
    async fn post_jws_once(
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

        let (status, headers, raw) = self.http_dispatch(req).await?;
        // Cache the nonce from the response for the next request.
        if let Ok(nonce) = nonce_from_headers(&headers) {
            *self.cached_nonce.lock().await = Some(nonce);
        }
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

    let profile = body
        .get("profile")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    Ok(Order {
        status,
        url,
        finalize,
        authorizations,
        certificate,
        identifiers,
        profile,
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
/// Extract `(serial_bytes, aki_bytes)` from a PEM or binary-DER certificate.
///
/// Accepts X.509 `Certificate` PEM/DER and MTC `StandaloneCertificate` DER alike,
/// since both begin with `SEQUENCE { TBSCertificate, ... }`.
fn cert_id_from_bytes(cert_bytes: &[u8]) -> Result<(Vec<u8>, Vec<u8>), ClientError> {
    use synta::{Decoder, Encoding};
    use synta_certificate::oids;
    use synta_certificate::owned::{Certificate, TBSCertificate};

    let extract = |tbs: TBSCertificate| -> Result<(Vec<u8>, Vec<u8>), ClientError> {
        let serial = tbs.serial_number.as_bytes().to_vec();
        let extensions = tbs
            .extensions
            .as_ref()
            .ok_or_else(|| ClientError::Crypto("certificate has no extensions".into()))?;
        let aki_ext = extensions
            .iter()
            .find(|e| e.extn_id.components() == oids::AUTHORITY_KEY_IDENTIFIER)
            .ok_or_else(|| ClientError::Crypto("certificate missing AKI extension".into()))?;
        let aki = aki_key_id_bytes(aki_ext.extn_value.as_bytes())
            .ok_or_else(|| ClientError::Crypto("could not parse AKI key identifier".into()))?;
        Ok((serial, aki))
    };

    let cert_ders = synta_certificate::pem_to_der(cert_bytes);
    if let Some(cert_der) = cert_ders.into_iter().next() {
        let cert: Certificate = {
            let mut dec = Decoder::new(&cert_der, Encoding::Der);
            dec.decode()
                .map_err(|e| ClientError::Crypto(format!("cert parse: {e}")))?
        };
        extract(cert.tbs_certificate)
    } else {
        // Binary DER: validate_envelope locates the TBSCertificate TLV.
        let tbs_range = synta_certificate::validate_envelope(cert_bytes).map_err(|_| {
            ClientError::Crypto(
                "no PEM certificate found and binary DER is not a valid SEQUENCE".into(),
            )
        })?;
        let tbs_der = cert_bytes
            .get(tbs_range)
            .ok_or_else(|| ClientError::Crypto("DER input is truncated or malformed".into()))?;
        let tbs: TBSCertificate = {
            let mut dec = Decoder::new(tbs_der, Encoding::Der);
            dec.decode()
                .map_err(|e| ClientError::Crypto(format!("TBSCertificate parse: {e}")))?
        };
        extract(tbs)
    }
}

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

/// Format a JWK thumbprint as an RFC 9447 fingerprint string.
///
/// `thumbprint_b64url` is the base64url (no padding) SHA-256 of the canonical
/// JWK.  Returns `"SHA256 XX:XX:..."` (colon-separated uppercase hex bytes).
pub fn rfc9447_fingerprint(thumbprint_b64url: &str) -> Result<String, ClientError> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;
    let raw = URL_SAFE_NO_PAD
        .decode(thumbprint_b64url)
        .map_err(|e| ClientError::Http(format!("base64url decode thumbprint: {e}")))?;
    Ok(format!(
        "SHA256 {}",
        raw.iter()
            .map(|b| format!("{b:02X}"))
            .collect::<Vec<_>>()
            .join(":")
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cert_id_from_bytes_rejects_garbage() {
        let err = cert_id_from_bytes(b"not a certificate").unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("no PEM certificate found")
                || msg.contains("DER input")
                || msg.contains("parse"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn cert_id_from_bytes_rejects_truncated_der() {
        // A valid SEQUENCE tag/length prefix but truncated body — must not panic.
        let truncated = &[0x30u8, 0x82, 0x01, 0x00, 0x01, 0x02];
        let err = cert_id_from_bytes(truncated).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("no PEM certificate found")
                || msg.contains("DER input")
                || msg.contains("parse"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn aki_key_id_bytes_empty_returns_none() {
        assert!(aki_key_id_bytes(&[]).is_none());
    }

    #[test]
    fn aki_key_id_bytes_wrong_tag_returns_none() {
        assert!(aki_key_id_bytes(&[0x31, 0x04, 0x80, 0x02, 0xAA, 0xBB]).is_none());
    }

    #[test]
    fn aki_key_id_bytes_happy_path() {
        // SEQUENCE { [0] PRIMITIVE 0xAA 0xBB }
        let aki_der = &[0x30u8, 0x04, 0x80, 0x02, 0xAA, 0xBB];
        assert_eq!(aki_key_id_bytes(aki_der), Some(vec![0xAA, 0xBB]));
    }

    #[test]
    fn rfc9447_fingerprint_formats_correctly() {
        // SHA-256 of the empty string, base64url-encoded (no padding).
        // SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        let b64url = "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU";
        let fp = rfc9447_fingerprint(b64url).unwrap();
        assert_eq!(
            fp,
            "SHA256 E3:B0:C4:42:98:FC:1C:14:9A:FB:F4:C8:99:6F:B9:24:\
             27:AE:41:E4:64:9B:93:4C:A4:95:99:1B:78:52:B8:55"
        );
    }

    #[test]
    fn rfc9447_fingerprint_rejects_invalid_base64() {
        let err = rfc9447_fingerprint("not!valid!base64url").unwrap_err();
        assert!(
            err.to_string().contains("base64") || err.to_string().contains("decode"),
            "unexpected error: {err}"
        );
    }
}
