//! Order lifecycle: new-order, get-authz, trigger-challenge, poll, finalize, download.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use hyper::StatusCode;
use serde_json::Value;
use tokio::time::{sleep, Duration};

use crate::{
    account::Account,
    error::ClientError,
    types::{Authorization, Challenge, Identifier, Order},
};

use super::{acme_error, AcmeClient};

impl AcmeClient {
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

        let order_url = super::location_hdr(&headers)?;
        parse_order(&body, order_url)
    }

    /// Place a delegation order (RFC 9115 §2.3.2).
    ///
    /// The `delegation_url` is included in the newOrder payload.
    /// The resulting order starts in `"ready"` with no authorizations.
    pub async fn new_order_with_delegation(
        &self,
        acct: &Account,
        ids: &[Identifier],
        delegation_url: &str,
        profile: Option<&str>,
    ) -> Result<Order, ClientError> {
        let url = &self.new_order_url;
        let mut payload = serde_json::json!({
            "identifiers": ids,
            "delegation": delegation_url,
        });
        if let Some(p) = profile {
            payload["profile"] = serde_json::json!(p);
        }
        let payload_bytes = serde_json::to_vec(&payload)
            .map_err(|e| ClientError::Http(format!("serialize new-order payload: {e}")))?;
        let (status, body, headers) = self.post_kid(acct, url, Some(&payload_bytes)).await?;
        if status != StatusCode::CREATED {
            return Err(acme_error(&body, status, "new-order"));
        }
        let order_url = super::location_hdr(&headers)?;
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

    /// Fetch the current state of an order (single POST-as-GET, no polling).
    pub async fn get_order(&self, acct: &Account, order_url: &str) -> Result<Order, ClientError> {
        let (status, body, _) = self.post_kid(acct, order_url, None).await?;
        if status != StatusCode::OK {
            return Err(acme_error(&body, status, "get-order"));
        }
        parse_order(&body, order_url.to_owned())
    }

    /// Poll an order URL until status is `"ready"` or `"valid"`.
    ///
    /// Polls with exponential backoff (1 ms -> doubles -> cap 2 s).
    /// Respects the `Retry-After` header from the server when present.
    pub async fn poll_order(
        &self,
        acct: &Account,
        order_url: &str,
        timeout: Duration,
    ) -> Result<Order, ClientError> {
        let deadline = tokio::time::Instant::now() + timeout;
        let mut delay_ms: u64 = 1;

        loop {
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
                other => {
                    tracing::debug!(
                        order_url,
                        status = other.unwrap_or("<missing>"),
                        "poll_order: waiting (status not terminal)"
                    );
                }
            }

            // Use Retry-After if the server sent one, otherwise use exponential backoff.
            let retry_after = headers
                .get("retry-after")
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.parse::<u64>().ok());
            let sleep_ms = retry_after.map(|s| s * 1000).unwrap_or(delay_ms);
            sleep(Duration::from_millis(sleep_ms)).await;
            if retry_after.is_none() {
                delay_ms = (delay_ms * 2).min(2000);
            }
        }
    }

    /// Poll an authorization URL until status is `"valid"` or `"invalid"`.
    ///
    /// On `"valid"`, returns `Ok(Authorization)`.
    /// On `"invalid"`, returns an error containing challenge error details.
    /// Polls with exponential backoff (250 ms → doubles → cap 2 s).
    /// Respects the `Retry-After` header from the server when present.
    pub async fn poll_authorization(
        &self,
        acct: &Account,
        authz_url: &str,
        timeout: Duration,
    ) -> Result<Authorization, ClientError> {
        let deadline = tokio::time::Instant::now() + timeout;
        let mut delay_ms: u64 = 250;

        loop {
            if tokio::time::Instant::now() > deadline {
                return Err(ClientError::Http(format!(
                    "timed out polling authorization {authz_url}"
                )));
            }

            let (status, body, headers) = self.post_kid(acct, authz_url, None).await?;
            if status != StatusCode::OK {
                return Err(acme_error(&body, status, "poll-authorization"));
            }

            let authz: Authorization = serde_json::from_value(body)
                .map_err(|e| ClientError::Http(format!("parse authorization: {e}")))?;

            match authz.status.as_str() {
                "valid" => return Ok(authz),
                "invalid" => {
                    let errors: Vec<String> = authz
                        .challenges
                        .iter()
                        .filter_map(|c| {
                            c.error.as_ref().map(|e| {
                                let fallback = e.to_string();
                                let detail = e["detail"].as_str().unwrap_or(&fallback);
                                format!("{}: {detail}", c.r#type)
                            })
                        })
                        .collect();
                    let detail = if errors.is_empty() {
                        format!("authorization for {} is invalid", authz.identifier.value)
                    } else {
                        format!(
                            "authorization for {} failed: {}",
                            authz.identifier.value,
                            errors.join("; ")
                        )
                    };
                    return Err(ClientError::Http(detail));
                }
                other => {
                    tracing::debug!(
                        authz_url,
                        status = other,
                        identifier = %authz.identifier.value,
                        "poll_authorization: waiting"
                    );
                }
            }

            let retry_after = headers
                .get("retry-after")
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.parse::<u64>().ok());
            let sleep_ms = retry_after.map(|s| s * 1000).unwrap_or(delay_ms);
            sleep(Duration::from_millis(sleep_ms)).await;
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

    let delegation = body["delegation"].as_str().map(String::from);

    Ok(Order {
        status,
        url,
        finalize,
        authorizations,
        certificate,
        identifiers,
        profile,
        delegation,
    })
}
