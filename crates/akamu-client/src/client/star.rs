//! STAR order operations (RFC 8739).

use http_body_util::Full;
use hyper::{body::Bytes, Method, Request, StatusCode};
use serde_json::Value;

use crate::{
    account::Account,
    error::ClientError,
    types::{StarOrder, StarOrderParams},
};

use super::{acme_error, location_hdr, AcmeClient};

impl AcmeClient {
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
