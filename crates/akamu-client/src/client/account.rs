//! Account operations: registration, lookup, update, deactivation, key rollover.

use std::sync::Arc;

use hyper::StatusCode;
use serde_json::Value;

use akamu_jose::{JwsFlattened, JwsKeyRef};

use crate::{
    account::{Account, AccountKey},
    eab::create_eab_jws,
    error::ClientError,
    types::AccountOptions,
};

use super::{acme_error, location_hdr, AcmeClient};

impl AcmeClient {
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
