//! Axum route assembly and shared request-handling utilities.

use std::sync::Arc;

use axum::body::Bytes;
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, head, post};
use axum::{Json, Router};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde_json::Value;
use tower_http::trace::TraceLayer;

use crate::db;
use crate::error::AcmeError;
use crate::jose::jws::{JwsFlattened, JwsKeyRef, JwsProtectedHeader};
use crate::jose::kid::spki_for_kid;
use crate::state::AppState;

pub mod account;
pub mod authz;
pub mod certificate;
pub mod challenge;
pub mod directory;
pub mod finalize;
pub mod key_change;
pub mod nonce;
pub mod order;
pub mod renewal_info;
pub mod revoke;

/// Build the main axum router with all ACME endpoints.
pub fn build_router(state: Arc<AppState>) -> Router {
    Router::new()
        // Directory
        .route("/acme/directory", get(directory::get_directory))
        // Nonces
        .route("/acme/new-nonce", head(nonce::new_nonce_head))
        .route("/acme/new-nonce", get(nonce::new_nonce_get))
        // Accounts
        .route("/acme/new-account", post(account::new_account))
        .route("/acme/account/{id}", post(account::update_account))
        // Orders
        .route("/acme/new-order", post(order::new_order))
        .route("/acme/order/{id}", post(order::get_order))
        .route("/acme/order/{id}/finalize", post(finalize::finalize_order))
        // Authorizations
        .route("/acme/authz/{id}", post(authz::get_authz))
        // Challenges
        .route(
            "/acme/chall/{authz_id}/{type}",
            post(challenge::respond_challenge),
        )
        // Certificates — GET for plain clients; POST for RFC 8555 POST-as-GET clients
        .route(
            "/acme/cert/{id}",
            get(certificate::download_cert).post(certificate::download_cert_post),
        )
        // Revocation
        .route("/acme/revoke-cert", post(revoke::revoke_cert))
        // Key change
        .route("/acme/key-change", post(key_change::key_change))
        // Renewal Info (RFC 9773 ARI)
        .route(
            "/acme/renewal-info/{cert_id}",
            get(renewal_info::get_renewal_info),
        )
        .layer(
            TraceLayer::new_for_http()
                // Suppress "started processing request" — the response line already
                // carries method, URI, status, and latency; the request event is redundant.
                .on_request(())
                // Suppress "end of stream" — this fires after the body is fully
                // sent and adds no useful information for ACME endpoints.
                .on_eos(()),
        )
        .with_state(state)
}

// ── Shared request helpers ────────────────────────────────────────────────────

/// Result of JWS parsing and verification.
pub(crate) struct JwsContext {
    pub header: JwsProtectedHeader,
    /// Decoded payload bytes (empty for POST-as-GET).
    pub payload: Vec<u8>,
    /// SPKI DER of the key used to sign the request.
    pub spki_der: Vec<u8>,
    /// Account ID from `kid`, or `None` for new-account with `jwk`.
    pub account_id: Option<String>,
}

/// Parse, verify nonce, and verify signature for an ACME POST request.
///
/// `expected_url` must be the full URL the client should have signed, e.g.
/// `"https://acme.example.com/acme/new-account"`.
pub(crate) async fn parse_jws(
    state: &AppState,
    body: Bytes,
    expected_url: &str,
) -> Result<JwsContext, AcmeError> {
    // Parse the JWS flattened JSON body.
    let jws: JwsFlattened = serde_json::from_slice(&body)
        .map_err(|e| AcmeError::BadRequest(format!("JWS parse: {e}")))?;

    let header = jws.decode_header()?;

    // Verify the URL claim.
    if header.url != expected_url {
        return Err(AcmeError::Unauthorized(format!(
            "JWS url mismatch: got '{}', expected '{}'",
            header.url, expected_url
        )));
    }

    // Consume the nonce (replay protection).
    let nonce_valid = db::nonces::consume(&state.db, &header.nonce)
        .await
        .map_err(|e| AcmeError::Internal(format!("nonce check: {e}")))?;
    if !nonce_valid {
        return Err(AcmeError::BadNonce);
    }

    // Resolve the signing key and account ID.
    let (spki_der, account_id) = match &header.key_ref {
        JwsKeyRef::Jwk { jwk } => {
            let spki = jwk.to_spki_der()?;
            (spki, None)
        }
        JwsKeyRef::Kid { kid } => {
            let id = crate::jose::kid::account_id_from_kid(&state.config.base_url, kid)?;
            // Try the in-memory SPKI cache first to avoid a DB round-trip.
            let cached = state.spki_cache.read().unwrap().get(&id).cloned();
            let spki = if let Some(spki) = cached {
                spki
            } else {
                let spki = spki_for_kid(&state.db, &state.config.base_url, kid).await?;
                state
                    .spki_cache
                    .write()
                    .unwrap()
                    .insert(id.clone(), spki.clone());
                spki
            };
            (spki, Some(id))
        }
    };

    // Verify the JWS signature.
    jws.verify(&spki_der)?;

    let payload = jws.decode_payload()?;
    Ok(JwsContext {
        header,
        payload,
        spki_der,
        account_id,
    })
}

// ── Response helpers ──────────────────────────────────────────────────────────

/// Generate a fresh anti-replay nonce, store it in the DB, and return it.
pub(crate) async fn new_nonce(state: &AppState) -> Result<String, AcmeError> {
    let mut bytes = [0u8; 16];
    getrandom::getrandom(&mut bytes).map_err(|e| AcmeError::Internal(format!("nonce rng: {e}")))?;
    let nonce = URL_SAFE_NO_PAD.encode(bytes);
    db::nonces::insert(&state.db, &nonce).await?;
    Ok(nonce)
}

/// Build standard ACME response headers: Replay-Nonce, Link: directory.
pub(crate) async fn acme_headers(state: &AppState) -> Result<HeaderMap, AcmeError> {
    let nonce = new_nonce(state).await?;
    let mut headers = HeaderMap::new();
    headers.insert(
        HeaderName::from_static("replay-nonce"),
        HeaderValue::from_str(&nonce).unwrap(),
    );
    let link_val = format!("<{}/acme/directory>;rel=\"index\"", state.config.base_url);
    headers.insert(
        axum::http::header::LINK,
        HeaderValue::from_str(&link_val).unwrap(),
    );
    Ok(headers)
}

/// Wrap a JSON response with ACME headers.
pub(crate) async fn json_response(
    state: &AppState,
    status: StatusCode,
    body: Value,
) -> Result<Response, AcmeError> {
    let headers = acme_headers(state).await?;
    let mut resp = (status, Json(body)).into_response();
    resp.headers_mut().extend(headers);
    resp.headers_mut().insert(
        axum::http::header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    Ok(resp)
}

/// Parse the payload as JSON, return an error if the payload is empty
/// (POST-as-GET is not allowed here).
pub(crate) fn require_payload<T: serde::de::DeserializeOwned>(
    payload: &[u8],
    ctx: &str,
) -> Result<T, AcmeError> {
    if payload.is_empty() {
        return Err(AcmeError::BadRequest(format!(
            "{ctx}: payload is required (not POST-as-GET)"
        )));
    }
    serde_json::from_slice(payload).map_err(|e| AcmeError::BadRequest(format!("{ctx} JSON: {e}")))
}

/// Return the current Unix timestamp in seconds.
pub(crate) fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

/// Format a Unix timestamp as an RFC 3339 string (`YYYY-MM-DDTHH:MM:SSZ`).
///
/// Uses `synta::GeneralizedTime::from_unix` for the Gregorian decomposition.
pub(crate) fn fmt_time(unix: i64) -> String {
    let gt = synta::GeneralizedTime::from_unix(unix)
        .unwrap_or_else(|| synta::GeneralizedTime::from_unix(0).unwrap());
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        gt.year, gt.month, gt.day, gt.hour, gt.minute, gt.second
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fmt_time_known_epoch() {
        // Unix epoch = 1970-01-01T00:00:00Z
        assert_eq!(fmt_time(0), "1970-01-01T00:00:00Z");
    }

    #[test]
    fn fmt_time_known_date() {
        // 2024-01-01 00:00:00 UTC = 1704067200
        assert_eq!(fmt_time(1_704_067_200), "2024-01-01T00:00:00Z");
    }

    #[test]
    fn unix_now_is_positive() {
        let t = unix_now();
        assert!(t > 0, "unix_now() should return a positive Unix timestamp");
    }

    #[test]
    fn require_payload_empty_returns_error() {
        let result: Result<serde_json::Value, _> = require_payload(b"", "test-ctx");
        assert!(result.is_err());
        match result.unwrap_err() {
            AcmeError::BadRequest(msg) => {
                assert!(msg.contains("test-ctx"));
                assert!(msg.contains("required"));
            }
            other => panic!("expected BadRequest, got {other:?}"),
        }
    }

    #[test]
    fn require_payload_invalid_json_returns_error() {
        let result: Result<serde_json::Value, _> = require_payload(b"not json", "test-ctx");
        assert!(result.is_err());
        match result.unwrap_err() {
            AcmeError::BadRequest(msg) => assert!(msg.contains("test-ctx")),
            other => panic!("expected BadRequest, got {other:?}"),
        }
    }

    #[test]
    fn require_payload_valid_json() {
        let result: Result<serde_json::Value, _> =
            require_payload(b"{\"key\":\"value\"}", "test-ctx");
        assert!(result.is_ok());
    }
}
