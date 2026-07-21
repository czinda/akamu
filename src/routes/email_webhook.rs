//! POST /acme/email-webhook — inbound email reply handler for RFC 8823.
//!
//! This endpoint is NOT an ACME JWS-authenticated route.  Authentication is
//! performed by verifying a HMAC-SHA256 signature over the raw request body:
//!
//! ```text
//! X-Akamu-Signature: sha256=<lowercase-hex(HMAC-SHA256(body, webhook_hmac_secret))>
//! ```
//!
//! The handler always returns HTTP 200 regardless of the challenge outcome
//! (returning non-200 would cause the webhook caller to retry indefinitely).
//! A 403 is returned only on HMAC mismatch, which indicates an unknown caller.
//!
//! This endpoint is intentionally exempt from the `halt_check` (FAU_STG.4)
//! middleware layer because it is called by infrastructure-level mail routing
//! tooling that must not be halted by a full audit store — the challenge would
//! otherwise be stuck in "processing" indefinitely.  Audit events are still
//! recorded for authentication failures; challenge outcomes are audited by
//! the `on_valid` / `on_invalid` functions inside `email_reply_00`.

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use native_ossl::util::hex_encode;
use synta_certificate::{crypto::HmacProvider as _, default_hmac_provider};

use crate::state::AppState;
use crate::validation::email_reply_00::{verify_response, VerifyOutcome, WebhookPayload};

/// `POST /acme/email-webhook`
pub async fn handle_webhook(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    // Retrieve HMAC secret; 503 if email_challenge is unconfigured.
    let secret = match state
        .config
        .email_challenge
        .as_ref()
        .filter(|ec| ec.enabled)
    {
        Some(ec) => ec.webhook_hmac_secret.as_bytes(),
        None => {
            tracing::warn!("email webhook called but email_challenge is not configured/enabled");
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                "email challenge not configured",
            )
                .into_response();
        }
    };

    // Authenticate: compute HMAC-SHA256 over raw body, compare to X-Akamu-Signature header.
    let expected_mac = match default_hmac_provider().hmac_compute("sha256", secret, &body) {
        Ok(mac) => mac,
        Err(e) => {
            tracing::error!("email webhook: HMAC computation failed: {e}");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };
    let expected_hex = hex_encode(&expected_mac);
    let expected_header = format!("sha256={expected_hex}");

    let sig_header = headers.get("x-akamu-signature");
    let provided = sig_header.and_then(|v| v.to_str().ok()).unwrap_or("");

    // Constant-time comparison of the full "sha256=<hex>" strings.
    let provided_bytes = provided.as_bytes();
    let expected_bytes = expected_header.as_bytes();
    if provided_bytes.len() != expected_bytes.len()
        || !synta_certificate::crypto::constant_time_eq(provided_bytes, expected_bytes)
    {
        let failure_reason = if sig_header.is_none() {
            "missing"
        } else if sig_header.and_then(|v| v.to_str().ok()).is_none() {
            "non-UTF8"
        } else {
            "mismatch"
        };
        tracing::warn!(
            failure_reason,
            "email webhook: HMAC authentication failed — request rejected"
        );
        state
            .record_audit(crate::audit::AuditEvent::failure(
                crate::audit::AuditEventType::AuthWebhookHmacFail,
            ))
            .await;
        return StatusCode::FORBIDDEN.into_response();
    }

    // Parse the JSON payload after HMAC passes.
    let payload: WebhookPayload = match serde_json::from_slice(&body) {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!("email webhook: invalid JSON payload: {e}");
            return (StatusCode::OK, "invalid payload").into_response();
        }
    };

    // Truncate in_reply_to before logging to bound log line length and
    // prevent log injection from attacker-controlled Message-ID values.
    // Use char_indices to find the 128th codepoint boundary (safe on multi-byte UTF-8).
    let truncated;
    let in_reply_to_log: &str = match payload.in_reply_to.char_indices().nth(128) {
        Some((i, _)) => {
            truncated = format!("{}…", &payload.in_reply_to[..i]);
            &truncated
        }
        None => &payload.in_reply_to,
    };
    let outcome = verify_response(&state, &payload).await;

    match &outcome {
        VerifyOutcome::Valid => {
            tracing::info!(in_reply_to = %in_reply_to_log, "email webhook: verification complete: valid");
        }
        VerifyOutcome::Invalid(reason) => {
            tracing::warn!(in_reply_to = %in_reply_to_log, reason, "email webhook: verification failed");
        }
    }

    StatusCode::OK.into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_encode_known_value() {
        assert_eq!(hex_encode([0x00, 0xff, 0xab, 0x12]), "00ffab12");
        assert_eq!(hex_encode([]), "");
    }
}
