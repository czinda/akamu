//! email-reply-00 challenge (RFC 8823) — two-channel token validation.
//!
//! **Phase 1 (this module, called on client POST to challenge URL)**:
//! Generate token-part1, store it and the Message-ID in the DB, then invoke
//! the configured send script.  The DB write happens first so that a script
//! failure leaves a recoverable token record and the challenge is marked
//! `"invalid"` (client can retry).  The challenge stays `"processing"` only
//! after a successful script execution.
//!
//! **Phase 2 (called from the email webhook handler)**:
//! Receive the client's email reply, verify the DKIM domain, extract the
//! ACME response block, compute the expected digest, and mark the challenge
//! as `"valid"` or `"invalid"`.

use std::sync::Arc;
use std::time::Duration;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use synta_certificate::{crypto::DataHasher, default_data_hasher};

use crate::db;
use crate::error::AcmeError;
use crate::state::AppState;
use crate::util::unix_now;

use super::{on_invalid, on_valid};

// ── Phase 1: send challenge email ────────────────────────────────────────────

/// Called when the client POSTs to the challenge URL.
///
/// Generates token-part1, stores token-part1 and the `Message-ID` in the DB
/// **before** invoking the send script, then invokes the configured
/// `send_script`.  On success the challenge stays at `"processing"` —
/// validation completes asynchronously via the webhook (phase 2).
///
/// # Errors
///
/// Returns an error if the send script exits non-zero, times out, or cannot
/// be spawned.  The caller should mark the challenge `"invalid"` in this case.
pub async fn send_challenge_email(
    state: &Arc<AppState>,
    challenge_id: &str,
    email_addr: &str,
    token_part2_b64: &str,
) -> Result<(), AcmeError> {
    let ec = state
        .config
        .email_challenge
        .as_ref()
        .filter(|ec| ec.enabled)
        .ok_or_else(|| AcmeError::Internal("email_challenge not configured".into()))?;

    // Generate token-part1: 20 random bytes → base64url (160 bits, ≥128-bit requirement).
    let mut raw = [0u8; 20];
    getrandom::getrandom(&mut raw)
        .map_err(|e| AcmeError::Internal(format!("email token-part1 random: {e}")))?;
    let token_part1_b64 = URL_SAFE_NO_PAD.encode(raw);

    // Generate a unique Message-ID: <uuid@from-domain>.
    let from_domain = ec
        .from_address
        .split_once('@')
        .map(|(_, d)| d)
        .unwrap_or_else(|| {
            tracing::warn!(
                from_address = %ec.from_address,
                "email_challenge.from_address has no '@'; Message-ID will use 'localhost'"
            );
            "localhost"
        });
    let message_id = format!("<{}@{}>", uuid::Uuid::new_v4(), from_domain);

    // Write token-part1 and Message-ID to the DB before invoking the script.
    // If the script fails, the challenge is marked invalid but the token record
    // exists; the client can retry (set_processing_if_pending will re-trigger).
    let now = unix_now();
    db::challenges::set_email_token(&state.db, challenge_id, &token_part1_b64, &message_id, now)
        .await?;

    // Build subject: "ACME: <token-part1-base64url>"
    let subject = format!("ACME: {token_part1_b64}");

    let timeout_secs = ec.send_script_timeout_secs;

    // Invoke the external send script with a timeout.
    // env_clear() prevents server secrets (DATABASE_URL, etc.) from leaking
    // into the script's environment; only the ACME_* variables are injected.
    let spawn_result = tokio::time::timeout(
        Duration::from_secs(timeout_secs),
        tokio::process::Command::new(&ec.send_script)
            .env_clear()
            .env("ACME_TO", email_addr)
            .env("ACME_FROM", &ec.from_address)
            .env("ACME_SUBJECT", &subject)
            .env("ACME_MESSAGE_ID", &message_id)
            .env("ACME_AUTO_SUBMITTED", "auto-generated; type=acme")
            .env("ACME_TOKEN_PART2", token_part2_b64)
            .status(),
    )
    .await;

    let exit_status = match spawn_result {
        Err(_elapsed) => {
            tracing::error!(
                challenge_id,
                send_script = %ec.send_script,
                timeout_secs,
                "email-reply-00: send_script timed out"
            );
            return Err(AcmeError::Internal(
                "email-reply-00: send script timed out".into(),
            ));
        }
        Ok(Err(e)) => {
            tracing::error!(
                challenge_id,
                send_script = %ec.send_script,
                "email-reply-00: failed to spawn send_script: {e}"
            );
            return Err(AcmeError::Internal(
                "email-reply-00: send script could not be executed".into(),
            ));
        }
        Ok(Ok(s)) => s,
    };

    if !exit_status.success() {
        let code = exit_status.code().unwrap_or(-1);
        tracing::error!(
            challenge_id,
            send_script = %ec.send_script,
            exit_code = code,
            "email-reply-00: send_script exited with non-zero status"
        );
        return Err(AcmeError::Internal(format!(
            "email-reply-00: send script exited with code {code}"
        )));
    }

    tracing::info!(
        challenge_id,
        message_id,
        "email-reply-00: challenge email sent"
    );
    Ok(())
}

// ── Phase 2: verify webhook payload ──────────────────────────────────────────

/// Inbound webhook payload (parsed by the webhook handler before calling this).
///
/// The webhook handler is responsible for HMAC-SHA256 authentication of the
/// request body against `email_challenge.webhook_hmac_secret` before calling
/// this function.  `dkim_domain` and `dkim_status` are caller-supplied and
/// must not be trusted until the HMAC check passes.
pub struct WebhookPayload {
    /// Sender address from the reply email `From:` header.
    pub from: String,
    /// `In-Reply-To:` header value — matches the `Message-ID` of the challenge email.
    pub in_reply_to: String,
    /// DKIM `d=` tag value as verified by the caller's MTA.
    pub dkim_domain: String,
    /// DKIM verification result; must be `"pass"` for the challenge to proceed.
    pub dkim_status: String,
    /// Decoded text body of the reply email.
    pub body: String,
}

/// Outcome of webhook verification — used by the webhook handler to decide
/// what to log; the handler always returns HTTP 200 regardless.
#[derive(Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum VerifyOutcome {
    Valid,
    Invalid(String),
}

/// Called from the webhook handler after HMAC authentication passes.
///
/// Looks up the challenge by `In-Reply-To`, verifies the DKIM domain,
/// extracts the ACME response block, and checks the SHA-256 digest against
/// the expected key-authorization digest.  Updates challenge + authz status.
pub async fn verify_response(state: &Arc<AppState>, payload: &WebhookPayload) -> VerifyOutcome {
    let now = unix_now();

    // 1. Look up challenge by In-Reply-To / Message-ID.
    let chall = match db::challenges::get_by_email_message_id(&state.db, &payload.in_reply_to).await
    {
        Ok(Some(c)) => c,
        Ok(None) => {
            return VerifyOutcome::Invalid(format!(
                "no email-reply-00 challenge found for In-Reply-To '{}'",
                payload.in_reply_to
            ));
        }
        Err(e) => {
            tracing::error!(
                in_reply_to = %payload.in_reply_to,
                "email-reply-00 webhook: DB lookup failed: {e}"
            );
            return VerifyOutcome::Invalid("internal error".into());
        }
    };

    // Only accept challenges in "processing" state (already triggered).
    if chall.status != "processing" {
        return VerifyOutcome::Invalid(format!(
            "challenge {} is in status '{}', expected 'processing'",
            chall.id, chall.status
        ));
    }

    let token_part1: &str = match chall.email_token_part1.as_deref() {
        Some(t) => t,
        None => {
            tracing::error!(
                challenge_id = %chall.id,
                authz_id = %chall.authz_id,
                "email-reply-00 webhook: processing challenge has no email_token_part1"
            );
            on_invalid(
                state,
                &chall.id,
                &chall.authz_id,
                AcmeError::Internal("email token-part1 missing from processing challenge".into()),
                now,
            )
            .await;
            return VerifyOutcome::Invalid("internal error".into());
        }
    };

    // 2. Look up the authorization to get the identifier value and order_id.
    let authz = match db::authz::get_by_id(&state.db_ro, &chall.authz_id).await {
        Ok(Some(a)) => a,
        Ok(None) => {
            tracing::error!(
                challenge_id = %chall.id,
                authz_id = %chall.authz_id,
                "email-reply-00 webhook: authorization not found for processing challenge"
            );
            on_invalid(
                state,
                &chall.id,
                &chall.authz_id,
                AcmeError::Internal("authorization missing for email challenge".into()),
                now,
            )
            .await;
            return VerifyOutcome::Invalid("internal error".into());
        }
        Err(e) => {
            tracing::error!(
                challenge_id = %chall.id,
                authz_id = %chall.authz_id,
                "email-reply-00 webhook: authz lookup failed: {e}"
            );
            return VerifyOutcome::Invalid("internal error".into());
        }
    };

    // Parse the identifier to get the email address.
    let identifier: serde_json::Value = match serde_json::from_str(&authz.identifier) {
        Ok(v) => v,
        Err(e) => {
            tracing::error!(
                challenge_id = %chall.id,
                authz_id = %chall.authz_id,
                "email-reply-00 webhook: corrupt identifier JSON in authz: {e}"
            );
            on_invalid(
                state,
                &chall.id,
                &chall.authz_id,
                AcmeError::Internal("corrupt identifier JSON in authorization".into()),
                now,
            )
            .await;
            return VerifyOutcome::Invalid("internal error".into());
        }
    };
    let expected_email = match identifier["value"].as_str() {
        Some(s) => s.to_string(),
        None => {
            tracing::error!(
                challenge_id = %chall.id,
                authz_id = %chall.authz_id,
                "email-reply-00 webhook: identifier has no value field"
            );
            on_invalid(
                state,
                &chall.id,
                &chall.authz_id,
                AcmeError::Internal("identifier value field missing in authorization".into()),
                now,
            )
            .await;
            return VerifyOutcome::Invalid("internal error".into());
        }
    };

    // 3. Verify From address matches the challenge's identifier (case-insensitive domain).
    if !emails_match(&payload.from, &expected_email) {
        tracing::warn!(
            challenge_id = %chall.id,
            in_reply_to = %payload.in_reply_to,
            from = %payload.from,
            expected = %expected_email,
            "email-reply-00: From address does not match challenge identifier"
        );
        return VerifyOutcome::Invalid(format!(
            "From '{}' does not match identifier '{}'",
            payload.from, expected_email
        ));
    }

    // 4. Verify DKIM domain matches the domain part of the From address.
    // RFC 8823 §3.2: DKIM d= tag MUST match the From domain.
    let from_domain = payload.from.split_once('@').map(|(_, d)| d).unwrap_or("");
    if !payload.dkim_domain.eq_ignore_ascii_case(from_domain) {
        tracing::warn!(
            challenge_id = %chall.id,
            in_reply_to = %payload.in_reply_to,
            dkim_domain = %payload.dkim_domain,
            from_domain,
            "email-reply-00: DKIM domain does not match From domain"
        );
        return VerifyOutcome::Invalid(format!(
            "DKIM domain '{}' does not match From domain '{}'",
            payload.dkim_domain, from_domain
        ));
    }

    // 5. Verify DKIM status is "pass".
    if payload.dkim_status != "pass" {
        tracing::warn!(
            challenge_id = %chall.id,
            in_reply_to = %payload.in_reply_to,
            dkim_status = %payload.dkim_status,
            "email-reply-00: DKIM verification did not pass"
        );
        return VerifyOutcome::Invalid(format!(
            "DKIM status is '{}', expected 'pass'",
            payload.dkim_status
        ));
    }

    // 6. Extract the ACME response block from the email body.
    let response_b64 = match extract_acme_response(&payload.body) {
        Some(s) => s,
        None => {
            return VerifyOutcome::Invalid("no ACME response block found in email body".into());
        }
    };

    // 7. Base64url-decode the response.
    let response_bytes = match URL_SAFE_NO_PAD.decode(response_b64.as_bytes()) {
        Ok(b) => b,
        Err(e) => {
            return VerifyOutcome::Invalid(format!(
                "ACME response block is not valid base64url: {e}"
            ));
        }
    };

    // 8. Look up the account to get the JWK thumbprint.
    let thumbprint = match db::accounts::get_by_id(&state.db_ro, &authz.account_id).await {
        Ok(Some(acc)) => acc.jwk_thumbprint,
        Ok(None) => {
            tracing::error!(
                challenge_id = %chall.id,
                authz_id = %chall.authz_id,
                account_id = %authz.account_id,
                "email-reply-00 webhook: account not found"
            );
            on_invalid(
                state,
                &chall.id,
                &chall.authz_id,
                AcmeError::Internal("account missing for email challenge".into()),
                now,
            )
            .await;
            return VerifyOutcome::Invalid("internal error".into());
        }
        Err(e) => {
            tracing::error!(
                challenge_id = %chall.id,
                authz_id = %chall.authz_id,
                "email-reply-00 webhook: account lookup failed: {e}"
            );
            return VerifyOutcome::Invalid("internal error".into());
        }
    };

    // 9. Compute expected digest.
    // RFC 8823 §4.2:
    //   keyAuth = base64url(token-part1) || base64url(token-part2) || "." || thumbprint
    // Both stored values are already base64url; token (token-part2) is the challenge token.
    let key_auth = format!("{}{}.{}", token_part1, chall.token, thumbprint);
    let hasher = default_data_hasher();
    let expected_digest = match hasher.hash_data("sha256", key_auth.as_bytes()) {
        Ok(d) => d,
        Err(e) => {
            tracing::error!(
                challenge_id = %chall.id,
                "email-reply-00: SHA-256 failed: {e}"
            );
            return VerifyOutcome::Invalid("digest computation error".into());
        }
    };

    let order_id = authz.order_id.as_str();

    // 10. Constant-time compare on raw digest bytes.
    if response_bytes.len() != expected_digest.len()
        || !synta_certificate::crypto::constant_time_eq(&response_bytes, &expected_digest)
    {
        on_invalid(
            state,
            &chall.id,
            &chall.authz_id,
            AcmeError::IncorrectResponse("email response digest mismatch".into()),
            now,
        )
        .await;
        return VerifyOutcome::Invalid("response digest mismatch".into());
    }

    // 11. Mark challenge + authz + order valid.
    on_valid(state, &chall.id, &chall.authz_id, order_id, now).await;

    tracing::info!(
        challenge_id = chall.id,
        authz_id = chall.authz_id,
        "email-reply-00: challenge validated successfully"
    );
    VerifyOutcome::Valid
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Extract base64url payload between ACME response block delimiters.
fn extract_acme_response(body: &str) -> Option<String> {
    const BEGIN: &str = "-----BEGIN ACME RESPONSE-----";
    const END: &str = "-----END ACME RESPONSE-----";
    let start = body.find(BEGIN)? + BEGIN.len();
    let rest = &body[start..];
    let end = rest.find(END)?;
    // Filter ASCII whitespace only — base64url is ASCII-only.
    let content: String = rest[..end]
        .bytes()
        .filter(|b| !b.is_ascii_whitespace())
        .map(|b| b as char)
        .collect();
    if content.is_empty() {
        None
    } else {
        Some(content)
    }
}

/// Case-insensitive domain comparison per RFC 5321 §2.4.
/// Local-part is compared case-sensitively.
fn emails_match(a: &str, b: &str) -> bool {
    match (a.split_once('@'), b.split_once('@')) {
        (Some((a_local, a_dom)), Some((b_local, b_dom))) => {
            a_local == b_local && a_dom.eq_ignore_ascii_case(b_dom)
        }
        _ => a == b,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_acme_response_basic() {
        let body = "Please reply.\n\
                    -----BEGIN ACME RESPONSE-----\n\
                    ABC123\n\
                    -----END ACME RESPONSE-----\n";
        assert_eq!(extract_acme_response(body).as_deref(), Some("ABC123"));
    }

    #[test]
    fn extract_acme_response_multiline_stripped() {
        let body = "-----BEGIN ACME RESPONSE-----\nA\nB\nC\n-----END ACME RESPONSE-----";
        assert_eq!(extract_acme_response(body).as_deref(), Some("ABC"));
    }

    #[test]
    fn extract_acme_response_missing() {
        assert_eq!(extract_acme_response("no block here"), None);
    }

    #[test]
    fn extract_acme_response_whitespace_only_returns_none() {
        let body = "-----BEGIN ACME RESPONSE-----\n   \n-----END ACME RESPONSE-----";
        assert_eq!(extract_acme_response(body), None);
    }

    #[test]
    fn emails_match_case_insensitive_domain() {
        assert!(emails_match("user@EXAMPLE.COM", "user@example.com"));
        assert!(emails_match("user@example.com", "user@EXAMPLE.COM"));
        // Local-part is case-sensitive per RFC 5321.
        assert!(!emails_match("User@example.com", "user@example.com"));
        assert!(!emails_match("user@example.com", "other@example.com"));
    }

    #[test]
    fn emails_match_no_at_sign_exact() {
        // Fallback: both are compared byte-for-byte when neither has '@'.
        assert!(emails_match("notanemail", "notanemail"));
        assert!(!emails_match("notanemail", "other"));
    }
}
