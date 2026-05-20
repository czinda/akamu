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
    if email_addr.is_empty() {
        return Err(AcmeError::Internal(
            "email-reply-00: recipient email address is empty".into(),
        ));
    }

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
        .ok_or_else(|| {
            AcmeError::Internal(format!(
                "email_challenge.from_address '{}' is not a valid email address (no '@')",
                ec.from_address
            ))
        })?;
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
    //
    // kill_on_drop(true) ensures the child is killed when the timeout future is
    // dropped, preventing orphan processes from delivering the email after the
    // challenge has already been marked invalid.
    let mut child = match tokio::process::Command::new(&ec.send_script)
        .env_clear()
        .env("ACME_TO", email_addr)
        .env("ACME_FROM", &ec.from_address)
        .env("ACME_SUBJECT", &subject)
        .env("ACME_MESSAGE_ID", &message_id)
        .env("ACME_AUTO_SUBMITTED", "auto-generated; type=acme")
        .env("ACME_TOKEN_PART2", token_part2_b64)
        .kill_on_drop(true)
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(
                challenge_id,
                send_script = %ec.send_script,
                "email-reply-00: failed to spawn send_script: {e}"
            );
            return Err(AcmeError::Internal(
                "email-reply-00: send script could not be executed".into(),
            ));
        }
    };

    let wait_result = tokio::time::timeout(Duration::from_secs(timeout_secs), child.wait()).await;

    let exit_status = match wait_result {
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
                "email-reply-00: error waiting for send_script: {e}"
            );
            return Err(AcmeError::Internal(
                "email-reply-00: send script wait failed".into(),
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
#[derive(serde::Deserialize)]
pub(crate) struct WebhookPayload {
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
pub(crate) enum VerifyOutcome {
    Valid,
    Invalid(String),
}

impl std::fmt::Display for VerifyOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Valid => write!(f, "valid"),
            Self::Invalid(reason) => write!(f, "invalid: {reason}"),
        }
    }
}

/// Called from the webhook handler after HMAC authentication passes.
///
/// Looks up the challenge by `In-Reply-To`, verifies the DKIM domain,
/// extracts the ACME response block, and checks the SHA-256 digest against
/// the expected key-authorization digest.  Updates challenge + authz status.
pub(crate) async fn verify_response(
    state: &Arc<AppState>,
    payload: &WebhookPayload,
) -> VerifyOutcome {
    let now = unix_now();

    // 1. Look up challenge by In-Reply-To / Message-ID.
    // Use the write pool to avoid stale WAL reads: Phase 1 writes email_token_part1
    // to state.db; a db_ro read before WAL checkpoint would return NULL and
    // permanently invalidate a valid challenge.
    let chall = match db::challenges::get_by_email_message_id(&state.db, &payload.in_reply_to).await
    {
        Ok(Some(c)) => c,
        Ok(None) => {
            let in_reply_to_display = match payload.in_reply_to.char_indices().nth(128) {
                Some((i, _)) => format!("{}…", &payload.in_reply_to[..i]),
                None => payload.in_reply_to.clone(),
            };
            return VerifyOutcome::Invalid(format!(
                "no email-reply-00 challenge found for In-Reply-To '{in_reply_to_display}'"
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
            let _ = on_invalid(
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
    // Use the write pool: the authz may have been created in the same WAL
    // transaction as the challenge, so db_ro may not yet see it.
    let authz = match db::authz::get_by_id(&state.db, &chall.authz_id).await {
        Ok(Some(a)) => a,
        Ok(None) => {
            tracing::error!(
                challenge_id = %chall.id,
                authz_id = %chall.authz_id,
                "email-reply-00 webhook: authorization not found for processing challenge"
            );
            let _ = on_invalid(
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
            let _ = on_invalid(
                state,
                &chall.id,
                &chall.authz_id,
                AcmeError::Internal("authorization lookup failed".into()),
                now,
            )
            .await;
            return VerifyOutcome::Invalid("internal error".into());
        }
    };

    // 2b. Reject if the authorization has expired — the client must re-order.
    // Other challenge types complete synchronously within the HTTP request where
    // the route handler already enforces expiry; the async webhook path does not.
    if let Some(expires) = authz.expires {
        if now > expires {
            tracing::warn!(
                challenge_id = %chall.id,
                authz_id = %chall.authz_id,
                expires,
                "email-reply-00: authorization has expired; rejecting late reply"
            );
            let _ = on_invalid(
                state,
                &chall.id,
                &chall.authz_id,
                AcmeError::IncorrectResponse("authorization has expired".into()),
                now,
            )
            .await;
            return VerifyOutcome::Invalid("authorization expired".into());
        }
    }

    // Parse the identifier to get the email address.
    let identifier: serde_json::Value = match serde_json::from_str(&authz.identifier) {
        Ok(v) => v,
        Err(e) => {
            tracing::error!(
                challenge_id = %chall.id,
                authz_id = %chall.authz_id,
                "email-reply-00 webhook: corrupt identifier JSON in authz: {e}"
            );
            let _ = on_invalid(
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
            let _ = on_invalid(
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
        let _ = on_invalid(
            state,
            &chall.id,
            &chall.authz_id,
            AcmeError::IncorrectResponse("From address does not match identifier".into()),
            now,
        )
        .await;
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
        let _ = on_invalid(
            state,
            &chall.id,
            &chall.authz_id,
            AcmeError::IncorrectResponse("DKIM domain does not match From domain".into()),
            now,
        )
        .await;
        return VerifyOutcome::Invalid(format!(
            "DKIM domain '{}' does not match From domain '{}'",
            payload.dkim_domain, from_domain
        ));
    }

    // 5. Verify DKIM status is "pass" (case-insensitive: Exim reports "Pass").
    if !payload.dkim_status.eq_ignore_ascii_case("pass") {
        tracing::warn!(
            challenge_id = %chall.id,
            in_reply_to = %payload.in_reply_to,
            dkim_status = %payload.dkim_status,
            "email-reply-00: DKIM verification did not pass"
        );
        let _ = on_invalid(
            state,
            &chall.id,
            &chall.authz_id,
            AcmeError::IncorrectResponse("DKIM verification did not pass".into()),
            now,
        )
        .await;
        return VerifyOutcome::Invalid(format!(
            "DKIM status is '{}', expected 'pass'",
            payload.dkim_status
        ));
    }

    // 6. Extract the ACME response block from the email body.
    let response_b64 = match extract_acme_response(&payload.body) {
        Some(s) => s,
        None => {
            tracing::warn!(
                challenge_id = %chall.id,
                authz_id = %chall.authz_id,
                "email-reply-00: no ACME response block found in email body"
            );
            let _ = on_invalid(
                state,
                &chall.id,
                &chall.authz_id,
                AcmeError::IncorrectResponse("no ACME response block found in email body".into()),
                now,
            )
            .await;
            return VerifyOutcome::Invalid("no ACME response block found in email body".into());
        }
    };

    // 7. Base64url-decode the response.
    let response_bytes = match URL_SAFE_NO_PAD.decode(response_b64.as_bytes()) {
        Ok(b) => b,
        Err(e) => {
            tracing::warn!(
                challenge_id = %chall.id,
                authz_id = %chall.authz_id,
                "email-reply-00: ACME response block is not valid base64url: {e}"
            );
            let _ = on_invalid(
                state,
                &chall.id,
                &chall.authz_id,
                AcmeError::IncorrectResponse(format!(
                    "ACME response block is not valid base64url: {e}"
                )),
                now,
            )
            .await;
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
            let _ = on_invalid(
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
            let _ = on_invalid(
                state,
                &chall.id,
                &chall.authz_id,
                AcmeError::Internal("account lookup failed".into()),
                now,
            )
            .await;
            return VerifyOutcome::Invalid("internal error".into());
        }
    };

    // 9. Compute expected digest.
    // RFC 8823 §4.2:
    //   keyAuth = base64url(token-part1) || base64url(token-part2) || "." || thumbprint
    // Both stored values are already base64url; token (token-part2) is the challenge token.
    let key_auth = format!("{}{}.{}", token_part1, chall.token, thumbprint);
    // The hasher is !Send, so it must be dropped before any .await.
    // Compute the digest in a non-async block; propagate errors outside.
    let digest_result = {
        let hasher = default_data_hasher();
        hasher.hash_data("sha256", key_auth.as_bytes())
        // hasher dropped here
    };
    let expected_digest = match digest_result {
        Ok(d) => d,
        Err(e) => {
            tracing::error!(
                challenge_id = %chall.id,
                "email-reply-00: SHA-256 failed: {e}"
            );
            let _ = on_invalid(
                state,
                &chall.id,
                &chall.authz_id,
                AcmeError::Internal("digest computation failed".into()),
                now,
            )
            .await;
            return VerifyOutcome::Invalid("digest computation error".into());
        }
    };

    let order_id = authz.order_id.as_str();

    // 10. Constant-time compare on raw digest bytes.
    if response_bytes.len() != expected_digest.len()
        || !synta_certificate::crypto::constant_time_eq(&response_bytes, &expected_digest)
    {
        let _ = on_invalid(
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
    match on_valid(state, &chall.id, &chall.authz_id, order_id, now).await {
        Err(e) => {
            tracing::error!(
                challenge_id = %chall.id,
                authz_id = %chall.authz_id,
                "email-reply-00: on_valid DB transaction failed: {e}; challenge remains in 'processing'"
            );
            return VerifyOutcome::Invalid("internal error — challenge state update failed".into());
        }
        Ok(false) => {
            // Another concurrent transition (on_invalid or a duplicate webhook delivery)
            // already moved the challenge out of 'processing'.  Distinguish the two cases
            // so the caller gets an accurate outcome rather than always reporting Valid.
            let current_status: Option<String> = db::challenges::get_status(&state.db, &chall.id)
                .await
                .unwrap_or(None);
            return match current_status.as_deref() {
                Some("valid") => {
                    tracing::debug!(
                        challenge_id = chall.id,
                        "email-reply-00: concurrent webhook delivery already marked challenge valid"
                    );
                    VerifyOutcome::Valid
                }
                other => {
                    tracing::warn!(
                        challenge_id = chall.id,
                        status = ?other,
                        "email-reply-00: challenge was concurrently invalidated before webhook could mark it valid"
                    );
                    VerifyOutcome::Invalid(format!(
                        "challenge transitioned to '{:?}' by concurrent operation",
                        other
                    ))
                }
            };
        }
        Ok(true) => {}
    }

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
    // SHA-256 base64url is 43 chars; 512 bytes is generous and prevents
    // a malicious payload from building a very large string in memory.
    const MAX_LEN: usize = 512;

    let start = body.find(BEGIN)? + BEGIN.len();
    let rest = &body[start..];
    let end = rest.find(END)?;

    let mut content = String::new();
    for b in rest[..end].bytes().filter(|b| !b.is_ascii_whitespace()) {
        if !b.is_ascii() || content.len() >= MAX_LEN {
            return None;
        }
        content.push(b as char);
    }

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

    // ── DB-backed integration tests for verify_response ───────────────────────

    #[cfg(test)]
    async fn make_verify_state() -> (Arc<crate::state::AppState>, String, String, String, String) {
        use crate::ca;
        use crate::config::{CaConfig, Config, DatabaseConfig, MtcConfig, ServerConfig};
        use crate::db;
        use crate::db::schema::{AccountRow, AuthorizationRow, ChallengeRow};
        use crate::state::{AppState, CaState, MtcState, NonceBucket};

        let now = crate::util::unix_now();
        let dir = tempfile::TempDir::new().unwrap();
        let config = Arc::new(Config {
            listen_addr: "127.0.0.1:0".into(),
            base_url: "https://acme.test".into(),
            database: DatabaseConfig {
                url: "sqlite::memory:".into(),
                max_connections: None,
                require_tls: false,
            },
            cas: vec![CaConfig {
                id: "default".to_owned(),
                is_default: true,
                caa_identities: vec![],
                key_file: dir.path().join("ca.key").to_string_lossy().into_owned(),
                cert_file: dir.path().join("ca.crt").to_string_lossy().into_owned(),
                key_type: "ec:P-256".into(),
                hash_alg: "sha256".into(),
                validity_days: 90,
                crl_url: None,
                ocsp_url: None,
                common_name: "Test CA".into(),
                organization: "Test".into(),
                ca_validity_years: 10,
                crl_next_update_secs: 86400,
                enforce_validity_cap: false,
                require_encrypted_key: false,
                key_password_file: None,
            }],
            mtc: MtcConfig {
                log_path: "/dev/null".into(),
                enabled: false,
                signing_key: None,
                checkpoint_interval_secs: 3600,
                cosigners: vec![],
                landmark_interval_secs: 86400,
                max_active_landmarks: 100,
                checkpoint_retention_count: 1000,
                hash_alg: "sha256".into(),
            },
            server: ServerConfig::default(),
            tls: Default::default(),
            profiles: Default::default(),
            admin: None,
            email_challenge: None,
            delegation_upstream: None,
            gossip: None,
        });
        let (ca_key, ca_cert_der) = ca::init::load_or_generate(config.default_ca()).unwrap();
        db::install_drivers();
        let db_conn = db::open("sqlite::memory:", 1, false).await.unwrap();
        let ca = Arc::new(CaState {
            id: "default".into(),
            key_type: "ec:P-256".into(),
            key: ca_key,
            cert_der: ca_cert_der,
            hash_alg: "sha256".into(),
            validity_days: 90,
            crl_url: None,
            ocsp_url: None,
            aki_bytes: Vec::new(),
            enforce_validity_cap: false,
            crl_next_update_secs: 604800,
            caa_identities: vec![],
        });

        let acc_id = "acc-vr-001".to_string();
        let order_id = "ord-vr-001".to_string();
        let authz_id = "authz-vr-001".to_string();
        let chall_id = "chall-vr-001".to_string();

        let token_part1 = "aaaaabbbbbcccccdddddeeeee"; // 24-char fake base64url
        let token_part2 = "zzzzzyyyyyxxxxwwwwvvvvuuuu"; // challenge token field
        let thumbprint = "test-thumbprint-001";
        let message_id = "<test-msg-001@acme.test>";
        let email_addr = "user@example.com";

        db::accounts::insert(
            &db_conn,
            AccountRow {
                id: acc_id.clone(),
                status: "valid".to_string(),
                contact: None,
                public_key: vec![0u8; 4],
                jwk_thumbprint: thumbprint.to_string(),
                created: now,
                updated: now,
                profile_grants: None,
                ca_id: String::new(),
            },
        )
        .await
        .unwrap();

        db::orders::insert(
            &db_conn,
            crate::db::schema::OrderRow {
                id: order_id.clone(),
                account_id: acc_id.clone(),
                status: "pending".to_string(),
                expires: Some(now + 3600),
                identifiers: format!(r#"[{{"type":"email","value":"{}"}}]"#, email_addr),
                not_before: None,
                not_after: None,
                error: None,
                certificate_id: None,
                replaces: None,
                created: now,
                updated: now,
                star_start_date: None,
                star_end_date: None,
                star_lifetime_secs: None,
                star_lifetime_adjust_secs: 0,
                star_allow_cert_get: 0,
                star_canceled_at: None,
                star_csr_der: None,
                profile: None,
                ca_id: "default".to_string(),
                delegation_id: None,
                allow_cert_get: 0,
                upstream_order_url: None,
                upstream_cert_url: None,
            },
        )
        .await
        .unwrap();

        db::authz::insert(
            &db_conn,
            AuthorizationRow {
                id: authz_id.clone(),
                order_id: order_id.clone(),
                account_id: acc_id.clone(),
                status: "pending".to_string(),
                identifier: format!(r#"{{"type":"email","value":"{}"}}"#, email_addr),
                expires: Some(now + 3600),
                wildcard: 0,
                subdomain_auth_allowed: 0,
                created: now,
                updated: now,
                ca_id: "default".to_string(),
            },
        )
        .await
        .unwrap();

        db::challenges::insert(
            &db_conn,
            ChallengeRow {
                id: chall_id.clone(),
                authz_id: authz_id.clone(),
                r#type: "email-reply-00".to_string(),
                status: "processing".to_string(),
                token: token_part2.to_string(),
                validated: None,
                error: None,
                created: now,
                updated: now,
                email_token_part1: None,
                email_message_id: None,
            },
        )
        .await
        .unwrap();

        // insert() does not write email-challenge columns; write them separately.
        db::challenges::set_email_token(&db_conn, &chall_id, token_part1, message_id, now)
            .await
            .unwrap();

        let state = Arc::new(AppState {
            config: Arc::clone(&config),
            db: db_conn.clone(),
            db_ro: db_conn,
            db_kind: crate::db::DbKind::Sqlite,
            profiles: crate::profiles::ProfileRegistry::empty(&ca),
            cas: {
                let mut map = indexmap::IndexMap::new();
                map.insert("default".to_string(), ca.clone());
                Arc::new(map)
            },
            default_ca_id: Arc::new("default".to_string()),
            mtc: Arc::new(MtcState {
                log: None,
                algorithm: synta_mtc::crypto::HashAlgorithm::Sha256,
                signing_key: None,
                signing_hash_alg: "sha256".into(),
                cosigner_clients: vec![],
                _log_lock: None,
            }),
            tls: None,
            spki_cache: Arc::new(std::sync::RwLock::new(std::collections::HashMap::new())),
            nonces: Arc::new(NonceBucket::new()),
            link_headers: {
                let mut m = std::collections::HashMap::new();
                m.insert(
                    "default".to_string(),
                    Arc::new(axum::http::HeaderValue::from_static(
                        "<https://acme.test/acme/directory>;rel=\"index\"",
                    )),
                );
                Arc::new(m)
            },
            validation_client: {
                let https = hyper_rustls::HttpsConnectorBuilder::new()
                    .with_native_roots()
                    .expect("native roots")
                    .https_or_http()
                    .enable_http1()
                    .build();
                hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
                    .build(https)
            },
            crl_caches: {
                let mut m = std::collections::HashMap::new();
                m.insert("default".to_string(), Default::default());
                Arc::new(m)
            },
            gss_cred: None,
            admin_gss_cred: None,
            eab_master_secret: None,
            audit: Arc::new(crate::audit::AuditState::new()),
            audit_policy: Arc::new(crate::audit::AuditPolicy::default()),
            admin_sessions: None,
            admin_auth_limiter: None,
            eab_session_nonces: None,
            startup_time: std::time::Instant::now(),
            crdt: Arc::new(tokio::sync::RwLock::new(akamu_crdt::AkaCrdt::default())),
            node_id: Arc::new("test".to_string()),
            node_kem_priv: Arc::new(vec![]),
            node_gossip_signing_priv: Arc::new(vec![]),
            node_gossip_signing_cert: Arc::new(vec![]),
            gossip_client: Arc::new(reqwest::Client::new()),
        });

        (
            state,
            chall_id,
            message_id.to_string(),
            token_part1.to_string(),
            token_part2.to_string(),
        )
    }

    fn make_response_digest(token_part1: &str, token_part2: &str, thumbprint: &str) -> String {
        let key_auth = format!("{token_part1}{token_part2}.{thumbprint}");
        let hasher = default_data_hasher();
        let digest = hasher.hash_data("sha256", key_auth.as_bytes()).unwrap();
        URL_SAFE_NO_PAD.encode(&digest)
    }

    fn make_acme_body(digest_b64: &str) -> String {
        format!(
            "Please reply.\n\
             -----BEGIN ACME RESPONSE-----\n\
             {}\n\
             -----END ACME RESPONSE-----\n",
            digest_b64
        )
    }

    #[tokio::test]
    async fn verify_response_valid_digest_returns_valid() {
        let (state, _chall_id, message_id, token_part1, token_part2) = make_verify_state().await;
        let thumbprint = "test-thumbprint-001";
        let digest = make_response_digest(&token_part1, &token_part2, thumbprint);
        let payload = WebhookPayload {
            from: "user@example.com".to_string(),
            in_reply_to: message_id,
            dkim_domain: "example.com".to_string(),
            dkim_status: "pass".to_string(),
            body: make_acme_body(&digest),
        };
        let outcome = verify_response(&state, &payload).await;
        assert_eq!(outcome, VerifyOutcome::Valid);
    }

    #[tokio::test]
    async fn verify_response_wrong_digest_returns_invalid() {
        let (state, _chall_id, message_id, _token_part1, _token_part2) = make_verify_state().await;
        let payload = WebhookPayload {
            from: "user@example.com".to_string(),
            in_reply_to: message_id,
            dkim_domain: "example.com".to_string(),
            dkim_status: "pass".to_string(),
            body: make_acme_body("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
        };
        match verify_response(&state, &payload).await {
            VerifyOutcome::Invalid(_) => {}
            other => panic!("expected Invalid, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn verify_response_dkim_domain_mismatch_returns_invalid() {
        let (state, _chall_id, message_id, token_part1, token_part2) = make_verify_state().await;
        let thumbprint = "test-thumbprint-001";
        let digest = make_response_digest(&token_part1, &token_part2, thumbprint);
        let payload = WebhookPayload {
            from: "user@example.com".to_string(),
            in_reply_to: message_id,
            dkim_domain: "attacker.com".to_string(), // does not match From domain
            dkim_status: "pass".to_string(),
            body: make_acme_body(&digest),
        };
        match verify_response(&state, &payload).await {
            VerifyOutcome::Invalid(r) if r.contains("DKIM domain") => {}
            other => panic!("expected DKIM domain mismatch Invalid, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn verify_response_dkim_status_fail_returns_invalid() {
        let (state, _chall_id, message_id, token_part1, token_part2) = make_verify_state().await;
        let thumbprint = "test-thumbprint-001";
        let digest = make_response_digest(&token_part1, &token_part2, thumbprint);
        let payload = WebhookPayload {
            from: "user@example.com".to_string(),
            in_reply_to: message_id,
            dkim_domain: "example.com".to_string(),
            dkim_status: "fail".to_string(), // not "pass"
            body: make_acme_body(&digest),
        };
        match verify_response(&state, &payload).await {
            VerifyOutcome::Invalid(r) if r.contains("DKIM status") => {}
            other => panic!("expected DKIM status Invalid, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn verify_response_already_validated_is_idempotent() {
        let (state, chall_id, message_id, token_part1, token_part2) = make_verify_state().await;
        let thumbprint = "test-thumbprint-001";
        let digest = make_response_digest(&token_part1, &token_part2, thumbprint);
        let payload = WebhookPayload {
            from: "user@example.com".to_string(),
            in_reply_to: message_id.clone(),
            dkim_domain: "example.com".to_string(),
            dkim_status: "pass".to_string(),
            body: make_acme_body(&digest),
        };
        // Mark the challenge as already valid (simulates a concurrent webhook).
        crate::db::query("UPDATE challenges SET status = 'valid' WHERE id = ?")
            .bind(&chall_id)
            .execute(&state.db)
            .await
            .unwrap();
        // A second delivery must not overwrite the already-valid challenge.
        let outcome = verify_response(&state, &payload).await;
        assert!(
            matches!(outcome, VerifyOutcome::Invalid(_)),
            "duplicate webhook delivery must be rejected when challenge is already valid, got: {outcome}"
        );
        let chall = crate::db::challenges::get_by_id(&state.db, &chall_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            chall.status, "valid",
            "challenge must remain valid after duplicate webhook delivery"
        );
    }

    #[tokio::test]
    async fn verify_response_no_acme_block_returns_invalid() {
        let (state, _chall_id, message_id, _token_part1, _token_part2) = make_verify_state().await;
        let payload = WebhookPayload {
            from: "user@example.com".to_string(),
            in_reply_to: message_id,
            dkim_domain: "example.com".to_string(),
            dkim_status: "pass".to_string(),
            body: "Hello, no ACME response block here.".to_string(),
        };
        match verify_response(&state, &payload).await {
            VerifyOutcome::Invalid(r) => {
                assert!(r.contains("ACME response block"), "reason: {r}")
            }
            other => panic!("expected Invalid, got {other}"),
        }
    }

    #[tokio::test]
    async fn verify_response_invalid_base64_returns_invalid() {
        let (state, _chall_id, message_id, _token_part1, _token_part2) = make_verify_state().await;
        let payload = WebhookPayload {
            from: "user@example.com".to_string(),
            in_reply_to: message_id,
            dkim_domain: "example.com".to_string(),
            dkim_status: "pass".to_string(),
            body: make_acme_body("not!!valid!!base64url"),
        };
        match verify_response(&state, &payload).await {
            VerifyOutcome::Invalid(r) => {
                assert!(r.contains("base64url"), "reason: {r}")
            }
            other => panic!("expected Invalid, got {other}"),
        }
    }

    #[tokio::test]
    async fn verify_response_expired_authz_returns_invalid() {
        let (state, _chall_id, message_id, token_part1, token_part2) = make_verify_state().await;
        let thumbprint = "test-thumbprint-001";
        let digest = make_response_digest(&token_part1, &token_part2, thumbprint);
        // Back-date the authorization expiry to the past.
        sqlx::query("UPDATE authorizations SET expires = 1 WHERE id = 'authz-vr-001'")
            .execute(&state.db)
            .await
            .unwrap();
        let payload = WebhookPayload {
            from: "user@example.com".to_string(),
            in_reply_to: message_id,
            dkim_domain: "example.com".to_string(),
            dkim_status: "pass".to_string(),
            body: make_acme_body(&digest),
        };
        match verify_response(&state, &payload).await {
            VerifyOutcome::Invalid(r) => {
                assert!(r.contains("expired"), "reason: {r}")
            }
            other => panic!("expected Invalid, got {other}"),
        }
    }

    #[tokio::test]
    async fn verify_response_unknown_in_reply_to_returns_invalid() {
        let (state, _chall_id, _message_id, _token_part1, _token_part2) = make_verify_state().await;
        let payload = WebhookPayload {
            from: "user@example.com".to_string(),
            in_reply_to: "<nonexistent@acme.test>".to_string(),
            dkim_domain: "example.com".to_string(),
            dkim_status: "pass".to_string(),
            body: make_acme_body("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
        };
        match verify_response(&state, &payload).await {
            VerifyOutcome::Invalid(_) => {}
            other => panic!("expected Invalid, got {other}"),
        }
    }

    // ── Helper function unit tests ─────────────────────────────────────────────

    #[test]
    fn extract_acme_response_oversized_returns_none() {
        let content = "A".repeat(513);
        let body = format!("-----BEGIN ACME RESPONSE-----\n{content}\n-----END ACME RESPONSE-----");
        assert_eq!(
            extract_acme_response(&body),
            None,
            "block over 512 bytes must be rejected"
        );
    }

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
