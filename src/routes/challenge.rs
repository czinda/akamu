//! POST /acme/chall/{authz_id}/{type} — RFC 8555 §7.5.1

use std::sync::Arc;

use crate::db;
use crate::error::AcmeError;
use crate::state::AppState;
use crate::validation;
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::Response;
use serde::Serialize;

use super::{acme_prefix, fmt_time, json_response, parse_jws, unix_now, CaId};

pub async fn respond_challenge(
    State(state): State<Arc<AppState>>,
    ca_id: CaId,
    Path((authz_id, chall_type)): Path<(String, String)>,
    body: Bytes,
) -> Result<Response, AcmeError> {
    let pfx = acme_prefix(&state.config.base_url, &ca_id.0, &state.default_ca_id);
    let url = format!("{pfx}/chall/{authz_id}/{chall_type}");
    let ctx = parse_jws(&state, body, &url).await?;

    let account_id = ctx
        .account_id
        .ok_or(AcmeError::Unauthorized("kid required".into()))?;

    // Two-step approach: one autocommit SELECT to validate ownership and get
    // challenge data, then one autocommit conditional UPDATE to flip the
    // challenge to "processing" atomically.  This avoids the overhead of an
    // explicit BEGIN/COMMIT pair (saving 2 DB round-trips vs a 4-RT transaction).
    //
    // The conditional UPDATE (`WHERE status = 'pending'`) handles concurrent
    // duplicate requests: if two requests arrive simultaneously, only one
    // succeeds (rows_affected = 1); the other gets rows_affected = 0 and
    // returns the current (already-processing) state.
    //
    // CA scope: `authz.ca_id` is set at `new-order` time; migration 009
    // backfills pre-existing rows to 'default', which is allowed on any CA.
    let now = unix_now();
    let (authz, challenge) = {
        let (authz, challenges) = db::authz::get_with_challenges(&state.db_ro, &authz_id)
            .await?
            .ok_or(AcmeError::NotFound)?;

        if authz.account_id != account_id {
            return Err(AcmeError::Unauthorized(
                "authorization belongs to different account".into(),
            ));
        }
        // 'default' is the migration-backfill sentinel; allow it on any CA.
        if !authz.ca_id.is_empty() && authz.ca_id != "default" && authz.ca_id != ca_id.0 {
            return Err(AcmeError::NotFound);
        }
        if authz.status != "pending" {
            return Err(AcmeError::BadRequest(format!(
                "authorization status is '{}', expected 'pending'",
                authz.status
            )));
        }

        let challenge = challenges
            .into_iter()
            .find(|c| c.r#type == chall_type)
            .ok_or(AcmeError::NotFound)?;

        let already_processing = if challenge.status == "pending" {
            let affected =
                db::challenges::set_processing_if_pending(&state.db, &challenge.id, now).await?;
            affected == 0 // race: another request beat us to it
        } else {
            true // already processing / valid
        };

        if already_processing {
            // Return current state without spawning another validation task.
            return challenge_response(&state, &challenge, &pfx, &ca_id.0, &ctx.next_nonce);
        }
        (authz, challenge)
    };
    // challenge.status was "pending" — the DB has now flipped it to "processing".

    // Extract identifier.
    let identifier: serde_json::Value = serde_json::from_str(&authz.identifier).map_err(|e| {
        AcmeError::Internal(format!(
            "corrupt identifier in authorization {authz_id}: {e}"
        ))
    })?;
    let id_type = identifier["type"].as_str().unwrap_or("").to_string();
    let id_value = identifier["value"].as_str().unwrap_or("").to_string();

    // JWK thumbprint was already loaded by parse_jws (SPKI cache or DB lookup).
    let jwk_thumbprint = ctx
        .jwk_thumbprint
        .clone()
        .ok_or_else(|| AcmeError::Internal("JWK thumbprint missing in challenge handler".into()))?;
    // dns-persist-01 is validated against the account URI stored as the key_auth;
    // all other challenge types use the standard token·thumbprint form.
    let key_auth = if chall_type == "dns-persist-01" {
        format!("{}/acme/account/{}", state.config.base_url, account_id)
    } else {
        format!("{}.{}", challenge.token, jwk_thumbprint)
    };

    // For onion-csr-01 (RFC 9799 §3.2): the client submits a CSR in the
    // challenge response payload as {"csr": "<base64url DER>"}.  Extract and
    // decode it here so it can be passed to the validation task.
    let onion_csr_der: Option<Vec<u8>> = if chall_type == "onion-csr-01" {
        #[derive(serde::Deserialize)]
        struct OnionCsrPayload {
            csr: String,
        }
        match serde_json::from_slice::<OnionCsrPayload>(&ctx.payload) {
            Ok(p) => {
                use base64::engine::general_purpose::URL_SAFE_NO_PAD;
                use base64::Engine;
                match URL_SAFE_NO_PAD.decode(p.csr.as_bytes()) {
                    Ok(der) => Some(der),
                    Err(e) => {
                        // Return an error immediately — don't spawn background task.
                        return Err(AcmeError::BadRequest(format!(
                            "onion-csr-01: csr field is not valid base64url: {e}"
                        )));
                    }
                }
            }
            Err(e) => {
                return Err(AcmeError::BadRequest(format!(
                    "onion-csr-01: payload must be {{\"csr\":\"<base64url>\"}}: {e}"
                )));
            }
        }
    } else {
        None
    };

    // Spawn background validation task. The JoinHandle is observed so that a
    // panic inside the task is logged rather than silently swallowed.
    //
    // `authz.order_id` is passed to avoid a redundant
    // `SELECT order_id FROM authorizations` inside the on_valid transaction.
    let state_clone = Arc::clone(&state);
    let challenge_id = challenge.id.clone();
    let order_id = authz.order_id.clone();
    let token = challenge.token.clone();
    let chall_type_clone = chall_type.clone();
    let authz_id_clone = authz_id.clone();
    let challenge_id_for_log = challenge.id.clone();

    let handle = tokio::spawn(async move {
        validation::validate_challenge(
            &state_clone,
            validation::ChallengeParams {
                challenge_id: &challenge_id,
                authz_id: &authz_id_clone,
                order_id: &order_id,
                chall_type: &chall_type_clone,
                id_type: &id_type,
                id_value: &id_value,
                key_auth: &key_auth,
                token: &token,
                onion_csr_der: onion_csr_der.as_deref(),
                account_id: &account_id,
            },
        )
        .await;
    });

    // Detach but watch for panics: spawn a lightweight observer task.
    tokio::spawn(async move {
        if let Err(e) = handle.await {
            tracing::error!("challenge {challenge_id_for_log}: validation task panicked: {e:?}");
        }
    });

    // Return immediately with processing state.
    let mut updated = challenge.clone();
    updated.status = "processing".into();
    challenge_response(&state, &updated, &pfx, &ca_id.0, &ctx.next_nonce)
}

/// Typed challenge response body — borrows `&str` fields from `ChallengeRow`
/// to avoid intermediate `serde_json::Value` (HashMap) allocation.
#[derive(Serialize)]
struct ChallengeJson<'a> {
    r#type: &'a str,
    url: String,
    status: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    token: Option<&'a str>,
    #[serde(
        rename = "issuer-domain-names",
        skip_serializing_if = "Option::is_none"
    )]
    issuer_domain_names: Option<Vec<String>>,
    /// RFC 9799 §3.2: present only for `onion-csr-01` challenges.
    #[serde(rename = "authKey", skip_serializing_if = "Option::is_none")]
    auth_key: Option<String>,
    /// RFC 8823 §3: present only for `email-reply-00` challenges.
    #[serde(skip_serializing_if = "Option::is_none")]
    from: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    validated: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<Box<serde_json::value::RawValue>>,
}

fn challenge_response(
    state: &AppState,
    challenge: &crate::db::schema::ChallengeRow,
    acme_pfx: &str,
    ca_id: &str,
    nonce: &str,
) -> Result<Response, AcmeError> {
    let (token, issuer_domain_names, auth_key, from) = if challenge.r#type == "dns-persist-01" {
        (
            None,
            Some(state.config.dns_persist_issuer_domains()),
            None,
            None,
        )
    } else if challenge.r#type == "email-reply-00" {
        let from_addr = match state
            .config
            .email_challenge
            .as_ref()
            .filter(|ec| ec.enabled)
        {
            Some(ec) => Some(ec.from_address.clone()),
            // Resolved challenges no longer need the from field.
            None if matches!(challenge.status.as_str(), "valid" | "invalid") => None,
            None => {
                tracing::warn!(
                    challenge_id = %challenge.id,
                    status = %challenge.status,
                    "email-reply-00 challenge exists but email_challenge is not configured or enabled"
                );
                return Err(AcmeError::Internal(
                    "email-reply-00 challenge cannot be served: \
                     email_challenge is not configured or enabled"
                        .into(),
                ));
            }
        };
        (Some(challenge.token.as_str()), None, None, from_addr)
    } else {
        (Some(challenge.token.as_str()), None, None, None)
    };
    let body = ChallengeJson {
        r#type: &challenge.r#type,
        url: format!(
            "{acme_pfx}/chall/{}/{}",
            challenge.authz_id, challenge.r#type
        ),
        status: &challenge.status,
        token,
        issuer_domain_names,
        auth_key,
        from,
        validated: challenge.validated.map(fmt_time),
        error: challenge.error.as_deref().and_then(|s| {
            serde_json::value::RawValue::from_string(s.to_string())
                .map_err(|e| {
                    tracing::warn!(
                        challenge_id = %challenge.id,
                        raw = s,
                        "corrupt error JSON in challenge row: {e}"
                    );
                })
                .ok()
        }),
    };
    json_response(state, ca_id, StatusCode::OK, body, nonce)
}
