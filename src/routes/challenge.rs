//! POST /acme/chall/{authz_id}/{type} — RFC 8555 §7.5.1

use std::sync::Arc;

use super::{account_uri, acme_prefix, fmt_time, json_response, parse_jws, unix_now, CaId};
use crate::crdt_hooks;
use crate::db;
use crate::error::AcmeError;
use crate::state::AppState;
use crate::status::{AuthzStatus, ChallengeStatus};
use crate::validation;
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderValue, StatusCode};
use axum::response::Response;

pub async fn respond_challenge(
    State(state): State<Arc<AppState>>,
    ca_id: CaId,
    Path(params): Path<std::collections::HashMap<String, String>>,
    body: Bytes,
) -> Result<Response, AcmeError> {
    let authz_id = params.get("authz_id").cloned().ok_or(AcmeError::NotFound)?;
    let chall_type = params.get("type").cloned().ok_or(AcmeError::NotFound)?;
    let pfx = acme_prefix(&state.config.base_url, &ca_id.0, &state.default_ca_id);
    let url = format!("{pfx}/chall/{authz_id}/{chall_type}");
    let ctx = parse_jws(&state, body, &url).await?;

    let account_id = ctx
        .account_id
        .ok_or(AcmeError::Unauthorized("kid required".into()))?;

    let jwk_thumbprint = ctx
        .jwk_thumbprint
        .clone()
        .ok_or_else(|| AcmeError::Internal("JWK thumbprint missing in challenge handler".into()))?;

    // Two-step approach: one read-only SELECT (via db_ro) to validate ownership
    // and get challenge data, then one autocommit conditional UPDATE to flip the
    // challenge to "processing" atomically.
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
        let challenge = challenges
            .into_iter()
            .find(|c| c.r#type == chall_type)
            .ok_or(AcmeError::NotFound)?;

        // RFC 8555 §7.5.1: if the authorization is no longer pending the server
        // MUST ignore the request body and return the current challenge object.
        // Clients legitimately poll challenge URLs after validation completes.
        if authz.status.parse() != Ok(AuthzStatus::Pending) {
            return challenge_response(
                &state,
                &challenge,
                &pfx,
                &ca_id.0,
                &ctx.next_nonce,
                &account_id,
                &jwk_thumbprint,
            );
        }

        let already_processing = if challenge.status.parse() == Ok(ChallengeStatus::Pending) {
            let affected = if let Some(ref coal) = state.write_coalescer {
                coal.submit_set_processing(challenge.id.clone(), now)
                    .await?
            } else {
                db::challenges::set_processing_if_pending(&state.db, &challenge.id, now).await?
            };
            affected == 0 // race: another request beat us to it
        } else {
            true // already processing / valid
        };

        if already_processing {
            // Return current state without spawning another validation task.
            return challenge_response(
                &state,
                &challenge,
                &pfx,
                &ca_id.0,
                &ctx.next_nonce,
                &account_id,
                &jwk_thumbprint,
            );
        }
        (authz, challenge)
    };
    crdt_hooks::on_challenge_set(
        &state,
        crdt_hooks::ChallengeSetParams {
            id: &challenge.id,
            authz_id: &authz_id,
            challenge_type: &chall_type,
            status: ChallengeStatus::Processing,
            token: &challenge.token,
            validated: challenge.validated,
            error: challenge.error.clone(),
            created: challenge.created,
            updated: now,
        },
    )
    .await;

    // Extract identifier.
    let identifier: serde_json::Value = serde_json::from_str(&authz.identifier).map_err(|e| {
        AcmeError::Internal(format!(
            "corrupt identifier in authorization {authz_id}: {e}"
        ))
    })?;
    let id_type = identifier["type"]
        .as_str()
        .ok_or_else(|| {
            AcmeError::Internal(format!(
                "missing or non-string 'type' in identifier for authorization {authz_id}"
            ))
        })?
        .to_string();
    let id_value = identifier["value"]
        .as_str()
        .ok_or_else(|| {
            AcmeError::Internal(format!(
                "missing or non-string 'value' in identifier for authorization {authz_id}"
            ))
        })?
        .to_string();

    // dns-persist-01 is validated against the account URI stored as the key_auth;
    // all other challenge types use the standard token·thumbprint form.
    let key_auth = if chall_type == "dns-persist-01" {
        account_uri(&pfx, &account_id)
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

    let authority_token: Option<String> = if chall_type == "tkauth-01" {
        #[derive(serde::Deserialize)]
        struct TkauthPayload {
            tkauth: String,
        }
        match serde_json::from_slice::<TkauthPayload>(&ctx.payload) {
            Ok(p) => Some(p.tkauth),
            Err(e) => {
                return Err(AcmeError::BadRequest(format!(
                    "tkauth-01: payload must be {{\"tkauth\":\"<JWT>\"}}: {e}"
                )));
            }
        }
    } else {
        None
    };

    // Spawn background validation task. The JoinHandle is observed so that a
    // panic inside the task is logged rather than silently swallowed.
    let state_clone = Arc::clone(&state);
    let challenge_id = challenge.id.clone();
    let order_id = authz.order_id.clone();
    let token = challenge.token.clone();
    let chall_type_clone = chall_type.clone();
    let authz_id_clone = authz_id.clone();
    let challenge_id_for_log = challenge.id.clone();
    let challenge_created_ts = challenge.created;
    let account_id_for_response = account_id.clone();

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
                authority_token: authority_token.as_deref(),
                challenge_created: challenge_created_ts,
            },
        )
        .await;
    });

    tokio::spawn(async move {
        if let Err(e) = handle.await {
            tracing::error!("challenge {challenge_id_for_log}: validation task panicked: {e:?}");
        }
    });

    let mut updated = challenge.clone();
    updated.status = "processing".into();
    challenge_response(
        &state,
        &updated,
        &pfx,
        &ca_id.0,
        &ctx.next_nonce,
        &account_id_for_response,
        &jwk_thumbprint,
    )
}

use super::ChallengeJson;

fn challenge_response(
    state: &AppState,
    challenge: &crate::db::schema::ChallengeRow,
    acme_pfx: &str,
    ca_id: &str,
    nonce: &str,
    account_id: &str,
    jwk_thumbprint: &str,
) -> Result<Response, AcmeError> {
    let (token, accounturi, issuer_domain_names, auth_key, from) = if challenge.r#type
        == "dns-persist-01"
    {
        let uri = account_uri(acme_pfx, account_id);
        (
            None,
            Some(uri),
            Some(state.config.dns_persist_issuer_domains()),
            None,
            None,
        )
    } else if challenge.r#type == "onion-csr-01" {
        (
            Some(challenge.token.as_str()),
            None,
            None,
            Some(jwk_thumbprint.to_string()),
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
            None if matches!(
                challenge.status.parse(),
                Ok(ChallengeStatus::Valid | ChallengeStatus::Invalid)
            ) =>
            {
                None
            }
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
        (Some(challenge.token.as_str()), None, None, None, from_addr)
    } else {
        (Some(challenge.token.as_str()), None, None, None, None)
    };
    let (tkauth_type, token_authority) = if challenge.r#type == "tkauth-01" {
        (
            challenge.tkauth_type.as_deref(),
            challenge.token_authority.as_deref(),
        )
    } else {
        (None, None)
    };
    let challenge_nonce = if challenge.r#type == "onion-csr-01" {
        Some(challenge.token.as_str())
    } else {
        None
    };
    let body = ChallengeJson {
        r#type: &challenge.r#type,
        url: format!(
            "{acme_pfx}/chall/{}/{}",
            challenge.authz_id, challenge.r#type
        ),
        status: &challenge.status,
        token,
        accounturi,
        issuer_domain_names,
        auth_key,
        nonce: challenge_nonce,
        from,
        tkauth_type,
        token_authority,
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
    let mut resp = json_response(state, ca_id, StatusCode::OK, body, nonce)?;
    // RFC 8555 §7.5.1: challenge response MUST include Link rel="up" pointing
    // to the parent authorization resource so clients can poll for authz status.
    let authz_url = format!("{acme_pfx}/authz/{}", challenge.authz_id);
    if let Ok(link_up) = HeaderValue::from_str(&format!("<{authz_url}>;rel=\"up\"")) {
        resp.headers_mut().append(axum::http::header::LINK, link_up);
    } else {
        tracing::warn!(
            challenge_id = %challenge.id,
            authz_url,
            "could not build Link rel=up header for challenge response"
        );
    }
    Ok(resp)
}
