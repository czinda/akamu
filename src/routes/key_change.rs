//! POST /acme/key-change — RFC 8555 §7.3.5

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::Response;
use serde::Deserialize;
use serde_json::json;

use crate::db;
use crate::error::AcmeError;
use crate::jose::jws::{JwsFlattened, JwsKeyRef};
use crate::state::AppState;

use super::{acme_prefix, json_response, parse_jws, unix_now, CaId};

pub async fn key_change(
    State(state): State<Arc<AppState>>,
    ca_id: CaId,
    body: Bytes,
) -> Result<Response, AcmeError> {
    let pfx = acme_prefix(&state.config.base_url, &ca_id.0, &state.default_ca_id);
    let url = format!("{pfx}/key-change");
    let ctx = parse_jws(&state, body, &url).await?;

    let account_id = ctx
        .account_id
        .ok_or(AcmeError::Unauthorized("kid required".into()))?;

    // The payload is itself an inner JWS signed with the new key.
    if ctx.payload.is_empty() {
        return Err(AcmeError::BadRequest(
            "key-change payload is required".into(),
        ));
    }

    // Parse the inner JWS.
    let inner_jws: JwsFlattened = serde_json::from_slice(&ctx.payload)
        .map_err(|e| AcmeError::BadRequest(format!("inner JWS parse: {e}")))?;

    // The inner JWS must be signed with the new key (jwk).
    let inner_header = inner_jws.decode_header()?;
    let new_jwk = match &inner_header.key_ref {
        JwsKeyRef::Jwk { jwk } => jwk.clone(),
        JwsKeyRef::Kid { .. } => {
            return Err(AcmeError::BadRequest(
                "inner key-change JWS must use jwk (new key)".into(),
            ));
        }
    };

    let new_spki = new_jwk.to_spki_der()?;
    let new_thumbprint = new_jwk.thumbprint()?;

    // Verify inner JWS signature with new key.
    inner_jws.verify(&new_spki)?;

    // Inner payload must be { account: <account_url>, oldKey: <old_jwk> }.
    let inner_payload_bytes = inner_jws.decode_payload()?;
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct InnerPayload {
        account: String,
        old_key: crate::jose::jwk::JwkPublic,
    }
    let inner_payload: InnerPayload = serde_json::from_slice(&inner_payload_bytes)
        .map_err(|e| AcmeError::BadRequest(format!("inner payload JSON: {e}")))?;

    // Verify account URL matches.
    let expected_account_url = format!("{pfx}/account/{account_id}");
    if inner_payload.account != expected_account_url {
        return Err(AcmeError::BadRequest(
            "inner payload account URL does not match".into(),
        ));
    }

    // RFC 8555 §7.3.5: oldKey must match the current account key.
    let old_spki = inner_payload.old_key.to_spki_der()?;
    if old_spki != ctx.spki_der {
        return Err(AcmeError::Unauthorized(
            "inner payload oldKey does not match current account key".into(),
        ));
    }

    // Verify the new key is not already in use.
    if db::accounts::get_by_thumbprint(&state.db, &new_thumbprint)
        .await?
        .is_some()
    {
        return Err(AcmeError::Conflict(
            "new key already in use by another account".into(),
        ));
    }

    // Update the account key and evict from the SPKI cache so the next
    // request re-loads the new key from the database.
    let old_thumbprint = ctx.jwk_thumbprint.clone().unwrap_or_default();
    let now = unix_now();
    db::accounts::update_key(
        &state.db,
        &account_id,
        new_spki,
        new_thumbprint.clone(),
        now,
    )
    .await?;
    state.spki_cache.write().unwrap_or_else(|e| e.into_inner()).remove(&account_id);

    state
        .record_audit(
            crate::audit::AuditEvent::success(crate::audit::AuditEventType::AccountKeyChange)
                .with_subject(&account_id)
                .with_principal(format!("acme:{old_thumbprint}"))
                .with_detail(format!("new_key={new_thumbprint}")),
        )
        .await;

    let account = db::accounts::get_by_id(&state.db, &account_id)
        .await?
        .ok_or(AcmeError::AccountDoesNotExist)?;

    let contacts: Vec<String> = account
        .contact
        .as_deref()
        .and_then(|s| serde_json::from_str(s).ok())
        .unwrap_or_default();

    json_response(
        &state,
        &ca_id.0,
        StatusCode::OK,
        json!({
            "status": account.status,
            "contact": contacts,
            "orders": format!("{pfx}/orders/{account_id}"),
        }),
        &ctx.next_nonce,
    )
}
