//! POST /acme/new-account and POST /acme/account/{id} — RFC 8555 §7.3

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderValue, StatusCode};
use axum::response::Response;
use serde::Deserialize;
use serde_json::json;

use crate::db;
use crate::db::schema::AccountRow;
use crate::error::AcmeError;
use crate::jose::jws::JwsKeyRef;
use crate::state::AppState;

use super::{json_response, parse_jws, require_payload, unix_now};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct NewAccountPayload {
    contact: Option<Vec<String>>,
    #[serde(default)]
    only_return_existing: bool,
}

pub async fn new_account(
    State(state): State<Arc<AppState>>,
    body: Bytes,
) -> Result<Response, AcmeError> {
    let url = format!("{}/acme/new-account", state.config.base_url);
    let ctx = parse_jws(&state, body, &url).await?;

    // new-account must use jwk (not kid).
    let jwk = match &ctx.header.key_ref {
        JwsKeyRef::Jwk { jwk } => jwk.clone(),
        JwsKeyRef::Kid { .. } => {
            return Err(AcmeError::BadRequest("new-account must use jwk".into()));
        }
    };

    let payload: NewAccountPayload = require_payload(&ctx.payload, "new-account")?;
    let thumbprint = jwk.thumbprint()?;
    let now = unix_now();

    // Check if an account with this key already exists.
    if let Some(existing) = db::accounts::get_by_thumbprint(&state.db, &thumbprint).await? {
        let account_url = format!("{}/acme/account/{}", state.config.base_url, existing.id);
        let contacts = parse_contacts(&existing.contact);
        let mut resp = json_response(
            &state,
            StatusCode::OK,
            account_json(&existing, &contacts, &state.config.base_url),
        )
        .await?;
        resp.headers_mut().insert(
            axum::http::header::LOCATION,
            HeaderValue::from_str(&account_url).unwrap(),
        );
        return Ok(resp);
    }

    if payload.only_return_existing {
        return Err(AcmeError::AccountDoesNotExist);
    }

    // Validate contacts.
    validate_contacts(payload.contact.as_deref().unwrap_or(&[]))?;

    let id = uuid::Uuid::new_v4().to_string();
    let contact_json = payload
        .contact
        .as_ref()
        .map(|c| serde_json::to_string(c).unwrap());

    db::accounts::insert(
        &state.db,
        AccountRow {
            id: id.clone(),
            status: "valid".into(),
            contact: contact_json.clone(),
            public_key: ctx.spki_der,
            jwk_thumbprint: thumbprint,
            created: now,
            updated: now,
        },
    )
    .await?;

    let row = AccountRow {
        id: id.clone(),
        status: "valid".into(),
        contact: contact_json,
        public_key: vec![],
        jwk_thumbprint: String::new(),
        created: now,
        updated: now,
    };
    let contacts = payload.contact.unwrap_or_default();
    let account_url = format!("{}/acme/account/{}", state.config.base_url, id);
    let mut resp = json_response(
        &state,
        StatusCode::CREATED,
        account_json(&row, &contacts, &state.config.base_url),
    )
    .await?;
    resp.headers_mut().insert(
        axum::http::header::LOCATION,
        HeaderValue::from_str(&account_url).unwrap(),
    );
    Ok(resp)
}

pub async fn update_account(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    body: Bytes,
) -> Result<Response, AcmeError> {
    let url = format!("{}/acme/account/{}", state.config.base_url, id);
    let ctx = parse_jws(&state, body, &url).await?;

    // Must use kid pointing to this account.
    let account_id = ctx.account_id.ok_or(AcmeError::Unauthorized("kid required".into()))?;
    if account_id != id {
        return Err(AcmeError::Unauthorized("kid does not match account ID".into()));
    }

    let account = db::accounts::get_by_id(&state.db, &id)
        .await?
        .ok_or(AcmeError::AccountDoesNotExist)?;

    // POST-as-GET: return account details.
    if ctx.payload.is_empty() {
        let contacts = parse_contacts(&account.contact);
        return json_response(
            &state,
            StatusCode::OK,
            account_json(&account, &contacts, &state.config.base_url),
        )
        .await;
    }

    // Parse update payload.
    #[derive(Deserialize)]
    struct UpdatePayload {
        contact: Option<Vec<String>>,
        status: Option<String>,
    }
    let payload: UpdatePayload = serde_json::from_slice(&ctx.payload)
        .map_err(|e| AcmeError::BadRequest(format!("update-account JSON: {e}")))?;

    // Handle deactivation.
    if payload.status.as_deref() == Some("deactivated") {
        db::accounts::update_status(&state.db, &id, "deactivated", unix_now()).await?;
        let mut deactivated = account.clone();
        deactivated.status = "deactivated".into();
        let contacts = parse_contacts(&deactivated.contact);
        return json_response(
            &state,
            StatusCode::OK,
            account_json(&deactivated, &contacts, &state.config.base_url),
        )
        .await;
    }

    // Update contact.
    if let Some(new_contacts) = &payload.contact {
        validate_contacts(new_contacts)?;
        let contact_json = serde_json::to_string(new_contacts).unwrap();
        db::accounts::update_contact(&state.db, &id, Some(contact_json), unix_now()).await?;
    }

    let updated = db::accounts::get_by_id(&state.db, &id)
        .await?
        .ok_or(AcmeError::AccountDoesNotExist)?;
    let contacts = parse_contacts(&updated.contact);
    json_response(
        &state,
        StatusCode::OK,
        account_json(&updated, &contacts, &state.config.base_url),
    )
    .await
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn account_json(row: &AccountRow, contacts: &[String], base_url: &str) -> serde_json::Value {
    json!({
        "status": row.status,
        "contact": contacts,
        "orders": format!("{base_url}/acme/orders/{}", row.id),
    })
}

fn parse_contacts(contact_json: &Option<String>) -> Vec<String> {
    contact_json
        .as_deref()
        .and_then(|s| serde_json::from_str::<Vec<String>>(s).ok())
        .unwrap_or_default()
}

fn validate_contacts(contacts: &[String]) -> Result<(), AcmeError> {
    for c in contacts {
        if !c.starts_with("mailto:") {
            return Err(AcmeError::UnsupportedContact);
        }
    }
    Ok(())
}
