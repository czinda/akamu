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
    external_account_binding: Option<serde_json::Value>,
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

    // RFC 8555 §7.3.4 — when externalAccountRequired is set the payload MUST
    // contain an externalAccountBinding field.  Full MAC verification of the
    // EAB JWS is deferred until key-management support is added; presence
    // checking is the correct first gate per the spec.
    if state.config.server.external_account_required
        && payload.external_account_binding.is_none()
    {
        return Err(AcmeError::ExternalAccountRequired);
    }

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
            &ctx.next_nonce,
        )?;
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
        &ctx.next_nonce,
    )?;
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
    let account_id = ctx
        .account_id
        .ok_or(AcmeError::Unauthorized("kid required".into()))?;
    if account_id != id {
        return Err(AcmeError::Unauthorized(
            "kid does not match account ID".into(),
        ));
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
            &ctx.next_nonce,
        );
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
        state.spki_cache.write().unwrap().remove(&id);
        let mut deactivated = account.clone();
        deactivated.status = "deactivated".into();
        let contacts = parse_contacts(&deactivated.contact);
        return json_response(
            &state,
            StatusCode::OK,
            account_json(&deactivated, &contacts, &state.config.base_url),
            &ctx.next_nonce,
        );
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
        &ctx.next_nonce,
    )
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_contacts_accepts_mailto_urls() {
        validate_contacts(&["mailto:user@example.com".to_string()]).unwrap();
        validate_contacts(&["mailto:a@b.com".to_string(), "mailto:c@d.org".to_string()]).unwrap();
    }

    #[test]
    fn validate_contacts_rejects_non_mailto() {
        let result = validate_contacts(&["https://example.com".to_string()]);
        assert!(result.is_err());
        match result.unwrap_err() {
            AcmeError::UnsupportedContact => {}
            other => panic!("expected UnsupportedContact, got {other:?}"),
        }
    }

    #[test]
    fn validate_contacts_empty_slice_is_ok() {
        validate_contacts(&[]).unwrap();
    }

    #[test]
    fn parse_contacts_none_returns_empty_vec() {
        let result = parse_contacts(&None);
        assert!(result.is_empty());
    }

    #[test]
    fn parse_contacts_valid_json_array() {
        let json = Some("[\"mailto:a@b.com\",\"mailto:c@d.org\"]".to_string());
        let result = parse_contacts(&json);
        assert_eq!(result, vec!["mailto:a@b.com", "mailto:c@d.org"]);
    }

    #[test]
    fn parse_contacts_invalid_json_returns_empty() {
        let json = Some("not-json".to_string());
        let result = parse_contacts(&json);
        assert!(result.is_empty());
    }

    /// Verifies that `NewAccountPayload` deserialises `externalAccountBinding`
    /// when present and treats its absence as `None` (RFC 8555 §7.3.4).
    /// The handler-level enforcement (returning `ExternalAccountRequired` when
    /// `server.external_account_required` is true and the field is absent) is
    /// covered by integration tests that exercise the full Axum stack.
    #[test]
    fn new_account_payload_eab_field_optional() {
        // Without the field → None
        let without: NewAccountPayload =
            serde_json::from_str(r#"{"termsOfServiceAgreed":true}"#).unwrap();
        assert!(without.external_account_binding.is_none());

        // With the field → Some
        let with_eab: NewAccountPayload = serde_json::from_str(
            r#"{"termsOfServiceAgreed":true,"externalAccountBinding":{"protected":"x","payload":"y","signature":"z"}}"#,
        )
        .unwrap();
        assert!(with_eab.external_account_binding.is_some());
    }

    #[test]
    fn account_json_has_required_fields() {
        let row = AccountRow {
            id: "test-id".to_string(),
            status: "valid".to_string(),
            contact: None,
            public_key: vec![],
            jwk_thumbprint: "thumb".to_string(),
            created: 0,
            updated: 0,
        };
        let contacts = vec!["mailto:a@b.com".to_string()];
        let json = account_json(&row, &contacts, "https://acme.test");
        assert_eq!(json["status"], "valid");
        assert!(json["orders"].as_str().unwrap().contains("test-id"));
    }
}
