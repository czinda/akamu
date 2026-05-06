//! POST /acme/new-account and POST /acme/account/{id} — RFC 8555 §7.3

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::Deserialize;
use serde_json::json;

use crate::db;
use crate::db::schema::AccountRow;
use crate::error::AcmeError;
use crate::jose::jws::JwsKeyRef;
use crate::state::AppState;

use super::{acme_headers, acme_prefix, json_response, parse_jws, require_payload, unix_now, CaId};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct NewAccountPayload {
    contact: Option<Vec<String>>,
    #[serde(default)]
    terms_of_service_agreed: Option<bool>,
    #[serde(default)]
    only_return_existing: bool,
    external_account_binding: Option<serde_json::Value>,
}

pub async fn new_account(
    State(state): State<Arc<AppState>>,
    ca_id: CaId,
    body: Bytes,
) -> Result<Response, AcmeError> {
    let pfx = acme_prefix(&state.config.base_url, &ca_id.0, &state.default_ca_id);
    let url = format!("{pfx}/new-account");
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
    // EAB checks only apply to new account creation, not returning clients.
    if let Some(existing) = db::accounts::get_by_thumbprint(&state.db, &thumbprint).await? {
        let account_url = format!("{pfx}/account/{}", existing.id);
        let contacts = parse_contacts(&existing.contact);
        let mut resp = json_response(
            &state,
            &ca_id.0,
            StatusCode::OK,
            account_json(&existing, &contacts, &pfx),
            &ctx.next_nonce,
        )?;
        let loc = HeaderValue::from_str(&account_url)
            .map_err(|e| AcmeError::Internal(format!("invalid Location header: {e}")))?;
        resp.headers_mut().insert(axum::http::header::LOCATION, loc);
        return Ok(resp);
    }

    if payload.only_return_existing {
        // RFC 8555 §7.3.1: respond with accountDoesNotExist.
        // Include Replay-Nonce so the client can retry with a creation request
        // (RFC 8555 §6.5.1 SHOULD include nonce in error responses).
        let mut resp = AcmeError::AccountDoesNotExist.into_response();
        resp.headers_mut()
            .extend(acme_headers(&state, &ca_id.0, &ctx.next_nonce));
        return Ok(resp);
    }

    // ── Terms of Service (RFC 8555 §7.3.3) ───────────────────────────────────
    // Enforce ToS agreement only for new account creation; existing accounts
    // that predate a ToS update are handled by the lookup path above.
    if let Some(tos_url) = &state.config.server.terms_of_service_url {
        if payload.terms_of_service_agreed != Some(true) {
            let mut resp =
                AcmeError::UserActionRequired("you must agree to the terms of service".into())
                    .into_response();
            resp.headers_mut()
                .extend(acme_headers(&state, &ca_id.0, &ctx.next_nonce));
            resp.headers_mut().append(
                axum::http::header::LINK,
                HeaderValue::from_str(&format!("<{tos_url}>; rel=\"terms-of-service\""))
                    .unwrap_or_else(|_| HeaderValue::from_static("")),
            );
            return Ok(resp);
        }
    }

    // Validate contacts.
    validate_contacts(payload.contact.as_deref().unwrap_or(&[]))?;

    // ── External Account Binding (RFC 8555 §7.3.4) ────────────────────────────
    // When external_account_required is set every new-account request must carry
    // a valid HMAC-signed EAB JWS whose payload is the account public key.
    // The (kid, profile_grants) tuple lets us copy grants from the EAB key to
    // the account atomically in the same transaction.
    let verified_eab: Option<(String, Option<String>)> =
        if state.config.server.external_account_required {
            let eab_val = payload
                .external_account_binding
                .as_ref()
                .ok_or(AcmeError::ExternalAccountRequired)?;

            // Extract kid from EAB protected header → look it up in the DB.
            let kid = crate::jose::eab::parse_eab_kid(eab_val)?;
            let key_row = db::eab::get_by_kid(&state.db, &kid)
                .await?
                .ok_or_else(|| AcmeError::Unauthorized(format!("EAB: unknown kid '{kid}'")))?;

            if key_row.used_at.is_some() {
                return Err(AcmeError::Unauthorized(format!(
                    "EAB: kid '{kid}' has already been used"
                )));
            }

            // Decode the raw HMAC key bytes.
            let hmac_key = URL_SAFE_NO_PAD
                .decode(&key_row.hmac_key_b64u)
                .map_err(|e| {
                    AcmeError::BadRequest(format!("EAB: invalid HMAC key encoding: {e}"))
                })?;

            // Full HMAC verification: alg, url, payload-key, and MAC.
            if let Err(e) =
                crate::jose::eab::verify_eab_jws(eab_val, &url, &kid, &thumbprint, &hmac_key)
            {
                state
                    .record_audit(
                        crate::audit::AuditEvent::failure(crate::audit::AuditEventType::EabReject)
                            .with_subject(&kid),
                    )
                    .await;
                state
                    .record_audit(
                        crate::audit::AuditEvent::failure(
                            crate::audit::AuditEventType::SecurityViolation,
                        )
                        .with_subject(&kid)
                        .with_detail("EAB HMAC verification failed"),
                    )
                    .await;
                return Err(e);
            }
            state
                .record_audit(
                    crate::audit::AuditEvent::success(crate::audit::AuditEventType::EabUse)
                        .with_subject(&kid),
                )
                .await;

            // Capture grants before dropping key_row.
            let grants = key_row.profile_grants.clone();
            Some((kid, grants))
        } else {
            None
        };

    let id = uuid::Uuid::new_v4().to_string();
    let contact_json = payload
        .contact
        .as_ref()
        .map(|c| serde_json::to_string(c))
        .transpose()
        .map_err(|e| AcmeError::Internal(format!("contact serialization: {e}")))?;

    // Profile grants inherited from the EAB key (None when no EAB was used).
    let eab_profile_grants = verified_eab.as_ref().and_then(|(_, g)| g.clone());

    // Insert the new account — atomically consume the EAB key if one was verified.
    // Both paths use a transaction so the insert is atomic with any EAB mark.
    {
        let mut tx = db::begin_write(&state.db, state.db_kind).await?;
        db::accounts::insert(
            &mut *tx,
            AccountRow {
                id: id.clone(),
                status: "valid".into(),
                contact: contact_json.clone(),
                public_key: ctx.spki_der,
                jwk_thumbprint: thumbprint,
                created: now,
                updated: now,
                profile_grants: eab_profile_grants,
                ca_id: String::new(),
            },
        )
        .await?;
        if let Some((eab_kid, _)) = verified_eab {
            db::eab::mark_used(&mut *tx, &eab_kid, now).await?;
        }
        tx.commit().await.map_err(AcmeError::from)?;
        state
            .record_audit(
                crate::audit::AuditEvent::success(crate::audit::AuditEventType::AccountCreate)
                    .with_subject(&id),
            )
            .await;
    }

    let row = AccountRow {
        id: id.clone(),
        status: "valid".into(),
        contact: contact_json,
        public_key: vec![],
        jwk_thumbprint: String::new(),
        created: now,
        updated: now,
        profile_grants: None,
        ca_id: String::new(),
    };
    let contacts = payload.contact.unwrap_or_default();
    let account_url = format!("{pfx}/account/{id}");
    let mut resp = json_response(
        &state,
        &ca_id.0,
        StatusCode::CREATED,
        account_json(&row, &contacts, &pfx),
        &ctx.next_nonce,
    )?;
    let loc = HeaderValue::from_str(&account_url)
        .map_err(|e| AcmeError::Internal(format!("invalid Location header: {e}")))?;
    resp.headers_mut().insert(axum::http::header::LOCATION, loc);
    Ok(resp)
}

pub async fn update_account(
    State(state): State<Arc<AppState>>,
    ca_id: CaId,
    Path(id): Path<String>,
    body: Bytes,
) -> Result<Response, AcmeError> {
    let pfx = acme_prefix(&state.config.base_url, &ca_id.0, &state.default_ca_id);
    let url = format!("{pfx}/account/{id}");
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
            &ca_id.0,
            StatusCode::OK,
            account_json(&account, &contacts, &pfx),
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
        match state.spki_cache.write() {
            Ok(mut cache) => { cache.remove(&id); }
            Err(e) => {
                tracing::error!("spki_cache RwLock poisoned; evicting deactivated account under poison guard");
                e.into_inner().remove(&id);
            }
        }
        state
            .record_audit(
                crate::audit::AuditEvent::success(crate::audit::AuditEventType::AccountDeactivate)
                    .with_subject(&id),
            )
            .await;
        let mut deactivated = account.clone();
        deactivated.status = "deactivated".into();
        let contacts = parse_contacts(&deactivated.contact);
        return json_response(
            &state,
            &ca_id.0,
            StatusCode::OK,
            account_json(&deactivated, &contacts, &pfx),
            &ctx.next_nonce,
        );
    }

    // Update contact.
    if let Some(new_contacts) = &payload.contact {
        validate_contacts(new_contacts)?;
        let contact_json = serde_json::to_string(new_contacts)
            .map_err(|e| AcmeError::Internal(format!("contact serialization: {e}")))?;
        db::accounts::update_contact(&state.db, &id, Some(contact_json), unix_now()).await?;
    }

    let updated = db::accounts::get_by_id(&state.db, &id)
        .await?
        .ok_or(AcmeError::AccountDoesNotExist)?;
    let contacts = parse_contacts(&updated.contact);
    json_response(
        &state,
        &ca_id.0,
        StatusCode::OK,
        account_json(&updated, &contacts, &pfx),
        &ctx.next_nonce,
    )
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn account_json(row: &AccountRow, contacts: &[String], pfx: &str) -> serde_json::Value {
    json!({
        "status": row.status,
        "contact": contacts,
        "orders": format!("{pfx}/orders/{}", row.id),
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
        // RFC 8555 §7.1.2 requires contacts to be URLs.  Any URI scheme is
        // accepted; bare strings without a scheme separator are rejected.
        if !c.contains(':') {
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
    fn validate_contacts_accepts_any_uri_scheme() {
        validate_contacts(&["https://example.com".to_string()]).unwrap();
        validate_contacts(&["tel:+1-555-000-0000".to_string()]).unwrap();
        validate_contacts(&["xmpp:user@example.com".to_string()]).unwrap();
    }

    #[test]
    fn validate_contacts_rejects_bare_strings() {
        let result = validate_contacts(&["user@example.com".to_string()]);
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

    #[test]
    fn new_account_payload_tos_field() {
        // Absent → None (not agreed)
        let absent: NewAccountPayload =
            serde_json::from_str(r#"{"contact":["mailto:a@b.com"]}"#).unwrap();
        assert_eq!(absent.terms_of_service_agreed, None);

        // Explicit true → Some(true)
        let agreed: NewAccountPayload =
            serde_json::from_str(r#"{"termsOfServiceAgreed":true}"#).unwrap();
        assert_eq!(agreed.terms_of_service_agreed, Some(true));

        // Explicit false → Some(false)
        let refused: NewAccountPayload =
            serde_json::from_str(r#"{"termsOfServiceAgreed":false}"#).unwrap();
        assert_eq!(refused.terms_of_service_agreed, Some(false));
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
            profile_grants: None,
            ca_id: String::new(),
        };
        let contacts = vec!["mailto:a@b.com".to_string()];
        let json = account_json(&row, &contacts, "https://acme.test");
        assert_eq!(json["status"], "valid");
        assert!(json["orders"].as_str().unwrap().contains("test-id"));
    }
}
