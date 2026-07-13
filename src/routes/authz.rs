//! POST /acme/new-authz — RFC 8555 §7.4.1
//! POST /acme/authz/{id} — RFC 8555 §7.5

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::Response;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::db;
use crate::db::schema::{AuthorizationRow, ChallengeRow};
use crate::error::AcmeError;
use crate::state::AppState;

use super::{
    account_uri, acme_prefix, fmt_time, json_response, parse_jws, require_payload, unix_now, CaId,
};

fn is_false(b: &bool) -> bool {
    !b
}

use super::ChallengeJson;

/// Typed authorization response body.
///
/// `identifier` is embedded as raw JSON (no re-parse from the stored string).
/// `wildcard` and `subdomain_auth_allowed` are omitted when false.
#[derive(Serialize)]
struct AuthzJson<'a> {
    status: &'a str,
    identifier: Box<serde_json::value::RawValue>,
    challenges: Vec<ChallengeJson<'a>>,
    #[serde(skip_serializing_if = "is_false")]
    wildcard: bool,
    #[serde(rename = "subdomainAuthAllowed", skip_serializing_if = "is_false")]
    subdomain_auth_allowed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    expires: Option<String>,
}

// ── new-authz payload types ───────────────────────────────────────────────────

#[derive(Deserialize)]
struct NewAuthzIdentifier {
    r#type: String,
    value: String,
}

#[derive(Deserialize)]
struct NewAuthzPayload {
    identifier: NewAuthzIdentifier,
    #[serde(default, rename = "subdomainAuthAllowed")]
    subdomain_auth_allowed: bool,
}

// ── Handlers ─────────────────────────────────────────────────────────────────

/// POST /acme/new-authz — RFC 8555 §7.4.1 pre-authorization.
pub async fn new_authz(
    State(state): State<Arc<AppState>>,
    ca_id: CaId,
    body: Bytes,
) -> Result<Response, AcmeError> {
    let pfx = acme_prefix(&state.config.base_url, &ca_id.0, &state.default_ca_id);
    let url = format!("{pfx}/new-authz");
    let ctx = parse_jws(&state, body, &url).await?;

    let account_id = ctx
        .account_id
        .ok_or(AcmeError::Unauthorized("kid required".into()))?;

    let payload: NewAuthzPayload = require_payload(&ctx.payload, "new-authz")?;

    // Validate identifier type.
    match payload.identifier.r#type.as_str() {
        "dns" | "ip" => {}
        "email" => {
            if !state
                .config
                .email_challenge
                .as_ref()
                .is_some_and(|ec| ec.enabled)
            {
                return Err(AcmeError::UnsupportedIdentifier("email".into()));
            }
            if !super::order::is_valid_email(&payload.identifier.value) {
                return Err(AcmeError::BadRequest(format!(
                    "invalid email identifier: '{}'",
                    payload.identifier.value
                )));
            }
        }
        other => return Err(AcmeError::UnsupportedIdentifier(other.into())),
    }

    // Wildcards are not allowed in pre-authorization (RFC 8555: wildcards only in orders).
    if payload.identifier.value.starts_with("*.") {
        return Err(AcmeError::RejectedIdentifier(
            "wildcard identifiers are not allowed in pre-authorization".into(),
        ));
    }

    // RFC 9444 §4: reject subdomainAuthAllowed if the server does not support it.
    if payload.subdomain_auth_allowed && !state.config.server.allow_subdomain_auth {
        return Err(AcmeError::BadRequest(
            "server does not support subdomainAuthAllowed pre-authorization".into(),
        ));
    }

    let identifier_json = serde_json::to_string(
        &json!({"type": payload.identifier.r#type, "value": payload.identifier.value}),
    )
    .map_err(|e| AcmeError::Internal(format!("identifier serialization: {e}")))?;

    let now = unix_now();

    // Check for an existing valid unexpired authorization for this account+identifier.
    if let Some(existing_authz) = db::authz::find_valid_by_account_and_identifier(
        &state.db_ro,
        &account_id,
        &identifier_json,
        &ca_id.0,
        now,
    )
    .await?
    {
        // Return the existing authorization.
        let (authz, challenges) = db::authz::get_with_challenges(&state.db_ro, &existing_authz.id)
            .await?
            .ok_or(AcmeError::NotFound)?;
        let location = format!("{pfx}/authz/{}", authz.id);
        let thumbprint = ctx
            .jwk_thumbprint
            .as_deref()
            .ok_or_else(|| AcmeError::Internal("JWK thumbprint missing in authz handler".into()))?;
        let body = build_authz_json(&authz, &challenges, &pfx, &state, thumbprint)?;
        let mut resp = json_response(&state, &ca_id.0, StatusCode::CREATED, body, &ctx.next_nonce)?;
        resp.headers_mut().insert(
            axum::http::header::LOCATION,
            location
                .parse()
                .map_err(|e| AcmeError::Internal(format!("invalid Location header: {e}")))?,
        );
        return Ok(resp);
    }

    // Build the new authorization and its challenges.
    let authz_id = uuid::Uuid::new_v4().to_string();
    let authz_expiry = now + state.config.server.authz_expiry_secs as i64;

    // RFC 9799 §2: validate v3 .onion addresses in pre-authorization.
    let is_onion = payload.identifier.r#type == "dns"
        && payload
            .identifier
            .value
            .to_ascii_lowercase()
            .ends_with(".onion");
    if is_onion && !crate::validation::onion_csr_01::validate_onion_v3(&payload.identifier.value) {
        return Err(AcmeError::RejectedIdentifier(format!(
            "only v3 .onion addresses are supported (56-char base32 label); got: {}",
            payload.identifier.value
        )));
    }

    let token = gen_token()?;
    let dns_persist_enabled = !state.config.dns_persist_issuer_domains().is_empty();
    let dns_types: &[&str] = if dns_persist_enabled {
        &["http-01", "dns-01", "tls-alpn-01", "dns-persist-01"]
    } else {
        &["http-01", "dns-01", "tls-alpn-01"]
    };
    let challenge_types: &[&str] = match payload.identifier.r#type.as_str() {
        // RFC 9799 §3.1.1: .onion domains MUST offer onion-csr-01 and MUST NOT
        // offer dns-01.  http-01 and tls-alpn-01 are allowed (require Tor).
        "dns" if is_onion => &["onion-csr-01", "http-01", "tls-alpn-01"],
        "dns" => dns_types,
        "ip" => &["http-01", "tls-alpn-01"],
        "email" => &["email-reply-00"],
        _ => &[],
    };

    // Build challenge rows before crossing the await boundary.
    let challenges: Vec<(String, String)> = challenge_types
        .iter()
        .map(|&t| (uuid::Uuid::new_v4().to_string(), t.to_string()))
        .collect();

    let subdomain_auth_allowed = payload.subdomain_auth_allowed;

    {
        let mut tx = db::begin_write(&state.db, state.db_kind).await?;
        db::pg_local_async_commit(&mut tx, state.db_kind).await?;
        crate::db::query(
            "INSERT INTO authorizations
             (id, order_id, account_id, status, identifier, expires,
              wildcard, subdomain_auth_allowed, created, updated, ca_id)
             VALUES (?, NULL, ?, 'pending', ?, ?, 0, ?, ?, ?, ?)",
        )
        .bind(&authz_id)
        .bind(&account_id)
        .bind(&identifier_json)
        .bind(authz_expiry)
        .bind(subdomain_auth_allowed as i64)
        .bind(now)
        .bind(now)
        .bind(&ca_id.0)
        .execute(&mut *tx)
        .await
        .map_err(AcmeError::from)?;

        db::challenges::insert_batch(
            &mut *tx,
            &authz_id,
            &challenges,
            &token,
            now,
            state
                .config
                .tkauth
                .as_ref()
                .and_then(|t| t.token_authority_url.as_deref()),
        )
        .await?;
        tx.commit().await.map_err(AcmeError::from)?;
    }

    // Fetch the freshly inserted authorization and its challenges for the response.
    let (authz, chall_rows) = db::authz::get_with_challenges(&state.db_ro, &authz_id)
        .await?
        .ok_or(AcmeError::NotFound)?;

    let location = format!("{pfx}/authz/{authz_id}");
    let thumbprint = ctx
        .jwk_thumbprint
        .as_deref()
        .ok_or_else(|| AcmeError::Internal("JWK thumbprint missing in authz handler".into()))?;
    let body = build_authz_json(&authz, &chall_rows, &pfx, &state, thumbprint)?;
    let mut resp = json_response(&state, &ca_id.0, StatusCode::CREATED, body, &ctx.next_nonce)?;
    resp.headers_mut().insert(
        axum::http::header::LOCATION,
        location
            .parse()
            .map_err(|e| AcmeError::Internal(format!("invalid Location header: {e}")))?,
    );
    Ok(resp)
}

/// Build the typed `AuthzJson` response body from a row + challenges.
///
/// `jwk_thumbprint` is the account's JWK thumbprint, used to populate the
/// `authKey` field for `onion-csr-01` challenges (RFC 9799 §3.2).
fn build_authz_json<'a>(
    authz: &'a AuthorizationRow,
    challenges: &'a [ChallengeRow],
    acme_pfx: &str,
    state: &'a AppState,
    jwk_thumbprint: &str,
) -> Result<AuthzJson<'a>, AcmeError> {
    let issuer_domains = state.config.dns_persist_issuer_domains();
    let challs: Vec<ChallengeJson<'_>> = challenges
        .iter()
        .map(|c| -> Result<ChallengeJson<'_>, AcmeError> {
            let (token, accounturi, issuer_domain_names, auth_key) =
                if c.r#type == "dns-persist-01" {
                    let uri = account_uri(acme_pfx, &authz.account_id);
                    (None, Some(uri), Some(issuer_domains), None)
                } else if c.r#type == "onion-csr-01" {
                    (
                        Some(c.token.as_str()),
                        None,
                        None,
                        Some(jwk_thumbprint.to_string()),
                    )
                } else {
                    (Some(c.token.as_str()), None, None, None)
                };
            let from = if c.r#type == "email-reply-00" {
                match state.config.email_challenge.as_ref().filter(|ec| ec.enabled) {
                    Some(ec) => Some(ec.from_address.clone()),
                    // For already-resolved challenges, omit the field — it is no
                    // longer needed and the config may have been legitimately
                    // removed after the challenge completed.
                    None if matches!(c.status.as_str(), "valid" | "invalid") => None,
                    None => {
                        tracing::warn!(
                            challenge_id = %c.id,
                            status = %c.status,
                            "email-reply-00 challenge exists but email_challenge is not configured or enabled"
                        );
                        return Err(AcmeError::Internal(
                            "email-reply-00 challenge cannot be served: \
                             email_challenge is not configured or enabled"
                                .into(),
                        ));
                    }
                }
            } else {
                None
            };
            let (tkauth_type, token_authority) = if c.r#type == "tkauth-01" {
                (c.tkauth_type.as_deref(), c.token_authority.as_deref())
            } else {
                (None, None)
            };
            Ok(ChallengeJson {
                r#type: &c.r#type,
                url: format!("{acme_pfx}/chall/{}/{}", authz.id, c.r#type),
                status: &c.status,
                token,
                accounturi,
                issuer_domain_names,
                auth_key,
                from,
                tkauth_type,
                token_authority,
                validated: c.validated.map(fmt_time),
                error: c.error.as_deref().and_then(|s| {
                    serde_json::value::RawValue::from_string(s.to_string())
                        .map_err(|e| {
                            tracing::warn!(
                                challenge_id = %c.id,
                                raw = s,
                                "corrupt error JSON in challenge row: {e}"
                            );
                        })
                        .ok()
                }),
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let identifier =
        serde_json::value::RawValue::from_string(authz.identifier.clone()).map_err(|e| {
            AcmeError::Internal(format!(
                "corrupt identifier JSON in authorization {}: {e}",
                authz.id
            ))
        })?;
    Ok(AuthzJson {
        status: &authz.status,
        identifier,
        challenges: challs,
        wildcard: authz.wildcard != 0,
        subdomain_auth_allowed: authz.subdomain_auth_allowed != 0,
        expires: authz.expires.map(fmt_time),
    })
}

/// Generate a random base64url-encoded token (32 bytes, no padding).
fn gen_token() -> Result<String, AcmeError> {
    let mut bytes = [0u8; 32];
    native_ossl::rand::Rand::fill(&mut bytes)
        .map_err(|e| AcmeError::Internal(format!("CSPRNG failure: {e}")))?;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

pub async fn get_authz(
    State(state): State<Arc<AppState>>,
    ca_id: CaId,
    Path(params): Path<std::collections::HashMap<String, String>>,
    body: Bytes,
) -> Result<Response, AcmeError> {
    let id = params.get("id").cloned().ok_or(AcmeError::NotFound)?;
    let pfx = acme_prefix(&state.config.base_url, &ca_id.0, &state.default_ca_id);
    let url = format!("{pfx}/authz/{id}");
    let ctx = parse_jws(&state, body, &url).await?;

    let account_id = ctx
        .account_id
        .ok_or(AcmeError::Unauthorized("kid required".into()))?;

    let (authz, challenges) = db::authz::get_with_challenges(&state.db_ro, &id)
        .await?
        .ok_or(AcmeError::NotFound)?;
    if authz.account_id != account_id {
        return Err(AcmeError::Unauthorized(
            "authorization belongs to different account".into(),
        ));
    }
    // authz.ca_id is set to the order's CA at creation time (migration 009
    // backfills pre-existing rows to 'default', which is allowed on any CA).
    if !authz.ca_id.is_empty() && authz.ca_id != "default" && authz.ca_id != ca_id.0 {
        return Err(AcmeError::NotFound);
    }
    let thumbprint = ctx
        .jwk_thumbprint
        .as_deref()
        .ok_or_else(|| AcmeError::Internal("JWK thumbprint missing in authz handler".into()))?;
    let body = build_authz_json(&authz, &challenges, &pfx, &state, thumbprint)?;
    json_response(&state, &ca_id.0, StatusCode::OK, body, &ctx.next_nonce)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::schema::{AuthorizationRow, ChallengeRow};

    fn make_authz(status: &str, wildcard: bool, expires: Option<i64>) -> AuthorizationRow {
        AuthorizationRow {
            id: "authz-1".to_string(),
            order_id: "order-1".to_string(),
            account_id: "acct-1".to_string(),
            status: status.to_string(),
            identifier: "{\"type\":\"dns\",\"value\":\"example.com\"}".to_string(),
            expires,
            wildcard: i64::from(wildcard),
            subdomain_auth_allowed: 0,
            created: 1_700_000_000,
            updated: 1_700_000_000,
            ca_id: "default".to_string(),
        }
    }

    fn make_challenge(chall_type: &str, status: &str) -> ChallengeRow {
        ChallengeRow {
            id: format!("chall-{chall_type}"),
            authz_id: "authz-1".to_string(),
            r#type: chall_type.to_string(),
            status: status.to_string(),
            token: "test-token".to_string(),
            validated: None,
            error: None,
            created: 1_700_000_000,
            updated: 1_700_000_000,
            email_token_part1: None,
            email_message_id: None,
            tkauth_type: None,
            token_authority: None,
        }
    }

    /// Verify the payload parsing rejects unknown identifier types.
    #[test]
    fn invalid_identifier_type_rejected() {
        let raw = br#"{"identifier":{"type":"foobar","value":"example.com"}}"#;
        let result: Result<NewAuthzPayload, _> = serde_json::from_slice(raw);
        // Deserialization itself succeeds — the type check happens in the handler.
        // We test the check logic by inspecting the parsed type.
        let payload = result.unwrap();
        assert_eq!(payload.identifier.r#type, "foobar");
        // Simulate the type-guard in the handler.
        let accepted = matches!(payload.identifier.r#type.as_str(), "dns" | "ip");
        assert!(!accepted, "foobar should be rejected");
    }

    /// Verify that a wildcard identifier value is detected correctly.
    #[test]
    fn wildcard_identifier_detected() {
        let raw = br#"{"identifier":{"type":"dns","value":"*.example.com"}}"#;
        let payload: NewAuthzPayload = serde_json::from_slice(raw).unwrap();
        assert!(payload.identifier.value.starts_with("*."));
    }

    /// Verify that a non-wildcard dns identifier is not mistakenly flagged.
    #[test]
    fn non_wildcard_identifier_not_rejected() {
        let raw = br#"{"identifier":{"type":"dns","value":"example.com"}}"#;
        let payload: NewAuthzPayload = serde_json::from_slice(raw).unwrap();
        assert!(!payload.identifier.value.starts_with("*."));
        let accepted = matches!(payload.identifier.r#type.as_str(), "dns" | "ip");
        assert!(accepted);
    }

    /// Verify subdomainAuthAllowed is parsed and defaults to false.
    #[test]
    fn subdomain_auth_allowed_defaults_to_false() {
        let raw = br#"{"identifier":{"type":"dns","value":"example.com"}}"#;
        let payload: NewAuthzPayload = serde_json::from_slice(raw).unwrap();
        assert!(!payload.subdomain_auth_allowed);
    }

    #[test]
    fn subdomain_auth_allowed_parsed_when_true() {
        let raw =
            br#"{"identifier":{"type":"dns","value":"example.com"},"subdomainAuthAllowed":true}"#;
        let payload: NewAuthzPayload = serde_json::from_slice(raw).unwrap();
        assert!(payload.subdomain_auth_allowed);
    }

    /// gen_token produces a non-empty base64url string.
    #[test]
    fn gen_token_is_non_empty_base64url() {
        let t = gen_token().expect("CSPRNG available in test");
        assert!(!t.is_empty());
        assert!(t
            .chars()
            .all(|c| c.is_alphanumeric() || c == '-' || c == '_'));
    }

    /// AuthzJson serializes correctly for a pending authz with challenges.
    /// Tests the shape of the response body without needing a live AppState.
    #[test]
    fn authz_json_serializes_pending() {
        let authz = make_authz("pending", false, Some(1_700_100_000));
        let challs = [
            make_challenge("http-01", "pending"),
            make_challenge("dns-01", "pending"),
        ];
        let base = "https://acme.test";
        let chall_jsons: Vec<ChallengeJson<'_>> = challs
            .iter()
            .map(|c| ChallengeJson {
                r#type: &c.r#type,
                url: format!("{base}/acme/chall/{}/{}", authz.id, c.r#type),
                status: &c.status,
                token: Some(c.token.as_str()),
                accounturi: None,
                issuer_domain_names: None,
                auth_key: None,
                from: None,
                tkauth_type: None,
                token_authority: None,
                validated: None,
                error: None,
            })
            .collect();
        let identifier =
            serde_json::value::RawValue::from_string(authz.identifier.clone()).unwrap();
        let body = AuthzJson {
            status: &authz.status,
            identifier,
            challenges: chall_jsons,
            wildcard: authz.wildcard != 0,
            subdomain_auth_allowed: authz.subdomain_auth_allowed != 0,
            expires: authz.expires.map(super::super::fmt_time),
        };
        let val = serde_json::to_value(body).unwrap();

        assert_eq!(val["status"], "pending");
        // wildcard=false is omitted by skip_serializing_if.
        assert!(
            val.get("wildcard").is_none() || val["wildcard"].is_null(),
            "wildcard=false should be omitted"
        );
        assert!(val["expires"].as_str().is_some());
        let challenges = val["challenges"].as_array().unwrap();
        assert_eq!(challenges.len(), 2);
        let types: Vec<&str> = challenges
            .iter()
            .map(|c| c["type"].as_str().unwrap())
            .collect();
        assert!(types.contains(&"http-01"));
        assert!(types.contains(&"dns-01"));
        // Challenge URLs should contain the authz id.
        assert!(challenges[0]["url"].as_str().unwrap().contains("authz-1"));
    }

    /// AuthzJson with wildcard=true includes the wildcard field.
    #[test]
    fn authz_json_includes_wildcard_when_true() {
        let authz = make_authz("valid", true, None);
        let identifier =
            serde_json::value::RawValue::from_string(authz.identifier.clone()).unwrap();
        let body = AuthzJson {
            status: &authz.status,
            identifier,
            challenges: vec![],
            wildcard: true,
            subdomain_auth_allowed: false,
            expires: None,
        };
        let val = serde_json::to_value(body).unwrap();
        assert_eq!(val["wildcard"], true);
    }

    /// AuthzJson omits expires when None.
    #[test]
    fn authz_json_omits_expires_when_none() {
        let authz = make_authz("valid", false, None);
        let identifier =
            serde_json::value::RawValue::from_string(authz.identifier.clone()).unwrap();
        let body = AuthzJson {
            status: &authz.status,
            identifier,
            challenges: vec![],
            wildcard: false,
            subdomain_auth_allowed: false,
            expires: None,
        };
        let val = serde_json::to_value(body).unwrap();
        assert!(
            val.get("expires").is_none_or(|v| v.is_null()),
            "expires should be absent when None"
        );
    }
}
