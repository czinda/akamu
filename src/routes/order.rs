//! POST /acme/new-order, POST /acme/order/{id} — RFC 8555 §7.4

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::Response;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::db;
use crate::db::schema::OrderRow;
use crate::error::AcmeError;
use crate::state::AppState;

use super::{fmt_time, json_response, parse_jws, require_payload, unix_now};

#[derive(Deserialize)]
struct NewOrderIdentifier {
    r#type: String,
    value: String,
    #[serde(default, rename = "ancestorDomain")]
    ancestor_domain: Option<String>,
}

#[derive(Deserialize)]
struct NewOrderPayload {
    identifiers: Vec<NewOrderIdentifier>,
    #[serde(default)]
    replaces: Option<String>,
}

pub async fn new_order(
    State(state): State<Arc<AppState>>,
    body: Bytes,
) -> Result<Response, AcmeError> {
    let url = format!("{}/acme/new-order", state.config.base_url);
    let ctx = parse_jws(&state, body, &url).await?;

    let account_id = ctx
        .account_id
        .ok_or(AcmeError::Unauthorized("kid required".into()))?;

    // Account validity was already verified by parse_jws (SPKI cache or DB lookup).

    let payload: NewOrderPayload = require_payload(&ctx.payload, "new-order")?;

    // Validate identifiers.
    if payload.identifiers.is_empty() {
        return Err(AcmeError::BadRequest(
            "identifiers must not be empty".into(),
        ));
    }
    for id in &payload.identifiers {
        match id.r#type.as_str() {
            "dns" | "ip" => {}
            other => return Err(AcmeError::UnsupportedIdentifier(other.into())),
        }
        // Validate ancestorDomain if present: identifier.value must end with
        // ".<ancestor_domain>" (label-aligned, case-insensitive).
        if let Some(ref ancestor) = id.ancestor_domain {
            let value_lc = id.value.to_ascii_lowercase();
            let ancestor_lc = ancestor.to_ascii_lowercase();
            let suffix = format!(".{}", ancestor_lc);
            if !value_lc.ends_with(&suffix) {
                return Err(AcmeError::BadRequest(
                    "ancestorDomain is not an ancestor of the identifier".into(),
                ));
            }
        }
    }

    // Validate the optional `replaces` cert_id (RFC 9773 §5).
    let validated_replaces: Option<String> = if let Some(ref cert_id) = payload.replaces {
        let pred = db::certs::get_by_cert_id(&state.db, cert_id)
            .await?
            .ok_or(AcmeError::NotFound)?;
        if pred.account_id != account_id {
            return Err(AcmeError::Unauthorized(
                "replaces certificate belongs to different account".into(),
            ));
        }
        if pred.replaced_by.is_some() {
            return Err(AcmeError::CertAlreadyReplaced);
        }
        Some(cert_id.clone())
    } else {
        None
    };

    let now = unix_now();
    let expiry = now + state.config.server.order_expiry_secs as i64;
    let authz_expiry = now + state.config.server.authz_expiry_secs as i64;

    let order_id = uuid::Uuid::new_v4().to_string();
    let identifiers_json = serde_json::to_string(
        &payload
            .identifiers
            .iter()
            .map(|id| json!({"type": id.r#type, "value": id.value}))
            .collect::<Vec<_>>(),
    )
    .unwrap();

    // Build all the rows before entering the DB call so we don't need to
    // cross an await boundary inside the transaction closure.
    struct AuthzPlan {
        authz_id: String,
        identifier_json: String,
        wildcard: bool,
        subdomain_auth_allowed: bool,
        challenges: Vec<(String, String)>, // (challenge_id, type)
        token: String,
    }

    let mut authz_plans: Vec<AuthzPlan> = Vec::new();
    let mut authz_urls: Vec<String> = Vec::new();

    for id in &payload.identifiers {
        let authz_id = uuid::Uuid::new_v4().to_string();
        // When ancestorDomain is set, issue the authz against the ancestor domain
        // and mark it subdomainAuthAllowed; the proof is for the ancestor, not
        // the exact subdomain.
        let (authz_type, authz_value, subdomain_auth_allowed) =
            if let Some(ref ancestor) = id.ancestor_domain {
                (id.r#type.as_str(), ancestor.as_str(), true)
            } else {
                (id.r#type.as_str(), id.value.as_str(), false)
            };
        let identifier_json =
            serde_json::to_string(&json!({"type": authz_type, "value": authz_value})).unwrap();
        let token = gen_token();
        // dns-persist-01 is offered only when the operator has explicitly configured
        // an issuer domain — without it the challenge cannot be validated.
        let dns_persist_enabled = state.config.server.dns_persist_issuer_domain.is_some();
        let dns_types: &[&str] = if dns_persist_enabled {
            &["http-01", "dns-01", "tls-alpn-01", "dns-persist-01"]
        } else {
            &["http-01", "dns-01", "tls-alpn-01"]
        };
        let challenge_types: &[&str] = match authz_type {
            "dns" => dns_types,
            "ip" => &["http-01", "tls-alpn-01"],
            _ => &[],
        };
        let challenges = challenge_types
            .iter()
            .map(|&t| (uuid::Uuid::new_v4().to_string(), t.to_string()))
            .collect();
        authz_urls.push(format!("{}/acme/authz/{}", state.config.base_url, authz_id));
        authz_plans.push(AuthzPlan {
            authz_id,
            identifier_json,
            wildcard: authz_value.starts_with("*."),
            subdomain_auth_allowed,
            challenges,
            token,
        });
    }

    // Write everything inside a single transaction so a partial failure
    // cannot leave orphaned orders, authorizations, or challenges.
    {
        let order_id_clone = order_id.clone();
        let account_id_clone = account_id.clone();
        let replaces_clone = validated_replaces.clone();
        let identifiers_json_clone = identifiers_json.clone();
        state
            .db
            .call(move |conn| {
                let tx = conn.transaction()?;
                tx.prepare_cached(
                    "INSERT INTO orders
                     (id, account_id, status, expires, identifiers,
                      not_before, not_after, error, certificate_id, replaces, created, updated)
                     VALUES (?1, ?2, 'pending', ?3, ?4, NULL, NULL, NULL, NULL, ?5, ?6, ?6)",
                )?
                .execute(rusqlite::params![
                    order_id_clone,
                    account_id_clone,
                    expiry,
                    identifiers_json_clone,
                    replaces_clone,
                    now
                ])?;
                for plan in &authz_plans {
                    tx.prepare_cached(
                        "INSERT INTO authorizations
                         (id, order_id, account_id, status, identifier, expires,
                          wildcard, subdomain_auth_allowed, created, updated)
                         VALUES (?1, ?2, ?3, 'pending', ?4, ?5, ?6, ?7, ?8, ?8)",
                    )?
                    .execute(rusqlite::params![
                        plan.authz_id,
                        order_id_clone,
                        account_id_clone,
                        plan.identifier_json,
                        authz_expiry,
                        plan.wildcard as i64,
                        plan.subdomain_auth_allowed as i64,
                        now
                    ])?;
                    for (chall_id, chall_type) in &plan.challenges {
                        tx.prepare_cached(
                            "INSERT INTO challenges
                             (id, authz_id, type, status, token, validated,
                              error, created, updated)
                             VALUES (?1, ?2, ?3, 'pending', ?4, NULL, NULL, ?5, ?5)",
                        )?
                        .execute(rusqlite::params![
                            chall_id,
                            plan.authz_id,
                            chall_type,
                            plan.token,
                            now
                        ])?;
                    }
                }
                tx.commit()?;
                Ok(())
            })
            .await
            .map_err(AcmeError::from)?;
    }

    let base = &state.config.base_url;
    // Build a temporary OrderRow so we can reuse order_json() and get replaces for free.
    let new_order_row = OrderRow {
        id: order_id.clone(),
        account_id: account_id.clone(),
        status: "pending".to_string(),
        expires: Some(expiry),
        identifiers: identifiers_json.clone(),
        not_before: None,
        not_after: None,
        error: None,
        certificate_id: None,
        replaces: validated_replaces,
        created: now,
        updated: now,
    };
    let mut resp = json_response(
        &state,
        StatusCode::CREATED,
        order_json(&new_order_row, &authz_urls, base),
        &ctx.next_nonce,
    )?;
    resp.headers_mut().insert(
        axum::http::header::LOCATION,
        format!("{base}/acme/order/{order_id}").parse().unwrap(),
    );
    Ok(resp)
}

pub async fn get_order(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    body: Bytes,
) -> Result<Response, AcmeError> {
    let url = format!("{}/acme/order/{}", state.config.base_url, id);
    let ctx = parse_jws(&state, body, &url).await?;

    let account_id = ctx
        .account_id
        .ok_or(AcmeError::Unauthorized("kid required".into()))?;

    // Fetch order and its authz IDs in one DB call.
    let (order, authz_ids) = db::orders::get_with_authz_ids(&state.db, &id)
        .await?
        .ok_or(AcmeError::NotFound)?;
    if order.account_id != account_id {
        return Err(AcmeError::Unauthorized(
            "order belongs to different account".into(),
        ));
    }

    let authz_urls: Vec<_> = authz_ids
        .iter()
        .map(|aid| format!("{}/acme/authz/{}", state.config.base_url, aid))
        .collect();

    json_response(
        &state,
        StatusCode::OK,
        order_json(&order, &authz_urls, &state.config.base_url),
        &ctx.next_nonce,
    )
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Typed ACME order response body. Using `Box<RawValue>` for `identifiers`
/// avoids the `serde_json::from_str` parse + `Vec<Value>` / `HashMap`
/// allocations that the old `json!` macro approach required. The identifiers
/// JSON string stored in the DB is embedded directly into the response without
/// being re-parsed.
#[derive(Serialize)]
pub(crate) struct OrderJson<'a> {
    status: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    expires: Option<String>,
    identifiers: Box<serde_json::value::RawValue>,
    authorizations: &'a [String],
    finalize: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    certificate: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<Box<serde_json::value::RawValue>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    replaces: Option<&'a str>,
}

pub(crate) fn order_json<'a>(
    order: &'a OrderRow,
    authz_urls: &'a [String],
    base_url: &str,
) -> OrderJson<'a> {
    // Embed identifiers as raw JSON — no parse, no Vec<Value>/HashMap allocs.
    // The stored string is always valid JSON (written by serde_json::to_string).
    let identifiers = serde_json::value::RawValue::from_string(order.identifiers.clone())
        .unwrap_or_else(|_| serde_json::value::RawValue::from_string("[]".to_string()).unwrap());
    // Same for error: embed raw JSON if present; skip if None or unparseable.
    let error = order
        .error
        .as_deref()
        .and_then(|s| serde_json::value::RawValue::from_string(s.to_string()).ok());
    OrderJson {
        status: &order.status,
        expires: order.expires.map(fmt_time),
        identifiers,
        authorizations: authz_urls,
        finalize: format!("{base_url}/acme/order/{}/finalize", order.id),
        certificate: if order.status == "valid" {
            order
                .certificate_id
                .as_ref()
                .map(|c| format!("{base_url}/acme/cert/{c}"))
        } else {
            None
        },
        error,
        replaces: order.replaces.as_deref(),
    }
}

fn gen_token() -> String {
    let mut bytes = [0u8; 32];
    getrandom::getrandom(&mut bytes).unwrap_or(());
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    URL_SAFE_NO_PAD.encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_order(
        status: &str,
        expires: Option<i64>,
        cert_id: Option<&str>,
        error: Option<&str>,
    ) -> OrderRow {
        OrderRow {
            id: "order-1".to_string(),
            account_id: "acct-1".to_string(),
            status: status.to_string(),
            expires,
            identifiers: "[{\"type\":\"dns\",\"value\":\"example.com\"}]".to_string(),
            not_before: None,
            not_after: None,
            error: error.map(|s| s.to_string()),
            certificate_id: cert_id.map(|s| s.to_string()),
            replaces: None,
            created: 1_700_000_000,
            updated: 1_700_000_000,
        }
    }

    // Helper: serialize the typed OrderJson to a serde_json::Value for assertions.
    fn to_val<'a>(j: OrderJson<'a>) -> serde_json::Value {
        serde_json::to_value(j).unwrap()
    }

    #[test]
    fn order_json_pending_order() {
        let order = make_order("pending", Some(1_700_100_000), None, None);
        let json = to_val(order_json(
            &order,
            &["https://acme.test/acme/authz/a".to_string()],
            "https://acme.test",
        ));
        assert_eq!(json["status"], "pending");
        assert!(json["expires"].as_str().is_some());
        assert!(json["certificate"].is_null() || json.get("certificate").is_none());
        assert!(json["finalize"].as_str().unwrap().contains("order-1"));
    }

    #[test]
    fn order_json_valid_order_includes_certificate() {
        let order = make_order("valid", None, Some("cert-abc"), None);
        let json = to_val(order_json(&order, &[], "https://acme.test"));
        assert_eq!(json["status"], "valid");
        assert!(json["certificate"].as_str().unwrap().contains("cert-abc"));
    }

    #[test]
    fn order_json_invalid_order_includes_error() {
        let order = make_order(
            "invalid",
            None,
            None,
            Some("{\"type\":\"urn:ietf:params:acme:error:connection\",\"detail\":\"failed\"}"),
        );
        let json = to_val(order_json(&order, &[], "https://acme.test"));
        assert_eq!(json["status"], "invalid");
        assert_eq!(
            json["error"]["type"],
            "urn:ietf:params:acme:error:connection"
        );
    }

    #[test]
    fn order_json_no_expires_when_none() {
        let order = make_order("ready", None, None, None);
        let json = to_val(order_json(&order, &[], "https://acme.test"));
        assert!(json.get("expires").is_none() || json["expires"].is_null());
    }

    #[test]
    fn order_json_valid_status_without_cert_no_certificate_field() {
        // valid status but no certificate_id → no "certificate" field
        let order = make_order("valid", None, None, None);
        let json = to_val(order_json(&order, &[], "https://acme.test"));
        // either missing or null
        assert!(json.get("certificate").map_or(true, |v| v.is_null()));
    }

    #[test]
    fn order_json_with_replaces_includes_field() {
        let mut order = make_order("pending", None, None, None);
        order.replaces = Some("akiABC.serialXYZ".to_string());
        let json = to_val(order_json(&order, &[], "https://acme.test"));
        assert_eq!(json["replaces"], "akiABC.serialXYZ");
    }

    #[test]
    fn order_json_without_replaces_omits_field() {
        let order = make_order("pending", None, None, None);
        let json = to_val(order_json(&order, &[], "https://acme.test"));
        assert!(json.get("replaces").map_or(true, |v| v.is_null()));
    }

    #[test]
    fn gen_token_returns_non_empty_string() {
        let t = gen_token();
        assert!(!t.is_empty());
        // Should be base64url without padding — only alphanumeric, '-', '_'
        assert!(t
            .chars()
            .all(|c| c.is_alphanumeric() || c == '-' || c == '_'));
    }
}
