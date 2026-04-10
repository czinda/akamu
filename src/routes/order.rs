//! POST /acme/new-order, POST /acme/order/{id} — RFC 8555 §7.4

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::Response;
use serde::Deserialize;
use serde_json::json;

use crate::db;
use crate::db::schema::OrderRow;
use crate::error::AcmeError;
use crate::state::AppState;

use super::{fmt_time, json_response, parse_jws, require_payload, unix_now};

#[derive(Deserialize)]
struct Identifier {
    r#type: String,
    value: String,
}

#[derive(Deserialize)]
struct NewOrderPayload {
    identifiers: Vec<Identifier>,
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
    }

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
        challenges: Vec<(String, String)>, // (challenge_id, type)
        token: String,
    }

    let mut authz_plans: Vec<AuthzPlan> = Vec::new();
    let mut authz_urls: Vec<String> = Vec::new();

    for id in &payload.identifiers {
        let authz_id = uuid::Uuid::new_v4().to_string();
        let identifier_json =
            serde_json::to_string(&json!({"type": id.r#type, "value": id.value})).unwrap();
        let token = gen_token();
        // dns-persist-01 is offered only when the operator has explicitly configured
        // an issuer domain — without it the challenge cannot be validated.
        let dns_persist_enabled = state.config.server.dns_persist_issuer_domain.is_some();
        let dns_types: &[&str] = if dns_persist_enabled {
            &["http-01", "dns-01", "tls-alpn-01", "dns-persist-01"]
        } else {
            &["http-01", "dns-01", "tls-alpn-01"]
        };
        let challenge_types: &[&str] = match id.r#type.as_str() {
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
            wildcard: id.value.starts_with("*."),
            challenges,
            token,
        });
    }

    // Write everything inside a single transaction so a partial failure
    // cannot leave orphaned orders, authorizations, or challenges.
    {
        let order_id_clone = order_id.clone();
        let account_id_clone = account_id.clone();
        state
            .db
            .call(move |conn| {
                let tx = conn.transaction()?;
                tx.prepare_cached(
                    "INSERT INTO orders
                     (id, account_id, status, expires, identifiers,
                      not_before, not_after, error, certificate_id, created, updated)
                     VALUES (?1, ?2, 'pending', ?3, ?4, NULL, NULL, NULL, NULL, ?5, ?5)",
                )?
                .execute(rusqlite::params![
                    order_id_clone,
                    account_id_clone,
                    expiry,
                    identifiers_json,
                    now
                ])?;
                for plan in &authz_plans {
                    tx.prepare_cached(
                        "INSERT INTO authorizations
                         (id, order_id, account_id, status, identifier, expires,
                          wildcard, created, updated)
                         VALUES (?1, ?2, ?3, 'pending', ?4, ?5, ?6, ?7, ?7)",
                    )?
                    .execute(rusqlite::params![
                        plan.authz_id,
                        order_id_clone,
                        account_id_clone,
                        plan.identifier_json,
                        authz_expiry,
                        plan.wildcard as i64,
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
    let order_json = json!({
        "status": "pending",
        "expires": fmt_time(expiry),
        "identifiers": payload.identifiers.iter().map(|id| {
            json!({"type": id.r#type, "value": id.value})
        }).collect::<Vec<_>>(),
        "authorizations": authz_urls,
        "finalize": format!("{base}/acme/order/{order_id}/finalize"),
    });

    let mut resp = json_response(&state, StatusCode::CREATED, order_json, &ctx.next_nonce)?;
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

pub(crate) fn order_json(
    order: &OrderRow,
    authz_urls: &[String],
    base_url: &str,
) -> serde_json::Value {
    let identifiers: Vec<serde_json::Value> =
        serde_json::from_str(&order.identifiers).unwrap_or_default();
    let mut obj = json!({
        "status": order.status,
        "identifiers": identifiers,
        "authorizations": authz_urls,
        "finalize": format!("{base_url}/acme/order/{}/finalize", order.id),
    });
    if let Some(exp) = order.expires {
        obj["expires"] = json!(fmt_time(exp));
    }
    if order.status == "valid" {
        if let Some(cert_id) = &order.certificate_id {
            obj["certificate"] = json!(format!("{base_url}/acme/cert/{cert_id}"));
        }
    }
    if let Some(err) = &order.error {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(err) {
            obj["error"] = v;
        }
    }
    obj
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
            created: 1_700_000_000,
            updated: 1_700_000_000,
        }
    }

    #[test]
    fn order_json_pending_order() {
        let order = make_order("pending", Some(1_700_100_000), None, None);
        let json = order_json(
            &order,
            &["https://acme.test/acme/authz/a".to_string()],
            "https://acme.test",
        );
        assert_eq!(json["status"], "pending");
        assert!(json["expires"].as_str().is_some());
        assert!(json["certificate"].is_null() || json.get("certificate").is_none());
        assert!(json["finalize"].as_str().unwrap().contains("order-1"));
    }

    #[test]
    fn order_json_valid_order_includes_certificate() {
        let order = make_order("valid", None, Some("cert-abc"), None);
        let json = order_json(&order, &[], "https://acme.test");
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
        let json = order_json(&order, &[], "https://acme.test");
        assert_eq!(json["status"], "invalid");
        assert_eq!(
            json["error"]["type"],
            "urn:ietf:params:acme:error:connection"
        );
    }

    #[test]
    fn order_json_no_expires_when_none() {
        let order = make_order("ready", None, None, None);
        let json = order_json(&order, &[], "https://acme.test");
        assert!(json.get("expires").is_none() || json["expires"].is_null());
    }

    #[test]
    fn order_json_valid_status_without_cert_no_certificate_field() {
        // valid status but no certificate_id → no "certificate" field
        let order = make_order("valid", None, None, None);
        let json = order_json(&order, &[], "https://acme.test");
        // either missing or null
        assert!(json.get("certificate").map_or(true, |v| v.is_null()));
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
