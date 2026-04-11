//! POST /acme/authz/{id} — RFC 8555 §7.5

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::Response;
use serde::Serialize;

use crate::db;
use crate::error::AcmeError;
use crate::state::AppState;

use super::{fmt_time, json_response, parse_jws};

fn is_false(b: &bool) -> bool {
    !b
}

/// Typed challenge entry in the authz response.
///
/// Borrows `type` and `status` from `ChallengeRow`; `token` is borrowed for
/// non-dns-persist-01 challenges. `issuer_domain_names` is only populated
/// for dns-persist-01 (one allocation per authz at most).
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
    #[serde(skip_serializing_if = "Option::is_none")]
    validated: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<Box<serde_json::value::RawValue>>,
}

/// Typed authorization response body.
///
/// `identifier` is embedded as raw JSON (no re-parse from the stored string).
/// `wildcard` is omitted when false.
#[derive(Serialize)]
struct AuthzJson<'a> {
    status: &'a str,
    identifier: Box<serde_json::value::RawValue>,
    challenges: Vec<ChallengeJson<'a>>,
    #[serde(skip_serializing_if = "is_false")]
    wildcard: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    expires: Option<String>,
}

pub async fn get_authz(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    body: Bytes,
) -> Result<Response, AcmeError> {
    let url = format!("{}/acme/authz/{}", state.config.base_url, id);
    let ctx = parse_jws(&state, body, &url).await?;

    let account_id = ctx
        .account_id
        .ok_or(AcmeError::Unauthorized("kid required".into()))?;

    let (authz, challenges) = db::authz::get_with_challenges(&state.db, &id)
        .await?
        .ok_or(AcmeError::NotFound)?;
    if authz.account_id != account_id {
        return Err(AcmeError::Unauthorized(
            "authorization belongs to different account".into(),
        ));
    }
    let base = &state.config.base_url;
    let issuer_domain = state.config.dns_persist_issuer_domain();

    let challs: Vec<ChallengeJson<'_>> = challenges
        .iter()
        .map(|c| {
            // dns-persist-01 exposes the issuer domain instead of a per-challenge token.
            let (token, issuer_domain_names) = if c.r#type == "dns-persist-01" {
                (None, Some(vec![issuer_domain.to_string()]))
            } else {
                (Some(c.token.as_str()), None)
            };
            ChallengeJson {
                r#type: &c.r#type,
                url: format!("{base}/acme/chall/{}/{}", authz.id, c.r#type),
                status: &c.status,
                token,
                issuer_domain_names,
                validated: c.validated.map(fmt_time),
                error: c
                    .error
                    .as_deref()
                    .and_then(|s| serde_json::value::RawValue::from_string(s.to_string()).ok()),
            }
        })
        .collect();

    // Embed identifier as raw JSON — no parse, no HashMap alloc.
    let identifier = serde_json::value::RawValue::from_string(authz.identifier.clone())
        .unwrap_or_else(|_| serde_json::value::RawValue::from_string("{}".to_string()).unwrap());

    let body = AuthzJson {
        status: &authz.status,
        identifier,
        challenges: challs,
        wildcard: authz.wildcard,
        expires: authz.expires.map(fmt_time),
    };

    json_response(&state, StatusCode::OK, body, &ctx.next_nonce)
}
