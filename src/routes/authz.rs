//! POST /acme/authz/{id} — RFC 8555 §7.5

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::Response;
use serde_json::json;

use crate::db;
use crate::error::AcmeError;
use crate::state::AppState;

use super::{fmt_time, json_response, parse_jws};

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
    let chall_jsons: Vec<_> = challenges
        .iter()
        .map(|c| {
            let mut obj = json!({
                "type": c.r#type,
                "url": format!("{base}/acme/chall/{}/{}", authz.id, c.r#type),
                "status": c.status,
            });
            // dns-persist-01 has no per-challenge token; expose the issuer domain instead.
            if c.r#type == "dns-persist-01" {
                obj["issuer-domain-names"] = json!([issuer_domain]);
            } else {
                obj["token"] = json!(c.token);
            }
            if let Some(v) = c.validated {
                obj["validated"] = json!(fmt_time(v));
            }
            if let Some(err) = &c.error {
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(err) {
                    obj["error"] = v;
                }
            }
            obj
        })
        .collect();

    let identifier: serde_json::Value =
        serde_json::from_str(&authz.identifier).unwrap_or(json!({}));

    let mut obj = json!({
        "status": authz.status,
        "identifier": identifier,
        "challenges": chall_jsons,
        "wildcard": authz.wildcard,
    });
    if let Some(exp) = authz.expires {
        obj["expires"] = json!(fmt_time(exp));
    }

    json_response(&state, StatusCode::OK, obj).await
}
