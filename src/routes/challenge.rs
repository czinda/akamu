//! POST /acme/chall/{authz_id}/{type} — RFC 8555 §7.5.1

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::Response;
use serde_json::json;

use crate::db;
use crate::error::AcmeError;
use crate::state::AppState;
use crate::validation;

use super::{fmt_time, json_response, parse_jws, unix_now};

pub async fn respond_challenge(
    State(state): State<Arc<AppState>>,
    Path((authz_id, chall_type)): Path<(String, String)>,
    body: Bytes,
) -> Result<Response, AcmeError> {
    let url = format!(
        "{}/acme/chall/{}/{}",
        state.config.base_url, authz_id, chall_type
    );
    let ctx = parse_jws(&state, body, &url).await?;

    let account_id = ctx.account_id.ok_or(AcmeError::Unauthorized("kid required".into()))?;

    // Load the authorization.
    let authz = db::authz::get_by_id(&state.db, &authz_id)
        .await?
        .ok_or(AcmeError::NotFound)?;
    if authz.account_id != account_id {
        return Err(AcmeError::Unauthorized("authorization belongs to different account".into()));
    }
    if authz.status != "pending" {
        return Err(AcmeError::BadRequest(format!(
            "authorization status is '{}', expected 'pending'",
            authz.status
        )));
    }

    // Find the specific challenge.
    let challenges = db::challenges::list_by_authz(&state.db, &authz_id).await?;
    let challenge = challenges
        .into_iter()
        .find(|c| c.r#type == chall_type)
        .ok_or(AcmeError::NotFound)?;

    if challenge.status != "pending" {
        // Already processing or completed; just return current state.
        return challenge_response(&state, &challenge).await;
    }

    // Mark challenge as processing.
    db::challenges::set_processing(&state.db, &challenge.id, unix_now()).await?;

    // Extract identifier.
    let identifier: serde_json::Value =
        serde_json::from_str(&authz.identifier).unwrap_or(json!({}));
    let id_type = identifier["type"].as_str().unwrap_or("").to_string();
    let id_value = identifier["value"].as_str().unwrap_or("").to_string();

    // Compute key authorization (token + "." + JWK thumbprint).
    let account = db::accounts::get_by_id(&state.db, &account_id)
        .await?
        .ok_or(AcmeError::Unauthorized("account not found".into()))?;

    let jwk_thumbprint = account.jwk_thumbprint.clone();
    let key_auth = format!("{}.{}", challenge.token, jwk_thumbprint);

    // Spawn background validation task.
    let state_clone = Arc::clone(&state);
    let challenge_id = challenge.id.clone();
    let token = challenge.token.clone();
    let chall_type_clone = chall_type.clone();
    let authz_id_clone = authz_id.clone();

    tokio::spawn(async move {
        validation::validate_challenge(
            &state_clone,
            &challenge_id,
            &authz_id_clone,
            &chall_type_clone,
            &id_type,
            &id_value,
            &key_auth,
            &token,
        )
        .await;
    });

    // Return immediately with processing state.
    let mut updated = challenge.clone();
    updated.status = "processing".into();
    challenge_response(&state, &updated).await
}

async fn challenge_response(
    state: &AppState,
    challenge: &crate::db::schema::ChallengeRow,
) -> Result<Response, AcmeError> {
    let base = &state.config.base_url;
    let mut obj = json!({
        "type": challenge.r#type,
        "url": format!("{base}/acme/chall/{}/{}", challenge.authz_id, challenge.r#type),
        "status": challenge.status,
        "token": challenge.token,
    });
    if let Some(v) = challenge.validated {
        obj["validated"] = json!(fmt_time(v));
    }
    if let Some(err) = &challenge.error {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(err) {
            obj["error"] = v;
        }
    }
    json_response(state, StatusCode::OK, obj).await
}
