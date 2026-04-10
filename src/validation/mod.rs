//! Background challenge validation — http-01, dns-01, tls-alpn-01.
//!
//! Each call runs inside a `tokio::spawn` and must not panic.
//! After validation the function updates challenge, authorization, and order state.

mod dns01;
mod http01;
mod tls_alpn01;

use std::sync::Arc;

use serde_json::json;

use crate::db;
use crate::error::AcmeError;
use crate::state::AppState;

/// Entry point called from `routes::challenge::respond_challenge`.
///
/// This function is intentionally infallible — all errors are recorded in the
/// database rather than propagated.
pub async fn validate_challenge(
    state: &Arc<AppState>,
    challenge_id: &str,
    authz_id: &str,
    chall_type: &str,
    id_type: &str,
    id_value: &str,
    key_auth: &str,
    token: &str,
) {
    let result = dispatch(chall_type, id_type, id_value, key_auth, token).await;

    let now = unix_now();
    match result {
        Ok(()) => on_valid(state, challenge_id, authz_id, now).await,
        Err(e) => on_invalid(state, challenge_id, authz_id, e, now).await,
    }
}

/// Dispatch to the correct validator based on challenge type.
async fn dispatch(
    chall_type: &str,
    _id_type: &str,
    id_value: &str,
    key_auth: &str,
    token: &str,
) -> Result<(), AcmeError> {
    match chall_type {
        "http-01" => http01::validate(id_value, token, key_auth).await,
        "dns-01" => dns01::validate(id_value, key_auth).await,
        "tls-alpn-01" => tls_alpn01::validate(id_value, key_auth).await,
        other => Err(AcmeError::IncorrectResponse(format!(
            "unsupported challenge type: {other}"
        ))),
    }
}

/// Handle a successful challenge validation.
///
/// 1. Mark challenge as `valid`.
/// 2. Mark the parent authorization as `valid`.
/// 3. If all authorizations for the order are now `valid`, advance the order to `ready`.
async fn on_valid(state: &AppState, challenge_id: &str, authz_id: &str, now: i64) {
    if let Err(e) = db::challenges::set_valid(&state.db, challenge_id, now).await {
        tracing::warn!("challenge {challenge_id}: set_valid failed: {e}");
        return;
    }

    if let Err(e) = db::authz::update_status(&state.db, authz_id, "valid", now).await {
        tracing::warn!("authz {authz_id}: update_status valid failed: {e}");
        return;
    }

    // Find the parent order so we can check whether all authzs are now valid.
    let authz = match db::authz::get_by_id(&state.db, authz_id).await {
        Ok(Some(a)) => a,
        Ok(None) => {
            tracing::warn!("authz {authz_id} not found after validation");
            return;
        }
        Err(e) => {
            tracing::warn!("authz {authz_id}: get_by_id failed: {e}");
            return;
        }
    };

    let order_authzs = match db::authz::list_by_order(&state.db, &authz.order_id).await {
        Ok(list) => list,
        Err(e) => {
            tracing::warn!("order {}: list_by_order failed: {e}", authz.order_id);
            return;
        }
    };

    let all_valid = order_authzs.iter().all(|a| a.status == "valid");
    if all_valid {
        if let Err(e) =
            db::orders::update_status(&state.db, &authz.order_id, "ready", None, now).await
        {
            tracing::warn!("order {}: set ready failed: {e}", authz.order_id);
        } else {
            tracing::info!("order {} is now ready", authz.order_id);
        }
    }
}

/// Handle a failed challenge validation.
///
/// 1. Record the error on the challenge.
/// 2. Mark the authorization as `invalid`.
/// 3. Mark the parent order as `invalid`.
async fn on_invalid(
    state: &AppState,
    challenge_id: &str,
    authz_id: &str,
    err: AcmeError,
    now: i64,
) {
    tracing::info!("challenge {challenge_id} failed: {err}");

    let error_json = json!({
        "type": err_type(&err),
        "detail": err.to_string(),
    })
    .to_string();

    if let Err(e) =
        db::challenges::set_invalid(&state.db, challenge_id, error_json, now).await
    {
        tracing::warn!("challenge {challenge_id}: set_invalid failed: {e}");
    }

    if let Err(e) = db::authz::update_status(&state.db, authz_id, "invalid", now).await {
        tracing::warn!("authz {authz_id}: set invalid failed: {e}");
    }

    // Mark the order invalid too.
    if let Ok(Some(authz)) = db::authz::get_by_id(&state.db, authz_id).await {
        if let Err(e) =
            db::orders::update_status(&state.db, &authz.order_id, "invalid", None, now).await
        {
            tracing::warn!("order {}: set invalid failed: {e}", authz.order_id);
        }
    }
}

fn err_type(e: &AcmeError) -> &'static str {
    match e {
        AcmeError::Connection(_) => "urn:ietf:params:acme:error:connection",
        AcmeError::Dns(_) => "urn:ietf:params:acme:error:dns",
        AcmeError::Tls(_) => "urn:ietf:params:acme:error:tls",
        AcmeError::IncorrectResponse(_) => "urn:ietf:params:acme:error:incorrectResponse",
        _ => "urn:ietf:params:acme:error:serverInternal",
    }
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}
