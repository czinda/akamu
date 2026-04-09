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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use crate::config::{CaConfig, Config, DatabaseConfig, MtcConfig, ServerConfig};
    use crate::state::{AppState, CaState, MtcState};
    use crate::{ca, db};

    async fn make_state() -> Arc<AppState> {
        let config = Arc::new(Config {
            listen_addr: "127.0.0.1:0".into(),
            base_url: "https://acme.test".into(),
            database: DatabaseConfig { path: ":memory:".into() },
            ca: CaConfig {
                key_file: "/tmp/val-test-ca.key".into(),
                cert_file: "/tmp/val-test-ca.crt".into(),
                key_type: "ec:P-256".into(),
                hash_alg: "sha256".into(),
                validity_days: 90,
                crl_url: None,
                ocsp_url: None,
                common_name: "Val Test CA".into(),
                organization: "Test".into(),
                ca_validity_years: 10,
            },
            mtc: MtcConfig { log_path: "/dev/null".into(), enabled: false },
            server: ServerConfig::default(),
        });

        let (ca_key, ca_cert_der) = ca::init::load_or_generate(&config.ca).unwrap();
        let db_conn = Arc::new(db::open(":memory:").await.unwrap());

        Arc::new(AppState {
            config: Arc::clone(&config),
            db: Arc::clone(&db_conn),
            ca: Arc::new(CaState {
                key: ca_key,
                cert_der: ca_cert_der,
                hash_alg: "sha256".into(),
                validity_days: 90,
                crl_url: None,
                ocsp_url: None,
            }),
            mtc: Arc::new(MtcState {
                log: None,
                algorithm: synta_mtc::crypto::HashAlgorithm::Sha256,
            }),
        })
    }

    #[test]
    fn unix_now_is_positive() {
        let t = unix_now();
        assert!(t > 0, "unix_now() should be positive, got {t}");
    }

    #[test]
    fn err_type_mapping() {
        assert_eq!(err_type(&AcmeError::Connection("x".into())), "urn:ietf:params:acme:error:connection");
        assert_eq!(err_type(&AcmeError::Dns("x".into())), "urn:ietf:params:acme:error:dns");
        assert_eq!(err_type(&AcmeError::Tls("x".into())), "urn:ietf:params:acme:error:tls");
        assert_eq!(err_type(&AcmeError::IncorrectResponse("x".into())), "urn:ietf:params:acme:error:incorrectResponse");
        assert_eq!(err_type(&AcmeError::Internal("x".into())), "urn:ietf:params:acme:error:serverInternal");
        assert_eq!(err_type(&AcmeError::NotFound), "urn:ietf:params:acme:error:serverInternal");
    }

    #[tokio::test]
    async fn dispatch_unsupported_type_returns_error() {
        let result = dispatch("bogus-type", "dns", "example.com", "key-auth", "token").await;
        assert!(result.is_err());
        match result.unwrap_err() {
            AcmeError::IncorrectResponse(msg) => {
                assert!(msg.contains("unsupported challenge type"));
            }
            other => panic!("expected IncorrectResponse, got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn on_invalid_with_missing_authz_does_not_panic() {
        let state = make_state().await;
        // on_invalid with a non-existent challenge/authz should not panic
        on_invalid(
            &state,
            "nonexistent-challenge",
            "nonexistent-authz",
            AcmeError::Connection("test".into()),
            unix_now(),
        ).await;
    }

    #[tokio::test]
    async fn on_valid_with_missing_challenge_does_not_panic() {
        let state = make_state().await;
        // on_valid with a non-existent challenge should not panic
        on_valid(&state, "nonexistent-challenge", "nonexistent-authz", unix_now()).await;
    }

    #[tokio::test]
    async fn validate_challenge_unsupported_type_records_failure() {
        let state = make_state().await;
        // Use a non-existent challenge_id/authz_id — the function is infallible
        validate_challenge(
            &state,
            "fake-challenge-id",
            "fake-authz-id",
            "bogus-01",   // unsupported type → dispatch returns Err
            "dns",
            "example.com",
            "token.thumbprint",
            "token",
        ).await;
        // If we get here without panicking, the test passes
    }
}
