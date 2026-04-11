//! Background challenge validation — http-01, dns-01, tls-alpn-01.
//!
//! Each call runs inside a `tokio::spawn` and must not panic.
//! After validation the function updates challenge, authorization, and order state.

mod dns01;
mod dns_persist_01;
mod http01;
mod tls_alpn01;

use std::sync::Arc;

use rusqlite::OptionalExtension;
use serde_json::json;

use crate::error::AcmeError;
use crate::state::AppState;

/// Entry point called from `routes::challenge::respond_challenge`.
///
/// This function is intentionally infallible — all errors are recorded in the
/// database rather than propagated.
#[allow(clippy::too_many_arguments)]
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
    let http_port = state.config.server.http_validation_port;
    let issuer_domain = state.config.dns_persist_issuer_domain();
    let dns_resolver_addr = state
        .config
        .server
        .dns_resolver_addr
        .as_deref()
        .and_then(|s| s.parse::<std::net::SocketAddr>().ok());
    let result = dispatch(
        chall_type,
        id_type,
        id_value,
        key_auth,
        token,
        http_port,
        &issuer_domain,
        dns_resolver_addr,
        &state.validation_client,
    )
    .await;

    let now = unix_now();
    match result {
        Ok(()) => on_valid(state, challenge_id, authz_id, now).await,
        Err(e) => on_invalid(state, challenge_id, authz_id, e, now).await,
    }
}

/// Dispatch to the correct validator based on challenge type.
///
/// For `dns-persist-01`, `key_auth` carries the account URI (not a token·thumbprint).
#[allow(clippy::too_many_arguments)]
async fn dispatch(
    chall_type: &str,
    _id_type: &str,
    id_value: &str,
    key_auth: &str,
    token: &str,
    http_port: u16,
    issuer_domain: &str,
    dns_resolver_addr: Option<std::net::SocketAddr>,
    validation_client: &crate::state::ValidationClient,
) -> Result<(), AcmeError> {
    match chall_type {
        "http-01" => {
            http01::validate(id_value, token, key_auth, http_port, validation_client).await
        }
        "dns-01" => dns01::validate(id_value, key_auth).await,
        "tls-alpn-01" => tls_alpn01::validate(id_value, key_auth).await,
        "dns-persist-01" => {
            dns_persist_01::validate(id_value, key_auth, issuer_domain, dns_resolver_addr).await
        }
        other => Err(AcmeError::IncorrectResponse(format!(
            "unsupported challenge type: {other}"
        ))),
    }
}

/// Handle a successful challenge validation.
///
/// All state transitions (challenge → authz → order) run inside a single
/// SQLite transaction so a partial failure cannot leave the DB inconsistent.
///
/// 1. Mark challenge as `valid`.
/// 2. Mark the parent authorization as `valid`.
/// 3. If all authorizations for the order are now `valid`, advance the order to `ready`.
async fn on_valid(state: &AppState, challenge_id: &str, authz_id: &str, now: i64) {
    let challenge_id = challenge_id.to_string();
    let authz_id = authz_id.to_string();
    let authz_id_log = authz_id.clone();

    let result = state
        .db
        .call(move |conn| {
            let tx = conn.transaction()?;

            // 1. Mark challenge valid.
            tx.prepare_cached(
                "UPDATE challenges SET status = 'valid', validated = ?1, updated = ?1 WHERE id = ?2",
            )?
            .execute(rusqlite::params![now, challenge_id])?;

            // 2. Mark authorization valid.
            tx.prepare_cached(
                "UPDATE authorizations SET status = 'valid', updated = ?1 WHERE id = ?2",
            )?
            .execute(rusqlite::params![now, authz_id])?;

            // 3. Find the parent order_id.
            let order_id: Option<String> = {
                let mut stmt = tx.prepare_cached(
                    "SELECT order_id FROM authorizations WHERE id = ?1",
                )?;
                stmt.query_row(rusqlite::params![authz_id], |row| row.get(0))
                    .optional()?
            };

            let order_id = match order_id {
                Some(id) => id,
                None => {
                    // Authz disappeared (shouldn't happen, but be safe).
                    tx.commit()?;
                    return Ok(None);
                }
            };

            // 4. Check whether all authzs for this order are now valid.
            let pending_count: i64 = {
                let mut stmt = tx.prepare_cached(
                    "SELECT COUNT(*) FROM authorizations WHERE order_id = ?1 AND status != 'valid'",
                )?;
                stmt.query_row(rusqlite::params![order_id], |row| row.get(0))?
            };

            let all_valid = pending_count == 0;
            if all_valid {
                tx.prepare_cached(
                    "UPDATE orders SET status = 'ready', error = NULL, updated = ?1 WHERE id = ?2",
                )?
                .execute(rusqlite::params![now, order_id])?;
            }

            tx.commit()?;
            Ok(Some((order_id, all_valid)))
        })
        .await;

    match result {
        Ok(Some((order_id, true))) => {
            tracing::info!("order {order_id} is now ready");
        }
        Ok(_) => {}
        Err(e) => {
            tracing::warn!("authz {authz_id_log}: on_valid transaction failed: {e}");
        }
    }
}

/// Handle a failed challenge validation.
///
/// 1. Record the error on the challenge.
/// 2. Mark the authorization as `invalid`.
/// 3. Mark the parent order as `invalid`.
///
/// All three state transitions run inside a single SQLite transaction so a
/// partial failure cannot leave challenge valid while authz/order stays pending.
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

    let challenge_id = challenge_id.to_string();
    let authz_id = authz_id.to_string();
    let authz_id_log = authz_id.clone();

    let result = state
        .db
        .call(move |conn| {
            let tx = conn.transaction()?;

            // 1. Mark challenge invalid with the error detail.
            tx.prepare_cached(
                "UPDATE challenges SET status = 'invalid', error = ?1, updated = ?2 WHERE id = ?3",
            )?
            .execute(rusqlite::params![error_json, now, challenge_id])?;

            // 2. Mark authorization invalid.
            tx.prepare_cached(
                "UPDATE authorizations SET status = 'invalid', updated = ?1 WHERE id = ?2",
            )?
            .execute(rusqlite::params![now, authz_id])?;

            // 3. Find the parent order_id and mark it invalid.
            let order_id: Option<String> = {
                let mut stmt = tx.prepare_cached(
                    "SELECT order_id FROM authorizations WHERE id = ?1",
                )?;
                stmt.query_row(rusqlite::params![authz_id], |row| row.get(0))
                    .optional()?
            };

            if let Some(oid) = order_id {
                tx.prepare_cached(
                    "UPDATE orders SET status = 'invalid', error = NULL, updated = ?1 WHERE id = ?2",
                )?
                .execute(rusqlite::params![now, oid])?;
            }

            tx.commit()?;
            Ok(())
        })
        .await;

    if let Err(e) = result {
        tracing::warn!("authz {authz_id_log}: on_invalid transaction failed: {e}");
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
            database: DatabaseConfig {
                path: ":memory:".into(),
            },
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
            mtc: MtcConfig {
                log_path: "/dev/null".into(),
                enabled: false,
            },
            server: ServerConfig::default(),
            tls: Default::default(),
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
            tls: None,
            spki_cache: Arc::new(std::sync::RwLock::new(std::collections::HashMap::new())),
            link_header: Arc::new(axum::http::HeaderValue::from_static(
                "<https://acme.test/acme/directory>;rel=\"index\"",
            )),
            validation_client: hyper_util::client::legacy::Client::builder(
                hyper_util::rt::TokioExecutor::new(),
            )
            .build_http::<http_body_util::Empty<hyper::body::Bytes>>(),
        })
    }

    #[test]
    fn unix_now_is_positive() {
        let t = unix_now();
        assert!(t > 0, "unix_now() should be positive, got {t}");
    }

    #[test]
    fn err_type_mapping() {
        assert_eq!(
            err_type(&AcmeError::Connection("x".into())),
            "urn:ietf:params:acme:error:connection"
        );
        assert_eq!(
            err_type(&AcmeError::Dns("x".into())),
            "urn:ietf:params:acme:error:dns"
        );
        assert_eq!(
            err_type(&AcmeError::Tls("x".into())),
            "urn:ietf:params:acme:error:tls"
        );
        assert_eq!(
            err_type(&AcmeError::IncorrectResponse("x".into())),
            "urn:ietf:params:acme:error:incorrectResponse"
        );
        assert_eq!(
            err_type(&AcmeError::Internal("x".into())),
            "urn:ietf:params:acme:error:serverInternal"
        );
        assert_eq!(
            err_type(&AcmeError::NotFound),
            "urn:ietf:params:acme:error:serverInternal"
        );
    }

    #[tokio::test]
    async fn dispatch_unsupported_type_returns_error() {
        let client =
            hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
                .build_http::<http_body_util::Empty<hyper::body::Bytes>>();
        let result = dispatch(
            "bogus-type",
            "dns",
            "example.com",
            "key-auth",
            "token",
            80,
            "acme.test",
            None,
            &client,
        )
        .await;
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
        )
        .await;
    }

    #[tokio::test]
    async fn on_valid_with_missing_challenge_does_not_panic() {
        let state = make_state().await;
        // on_valid with a non-existent challenge should not panic
        on_valid(
            &state,
            "nonexistent-challenge",
            "nonexistent-authz",
            unix_now(),
        )
        .await;
    }

    #[tokio::test]
    async fn validate_challenge_unsupported_type_records_failure() {
        let state = make_state().await;
        // Use a non-existent challenge_id/authz_id — the function is infallible
        validate_challenge(
            &state,
            "fake-challenge-id",
            "fake-authz-id",
            "bogus-01", // unsupported type → dispatch returns Err
            "dns",
            "example.com",
            "token.thumbprint",
            "token",
        )
        .await;
        // If we get here without panicking, the test passes
    }

    #[tokio::test]
    async fn on_valid_with_real_rows_updates_db() {
        use crate::db;
        use crate::db::schema::{AccountRow, AuthorizationRow, ChallengeRow, OrderRow};

        let state = make_state().await;
        let now = unix_now();

        let acc_id = "acc-val-001".to_string();
        let order_id = "ord-val-001".to_string();
        let authz_id = "authz-val-001".to_string();
        let chall_id = "chall-val-001".to_string();

        db::accounts::insert(
            &state.db,
            AccountRow {
                id: acc_id.clone(),
                status: "valid".to_string(),
                contact: None,
                public_key: vec![0u8; 4],
                jwk_thumbprint: "thumb-val-001".to_string(),
                created: now,
                updated: now,
            },
        )
        .await
        .unwrap();

        db::orders::insert(
            &state.db,
            OrderRow {
                id: order_id.clone(),
                account_id: acc_id.clone(),
                status: "pending".to_string(),
                expires: Some(now + 3600),
                identifiers: r#"[{"type":"dns","value":"example.com"}]"#.to_string(),
                not_before: None,
                not_after: None,
                error: None,
                certificate_id: None,
                replaces: None,
                created: now,
                updated: now,
            },
        )
        .await
        .unwrap();

        db::authz::insert(
            &state.db,
            AuthorizationRow {
                id: authz_id.clone(),
                order_id: order_id.clone(),
                account_id: acc_id.clone(),
                status: "pending".to_string(),
                identifier: r#"{"type":"dns","value":"example.com"}"#.to_string(),
                expires: Some(now + 3600),
                wildcard: false,
                created: now,
                updated: now,
            },
        )
        .await
        .unwrap();

        db::challenges::insert(
            &state.db,
            ChallengeRow {
                id: chall_id.clone(),
                authz_id: authz_id.clone(),
                r#type: "http-01".to_string(),
                status: "pending".to_string(),
                token: "mytoken".to_string(),
                validated: None,
                error: None,
                created: now,
                updated: now,
            },
        )
        .await
        .unwrap();

        // Call on_valid — should update challenge, authz, and order status.
        on_valid(&state, &chall_id, &authz_id, now).await;

        let chall = db::challenges::get_by_id(&state.db, &chall_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(chall.status, "valid");

        let authz = db::authz::get_by_id(&state.db, &authz_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(authz.status, "valid");

        // Single authz now valid → order → ready.
        let order = db::orders::get_by_id(&state.db, &order_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(order.status, "ready");
    }

    #[tokio::test]
    async fn on_invalid_with_real_rows_marks_invalid() {
        use crate::db;
        use crate::db::schema::{AccountRow, AuthorizationRow, ChallengeRow, OrderRow};

        let state = make_state().await;
        let now = unix_now();

        let acc_id = "acc-inv-001".to_string();
        let order_id = "ord-inv-001".to_string();
        let authz_id = "authz-inv-001".to_string();
        let chall_id = "chall-inv-001".to_string();

        db::accounts::insert(
            &state.db,
            AccountRow {
                id: acc_id.clone(),
                status: "valid".to_string(),
                contact: None,
                public_key: vec![0u8; 4],
                jwk_thumbprint: "thumb-inv-001".to_string(),
                created: now,
                updated: now,
            },
        )
        .await
        .unwrap();

        db::orders::insert(
            &state.db,
            OrderRow {
                id: order_id.clone(),
                account_id: acc_id.clone(),
                status: "pending".to_string(),
                expires: Some(now + 3600),
                identifiers: r#"[{"type":"dns","value":"example.com"}]"#.to_string(),
                not_before: None,
                not_after: None,
                error: None,
                certificate_id: None,
                replaces: None,
                created: now,
                updated: now,
            },
        )
        .await
        .unwrap();

        db::authz::insert(
            &state.db,
            AuthorizationRow {
                id: authz_id.clone(),
                order_id: order_id.clone(),
                account_id: acc_id.clone(),
                status: "pending".to_string(),
                identifier: r#"{"type":"dns","value":"example.com"}"#.to_string(),
                expires: Some(now + 3600),
                wildcard: false,
                created: now,
                updated: now,
            },
        )
        .await
        .unwrap();

        db::challenges::insert(
            &state.db,
            ChallengeRow {
                id: chall_id.clone(),
                authz_id: authz_id.clone(),
                r#type: "http-01".to_string(),
                status: "pending".to_string(),
                token: "mytoken".to_string(),
                validated: None,
                error: None,
                created: now,
                updated: now,
            },
        )
        .await
        .unwrap();

        on_invalid(
            &state,
            &chall_id,
            &authz_id,
            AcmeError::Connection("test failure".into()),
            now,
        )
        .await;

        let chall = db::challenges::get_by_id(&state.db, &chall_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(chall.status, "invalid");

        let authz = db::authz::get_by_id(&state.db, &authz_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(authz.status, "invalid");

        let order = db::orders::get_by_id(&state.db, &order_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(order.status, "invalid");
    }

    #[tokio::test]
    async fn validate_challenge_http01_success_updates_db() {
        use crate::db::schema::{AccountRow, AuthorizationRow, ChallengeRow, OrderRow};
        use axum::{routing::get, Router};
        use tokio::net::TcpListener;

        let now = unix_now();

        let token = "test-http01-token";
        let key_auth = format!("{token}.fake-thumbprint");
        let key_auth_clone = key_auth.clone();

        // Start the challenge responder first so we know the port.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let path = format!("/.well-known/acme-challenge/{token}");
        let router = Router::new().route(
            &path,
            get(move || {
                let body = key_auth_clone.clone();
                async move { body }
            }),
        );
        tokio::spawn(async move {
            axum::serve(listener, router).await.ok();
        });

        // Build state with http_validation_port pointing at our test responder.
        let config = Arc::new(Config {
            listen_addr: "127.0.0.1:0".into(),
            base_url: "https://acme.test".into(),
            database: DatabaseConfig {
                path: ":memory:".into(),
            },
            ca: CaConfig {
                key_file: "/tmp/val-test-http01-ca.key".into(),
                cert_file: "/tmp/val-test-http01-ca.crt".into(),
                key_type: "ec:P-256".into(),
                hash_alg: "sha256".into(),
                validity_days: 90,
                crl_url: None,
                ocsp_url: None,
                common_name: "Val Test CA".into(),
                organization: "Test".into(),
                ca_validity_years: 10,
            },
            mtc: MtcConfig {
                log_path: "/dev/null".into(),
                enabled: false,
            },
            server: ServerConfig {
                http_validation_port: addr.port(),
                ..ServerConfig::default()
            },
            tls: Default::default(),
        });
        let (ca_key, ca_cert_der) = ca::init::load_or_generate(&config.ca).unwrap();
        let db_conn = Arc::new(db::open(":memory:").await.unwrap());
        let state = Arc::new(AppState {
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
            tls: None,
            spki_cache: Arc::new(std::sync::RwLock::new(std::collections::HashMap::new())),
            link_header: Arc::new(axum::http::HeaderValue::from_static(
                "<https://acme.test/acme/directory>;rel=\"index\"",
            )),
            validation_client: hyper_util::client::legacy::Client::builder(
                hyper_util::rt::TokioExecutor::new(),
            )
            .build_http::<http_body_util::Empty<hyper::body::Bytes>>(),
        });

        // The identifier is just the IP address — no port embedded.
        let id_value = "127.0.0.1".to_string();

        let acc_id = "acc-http01-001".to_string();
        let order_id = "ord-http01-001".to_string();
        let authz_id = "authz-http01-001".to_string();
        let chall_id = "chall-http01-001".to_string();

        db::accounts::insert(
            &state.db,
            AccountRow {
                id: acc_id.clone(),
                status: "valid".to_string(),
                contact: None,
                public_key: vec![0u8; 4],
                jwk_thumbprint: "thumb-http01-001".to_string(),
                created: now,
                updated: now,
            },
        )
        .await
        .unwrap();

        db::orders::insert(
            &state.db,
            OrderRow {
                id: order_id.clone(),
                account_id: acc_id.clone(),
                status: "pending".to_string(),
                expires: Some(now + 3600),
                identifiers: r#"[{"type":"ip","value":"127.0.0.1"}]"#.to_string(),
                not_before: None,
                not_after: None,
                error: None,
                certificate_id: None,
                replaces: None,
                created: now,
                updated: now,
            },
        )
        .await
        .unwrap();

        db::authz::insert(
            &state.db,
            AuthorizationRow {
                id: authz_id.clone(),
                order_id: order_id.clone(),
                account_id: acc_id.clone(),
                status: "pending".to_string(),
                identifier: format!(r#"{{"type":"ip","value":"{}"}}"#, id_value),
                expires: Some(now + 3600),
                wildcard: false,
                created: now,
                updated: now,
            },
        )
        .await
        .unwrap();

        db::challenges::insert(
            &state.db,
            ChallengeRow {
                id: chall_id.clone(),
                authz_id: authz_id.clone(),
                r#type: "http-01".to_string(),
                status: "pending".to_string(),
                token: token.to_string(),
                validated: None,
                error: None,
                created: now,
                updated: now,
            },
        )
        .await
        .unwrap();

        validate_challenge(
            &state, &chall_id, &authz_id, "http-01", "ip", &id_value, &key_auth, token,
        )
        .await;

        // Covers Ok(()) => on_valid branch in validate_challenge.
        let chall = db::challenges::get_by_id(&state.db, &chall_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            chall.status, "valid",
            "http-01 validation should mark challenge valid"
        );
    }

    /// Call on_valid with a raw (no-schema) DB so that set_valid fails immediately.
    /// Covers validation/mod.rs lines 65-67 (set_valid Err path → warn + return).
    #[tokio::test]
    async fn on_valid_db_error_set_valid_fails() {
        use crate::ca;
        use crate::config::{CaConfig, Config, DatabaseConfig, MtcConfig, ServerConfig};
        use crate::state::{AppState, CaState, MtcState};

        let dir = tempfile::TempDir::new().unwrap();
        let config = Arc::new(Config {
            listen_addr: "127.0.0.1:0".into(),
            base_url: "https://acme.test".into(),
            database: DatabaseConfig {
                path: ":memory:".into(),
            },
            ca: CaConfig {
                key_file: dir.path().join("ca.key").to_string_lossy().into_owned(),
                cert_file: dir.path().join("ca.crt").to_string_lossy().into_owned(),
                key_type: "ec:P-256".into(),
                hash_alg: "sha256".into(),
                validity_days: 90,
                crl_url: None,
                ocsp_url: None,
                common_name: "Test CA".into(),
                organization: "Test".into(),
                ca_validity_years: 10,
            },
            mtc: MtcConfig {
                log_path: "/dev/null".into(),
                enabled: false,
            },
            server: ServerConfig::default(),
            tls: Default::default(),
        });
        let (ca_key, ca_cert_der) = ca::init::load_or_generate(&config.ca).unwrap();
        // Raw connection — no schema — so every DB call fails immediately.
        let raw_db = Arc::new(tokio_rusqlite::Connection::open_in_memory().await.unwrap());
        let state = Arc::new(AppState {
            config: Arc::clone(&config),
            db: Arc::clone(&raw_db),
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
            tls: None,
            spki_cache: Arc::new(std::sync::RwLock::new(std::collections::HashMap::new())),
            link_header: Arc::new(axum::http::HeaderValue::from_static(
                "<https://acme.test/acme/directory>;rel=\"index\"",
            )),
            validation_client: hyper_util::client::legacy::Client::builder(
                hyper_util::rt::TokioExecutor::new(),
            )
            .build_http::<http_body_util::Empty<hyper::body::Bytes>>(),
        });
        // on_valid tries set_valid first; fails on no-table DB → warn + return (lines 65-67).
        on_valid(&state, "fake-chall", "fake-authz", unix_now()).await;
    }

    /// Call on_invalid with a raw (no-schema) DB so set_invalid fails immediately.
    /// Covers validation/mod.rs lines 128-135 (set_invalid + update_status Err paths).
    #[tokio::test]
    async fn on_invalid_db_error_set_invalid_fails() {
        use crate::ca;
        use crate::config::{CaConfig, Config, DatabaseConfig, MtcConfig, ServerConfig};
        use crate::state::{AppState, CaState, MtcState};

        let dir = tempfile::TempDir::new().unwrap();
        let config = Arc::new(Config {
            listen_addr: "127.0.0.1:0".into(),
            base_url: "https://acme.test".into(),
            database: DatabaseConfig {
                path: ":memory:".into(),
            },
            ca: CaConfig {
                key_file: dir.path().join("ca2.key").to_string_lossy().into_owned(),
                cert_file: dir.path().join("ca2.crt").to_string_lossy().into_owned(),
                key_type: "ec:P-256".into(),
                hash_alg: "sha256".into(),
                validity_days: 90,
                crl_url: None,
                ocsp_url: None,
                common_name: "Test CA".into(),
                organization: "Test".into(),
                ca_validity_years: 10,
            },
            mtc: MtcConfig {
                log_path: "/dev/null".into(),
                enabled: false,
            },
            server: ServerConfig::default(),
            tls: Default::default(),
        });
        let (ca_key, ca_cert_der) = ca::init::load_or_generate(&config.ca).unwrap();
        let raw_db = Arc::new(tokio_rusqlite::Connection::open_in_memory().await.unwrap());
        let state = Arc::new(AppState {
            config: Arc::clone(&config),
            db: Arc::clone(&raw_db),
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
            tls: None,
            spki_cache: Arc::new(std::sync::RwLock::new(std::collections::HashMap::new())),
            link_header: Arc::new(axum::http::HeaderValue::from_static(
                "<https://acme.test/acme/directory>;rel=\"index\"",
            )),
            validation_client: hyper_util::client::legacy::Client::builder(
                hyper_util::rt::TokioExecutor::new(),
            )
            .build_http::<http_body_util::Empty<hyper::body::Bytes>>(),
        });
        // on_invalid tries set_invalid first; fails on no-table DB → warn (lines 128-135).
        on_invalid(
            &state,
            "fake-chall",
            "fake-authz",
            AcmeError::Connection("test".into()),
            unix_now(),
        )
        .await;
    }

    /// on_valid where set_valid succeeds (challenges table present) but
    /// update_status(authz) fails (authorizations table absent).
    /// Covers validation/mod.rs lines 70-72 (update_status Err → warn + return).
    #[tokio::test]
    async fn on_valid_set_valid_ok_but_authz_update_fails() {
        use crate::ca;
        use crate::config::{CaConfig, Config, DatabaseConfig, MtcConfig, ServerConfig};
        use crate::state::{AppState, CaState, MtcState};

        let dir = tempfile::TempDir::new().unwrap();
        let config = Arc::new(Config {
            listen_addr: "127.0.0.1:0".into(),
            base_url: "https://acme.test".into(),
            database: DatabaseConfig {
                path: ":memory:".into(),
            },
            ca: CaConfig {
                key_file: dir.path().join("ca3.key").to_string_lossy().into_owned(),
                cert_file: dir.path().join("ca3.crt").to_string_lossy().into_owned(),
                key_type: "ec:P-256".into(),
                hash_alg: "sha256".into(),
                validity_days: 90,
                crl_url: None,
                ocsp_url: None,
                common_name: "Test CA".into(),
                organization: "Test".into(),
                ca_validity_years: 10,
            },
            mtc: MtcConfig {
                log_path: "/dev/null".into(),
                enabled: false,
            },
            server: ServerConfig::default(),
            tls: Default::default(),
        });
        let (ca_key, ca_cert_der) = ca::init::load_or_generate(&config.ca).unwrap();

        // Create a DB with only the challenges table (no authorizations/orders).
        let partial_db = Arc::new(tokio_rusqlite::Connection::open_in_memory().await.unwrap());
        partial_db
            .call(|conn| {
                conn.execute_batch(
                    "PRAGMA foreign_keys=OFF;
                 CREATE TABLE challenges (
                     id TEXT PRIMARY KEY,
                     authz_id TEXT NOT NULL,
                     type TEXT NOT NULL,
                     status TEXT NOT NULL DEFAULT 'pending',
                     token TEXT NOT NULL,
                     validated INTEGER,
                     error TEXT,
                     created INTEGER NOT NULL,
                     updated INTEGER NOT NULL
                 );
                 INSERT INTO challenges
                     (id, authz_id, type, status, token, created, updated)
                 VALUES ('chall-partial', 'authz-partial', 'http-01', 'pending', 'tok', 0, 0);",
                )?;
                Ok(())
            })
            .await
            .unwrap();

        let state = Arc::new(AppState {
            config: Arc::clone(&config),
            db: Arc::clone(&partial_db),
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
            tls: None,
            spki_cache: Arc::new(std::sync::RwLock::new(std::collections::HashMap::new())),
            link_header: Arc::new(axum::http::HeaderValue::from_static(
                "<https://acme.test/acme/directory>;rel=\"index\"",
            )),
            validation_client: hyper_util::client::legacy::Client::builder(
                hyper_util::rt::TokioExecutor::new(),
            )
            .build_http::<http_body_util::Empty<hyper::body::Bytes>>(),
        });

        // set_valid succeeds (challenge row exists), then update_status(authz) fails
        // (no authorizations table) → lines 70-72 (warn + return) are covered.
        on_valid(&state, "chall-partial", "authz-partial", unix_now()).await;
    }

    /// Helper to build a state backed by a given db connection.
    async fn make_state_with_db(db: Arc<tokio_rusqlite::Connection>) -> Arc<AppState> {
        use crate::config::{CaConfig, Config, DatabaseConfig, MtcConfig, ServerConfig};
        use crate::state::{AppState, CaState, MtcState};
        let dir = tempfile::TempDir::new().unwrap();
        let config = Arc::new(Config {
            listen_addr: "127.0.0.1:0".into(),
            base_url: "https://acme.test".into(),
            database: DatabaseConfig {
                path: ":memory:".into(),
            },
            ca: CaConfig {
                key_file: dir.path().join("ca-p.key").to_string_lossy().into_owned(),
                cert_file: dir.path().join("ca-p.crt").to_string_lossy().into_owned(),
                key_type: "ec:P-256".into(),
                hash_alg: "sha256".into(),
                validity_days: 90,
                crl_url: None,
                ocsp_url: None,
                common_name: "Test CA".into(),
                organization: "Test".into(),
                ca_validity_years: 10,
            },
            mtc: MtcConfig {
                log_path: "/dev/null".into(),
                enabled: false,
            },
            server: ServerConfig::default(),
            tls: Default::default(),
        });
        let (ca_key, ca_cert_der) = crate::ca::init::load_or_generate(&config.ca).unwrap();
        Arc::new(AppState {
            config,
            db: Arc::clone(&db),
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
            tls: None,
            spki_cache: Arc::new(std::sync::RwLock::new(std::collections::HashMap::new())),
            link_header: Arc::new(axum::http::HeaderValue::from_static(
                "<https://acme.test/acme/directory>;rel=\"index\"",
            )),
            validation_client: hyper_util::client::legacy::Client::builder(
                hyper_util::rt::TokioExecutor::new(),
            )
            .build_http::<http_body_util::Empty<hyper::body::Bytes>>(),
        })
    }

    /// Insert minimal test data: account, order, authz, challenge — all with the given IDs.
    async fn insert_test_rows(
        db: &Arc<tokio_rusqlite::Connection>,
        acc_id: &str,
        order_id: &str,
        authz_id: &str,
        chall_id: &str,
    ) {
        use crate::db;
        use crate::db::schema::{AccountRow, AuthorizationRow, ChallengeRow, OrderRow};
        let now = unix_now();
        db::accounts::insert(
            db,
            AccountRow {
                id: acc_id.to_string(),
                status: "valid".into(),
                contact: None,
                public_key: vec![0],
                jwk_thumbprint: format!("t-{acc_id}"),
                created: now,
                updated: now,
            },
        )
        .await
        .unwrap();
        db::orders::insert(
            db,
            OrderRow {
                id: order_id.to_string(),
                account_id: acc_id.to_string(),
                status: "pending".into(),
                expires: None,
                identifiers: r#"[{"type":"dns","value":"x.test"}]"#.into(),
                not_before: None,
                not_after: None,
                error: None,
                certificate_id: None,
                replaces: None,
                created: now,
                updated: now,
            },
        )
        .await
        .unwrap();
        db::authz::insert(
            db,
            AuthorizationRow {
                id: authz_id.to_string(),
                order_id: order_id.to_string(),
                account_id: acc_id.to_string(),
                status: "pending".into(),
                identifier: r#"{"type":"dns","value":"x.test"}"#.into(),
                expires: None,
                wildcard: false,
                created: now,
                updated: now,
            },
        )
        .await
        .unwrap();
        db::challenges::insert(
            db,
            ChallengeRow {
                id: chall_id.to_string(),
                authz_id: authz_id.to_string(),
                r#type: "http-01".into(),
                status: "pending".into(),
                token: "tok".into(),
                validated: None,
                error: None,
                created: now,
                updated: now,
            },
        )
        .await
        .unwrap();
    }

    /// on_valid where set_valid + update_status + get_by_id + list_by_order all
    /// succeed, but update_status(orders "ready") fails because the orders table
    /// was dropped.  Covers lines 97-105 (all_valid=true + orders-update Err path).
    #[tokio::test]
    async fn on_valid_orders_update_fails() {
        let db_conn = Arc::new(crate::db::open(":memory:").await.unwrap());
        insert_test_rows(&db_conn, "acc-ov", "ord-ov", "authz-ov", "chall-ov").await;

        // Drop the orders table so update_status("ready") fails.
        db_conn
            .call(|c| {
                c.execute_batch("PRAGMA foreign_keys=OFF; DROP TABLE orders;")?;
                Ok(())
            })
            .await
            .unwrap();

        let state = make_state_with_db(db_conn).await;
        // on_valid: set_valid OK → update_status(authz) OK → get_by_id OK(Some) →
        //   list_by_order OK([authz valid]) → all_valid=true → orders update FAIL →
        //   lines 98-101 (warn) + line 105 (closing }) covered.
        on_valid(&state, "chall-ov", "authz-ov", unix_now()).await;
    }

    /// on_invalid where set_invalid + update_status(authz invalid) + get_by_id
    /// succeed but update_status(orders invalid) fails because orders was dropped.
    /// Covers lines 139-143 (orders-invalid Err path).
    #[tokio::test]
    async fn on_invalid_orders_update_fails() {
        let db_conn = Arc::new(crate::db::open(":memory:").await.unwrap());
        insert_test_rows(&db_conn, "acc-oi", "ord-oi", "authz-oi", "chall-oi").await;

        // Drop orders table so the order-invalid update fails.
        db_conn
            .call(|c| {
                c.execute_batch("PRAGMA foreign_keys=OFF; DROP TABLE orders;")?;
                Ok(())
            })
            .await
            .unwrap();

        let state = make_state_with_db(db_conn).await;
        // on_invalid: set_invalid OK → update_status(authz invalid) OK →
        //   get_by_id(authz) Ok(Some) → orders update FAIL → lines 140-143 covered.
        on_invalid(
            &state,
            "chall-oi",
            "authz-oi",
            AcmeError::Connection("test".into()),
            unix_now(),
        )
        .await;
    }
}
