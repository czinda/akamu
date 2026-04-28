//! Background challenge validation — http-01, dns-01, tls-alpn-01.
//!
//! Each call runs inside a `tokio::spawn` and must not panic.
//! After validation the function updates challenge, authorization, and order state.

pub mod caa;
mod dns01;
mod dns_persist_01;
mod http01;
pub mod onion_csr_01;
mod tls_alpn01;

use std::sync::Arc;

use serde_json::json;

use crate::error::AcmeError;
use crate::state::AppState;

/// Challenge parameters for [`validate_challenge`].
pub struct ChallengeParams<'a> {
    pub challenge_id: &'a str,
    pub authz_id: &'a str,
    pub order_id: &'a str,
    pub chall_type: &'a str,
    pub id_type: &'a str,
    pub id_value: &'a str,
    pub key_auth: &'a str,
    pub token: &'a str,
    pub onion_csr_der: Option<&'a [u8]>,
}

/// Entry point called from `routes::challenge::respond_challenge`.
///
/// This function is intentionally infallible — all errors are recorded in the
/// database rather than propagated.
///
/// Returns the final challenge status: `"valid"` on success, `"invalid"` on
/// failure.  The caller can use this to return the definitive challenge state
/// in the HTTP response without a separate DB re-fetch.
///
/// `order_id` is passed in to avoid a redundant `SELECT order_id FROM
/// authorizations` query inside the `on_valid` transaction.
///
/// `onion_csr_der` carries the DER-encoded CSR submitted by the client for
/// `onion-csr-01` challenges; it is `None` for all other challenge types.
pub async fn validate_challenge(
    state: &Arc<AppState>,
    params: ChallengeParams<'_>,
) -> &'static str {
    let ChallengeParams {
        challenge_id,
        authz_id,
        order_id,
        chall_type,
        id_type,
        id_value,
        key_auth,
        token,
        onion_csr_der,
    } = params;
    let http_port = state.config.server.http_validation_port;
    let issuer_domain = state.config.dns_persist_issuer_domain();
    let dns_resolver_addr = state
        .config
        .server
        .dns_resolver_addr
        .as_deref()
        .and_then(|s| s.parse::<std::net::SocketAddr>().ok());
    let validate_dnssec = state.config.server.validate_dnssec;
    let result = dispatch(DispatchParams {
        chall_type,
        id_type,
        id_value,
        key_auth,
        token,
        http_port,
        issuer_domain: &issuer_domain,
        dns_resolver_addr,
        validate_dnssec,
        validation_client: &state.validation_client,
        onion_csr_der,
    })
    .await;

    let now = unix_now();
    match result {
        Ok(()) => {
            on_valid(state, challenge_id, authz_id, order_id, now).await;
            "valid"
        }
        Err(e) => {
            on_invalid(state, challenge_id, authz_id, e, now).await;
            "invalid"
        }
    }
}

struct DispatchParams<'a> {
    chall_type: &'a str,
    id_type: &'a str,
    id_value: &'a str,
    key_auth: &'a str,
    token: &'a str,
    http_port: u16,
    issuer_domain: &'a str,
    dns_resolver_addr: Option<std::net::SocketAddr>,
    validate_dnssec: bool,
    validation_client: &'a crate::state::ValidationClient,
    onion_csr_der: Option<&'a [u8]>,
}

/// Dispatch to the correct validator based on challenge type.
///
/// For `dns-persist-01`, `key_auth` carries the account URI (not a token·thumbprint).
/// For `onion-csr-01`, `onion_csr_der` must be `Some(der)` containing the client's CSR.
async fn dispatch(
    DispatchParams {
        chall_type,
        id_type,
        id_value,
        key_auth,
        token,
        http_port,
        issuer_domain,
        dns_resolver_addr,
        validate_dnssec,
        validation_client,
        onion_csr_der,
    }: DispatchParams<'_>,
) -> Result<(), AcmeError> {
    match chall_type {
        "http-01" => {
            http01::validate(id_value, token, key_auth, http_port, validation_client).await
        }
        "dns-01" => dns01::validate(id_value, key_auth, validate_dnssec).await,
        "tls-alpn-01" => tls_alpn01::validate(id_type, id_value, key_auth).await,
        "dns-persist-01" => {
            dns_persist_01::validate(
                id_value,
                key_auth,
                issuer_domain,
                dns_resolver_addr,
                validate_dnssec,
            )
            .await
        }
        "onion-csr-01" => {
            let csr_der = onion_csr_der.ok_or_else(|| {
                AcmeError::IncorrectResponse(
                    "onion-csr-01: CSR not provided in challenge response".into(),
                )
            })?;
            // id_value is the .onion domain; key_auth is token.thumbprint.
            onion_csr_01::validate(id_value, csr_der, key_auth)
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
///
/// `order_id` is provided by the caller (from the already-loaded authz row)
/// to avoid a redundant `SELECT order_id FROM authorizations` inside the
/// transaction.
async fn on_valid(state: &AppState, challenge_id: &str, authz_id: &str, order_id: &str, now: i64) {
    let authz_id_log = authz_id.to_string();

    let result: Result<bool, sqlx::Error> = async {
        let mut tx = state.db.begin().await?;

        // 1. Mark challenge valid.
        sqlx::query(
            "UPDATE challenges SET status = 'valid', validated = ?, updated = ? WHERE id = ?",
        )
        .bind(now)
        .bind(now)
        .bind(challenge_id)
        .execute(&mut *tx)
        .await?;

        // 2. Mark authorization valid.
        sqlx::query("UPDATE authorizations SET status = 'valid', updated = ? WHERE id = ?")
            .bind(now)
            .bind(authz_id)
            .execute(&mut *tx)
            .await?;

        // 3. Advance order to 'ready' only when all its authorizations are now
        // valid.  A single conditional UPDATE replaces the previous
        // SELECT COUNT(*) + conditional UPDATE — saves one DB round-trip on
        // the common (single-identifier) path.
        let rows = sqlx::query(
            "UPDATE orders SET status = 'ready', error = NULL, updated = ?
             WHERE id = ?
               AND NOT EXISTS (
                   SELECT 1 FROM authorizations
                   WHERE order_id = ? AND status != 'valid'
               )",
        )
        .bind(now)
        .bind(order_id)
        .bind(order_id)
        .execute(&mut *tx)
        .await?
        .rows_affected();

        tx.commit().await?;
        Ok(rows > 0)
    }
    .await;

    match result {
        Ok(true) => {
            tracing::info!("order {order_id} is now ready");
        }
        Ok(false) => {}
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

    let authz_id_log = authz_id.to_string();

    let result: Result<(), sqlx::Error> = async {
        let mut tx = state.db.begin().await?;

        // 1. Mark challenge invalid with the error detail.
        sqlx::query(
            "UPDATE challenges SET status = 'invalid', error = ?, updated = ? WHERE id = ?",
        )
        .bind(&error_json)
        .bind(now)
        .bind(challenge_id)
        .execute(&mut *tx)
        .await?;

        // 2. Mark authorization invalid.
        sqlx::query("UPDATE authorizations SET status = 'invalid', updated = ? WHERE id = ?")
            .bind(now)
            .bind(authz_id)
            .execute(&mut *tx)
            .await?;

        // 3. Find the parent order_id and mark it invalid.
        let order_id_row: Option<(String,)> =
            sqlx::query_as("SELECT order_id FROM authorizations WHERE id = ?")
                .bind(authz_id)
                .fetch_optional(&mut *tx)
                .await?;

        if let Some((oid,)) = order_id_row {
            sqlx::query(
                "UPDATE orders SET status = 'invalid', error = NULL, updated = ? WHERE id = ?",
            )
            .bind(now)
            .bind(&oid)
            .execute(&mut *tx)
            .await?;
        }

        tx.commit().await?;
        Ok(())
    }
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
    use crate::state::{AppState, CaState, MtcState, NonceBucket};
    use crate::{ca, db};

    async fn make_state() -> Arc<AppState> {
        let dir = tempfile::TempDir::new().unwrap();
        let config = Arc::new(Config {
            listen_addr: "127.0.0.1:0".into(),
            base_url: "https://acme.test".into(),
            database: DatabaseConfig {
                url: "sqlite::memory:".into(),
                max_connections: None,
            },
            ca: CaConfig {
                key_file: dir.path().join("ca.key").to_string_lossy().into_owned(),
                cert_file: dir.path().join("ca.crt").to_string_lossy().into_owned(),
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
                signing_key: None,
                checkpoint_interval_secs: 3600,
                cosigners: vec![],
                landmark_interval_secs: 86400,
                max_active_landmarks: 100,
                checkpoint_retention_count: 1000,
            },
            server: ServerConfig::default(),
            tls: Default::default(),
            profiles: Default::default(),
            admin: None,
        });

        let (ca_key, ca_cert_der) = ca::init::load_or_generate(&config.ca).unwrap();
        db::install_drivers();
        let db_conn = db::open("sqlite::memory:", 1, "./migrations/sqlite")
            .await
            .unwrap();

        let ca = Arc::new(CaState {
            key: ca_key,
            cert_der: ca_cert_der,
            hash_alg: "sha256".into(),
            validity_days: 90,
            crl_url: None,
            ocsp_url: None,
            aki_bytes: Vec::new(),
        });
        Arc::new(AppState {
            config: Arc::clone(&config),
            db: db_conn,
            db_kind: crate::db::DbKind::Sqlite,
            profiles: crate::profiles::ProfileRegistry::empty(&ca),
            ca,
            mtc: Arc::new(MtcState {
                log: None,
                algorithm: synta_mtc::crypto::HashAlgorithm::Sha256,
                signing_key: None,
                signing_hash_alg: "sha256".into(),
                cosigner_clients: vec![],
            }),
            tls: None,
            spki_cache: Arc::new(std::sync::RwLock::new(std::collections::HashMap::new())),
            nonces: Arc::new(NonceBucket::new()),
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
        let result = dispatch(DispatchParams {
            chall_type: "bogus-type",
            id_type: "dns",
            id_value: "example.com",
            key_auth: "key-auth",
            token: "token",
            http_port: 80,
            issuer_domain: "acme.test",
            dns_resolver_addr: None,
            validate_dnssec: false,
            validation_client: &client,
            onion_csr_der: None,
        })
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
            "nonexistent-order",
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
            ChallengeParams {
                challenge_id: "fake-challenge-id",
                authz_id: "fake-authz-id",
                order_id: "fake-order-id",
                chall_type: "bogus-01", // unsupported type → dispatch returns Err
                id_type: "dns",
                id_value: "example.com",
                key_auth: "token.thumbprint",
                token: "token",
                onion_csr_der: None,
            },
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
                profile_grants: None,
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
                star_start_date: None,
                star_end_date: None,
                star_lifetime_secs: None,
                star_lifetime_adjust_secs: 0,
                star_allow_cert_get: 0,
                star_canceled_at: None,
                star_csr_der: None,
                profile: None,
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
                wildcard: 0,
                subdomain_auth_allowed: 0,
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
        on_valid(&state, &chall_id, &authz_id, &order_id, now).await;

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
                profile_grants: None,
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
                star_start_date: None,
                star_end_date: None,
                star_lifetime_secs: None,
                star_lifetime_adjust_secs: 0,
                star_allow_cert_get: 0,
                star_canceled_at: None,
                star_csr_der: None,
                profile: None,
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
                wildcard: 0,
                subdomain_auth_allowed: 0,
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
        let dir = tempfile::TempDir::new().unwrap();
        let config = Arc::new(Config {
            listen_addr: "127.0.0.1:0".into(),
            base_url: "https://acme.test".into(),
            database: DatabaseConfig {
                url: "sqlite::memory:".into(),
                max_connections: None,
            },
            ca: CaConfig {
                key_file: dir.path().join("ca.key").to_string_lossy().into_owned(),
                cert_file: dir.path().join("ca.crt").to_string_lossy().into_owned(),
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
                signing_key: None,
                checkpoint_interval_secs: 3600,
                cosigners: vec![],
                landmark_interval_secs: 86400,
                max_active_landmarks: 100,
                checkpoint_retention_count: 1000,
            },
            server: ServerConfig {
                http_validation_port: addr.port(),
                ..ServerConfig::default()
            },
            tls: Default::default(),
            profiles: Default::default(),
            admin: None,
        });
        let (ca_key, ca_cert_der) = ca::init::load_or_generate(&config.ca).unwrap();
        db::install_drivers();
        let db_conn = db::open("sqlite::memory:", 1, "./migrations/sqlite")
            .await
            .unwrap();
        let ca = Arc::new(CaState {
            key: ca_key,
            cert_der: ca_cert_der,
            hash_alg: "sha256".into(),
            validity_days: 90,
            crl_url: None,
            ocsp_url: None,
            aki_bytes: Vec::new(),
        });
        let state = Arc::new(AppState {
            config: Arc::clone(&config),
            db: db_conn,
            db_kind: crate::db::DbKind::Sqlite,
            profiles: crate::profiles::ProfileRegistry::empty(&ca),
            ca,
            mtc: Arc::new(MtcState {
                log: None,
                algorithm: synta_mtc::crypto::HashAlgorithm::Sha256,
                signing_key: None,
                signing_hash_alg: "sha256".into(),
                cosigner_clients: vec![],
            }),
            tls: None,
            spki_cache: Arc::new(std::sync::RwLock::new(std::collections::HashMap::new())),
            nonces: Arc::new(NonceBucket::new()),
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
                profile_grants: None,
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
                star_start_date: None,
                star_end_date: None,
                star_lifetime_secs: None,
                star_lifetime_adjust_secs: 0,
                star_allow_cert_get: 0,
                star_canceled_at: None,
                star_csr_der: None,
                profile: None,
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
                wildcard: 0,
                subdomain_auth_allowed: 0,
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
            &state,
            ChallengeParams {
                challenge_id: &chall_id,
                authz_id: &authz_id,
                order_id: &order_id,
                chall_type: "http-01",
                id_type: "ip",
                id_value: &id_value,
                key_auth: &key_auth,
                token,
                onion_csr_der: None,
            },
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

    /// Create a raw (no-schema) sqlx pool for error-path tests.
    async fn raw_no_schema_pool() -> crate::db::Db {
        crate::db::install_drivers();
        sqlx::any::AnyPoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap()
    }

    /// Call on_valid with a raw (no-schema) DB so that set_valid fails immediately.
    /// Covers on_valid transaction Err path → warn + return.
    #[tokio::test]
    async fn on_valid_db_error_set_valid_fails() {
        let raw_db = raw_no_schema_pool().await;
        let state = make_state_with_db(raw_db).await;
        // on_valid tries to begin a transaction and execute UPDATE on challenges;
        // fails on no-table DB → warns and returns.
        on_valid(&state, "fake-chall", "fake-authz", "fake-order", unix_now()).await;
    }

    /// Call on_invalid with a raw (no-schema) DB so set_invalid fails immediately.
    /// Covers on_invalid transaction Err path → warn.
    #[tokio::test]
    async fn on_invalid_db_error_set_invalid_fails() {
        let raw_db = raw_no_schema_pool().await;
        let state = make_state_with_db(raw_db).await;
        // on_invalid tries to begin a transaction and execute UPDATE on challenges;
        // fails on no-table DB → warns.
        on_invalid(
            &state,
            "fake-chall",
            "fake-authz",
            AcmeError::Connection("test".into()),
            unix_now(),
        )
        .await;
    }

    /// on_valid where challenges table exists and authz update fails within the
    /// same transaction (transactions are atomic in sqlx — the whole tx fails).
    /// This test verifies that on_valid is robust when the transaction fails.
    #[tokio::test]
    async fn on_valid_set_valid_ok_but_authz_update_fails() {
        crate::db::install_drivers();
        // Create a DB with only the challenges table (no authorizations/orders).
        let partial_db: crate::db::Db = sqlx::any::AnyPoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        sqlx::query(
            "CREATE TABLE challenges (
                 id TEXT PRIMARY KEY,
                 authz_id TEXT NOT NULL,
                 type TEXT NOT NULL,
                 status TEXT NOT NULL DEFAULT 'pending',
                 token TEXT NOT NULL,
                 validated INTEGER,
                 error TEXT,
                 created INTEGER NOT NULL,
                 updated INTEGER NOT NULL
             )",
        )
        .execute(&partial_db)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO challenges (id, authz_id, type, status, token, created, updated)
             VALUES ('chall-partial', 'authz-partial', 'http-01', 'pending', 'tok', 0, 0)",
        )
        .execute(&partial_db)
        .await
        .unwrap();

        let state = make_state_with_db(partial_db).await;
        // Transaction begins, challenge update succeeds, then authz update fails
        // (no authorizations table) — the whole transaction is rolled back and
        // the error is logged as a warning.
        on_valid(
            &state,
            "chall-partial",
            "authz-partial",
            "order-partial",
            unix_now(),
        )
        .await;
    }

    /// Helper to build a state backed by a given db pool.
    async fn make_state_with_db(db: crate::db::Db) -> Arc<AppState> {
        use crate::config::{CaConfig, Config, DatabaseConfig, MtcConfig, ServerConfig};
        use crate::state::{AppState, CaState, MtcState, NonceBucket};
        let dir = tempfile::TempDir::new().unwrap();
        let config = Arc::new(Config {
            listen_addr: "127.0.0.1:0".into(),
            base_url: "https://acme.test".into(),
            database: DatabaseConfig {
                url: "sqlite::memory:".into(),
                max_connections: None,
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
                signing_key: None,
                checkpoint_interval_secs: 3600,
                cosigners: vec![],
                landmark_interval_secs: 86400,
                max_active_landmarks: 100,
                checkpoint_retention_count: 1000,
            },
            server: ServerConfig::default(),
            tls: Default::default(),
            profiles: Default::default(),
            admin: None,
        });
        let (ca_key, ca_cert_der) = crate::ca::init::load_or_generate(&config.ca).unwrap();
        let ca = Arc::new(CaState {
            key: ca_key,
            cert_der: ca_cert_der,
            hash_alg: "sha256".into(),
            validity_days: 90,
            crl_url: None,
            ocsp_url: None,
            aki_bytes: Vec::new(),
        });
        Arc::new(AppState {
            config,
            db,
            db_kind: crate::db::DbKind::Sqlite,
            profiles: crate::profiles::ProfileRegistry::empty(&ca),
            ca,
            mtc: Arc::new(MtcState {
                log: None,
                algorithm: synta_mtc::crypto::HashAlgorithm::Sha256,
                signing_key: None,
                signing_hash_alg: "sha256".into(),
                cosigner_clients: vec![],
            }),
            tls: None,
            spki_cache: Arc::new(std::sync::RwLock::new(std::collections::HashMap::new())),
            nonces: Arc::new(NonceBucket::new()),
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
        db: &crate::db::Db,
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
                profile_grants: None,
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
                star_start_date: None,
                star_end_date: None,
                star_lifetime_secs: None,
                star_lifetime_adjust_secs: 0,
                star_allow_cert_get: 0,
                star_canceled_at: None,
                star_csr_der: None,
                profile: None,
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
                wildcard: 0,
                subdomain_auth_allowed: 0,
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

    /// on_valid where all updates succeed but update_status(orders "ready") fails
    /// because the orders table was dropped.
    #[tokio::test]
    async fn on_valid_orders_update_fails() {
        crate::db::install_drivers();
        let db_conn = crate::db::open("sqlite::memory:", 1, "./migrations/sqlite")
            .await
            .unwrap();
        insert_test_rows(&db_conn, "acc-ov", "ord-ov", "authz-ov", "chall-ov").await;

        // Both DDL statements must run on the same connection: PRAGMA is
        // connection-local, so foreign_keys=OFF must be visible to the DROP TABLE.
        let mut conn = db_conn.acquire().await.unwrap();
        sqlx::query("PRAGMA foreign_keys=OFF")
            .execute(&mut *conn)
            .await
            .unwrap();
        sqlx::query("DROP TABLE orders")
            .execute(&mut *conn)
            .await
            .unwrap();
        drop(conn);

        let state = make_state_with_db(db_conn).await;
        // on_valid: transaction tries UPDATE orders SET status = 'ready' → fails
        // (no orders table) → transaction rolled back → error logged as warning.
        on_valid(&state, "chall-ov", "authz-ov", "ord-ov", unix_now()).await;
    }

    /// on_invalid where all updates succeed but the orders update fails because
    /// orders table was dropped.
    #[tokio::test]
    async fn on_invalid_orders_update_fails() {
        crate::db::install_drivers();
        let db_conn = crate::db::open("sqlite::memory:", 1, "./migrations/sqlite")
            .await
            .unwrap();
        insert_test_rows(&db_conn, "acc-oi", "ord-oi", "authz-oi", "chall-oi").await;

        // Both DDL statements must run on the same connection (PRAGMA is
        // connection-local).
        let mut conn = db_conn.acquire().await.unwrap();
        sqlx::query("PRAGMA foreign_keys=OFF")
            .execute(&mut *conn)
            .await
            .unwrap();
        sqlx::query("DROP TABLE orders")
            .execute(&mut *conn)
            .await
            .unwrap();
        drop(conn);

        let state = make_state_with_db(db_conn).await;
        // on_invalid: transaction tries UPDATE orders → fails (no orders table) →
        // rolled back → error logged as warning.
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
