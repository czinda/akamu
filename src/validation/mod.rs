//! Background challenge validation — http-01, dns-01, tls-alpn-01.
//!
//! Each call runs inside a `tokio::spawn` and must not panic.
//! After validation the function updates challenge, authorization, and order state.

pub mod caa;
pub mod claim_encoder;
mod dns01;
mod dns_persist_01;
pub mod email_reply_00;
mod http01;
pub mod onion_csr_01;
pub(crate) mod tkauth01;
mod tls_alpn01;

use std::sync::Arc;

use serde_json::json;

use crate::error::AcmeError;
use crate::state::AppState;
use crate::util::unix_now;

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
    /// String account ID (UUID or numeric string) of the account that triggered
    /// this challenge.  Used by dns-persist-01 to verify the account is still
    /// active before trusting the long-lived TXT record.
    pub account_id: &'a str,
    /// Raw compact JWT from the client's tkauth-01 challenge response payload.
    /// `None` for all other challenge types.
    pub authority_token: Option<&'a str>,
    /// Unix timestamp when the challenge was created.
    pub challenge_created: i64,
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
        account_id,
        authority_token,
        challenge_created,
    } = params;

    // dns-persist-01: the TXT record is long-lived and pre-provisioned; the
    // account may have been deactivated or revoked between the record being
    // published and this validation task running.  Reject early so we don't
    // count a stale record as a successful validation.
    if chall_type == "dns-persist-01" {
        let status: Result<String, _> =
            crate::db::query_as::<(String,)>("SELECT status FROM accounts WHERE id = ?")
                .bind(account_id)
                .fetch_one(&state.db)
                .await
                .map(|(s,)| s);

        match status.as_deref() {
            Ok("valid") => {}
            Ok(s) => {
                let err =
                    AcmeError::Unauthorized(format!("dns-persist-01: account {account_id} is {s}"));
                let now = unix_now();
                if let Err(db_err) =
                    on_invalid_with_order(state, challenge_id, authz_id, Some(order_id), err, now)
                        .await
                {
                    tracing::warn!(challenge_id, error = %db_err, "failed to record challenge failure");
                }
                return "invalid";
            }
            Err(e) => {
                let err = AcmeError::Internal(format!("account status lookup: {e}"));
                let now = unix_now();
                if let Err(db_err) =
                    on_invalid_with_order(state, challenge_id, authz_id, Some(order_id), err, now)
                        .await
                {
                    tracing::warn!(challenge_id, error = %db_err, "failed to record challenge failure");
                }
                return "invalid";
            }
        }
    }

    // tkauth-01 (RFC 9447): authority token presented in challenge response.
    if chall_type == "tkauth-01" {
        let now = unix_now();
        let token_jwt = match authority_token {
            Some(t) => t,
            None => {
                let err = AcmeError::IncorrectResponse(
                    "tkauth-01: authority token not provided in challenge response".into(),
                );
                if let Err(db_err) =
                    on_invalid_with_order(state, challenge_id, authz_id, Some(order_id), err, now)
                        .await
                {
                    tracing::warn!(challenge_id, error = %db_err, "failed to record challenge failure");
                }
                return "invalid";
            }
        };
        let result = tkauth01::validate(
            id_type, id_value, key_auth, token_jwt, authz_id, order_id, state,
        )
        .await;
        return match result {
            Ok(()) => {
                if let Err(db_err) = on_valid(state, challenge_id, authz_id, order_id, now).await {
                    tracing::warn!(challenge_id, error = %db_err, "failed to mark challenge valid");
                }
                "valid"
            }
            Err(e) => {
                if let Err(db_err) =
                    on_invalid_with_order(state, challenge_id, authz_id, Some(order_id), e, now)
                        .await
                {
                    tracing::warn!(challenge_id, error = %db_err, "failed to record challenge failure");
                }
                "invalid"
            }
        };
    }

    // email-reply-00 (RFC 8823): triggering the challenge sends the challenge
    // email.  Validation happens asynchronously via the webhook — so we return
    // "processing" rather than "valid" after a successful send.
    if chall_type == "email-reply-00" {
        let now = unix_now();
        match email_reply_00::send_challenge_email(state, challenge_id, id_value, token).await {
            Ok(()) => return "processing",
            Err(e) => {
                if let Err(db_err) =
                    on_invalid_with_order(state, challenge_id, authz_id, Some(order_id), e, now)
                        .await
                {
                    tracing::warn!(challenge_id, error = %db_err, "failed to record challenge failure");
                }
                return "invalid";
            }
        }
    }

    let http_port = state.config.server.http_validation_port;
    let http_allow_private_ips = state.config.server.http_validation_allow_private_ips;
    let issuer_domains = state.config.dns_persist_issuer_domains();
    let issuer_domain_refs: Vec<&str> = issuer_domains.iter().map(String::as_str).collect();
    let dns_resolver_addr = state
        .config
        .server
        .dns_resolver_addr
        .as_deref()
        .and_then(|s| match s.parse::<std::net::SocketAddr>() {
            Ok(a) => Some(a),
            Err(e) => {
                tracing::warn!(addr = %s, "dns_resolver_addr is not a valid socket address, ignoring: {e}");
                None
            }
        });
    let dns_persist01_resolver_addr = state
        .config
        .server
        .dns_persist01_resolver_addr
        .as_deref()
        .and_then(|s| match s.parse::<std::net::SocketAddr>() {
            Ok(a) => Some(a),
            Err(e) => {
                tracing::warn!(addr = %s, "dns_persist01_resolver_addr is not a valid socket address, ignoring: {e}");
                None
            }
        })
        .or(dns_resolver_addr);
    let validate_dnssec = state.config.server.validate_dnssec;
    let dot_server_name = state.config.server.dns_dot_server_name.clone();
    let result = dispatch(DispatchParams {
        chall_type,
        id_type,
        id_value,
        key_auth,
        token,
        http_port,
        http_allow_private_ips,
        issuer_domains: &issuer_domain_refs,
        dns_persist01_resolver_addr,
        validate_dnssec,
        dot_server_name: dot_server_name.as_deref(),
        validation_client: &state.validation_client,
        onion_csr_der,
        challenge_created,
    })
    .await;

    let now = unix_now();
    match result {
        Ok(()) => {
            if let Err(db_err) = on_valid(state, challenge_id, authz_id, order_id, now).await {
                tracing::warn!(challenge_id, error = %db_err, "failed to mark challenge valid");
            }
            "valid"
        }
        Err(e) => {
            if let Err(db_err) =
                on_invalid_with_order(state, challenge_id, authz_id, Some(order_id), e, now).await
            {
                tracing::warn!(challenge_id, error = %db_err, "failed to record challenge failure");
            }
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
    http_allow_private_ips: bool,
    issuer_domains: &'a [&'a str],
    dns_persist01_resolver_addr: Option<std::net::SocketAddr>,
    validate_dnssec: bool,
    dot_server_name: Option<&'a str>,
    validation_client: &'a crate::state::ValidationClient,
    onion_csr_der: Option<&'a [u8]>,
    challenge_created: i64,
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
        http_allow_private_ips,
        issuer_domains,
        dns_persist01_resolver_addr,
        validate_dnssec,
        dot_server_name,
        validation_client,
        onion_csr_der,
        challenge_created,
    }: DispatchParams<'_>,
) -> Result<(), AcmeError> {
    match chall_type {
        "http-01" => {
            http01::validate(
                id_value,
                token,
                key_auth,
                http_port,
                http_allow_private_ips,
                validation_client,
            )
            .await
        }
        "dns-01" => dns01::validate(id_value, key_auth, validate_dnssec, dot_server_name).await,
        "tls-alpn-01" => tls_alpn01::validate(id_type, id_value, key_auth).await,
        "dns-persist-01" => {
            dns_persist_01::validate(
                id_value,
                key_auth,
                issuer_domains,
                dns_persist01_resolver_addr,
                validate_dnssec,
                dot_server_name,
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
            // token serves as the server-generated nonce (RFC 9799 §3.2).
            onion_csr_01::validate(id_value, csr_der, key_auth, token, challenge_created)
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
async fn on_valid(
    state: &AppState,
    challenge_id: &str,
    authz_id: &str,
    order_id: &str,
    now: i64,
) -> Result<bool, sqlx::Error> {
    let authz_id_log = authz_id.to_string();

    // Returns (validated_now, order_advanced):
    // - (false, false): concurrent caller already committed; no DB changes made.
    // - (true, false):  challenge and authz marked valid; order has more pending authz.
    // - (true, true):   challenge and authz marked valid; order advanced to "ready".
    let result: Result<(bool, bool), sqlx::Error> = if let Some(ref coal) = state.write_coalescer {
        coal.submit_on_valid(
            challenge_id.to_string(),
            authz_id.to_string(),
            order_id.to_string(),
            now,
        )
        .await
        .map_err(|e| sqlx::Error::Protocol(e.to_string()))
    } else {
        async {
            let mut tx = crate::db::begin_write(&state.db, state.db_kind)
                .await
                .map_err(|e| sqlx::Error::Protocol(e.to_string()))?;
            crate::db::pg_local_async_commit(&mut tx, state.db_kind).await?;

            let chall_rows = crate::db::query(
                "UPDATE challenges SET status = 'valid', validated = ?, updated = ?
                     WHERE id = ? AND status = 'processing'",
            )
            .bind(now)
            .bind(now)
            .bind(challenge_id)
            .execute(&mut *tx)
            .await?
            .rows_affected();

            if chall_rows == 0 {
                tx.commit().await?;
                return Ok((false, false));
            }

            crate::db::query(
                "UPDATE authorizations SET status = 'valid', updated = ? WHERE id = ?",
            )
            .bind(now)
            .bind(authz_id)
            .execute(&mut *tx)
            .await?;

            let rows = crate::db::query(
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
            Ok((true, rows > 0))
        }
        .await
    };

    match result {
        Ok((true, order_advanced)) => {
            // Update in-memory CRDT so gossip propagates the validated state to
            // other cluster nodes without waiting for a full DB reload.
            // Skip entirely when gossip is not configured (single-node mode).
            if state.config.gossip.is_some() {
                use akamu_crdt::{AuthzEntry, ChallengeEntry, OrderEntry};
                let (ch_gen, authz_gen, ord_gen) = {
                    let mut crdt = state.crdt.write().await;

                    let ch_gen =
                        if let Some(ch) = crdt.challenges.get(&challenge_id.to_string()).cloned() {
                            let updated = ChallengeEntry {
                                status: "valid".into(),
                                validated: Some(now),
                                updated: now,
                                ..ch
                            };
                            Some(crdt.challenges.set(
                                challenge_id.to_string(),
                                updated,
                                now,
                                state.node_id.as_str(),
                            ))
                        } else {
                            None
                        };

                    let authz_gen =
                        if let Some(az) = crdt.authorizations.get(&authz_id.to_string()).cloned() {
                            let updated = AuthzEntry {
                                status: "valid".into(),
                                updated: now,
                                ..az
                            };
                            Some(
                                crdt.authorizations
                                    .upsert(authz_id.to_string(), updated, now),
                            )
                        } else {
                            None
                        };

                    let ord_gen = if order_advanced {
                        if let Some(ord) = crdt.orders.get(&order_id.to_string()).cloned() {
                            let updated = OrderEntry {
                                status: "ready".into(),
                                error: None,
                                updated: now,
                                ..ord
                            };
                            Some(crdt.orders.upsert(order_id.to_string(), updated, now))
                        } else {
                            None
                        }
                    } else {
                        None
                    };

                    (ch_gen, authz_gen, ord_gen)
                };
                if let Some(gen) = ch_gen {
                    let _ = crate::db::query("UPDATE challenges SET local_gen = ? WHERE id = ?")
                        .bind(gen as i64)
                        .bind(challenge_id)
                        .execute(&state.db)
                        .await;
                }
                if let Some(gen) = authz_gen {
                    let _ =
                        crate::db::query("UPDATE authorizations SET local_gen = ? WHERE id = ?")
                            .bind(gen as i64)
                            .bind(authz_id)
                            .execute(&state.db)
                            .await;
                }
                if let Some(gen) = ord_gen {
                    let _ = crate::db::query("UPDATE orders SET local_gen = ? WHERE id = ?")
                        .bind(gen as i64)
                        .bind(order_id)
                        .execute(&state.db)
                        .await;
                }
            } // end gossip-enabled block
            if order_advanced {
                tracing::info!("order {order_id} is now ready");
                state
                    .record_audit(
                        crate::audit::AuditEvent::success(
                            crate::audit::AuditEventType::AuthChallengeOk,
                        )
                        .with_subject(authz_id),
                    )
                    .await;
            }
            Ok(order_advanced)
        }
        Ok((false, _)) => {
            // Concurrent caller already committed; no CRDT update needed.
            Ok(false)
        }
        Err(e) => {
            tracing::error!("authz {authz_id_log}: on_valid transaction failed: {e}");
            Err(e)
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
///
/// `order_id` may be `None` when the caller does not have it at hand; the
/// function will retrieve it from the authorizations table in that case.
pub(super) async fn on_invalid(
    state: &AppState,
    challenge_id: &str,
    authz_id: &str,
    err: AcmeError,
    now: i64,
) -> Result<bool, sqlx::Error> {
    on_invalid_with_order(state, challenge_id, authz_id, None, err, now).await
}

async fn on_invalid_with_order(
    state: &AppState,
    challenge_id: &str,
    authz_id: &str,
    order_id: Option<&str>,
    err: AcmeError,
    now: i64,
) -> Result<bool, sqlx::Error> {
    tracing::info!("challenge {challenge_id} failed: {err}");

    let error_json = json!({
        "type": err_type(&err),
        "detail": err.to_string(),
    })
    .to_string();

    let authz_id_log = authz_id.to_string();

    let result: Result<bool, sqlx::Error> = if let Some(ref coal) = state.write_coalescer {
        coal.submit_on_invalid(
            challenge_id.to_string(),
            authz_id.to_string(),
            order_id.map(|s| s.to_string()),
            error_json.clone(),
            now,
        )
        .await
        .map_err(|e| sqlx::Error::Protocol(e.to_string()))
    } else {
        async {
            let mut tx = crate::db::begin_write(&state.db, state.db_kind)
                .await
                .map_err(|e| sqlx::Error::Protocol(e.to_string()))?;
            crate::db::pg_local_async_commit(&mut tx, state.db_kind).await?;

            let chall_rows = crate::db::query(
                "UPDATE challenges SET status = 'invalid', error = ?, updated = ?
                     WHERE id = ? AND status = 'processing'",
            )
            .bind(&error_json)
            .bind(now)
            .bind(challenge_id)
            .execute(&mut *tx)
            .await?
            .rows_affected();

            if chall_rows == 0 {
                tx.commit().await?;
                return Ok(false);
            }

            crate::db::query(
                "UPDATE authorizations SET status = 'invalid', updated = ? WHERE id = ?",
            )
            .bind(now)
            .bind(authz_id)
            .execute(&mut *tx)
            .await?;

            let oid: Option<String> = if let Some(oid) = order_id {
                Some(oid.to_owned())
            } else {
                crate::db::query_as::<(String,)>("SELECT order_id FROM authorizations WHERE id = ?")
                    .bind(authz_id)
                    .fetch_optional(&mut *tx)
                    .await?
                    .map(|(s,)| s)
            };

            if let Some(oid) = oid {
                crate::db::query(
                    "UPDATE orders SET status = 'invalid', error = ?, updated = ? WHERE id = ?",
                )
                .bind(&error_json)
                .bind(now)
                .bind(&oid)
                .execute(&mut *tx)
                .await?;
            }

            tx.commit().await?;
            Ok(true)
        }
        .await
    };

    match result {
        Ok(true) => {
            state
                .record_audit(
                    crate::audit::AuditEvent::failure(
                        crate::audit::AuditEventType::AuthChallengeFail,
                    )
                    .with_subject(authz_id),
                )
                .await;
            Ok(true)
        }
        Ok(false) => {
            // Challenge already transitioned; no audit needed.
            Ok(false)
        }
        Err(e) => {
            tracing::error!("authz {authz_id_log}: on_invalid transaction failed: {e}");
            Err(e)
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use crate::config::{CaConfig, Config, DatabaseConfig, ServerConfig};
    use crate::state::{AppState, AppStateBuilder, CaState, MtcState};
    use crate::{ca, db};

    async fn make_state() -> Arc<AppState> {
        let dir = tempfile::TempDir::new().unwrap();
        let config = Arc::new(Config {
            listen_addr: "127.0.0.1:0".into(),
            base_url: "https://acme.test".into(),
            database: DatabaseConfig {
                url: "sqlite::memory:".into(),
                max_connections: None,
                require_tls: false,
            },
            cas: vec![CaConfig {
                id: "default".to_owned(),
                is_default: true,
                caa_identities: vec![],
                key_file: Some(dir.path().join("ca.key").to_string_lossy().into_owned()),
                cert_file: dir.path().join("ca.crt").to_string_lossy().into_owned(),
                key_type: "ec:P-256".into(),
                hash_alg: "sha256".into(),
                validity_days: 90,
                crl_url: None,
                ocsp_url: None,
                common_name: "Val Test CA".into(),
                organization: "Test".into(),
                ca_validity_years: 10,
                crl_next_update_secs: 86400,
                enforce_validity_cap: false,
                require_encrypted_key: false,
                key_password_file: None,
                mtc: None,
                default_linter: None,
                signer: None,
            }],
            mtc: None,
            server: ServerConfig::default(),
            tls: Default::default(),
            profiles: Default::default(),
            linter: Default::default(),
            admin: None,
            email_challenge: None,
            delegation_upstream: None,
            gossip: None,
            crdt_db_url: None,
            tkauth: None,
        });

        let (ca_key, ca_cert_der) = ca::init::load_or_generate(config.default_ca()).unwrap();
        db::install_drivers();
        let db_conn = db::open("sqlite::memory:", 1, false).await.unwrap();

        let ca = Arc::new(CaState {
            id: "default".into(),
            key_type: "ec:P-256".into(),
            signing: crate::state::SigningBackend::Local {
                key: Box::new(ca_key),
            },
            cert_der: ca_cert_der,
            hash_alg: "sha256".into(),
            validity_days: 90,
            crl_url: None,
            ocsp_url: None,
            aki_bytes: Vec::new(),
            enforce_validity_cap: false,
            crl_next_update_secs: 604800,
            caa_identities: vec![],
            mtc: Arc::new(MtcState::disabled()),
            default_linter: None,
            cached_der: std::sync::OnceLock::new(),
            lint_store: std::sync::OnceLock::new(),
        });
        let mut cas_map = indexmap::IndexMap::new();
        cas_map.insert("default".to_string(), ca.clone());
        AppStateBuilder::new(
            Arc::clone(&config),
            db_conn.clone(),
            crate::db::DbKind::Sqlite,
            Arc::new(cas_map),
            Arc::new("default".to_string()),
        )
        .node_id(Arc::new("test".to_string()))
        .build()
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
        let client = {
            let https = hyper_rustls::HttpsConnectorBuilder::new()
                .with_native_roots()
                .expect("native roots")
                .https_or_http()
                .enable_http1()
                .build();
            hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
                .build(https)
        };
        let result = dispatch(DispatchParams {
            chall_type: "bogus-type",
            id_type: "dns",
            id_value: "example.com",
            key_auth: "key-auth",
            token: "token",
            http_port: 80,
            http_allow_private_ips: false,
            issuer_domains: &["acme.test"],
            dns_persist01_resolver_addr: None,
            validate_dnssec: false,
            dot_server_name: None,
            validation_client: &client,
            onion_csr_der: None,
            challenge_created: 0,
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
        let _ = on_invalid(
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
        let _ = on_valid(
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
                account_id: "1",
                authority_token: None,
                challenge_created: 0,
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
                ca_id: String::new(),
                kerberos_principal: None,
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
                ca_id: "default".to_string(),
                delegation_id: None,
                allow_cert_get: 0,
                upstream_order_url: None,
                upstream_cert_url: None,
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
                ca_id: "default".to_string(),
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
                status: "processing".to_string(),
                token: "mytoken".to_string(),
                validated: None,
                error: None,
                created: now,
                updated: now,
                email_token_part1: None,
                email_message_id: None,
                tkauth_type: None,
                token_authority: None,
            },
        )
        .await
        .unwrap();

        // Call on_valid — should update challenge, authz, and order status.
        on_valid(&state, &chall_id, &authz_id, &order_id, now)
            .await
            .unwrap();

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
                ca_id: String::new(),
                kerberos_principal: None,
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
                ca_id: "default".to_string(),
                delegation_id: None,
                allow_cert_get: 0,
                upstream_order_url: None,
                upstream_cert_url: None,
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
                ca_id: "default".to_string(),
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
                // on_invalid's idempotency guard requires AND status = 'processing'.
                status: "processing".to_string(),
                token: "mytoken".to_string(),
                validated: None,
                error: None,
                created: now,
                updated: now,
                email_token_part1: None,
                email_message_id: None,
                tkauth_type: None,
                token_authority: None,
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
        .await
        .unwrap();

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
                require_tls: false,
            },
            cas: vec![CaConfig {
                id: "default".to_owned(),
                is_default: true,
                caa_identities: vec![],
                key_file: Some(dir.path().join("ca.key").to_string_lossy().into_owned()),
                cert_file: dir.path().join("ca.crt").to_string_lossy().into_owned(),
                key_type: "ec:P-256".into(),
                hash_alg: "sha256".into(),
                validity_days: 90,
                crl_url: None,
                ocsp_url: None,
                common_name: "Val Test CA".into(),
                organization: "Test".into(),
                ca_validity_years: 10,
                crl_next_update_secs: 86400,
                enforce_validity_cap: false,
                require_encrypted_key: false,
                key_password_file: None,
                mtc: None,
                default_linter: None,
                signer: None,
            }],
            mtc: None,
            server: ServerConfig {
                http_validation_port: addr.port(),
                http_validation_allow_private_ips: true,
                ..ServerConfig::default()
            },
            tls: Default::default(),
            profiles: Default::default(),
            linter: Default::default(),
            admin: None,
            email_challenge: None,
            delegation_upstream: None,
            gossip: None,
            crdt_db_url: None,
            tkauth: None,
        });
        let (ca_key, ca_cert_der) = ca::init::load_or_generate(config.default_ca()).unwrap();
        db::install_drivers();
        let db_conn = db::open("sqlite::memory:", 1, false).await.unwrap();
        let ca = Arc::new(CaState {
            id: "default".into(),
            key_type: "ec:P-256".into(),
            signing: crate::state::SigningBackend::Local {
                key: Box::new(ca_key),
            },
            cert_der: ca_cert_der,
            hash_alg: "sha256".into(),
            validity_days: 90,
            crl_url: None,
            ocsp_url: None,
            aki_bytes: Vec::new(),
            enforce_validity_cap: false,
            crl_next_update_secs: 604800,
            caa_identities: vec![],
            mtc: Arc::new(MtcState::disabled()),
            default_linter: None,
            cached_der: std::sync::OnceLock::new(),
            lint_store: std::sync::OnceLock::new(),
        });
        let mut cas_map = indexmap::IndexMap::new();
        cas_map.insert("default".to_string(), ca.clone());
        let state = AppStateBuilder::new(
            Arc::clone(&config),
            db_conn.clone(),
            crate::db::DbKind::Sqlite,
            Arc::new(cas_map),
            Arc::new("default".to_string()),
        )
        .node_id(Arc::new("test".to_string()))
        .build();

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
                ca_id: String::new(),
                kerberos_principal: None,
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
                ca_id: "default".to_string(),
                delegation_id: None,
                allow_cert_get: 0,
                upstream_order_url: None,
                upstream_cert_url: None,
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
                ca_id: "default".to_string(),
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
                // The route handler always sets the challenge to "processing" before
                // calling validate_challenge; mirror that here so on_valid's idempotency
                // guard (AND status = 'processing') fires correctly.
                status: "processing".to_string(),
                token: token.to_string(),
                validated: None,
                error: None,
                created: now,
                updated: now,
                email_token_part1: None,
                email_message_id: None,
                tkauth_type: None,
                token_authority: None,
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
                account_id: "1",
                authority_token: None,
                challenge_created: 0,
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
        let _ = on_valid(&state, "fake-chall", "fake-authz", "fake-order", unix_now()).await;
    }

    /// Call on_invalid with a raw (no-schema) DB so set_invalid fails immediately.
    /// Covers on_invalid transaction Err path → warn.
    #[tokio::test]
    async fn on_invalid_db_error_set_invalid_fails() {
        let raw_db = raw_no_schema_pool().await;
        let state = make_state_with_db(raw_db).await;
        // on_invalid tries to begin a transaction and execute UPDATE on challenges;
        // fails on no-table DB → warns.
        let _ = on_invalid(
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
        let _ = on_valid(
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
        use crate::config::{CaConfig, Config, DatabaseConfig, ServerConfig};
        use crate::state::{AppStateBuilder, CaState, MtcState};
        let dir = tempfile::TempDir::new().unwrap();
        let config = Arc::new(Config {
            listen_addr: "127.0.0.1:0".into(),
            base_url: "https://acme.test".into(),
            database: DatabaseConfig {
                url: "sqlite::memory:".into(),
                max_connections: None,
                require_tls: false,
            },
            cas: vec![CaConfig {
                id: "default".to_owned(),
                is_default: true,
                caa_identities: vec![],
                key_file: Some(dir.path().join("ca-p.key").to_string_lossy().into_owned()),
                cert_file: dir.path().join("ca-p.crt").to_string_lossy().into_owned(),
                key_type: "ec:P-256".into(),
                hash_alg: "sha256".into(),
                validity_days: 90,
                crl_url: None,
                ocsp_url: None,
                common_name: "Test CA".into(),
                organization: "Test".into(),
                ca_validity_years: 10,
                crl_next_update_secs: 86400,
                enforce_validity_cap: false,
                require_encrypted_key: false,
                key_password_file: None,
                mtc: None,
                default_linter: None,
                signer: None,
            }],
            mtc: None,
            server: ServerConfig::default(),
            tls: Default::default(),
            profiles: Default::default(),
            linter: Default::default(),
            admin: None,
            email_challenge: None,
            delegation_upstream: None,
            gossip: None,
            crdt_db_url: None,
            tkauth: None,
        });
        let (ca_key, ca_cert_der) = crate::ca::init::load_or_generate(config.default_ca()).unwrap();
        let ca = Arc::new(CaState {
            id: "default".into(),
            key_type: "ec:P-256".into(),
            signing: crate::state::SigningBackend::Local {
                key: Box::new(ca_key),
            },
            cert_der: ca_cert_der,
            hash_alg: "sha256".into(),
            validity_days: 90,
            crl_url: None,
            ocsp_url: None,
            aki_bytes: Vec::new(),
            enforce_validity_cap: false,
            crl_next_update_secs: 604800,
            caa_identities: vec![],
            mtc: Arc::new(MtcState::disabled()),
            default_linter: None,
            cached_der: std::sync::OnceLock::new(),
            lint_store: std::sync::OnceLock::new(),
        });
        let mut cas_map = indexmap::IndexMap::new();
        cas_map.insert("default".to_string(), ca.clone());
        AppStateBuilder::new(
            config,
            db,
            crate::db::DbKind::Sqlite,
            Arc::new(cas_map),
            Arc::new("default".to_string()),
        )
        .node_id(Arc::new("test".to_string()))
        .build()
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
                ca_id: String::new(),
                kerberos_principal: None,
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
                ca_id: "default".to_string(),
                delegation_id: None,
                allow_cert_get: 0,
                upstream_order_url: None,
                upstream_cert_url: None,
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
                ca_id: "default".to_string(),
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
                // Both on_valid and on_invalid require AND status = 'processing'.
                status: "processing".into(),
                token: "tok".into(),
                validated: None,
                error: None,
                created: now,
                updated: now,
                email_token_part1: None,
                email_message_id: None,
                tkauth_type: None,
                token_authority: None,
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
        let db_conn = crate::db::open("sqlite::memory:", 1, false).await.unwrap();
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
        let _ = on_valid(&state, "chall-ov", "authz-ov", "ord-ov", unix_now()).await;
    }

    /// on_invalid where all updates succeed but the orders update fails because
    /// orders table was dropped.
    #[tokio::test]
    async fn on_invalid_orders_update_fails() {
        crate::db::install_drivers();
        let db_conn = crate::db::open("sqlite::memory:", 1, false).await.unwrap();
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
        let _ = on_invalid(
            &state,
            "chall-oi",
            "authz-oi",
            AcmeError::Connection("test".into()),
            unix_now(),
        )
        .await;
    }
}
