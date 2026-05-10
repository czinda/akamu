//! RFC 9115 IdO→CA upstream ACME flow.
//!
//! When `[delegation_upstream]` is configured, Akamu acts as an IdO that places
//! orders with an upstream CA on behalf of NDC delegation orders.  This module
//! spawns a background task that polls for delegation orders in `processing` state
//! and drives them through the upstream ACME protocol:
//!
//! 1. Obtain an ACME account on the upstream CA (loaded from `account_key_file`).
//! 2. For each `processing` order without an `upstream_order_url`: place Order2.
//! 3. Solve challenges for each pending authorization using the configured solver.
//! 4. Finalize Order2 with the NDC's CSR; poll until `valid`.
//! 5. Store `upstream_cert_url` and advance Order1 to `valid`.

use std::sync::Arc;
use std::time::Duration;

use akamu_client::{
    account::{Account, AccountKey},
    client::AcmeClient,
    error::ClientError,
    types::{AccountOptions, Identifier, Order},
};

const ACME_ERROR_ACCOUNT_NOT_EXIST: &str = "urn:ietf:params:acme:error:accountDoesNotExist";

use crate::config::DelegationUpstreamConfig;
use crate::db;
use crate::db::schema::OrderRow;
use crate::state::AppState;
use crate::util::unix_now;

/// Spawn the upstream delegation background task.
///
/// Returns `None` when `[delegation_upstream]` is not configured.
pub fn spawn(state: Arc<AppState>) -> Option<tokio::task::JoinHandle<()>> {
    state.config.delegation_upstream.as_ref()?;
    Some(tokio::spawn(async move {
        run_loop(state).await;
    }))
}

async fn run_loop(state: Arc<AppState>) {
    let du = match state.config.delegation_upstream.as_ref() {
        Some(du) => du.clone(),
        None => return,
    };

    // Initialise the AcmeClient and account once; retry with exponential backoff on failure.
    let (client, account) = {
        let mut delay = Duration::from_secs(5);
        loop {
            match init_client_and_account(&du).await {
                Ok(pair) => break pair,
                Err(e) => {
                    tracing::error!(
                        "delegation_upstream: initialisation failed: {e}; retrying in {}s",
                        delay.as_secs()
                    );
                    tokio::time::sleep(delay).await;
                    delay = (delay * 2).min(Duration::from_secs(300));
                }
            }
        }
    };
    let account = Arc::new(account);

    loop {
        run_once(&state, &du, &client, &account).await;
        tokio::time::sleep(Duration::from_secs(du.poll_interval_secs)).await;
    }
}

/// Load the upstream ACME account, registering a new one if it does not exist.
async fn init_client_and_account(
    du: &DelegationUpstreamConfig,
) -> Result<(AcmeClient, Account), String> {
    let pem = tokio::fs::read(&du.account_key_file)
        .await
        .map_err(|e| format!("read account_key_file {:?}: {e}", du.account_key_file))?;
    let key =
        Arc::new(AccountKey::from_pem(&pem).map_err(|e| format!("parse account key PEM: {e}"))?);
    let client = AcmeClient::new_https_only(&du.directory_url)
        .await
        .map_err(|e| format!("AcmeClient::new({}): {e}", du.directory_url))?;

    let contact_refs: Vec<&str> = du.contacts.iter().map(|s| s.as_str()).collect();

    let account = match client.find_account(Arc::clone(&key)).await {
        Ok(acct) => {
            tracing::info!(
                url = %acct.url,
                "delegation_upstream: found existing upstream ACME account"
            );
            acct
        }
        Err(ClientError::Acme { ref acme_type, .. })
            if acme_type == ACME_ERROR_ACCOUNT_NOT_EXIST =>
        {
            tracing::info!(
                directory = %du.directory_url,
                "delegation_upstream: registering new upstream ACME account"
            );
            let opts = AccountOptions {
                contacts: &contact_refs,
                agree_tos: true,
                eab: None,
            };
            client
                .new_account(Arc::clone(&key), &opts)
                .await
                .map_err(|e| format!("new_account: {e}"))?
        }
        Err(e) => return Err(format!("find_account: {e}")),
    };
    Ok((client, account))
}

/// One iteration: collect all `processing` delegation orders and drive each.
async fn run_once(
    state: &AppState,
    du: &DelegationUpstreamConfig,
    client: &AcmeClient,
    account: &Arc<Account>,
) {
    let orders = match db::orders::list_pending_delegation_orders(&state.db).await {
        Ok(v) => v,
        Err(e) => {
            tracing::error!("delegation_upstream: list_pending_delegation_orders: {e}");
            return;
        }
    };

    for order in orders {
        let order_id = order.id.clone();
        let upstream_url = order.upstream_order_url.clone();
        if let Err(e) = drive_order(state, du, client, account, order).await {
            tracing::error!(
                order_id = %order_id,
                upstream_url = ?upstream_url,
                "delegation_upstream: drive_order: {e}"
            );
        }
    }
}

/// Drive a single delegation order through the upstream ACME protocol.
async fn drive_order(
    state: &AppState,
    du: &DelegationUpstreamConfig,
    client: &AcmeClient,
    account: &Arc<Account>,
    order: OrderRow,
) -> Result<(), String> {
    let now = unix_now();

    // ── Step 1: place Order2 on the upstream CA if not yet done ──────────────
    let upstream_order_url = if let Some(ref url) = order.upstream_order_url {
        url.clone()
    } else {
        let raw: Vec<serde_json::Value> =
            serde_json::from_str::<Vec<serde_json::Value>>(&order.identifiers)
                .map_err(|e| format!("parse identifiers JSON: {e}"))?;

        let identifiers: Vec<Identifier> = raw
            .into_iter()
            .enumerate()
            .map(|(i, v)| {
                let id_type = v["type"]
                    .as_str()
                    .ok_or_else(|| format!("identifier[{i}] missing 'type' field"))?
                    .to_string();
                let value = v["value"]
                    .as_str()
                    .ok_or_else(|| format!("identifier[{i}] missing 'value' field"))?
                    .to_string();
                Ok(Identifier {
                    r#type: id_type,
                    value,
                })
            })
            .collect::<Result<Vec<_>, String>>()?;

        if identifiers.is_empty() {
            return Err("delegation order has no valid identifiers; cannot place Order2".into());
        }

        let order2 = client
            .new_order(account, &identifiers)
            .await
            .map_err(|e| format!("new_order on upstream CA: {e}"))?;
        let url = order2.url.clone();
        db::orders::set_upstream_order_url(&state.db, &order.id, &url, now)
            .await
            .map_err(|e| format!("set_upstream_order_url: {e}"))?;
        tracing::info!(
            order_id = %order.id,
            upstream_url = %url,
            "delegation_upstream: placed Order2 on upstream CA"
        );
        url
    };

    // ── Step 2: poll Order2 status ────────────────────────────────────────────
    let order2 = client
        .poll_order(account, &upstream_order_url)
        .await
        .map_err(|e| format!("poll_order: {e}"))?;

    match order2.status.as_str() {
        "pending" => {
            // Satisfy pending authorizations.
            satisfy_authorizations(du, client, account, &order2, &order.id).await?;
        }
        "ready" => {
            // All authzs validated — run dns-01 cleanup before finalizing.
            if du.challenge_solver == "dns-01" {
                if let Some(ref cleanup) = du.challenge_cleanup_script {
                    cleanup_all_authorizations(du, client, account, &order2, &order.id, cleanup)
                        .await;
                }
            }
            finalize_upstream(state, client, account, &order2, &order, now).await?;
        }
        "processing" => {
            tracing::debug!(order_id = %order.id, "delegation_upstream: upstream Order2 still processing");
        }
        "valid" => {
            // Cert is ready.
            complete_order(state, &order2, &order.id, now).await?;
        }
        "invalid" => {
            tracing::warn!(
                order_id = %order.id,
                upstream = %upstream_order_url,
                "delegation_upstream: upstream Order2 is invalid; marking Order1 invalid"
            );
            let err_json = serde_json::json!({
                "type": "urn:ietf:params:acme:error:serverInternal",
                "detail": "upstream CA rejected the order"
            })
            .to_string();
            db::orders::update_status(&state.db, &order.id, "invalid", Some(err_json), now)
                .await
                .map_err(|e| format!("update_status to invalid: {e}"))?;
        }
        other => {
            tracing::warn!(
                order_id = %order.id,
                status = %other,
                "delegation_upstream: unexpected upstream Order2 status"
            );
        }
    }
    Ok(())
}

/// Satisfy any pending authorizations using the configured challenge solver.
///
/// When an authorization is already `valid`, runs the dns-01 cleanup script if configured.
/// Cleanup is deferred to this point (not immediately after triggering) so the CA has time
/// to query the deployed TXT record before it is removed.
async fn satisfy_authorizations(
    du: &DelegationUpstreamConfig,
    client: &AcmeClient,
    account: &Arc<Account>,
    order2: &Order,
    order1_id: &str,
) -> Result<(), String> {
    for authz_url in &order2.authorizations {
        let authz = client
            .get_authorization(account, authz_url)
            .await
            .map_err(|e| format!("get_authorization({authz_url}): {e}"))?;

        if authz.status == "valid" {
            // Authz transitioned to valid — remove the deployed TXT record.
            if du.challenge_solver == "dns-01" {
                if let Some(ref cleanup) = du.challenge_cleanup_script {
                    run_dns01_cleanup(du, account, cleanup, &authz, order1_id).await;
                }
            }
            continue;
        }
        if authz.status != "pending" {
            return Err(format!(
                "authorization {authz_url} has status '{}', cannot solve",
                authz.status
            ));
        }

        let challenge = authz.find_challenge(&du.challenge_solver).ok_or_else(|| {
            format!(
                "authorization {authz_url}: no {} challenge found",
                du.challenge_solver
            )
        })?;

        let token = challenge
            .token
            .as_deref()
            .ok_or_else(|| format!("challenge {}: missing token", challenge.url))?;

        let key_auth = account.key_authorization(token);

        // Deploy the challenge.
        match du.challenge_solver.as_str() {
            "dns-01" => {
                let txt = akamu_client::challenge::Dns01Helper::txt_value(&key_auth)
                    .map_err(|e| format!("Dns01Helper::txt_value: {e}"))?;
                let deploy = du
                    .challenge_deploy_script
                    .as_deref()
                    .ok_or("challenge_deploy_script required for dns-01 but not configured")?;
                let domain = bare_domain(&authz.identifier.value);
                run_deploy_script(deploy, &domain, &txt)
                    .await
                    .map_err(|e| format!("challenge_deploy_script: {e}"))?;
                tracing::info!(
                    order_id = %order1_id,
                    domain = %domain,
                    "delegation_upstream: deployed dns-01 TXT record"
                );
            }
            other => {
                return Err(format!(
                    "challenge solver '{other}' is not supported in this version"
                ));
            }
        }

        // Trigger the challenge on the upstream CA.
        // Cleanup is intentionally deferred: it runs on the next poll cycle when
        // the authorization transitions to 'valid', ensuring the CA has time to
        // query the DNS TXT record before it is removed.
        client
            .trigger_challenge(account, challenge)
            .await
            .map_err(|e| format!("trigger_challenge({}): {e}", challenge.url))?;
    }
    Ok(())
}

/// Best-effort dns-01 cleanup for a single already-valid authorization.
async fn run_dns01_cleanup(
    _du: &DelegationUpstreamConfig,
    account: &Arc<Account>,
    cleanup_script: &str,
    authz: &akamu_client::types::Authorization,
    order1_id: &str,
) {
    let Some(ch) = authz.find_challenge("dns-01") else {
        return;
    };
    let Some(token) = ch.token.as_deref() else {
        return;
    };
    let key_auth = account.key_authorization(token);
    let Ok(txt) = akamu_client::challenge::Dns01Helper::txt_value(&key_auth) else {
        return;
    };
    let domain = bare_domain(&authz.identifier.value);
    if let Err(e) = run_cleanup_script(cleanup_script, &domain, &txt).await {
        tracing::warn!(order_id = %order1_id, "challenge_cleanup_script: {e}");
    }
}

/// Run dns-01 cleanup for every authorization in an order (used in the `ready` branch).
async fn cleanup_all_authorizations(
    du: &DelegationUpstreamConfig,
    client: &AcmeClient,
    account: &Arc<Account>,
    order2: &Order,
    order1_id: &str,
    cleanup_script: &str,
) {
    for authz_url in &order2.authorizations {
        match client.get_authorization(account, authz_url).await {
            Ok(authz) => {
                run_dns01_cleanup(du, account, cleanup_script, &authz, order1_id).await;
            }
            Err(e) => {
                tracing::warn!(
                    order_id = %order1_id,
                    authz_url = %authz_url,
                    "delegation_upstream: get_authorization for cleanup: {e}"
                );
            }
        }
    }
}

/// Finalize the upstream Order2 with the NDC's CSR DER.
async fn finalize_upstream(
    state: &AppState,
    client: &AcmeClient,
    account: &Arc<Account>,
    order2: &Order,
    order1: &OrderRow,
    now: i64,
) -> Result<(), String> {
    let csr_der = order1
        .star_csr_der
        .clone()
        .ok_or("delegation order has no stored CSR DER")?;

    let finalized = client
        .finalize(account, order2, &csr_der)
        .await
        .map_err(|e| format!("finalize on upstream CA: {e}"))?;

    // Update upstream_order_url to the finalized order's URL (may have changed).
    db::orders::set_upstream_order_url(&state.db, &order1.id, &finalized.url, now)
        .await
        .map_err(|e| format!("set_upstream_order_url after finalize: {e}"))?;

    tracing::info!(
        order_id = %order1.id,
        finalize_url = %order2.finalize,
        "delegation_upstream: submitted finalize to upstream CA"
    );
    Ok(())
}

/// Order2 is `valid` — store the cert URL and advance Order1 to `valid`.
async fn complete_order(
    state: &AppState,
    order2: &Order,
    order1_id: &str,
    now: i64,
) -> Result<(), String> {
    let cert_url = order2
        .certificate
        .as_deref()
        .ok_or("upstream Order2 is valid but has no certificate URL")?;

    db::orders::set_upstream_cert_url(&state.db, order1_id, cert_url, now)
        .await
        .map_err(|e| format!("set_upstream_cert_url: {e}"))?;

    // Advance Order1 to valid.
    db::orders::update_status(&state.db, order1_id, "valid", None, now)
        .await
        .map_err(|e| format!("update_status to valid: {e}"))?;

    tracing::info!(
        order_id = %order1_id,
        cert_url = %cert_url,
        "delegation_upstream: Order1 completed; cert URL stored"
    );
    Ok(())
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Strip the `*.` wildcard prefix from a DNS identifier value to get the bare domain.
fn bare_domain(value: &str) -> String {
    value.strip_prefix("*.").unwrap_or(value).to_string()
}

/// Run the dns-01 deploy script with CERTBOT-style environment variables.
///
/// Uses `tokio::process::Command` (non-blocking) with `env_clear` so that server
/// secrets (DATABASE_URL, etc.) cannot leak into the script's environment.
async fn run_deploy_script(path: &str, domain: &str, validation: &str) -> Result<(), String> {
    let status = tokio::time::timeout(
        Duration::from_secs(60),
        tokio::process::Command::new(path)
            .env_clear()
            .env("CERTBOT_DOMAIN", domain)
            .env("CERTBOT_VALIDATION", validation)
            .status(),
    )
    .await
    .map_err(|_| format!("deploy script {path:?} timed out after 60s"))?
    .map_err(|e| format!("execute deploy script {path:?}: {e}"))?;

    if !status.success() {
        return Err(format!(
            "deploy script {path:?} exited with status {status}"
        ));
    }
    Ok(())
}

/// Run the dns-01 cleanup script with CERTBOT-style environment variables.
///
/// `CERTBOT_AUTH_OUTPUT` is set to the empty string (no stdout capture from the deploy
/// script in the current implementation).  Cleanup failures are non-fatal and are
/// only logged at WARN level by callers.
async fn run_cleanup_script(path: &str, domain: &str, validation: &str) -> Result<(), String> {
    let status = tokio::time::timeout(
        Duration::from_secs(60),
        tokio::process::Command::new(path)
            .env_clear()
            .env("CERTBOT_DOMAIN", domain)
            .env("CERTBOT_VALIDATION", validation)
            .env("CERTBOT_AUTH_OUTPUT", "")
            .status(),
    )
    .await
    .map_err(|_| format!("cleanup script {path:?} timed out after 60s"))?
    .map_err(|e| format!("execute cleanup script {path:?}: {e}"))?;

    if !status.success() {
        return Err(format!(
            "cleanup script {path:?} exited with status {status}"
        ));
    }
    Ok(())
}
