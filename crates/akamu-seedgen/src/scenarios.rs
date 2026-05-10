//! Per-scenario issuance loop and state distribution logic.

use akamu::db;
use akamu::db::schema::{DelegationRow, OrderRow};
use akamu_client::{
    client::AcmeClient,
    csr::build_csr,
    types::{Identifier, Order, StarOrderParams},
    Account,
};
use rand::Rng;
use uuid::Uuid;

use crate::{
    acme::{self, generate_leaf_key, IssuedCert},
    challenge::ChallengeResponder,
    names,
    server::SeedServer,
    spec::ScenarioSpec,
};

/// RFC 5280 revocation reason codes used in practice.
const REVOKE_REASONS: &[u8] = &[0, 1, 3, 4, 5];

/// The state postprocess.rs should apply to this cert after issuance.
#[derive(Debug, Clone)]
pub enum TargetState {
    Valid,
    Revoked {
        reason: u8,
    },
    Expired,
    NearExpiry,
    /// ARI replacement chain.  `chain_index` identifies the chain;
    /// `position` is 0 (oldest), 1 (middle), 2 (newest in a 3-cert chain).
    AriChain {
        chain_index: usize,
        position: usize,
    },
}

/// All data returned from one scenario run, consumed by postprocess.rs.
#[derive(Debug)]
pub struct ScenarioOutcome {
    pub name: String,
    /// Regular certs with their target post-processing state.
    pub issued: Vec<(IssuedCert, TargetState)>,
    /// STAR order URLs left in `valid` state (auto-renewal active).
    pub star_active_order_urls: Vec<String>,
    /// STAR order URLs that have been canceled after finalization.
    pub star_canceled_order_urls: Vec<String>,
    /// Orders in `processing` state with a `delegation_id` set (direct DB).
    pub delegation_order_urls: Vec<String>,
    /// Orders in `pending` state, never finalized.
    pub pending_order_urls: Vec<String>,
    /// Orders in `pending` state that postprocess.rs will mark `invalid`.
    pub invalid_order_urls: Vec<String>,
    pub account_count: usize,
}

/// Run a single scenario: register accounts, issue certs, create special orders.
pub async fn run_scenario(
    server: &SeedServer,
    responder: &ChallengeResponder,
    spec: &ScenarioSpec,
    rng: &mut impl Rng,
    verbose: bool,
) -> Result<ScenarioOutcome, String> {
    let mut outcome = ScenarioOutcome {
        name: spec.name.clone(),
        issued: Vec::new(),
        star_active_order_urls: Vec::new(),
        star_canceled_order_urls: Vec::new(),
        delegation_order_urls: Vec::new(),
        pending_order_urls: Vec::new(),
        invalid_order_urls: Vec::new(),
        account_count: spec.num_accounts,
    };

    let key_types = spec.certs.effective_key_types();

    // ── 1. Register accounts ──────────────────────────────────────────────────
    //
    // Accounts are registered server-wide (non-CA-scoped endpoint) so the
    // returned account URL (`/acme/account/{UUID}`) is parseable by
    // `account_id_from_kid` regardless of which CA is used for ordering.
    // A separate CA-specific client is created per account for order placement.
    // (AcmeClient fetches the directory on construction; ~1 RTT per account.)

    let mut accounts: Vec<(AcmeClient, Account)> = Vec::new();
    for _ in 0..spec.num_accounts {
        let contact = names::next_contact(rng);
        let account = acme::register_account(&server.base_url, &contact, "ec:P-256")
            .await
            .map_err(|e| format!("[{}] register account: {e}", spec.name))?;
        if verbose {
            tracing::info!(scenario = %spec.name, account = %account.url, "account registered");
        }
        let client = acme::new_ca_client(&server.base_url, &spec.ca_id)
            .await
            .map_err(|e| format!("[{}] init CA client: {e}", spec.name))?;
        accounts.push((client, account));
    }

    let n = accounts.len();
    let ctx = IssueCtx {
        responder,
        spec,
        n,
        accounts: &accounts,
        key_types: &key_types,
        verbose,
    };

    // ── 2. Valid certs ────────────────────────────────────────────────────────

    for _ in 0..spec.certs.valid {
        let cert = issue_one(&ctx, rng).await?;
        outcome.issued.push((cert, TargetState::Valid));
    }

    // ── 3. Revoked certs ──────────────────────────────────────────────────────

    for _ in 0..spec.certs.revoked {
        let cert = issue_one(&ctx, rng).await?;
        let reason = REVOKE_REASONS[rng.gen_range(0..REVOKE_REASONS.len())];
        outcome.issued.push((cert, TargetState::Revoked { reason }));
    }

    // ── 4. Expired certs ──────────────────────────────────────────────────────

    for _ in 0..spec.certs.expired {
        let cert = issue_one(&ctx, rng).await?;
        outcome.issued.push((cert, TargetState::Expired));
    }

    // ── 5. Near-expiry certs ──────────────────────────────────────────────────

    for _ in 0..spec.certs.near_expiry {
        let cert = issue_one(&ctx, rng).await?;
        outcome.issued.push((cert, TargetState::NearExpiry));
    }

    // ── 6. ARI replacement chains ─────────────────────────────────────────────
    // 3 certs per chain: position 0 = oldest, 1 = middle, 2 = newest.

    for chain_idx in 0..spec.certs.ari_chains {
        for pos in 0..3 {
            let cert = issue_one(&ctx, rng).await?;
            outcome.issued.push((
                cert,
                TargetState::AriChain {
                    chain_index: chain_idx,
                    position: pos,
                },
            ));
        }
    }

    // ── 7. STAR orders ────────────────────────────────────────────────────────
    // Issue star_canceled first so that cancellation index i < star_canceled.

    let star_total = spec.certs.star_canceled + spec.certs.star_active;
    for i in 0..star_total {
        let acct_idx = rng.gen_range(0..n);
        let (client, account) = (&accounts[acct_idx].0, &accounts[acct_idx].1);
        let key_type = names::pick_key_type(rng, &key_types);
        let domains = names::next_domains(rng, &spec.name, 1);
        let ids: Vec<Identifier> = domains.iter().map(Identifier::dns).collect();

        let star_url =
            run_star_order(client, account, responder, &ids, &key_type, spec, verbose).await?;

        if i < spec.certs.star_canceled {
            client
                .cancel_star_order(account, &star_url)
                .await
                .map_err(|e| format!("[{}] cancel_star_order: {e}", spec.name))?;
            outcome.star_canceled_order_urls.push(star_url);
        } else {
            outcome.star_active_order_urls.push(star_url);
        }
    }

    // ── 8. Delegation orders (direct DB) ──────────────────────────────────────

    let now = unix_now();
    for _ in 0..spec.certs.delegation {
        let acct_idx = rng.gen_range(0..n);
        let account = &accounts[acct_idx].1;
        let domains = names::next_domains(rng, &spec.name, 1);

        let order_url = create_delegation_order(server, account, &spec.ca_id, &domains, now)
            .await
            .map_err(|e| format!("[{}] create delegation order: {e}", spec.name))?;
        if verbose {
            tracing::info!(scenario = %spec.name, %order_url, "delegation order created");
        }
        outcome.delegation_order_urls.push(order_url);
    }

    // ── 9. Pending orders (ACME new-order, no challenge resolution) ───────────

    for _ in 0..spec.certs.pending_orders {
        let acct_idx = rng.gen_range(0..n);
        let (client, account) = (&accounts[acct_idx].0, &accounts[acct_idx].1);
        let domains = names::next_domains(rng, &spec.name, 1);
        let ids: Vec<Identifier> = domains.iter().map(Identifier::dns).collect();
        let order = client
            .new_order_with_profile(account, &ids, spec.profile_id.as_deref())
            .await
            .map_err(|e| format!("[{}] new_order (pending): {e}", spec.name))?;
        outcome.pending_order_urls.push(order.url);
    }

    // ── 10. Orders postprocess.rs will mark invalid ───────────────────────────

    for _ in 0..spec.certs.invalid_orders {
        let acct_idx = rng.gen_range(0..n);
        let (client, account) = (&accounts[acct_idx].0, &accounts[acct_idx].1);
        let domains = names::next_domains(rng, &spec.name, 1);
        let ids: Vec<Identifier> = domains.iter().map(Identifier::dns).collect();
        let order = client
            .new_order_with_profile(account, &ids, spec.profile_id.as_deref())
            .await
            .map_err(|e| format!("[{}] new_order (will-be-invalid): {e}", spec.name))?;
        outcome.invalid_order_urls.push(order.url);
    }

    // ── 11. Deactivate accounts ───────────────────────────────────────────────

    for (client, account) in accounts
        .iter()
        .take(spec.accounts.deactivated)
        .map(|(c, a)| (c, a))
    {
        client
            .deactivate_account(account)
            .await
            .map_err(|e| format!("[{}] deactivate_account: {e}", spec.name))?;
        if verbose {
            tracing::info!(scenario = %spec.name, account = %account.url, "account deactivated");
        }
    }

    Ok(outcome)
}

// ── Private helpers ───────────────────────────────────────────────────────────

/// Bundled context for `issue_one` (avoids the too-many-arguments lint).
struct IssueCtx<'a> {
    responder: &'a ChallengeResponder,
    spec: &'a ScenarioSpec,
    n: usize,
    accounts: &'a [(AcmeClient, Account)],
    key_types: &'a std::collections::HashMap<String, u32>,
    verbose: bool,
}

/// Issue a single cert via the full ACME HTTP-01 flow, with retry on transient
/// challenge-validation failures (e.g. momentary connection errors to the
/// challenge responder that cause the order to go invalid).
async fn issue_one(ctx: &IssueCtx<'_>, rng: &mut impl Rng) -> Result<IssuedCert, String> {
    const MAX_ATTEMPTS: u32 = 4;
    const RETRY_DELAYS_MS: &[u64] = &[2_000, 5_000, 10_000];

    let acct_idx = rng.gen_range(0..ctx.n);
    let (client, account) = (&ctx.accounts[acct_idx].0, &ctx.accounts[acct_idx].1);
    let key_type = names::pick_key_type(rng, ctx.key_types);
    let domains = names::next_domains(rng, &ctx.spec.name, 1);

    let mut last_err = String::new();
    for attempt in 0..MAX_ATTEMPTS {
        if attempt > 0 {
            let delay_ms = RETRY_DELAYS_MS[(attempt as usize - 1).min(RETRY_DELAYS_MS.len() - 1)];
            tracing::warn!(
                scenario = %ctx.spec.name,
                attempt,
                delay_ms,
                "retrying cert issuance after transient challenge failure"
            );
            tokio::time::sleep(tokio::time::Duration::from_millis(delay_ms)).await;
        }

        match acme::issue_cert(
            client,
            account,
            ctx.responder,
            &domains,
            &key_type,
            ctx.spec.profile_id.as_deref(),
            &ctx.spec.ca_id,
        )
        .await
        {
            Ok(cert) => {
                if ctx.verbose {
                    tracing::info!(scenario = %ctx.spec.name, order = %cert.order_url, "cert issued");
                }
                return Ok(cert);
            }
            Err(e) => {
                let msg = e.to_string();
                // Only retry on order-invalid errors caused by challenge validation
                // failures (connection errors, timeouts). Any other error is fatal.
                if msg.contains("order invalid") || msg.contains("connection error") {
                    last_err = format!("[{}] issue cert: {msg}", ctx.spec.name);
                    continue;
                }
                return Err(format!("[{}] issue cert: {msg}", ctx.spec.name));
            }
        }
    }

    Err(last_err)
}

/// Drive the full ACME flow for a STAR order; return the order URL.
///
/// Uses a fixed far-future end_date since seedgen does not simulate real
/// STAR scheduling — it only needs the order row to exist in the right state.
async fn run_star_order(
    client: &AcmeClient,
    account: &Account,
    responder: &ChallengeResponder,
    ids: &[Identifier],
    key_type: &str,
    spec: &ScenarioSpec,
    verbose: bool,
) -> Result<String, String> {
    const STAR_END_DATE: &str = "2030-01-01T00:00:00Z";
    const STAR_LIFETIME_SECS: u64 = 86400;

    let star_order = client
        .new_star_order(
            account,
            &StarOrderParams {
                identifiers: ids,
                end_date: STAR_END_DATE,
                lifetime_secs: STAR_LIFETIME_SECS,
                start_date: None,
                lifetime_adjust_secs: 0,
                allow_certificate_get: false,
            },
        )
        .await
        .map_err(|e| format!("[{}] new_star_order: {e}", spec.name))?;

    let star_url = star_order.url.clone();

    // Construct a pseudo-Order so we can reuse the client's finalize/poll methods.
    let pseudo_order = Order {
        url: star_order.url,
        status: star_order.status,
        finalize: star_order.finalize,
        authorizations: star_order.authorizations,
        certificate: None,
        identifiers: ids.to_vec(),
    };

    // Resolve HTTP-01 authorizations, keeping tokens live until poll_order
    // completes so the server can validate them (mirrors acme::issue_cert).
    let mut tokens: Vec<String> = Vec::new();
    let result: Result<Order, String> = async {
        for authz_url in &pseudo_order.authorizations {
            let authz = client
                .get_authorization(account, authz_url)
                .await
                .map_err(|e| format!("[{}] star get_authorization: {e}", spec.name))?;
            if authz.status == "valid" {
                continue;
            }
            let challenge = authz
                .find_challenge("http-01")
                .ok_or_else(|| format!("[{}] no http-01 challenge for STAR order", spec.name))?
                .clone();
            let token = challenge
                .token
                .as_deref()
                .ok_or_else(|| format!("[{}] STAR challenge missing token", spec.name))?;
            let key_auth = account.key_authorization(token);
            responder.present(token, &key_auth).await;
            tokens.push(token.to_string());
            client
                .trigger_challenge(account, &challenge)
                .await
                .map_err(|e| format!("[{}] star trigger_challenge: {e}", spec.name))?;
        }

        // Poll until ready — tokens must stay live in the responder until here.
        client
            .poll_order(account, &star_url)
            .await
            .map_err(|e| format!("[{}] star poll (ready): {e}", spec.name))
    }
    .await;
    for t in &tokens {
        responder.cleanup(t).await;
    }
    let ready_order = result?;

    // Generate key and CSR off the async executor (spawn_blocking is compatible with
    // current_thread runtimes unlike block_in_place).
    let key_type_owned = key_type.to_string();
    let scenario_name = spec.name.clone();
    let cert_key = tokio::task::spawn_blocking(move || generate_leaf_key(&key_type_owned))
        .await
        .map_err(|e| format!("[{scenario_name}] star key gen task panicked: {e}"))?
        .map_err(|e| format!("[{scenario_name}] star key gen: {e}"))?;

    let domain_strs: Vec<&str> = ids
        .iter()
        .filter_map(|id| {
            if id.r#type == "dns" {
                Some(id.value.as_str())
            } else {
                None
            }
        })
        .collect();
    let csr_der =
        build_csr(&domain_strs, &cert_key).map_err(|e| format!("[{}] star CSR: {e}", spec.name))?;

    // Finalize and poll until valid.
    let finalized = client
        .finalize(account, &ready_order, &csr_der)
        .await
        .map_err(|e| format!("[{}] star finalize: {e}", spec.name))?;
    if finalized.status != "valid" {
        client
            .poll_order(account, &star_url)
            .await
            .map_err(|e| format!("[{}] star poll (valid): {e}", spec.name))?;
    }

    if verbose {
        tracing::info!(scenario = %spec.name, %star_url, "STAR order finalized");
    }
    Ok(star_url)
}

/// Insert a delegation order and its `DelegationRow` directly into the DB.
///
/// The order is placed in `processing` state with a throwaway CSR DER and a
/// fake upstream order URL, simulating an IdO→CA delegation in flight.
async fn create_delegation_order(
    server: &SeedServer,
    account: &Account,
    ca_id: &str,
    domains: &[String],
    now: i64,
) -> Result<String, akamu::error::AcmeError> {
    let san_entries: Vec<serde_json::Value> = domains
        .iter()
        .map(|d| serde_json::json!({"type": "dns", "value": d}))
        .collect();
    let csr_template = serde_json::json!({ "san": san_entries }).to_string();

    // accounts.id is the UUID from the account URL's last path segment,
    // not the full URL that the ACME client stores in Account::url.
    let account_db_id = account
        .url
        .rsplit('/')
        .next()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            akamu::error::AcmeError::Internal(format!(
                "account URL has no path segment: {}",
                account.url
            ))
        })?
        .to_string();

    let delegation_id = Uuid::new_v4().to_string();
    db::delegations::insert(
        &server.db,
        DelegationRow {
            id: delegation_id.clone(),
            account_id: account_db_id.clone(),
            csr_template,
            cname_map: None,
            created: now,
            updated: now,
        },
    )
    .await?;

    // Throwaway P-256 key + CSR for the stored `star_csr_der`.
    let throwaway_key =
        tokio::task::spawn_blocking(|| synta_certificate::BackendPrivateKey::generate_ec("P-256"))
            .await
            .map_err(|e| {
                akamu::error::AcmeError::Internal(format!(
                    "delegation CSR key gen (task panic): {e}"
                ))
            })?
            .map_err(|e| {
                akamu::error::AcmeError::Internal(format!("delegation CSR key gen: {e}"))
            })?;

    let domain_strs: Vec<&str> = domains.iter().map(String::as_str).collect();
    let csr_der = build_csr(&domain_strs, &throwaway_key)
        .map_err(|e| akamu::error::AcmeError::Internal(format!("delegation CSR build: {e}")))?;

    let order_url = format!(
        "{}/acme/{}/order/{}",
        server.base_url.trim_end_matches('/'),
        ca_id,
        Uuid::new_v4()
    );

    let identifiers_json = serde_json::json!(domains
        .iter()
        .map(|d| serde_json::json!({"type":"dns","value":d}))
        .collect::<Vec<_>>())
    .to_string();

    db::orders::insert(
        &server.db,
        OrderRow {
            id: order_url.clone(),
            account_id: account_db_id,
            status: "processing".to_string(),
            expires: Some(now + 7 * 24 * 3600),
            identifiers: identifiers_json,
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
            star_csr_der: Some(csr_der),
            profile: None,
            ca_id: ca_id.to_string(),
            delegation_id: Some(delegation_id),
            allow_cert_get: 0,
            upstream_order_url: Some(format!(
                "https://upstream-ca.acme-test.example/acme/order/{}",
                Uuid::new_v4()
            )),
            upstream_cert_url: None,
        },
    )
    .await?;

    Ok(order_url)
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock is set to before the Unix epoch")
        .as_secs() as i64
}
