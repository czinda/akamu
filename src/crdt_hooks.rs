//! Write-path CRDT hooks.
//!
//! Each function is called after a successful DB write to keep the in-memory
//! `AppState::crdt` replica consistent.  Errors are logged but not propagated
//! — a missed CRDT update is recoverable via gossip or server restart.

use crate::state::AppState;
use crate::status::{AccountStatus, AuthzStatus, CertStatus, ChallengeStatus, OrderStatus};
use akamu_crdt::{
    AccountEntry, AuthzEntry, CertEntry, ChallengeEntry, DelegationEntry, EabKeyEntry,
    OperatorEntry, OrderEntry, PolicyRuleEntry,
};
use std::time::Duration;

const WRITE_LOCK_TIMEOUT: Duration = Duration::from_secs(5);

// ── Parameter structs ─────────────────────────────────────────────────────────

pub struct AccountUpsertParams<'a> {
    pub id: &'a str,
    pub status: AccountStatus,
    pub contact: Option<String>,
    pub public_key_der: Vec<u8>,
    pub jwk_thumbprint: String,
    pub created: i64,
    pub updated: i64,
    pub profile_grants: Option<String>,
    pub ca_id: &'a str,
}

pub struct OrderUpsertParams<'a> {
    pub id: &'a str,
    pub account_id: &'a str,
    pub status: OrderStatus,
    pub expires: Option<i64>,
    pub identifiers: &'a str,
    pub not_before: Option<i64>,
    pub not_after: Option<i64>,
    pub error: Option<String>,
    pub certificate_id: Option<String>,
    pub created: i64,
    pub updated: i64,
    pub ca_id: &'a str,
}

pub struct AuthzUpsertParams<'a> {
    pub id: &'a str,
    pub order_id: &'a str,
    pub account_id: &'a str,
    pub status: AuthzStatus,
    pub identifier: &'a str,
    pub expires: Option<i64>,
    pub wildcard: bool,
    pub created: i64,
    pub updated: i64,
    pub ca_id: &'a str,
}

pub struct ChallengeSetParams<'a> {
    pub id: &'a str,
    pub authz_id: &'a str,
    pub challenge_type: &'a str,
    pub status: ChallengeStatus,
    pub token: &'a str,
    pub validated: Option<i64>,
    pub error: Option<String>,
    pub created: i64,
    pub updated: i64,
}

pub struct CertUpsertParams<'a> {
    pub id: &'a str,
    pub order_id: &'a str,
    pub account_id: &'a str,
    pub serial_number: &'a str,
    pub status: CertStatus,
    pub not_before: i64,
    pub not_after: i64,
    pub revoked_at: Option<i64>,
    pub revocation_reason: Option<i64>,
    pub created: i64,
    pub ca_id: &'a str,
}

/// Acquire the CRDT write lock with a timeout to prevent admin handlers from
/// hanging indefinitely if the lock is held by a blocked reader.
macro_rules! write_lock_or_return {
    ($state:expr) => {
        match tokio::time::timeout(WRITE_LOCK_TIMEOUT, $state.crdt.write()).await {
            Ok(guard) => guard,
            Err(_) => {
                tracing::error!(
                    timeout_secs = WRITE_LOCK_TIMEOUT.as_secs(),
                    "CRDT write-lock acquisition timed out — skipping update (gossip will recover)"
                );
                return;
            }
        }
    };
}

// ── Gossip gate ───────────────────────────────────────────────────────────────
// In single-node deployments (no gossip configured) there are no peers to
// replicate to, so maintaining the in-memory CRDT and persisting local_gen
// would be pure overhead.  Every public hook returns early when gossip is off.
#[inline(always)]
fn gossip_enabled(state: &AppState) -> bool {
    let enabled = state.config.gossip.is_some();
    if !enabled {
        static LOGGED: std::sync::Once = std::sync::Once::new();
        LOGGED.call_once(|| {
            tracing::debug!("CRDT hooks disabled — gossip not configured (single-node mode)");
        });
    }
    enabled
}

// ── Accounts ──────────────────────────────────────────────────────────────────

pub async fn on_account_upsert(state: &AppState, p: AccountUpsertParams<'_>) {
    if !gossip_enabled(state) {
        return;
    }
    let entry = AccountEntry {
        account_id: p.id.to_string(),
        status: p.status.as_str().to_string(),
        contact: p.contact,
        public_key_der: p.public_key_der,
        jwk_thumbprint: p.jwk_thumbprint,
        created: p.created,
        updated: p.updated,
        profile_grants: p.profile_grants,
        ca_id: p.ca_id.to_string(),
    };
    {
        let mut crdt = write_lock_or_return!(state);
        crdt.accounts.upsert(p.id.to_string(), entry, p.updated)
    };
    state.write_notify.notify_one();
}

pub async fn on_account_tombstone(state: &AppState, id: &str, now: i64) {
    if !gossip_enabled(state) {
        return;
    }
    {
        let mut crdt = write_lock_or_return!(state);
        crdt.accounts.remove(&id.to_string(), now)
    };
    state.write_notify.notify_one();
}

// ── Orders ────────────────────────────────────────────────────────────────────

pub async fn on_order_upsert(state: &AppState, p: OrderUpsertParams<'_>) {
    if !gossip_enabled(state) {
        return;
    }
    let entry = OrderEntry {
        order_id: p.id.to_string(),
        account_id: p.account_id.to_string(),
        status: p.status.as_str().to_string(),
        expires: p.expires,
        identifiers: p.identifiers.to_string(),
        not_before: p.not_before,
        not_after: p.not_after,
        error: p.error,
        certificate_id: p.certificate_id,
        created: p.created,
        updated: p.updated,
        ca_id: p.ca_id.to_string(),
        processing_node_id: None,
        processing_claimed_at: None,
    };
    {
        let mut crdt = write_lock_or_return!(state);
        crdt.orders.upsert(p.id.to_string(), entry, p.updated)
    };
    state.write_notify.notify_one();
}

pub async fn on_order_tombstone(state: &AppState, id: &str, now: i64) {
    if !gossip_enabled(state) {
        return;
    }
    {
        let mut crdt = write_lock_or_return!(state);
        crdt.orders.remove(&id.to_string(), now)
    };
    state.write_notify.notify_one();
}

// ── Authorizations ────────────────────────────────────────────────────────────

pub async fn on_authz_upsert(state: &AppState, p: AuthzUpsertParams<'_>) {
    if !gossip_enabled(state) {
        return;
    }
    let entry = AuthzEntry {
        authz_id: p.id.to_string(),
        order_id: p.order_id.to_string(),
        account_id: p.account_id.to_string(),
        status: p.status.as_str().to_string(),
        identifier: p.identifier.to_string(),
        expires: p.expires,
        wildcard: p.wildcard,
        created: p.created,
        updated: p.updated,
        ca_id: p.ca_id.to_string(),
    };
    {
        let mut crdt = write_lock_or_return!(state);
        crdt.authorizations
            .upsert(p.id.to_string(), entry, p.updated)
    };
    state.write_notify.notify_one();
}

pub async fn on_authz_tombstone(state: &AppState, id: &str, now: i64) {
    if !gossip_enabled(state) {
        return;
    }
    {
        let mut crdt = write_lock_or_return!(state);
        crdt.authorizations.remove(&id.to_string(), now)
    };
    state.write_notify.notify_one();
}

// ── Challenges ────────────────────────────────────────────────────────────────

pub async fn on_challenge_set(state: &AppState, p: ChallengeSetParams<'_>) {
    if !gossip_enabled(state) {
        return;
    }
    let entry = ChallengeEntry {
        challenge_id: p.id.to_string(),
        authz_id: p.authz_id.to_string(),
        challenge_type: p.challenge_type.to_string(),
        status: p.status.as_str().to_string(),
        token: p.token.to_string(),
        validated: p.validated,
        error: p.error,
        created: p.created,
        updated: p.updated,
    };
    {
        let mut crdt = write_lock_or_return!(state);
        crdt.challenges
            .set(p.id.to_string(), entry, p.updated, &state.node_id)
    };
    state.write_notify.notify_one();
}

// ── Certificates ──────────────────────────────────────────────────────────────

pub async fn on_cert_upsert(state: &AppState, p: CertUpsertParams<'_>) {
    if !gossip_enabled(state) {
        return;
    }
    let entry = CertEntry {
        cert_id: p.id.to_string(),
        order_id: p.order_id.to_string(),
        account_id: p.account_id.to_string(),
        serial_number: p.serial_number.to_string(),
        status: p.status.as_str().to_string(),
        not_before: p.not_before,
        not_after: p.not_after,
        revoked_at: p.revoked_at,
        revocation_reason: p.revocation_reason,
        created: p.created,
        ca_id: p.ca_id.to_string(),
    };
    {
        let mut crdt = write_lock_or_return!(state);
        crdt.certificates.upsert(p.id.to_string(), entry, p.created)
    };
    state.write_notify.notify_one();
}

pub async fn on_cert_tombstone(state: &AppState, id: &str, now: i64) {
    if !gossip_enabled(state) {
        return;
    }
    {
        let mut crdt = write_lock_or_return!(state);
        crdt.certificates.remove(&id.to_string(), now)
    };
    state.write_notify.notify_one();
}

// ── EAB keys ─────────────────────────────────────────────────────────────────

pub async fn on_eab_key_set(
    state: &AppState,
    kid: &str,
    hmac_key_b64u: &str,
    created: i64,
    used_at: Option<i64>,
    profile_grants: Option<String>,
) {
    if !gossip_enabled(state) {
        return;
    }
    let entry = EabKeyEntry {
        kid: kid.to_string(),
        hmac_key_b64u: hmac_key_b64u.to_string(),
        created,
        used_at,
        profile_grants,
    };
    {
        let mut crdt = write_lock_or_return!(state);
        let ts = used_at.unwrap_or(created);
        crdt.eab_keys
            .set(kid.to_string(), entry, ts, &state.node_id)
    };
    state.write_notify.notify_one();
}

// ── Operators ─────────────────────────────────────────────────────────────────

pub async fn on_operator_upsert(
    state: &AppState,
    id: i64,
    name: &str,
    role: &str,
    ca_id: &str,
    created: i64,
) {
    if !gossip_enabled(state) {
        return;
    }
    let entry = OperatorEntry {
        operator_id: id,
        name: name.to_string(),
        role: role.to_string(),
        ca_id: ca_id.to_string(),
        created,
    };
    {
        let mut crdt = write_lock_or_return!(state);
        crdt.operators.upsert(id.to_string(), entry, created)
    };
    state.write_notify.notify_one();
}

pub async fn on_operator_tombstone(state: &AppState, id: i64, now: i64) {
    if !gossip_enabled(state) {
        return;
    }
    {
        let mut crdt = write_lock_or_return!(state);
        crdt.operators.remove(&id.to_string(), now)
    };
    state.write_notify.notify_one();
}

// ── Delegations ───────────────────────────────────────────────────────────────

pub async fn on_delegation_upsert(
    state: &AppState,
    id: &str,
    account_id: &str,
    csr_template: &str,
    created: i64,
    ca_id: &str,
) {
    if !gossip_enabled(state) {
        return;
    }
    let entry = DelegationEntry {
        delegation_id: id.to_string(),
        account_id: account_id.to_string(),
        csr_template: csr_template.to_string(),
        created,
        ca_id: ca_id.to_string(),
    };
    {
        let mut crdt = write_lock_or_return!(state);
        crdt.delegations.upsert(id.to_string(), entry, created)
    };
    state.write_notify.notify_one();
}

pub async fn on_delegation_tombstone(state: &AppState, id: &str, now: i64) {
    if !gossip_enabled(state) {
        return;
    }
    {
        let mut crdt = write_lock_or_return!(state);
        crdt.delegations.remove(&id.to_string(), now)
    };
    state.write_notify.notify_one();
}

// ── Policy rules ─────────────────────────────────────────────────────────────

pub struct PolicyRuleUpsertParams<'a> {
    pub id: &'a str,
    pub scope: &'a str,
    pub name: &'a str,
    pub rule_json: &'a str,
    pub enabled: bool,
    pub created_at: &'a str,
    pub updated_at: &'a str,
    pub created_by: Option<&'a str>,
}

pub async fn on_policy_rule_upsert(state: &AppState, p: PolicyRuleUpsertParams<'_>, now: i64) {
    if !gossip_enabled(state) {
        return;
    }
    let entry = PolicyRuleEntry {
        id: p.id.to_string(),
        scope: p.scope.to_string(),
        name: p.name.to_string(),
        rule_json: p.rule_json.to_string(),
        enabled: p.enabled,
        created_at: p.created_at.to_string(),
        updated_at: p.updated_at.to_string(),
        created_by: p.created_by.map(str::to_string),
    };
    {
        let mut crdt = write_lock_or_return!(state);
        crdt.policy_rules.upsert(p.id.to_string(), entry, now)
    };
    state.write_notify.notify_one();
}

pub async fn on_policy_rule_remove(state: &AppState, id: &str, now: i64) {
    if !gossip_enabled(state) {
        return;
    }
    {
        let mut crdt = write_lock_or_return!(state);
        crdt.policy_rules.remove(&id.to_string(), now)
    };
    state.write_notify.notify_one();
}
