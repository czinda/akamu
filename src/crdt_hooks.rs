//! Write-path CRDT hooks.
//!
//! Each function is called after a successful DB write to keep the in-memory
//! `AppState::crdt` replica consistent.  Errors are logged but not propagated
//! — a missed CRDT update is recoverable via gossip or server restart.

use crate::db::query;
use crate::state::AppState;
use akamu_crdt::{
    AccountEntry, AuthzEntry, CertEntry, ChallengeEntry, DelegationEntry, EabKeyEntry,
    OperatorEntry, OrderEntry,
};

// ── Parameter structs ─────────────────────────────────────────────────────────

pub struct AccountUpsertParams<'a> {
    pub id: &'a str,
    pub status: &'a str,
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
    pub status: &'a str,
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
    pub status: &'a str,
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
    pub status: &'a str,
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
    pub status: &'a str,
    pub not_before: i64,
    pub not_after: i64,
    pub revoked_at: Option<i64>,
    pub revocation_reason: Option<i64>,
    pub created: i64,
    pub ca_id: &'a str,
}

// ── Gossip gate ───────────────────────────────────────────────────────────────
// In single-node deployments (no gossip configured) there are no peers to
// replicate to, so maintaining the in-memory CRDT and persisting local_gen
// would be pure overhead.  Every public hook returns early when gossip is off.
#[inline(always)]
fn gossip_enabled(state: &AppState) -> bool {
    state.config.gossip.is_some()
}

// ── Accounts ──────────────────────────────────────────────────────────────────

pub async fn on_account_upsert(state: &AppState, p: AccountUpsertParams<'_>) {
    if !gossip_enabled(state) {
        return;
    }
    let entry = AccountEntry {
        account_id: p.id.to_string(),
        status: p.status.to_string(),
        contact: p.contact,
        public_key_der: p.public_key_der,
        jwk_thumbprint: p.jwk_thumbprint,
        created: p.created,
        updated: p.updated,
        profile_grants: p.profile_grants,
        ca_id: p.ca_id.to_string(),
    };
    let local_gen = {
        let mut crdt = state.crdt.write().await;
        crdt.accounts.upsert(p.id.to_string(), entry, p.updated)
    };
    if let Err(e) = query("UPDATE accounts SET local_gen = CASE WHEN local_gen > ? THEN local_gen ELSE ? END WHERE id = ?")
        .bind(local_gen as i64)
        .bind(local_gen as i64)
        .bind(p.id)
        .execute(&state.db)
        .await
    {
        tracing::error!(id = %p.id, err = %e, "crdt_hook: failed to persist local_gen for account");
    }
}

pub async fn on_account_tombstone(state: &AppState, id: &str, now: i64) {
    if !gossip_enabled(state) {
        return;
    }
    let local_gen = {
        let mut crdt = state.crdt.write().await;
        crdt.accounts.remove(&id.to_string(), now)
    };
    if let Err(e) = query("UPDATE accounts SET local_gen = CASE WHEN local_gen > ? THEN local_gen ELSE ? END WHERE id = ?")
        .bind(local_gen as i64)
        .bind(local_gen as i64)
        .bind(id)
        .execute(&state.db)
        .await
    {
        tracing::error!(%id, err = %e, "crdt_hook: failed to persist local_gen for account tombstone");
    }
}

// ── Orders ────────────────────────────────────────────────────────────────────

pub async fn on_order_upsert(state: &AppState, p: OrderUpsertParams<'_>) {
    if !gossip_enabled(state) {
        return;
    }
    let entry = OrderEntry {
        order_id: p.id.to_string(),
        account_id: p.account_id.to_string(),
        status: p.status.to_string(),
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
    let local_gen = {
        let mut crdt = state.crdt.write().await;
        crdt.orders.upsert(p.id.to_string(), entry, p.updated)
    };
    if let Err(e) = query("UPDATE orders SET local_gen = CASE WHEN local_gen > ? THEN local_gen ELSE ? END WHERE id = ?")
        .bind(local_gen as i64)
        .bind(local_gen as i64)
        .bind(p.id)
        .execute(&state.db)
        .await
    {
        tracing::error!(id = %p.id, err = %e, "crdt_hook: failed to persist local_gen for order");
    }
}

pub async fn on_order_tombstone(state: &AppState, id: &str, now: i64) {
    if !gossip_enabled(state) {
        return;
    }
    let local_gen = {
        let mut crdt = state.crdt.write().await;
        crdt.orders.remove(&id.to_string(), now)
    };
    if let Err(e) = query("UPDATE orders SET local_gen = CASE WHEN local_gen > ? THEN local_gen ELSE ? END WHERE id = ?")
        .bind(local_gen as i64)
        .bind(local_gen as i64)
        .bind(id)
        .execute(&state.db)
        .await
    {
        tracing::error!(%id, err = %e, "crdt_hook: failed to persist local_gen for order tombstone");
    }
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
        status: p.status.to_string(),
        identifier: p.identifier.to_string(),
        expires: p.expires,
        wildcard: p.wildcard,
        created: p.created,
        updated: p.updated,
        ca_id: p.ca_id.to_string(),
    };
    let local_gen = {
        let mut crdt = state.crdt.write().await;
        crdt.authorizations
            .upsert(p.id.to_string(), entry, p.updated)
    };
    if let Err(e) = query("UPDATE authorizations SET local_gen = CASE WHEN local_gen > ? THEN local_gen ELSE ? END WHERE id = ?")
        .bind(local_gen as i64)
        .bind(local_gen as i64)
        .bind(p.id)
        .execute(&state.db)
        .await
    {
        tracing::error!(id = %p.id, err = %e, "crdt_hook: failed to persist local_gen for authz");
    }
}

pub async fn on_authz_tombstone(state: &AppState, id: &str, now: i64) {
    if !gossip_enabled(state) {
        return;
    }
    let local_gen = {
        let mut crdt = state.crdt.write().await;
        crdt.authorizations.remove(&id.to_string(), now)
    };
    if let Err(e) = query("UPDATE authorizations SET local_gen = CASE WHEN local_gen > ? THEN local_gen ELSE ? END WHERE id = ?")
        .bind(local_gen as i64)
        .bind(local_gen as i64)
        .bind(id)
        .execute(&state.db)
        .await
    {
        tracing::error!(%id, err = %e, "crdt_hook: failed to persist local_gen for authz tombstone");
    }
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
        status: p.status.to_string(),
        token: p.token.to_string(),
        validated: p.validated,
        error: p.error,
        created: p.created,
        updated: p.updated,
    };
    let local_gen = {
        let mut crdt = state.crdt.write().await;
        crdt.challenges
            .set(p.id.to_string(), entry, p.updated, &state.node_id)
    };
    if let Err(e) = query("UPDATE challenges SET local_gen = CASE WHEN local_gen > ? THEN local_gen ELSE ? END WHERE id = ?")
        .bind(local_gen as i64)
        .bind(local_gen as i64)
        .bind(p.id)
        .execute(&state.db)
        .await
    {
        tracing::error!(id = %p.id, err = %e, "crdt_hook: failed to persist local_gen for challenge");
    }
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
        status: p.status.to_string(),
        not_before: p.not_before,
        not_after: p.not_after,
        revoked_at: p.revoked_at,
        revocation_reason: p.revocation_reason,
        created: p.created,
        ca_id: p.ca_id.to_string(),
    };
    let local_gen = {
        let mut crdt = state.crdt.write().await;
        crdt.certificates.upsert(p.id.to_string(), entry, p.created)
    };
    if let Err(e) = query("UPDATE certificates SET local_gen = CASE WHEN local_gen > ? THEN local_gen ELSE ? END WHERE id = ?")
        .bind(local_gen as i64)
        .bind(local_gen as i64)
        .bind(p.id)
        .execute(&state.db)
        .await
    {
        tracing::error!(id = %p.id, err = %e, "crdt_hook: failed to persist local_gen for certificate");
    }
}

pub async fn on_cert_tombstone(state: &AppState, id: &str, now: i64) {
    if !gossip_enabled(state) {
        return;
    }
    let local_gen = {
        let mut crdt = state.crdt.write().await;
        crdt.certificates.remove(&id.to_string(), now)
    };
    if let Err(e) = query("UPDATE certificates SET local_gen = CASE WHEN local_gen > ? THEN local_gen ELSE ? END WHERE id = ?")
        .bind(local_gen as i64)
        .bind(local_gen as i64)
        .bind(id)
        .execute(&state.db)
        .await
    {
        tracing::error!(%id, err = %e, "crdt_hook: failed to persist local_gen for certificate tombstone");
    }
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
    let local_gen = {
        let mut crdt = state.crdt.write().await;
        let ts = used_at.unwrap_or(created);
        crdt.eab_keys
            .set(kid.to_string(), entry, ts, &state.node_id)
    };
    if let Err(e) = query("UPDATE eab_keys SET local_gen = CASE WHEN local_gen > ? THEN local_gen ELSE ? END WHERE kid = ?")
        .bind(local_gen as i64)
        .bind(local_gen as i64)
        .bind(kid)
        .execute(&state.db)
        .await
    {
        tracing::error!(%kid, err = %e, "crdt_hook: failed to persist local_gen for eab_key");
    }
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
    let local_gen = {
        let mut crdt = state.crdt.write().await;
        crdt.operators.upsert(id.to_string(), entry, created)
    };
    if let Err(e) = query("UPDATE operators SET local_gen = CASE WHEN local_gen > ? THEN local_gen ELSE ? END WHERE id = ?")
        .bind(local_gen as i64)
        .bind(local_gen as i64)
        .bind(id)
        .execute(&state.db)
        .await
    {
        tracing::error!(%id, err = %e, "crdt_hook: failed to persist local_gen for operator");
    }
}

pub async fn on_operator_tombstone(state: &AppState, id: i64, now: i64) {
    if !gossip_enabled(state) {
        return;
    }
    let local_gen = {
        let mut crdt = state.crdt.write().await;
        crdt.operators.remove(&id.to_string(), now)
    };
    if let Err(e) = query("UPDATE operators SET local_gen = CASE WHEN local_gen > ? THEN local_gen ELSE ? END WHERE id = ?")
        .bind(local_gen as i64)
        .bind(local_gen as i64)
        .bind(id)
        .execute(&state.db)
        .await
    {
        tracing::error!(%id, err = %e, "crdt_hook: failed to persist local_gen for operator tombstone");
    }
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
    let local_gen = {
        let mut crdt = state.crdt.write().await;
        crdt.delegations.upsert(id.to_string(), entry, created)
    };
    if let Err(e) = query("UPDATE delegations SET local_gen = CASE WHEN local_gen > ? THEN local_gen ELSE ? END WHERE id = ?")
        .bind(local_gen as i64)
        .bind(local_gen as i64)
        .bind(id)
        .execute(&state.db)
        .await
    {
        tracing::error!(%id, err = %e, "crdt_hook: failed to persist local_gen for delegation");
    }
}

pub async fn on_delegation_tombstone(state: &AppState, id: &str, now: i64) {
    if !gossip_enabled(state) {
        return;
    }
    let local_gen = {
        let mut crdt = state.crdt.write().await;
        crdt.delegations.remove(&id.to_string(), now)
    };
    if let Err(e) = query("UPDATE delegations SET local_gen = CASE WHEN local_gen > ? THEN local_gen ELSE ? END WHERE id = ?")
        .bind(local_gen as i64)
        .bind(local_gen as i64)
        .bind(id)
        .execute(&state.db)
        .await
    {
        tracing::error!(%id, err = %e, "crdt_hook: failed to persist local_gen for delegation tombstone");
    }
}
