//! Database persistence for `AkaCrdt`.
//!
//! Loads initial CRDT state from the node's local database on startup and
//! persists changes back after gossip merges.  Each Akamu node has its own
//! local database; no shared database is required for cluster consensus.
//!
//! Call [`init_db_kind`] once at startup (before any other function) to tell
//! this module whether the pool is backed by PostgreSQL so that `?`
//! placeholders are rewritten to `$N` as needed.

use std::sync::atomic::Ordering;
use std::sync::OnceLock;

use sqlx::AnyPool;

use crate::crdt::AkaCrdt;
use crate::lww_register::LwwRegister;
use crate::types::{
    AccountEntry, AkaNodeEntry, AuthzEntry, CertEntry, ChallengeEntry, DelegationEntry,
    EabKeyEntry, MtcCheckpointEntry, MtcWriter, OperatorEntry, OrderEntry, OrderOwner,
};

// ── PostgreSQL placeholder rewriting ──────────────────────────────────────────

static IS_POSTGRES: OnceLock<bool> = OnceLock::new();

/// Tell the DB module whether the pool is backed by PostgreSQL.
///
/// Must be called once at startup, before any other function in this module.
pub fn init_db_kind(is_postgres: bool) {
    let _ = IS_POSTGRES.set(is_postgres);
}

fn pg_sql(s: &'static str) -> &'static str {
    if !IS_POSTGRES.get().copied().unwrap_or(false) {
        return s;
    }
    static CACHE: OnceLock<std::sync::Mutex<std::collections::HashMap<usize, &'static str>>> =
        OnceLock::new();
    let cache = CACHE.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()));
    let key = s.as_ptr() as usize;
    {
        let guard = cache.lock().unwrap();
        if let Some(&cached) = guard.get(&key) {
            return cached;
        }
    }
    let mut n = 0u32;
    let mut out = String::with_capacity(s.len() + 8);
    for ch in s.chars() {
        if ch == '?' {
            n += 1;
            out.push('$');
            out.push_str(&n.to_string());
        } else {
            out.push(ch);
        }
    }
    let leaked: &'static str = Box::leak(out.into_boxed_str());
    cache.lock().unwrap().insert(key, leaked);
    leaked
}

fn q<'q>(sql: &'static str) -> sqlx::query::Query<'q, sqlx::Any, sqlx::any::AnyArguments<'q>> {
    sqlx::query(pg_sql(sql))
}

fn qa<'q, O>(
    sql: &'static str,
) -> sqlx::query::QueryAs<'q, sqlx::Any, O, sqlx::any::AnyArguments<'q>>
where
    O: for<'r> sqlx::FromRow<'r, sqlx::any::AnyRow>,
{
    sqlx::query_as::<sqlx::Any, O>(pg_sql(sql))
}

// ── Public types ──────────────────────────────────────────────────────────────

/// Node KEM and signing keys.  Stored in `node_keys`; never gossiped.
pub struct NodeKeysRow {
    pub node_id: String,
    pub kem_private_key_der: Vec<u8>,
    pub kem_public_key_der: Vec<u8>,
    pub signing_private_key_der: Vec<u8>,
    pub signing_public_key_der: Vec<u8>,
    pub signing_certificate_der: Vec<u8>,
    pub created_at: i64,
}

// ── Private DB load structs ───────────────────────────────────────────────────
// Minimal projections: only the columns needed to build each CRDT entry.

#[derive(sqlx::FromRow)]
struct AccountLoad {
    id: String,
    status: String,
    contact: Option<String>,
    public_key: Vec<u8>,
    jwk_thumbprint: String,
    created: i64,
    updated: i64,
    profile_grants: Option<String>,
    ca_id: String,
    local_gen: i64,
}

#[derive(sqlx::FromRow)]
struct OrderLoad {
    id: String,
    account_id: String,
    status: String,
    expires: Option<i64>,
    identifiers: String,
    not_before: Option<i64>,
    not_after: Option<i64>,
    error: Option<String>,
    certificate_id: Option<String>,
    created: i64,
    updated: i64,
    ca_id: String,
    local_gen: i64,
}

#[derive(sqlx::FromRow)]
struct AuthzLoad {
    id: String,
    order_id: String,
    account_id: String,
    status: String,
    identifier: String,
    expires: Option<i64>,
    wildcard: i64,
    created: i64,
    updated: i64,
    ca_id: String,
    local_gen: i64,
}

#[derive(sqlx::FromRow)]
struct ChallengeLoad {
    id: String,
    authz_id: String,
    challenge_type: String, // aliased from `type` in SELECT to avoid SQL keyword conflict
    status: String,
    token: String,
    validated: Option<i64>,
    error: Option<String>,
    created: i64,
    updated: i64,
    local_gen: i64,
}

#[derive(sqlx::FromRow)]
struct CertLoad {
    id: String,
    order_id: String,
    account_id: String,
    serial_number: String,
    status: String,
    not_before: i64,
    not_after: i64,
    revoked_at: Option<i64>,
    revocation_reason: Option<i64>,
    created: i64,
    ca_id: String,
    local_gen: i64,
}

#[derive(sqlx::FromRow)]
struct EabKeyLoad {
    kid: String,
    hmac_key_b64u: String,
    created: i64,
    used_at: Option<i64>,
    profile_grants: Option<String>,
    local_gen: i64,
}

#[derive(sqlx::FromRow)]
struct OperatorLoad {
    id: i64,
    name: String,
    role: String,
    ca_id: String,
    active: i64,
    local_gen: i64,
}

#[derive(sqlx::FromRow)]
struct DelegationLoad {
    id: String,
    account_id: String,
    csr_template: String,
    created: i64,
    local_gen: i64,
}

#[derive(sqlx::FromRow)]
struct MtcCheckpointLoad {
    tree_size: i64,
    root_hex: String,
    signature: Vec<u8>,
    created: i64,
    local_gen: i64,
}

#[derive(sqlx::FromRow)]
struct CrdtClusterNodeLoad {
    node_id: String,
    gossip_url: String,
    kem_public_key_der: Vec<u8>,
    signing_public_key_der: Vec<u8>,
    signing_certificate_der: Vec<u8>,
    ca_ids: String,
    registered_at: i64,
    tombstone: i64,
    tombstone_at: Option<i64>,
    local_gen: i64,
}

#[derive(sqlx::FromRow)]
struct CrdtOrderOwnerLoad {
    order_id: String,
    node_id: String,
    claimed_at: i64,
    local_gen: i64,
}

#[derive(sqlx::FromRow)]
struct CrdtMtcWriterLoad {
    node_id: String,
    claimed_at: i64,
    local_gen: i64,
}

#[derive(sqlx::FromRow)]
struct NodeKeysLoad {
    node_id: String,
    kem_private_key_der: Vec<u8>,
    kem_public_key_der: Vec<u8>,
    signing_private_key_der: Vec<u8>,
    signing_public_key_der: Vec<u8>,
    signing_certificate_der: Vec<u8>,
    created_at: i64,
}

// ── Public DB functions ───────────────────────────────────────────────────────

/// Load the full `AkaCrdt` state from the node's local database.
///
/// Sets `local_gen` on each entry directly from the stored DB column so that
/// in-memory delta tracking resumes correctly after a restart.  After loading,
/// `CRDT_GENERATION` is advanced beyond all loaded generation numbers so that
/// new mutations receive strictly higher generation values.
///
/// `audit_events` and `mtc_cosignatures` GrowSets are intentionally not loaded:
/// the DB schema stores them with integer PKs incompatible with the CRDT entry
/// types.  They are repopulated via gossip on first sync after restart.
pub async fn load_from_db(pool: &AnyPool) -> Result<AkaCrdt, sqlx::Error> {
    let mut crdt = AkaCrdt::default();
    let mut max_gen: u64 = 0;

    // ── Accounts ──────────────────────────────────────────────────────────────
    let rows: Vec<AccountLoad> = sqlx::query_as(
        "SELECT id, status, contact, public_key, jwk_thumbprint, created, updated, \
         profile_grants, ca_id, local_gen FROM accounts",
    )
    .fetch_all(pool)
    .await?;
    for row in rows {
        let gen = row.local_gen as u64;
        max_gen = max_gen.max(gen);
        let tombstone = matches!(row.status.as_str(), "deactivated" | "revoked");
        let entry = AccountEntry {
            account_id: row.id.clone(),
            status: row.status,
            contact: row.contact,
            public_key_der: row.public_key,
            jwk_thumbprint: row.jwk_thumbprint,
            created: row.created,
            updated: row.updated,
            profile_grants: row.profile_grants,
            ca_id: row.ca_id,
        };
        crdt.accounts.load_entry(
            row.id,
            entry,
            row.created,
            tombstone,
            tombstone.then_some(row.updated),
            gen,
        );
    }

    // ── Orders ────────────────────────────────────────────────────────────────
    let rows: Vec<OrderLoad> = sqlx::query_as(
        "SELECT id, account_id, status, expires, identifiers, not_before, not_after, \
         error, certificate_id, created, updated, ca_id, local_gen FROM orders",
    )
    .fetch_all(pool)
    .await?;
    for row in rows {
        let gen = row.local_gen as u64;
        max_gen = max_gen.max(gen);
        let tombstone = row.status == "invalid";
        let entry = OrderEntry {
            order_id: row.id.clone(),
            account_id: row.account_id,
            status: row.status,
            expires: row.expires,
            identifiers: row.identifiers,
            not_before: row.not_before,
            not_after: row.not_after,
            error: row.error,
            certificate_id: row.certificate_id,
            created: row.created,
            updated: row.updated,
            ca_id: row.ca_id,
            processing_node_id: None,
            processing_claimed_at: None,
        };
        crdt.orders.load_entry(
            row.id,
            entry,
            row.created,
            tombstone,
            tombstone.then_some(row.updated),
            gen,
        );
    }

    // ── Authorizations ────────────────────────────────────────────────────────
    let rows: Vec<AuthzLoad> = sqlx::query_as(
        "SELECT id, order_id, account_id, status, identifier, expires, wildcard, \
         created, updated, ca_id, local_gen FROM authorizations",
    )
    .fetch_all(pool)
    .await?;
    for row in rows {
        let gen = row.local_gen as u64;
        max_gen = max_gen.max(gen);
        let tombstone = matches!(
            row.status.as_str(),
            "invalid" | "expired" | "deactivated" | "revoked"
        );
        let entry = AuthzEntry {
            authz_id: row.id.clone(),
            order_id: row.order_id,
            account_id: row.account_id,
            status: row.status,
            identifier: row.identifier,
            expires: row.expires,
            wildcard: row.wildcard != 0,
            created: row.created,
            updated: row.updated,
            ca_id: row.ca_id,
        };
        crdt.authorizations.load_entry(
            row.id,
            entry,
            row.created,
            tombstone,
            tombstone.then_some(row.updated),
            gen,
        );
    }

    // ── Challenges ────────────────────────────────────────────────────────────
    // Alias `type` → `challenge_type` to avoid SQL reserved-word issues across backends.
    let rows: Vec<ChallengeLoad> = sqlx::query_as(
        "SELECT id, authz_id, type AS challenge_type, status, token, validated, error, \
         created, updated, local_gen FROM challenges",
    )
    .fetch_all(pool)
    .await?;
    for row in rows {
        let gen = row.local_gen as u64;
        max_gen = max_gen.max(gen);
        let entry = ChallengeEntry {
            challenge_id: row.id.clone(),
            authz_id: row.authz_id,
            challenge_type: row.challenge_type,
            status: row.status,
            token: row.token,
            validated: row.validated,
            error: row.error,
            created: row.created,
            updated: row.updated,
        };
        crdt.challenges
            .load_entry(row.id, LwwRegister::load(Some(entry), row.created, "", gen));
    }

    // ── Certificates ──────────────────────────────────────────────────────────
    let rows: Vec<CertLoad> = sqlx::query_as(
        "SELECT id, order_id, account_id, serial_number, status, not_before, not_after, \
         revoked_at, revocation_reason, created, ca_id, local_gen FROM certificates",
    )
    .fetch_all(pool)
    .await?;
    for row in rows {
        let gen = row.local_gen as u64;
        max_gen = max_gen.max(gen);
        let tombstone = row.status == "revoked";
        let entry = CertEntry {
            cert_id: row.id.clone(),
            order_id: row.order_id,
            account_id: row.account_id,
            serial_number: row.serial_number,
            status: row.status,
            not_before: row.not_before,
            not_after: row.not_after,
            revoked_at: row.revoked_at,
            revocation_reason: row.revocation_reason,
            created: row.created,
            ca_id: row.ca_id,
        };
        crdt.certificates
            .load_entry(row.id, entry, row.created, tombstone, row.revoked_at, gen);
    }

    // ── EAB Keys ──────────────────────────────────────────────────────────────
    let rows: Vec<EabKeyLoad> = sqlx::query_as(
        "SELECT kid, hmac_key_b64u, created, used_at, profile_grants, local_gen FROM eab_keys",
    )
    .fetch_all(pool)
    .await?;
    for row in rows {
        let gen = row.local_gen as u64;
        max_gen = max_gen.max(gen);
        let entry = EabKeyEntry {
            kid: row.kid.clone(),
            hmac_key_b64u: row.hmac_key_b64u,
            created: row.created,
            used_at: row.used_at,
            profile_grants: row.profile_grants,
        };
        crdt.eab_keys.load_entry(
            row.kid,
            LwwRegister::load(Some(entry), row.created, "", gen),
        );
    }

    // ── Operators ─────────────────────────────────────────────────────────────
    // operators.created_at is TEXT (RFC 3339); not mapped to OperatorEntry.created (i64).
    let rows: Vec<OperatorLoad> =
        sqlx::query_as("SELECT id, name, role, ca_id, active, local_gen FROM operators")
            .fetch_all(pool)
            .await?;
    for row in rows {
        let gen = row.local_gen as u64;
        max_gen = max_gen.max(gen);
        let tombstone = row.active == 0;
        let entry = OperatorEntry {
            operator_id: row.id,
            name: row.name,
            role: row.role,
            ca_id: row.ca_id,
            created: 0,
        };
        crdt.operators
            .load_entry(row.id.to_string(), entry, 0, tombstone, None, gen);
    }

    // ── Delegations ───────────────────────────────────────────────────────────
    // delegations table has no ca_id column; DelegationEntry.ca_id is left empty.
    let rows: Vec<DelegationLoad> =
        sqlx::query_as("SELECT id, account_id, csr_template, created, local_gen FROM delegations")
            .fetch_all(pool)
            .await?;
    for row in rows {
        let gen = row.local_gen as u64;
        max_gen = max_gen.max(gen);
        let entry = DelegationEntry {
            delegation_id: row.id.clone(),
            account_id: row.account_id,
            csr_template: row.csr_template,
            created: row.created,
            ca_id: String::new(),
        };
        crdt.delegations
            .load_entry(row.id, entry, row.created, false, None, gen);
    }

    // ── MTC Checkpoints ───────────────────────────────────────────────────────
    let rows: Vec<MtcCheckpointLoad> = sqlx::query_as(
        "SELECT tree_size, root_hex, signature, created, local_gen FROM mtc_checkpoints",
    )
    .fetch_all(pool)
    .await?;
    for row in rows {
        let gen = row.local_gen as u64;
        max_gen = max_gen.max(gen);
        let tree_size = row.tree_size as u64;
        let entry = MtcCheckpointEntry {
            tree_size,
            root_hex: row.root_hex,
            signature: row.signature,
            created_at: row.created,
        };
        crdt.mtc_checkpoints.load_entry(
            tree_size,
            LwwRegister::load(Some(entry), row.created, "", gen),
        );
    }

    // ── CRDT cluster nodes ────────────────────────────────────────────────────
    let rows: Vec<CrdtClusterNodeLoad> = sqlx::query_as(
        "SELECT node_id, gossip_url, kem_public_key_der, signing_public_key_der, \
         signing_certificate_der, ca_ids, registered_at, tombstone, tombstone_at, \
         local_gen FROM crdt_cluster_nodes",
    )
    .fetch_all(pool)
    .await?;
    for row in rows {
        let gen = row.local_gen as u64;
        max_gen = max_gen.max(gen);
        let tombstone = row.tombstone != 0;
        let ca_ids: Vec<String> = serde_json::from_str(&row.ca_ids).unwrap_or_default();
        let entry = AkaNodeEntry {
            node_id: row.node_id.clone(),
            gossip_url: row.gossip_url,
            kem_public_key_der: row.kem_public_key_der,
            gossip_signing_pub_key_der: row.signing_public_key_der,
            gossip_signing_cert_der: row.signing_certificate_der,
            ca_ids,
            registered_at: row.registered_at,
        };
        crdt.cluster_nodes.load_entry(
            row.node_id,
            entry,
            row.registered_at,
            tombstone,
            row.tombstone_at,
            gen,
        );
    }

    // ── CRDT order owners ─────────────────────────────────────────────────────
    let rows: Vec<CrdtOrderOwnerLoad> =
        sqlx::query_as("SELECT order_id, node_id, claimed_at, local_gen FROM crdt_order_owners")
            .fetch_all(pool)
            .await?;
    for row in rows {
        let gen = row.local_gen as u64;
        max_gen = max_gen.max(gen);
        let owner = OrderOwner {
            node_id: row.node_id.clone(),
            claimed_at: row.claimed_at,
        };
        crdt.order_owners.load_entry(
            row.order_id,
            LwwRegister::load(Some(owner), row.claimed_at, &row.node_id, gen),
        );
    }

    // ── CRDT MTC writer ───────────────────────────────────────────────────────
    // At most one row (id = 'singleton').
    let rows: Vec<CrdtMtcWriterLoad> =
        sqlx::query_as("SELECT node_id, claimed_at, local_gen FROM crdt_mtc_writer")
            .fetch_all(pool)
            .await?;
    if let Some(row) = rows.into_iter().next() {
        let gen = row.local_gen as u64;
        max_gen = max_gen.max(gen);
        let writer = MtcWriter {
            node_id: row.node_id.clone(),
            claimed_at: row.claimed_at,
        };
        crdt.mtc_writer = LwwRegister::load(Some(writer), row.claimed_at, &row.node_id, gen);
    }

    // Advance CRDT_GENERATION beyond all loaded entries so new mutations receive
    // strictly higher generation numbers than anything already synced to peers.
    if max_gen > 0 {
        crate::generation::CRDT_GENERATION.fetch_max(max_gen, Ordering::Relaxed);
    }

    Ok(crdt)
}

/// Persist the full in-memory CRDT state to the node's local database.
///
/// - `crdt_cluster_nodes`, `crdt_order_owners`, `crdt_mtc_writer`: fully
///   replaced (DELETE + INSERT) since this node owns all columns.
/// - ACME tables: UPDATE-only for CRDT-tracked fields (status, revocation,
///   local_gen).  New entries received via gossip that have no matching row
///   in the local DB are skipped — they will be re-gossiped after restart.
///   Inserts for locally-created entries happen via write-path hooks (Phase 3).
pub async fn persist_crdt(pool: &AnyPool, crdt: &AkaCrdt) -> Result<(), sqlx::Error> {
    // ── CRDT cluster nodes (full replace) ─────────────────────────────────────
    q("DELETE FROM crdt_cluster_nodes").execute(pool).await?;
    for (node_id, entry) in crdt.cluster_nodes.all_entries() {
        let ca_ids_json = serde_json::to_string(&entry.value.ca_ids).unwrap_or_default();
        q("INSERT INTO crdt_cluster_nodes \
           (node_id, gossip_url, kem_public_key_der, signing_public_key_der, \
            signing_certificate_der, ca_ids, registered_at, tombstone, tombstone_at, local_gen) \
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
        .bind(node_id.as_str())
        .bind(&entry.value.gossip_url)
        .bind(&entry.value.kem_public_key_der)
        .bind(&entry.value.gossip_signing_pub_key_der)
        .bind(&entry.value.gossip_signing_cert_der)
        .bind(&ca_ids_json)
        .bind(entry.value.registered_at)
        .bind(entry.tombstone as i64)
        .bind(entry.tombstone_at)
        .bind(entry.local_gen as i64)
        .execute(pool)
        .await?;
    }

    // ── CRDT order owners (full replace) ──────────────────────────────────────
    q("DELETE FROM crdt_order_owners").execute(pool).await?;
    for (order_id, register) in crdt.order_owners.all_entries() {
        if let Some(owner) = register.get() {
            q(
                "INSERT INTO crdt_order_owners (order_id, node_id, claimed_at, local_gen) \
               VALUES (?, ?, ?, ?)",
            )
            .bind(order_id.as_str())
            .bind(&owner.node_id)
            .bind(owner.claimed_at)
            .bind(register.local_gen() as i64)
            .execute(pool)
            .await?;
        }
    }

    // ── CRDT MTC writer (full replace) ────────────────────────────────────────
    q("DELETE FROM crdt_mtc_writer").execute(pool).await?;
    if let Some(writer) = crdt.mtc_writer.get() {
        q(
            "INSERT INTO crdt_mtc_writer (id, node_id, claimed_at, local_gen) \
           VALUES ('singleton', ?, ?, ?)",
        )
        .bind(&writer.node_id)
        .bind(writer.claimed_at)
        .bind(crdt.mtc_writer.local_gen() as i64)
        .execute(pool)
        .await?;
    }

    // ── ACME tables: UPDATE CRDT-tracked fields ────────────────────────────────

    for (id, entry) in crdt.accounts.all_entries() {
        q("UPDATE accounts SET status = ?, local_gen = ? WHERE id = ?")
            .bind(&entry.value.status)
            .bind(entry.local_gen as i64)
            .bind(id.as_str())
            .execute(pool)
            .await?;
    }

    for (id, entry) in crdt.orders.all_entries() {
        q(
            "UPDATE orders SET status = ?, certificate_id = ?, error = ?, updated = ?, \
           local_gen = ? WHERE id = ?",
        )
        .bind(&entry.value.status)
        .bind(entry.value.certificate_id.as_deref())
        .bind(entry.value.error.as_deref())
        .bind(entry.value.updated)
        .bind(entry.local_gen as i64)
        .bind(id.as_str())
        .execute(pool)
        .await?;
    }

    for (id, entry) in crdt.authorizations.all_entries() {
        q("UPDATE authorizations SET status = ?, updated = ?, local_gen = ? WHERE id = ?")
            .bind(&entry.value.status)
            .bind(entry.value.updated)
            .bind(entry.local_gen as i64)
            .bind(id.as_str())
            .execute(pool)
            .await?;
    }

    for (id, register) in crdt.challenges.all_entries() {
        if let Some(ch) = register.get() {
            q(
                "UPDATE challenges SET status = ?, validated = ?, error = ?, updated = ?, \
               local_gen = ? WHERE id = ?",
            )
            .bind(&ch.status)
            .bind(ch.validated)
            .bind(ch.error.as_deref())
            .bind(ch.updated)
            .bind(register.local_gen() as i64)
            .bind(id.as_str())
            .execute(pool)
            .await?;
        }
    }

    for (id, entry) in crdt.certificates.all_entries() {
        q(
            "UPDATE certificates SET status = ?, revoked_at = ?, revocation_reason = ?, \
           local_gen = ? WHERE id = ?",
        )
        .bind(&entry.value.status)
        .bind(entry.value.revoked_at)
        .bind(entry.value.revocation_reason)
        .bind(entry.local_gen as i64)
        .bind(id.as_str())
        .execute(pool)
        .await?;
    }

    for (kid, register) in crdt.eab_keys.all_entries() {
        if let Some(k) = register.get() {
            q("UPDATE eab_keys SET used_at = ?, local_gen = ? WHERE kid = ?")
                .bind(k.used_at)
                .bind(register.local_gen() as i64)
                .bind(kid.as_str())
                .execute(pool)
                .await?;
        }
    }

    for (key, entry) in crdt.operators.all_entries() {
        if let Ok(id) = key.parse::<i64>() {
            q("UPDATE operators SET active = ?, local_gen = ? WHERE id = ?")
                .bind(if entry.tombstone { 0i64 } else { 1i64 })
                .bind(entry.local_gen as i64)
                .bind(id)
                .execute(pool)
                .await?;
        }
    }

    for (id, entry) in crdt.delegations.all_entries() {
        q("UPDATE delegations SET local_gen = ? WHERE id = ?")
            .bind(entry.local_gen as i64)
            .bind(id.as_str())
            .execute(pool)
            .await?;
    }

    for (tree_size, register) in crdt.mtc_checkpoints.all_entries() {
        q("UPDATE mtc_checkpoints SET local_gen = ? WHERE tree_size = ?")
            .bind(register.local_gen() as i64)
            .bind(*tree_size as i64)
            .execute(pool)
            .await?;
    }

    Ok(())
}

/// Upsert a single order ownership claim to `crdt_order_owners`.
///
/// Called from write-path hooks after `AkaCrdt::claim_order` succeeds so the
/// claim survives a restart without waiting for the next full persist.
pub async fn persist_order_owner(
    pool: &AnyPool,
    order_id: &str,
    owner: &OrderOwner,
    local_gen: u64,
) -> Result<(), sqlx::Error> {
    let updated = q(
        "UPDATE crdt_order_owners SET node_id = ?, claimed_at = ?, local_gen = ? \
         WHERE order_id = ?",
    )
    .bind(&owner.node_id)
    .bind(owner.claimed_at)
    .bind(local_gen as i64)
    .bind(order_id)
    .execute(pool)
    .await?;

    if updated.rows_affected() == 0 {
        q(
            "INSERT INTO crdt_order_owners (order_id, node_id, claimed_at, local_gen) \
           VALUES (?, ?, ?, ?)",
        )
        .bind(order_id)
        .bind(&owner.node_id)
        .bind(owner.claimed_at)
        .bind(local_gen as i64)
        .execute(pool)
        .await?;
    }

    Ok(())
}

/// Upsert the MTC writer election to `crdt_mtc_writer` (singleton row).
pub async fn persist_mtc_writer(
    pool: &AnyPool,
    writer: &MtcWriter,
    local_gen: u64,
) -> Result<(), sqlx::Error> {
    let updated = q(
        "UPDATE crdt_mtc_writer SET node_id = ?, claimed_at = ?, local_gen = ? \
         WHERE id = 'singleton'",
    )
    .bind(&writer.node_id)
    .bind(writer.claimed_at)
    .bind(local_gen as i64)
    .execute(pool)
    .await?;

    if updated.rows_affected() == 0 {
        q(
            "INSERT INTO crdt_mtc_writer (id, node_id, claimed_at, local_gen) \
           VALUES ('singleton', ?, ?, ?)",
        )
        .bind(&writer.node_id)
        .bind(writer.claimed_at)
        .bind(local_gen as i64)
        .execute(pool)
        .await?;
    }

    Ok(())
}

/// Load this node's KEM and signing keys from `node_keys`.
///
/// Returns `None` on first startup; the caller generates keys and calls
/// [`save_node_keys`].
pub async fn load_node_keys(
    pool: &AnyPool,
    node_id: &str,
) -> Result<Option<NodeKeysRow>, sqlx::Error> {
    let row: Option<NodeKeysLoad> = qa("SELECT node_id, kem_private_key_der, kem_public_key_der, \
         signing_private_key_der, signing_public_key_der, signing_certificate_der, \
         created_at FROM node_keys WHERE node_id = ?")
    .bind(node_id)
    .fetch_optional(pool)
    .await?;

    Ok(row.map(|r| NodeKeysRow {
        node_id: r.node_id,
        kem_private_key_der: r.kem_private_key_der,
        kem_public_key_der: r.kem_public_key_der,
        signing_private_key_der: r.signing_private_key_der,
        signing_public_key_der: r.signing_public_key_der,
        signing_certificate_der: r.signing_certificate_der,
        created_at: r.created_at,
    }))
}

/// Persist this node's KEM and signing keys to `node_keys`.
///
/// Safe to call on both first startup (INSERT) and key rotation (UPDATE).
pub async fn save_node_keys(pool: &AnyPool, row: &NodeKeysRow) -> Result<(), sqlx::Error> {
    let updated = q(
        "UPDATE node_keys SET kem_private_key_der = ?, kem_public_key_der = ?, \
         signing_private_key_der = ?, signing_public_key_der = ?, \
         signing_certificate_der = ?, created_at = ? WHERE node_id = ?",
    )
    .bind(&row.kem_private_key_der)
    .bind(&row.kem_public_key_der)
    .bind(&row.signing_private_key_der)
    .bind(&row.signing_public_key_der)
    .bind(&row.signing_certificate_der)
    .bind(row.created_at)
    .bind(&row.node_id)
    .execute(pool)
    .await?;

    if updated.rows_affected() == 0 {
        q("INSERT INTO node_keys \
           (node_id, kem_private_key_der, kem_public_key_der, \
            signing_private_key_der, signing_public_key_der, \
            signing_certificate_der, created_at) \
           VALUES (?, ?, ?, ?, ?, ?, ?)")
        .bind(&row.node_id)
        .bind(&row.kem_private_key_der)
        .bind(&row.kem_public_key_der)
        .bind(&row.signing_private_key_der)
        .bind(&row.signing_public_key_der)
        .bind(&row.signing_certificate_der)
        .bind(row.created_at)
        .execute(pool)
        .await?;
    }

    Ok(())
}
