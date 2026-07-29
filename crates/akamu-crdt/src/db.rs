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
    PolicyRuleEntry,
};

// ── PostgreSQL placeholder rewriting ──────────────────────────────────────────

static IS_POSTGRES: OnceLock<bool> = OnceLock::new();
static IS_MARIADB: OnceLock<bool> = OnceLock::new();

/// Tell the DB module which backend the pool is backed by.
///
/// Must be called once at startup, before any other function in this module.
pub fn init_db_kind(is_postgres: bool, is_mariadb: bool) {
    let _ = IS_POSTGRES.set(is_postgres);
    let _ = IS_MARIADB.set(is_mariadb);
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
        let guard = cache.lock().unwrap_or_else(|p| p.into_inner());
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
    cache
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .insert(key, leaked);
    leaked
}

fn q<'q>(sql: &'static str) -> sqlx::query::Query<'q, sqlx::Any, sqlx::any::AnyArguments<'q>> {
    sqlx::query(pg_sql(sql))
}

/// Build an upsert query using the dialect appropriate for the configured DB.
///
/// `sqlite_sql` uses `?` placeholders and `INSERT OR REPLACE`.
/// `mariadb_sql` uses `?` placeholders and `REPLACE INTO` (MariaDB/MySQL).
/// `pg_sql_str` uses `$N` placeholders and `INSERT ... ON CONFLICT DO UPDATE`.
fn q_upsert<'q>(
    sqlite_sql: &'static str,
    mariadb_sql: &'static str,
    pg_sql_str: &'static str,
) -> sqlx::query::Query<'q, sqlx::Any, sqlx::any::AnyArguments<'q>> {
    if IS_POSTGRES.get().copied().unwrap_or(false) {
        sqlx::query(pg_sql_str)
    } else if IS_MARIADB.get().copied().unwrap_or(false) {
        sqlx::query(mariadb_sql)
    } else {
        sqlx::query(sqlite_sql)
    }
}

/// Parse a UTC RFC 3339 string in `YYYY-MM-DDTHH:MM:SSZ` format to a Unix timestamp.
///
/// Returns 0 for malformed input. Only handles the exact format produced by
/// `util::unix_to_rfc3339`, which always emits UTC with a `Z` suffix.
fn rfc3339_utc_to_unix(s: &str) -> i64 {
    let b = s.as_bytes();
    if b.len() < 20 {
        return 0;
    }
    let p2 = |sl: &[u8]| -> i64 {
        if sl.len() < 2 {
            return 0;
        }
        (sl[0].wrapping_sub(b'0') as i64) * 10 + sl[1].wrapping_sub(b'0') as i64
    };
    let p4 = |sl: &[u8]| -> i64 { p2(sl) * 100 + p2(&sl[2..]) };
    let year = p4(b);
    let month = p2(&b[5..]);
    let day = p2(&b[8..]);
    let hour = p2(&b[11..]);
    let min = p2(&b[14..]);
    let sec = p2(&b[17..]);
    // Days since Unix epoch using https://howardhinnant.github.io/date_algorithms.html#days_from_civil
    let (y, m) = if month <= 2 {
        (year - 1, month + 9)
    } else {
        (year, month - 3)
    };
    let era = y / 400;
    let yoe = y - era * 400;
    let doy = (153 * m + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146097 + doe - 719468;
    days * 86400 + hour * 3600 + min * 60 + sec
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
}

#[derive(sqlx::FromRow)]
struct EabKeyLoad {
    kid: String,
    hmac_key_b64u: String,
    created: i64,
    used_at: Option<i64>,
    profile_grants: Option<String>,
}

#[derive(sqlx::FromRow)]
struct OperatorLoad {
    id: i64,
    name: String,
    role: String,
    ca_id: String,
    active: i64,
    created_at: String,
}

#[derive(sqlx::FromRow)]
struct DelegationLoad {
    id: String,
    account_id: String,
    csr_template: String,
    created: i64,
    ca_id: String,
}

#[derive(sqlx::FromRow)]
struct PolicyRuleLoad {
    id: String,
    scope: String,
    name: String,
    rule_json: String,
    enabled: i64,
    created_at: String,
    updated_at: String,
    created_by: Option<String>,
    local_gen: i64,
    tombstone: i64,
    tombstone_at: Option<i64>,
}

#[derive(sqlx::FromRow)]
struct MtcCheckpointLoad {
    tree_size: i64,
    root_hex: String,
    signature: Vec<u8>,
    created: i64,
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

/// Load the full `AkaCrdt` state from the node's local databases.
///
/// ACME entries (`accounts`, `orders`, etc.) are read from `main_pool` with
/// `local_gen = 0`.  After restart the first gossip round does a full-state
/// exchange regardless, so exact generation tracking on ACME entries is not
/// needed for correctness.
///
/// Cluster tables (`crdt_cluster_nodes`, `crdt_order_owners`, `crdt_mtc_writer`)
/// are read from `crdt_pool` with their stored `local_gen`, so delta gossip
/// resumes from the correct generation without a full push after restart.
///
/// `mtc_cosignatures` is intentionally not loaded: the DB schema stores them
/// with composite PKs that are repopulated via gossip on first sync after restart.
pub async fn load_from_db(
    main_pool: &AnyPool,
    crdt_pool: &AnyPool,
    node_id: &str,
) -> Result<AkaCrdt, sqlx::Error> {
    let pool = main_pool;
    let mut crdt = AkaCrdt::default();
    let mut max_gen: u64 = 0;

    // ── Accounts ──────────────────────────────────────────────────────────────
    let rows: Vec<AccountLoad> = sqlx::query_as(
        "SELECT id, status, contact, public_key, jwk_thumbprint, created, updated, \
         profile_grants, ca_id FROM accounts",
    )
    .fetch_all(pool)
    .await?;
    for row in rows {
        let gen = 0u64;
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
         error, certificate_id, created, updated, ca_id FROM orders",
    )
    .fetch_all(pool)
    .await?;
    for row in rows {
        let gen = 0u64;
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
         created, updated, ca_id FROM authorizations",
    )
    .fetch_all(pool)
    .await?;
    for row in rows {
        let gen = 0u64;
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
         created, updated FROM challenges",
    )
    .fetch_all(pool)
    .await?;
    for row in rows {
        let gen = 0u64;
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
        crdt.challenges.load_entry(
            row.id,
            LwwRegister::load(Some(entry), row.updated, node_id, gen),
        );
    }

    // ── Certificates ──────────────────────────────────────────────────────────
    let rows: Vec<CertLoad> = sqlx::query_as(
        "SELECT id, order_id, account_id, serial_number, status, not_before, not_after, \
         revoked_at, revocation_reason, created, ca_id FROM certificates",
    )
    .fetch_all(pool)
    .await?;
    for row in rows {
        let gen = 0u64;
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
    let rows: Vec<EabKeyLoad> =
        sqlx::query_as("SELECT kid, hmac_key_b64u, created, used_at, profile_grants FROM eab_keys")
            .fetch_all(pool)
            .await?;
    for row in rows {
        let gen = 0u64;
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
            LwwRegister::load(Some(entry), row.created, node_id, gen),
        );
    }

    // ── Operators ─────────────────────────────────────────────────────────────
    let rows: Vec<OperatorLoad> =
        sqlx::query_as("SELECT id, name, role, ca_id, active, created_at FROM operators")
            .fetch_all(pool)
            .await?;
    for row in rows {
        let gen = 0u64;
        max_gen = max_gen.max(gen);
        let tombstone = row.active == 0;
        let created = rfc3339_utc_to_unix(&row.created_at);
        let entry = OperatorEntry {
            operator_id: row.id,
            name: row.name,
            role: row.role,
            ca_id: row.ca_id,
            created,
        };
        crdt.operators
            .load_entry(row.id.to_string(), entry, created, tombstone, None, gen);
    }

    // ── Delegations ───────────────────────────────────────────────────────────
    let rows: Vec<DelegationLoad> =
        sqlx::query_as("SELECT id, account_id, csr_template, created, ca_id FROM delegations")
            .fetch_all(pool)
            .await?;
    for row in rows {
        let gen = 0u64;
        max_gen = max_gen.max(gen);
        let entry = DelegationEntry {
            delegation_id: row.id.clone(),
            account_id: row.account_id,
            csr_template: row.csr_template,
            created: row.created,
            ca_id: row.ca_id,
        };
        crdt.delegations
            .load_entry(row.id, entry, row.created, false, None, gen);
    }

    // ── Policy rules ─────────────────────────────────────────────────────────
    let rows: Vec<PolicyRuleLoad> = sqlx::query_as(
        "SELECT id, scope, name, rule_json, enabled, created_at, updated_at, \
         created_by, local_gen, tombstone, tombstone_at FROM policy_rules",
    )
    .fetch_all(pool)
    .await?;
    for row in rows {
        let gen = row.local_gen as u64;
        max_gen = max_gen.max(gen);
        let created = rfc3339_utc_to_unix(&row.created_at);
        let tombstone = row.tombstone != 0;
        let entry = PolicyRuleEntry {
            id: row.id.clone(),
            scope: row.scope,
            name: row.name,
            rule_json: row.rule_json,
            enabled: row.enabled != 0,
            created_at: row.created_at,
            updated_at: row.updated_at,
            created_by: row.created_by,
        };
        crdt.policy_rules
            .load_entry(row.id, entry, created, tombstone, row.tombstone_at, gen);
    }

    // ── MTC Checkpoints ───────────────────────────────────────────────────────
    let rows: Vec<MtcCheckpointLoad> =
        sqlx::query_as("SELECT tree_size, root_hex, signature, created FROM mtc_checkpoints")
            .fetch_all(pool)
            .await?;
    for row in rows {
        let gen = 0u64;
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
            LwwRegister::load(Some(entry), row.created, node_id, gen),
        );
    }

    // ── CRDT cluster nodes ────────────────────────────────────────────────────
    let rows: Vec<CrdtClusterNodeLoad> = sqlx::query_as(
        "SELECT node_id, gossip_url, kem_public_key_der, signing_public_key_der, \
         signing_certificate_der, ca_ids, registered_at, tombstone, tombstone_at, \
         local_gen FROM crdt_cluster_nodes",
    )
    .fetch_all(crdt_pool)
    .await?;
    for row in rows {
        let gen = row.local_gen as u64;
        max_gen = max_gen.max(gen);
        let tombstone = row.tombstone != 0;
        let ca_ids: Vec<String> = serde_json::from_str(&row.ca_ids).unwrap_or_else(|e| {
            tracing::error!(
                node_id = %row.node_id,
                raw = %row.ca_ids,
                error = %e,
                "crdt load: malformed ca_ids JSON — defaulting to empty list"
            );
            Vec::new()
        });
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
            .fetch_all(crdt_pool)
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
            .fetch_all(crdt_pool)
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
        crate::generation::CRDT_GENERATION.fetch_max(max_gen, Ordering::AcqRel);
    }

    Ok(crdt)
}

/// Persist the three CRDT-owned cluster tables to the CRDT database.
///
/// Writes `crdt_cluster_nodes`, `crdt_order_owners`, and `crdt_mtc_writer`
/// using full-replace (DELETE + INSERT) semantics.  Call with the CRDT pool
/// (`state.crdt_db`) to avoid contending with ACME writes on the main pool.
pub async fn persist_crdt_cluster(pool: &AnyPool, crdt: &AkaCrdt) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;

    // ── CRDT cluster nodes (full replace) ─────────────────────────────────────
    q("DELETE FROM crdt_cluster_nodes")
        .execute(&mut *tx)
        .await?;
    for (node_id, entry) in crdt.cluster_nodes.all_entries() {
        let ca_ids_json =
            serde_json::to_string(&entry.value.ca_ids).unwrap_or_else(|_| "[]".to_string());
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
        .execute(&mut *tx)
        .await?;
    }

    // ── CRDT order owners (full replace) ──────────────────────────────────────
    q("DELETE FROM crdt_order_owners").execute(&mut *tx).await?;
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
            .execute(&mut *tx)
            .await?;
        }
    }

    // ── CRDT MTC writer (full replace) ────────────────────────────────────────
    q("DELETE FROM crdt_mtc_writer").execute(&mut *tx).await?;
    if let Some(writer) = crdt.mtc_writer.get() {
        q(
            "INSERT INTO crdt_mtc_writer (id, node_id, claimed_at, local_gen) \
           VALUES ('singleton', ?, ?, ?)",
        )
        .bind(&writer.node_id)
        .bind(writer.claimed_at)
        .bind(crdt.mtc_writer.local_gen() as i64)
        .execute(&mut *tx)
        .await?;
    }

    tx.commit().await
}

/// Persist ACME-table CRDT fields to the main application database.
///
/// Upserts gossip-received entries so cross-node data (accounts, orders, etc.)
/// is visible to ACME handlers on this node.  Call with the main pool
/// (`state.db`).  Run on the slow periodic timer (every 30 s), not on the
/// hot path.
pub async fn persist_crdt_acme(pool: &AnyPool, crdt: &AkaCrdt) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;

    // Defer FK checks to commit time so the insert ordering within the transaction
    // (accounts → orders → authz → challenges) satisfies all constraints at commit
    // even if intermediate statements would temporarily violate them.
    // Non-SQLite backends ignore PRAGMA statements.
    let _ = q("PRAGMA defer_foreign_keys=ON").execute(&mut *tx).await;

    // ── ACME tables: upsert all fields so gossip-received entries land in the DB ──
    //
    // Uses ON CONFLICT … DO UPDATE (true upsert) rather than INSERT OR REPLACE.
    // INSERT OR REPLACE deletes the old row first, which violates FK constraints
    // (PRAGMA foreign_keys=ON) when child rows already reference the parent.
    //
    // Insert order follows FK dependency: accounts → orders → authorizations →
    // challenges, so a first-time gossip receive in a single persist call works.
    //
    // Certificates are intentionally kept as UPDATE-only: CertEntry does not carry
    // the PEM/DER bytes; only status/revocation fields are gossip-tracked.

    for (id, entry) in crdt.accounts.all_entries() {
        q_upsert(
            "INSERT INTO accounts \
             (id, status, contact, public_key, jwk_thumbprint, created, updated, \
              ca_id, profile_grants, local_gen) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) \
             ON CONFLICT(id) DO UPDATE SET \
             status = excluded.status, contact = excluded.contact, \
             updated = excluded.updated, ca_id = excluded.ca_id, \
             profile_grants = excluded.profile_grants, local_gen = excluded.local_gen",
            "INSERT INTO accounts \
             (id, status, contact, public_key, jwk_thumbprint, created, updated, \
              ca_id, profile_grants, local_gen) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) \
             ON DUPLICATE KEY UPDATE \
             status = VALUES(status), contact = VALUES(contact), \
             updated = VALUES(updated), ca_id = VALUES(ca_id), \
             profile_grants = VALUES(profile_grants), local_gen = VALUES(local_gen)",
            "INSERT INTO accounts \
             (id, status, contact, public_key, jwk_thumbprint, created, updated, \
              ca_id, profile_grants, local_gen) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) \
             ON CONFLICT (id) DO UPDATE SET \
             status = EXCLUDED.status, contact = EXCLUDED.contact, \
             updated = EXCLUDED.updated, ca_id = EXCLUDED.ca_id, \
             profile_grants = EXCLUDED.profile_grants, local_gen = EXCLUDED.local_gen",
        )
        .bind(id.as_str())
        .bind(&entry.value.status)
        .bind(entry.value.contact.as_deref())
        .bind(&entry.value.public_key_der)
        .bind(&entry.value.jwk_thumbprint)
        .bind(entry.value.created)
        .bind(entry.value.updated)
        .bind(&entry.value.ca_id)
        .bind(entry.value.profile_grants.as_deref())
        .bind(entry.local_gen as i64)
        .execute(&mut *tx)
        .await?;
    }

    for (id, entry) in crdt.orders.all_entries() {
        q_upsert(
            "INSERT INTO orders \
             (id, account_id, status, expires, identifiers, not_before, not_after, \
              error, certificate_id, created, updated, ca_id, local_gen) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) \
             ON CONFLICT(id) DO UPDATE SET \
             status = excluded.status, expires = excluded.expires, \
             error = excluded.error, certificate_id = excluded.certificate_id, \
             updated = excluded.updated, local_gen = excluded.local_gen",
            "INSERT INTO orders \
             (id, account_id, status, expires, identifiers, not_before, not_after, \
              error, certificate_id, created, updated, ca_id, local_gen) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) \
             ON DUPLICATE KEY UPDATE \
             status = VALUES(status), expires = VALUES(expires), \
             error = VALUES(error), certificate_id = VALUES(certificate_id), \
             updated = VALUES(updated), local_gen = VALUES(local_gen)",
            "INSERT INTO orders \
             (id, account_id, status, expires, identifiers, not_before, not_after, \
              error, certificate_id, created, updated, ca_id, local_gen) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13) \
             ON CONFLICT (id) DO UPDATE SET \
             status = EXCLUDED.status, expires = EXCLUDED.expires, \
             error = EXCLUDED.error, certificate_id = EXCLUDED.certificate_id, \
             updated = EXCLUDED.updated, local_gen = EXCLUDED.local_gen",
        )
        .bind(id.as_str())
        .bind(&entry.value.account_id)
        .bind(&entry.value.status)
        .bind(entry.value.expires)
        .bind(&entry.value.identifiers)
        .bind(entry.value.not_before)
        .bind(entry.value.not_after)
        .bind(entry.value.error.as_deref())
        .bind(entry.value.certificate_id.as_deref())
        .bind(entry.value.created)
        .bind(entry.value.updated)
        .bind(&entry.value.ca_id)
        .bind(entry.local_gen as i64)
        .execute(&mut *tx)
        .await?;
    }

    for (id, entry) in crdt.authorizations.all_entries() {
        q_upsert(
            "INSERT INTO authorizations \
             (id, order_id, account_id, status, identifier, expires, wildcard, \
              created, updated, ca_id, local_gen) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) \
             ON CONFLICT(id) DO UPDATE SET \
             status = excluded.status, expires = excluded.expires, \
             updated = excluded.updated, local_gen = excluded.local_gen",
            "INSERT INTO authorizations \
             (id, order_id, account_id, status, identifier, expires, wildcard, \
              created, updated, ca_id, local_gen) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) \
             ON DUPLICATE KEY UPDATE \
             status = VALUES(status), expires = VALUES(expires), \
             updated = VALUES(updated), local_gen = VALUES(local_gen)",
            "INSERT INTO authorizations \
             (id, order_id, account_id, status, identifier, expires, wildcard, \
              created, updated, ca_id, local_gen) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) \
             ON CONFLICT (id) DO UPDATE SET \
             status = EXCLUDED.status, expires = EXCLUDED.expires, \
             updated = EXCLUDED.updated, local_gen = EXCLUDED.local_gen",
        )
        .bind(id.as_str())
        .bind(&entry.value.order_id)
        .bind(&entry.value.account_id)
        .bind(&entry.value.status)
        .bind(&entry.value.identifier)
        .bind(entry.value.expires)
        .bind(if entry.value.wildcard { 1i64 } else { 0i64 })
        .bind(entry.value.created)
        .bind(entry.value.updated)
        .bind(&entry.value.ca_id)
        .bind(entry.local_gen as i64)
        .execute(&mut *tx)
        .await?;
    }

    for (id, register) in crdt.challenges.all_entries() {
        if let Some(ch) = register.get() {
            q_upsert(
                "INSERT INTO challenges \
                 (id, authz_id, type, status, token, validated, error, \
                  created, updated, local_gen) \
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) \
                 ON CONFLICT(id) DO UPDATE SET \
                 status = excluded.status, validated = excluded.validated, \
                 error = excluded.error, updated = excluded.updated, \
                 local_gen = excluded.local_gen",
                "INSERT INTO challenges \
                 (id, authz_id, type, status, token, validated, error, \
                  created, updated, local_gen) \
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) \
                 ON DUPLICATE KEY UPDATE \
                 status = VALUES(status), validated = VALUES(validated), \
                 error = VALUES(error), updated = VALUES(updated), \
                 local_gen = VALUES(local_gen)",
                "INSERT INTO challenges \
                 (id, authz_id, type, status, token, validated, error, \
                  created, updated, local_gen) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) \
                 ON CONFLICT (id) DO UPDATE SET \
                 status = EXCLUDED.status, validated = EXCLUDED.validated, \
                 error = EXCLUDED.error, updated = EXCLUDED.updated, \
                 local_gen = EXCLUDED.local_gen",
            )
            .bind(id.as_str())
            .bind(&ch.authz_id)
            .bind(&ch.challenge_type)
            .bind(&ch.status)
            .bind(&ch.token)
            .bind(ch.validated)
            .bind(ch.error.as_deref())
            .bind(ch.created)
            .bind(ch.updated)
            .bind(register.local_gen() as i64)
            .execute(&mut *tx)
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
        .execute(&mut *tx)
        .await?;
    }

    for (kid, register) in crdt.eab_keys.all_entries() {
        if let Some(k) = register.get() {
            q("UPDATE eab_keys SET used_at = ?, local_gen = ? WHERE kid = ?")
                .bind(k.used_at)
                .bind(register.local_gen() as i64)
                .bind(kid.as_str())
                .execute(&mut *tx)
                .await?;
        }
    }

    for (key, entry) in crdt.operators.all_entries() {
        if let Ok(id) = key.parse::<i64>() {
            q("UPDATE operators SET active = ?, local_gen = ? WHERE id = ?")
                .bind(if entry.tombstone { 0i64 } else { 1i64 })
                .bind(entry.local_gen as i64)
                .bind(id)
                .execute(&mut *tx)
                .await?;
        }
    }

    for (id, entry) in crdt.delegations.all_entries() {
        q("UPDATE delegations SET local_gen = ? WHERE id = ?")
            .bind(entry.local_gen as i64)
            .bind(id.as_str())
            .execute(&mut *tx)
            .await?;
    }

    for (id, entry) in crdt.policy_rules.all_entries() {
        if !entry.tombstone {
            // Evict any stale row that holds the same (scope, name) under a
            // different id — prevents UNIQUE-constraint failures when two
            // nodes independently create rules with the same name.
            q("DELETE FROM policy_rules WHERE scope = ? AND name = ? AND id != ?")
                .bind(&entry.value.scope)
                .bind(&entry.value.name)
                .bind(id.as_str())
                .execute(&mut *tx)
                .await?;
        }

        q_upsert(
            "INSERT INTO policy_rules \
             (id, scope, name, rule_json, enabled, created_at, updated_at, created_by, local_gen, tombstone, tombstone_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) \
             ON CONFLICT(id) DO UPDATE SET \
             scope = excluded.scope, name = excluded.name, \
             rule_json = excluded.rule_json, enabled = excluded.enabled, \
             updated_at = excluded.updated_at, local_gen = excluded.local_gen, \
             tombstone = excluded.tombstone, tombstone_at = excluded.tombstone_at",
            "INSERT INTO policy_rules \
             (id, scope, name, rule_json, enabled, created_at, updated_at, created_by, local_gen, tombstone, tombstone_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) \
             ON DUPLICATE KEY UPDATE \
             scope = VALUES(scope), name = VALUES(name), \
             rule_json = VALUES(rule_json), enabled = VALUES(enabled), \
             updated_at = VALUES(updated_at), local_gen = VALUES(local_gen), \
             tombstone = VALUES(tombstone), tombstone_at = VALUES(tombstone_at)",
            "INSERT INTO policy_rules \
             (id, scope, name, rule_json, enabled, created_at, updated_at, created_by, local_gen, tombstone, tombstone_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) \
             ON CONFLICT (id) DO UPDATE SET \
             scope = EXCLUDED.scope, name = EXCLUDED.name, \
             rule_json = EXCLUDED.rule_json, enabled = EXCLUDED.enabled, \
             updated_at = EXCLUDED.updated_at, local_gen = EXCLUDED.local_gen, \
             tombstone = EXCLUDED.tombstone, tombstone_at = EXCLUDED.tombstone_at",
        )
        .bind(id.as_str())
        .bind(&entry.value.scope)
        .bind(&entry.value.name)
        .bind(&entry.value.rule_json)
        .bind(entry.value.enabled as i64)
        .bind(&entry.value.created_at)
        .bind(&entry.value.updated_at)
        .bind(entry.value.created_by.as_deref())
        .bind(entry.local_gen as i64)
        .bind(entry.tombstone as i64)
        .bind(entry.tombstone_at)
        .execute(&mut *tx)
        .await?;
    }

    for (tree_size, register) in crdt.mtc_checkpoints.all_entries() {
        q("UPDATE mtc_checkpoints SET local_gen = ? WHERE tree_size = ?")
            .bind(register.local_gen() as i64)
            .bind(*tree_size as i64)
            .execute(&mut *tx)
            .await?;
    }

    tx.commit().await?;
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
    q_upsert(
        "INSERT OR REPLACE INTO crdt_order_owners \
         (order_id, node_id, claimed_at, local_gen) VALUES (?, ?, ?, ?)",
        "REPLACE INTO crdt_order_owners \
         (order_id, node_id, claimed_at, local_gen) VALUES (?, ?, ?, ?)",
        "INSERT INTO crdt_order_owners (order_id, node_id, claimed_at, local_gen) \
         VALUES ($1, $2, $3, $4) \
         ON CONFLICT (order_id) DO UPDATE SET \
         node_id = EXCLUDED.node_id, claimed_at = EXCLUDED.claimed_at, \
         local_gen = EXCLUDED.local_gen",
    )
    .bind(order_id)
    .bind(&owner.node_id)
    .bind(owner.claimed_at)
    .bind(local_gen as i64)
    .execute(pool)
    .await?;
    Ok(())
}

/// Upsert the MTC writer election to `crdt_mtc_writer` (singleton row).
pub async fn persist_mtc_writer(
    pool: &AnyPool,
    writer: &MtcWriter,
    local_gen: u64,
) -> Result<(), sqlx::Error> {
    q_upsert(
        "INSERT OR REPLACE INTO crdt_mtc_writer (id, node_id, claimed_at, local_gen) \
         VALUES ('singleton', ?, ?, ?)",
        "REPLACE INTO crdt_mtc_writer (id, node_id, claimed_at, local_gen) \
         VALUES ('singleton', ?, ?, ?)",
        "INSERT INTO crdt_mtc_writer (id, node_id, claimed_at, local_gen) \
         VALUES ('singleton', $1, $2, $3) \
         ON CONFLICT (id) DO UPDATE SET \
         node_id = EXCLUDED.node_id, claimed_at = EXCLUDED.claimed_at, \
         local_gen = EXCLUDED.local_gen",
    )
    .bind(&writer.node_id)
    .bind(writer.claimed_at)
    .bind(local_gen as i64)
    .execute(pool)
    .await?;
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
    q_upsert(
        "INSERT OR REPLACE INTO node_keys \
         (node_id, kem_private_key_der, kem_public_key_der, \
          signing_private_key_der, signing_public_key_der, \
          signing_certificate_der, created_at) \
         VALUES (?, ?, ?, ?, ?, ?, ?)",
        "REPLACE INTO node_keys \
         (node_id, kem_private_key_der, kem_public_key_der, \
          signing_private_key_der, signing_public_key_der, \
          signing_certificate_der, created_at) \
         VALUES (?, ?, ?, ?, ?, ?, ?)",
        "INSERT INTO node_keys \
         (node_id, kem_private_key_der, kem_public_key_der, \
          signing_private_key_der, signing_public_key_der, \
          signing_certificate_der, created_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7) \
         ON CONFLICT (node_id) DO UPDATE SET \
         kem_private_key_der = EXCLUDED.kem_private_key_der, \
         kem_public_key_der = EXCLUDED.kem_public_key_der, \
         signing_private_key_der = EXCLUDED.signing_private_key_der, \
         signing_public_key_der = EXCLUDED.signing_public_key_der, \
         signing_certificate_der = EXCLUDED.signing_certificate_der, \
         created_at = EXCLUDED.created_at",
    )
    .bind(&row.node_id)
    .bind(&row.kem_private_key_der)
    .bind(&row.kem_public_key_der)
    .bind(&row.signing_private_key_der)
    .bind(&row.signing_public_key_der)
    .bind(&row.signing_certificate_der)
    .bind(row.created_at)
    .execute(pool)
    .await?;

    Ok(())
}

/// Open a dedicated pool for CRDT cluster tables and run inline schema setup.
///
/// The CRDT DB is separate from the main ACME database so that periodic
/// cluster-state persists do not contend with ACME reads and writes on the
/// main pool.  Schema is managed inline (no migration files) because the
/// CRDT crate owns these tables entirely.
///
/// For SQLite the URL should be a file path (`sqlite:///path/crdt.db`) so WAL
/// mode can be enabled.  `:memory:` is accepted and silently skips WAL setup.
pub async fn open_crdt_db(url: &str) -> Result<AnyPool, sqlx::Error> {
    use sqlx::any::AnyPoolOptions;
    let is_mem = url.contains(":memory:");
    let owned;
    let effective_url = if url.starts_with("sqlite") && !is_mem && !url.contains("mode=") {
        owned = if url.contains('?') {
            format!("{url}&mode=rwc")
        } else {
            format!("{url}?mode=rwc")
        };
        owned.as_str()
    } else {
        url
    };
    let pool = AnyPoolOptions::new()
        .max_connections(if is_mem { 1 } else { 4 })
        .connect(effective_url)
        .await?;

    // Enable WAL on file-backed SQLite; ignored by Postgres/MariaDB.
    if !is_mem {
        let _ = sqlx::query("PRAGMA journal_mode=WAL").execute(&pool).await;
        let _ = sqlx::query("PRAGMA synchronous=NORMAL")
            .execute(&pool)
            .await;
    }

    // Create CRDT-owned tables (idempotent).
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS node_keys (
            node_id                  TEXT    PRIMARY KEY,
            kem_private_key_der      BLOB    NOT NULL,
            kem_public_key_der       BLOB    NOT NULL,
            signing_private_key_der  BLOB    NOT NULL,
            signing_public_key_der   BLOB    NOT NULL,
            signing_certificate_der  BLOB    NOT NULL,
            created_at               INTEGER NOT NULL
        )",
    )
    .execute(&pool)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS crdt_cluster_nodes (
            node_id                  TEXT    PRIMARY KEY,
            gossip_url               TEXT    NOT NULL,
            kem_public_key_der       BLOB    NOT NULL,
            signing_public_key_der   BLOB    NOT NULL,
            signing_certificate_der  BLOB    NOT NULL,
            ca_ids                   TEXT    NOT NULL DEFAULT '[]',
            registered_at            INTEGER NOT NULL,
            tombstone                INTEGER NOT NULL DEFAULT 0,
            tombstone_at             INTEGER,
            local_gen                INTEGER NOT NULL DEFAULT 0
        )",
    )
    .execute(&pool)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS crdt_order_owners (
            order_id    TEXT    PRIMARY KEY,
            node_id     TEXT    NOT NULL,
            claimed_at  INTEGER NOT NULL,
            local_gen   INTEGER NOT NULL DEFAULT 0
        )",
    )
    .execute(&pool)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS crdt_mtc_writer (
            id          TEXT    PRIMARY KEY,
            node_id     TEXT    NOT NULL,
            claimed_at  INTEGER NOT NULL,
            local_gen   INTEGER NOT NULL DEFAULT 0
        )",
    )
    .execute(&pool)
    .await?;

    Ok(pool)
}
