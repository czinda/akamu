//! Operator account store (PP CA v2.1 FMT).
//!
//! Each row represents a named administrative operator with a role and at
//! least one authentication credential (client certificate SHA-256 fingerprint
//! or Kerberos principal).

use crate::error::AcmeError;

/// A row from the `operators` table.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct OperatorRow {
    pub id: i64,
    pub name: String,
    /// Role string stored in the DB: `"administrator"`, `"ca_operations"`, `"ca_ra"`, `"auditor"`.
    pub role: String,
    /// SHA-256 hex fingerprint of the operator's mTLS certificate, or `None`.
    pub cert_fingerprint: Option<String>,
    /// Kerberos principal (e.g. `"alice@REALM"`) for GSSAPI authentication, or `None`.
    pub gssapi_principal: Option<String>,
    /// RFC 3339 timestamp when the operator was created.
    pub created_at: String,
    /// RFC 3339 timestamp of the last successful authentication, or `None` if never.
    pub last_seen_at: Option<String>,
    /// `1` when the account is active; `0` when deactivated.
    pub active: i64,
    /// Number of consecutive authentication failures since last successful login (FIA_AFL.1).
    pub failed_attempts: i64,
    /// RFC 3339 timestamp until which the account is locked, or `None` when not locked.
    pub locked_until: Option<String>,
    /// CA scope for `ca_ra` operators.  Empty string means server-wide (no restriction).
    /// Ignored for all roles other than `ca_ra`.
    pub ca_id: String,
}

/// Insert a new operator.
///
/// The caller can retrieve the assigned `id` immediately afterwards using
/// [`get_by_fingerprint`] or [`get_by_principal`], both of which include the
/// `id` field.  We avoid a separate `SELECT last_insert_rowid()` / `RETURNING
/// id` call because the cross-database syntax differs across SQLite, PostgreSQL
/// and MariaDB.
pub async fn insert(
    executor: impl sqlx::Executor<'_, Database = sqlx::Any>,
    name: &str,
    role: &str,
    cert_fingerprint: Option<&str>,
    gssapi_principal: Option<&str>,
    ca_id: &str,
    now: &str,
) -> Result<(), AcmeError> {
    super::query(
        "INSERT INTO operators \
         (name, role, cert_fingerprint, gssapi_principal, created_at, active, ca_id) \
         VALUES (?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(name)
    .bind(role)
    .bind(cert_fingerprint)
    .bind(gssapi_principal)
    .bind(now)
    .bind(1i64)
    .bind(ca_id)
    .execute(executor)
    .await?;
    Ok(())
}

/// Look up an active operator by SHA-256 certificate fingerprint (hex).
pub async fn get_by_fingerprint(
    executor: impl sqlx::Executor<'_, Database = sqlx::Any>,
    fingerprint: &str,
) -> Result<Option<OperatorRow>, AcmeError> {
    let row = super::query_as::<OperatorRow>(
        "SELECT id, name, role, cert_fingerprint, gssapi_principal, \
         created_at, last_seen_at, active, failed_attempts, locked_until, ca_id \
         FROM operators WHERE cert_fingerprint = ? AND active = ?",
    )
    .bind(fingerprint)
    .bind(1i64)
    .fetch_optional(executor)
    .await?;
    Ok(row)
}

/// Look up an active operator by Kerberos principal.
pub async fn get_by_principal(
    executor: impl sqlx::Executor<'_, Database = sqlx::Any>,
    principal: &str,
) -> Result<Option<OperatorRow>, AcmeError> {
    let row = super::query_as::<OperatorRow>(
        "SELECT id, name, role, cert_fingerprint, gssapi_principal, \
         created_at, last_seen_at, active, failed_attempts, locked_until, ca_id \
         FROM operators WHERE gssapi_principal = ? AND active = ?",
    )
    .bind(principal)
    .bind(1i64)
    .fetch_optional(executor)
    .await?;
    Ok(row)
}

/// Insert an operator only if no row with the same name already exists.
/// Returns `true` when a new row was inserted, `false` when the row already
/// existed (idempotent).
///
/// Uses a portable `WHERE NOT EXISTS` subquery so the query works on SQLite,
/// PostgreSQL, and MariaDB.  This replaces `INSERT OR IGNORE` which is
/// SQLite-specific.
pub async fn insert_if_absent(
    executor: impl sqlx::Executor<'_, Database = sqlx::Any>,
    name: &str,
    role: &str,
    cert_fingerprint: Option<&str>,
    gssapi_principal: Option<&str>,
    ca_id: &str,
    now: &str,
) -> Result<bool, AcmeError> {
    let result = super::query(
        "INSERT INTO operators \
         (name, role, cert_fingerprint, gssapi_principal, created_at, active, ca_id) \
         SELECT ?, ?, ?, ?, ?, ?, ? \
         WHERE NOT EXISTS (SELECT 1 FROM operators WHERE name = ?)",
    )
    .bind(name)
    .bind(role)
    .bind(cert_fingerprint)
    .bind(gssapi_principal)
    .bind(now)
    .bind(1i64)
    .bind(ca_id)
    .bind(name)
    .execute(executor)
    .await?;
    Ok(result.rows_affected() > 0)
}

/// Return `true` when the operators table contains no rows.
pub async fn is_empty(
    executor: impl sqlx::Executor<'_, Database = sqlx::Any>,
) -> Result<bool, AcmeError> {
    let (count,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM operators")
        .fetch_one(executor)
        .await?;
    Ok(count == 0)
}

/// Return operators (active and inactive) ordered by ID, with pagination.
///
/// `limit` is clamped to `[1, 1000]` by the caller; this function trusts the
/// caller to enforce the cap before calling.
pub async fn list(
    executor: impl sqlx::Executor<'_, Database = sqlx::Any>,
    limit: i64,
    offset: i64,
) -> Result<Vec<OperatorRow>, AcmeError> {
    let rows = super::query_as::<OperatorRow>(
        "SELECT id, name, role, cert_fingerprint, gssapi_principal, \
         created_at, last_seen_at, active, failed_attempts, locked_until, ca_id \
         FROM operators ORDER BY id ASC LIMIT ? OFFSET ?",
    )
    .bind(limit)
    .bind(offset)
    .fetch_all(executor)
    .await?;
    Ok(rows)
}

/// Set `active = 1` or `active = 0` and update `last_seen_at`.
///
/// Returns the number of rows updated; callers should treat 0 as "not found".
pub async fn set_active(
    executor: impl sqlx::Executor<'_, Database = sqlx::Any>,
    id: i64,
    active: bool,
    now: &str,
) -> Result<u64, AcmeError> {
    let result = super::query("UPDATE operators SET active = ?, last_seen_at = ? WHERE id = ?")
        .bind(if active { 1i64 } else { 0i64 })
        .bind(now)
        .bind(id)
        .execute(executor)
        .await?;
    Ok(result.rows_affected())
}

/// Look up an operator by ID (active or inactive).
pub async fn get_by_id(
    executor: impl sqlx::Executor<'_, Database = sqlx::Any>,
    id: i64,
) -> Result<Option<OperatorRow>, AcmeError> {
    let row = super::query_as::<OperatorRow>(
        "SELECT id, name, role, cert_fingerprint, gssapi_principal, \
         created_at, last_seen_at, active, failed_attempts, locked_until, ca_id \
         FROM operators WHERE id = ?",
    )
    .bind(id)
    .fetch_optional(executor)
    .await?;
    Ok(row)
}

/// Fields to update on an operator row.  Only `Some` fields are modified.
///
/// Pass `ca_id = Some("")` to clear the CA scope (server-wide), or
/// `ca_id = Some("rsa")` to set a specific CA scope.  `ca_id = None`
/// leaves the existing value unchanged.
pub struct OperatorUpdateParams<'a> {
    pub name: Option<&'a str>,
    pub role: Option<&'a str>,
    pub cert_fingerprint: Option<&'a str>,
    pub gssapi_principal: Option<&'a str>,
    pub ca_id: Option<&'a str>,
}

/// Update operator fields.  Only `Some` fields in `params` are changed.
///
/// Returns `true` when the operator was found and updated, `false` when no
/// row with the given `id` exists.
pub async fn update(
    executor: impl sqlx::Executor<'_, Database = sqlx::Any>,
    id: i64,
    params: OperatorUpdateParams<'_>,
    now: &str,
) -> Result<bool, AcmeError> {
    let OperatorUpdateParams {
        name,
        role,
        cert_fingerprint,
        gssapi_principal,
        ca_id,
    } = params;
    let mut qb = super::DynQueryBuilder::new("UPDATE operators SET last_seen_at = ");
    qb.push_bind(now);
    if let Some(n) = name {
        qb.push(", name = ");
        qb.push_bind(n);
    }
    if let Some(r) = role {
        qb.push(", role = ");
        qb.push_bind(r);
    }
    if let Some(fp) = cert_fingerprint {
        qb.push(", cert_fingerprint = ");
        qb.push_bind(fp);
    }
    if let Some(p) = gssapi_principal {
        qb.push(", gssapi_principal = ");
        qb.push_bind(p);
    }
    if let Some(c) = ca_id {
        qb.push(", ca_id = ");
        qb.push_bind(c);
    }
    qb.push(" WHERE id = ");
    qb.push_bind(id);

    let result = qb.execute(executor).await?;
    Ok(result.rows_affected() > 0)
}

/// Bump `last_seen_at` on successful authentication.
pub async fn update_last_seen(
    executor: impl sqlx::Executor<'_, Database = sqlx::Any>,
    id: i64,
    now: &str,
) -> Result<(), AcmeError> {
    super::query("UPDATE operators SET last_seen_at = ? WHERE id = ?")
        .bind(now)
        .bind(id)
        .execute(executor)
        .await?;
    Ok(())
}

/// Increment `failed_attempts` and, when the new count reaches `max_attempts`,
/// set `locked_until` (FIA_AFL.1).  Uses a single UPDATE with CASE so only one
/// executor use is needed.
pub async fn increment_failed(
    executor: impl sqlx::Executor<'_, Database = sqlx::Any>,
    id: i64,
    max_attempts: u32,
    lock_until_rfc3339: &str,
) -> Result<(), AcmeError> {
    super::query(
        "UPDATE operators \
         SET failed_attempts = failed_attempts + 1, \
             locked_until = CASE \
                 WHEN failed_attempts + 1 >= ? THEN ? \
                 ELSE locked_until \
             END \
         WHERE id = ?",
    )
    .bind(max_attempts as i64)
    .bind(lock_until_rfc3339)
    .bind(id)
    .execute(executor)
    .await?;
    Ok(())
}

/// Reset `failed_attempts` to 0 and clear `locked_until` (on successful auth).
pub async fn reset_failed(
    executor: impl sqlx::Executor<'_, Database = sqlx::Any>,
    id: i64,
) -> Result<(), AcmeError> {
    super::query("UPDATE operators SET failed_attempts = 0, locked_until = NULL WHERE id = ?")
        .bind(id)
        .execute(executor)
        .await?;
    Ok(())
}

/// Administrator unlock: reset `failed_attempts` and clear `locked_until`.
pub async fn unlock(
    executor: impl sqlx::Executor<'_, Database = sqlx::Any>,
    id: i64,
) -> Result<bool, AcmeError> {
    let result =
        super::query("UPDATE operators SET failed_attempts = 0, locked_until = NULL WHERE id = ?")
            .bind(id)
            .execute(executor)
            .await?;
    Ok(result.rows_affected() > 0)
}

/// Check whether an operator is currently locked.  Returns `true` when
/// `locked_until` is set and `>= now_rfc3339`.
pub fn is_locked(op: &OperatorRow, now_rfc3339: &str) -> bool {
    op.locked_until
        .as_deref()
        .is_some_and(|until| until >= now_rfc3339)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::Db;

    async fn open_db() -> Db {
        crate::db::install_drivers();
        crate::db::open("sqlite::memory:", 1, false).await.unwrap()
    }

    #[tokio::test]
    async fn insert_and_get_by_fingerprint() {
        let db = open_db().await;
        insert(
            &db,
            "alice",
            "administrator",
            Some("aabbcc"),
            None,
            "",
            "2026-01-01T00:00:00Z",
        )
        .await
        .unwrap();
        let row = get_by_fingerprint(&db, "aabbcc").await.unwrap().unwrap();
        assert_eq!(row.name, "alice");
        assert_eq!(row.role, "administrator");
        assert_eq!(row.active, 1);
    }

    #[tokio::test]
    async fn insert_and_get_by_principal() {
        let db = open_db().await;
        insert(
            &db,
            "bob",
            "auditor",
            None,
            Some("bob@REALM"),
            "",
            "2026-01-01T00:00:00Z",
        )
        .await
        .unwrap();
        let row = get_by_principal(&db, "bob@REALM").await.unwrap().unwrap();
        assert_eq!(row.name, "bob");
        assert_eq!(row.role, "auditor");
    }

    #[tokio::test]
    async fn unknown_fingerprint_returns_none() {
        let db = open_db().await;
        assert!(get_by_fingerprint(&db, "nope").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn list_returns_all_rows() {
        let db = open_db().await;
        insert(
            &db,
            "alice",
            "administrator",
            Some("fp-a"),
            None,
            "",
            "2026-01-01T00:00:00Z",
        )
        .await
        .unwrap();
        insert(
            &db,
            "bob",
            "auditor",
            None,
            Some("bob@REALM"),
            "",
            "2026-01-01T00:00:00Z",
        )
        .await
        .unwrap();
        let rows = list(&db, 100, 0).await.unwrap();
        assert_eq!(rows.len(), 2);
    }

    #[tokio::test]
    async fn set_active_false_hides_from_fingerprint_lookup() {
        let db = open_db().await;
        insert(
            &db,
            "alice",
            "administrator",
            Some("fp-b"),
            None,
            "",
            "2026-01-01T00:00:00Z",
        )
        .await
        .unwrap();
        // Retrieve ID via fingerprint lookup.
        let row = get_by_fingerprint(&db, "fp-b").await.unwrap().unwrap();
        set_active(&db, row.id, false, "2026-01-02T00:00:00Z")
            .await
            .unwrap();
        assert!(get_by_fingerprint(&db, "fp-b").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn update_last_seen_stores_timestamp() {
        let db = open_db().await;
        insert(
            &db,
            "carol",
            "ca_ra",
            Some("fp-c"),
            None,
            "",
            "2026-01-01T00:00:00Z",
        )
        .await
        .unwrap();
        let row = get_by_fingerprint(&db, "fp-c").await.unwrap().unwrap();
        update_last_seen(&db, row.id, "2026-06-01T12:00:00Z")
            .await
            .unwrap();
        let rows = list(&db, 100, 0).await.unwrap();
        assert_eq!(
            rows[0].last_seen_at.as_deref(),
            Some("2026-06-01T12:00:00Z")
        );
    }
}
