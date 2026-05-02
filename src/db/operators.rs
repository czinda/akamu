//! Operator account store (PP CA v2.1 FMT).
//!
//! Each row represents a named administrative operator with a role and at
//! least one authentication credential (client certificate SHA-256 fingerprint
//! or Kerberos principal).

use crate::error::AcmeError;

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct OperatorRow {
    pub id: i64,
    pub name: String,
    pub role: String,
    pub cert_fingerprint: Option<String>,
    pub gssapi_principal: Option<String>,
    pub created_at: String,
    pub last_seen_at: Option<String>,
    pub active: i64,
}

const COLUMNS: &str =
    "id, name, role, cert_fingerprint, gssapi_principal, created_at, last_seen_at, active";

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
    now: &str,
) -> Result<(), AcmeError> {
    sqlx::query(
        "INSERT INTO operators \
         (name, role, cert_fingerprint, gssapi_principal, created_at, active) \
         VALUES (?, ?, ?, ?, ?, 1)",
    )
    .bind(name)
    .bind(role)
    .bind(cert_fingerprint)
    .bind(gssapi_principal)
    .bind(now)
    .execute(executor)
    .await?;
    Ok(())
}

/// Look up an active operator by SHA-256 certificate fingerprint (hex).
pub async fn get_by_fingerprint(
    executor: impl sqlx::Executor<'_, Database = sqlx::Any>,
    fingerprint: &str,
) -> Result<Option<OperatorRow>, AcmeError> {
    let row = sqlx::query_as::<_, OperatorRow>(&format!(
        "SELECT {COLUMNS} FROM operators \
         WHERE cert_fingerprint = ? AND active = 1"
    ))
    .bind(fingerprint)
    .fetch_optional(executor)
    .await?;
    Ok(row)
}

/// Look up an active operator by Kerberos principal.
pub async fn get_by_principal(
    executor: impl sqlx::Executor<'_, Database = sqlx::Any>,
    principal: &str,
) -> Result<Option<OperatorRow>, AcmeError> {
    let row = sqlx::query_as::<_, OperatorRow>(&format!(
        "SELECT {COLUMNS} FROM operators \
         WHERE gssapi_principal = ? AND active = 1"
    ))
    .bind(principal)
    .fetch_optional(executor)
    .await?;
    Ok(row)
}

/// Return all operators (active and inactive) ordered by ID.
pub async fn list(
    executor: impl sqlx::Executor<'_, Database = sqlx::Any>,
) -> Result<Vec<OperatorRow>, AcmeError> {
    let rows = sqlx::query_as::<_, OperatorRow>(&format!(
        "SELECT {COLUMNS} FROM operators ORDER BY id ASC"
    ))
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
    let result = sqlx::query("UPDATE operators SET active = ?, last_seen_at = ? WHERE id = ?")
        .bind(if active { 1i64 } else { 0i64 })
        .bind(now)
        .bind(id)
        .execute(executor)
        .await?;
    Ok(result.rows_affected())
}

/// Bump `last_seen_at` on successful authentication.
pub async fn update_last_seen(
    executor: impl sqlx::Executor<'_, Database = sqlx::Any>,
    id: i64,
    now: &str,
) -> Result<(), AcmeError> {
    sqlx::query("UPDATE operators SET last_seen_at = ? WHERE id = ?")
        .bind(now)
        .bind(id)
        .execute(executor)
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::Db;

    async fn open_db() -> Db {
        crate::db::install_drivers();
        crate::db::open("sqlite::memory:", 1).await.unwrap()
    }

    #[tokio::test]
    async fn insert_and_get_by_fingerprint() {
        let db = open_db().await;
        insert(&db, "alice", "administrator", Some("aabbcc"), None, "2026-01-01T00:00:00Z")
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
        insert(&db, "bob", "auditor", None, Some("bob@REALM"), "2026-01-01T00:00:00Z")
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
        insert(&db, "alice", "administrator", Some("fp-a"), None, "2026-01-01T00:00:00Z")
            .await
            .unwrap();
        insert(&db, "bob", "auditor", None, Some("bob@REALM"), "2026-01-01T00:00:00Z")
            .await
            .unwrap();
        let rows = list(&db).await.unwrap();
        assert_eq!(rows.len(), 2);
    }

    #[tokio::test]
    async fn set_active_false_hides_from_fingerprint_lookup() {
        let db = open_db().await;
        insert(&db, "alice", "administrator", Some("fp-b"), None, "2026-01-01T00:00:00Z")
            .await
            .unwrap();
        // Retrieve ID via fingerprint lookup.
        let row = get_by_fingerprint(&db, "fp-b").await.unwrap().unwrap();
        set_active(&db, row.id, false, "2026-01-02T00:00:00Z").await.unwrap();
        assert!(get_by_fingerprint(&db, "fp-b").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn update_last_seen_stores_timestamp() {
        let db = open_db().await;
        insert(&db, "carol", "ca_ra", Some("fp-c"), None, "2026-01-01T00:00:00Z")
            .await
            .unwrap();
        let row = get_by_fingerprint(&db, "fp-c").await.unwrap().unwrap();
        update_last_seen(&db, row.id, "2026-06-01T12:00:00Z").await.unwrap();
        let rows = list(&db).await.unwrap();
        assert_eq!(rows[0].last_seen_at.as_deref(), Some("2026-06-01T12:00:00Z"));
    }
}
