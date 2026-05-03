//! External Account Binding key store (RFC 8555 §7.3.4).
//!
//! The `eab_keys` table is the canonical source of truth for all EAB keys,
//! regardless of how they were provisioned (config file or future admin
//! endpoint).  Config-file keys are seeded with `insert_if_absent()` on
//! startup so they never overwrite keys that were modified at runtime.

use crate::error::AcmeError;

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct EabKeyRow {
    pub kid: String,
    pub hmac_key_b64u: String,
    pub created: i64,
    /// `None` → key is unused and may be consumed by a new-account request.
    pub used_at: Option<i64>,
    /// JSON array of profile IDs that the account created with this key will
    /// inherit.  `None` = no restriction.
    pub profile_grants: Option<String>,
}

/// Seed a key from the config file.
///
/// Uses a portable `WHERE NOT EXISTS` subquery so that a key that already
/// exists in the DB (possibly modified or marked used by the admin endpoint)
/// is left alone.  This replaces `INSERT OR IGNORE` which is SQLite-specific.
pub async fn insert_if_absent(
    executor: impl sqlx::Executor<'_, Database = sqlx::Any>,
    kid: &str,
    hmac_key_b64u: &str,
    now: i64,
) -> Result<(), AcmeError> {
    sqlx::query(
        "INSERT INTO eab_keys (kid, hmac_key_b64u, created) \
         SELECT ?, ?, ? \
         WHERE NOT EXISTS (SELECT 1 FROM eab_keys WHERE kid = ?)",
    )
    .bind(kid)
    .bind(hmac_key_b64u)
    .bind(now)
    .bind(kid)
    .execute(executor)
    .await?;
    Ok(())
}

/// Provision a new key unconditionally (for the future admin endpoint).
///
/// Returns a `Conflict` error if a key with the same `kid` already exists.
pub async fn insert(
    executor: impl sqlx::Executor<'_, Database = sqlx::Any>,
    kid: &str,
    hmac_key_b64u: &str,
    now: i64,
) -> Result<(), AcmeError> {
    sqlx::query("INSERT INTO eab_keys (kid, hmac_key_b64u, created) VALUES (?, ?, ?)")
        .bind(kid)
        .bind(hmac_key_b64u)
        .bind(now)
        .execute(executor)
        .await?;
    Ok(())
}

/// Look up a key by its `kid`.  Returns `None` if the `kid` is unknown.
pub async fn get_by_kid(
    executor: impl sqlx::Executor<'_, Database = sqlx::Any>,
    kid: &str,
) -> Result<Option<EabKeyRow>, AcmeError> {
    let row = sqlx::query_as::<_, EabKeyRow>(
        "SELECT kid, hmac_key_b64u, created, used_at, profile_grants \
         FROM eab_keys WHERE kid = ?",
    )
    .bind(kid)
    .fetch_optional(executor)
    .await?;
    Ok(row)
}

/// Provision a new EAB key with optional profile grants (for the admin endpoint).
///
/// `profile_grants` is a JSON-serialised array of permitted profile IDs, or
/// `None` for no restriction.  Returns a `Conflict` error if the `kid` already
/// exists.
pub async fn insert_with_grants(
    executor: impl sqlx::Executor<'_, Database = sqlx::Any>,
    kid: &str,
    hmac_key_b64u: &str,
    profile_grants: Option<&str>,
    now: i64,
) -> Result<(), AcmeError> {
    sqlx::query(
        "INSERT INTO eab_keys (kid, hmac_key_b64u, created, profile_grants) VALUES (?, ?, ?, ?)",
    )
    .bind(kid)
    .bind(hmac_key_b64u)
    .bind(now)
    .bind(profile_grants)
    .execute(executor)
    .await?;
    Ok(())
}

/// Mark a key as used.
///
/// Pass `&mut *tx` to call this atomically within an existing transaction,
/// ensuring the key is consumed only when account creation fully commits.
///
/// Returns `Conflict` when `rows_affected == 0`, which means the key was
/// already consumed by a concurrent request between the outer `get_by_kid`
/// check and the transaction commit (TOCTOU guard).
pub async fn mark_used(
    executor: impl sqlx::Executor<'_, Database = sqlx::Any>,
    kid: &str,
    now: i64,
) -> Result<(), AcmeError> {
    let result =
        sqlx::query("UPDATE eab_keys SET used_at = ? WHERE kid = ? AND used_at IS NULL")
            .bind(now)
            .bind(kid)
            .execute(executor)
            .await?;
    if result.rows_affected() == 0 {
        return Err(AcmeError::Conflict(
            "EAB key already consumed by a concurrent request".into(),
        ));
    }
    Ok(())
}

/// List EAB keys with optional used-status filter, pagination.
///
/// `used_filter`: `Some(true)` = only used, `Some(false)` = only unused, `None` = all.
pub async fn list(
    db: &crate::db::Db,
    used_filter: Option<bool>,
    limit: i64,
    offset: i64,
) -> Result<Vec<EabKeyRow>, AcmeError> {
    let mut qb = sqlx::QueryBuilder::<sqlx::Any>::new(
        "SELECT kid, hmac_key_b64u, created, used_at, profile_grants FROM eab_keys WHERE 1=1",
    );
    match used_filter {
        Some(true) => qb.push(" AND used_at IS NOT NULL"),
        Some(false) => qb.push(" AND used_at IS NULL"),
        None => qb.push(""),
    };
    qb.push(" ORDER BY created DESC LIMIT ");
    qb.push_bind(limit);
    qb.push(" OFFSET ");
    qb.push_bind(offset);
    let rows = qb.build_query_as::<EabKeyRow>().fetch_all(db).await?;
    Ok(rows)
}

/// Delete a key entirely (for the future admin endpoint cleanup path).
/// Delete an EAB key by KID.
///
/// Returns the number of rows deleted; callers should treat 0 as "not found".
pub async fn delete(
    executor: impl sqlx::Executor<'_, Database = sqlx::Any>,
    kid: &str,
) -> Result<u64, AcmeError> {
    let result = sqlx::query("DELETE FROM eab_keys WHERE kid = ?")
        .bind(kid)
        .execute(executor)
        .await?;
    Ok(result.rows_affected())
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
    async fn insert_and_get_by_kid() {
        let db = open_db().await;
        insert(&db, "kid1", "c2VjcmV0", 1_700_000_000)
            .await
            .unwrap();
        let row = get_by_kid(&db, "kid1").await.unwrap().unwrap();
        assert_eq!(row.kid, "kid1");
        assert_eq!(row.hmac_key_b64u, "c2VjcmV0");
        assert_eq!(row.created, 1_700_000_000);
        assert!(row.used_at.is_none());
    }

    #[tokio::test]
    async fn get_by_kid_unknown_returns_none() {
        let db = open_db().await;
        assert!(get_by_kid(&db, "nope").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn insert_if_absent_does_not_overwrite() {
        let db = open_db().await;
        insert(&db, "kid2", "original", 1_000).await.unwrap();
        insert_if_absent(&db, "kid2", "replacement", 2_000)
            .await
            .unwrap();
        let row = get_by_kid(&db, "kid2").await.unwrap().unwrap();
        assert_eq!(row.hmac_key_b64u, "original");
    }

    #[tokio::test]
    async fn mark_used_sets_used_at() {
        let db = open_db().await;
        insert(&db, "kid3", "key", 1_000).await.unwrap();
        let mut tx = db.begin().await.unwrap();
        mark_used(&mut *tx, "kid3", 2_000).await.unwrap();
        tx.commit().await.unwrap();
        let row = get_by_kid(&db, "kid3").await.unwrap().unwrap();
        assert_eq!(row.used_at, Some(2_000));
    }

    #[tokio::test]
    async fn delete_removes_key() {
        let db = open_db().await;
        insert(&db, "kid4", "key", 1_000).await.unwrap();
        delete(&db, "kid4").await.unwrap();
        assert!(get_by_kid(&db, "kid4").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn insert_duplicate_kid_fails() {
        let db = open_db().await;
        insert(&db, "kid5", "key", 1_000).await.unwrap();
        assert!(insert(&db, "kid5", "key2", 2_000).await.is_err());
    }

    #[tokio::test]
    async fn insert_with_grants_stores_grants() {
        let db = open_db().await;
        insert_with_grants(&db, "kid6", "key", Some("[\"p1\"]"), 1_000)
            .await
            .unwrap();
        let row = get_by_kid(&db, "kid6").await.unwrap().unwrap();
        assert_eq!(row.profile_grants, Some("[\"p1\"]".to_string()));
    }

    #[tokio::test]
    async fn insert_with_grants_null_grants() {
        let db = open_db().await;
        insert_with_grants(&db, "kid7", "key", None, 1_000)
            .await
            .unwrap();
        let row = get_by_kid(&db, "kid7").await.unwrap().unwrap();
        assert!(row.profile_grants.is_none());
    }

    #[tokio::test]
    async fn insert_plain_has_null_grants() {
        let db = open_db().await;
        insert(&db, "kid8", "key", 1_000).await.unwrap();
        let row = get_by_kid(&db, "kid8").await.unwrap().unwrap();
        assert!(row.profile_grants.is_none());
    }
}
