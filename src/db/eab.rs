//! External Account Binding key store (RFC 8555 §7.3.4).
//!
//! The `eab_keys` table is the canonical source of truth for all EAB keys,
//! regardless of how they were provisioned (config file or future admin
//! endpoint).  Config-file keys are seeded with `insert_if_absent()` on
//! startup so they never overwrite keys that were modified at runtime.

use sqlx::SqliteConnection;

use crate::error::AcmeError;

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct EabKeyRow {
    pub kid: String,
    pub hmac_key_b64u: String,
    pub created: i64,
    /// `None` → key is unused and may be consumed by a new-account request.
    pub used_at: Option<i64>,
}

/// Seed a key from the config file.
///
/// Uses `INSERT OR IGNORE` so that a key that already exists in the DB
/// (possibly modified or marked used by the admin endpoint) is left alone.
pub async fn insert_if_absent(
    conn: &mut SqliteConnection,
    kid: &str,
    hmac_key_b64u: &str,
    now: i64,
) -> Result<(), AcmeError> {
    sqlx::query(
        "INSERT OR IGNORE INTO eab_keys (kid, hmac_key_b64u, created) VALUES (?1, ?2, ?3)",
    )
    .bind(kid)
    .bind(hmac_key_b64u)
    .bind(now)
    .execute(&mut *conn)
    .await
    .map_err(|e| AcmeError::Database(e.to_string()))?;
    Ok(())
}

/// Provision a new key unconditionally (for the future admin endpoint).
///
/// Returns a `Database` error if a key with the same `kid` already exists.
pub async fn insert(
    conn: &mut SqliteConnection,
    kid: &str,
    hmac_key_b64u: &str,
    now: i64,
) -> Result<(), AcmeError> {
    sqlx::query(
        "INSERT INTO eab_keys (kid, hmac_key_b64u, created) VALUES (?1, ?2, ?3)",
    )
    .bind(kid)
    .bind(hmac_key_b64u)
    .bind(now)
    .execute(&mut *conn)
    .await
    .map_err(|e| AcmeError::Database(e.to_string()))?;
    Ok(())
}

/// Look up a key by its `kid`.  Returns `None` if the `kid` is unknown.
pub async fn get_by_kid(
    conn: &mut SqliteConnection,
    kid: &str,
) -> Result<Option<EabKeyRow>, AcmeError> {
    let row = sqlx::query_as::<_, EabKeyRow>(
        "SELECT kid, hmac_key_b64u, created, used_at FROM eab_keys WHERE kid = ?1",
    )
    .bind(kid)
    .fetch_optional(&mut *conn)
    .await
    .map_err(|e| AcmeError::Database(e.to_string()))?;
    Ok(row)
}

/// Mark a key as used *within an existing sqlx transaction*.
///
/// Call this atomically with the account INSERT so that the key is consumed
/// only when account creation fully commits, and the DB is left consistent
/// if the transaction rolls back.
pub async fn mark_used_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    kid: &str,
    now: i64,
) -> Result<(), AcmeError> {
    sqlx::query("UPDATE eab_keys SET used_at = ?1 WHERE kid = ?2")
        .bind(now)
        .bind(kid)
        .execute(&mut **tx)
        .await
        .map_err(|e| AcmeError::Database(e.to_string()))?;
    Ok(())
}

/// Delete a key entirely (for the future admin endpoint cleanup path).
pub async fn delete(conn: &mut SqliteConnection, kid: &str) -> Result<(), AcmeError> {
    sqlx::query("DELETE FROM eab_keys WHERE kid = ?1")
        .bind(kid)
        .execute(&mut *conn)
        .await
        .map_err(|e| AcmeError::Database(e.to_string()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use sqlx::Connection as _;

    use super::*;

    async fn open_db() -> crate::db::Db {
        crate::db::open(":memory:").await.unwrap()
    }

    macro_rules! conn {
        ($db:expr) => {
            &mut *$db.acquire().await.unwrap()
        };
    }

    #[tokio::test]
    async fn insert_and_get_by_kid() {
        let db = open_db().await;
        insert(conn!(db), "kid1", "c2VjcmV0", 1_700_000_000)
            .await
            .unwrap();
        let row = get_by_kid(conn!(db), "kid1").await.unwrap().unwrap();
        assert_eq!(row.kid, "kid1");
        assert_eq!(row.hmac_key_b64u, "c2VjcmV0");
        assert_eq!(row.created, 1_700_000_000);
        assert!(row.used_at.is_none());
    }

    #[tokio::test]
    async fn get_by_kid_unknown_returns_none() {
        let db = open_db().await;
        assert!(get_by_kid(conn!(db), "nope").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn insert_if_absent_does_not_overwrite() {
        let db = open_db().await;
        insert(conn!(db), "kid2", "original", 1_000)
            .await
            .unwrap();
        insert_if_absent(conn!(db), "kid2", "replacement", 2_000)
            .await
            .unwrap();
        let row = get_by_kid(conn!(db), "kid2").await.unwrap().unwrap();
        assert_eq!(row.hmac_key_b64u, "original");
    }

    #[tokio::test]
    async fn mark_used_tx_sets_used_at() {
        let db = open_db().await;
        insert(conn!(db), "kid3", "key", 1_000).await.unwrap();

        let mut conn = db.acquire().await.unwrap();
        let mut tx = (*conn).begin().await.unwrap();
        mark_used_tx(&mut tx, "kid3", 2_000).await.unwrap();
        tx.commit().await.unwrap();
        drop(conn);

        let row = get_by_kid(conn!(db), "kid3").await.unwrap().unwrap();
        assert_eq!(row.used_at, Some(2_000));
    }

    #[tokio::test]
    async fn delete_removes_key() {
        let db = open_db().await;
        insert(conn!(db), "kid4", "key", 1_000).await.unwrap();
        delete(conn!(db), "kid4").await.unwrap();
        assert!(get_by_kid(conn!(db), "kid4").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn insert_duplicate_kid_fails() {
        let db = open_db().await;
        insert(conn!(db), "kid5", "key", 1_000).await.unwrap();
        assert!(insert(conn!(db), "kid5", "key2", 2_000).await.is_err());
    }

    #[tokio::test]
    async fn db_error_paths_no_table() {
        use sqlx::Connection as _;
        let mut raw: sqlx::SqliteConnection =
            sqlx::SqliteConnection::connect("sqlite::memory:").await.unwrap();
        assert!(insert(&mut raw, "kid", "key", 0).await.is_err());
        assert!(get_by_kid(&mut raw, "kid").await.is_err());
        assert!(insert_if_absent(&mut raw, "kid", "key", 0).await.is_err());
        assert!(delete(&mut raw, "kid").await.is_err());
    }
}
