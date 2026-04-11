//! External Account Binding key store (RFC 8555 §7.3.4).
//!
//! The `eab_keys` table is the canonical source of truth for all EAB keys,
//! regardless of how they were provisioned (config file or future admin
//! endpoint).  Config-file keys are seeded with `insert_if_absent()` on
//! startup so they never overwrite keys that were modified at runtime.

use tokio_rusqlite::Connection;

use crate::error::AcmeError;

#[derive(Debug, Clone)]
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
    db: &Connection,
    kid: &str,
    hmac_key_b64u: &str,
    now: i64,
) -> Result<(), AcmeError> {
    let kid = kid.to_string();
    let key = hmac_key_b64u.to_string();
    db.call(move |conn| {
        conn.prepare_cached(
            "INSERT OR IGNORE INTO eab_keys (kid, hmac_key_b64u, created) \
             VALUES (?1, ?2, ?3)",
        )?
        .execute(rusqlite::params![kid, key, now])?;
        Ok(())
    })
    .await
    .map_err(AcmeError::from)
}

/// Provision a new key unconditionally (for the future admin endpoint).
///
/// Returns a `Conflict` error if a key with the same `kid` already exists.
pub async fn insert(
    db: &Connection,
    kid: &str,
    hmac_key_b64u: &str,
    now: i64,
) -> Result<(), AcmeError> {
    let kid = kid.to_string();
    let key = hmac_key_b64u.to_string();
    db.call(move |conn| {
        conn.prepare_cached(
            "INSERT INTO eab_keys (kid, hmac_key_b64u, created) VALUES (?1, ?2, ?3)",
        )?
        .execute(rusqlite::params![kid, key, now])?;
        Ok(())
    })
    .await
    .map_err(AcmeError::from)
}

/// Look up a key by its `kid`.  Returns `None` if the `kid` is unknown.
pub async fn get_by_kid(db: &Connection, kid: &str) -> Result<Option<EabKeyRow>, AcmeError> {
    let kid = kid.to_string();
    db.call(move |conn| {
        let mut stmt = conn.prepare_cached(
            "SELECT kid, hmac_key_b64u, created, used_at \
             FROM eab_keys WHERE kid = ?1",
        )?;
        let mut rows = stmt.query(rusqlite::params![kid])?;
        if let Some(row) = rows.next()? {
            Ok(Some(EabKeyRow {
                kid: row.get(0)?,
                hmac_key_b64u: row.get(1)?,
                created: row.get(2)?,
                used_at: row.get(3)?,
            }))
        } else {
            Ok(None)
        }
    })
    .await
    .map_err(AcmeError::from)
}

/// Mark a key as used *within an existing rusqlite transaction*.
///
/// Call this atomically with the account INSERT so that the key is consumed
/// only when account creation fully commits, and the DB is left consistent
/// if the transaction rolls back.
pub fn mark_used_tx(tx: &rusqlite::Transaction<'_>, kid: &str, now: i64) -> rusqlite::Result<()> {
    tx.prepare_cached("UPDATE eab_keys SET used_at = ?1 WHERE kid = ?2")?
        .execute(rusqlite::params![now, kid])?;
    Ok(())
}

/// Delete a key entirely (for the future admin endpoint cleanup path).
pub async fn delete(db: &Connection, kid: &str) -> Result<(), AcmeError> {
    let kid = kid.to_string();
    db.call(move |conn| {
        conn.prepare_cached("DELETE FROM eab_keys WHERE kid = ?1")?
            .execute(rusqlite::params![kid])?;
        Ok(())
    })
    .await
    .map_err(AcmeError::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    async fn open_db() -> Arc<Connection> {
        Arc::new(crate::db::open(":memory:").await.unwrap())
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
    async fn mark_used_tx_sets_used_at() {
        let db = open_db().await;
        insert(&db, "kid3", "key", 1_000).await.unwrap();
        db.call(|conn| {
            let tx = conn.transaction()?;
            mark_used_tx(&tx, "kid3", 2_000)?;
            Ok(tx.commit()?)
        })
        .await
        .unwrap();
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
}
