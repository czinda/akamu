use sqlx::{Connection as _, SqliteConnection};

use crate::error::AcmeError;

/// Insert a new nonce (must be called before returning it to the client).
pub async fn insert(conn: &mut SqliteConnection, nonce: &str) -> Result<(), AcmeError> {
    let now = now_secs();
    sqlx::query("INSERT INTO nonces (nonce, created) VALUES (?1, ?2)")
        .bind(nonce)
        .bind(now)
        .execute(&mut *conn)
        .await
        .map_err(|e| AcmeError::Database(e.to_string()))?;
    Ok(())
}

/// Consume a nonce: returns true if the nonce existed and was deleted,
/// false if it did not exist (replay or unknown).
pub async fn consume(conn: &mut SqliteConnection, nonce: &str) -> Result<bool, AcmeError> {
    let result = sqlx::query("DELETE FROM nonces WHERE nonce = ?1")
        .bind(nonce)
        .execute(&mut *conn)
        .await
        .map_err(|e| AcmeError::Database(e.to_string()))?;
    Ok(result.rows_affected() > 0)
}

/// Consume an old nonce and atomically insert a new one in a single DB transaction.
///
/// Returns `true` if the old nonce was valid (deleted and replacement stored),
/// `false` if the old nonce was not found (replay or unknown).
pub async fn consume_and_insert(
    conn: &mut SqliteConnection,
    old_nonce: &str,
    new_nonce: &str,
) -> Result<bool, AcmeError> {
    let now = now_secs();
    let mut tx = conn
        .begin()
        .await
        .map_err(|e| AcmeError::Database(e.to_string()))?;

    let result = sqlx::query("DELETE FROM nonces WHERE nonce = ?1")
        .bind(old_nonce)
        .execute(&mut *tx)
        .await
        .map_err(|e| AcmeError::Database(e.to_string()))?;

    if result.rows_affected() == 0 {
        tx.rollback()
            .await
            .map_err(|e| AcmeError::Database(e.to_string()))?;
        return Ok(false);
    }

    sqlx::query("INSERT INTO nonces (nonce, created) VALUES (?1, ?2)")
        .bind(new_nonce)
        .bind(now)
        .execute(&mut *tx)
        .await
        .map_err(|e| AcmeError::Database(e.to_string()))?;

    tx.commit()
        .await
        .map_err(|e| AcmeError::Database(e.to_string()))?;

    Ok(true)
}

/// Delete nonces older than `max_age_secs` seconds.
pub async fn sweep_expired(
    conn: &mut SqliteConnection,
    max_age_secs: i64,
) -> Result<u64, AcmeError> {
    let cutoff = now_secs().saturating_sub(max_age_secs);
    let result = sqlx::query("DELETE FROM nonces WHERE created < ?1")
        .bind(cutoff)
        .execute(&mut *conn)
        .await
        .map_err(|e| AcmeError::Database(e.to_string()))?;
    Ok(result.rows_affected())
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

#[cfg(test)]
mod tests {
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
    async fn insert_and_consume_nonce() {
        let db = open_db().await;
        insert(conn!(db), "test-nonce-1").await.unwrap();

        let consumed = consume(conn!(db), "test-nonce-1").await.unwrap();
        assert!(consumed, "should consume existing nonce");

        // Second consume should return false (already deleted).
        let again = consume(conn!(db), "test-nonce-1").await.unwrap();
        assert!(!again, "consuming same nonce twice should return false");
    }

    #[tokio::test]
    async fn consume_nonexistent_nonce_returns_false() {
        let db = open_db().await;
        let result = consume(conn!(db), "nonexistent-nonce").await.unwrap();
        assert!(!result);
    }

    #[tokio::test]
    async fn sweep_expired_removes_old_nonces() {
        let db = open_db().await;

        // Insert a nonce.
        insert(conn!(db), "old-nonce").await.unwrap();

        // Use max_age_secs = -1 so the cutoff is now + 1 second (future), which
        // means ALL nonces (created <= now) are considered "expired".
        let deleted = sweep_expired(conn!(db), -1).await.unwrap();
        assert!(deleted >= 1, "should have deleted at least 1 nonce");

        // The nonce should no longer be consumable.
        let consumed = consume(conn!(db), "old-nonce").await.unwrap();
        assert!(!consumed, "nonce should have been swept");
    }

    #[tokio::test]
    async fn sweep_expired_keeps_recent_nonces() {
        let db = open_db().await;
        insert(conn!(db), "fresh-nonce").await.unwrap();

        // max_age_secs = 3600 means anything created within the last hour is kept.
        let deleted = sweep_expired(conn!(db), 3600).await.unwrap();
        assert_eq!(deleted, 0, "recent nonce should not be deleted");

        // The nonce should still be consumable.
        let consumed = consume(conn!(db), "fresh-nonce").await.unwrap();
        assert!(consumed);
    }

    #[tokio::test]
    async fn db_error_paths_no_table() {
        use sqlx::Connection as _;
        let mut raw: sqlx::SqliteConnection =
            sqlx::SqliteConnection::connect("sqlite::memory:").await.unwrap();
        assert!(insert(&mut raw, "any-nonce").await.is_err());
        assert!(consume(&mut raw, "any-nonce").await.is_err());
        assert!(sweep_expired(&mut raw, 3600).await.is_err());
    }
}
