use tokio_rusqlite::Connection;

use crate::error::AcmeError;

/// Insert a new nonce (must be called before returning it to the client).
pub async fn insert(db: &Connection, nonce: &str) -> Result<(), AcmeError> {
    let nonce = nonce.to_string();
    let now = now_secs();
    db.call(move |conn| {
        conn.execute(
            "INSERT INTO nonces (nonce, created) VALUES (?1, ?2)",
            rusqlite::params![nonce, now],
        )?;
        Ok(())
    })
    .await
    .map_err(AcmeError::from)
}

/// Consume a nonce: returns true if the nonce existed and was deleted,
/// false if it did not exist (replay or unknown).
pub async fn consume(db: &Connection, nonce: &str) -> Result<bool, AcmeError> {
    let nonce = nonce.to_string();
    db.call(move |conn| {
        let n = conn.execute(
            "DELETE FROM nonces WHERE nonce = ?1",
            rusqlite::params![nonce],
        )?;
        Ok(n > 0)
    })
    .await
    .map_err(AcmeError::from)
}

/// Delete nonces older than `max_age_secs` seconds.
pub async fn sweep_expired(db: &Connection, max_age_secs: i64) -> Result<u64, AcmeError> {
    let cutoff = now_secs().saturating_sub(max_age_secs);
    db.call(move |conn| {
        let n = conn.execute(
            "DELETE FROM nonces WHERE created < ?1",
            rusqlite::params![cutoff],
        )?;
        Ok(n as u64)
    })
    .await
    .map_err(AcmeError::from)
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
    use std::sync::Arc;

    async fn open_db() -> Arc<Connection> {
        Arc::new(crate::db::open(":memory:").await.unwrap())
    }

    #[tokio::test]
    async fn insert_and_consume_nonce() {
        let db = open_db().await;
        insert(&db, "test-nonce-1").await.unwrap();

        let consumed = consume(&db, "test-nonce-1").await.unwrap();
        assert!(consumed, "should consume existing nonce");

        // Second consume should return false (already deleted).
        let again = consume(&db, "test-nonce-1").await.unwrap();
        assert!(!again, "consuming same nonce twice should return false");
    }

    #[tokio::test]
    async fn consume_nonexistent_nonce_returns_false() {
        let db = open_db().await;
        let result = consume(&db, "nonexistent-nonce").await.unwrap();
        assert!(!result);
    }

    #[tokio::test]
    async fn sweep_expired_removes_old_nonces() {
        let db = open_db().await;

        // Insert a nonce.
        insert(&db, "old-nonce").await.unwrap();

        // Use max_age_secs = -1 so the cutoff is now + 1 second (future), which
        // means ALL nonces (created <= now) are considered "expired".
        let deleted = sweep_expired(&db, -1).await.unwrap();
        assert!(deleted >= 1, "should have deleted at least 1 nonce");

        // The nonce should no longer be consumable.
        let consumed = consume(&db, "old-nonce").await.unwrap();
        assert!(!consumed, "nonce should have been swept");
    }

    #[tokio::test]
    async fn sweep_expired_keeps_recent_nonces() {
        let db = open_db().await;
        insert(&db, "fresh-nonce").await.unwrap();

        // max_age_secs = 3600 means anything created within the last hour is kept.
        let deleted = sweep_expired(&db, 3600).await.unwrap();
        assert_eq!(deleted, 0, "recent nonce should not be deleted");

        // The nonce should still be consumable.
        let consumed = consume(&db, "fresh-nonce").await.unwrap();
        assert!(consumed);
    }

    #[tokio::test]
    async fn db_error_paths_no_table() {
        let raw = Arc::new(tokio_rusqlite::Connection::open_in_memory().await.unwrap());
        assert!(insert(&raw, "any-nonce").await.is_err());
        assert!(consume(&raw, "any-nonce").await.is_err());
        assert!(sweep_expired(&raw, 3600).await.is_err());
    }
}
