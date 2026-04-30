use crate::db::{Db, DbKind};
use crate::error::AcmeError;

/// Insert a new nonce (must be called before returning it to the client).
pub async fn insert(
    executor: impl sqlx::Executor<'_, Database = sqlx::Any>,
    nonce: &str,
) -> Result<(), AcmeError> {
    let now = now_secs();
    sqlx::query("INSERT INTO nonces (nonce, created) VALUES (?, ?)")
        .bind(nonce)
        .bind(now)
        .execute(executor)
        .await?;
    Ok(())
}

/// Consume a nonce: returns true if the nonce existed and was deleted,
/// false if it did not exist (replay or unknown).
pub async fn consume(
    executor: impl sqlx::Executor<'_, Database = sqlx::Any>,
    nonce: &str,
) -> Result<bool, AcmeError> {
    let n = sqlx::query("DELETE FROM nonces WHERE nonce = ?")
        .bind(nonce)
        .execute(executor)
        .await?
        .rows_affected();
    Ok(n > 0)
}

/// Consume an old nonce and atomically insert a new one in a single transaction.
///
/// Returns `true` if the old nonce was valid (deleted and replacement stored),
/// `false` if the old nonce was not found (replay or unknown).
///
/// Keeps `&Db` (not `impl Executor`) because it calls [`crate::db::begin_write`]
/// for internal atomicity — a pool reference is required to start a transaction.
pub async fn consume_and_insert(
    db: &Db,
    kind: DbKind,
    old_nonce: &str,
    new_nonce: &str,
) -> Result<bool, AcmeError> {
    let now = now_secs();
    let mut tx = crate::db::begin_write(db, kind).await?;

    let n = sqlx::query("DELETE FROM nonces WHERE nonce = ?")
        .bind(old_nonce)
        .execute(&mut *tx)
        .await?
        .rows_affected();

    if n == 0 {
        tx.rollback().await?;
        return Ok(false);
    }

    sqlx::query("INSERT INTO nonces (nonce, created) VALUES (?, ?)")
        .bind(new_nonce)
        .bind(now)
        .execute(&mut *tx)
        .await?;

    tx.commit().await?;
    Ok(true)
}

/// Delete nonces older than `max_age_secs` seconds.
pub async fn sweep_expired(
    executor: impl sqlx::Executor<'_, Database = sqlx::Any>,
    max_age_secs: i64,
) -> Result<u64, AcmeError> {
    let cutoff = now_secs().saturating_sub(max_age_secs);
    let n = sqlx::query("DELETE FROM nonces WHERE created < ?")
        .bind(cutoff)
        .execute(executor)
        .await?
        .rows_affected();
    Ok(n)
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

    async fn open_db() -> Db {
        crate::db::install_drivers();
        crate::db::open("sqlite::memory:", 1).await.unwrap()
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
        crate::db::install_drivers();
        let raw: Db = sqlx::any::AnyPoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        assert!(insert(&raw, "any-nonce").await.is_err());
        assert!(consume(&raw, "any-nonce").await.is_err());
        assert!(sweep_expired(&raw, 3600).await.is_err());
    }
}
