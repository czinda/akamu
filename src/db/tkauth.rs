//! JTI replay-prevention cache for RFC 9447 tkauth-01 authority tokens.

use crate::db::Db;

/// Insert a JTI into the replay-prevention cache.
///
/// Returns `true` if the JTI was new (insertion succeeded), `false` if it was
/// already present (replay detected).  Uses a portable `WHERE NOT EXISTS`
/// sub-query — the same technique as `db::eab::insert_if_absent` — so it works
/// identically on SQLite, PostgreSQL, and MariaDB.
pub async fn insert_jti(
    db: &Db,
    jti: &str,
    authz_id: &str,
    expires: i64,
    now: i64,
) -> Result<bool, sqlx::Error> {
    let result = super::query(
        "INSERT INTO tkauth_jti_cache (jti, authz_id, expires, created) \
         SELECT ?, ?, ?, ? \
         WHERE NOT EXISTS (SELECT 1 FROM tkauth_jti_cache WHERE jti = ?)",
    )
    .bind(jti)
    .bind(authz_id)
    .bind(expires)
    .bind(now)
    .bind(jti)
    .execute(db)
    .await?;
    Ok(result.rows_affected() > 0)
}

/// Delete expired JTI entries. Returns the count of deleted rows.
pub async fn purge_expired(db: &Db, now: i64) -> Result<u64, sqlx::Error> {
    let result = super::query("DELETE FROM tkauth_jti_cache WHERE expires < ?")
        .bind(now)
        .execute(db)
        .await?;
    Ok(result.rows_affected())
}

/// Count expired JTI entries without deleting (for dry-run).
pub async fn count_expired(db: &Db, now: i64) -> Result<i64, sqlx::Error> {
    let row: (i64,) = super::query_as("SELECT COUNT(*) FROM tkauth_jti_cache WHERE expires < ?")
        .bind(now)
        .fetch_one(db)
        .await?;
    Ok(row.0)
}
