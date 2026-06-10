use crate::db::schema::RevokedRangeRow;
use crate::error::AcmeError;

/// Insert a revoked range.  Silently ignores duplicates.
pub async fn insert(
    pool: &sqlx::AnyPool,
    ca_id: &str,
    start: i64,
    end: i64,
    now: i64,
) -> Result<(), AcmeError> {
    super::query(
        "INSERT INTO mtc_revoked_ranges (ca_id, range_start, range_end, created)
         SELECT ?, ?, ?, ?
         WHERE NOT EXISTS (
             SELECT 1 FROM mtc_revoked_ranges
             WHERE ca_id = ? AND range_start = ? AND range_end = ?
         )",
    )
    .bind(ca_id)
    .bind(start)
    .bind(end)
    .bind(now)
    .bind(ca_id)
    .bind(start)
    .bind(end)
    .execute(pool)
    .await?;
    Ok(())
}

/// Return all revoked ranges for a CA, ordered by range_start.
pub async fn get_all(pool: &sqlx::AnyPool, ca_id: &str) -> Result<Vec<RevokedRangeRow>, AcmeError> {
    let rows = super::query_as::<RevokedRangeRow>(
        "SELECT id, ca_id, range_start, range_end, created
         FROM mtc_revoked_ranges WHERE ca_id = ? ORDER BY range_start",
    )
    .bind(ca_id)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

/// Delete a specific revoked range.
pub async fn delete(
    pool: &sqlx::AnyPool,
    ca_id: &str,
    start: i64,
    end: i64,
) -> Result<bool, AcmeError> {
    let result = super::query(
        "DELETE FROM mtc_revoked_ranges WHERE ca_id = ? AND range_start = ? AND range_end = ?",
    )
    .bind(ca_id)
    .bind(start)
    .bind(end)
    .execute(pool)
    .await?;
    Ok(result.rows_affected() > 0)
}
