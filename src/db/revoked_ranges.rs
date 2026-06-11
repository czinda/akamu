use crate::db::schema::RevokedRangeRow;
use crate::error::AcmeError;

/// Insert a revoked range.  Silently ignores duplicates.
pub async fn insert(
    executor: impl sqlx::Executor<'_, Database = sqlx::Any>,
    ca_id: &str,
    start: i64,
    end: i64,
    now: i64,
) -> Result<(), AcmeError> {
    if start > end {
        return Err(AcmeError::BadRequest(
            "range_start must be <= range_end".into(),
        ));
    }
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
    .execute(executor)
    .await?;
    Ok(())
}

/// Return all revoked ranges for a CA, ordered by range_start.
pub async fn get_all(
    executor: impl sqlx::Executor<'_, Database = sqlx::Any>,
    ca_id: &str,
) -> Result<Vec<RevokedRangeRow>, AcmeError> {
    let rows = super::query_as::<RevokedRangeRow>(
        "SELECT id, ca_id, range_start, range_end, created
         FROM mtc_revoked_ranges WHERE ca_id = ? ORDER BY range_start",
    )
    .bind(ca_id)
    .fetch_all(executor)
    .await?;
    Ok(rows)
}

/// Delete a specific revoked range.
pub async fn delete(
    executor: impl sqlx::Executor<'_, Database = sqlx::Any>,
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
    .execute(executor)
    .await?;
    Ok(result.rows_affected() > 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn open_db() -> crate::db::Db {
        crate::db::install_drivers();
        crate::db::open("sqlite::memory:", 1, false).await.unwrap()
    }

    #[tokio::test]
    async fn insert_and_get_all() {
        let db = open_db().await;
        assert!(get_all(&db, "ca1").await.unwrap().is_empty());

        insert(&db, "ca1", 10, 20, 1000).await.unwrap();
        let rows = get_all(&db, "ca1").await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].ca_id, "ca1");
        assert_eq!(rows[0].range_start, 10);
        assert_eq!(rows[0].range_end, 20);
        assert_eq!(rows[0].created, 1000);
    }

    #[tokio::test]
    async fn insert_duplicate_is_noop() {
        let db = open_db().await;
        insert(&db, "ca1", 10, 20, 1000).await.unwrap();
        // Same range again -- should silently succeed without adding a row
        insert(&db, "ca1", 10, 20, 9999).await.unwrap();
        let rows = get_all(&db, "ca1").await.unwrap();
        assert_eq!(rows.len(), 1, "duplicate insert should not add a row");
    }

    #[tokio::test]
    async fn delete_removes_row() {
        let db = open_db().await;
        insert(&db, "ca1", 10, 20, 1000).await.unwrap();
        insert(&db, "ca1", 30, 40, 2000).await.unwrap();

        let deleted = delete(&db, "ca1", 10, 20).await.unwrap();
        assert!(deleted, "existing range should be deleted");

        let rows = get_all(&db, "ca1").await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].range_start, 30);

        let deleted_again = delete(&db, "ca1", 10, 20).await.unwrap();
        assert!(!deleted_again, "already-deleted range should return false");
    }

    #[tokio::test]
    async fn different_cas_are_independent() {
        let db = open_db().await;
        insert(&db, "ca1", 10, 20, 1000).await.unwrap();
        insert(&db, "ca2", 10, 20, 2000).await.unwrap();

        let rows1 = get_all(&db, "ca1").await.unwrap();
        let rows2 = get_all(&db, "ca2").await.unwrap();
        assert_eq!(rows1.len(), 1);
        assert_eq!(rows2.len(), 1);
        // Same range coordinates but different created timestamps prove independence
        assert_eq!(rows1[0].created, 1000);
        assert_eq!(rows2[0].created, 2000);

        // Deleting from ca1 should not affect ca2
        delete(&db, "ca1", 10, 20).await.unwrap();
        assert!(get_all(&db, "ca1").await.unwrap().is_empty());
        assert_eq!(get_all(&db, "ca2").await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn insert_rejects_inverted_range() {
        let db = open_db().await;
        let err = insert(&db, "ca1", 20, 10, 1000).await.unwrap_err();
        assert!(
            err.to_string().contains("range_start must be <= range_end"),
            "unexpected error: {err}"
        );
    }
}
