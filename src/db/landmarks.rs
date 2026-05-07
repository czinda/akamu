use crate::db::schema::LandmarkRow;
use crate::error::AcmeError;

/// Return the most recently allocated landmark, if any.
pub async fn get_latest(
    executor: impl sqlx::Executor<'_, Database = sqlx::Any>,
) -> Result<Option<LandmarkRow>, AcmeError> {
    let row = sqlx::query_as::<_, LandmarkRow>(
        "SELECT id, sequence_no, tree_size, cert_der, created
         FROM mtc_landmarks ORDER BY sequence_no DESC LIMIT 1",
    )
    .fetch_optional(executor)
    .await?;
    Ok(row)
}

/// Return all landmark rows ordered by sequence_no ascending.
///
/// `cert_der` is not fetched (NULL in result) to avoid loading potentially
/// large blobs when only the metadata fields are needed.
pub async fn list(
    executor: impl sqlx::Executor<'_, Database = sqlx::Any>,
) -> Result<Vec<LandmarkRow>, AcmeError> {
    let rows = sqlx::query_as::<_, LandmarkRow>(
        "SELECT id, sequence_no, tree_size, NULL AS cert_der, created
         FROM mtc_landmarks ORDER BY sequence_no ASC",
    )
    .fetch_all(executor)
    .await?;
    Ok(rows)
}

/// Return a single landmark by its sequence number.
pub async fn get_by_seq(
    executor: impl sqlx::Executor<'_, Database = sqlx::Any>,
    sequence_no: i64,
) -> Result<Option<LandmarkRow>, AcmeError> {
    let row = super::query_as::<LandmarkRow>(
        "SELECT id, sequence_no, tree_size, cert_der, created
         FROM mtc_landmarks WHERE sequence_no = ?",
    )
    .bind(sequence_no)
    .fetch_optional(executor)
    .await?;
    Ok(row)
}

/// Allocate a new landmark at the given tree size.
///
/// Returns `true` if the row was inserted, `false` if a landmark for this
/// `tree_size` already exists (idempotent).  The inserted row's fields are
/// fetched by the caller via `get_latest`.
pub async fn insert(
    executor: impl sqlx::Executor<'_, Database = sqlx::Any>,
    tree_size: i64,
    created: i64,
) -> Result<bool, AcmeError> {
    // Use a FROM-less SELECT so that the aggregate MAX() subquery does not
    // produce a spurious output row when NOT EXISTS is false.  A SELECT without
    // FROM produces exactly 0 or 1 row depending on the WHERE condition.
    let result = super::query(
        "INSERT INTO mtc_landmarks (sequence_no, tree_size, cert_der, created)
         SELECT
             (SELECT COALESCE(MAX(sequence_no), -1) + 1 FROM mtc_landmarks),
             ?, NULL, ?
         WHERE NOT EXISTS (SELECT 1 FROM mtc_landmarks WHERE tree_size = ?)",
    )
    .bind(tree_size)
    .bind(created)
    .bind(tree_size)
    .execute(executor)
    .await?;

    Ok(result.rows_affected() > 0)
}

/// Store the DER-encoded LandmarkCertificate for a landmark row.
pub async fn set_cert_der(
    executor: impl sqlx::Executor<'_, Database = sqlx::Any>,
    id: i64,
    cert_der: &[u8],
) -> Result<(), AcmeError> {
    let result = super::query("UPDATE mtc_landmarks SET cert_der = ? WHERE id = ?")
        .bind(cert_der)
        .bind(id)
        .execute(executor)
        .await?;
    if result.rows_affected() == 0 {
        return Err(AcmeError::Database(format!(
            "set_cert_der: landmark id {id} not found"
        )));
    }
    Ok(())
}

/// Return the count of active landmarks.
pub async fn count(
    executor: impl sqlx::Executor<'_, Database = sqlx::Any>,
) -> Result<i64, AcmeError> {
    let row: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM mtc_landmarks")
        .fetch_one(executor)
        .await?;
    Ok(row.0)
}

/// Delete the oldest landmarks, keeping only the most recent `keep_count`.
///
/// No-op when fewer than `keep_count` rows exist.  Returns the number of
/// deleted rows.
pub async fn prune_oldest(
    executor: impl sqlx::Executor<'_, Database = sqlx::Any>,
    keep_count: u32,
) -> Result<u64, AcmeError> {
    if keep_count == 0 {
        return Ok(0);
    }
    let result = super::query(
        "DELETE FROM mtc_landmarks
         WHERE sequence_no NOT IN (
             SELECT sequence_no FROM (
                 SELECT sequence_no FROM mtc_landmarks
                 ORDER BY sequence_no DESC
                 LIMIT ?
             ) _keep
         )",
    )
    .bind(keep_count as i64)
    .execute(executor)
    .await?;
    Ok(result.rows_affected())
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn open_db() -> crate::db::Db {
        crate::db::install_drivers();
        crate::db::open("sqlite::memory:", 1, false).await.unwrap()
    }

    #[tokio::test]
    async fn insert_and_get_latest() {
        let db = open_db().await;
        assert!(get_latest(&db).await.unwrap().is_none());

        let inserted = insert(&db, 100, 1000).await.unwrap();
        assert!(inserted, "first insert should succeed");

        let lm = get_latest(&db).await.unwrap().unwrap();
        assert_eq!(lm.tree_size, 100);
        assert_eq!(lm.sequence_no, 0);
        assert!(lm.cert_der.is_none());

        let inserted2 = insert(&db, 200, 2000).await.unwrap();
        assert!(inserted2);
        let lm2 = get_latest(&db).await.unwrap().unwrap();
        assert_eq!(lm2.tree_size, 200);
        assert_eq!(lm2.sequence_no, 1);
    }

    #[tokio::test]
    async fn insert_duplicate_tree_size_is_noop() {
        let db = open_db().await;
        assert!(insert(&db, 100, 1000).await.unwrap());
        let dup = insert(&db, 100, 9999).await.unwrap();
        assert!(!dup, "duplicate tree_size should return false");
        assert_eq!(count(&db).await.unwrap(), 1);
    }

    #[tokio::test]
    async fn get_by_seq_and_set_cert_der() {
        let db = open_db().await;
        insert(&db, 10, 100).await.unwrap();

        let lm = get_by_seq(&db, 0).await.unwrap().unwrap();
        assert_eq!(lm.tree_size, 10);
        assert!(lm.cert_der.is_none());

        set_cert_der(&db, lm.id, b"der_bytes").await.unwrap();
        let updated = get_by_seq(&db, 0).await.unwrap().unwrap();
        assert_eq!(updated.cert_der.as_deref(), Some(b"der_bytes".as_ref()));
    }

    #[tokio::test]
    async fn list_excludes_cert_der() {
        let db = open_db().await;
        insert(&db, 10, 100).await.unwrap();
        let lm_id = get_latest(&db).await.unwrap().unwrap().id;
        set_cert_der(&db, lm_id, b"heavy_blob").await.unwrap();

        let rows = list(&db).await.unwrap();
        assert_eq!(rows.len(), 1);
        assert!(
            rows[0].cert_der.is_none(),
            "list should not return cert_der"
        );
    }

    #[tokio::test]
    async fn prune_oldest_keeps_most_recent() {
        let db = open_db().await;
        for i in 1i64..=5 {
            insert(&db, i * 10, i * 100).await.unwrap();
        }
        let deleted = prune_oldest(&db, 3).await.unwrap();
        assert_eq!(deleted, 2);
        assert_eq!(count(&db).await.unwrap(), 3);
        let latest = get_latest(&db).await.unwrap().unwrap();
        assert_eq!(latest.sequence_no, 4);
    }
}
