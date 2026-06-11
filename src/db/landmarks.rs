use crate::db::schema::LandmarkRow;
use crate::error::AcmeError;

/// Return the most recently allocated landmark for a given CA, if any.
pub async fn get_latest(
    executor: impl sqlx::Executor<'_, Database = sqlx::Any>,
    ca_id: &str,
) -> Result<Option<LandmarkRow>, AcmeError> {
    let row = super::query_as::<LandmarkRow>(
        "SELECT id, ca_id, sequence_no, tree_size, cert_der, created
         FROM mtc_landmarks WHERE ca_id = ? ORDER BY sequence_no DESC LIMIT 1",
    )
    .bind(ca_id)
    .fetch_optional(executor)
    .await?;
    Ok(row)
}

/// Return all landmark rows for a given CA ordered by sequence_no ascending.
///
/// `cert_der` is not fetched (NULL in result) to avoid loading potentially
/// large blobs when only the metadata fields are needed.
pub async fn list(
    executor: impl sqlx::Executor<'_, Database = sqlx::Any>,
    ca_id: &str,
) -> Result<Vec<LandmarkRow>, AcmeError> {
    let rows = super::query_as::<LandmarkRow>(
        "SELECT id, ca_id, sequence_no, tree_size, NULL AS cert_der, created
         FROM mtc_landmarks WHERE ca_id = ? ORDER BY sequence_no ASC",
    )
    .bind(ca_id)
    .fetch_all(executor)
    .await?;
    Ok(rows)
}

/// Return a single landmark by its sequence number for a given CA.
pub async fn get_by_seq(
    executor: impl sqlx::Executor<'_, Database = sqlx::Any>,
    ca_id: &str,
    sequence_no: i64,
) -> Result<Option<LandmarkRow>, AcmeError> {
    let row = super::query_as::<LandmarkRow>(
        "SELECT id, ca_id, sequence_no, tree_size, cert_der, created
         FROM mtc_landmarks WHERE ca_id = ? AND sequence_no = ?",
    )
    .bind(ca_id)
    .bind(sequence_no)
    .fetch_optional(executor)
    .await?;
    Ok(row)
}

/// Return the first landmark whose `tree_size > log_index` for a given CA.
pub async fn get_covering(
    executor: impl sqlx::Executor<'_, Database = sqlx::Any>,
    ca_id: &str,
    log_index: i64,
) -> Result<Option<LandmarkRow>, AcmeError> {
    let row = super::query_as::<LandmarkRow>(
        "SELECT id, ca_id, sequence_no, tree_size, cert_der, created
         FROM mtc_landmarks WHERE ca_id = ? AND tree_size > ?
         ORDER BY tree_size ASC LIMIT 1",
    )
    .bind(ca_id)
    .bind(log_index)
    .fetch_optional(executor)
    .await?;
    Ok(row)
}

/// Allocate a new landmark at the given tree size for a given CA.
///
/// Returns `true` if the row was inserted, `false` if a landmark for this
/// `(ca_id, tree_size)` already exists (idempotent).
pub async fn insert(
    executor: impl sqlx::Executor<'_, Database = sqlx::Any>,
    ca_id: &str,
    tree_size: i64,
    created: i64,
) -> Result<bool, AcmeError> {
    let result = super::query(
        "INSERT INTO mtc_landmarks (ca_id, sequence_no, tree_size, cert_der, created)
         SELECT ?,
             (SELECT COALESCE(MAX(sequence_no), -1) + 1 FROM mtc_landmarks WHERE ca_id = ?),
             ?, NULL, ?
         WHERE NOT EXISTS (SELECT 1 FROM mtc_landmarks WHERE ca_id = ? AND tree_size = ?)",
    )
    .bind(ca_id)
    .bind(ca_id)
    .bind(tree_size)
    .bind(created)
    .bind(ca_id)
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

/// Return the count of active landmarks for a given CA.
pub async fn count(
    executor: impl sqlx::Executor<'_, Database = sqlx::Any>,
    ca_id: &str,
) -> Result<i64, AcmeError> {
    let row: (i64,) =
        super::query_as::<(i64,)>("SELECT COUNT(*) FROM mtc_landmarks WHERE ca_id = ?")
            .bind(ca_id)
            .fetch_one(executor)
            .await?;
    Ok(row.0)
}

/// Delete the oldest landmarks for a given CA, keeping only the most recent
/// `keep_count`.
///
/// No-op when fewer than `keep_count` rows exist.  Returns the number of
/// deleted rows.
pub async fn prune_oldest(
    executor: impl sqlx::Executor<'_, Database = sqlx::Any>,
    ca_id: &str,
    keep_count: u32,
) -> Result<u64, AcmeError> {
    if keep_count == 0 {
        return Ok(0);
    }
    let result = super::query(
        "DELETE FROM mtc_landmarks
         WHERE ca_id = ? AND sequence_no NOT IN (
             SELECT sequence_no FROM (
                 SELECT sequence_no FROM mtc_landmarks
                 WHERE ca_id = ?
                 ORDER BY sequence_no DESC
                 LIMIT ?
             ) _keep
         )",
    )
    .bind(ca_id)
    .bind(ca_id)
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
        assert!(get_latest(&db, "ca1").await.unwrap().is_none());

        let inserted = insert(&db, "ca1", 100, 1000).await.unwrap();
        assert!(inserted, "first insert should succeed");

        let lm = get_latest(&db, "ca1").await.unwrap().unwrap();
        assert_eq!(lm.tree_size, 100);
        assert_eq!(lm.sequence_no, 0);
        assert!(lm.cert_der.is_none());

        let inserted2 = insert(&db, "ca1", 200, 2000).await.unwrap();
        assert!(inserted2);
        let lm2 = get_latest(&db, "ca1").await.unwrap().unwrap();
        assert_eq!(lm2.tree_size, 200);
        assert_eq!(lm2.sequence_no, 1);
    }

    #[tokio::test]
    async fn insert_duplicate_tree_size_is_noop() {
        let db = open_db().await;
        assert!(insert(&db, "ca1", 100, 1000).await.unwrap());
        let dup = insert(&db, "ca1", 100, 9999).await.unwrap();
        assert!(!dup, "duplicate tree_size should return false");
        assert_eq!(count(&db, "ca1").await.unwrap(), 1);
    }

    #[tokio::test]
    async fn different_cas_are_independent() {
        let db = open_db().await;
        assert!(insert(&db, "ca1", 100, 1000).await.unwrap());
        assert!(insert(&db, "ca2", 100, 2000).await.unwrap());
        assert_eq!(count(&db, "ca1").await.unwrap(), 1);
        assert_eq!(count(&db, "ca2").await.unwrap(), 1);

        let lm1 = get_latest(&db, "ca1").await.unwrap().unwrap();
        let lm2 = get_latest(&db, "ca2").await.unwrap().unwrap();
        assert_eq!(lm1.sequence_no, 0);
        assert_eq!(lm2.sequence_no, 0);
    }

    #[tokio::test]
    async fn get_by_seq_and_set_cert_der() {
        let db = open_db().await;
        insert(&db, "ca1", 10, 100).await.unwrap();

        let lm = get_by_seq(&db, "ca1", 0).await.unwrap().unwrap();
        assert_eq!(lm.tree_size, 10);
        assert!(lm.cert_der.is_none());

        set_cert_der(&db, lm.id, b"der_bytes").await.unwrap();
        let updated = get_by_seq(&db, "ca1", 0).await.unwrap().unwrap();
        assert_eq!(updated.cert_der.as_deref(), Some(b"der_bytes".as_ref()));
    }

    #[tokio::test]
    async fn list_excludes_cert_der() {
        let db = open_db().await;
        insert(&db, "ca1", 10, 100).await.unwrap();
        let lm_id = get_latest(&db, "ca1").await.unwrap().unwrap().id;
        set_cert_der(&db, lm_id, b"heavy_blob").await.unwrap();

        let rows = list(&db, "ca1").await.unwrap();
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
            insert(&db, "ca1", i * 10, i * 100).await.unwrap();
        }
        let deleted = prune_oldest(&db, "ca1", 3).await.unwrap();
        assert_eq!(deleted, 2);
        assert_eq!(count(&db, "ca1").await.unwrap(), 3);
        let latest = get_latest(&db, "ca1").await.unwrap().unwrap();
        assert_eq!(latest.sequence_no, 4);
    }
}
