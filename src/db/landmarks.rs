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
    let row = sqlx::query_as::<_, LandmarkRow>(
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
    let result = sqlx::query(
        "INSERT INTO mtc_landmarks (sequence_no, tree_size, cert_der, created)
         SELECT COALESCE(MAX(sequence_no), -1) + 1, ?, NULL, ?
         FROM mtc_landmarks
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
    sqlx::query("UPDATE mtc_landmarks SET cert_der = ? WHERE id = ?")
        .bind(cert_der)
        .bind(id)
        .execute(executor)
        .await?;
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
    let result = sqlx::query(
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
