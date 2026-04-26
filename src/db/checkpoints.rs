use crate::db::schema::CheckpointRow;
use crate::error::AcmeError;

/// Return the checkpoint with the highest `tree_size`, or `None` if no
/// checkpoint has been produced yet.
pub async fn get_latest(
    executor: impl sqlx::Executor<'_, Database = sqlx::Any>,
) -> Result<Option<CheckpointRow>, AcmeError> {
    let row = sqlx::query_as::<_, CheckpointRow>(
        "SELECT id, tree_size, root_hex, signature, created
         FROM mtc_checkpoints
         ORDER BY tree_size DESC
         LIMIT 1",
    )
    .fetch_optional(executor)
    .await?;
    Ok(row)
}

/// Insert a checkpoint for `tree_size`.  If a row with the same `tree_size`
/// already exists it is left unchanged (idempotent).
pub async fn upsert(
    executor: impl sqlx::Executor<'_, Database = sqlx::Any>,
    tree_size: i64,
    root_hex: &str,
    signature: &[u8],
    created: i64,
) -> Result<(), AcmeError> {
    sqlx::query(
        "INSERT INTO mtc_checkpoints (tree_size, root_hex, signature, created)
         VALUES (?, ?, ?, ?)
         ON CONFLICT(tree_size) DO NOTHING",
    )
    .bind(tree_size)
    .bind(root_hex)
    .bind(signature)
    .bind(created)
    .execute(executor)
    .await?;
    Ok(())
}
