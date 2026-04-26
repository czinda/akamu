use crate::db::schema::CosignatureRow;
use crate::error::AcmeError;

/// Upsert a cosignature row.  If the same cosigner returns a new signature for
/// an already-stored checkpoint, the stored signature is updated in place.
pub async fn upsert(
    executor: impl sqlx::Executor<'_, Database = sqlx::Any>,
    checkpoint_id: i64,
    cosigner_url: &str,
    signature_der: &[u8],
    created: i64,
) -> Result<(), AcmeError> {
    sqlx::query(
        "INSERT INTO mtc_cosignatures (checkpoint_id, cosigner_url, signature_der, created)
         VALUES (?, ?, ?, ?)
         ON CONFLICT(checkpoint_id, cosigner_url) DO UPDATE SET
             signature_der = excluded.signature_der,
             created = excluded.created",
    )
    .bind(checkpoint_id)
    .bind(cosigner_url)
    .bind(signature_der)
    .bind(created)
    .execute(executor)
    .await?;
    Ok(())
}

/// Delete cosignatures whose checkpoint has been pruned.
pub async fn prune_orphaned(
    executor: impl sqlx::Executor<'_, Database = sqlx::Any>,
) -> Result<u64, AcmeError> {
    let result = sqlx::query(
        "DELETE FROM mtc_cosignatures
         WHERE checkpoint_id NOT IN (SELECT id FROM mtc_checkpoints)",
    )
    .execute(executor)
    .await?;
    Ok(result.rows_affected())
}

/// Return all cosignatures stored for a given checkpoint.
pub async fn get_by_checkpoint(
    executor: impl sqlx::Executor<'_, Database = sqlx::Any>,
    checkpoint_id: i64,
) -> Result<Vec<CosignatureRow>, AcmeError> {
    let rows = sqlx::query_as::<_, CosignatureRow>(
        "SELECT id, checkpoint_id, cosigner_url, signature_der, created
         FROM mtc_cosignatures WHERE checkpoint_id = ?",
    )
    .bind(checkpoint_id)
    .fetch_all(executor)
    .await?;
    Ok(rows)
}
