use crate::db::schema::CosignatureRow;
use crate::error::AcmeError;

/// Upsert a cosignature row.  The UNIQUE(checkpoint_id, cosigner_url) constraint
/// means a second call for the same cosigner on the same checkpoint is a no-op.
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
         ON CONFLICT(checkpoint_id, cosigner_url) DO NOTHING",
    )
    .bind(checkpoint_id)
    .bind(cosigner_url)
    .bind(signature_der)
    .bind(created)
    .execute(executor)
    .await?;
    Ok(())
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
