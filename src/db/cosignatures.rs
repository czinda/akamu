use crate::db::schema::CosignatureRow;
use crate::error::AcmeError;

/// Upsert a cosignature row.  If the same cosigner returns a new signature for
/// an already-stored checkpoint, the stored signature is updated in place.
///
/// Uses a two-step UPDATE + conditional INSERT to stay compatible with MariaDB,
/// which does not support `ON CONFLICT … DO UPDATE SET`.
pub async fn upsert(
    pool: &sqlx::AnyPool,
    ca_id: &str,
    checkpoint_id: i64,
    cosigner_url: &str,
    signature_der: &[u8],
    created: i64,
) -> Result<(), AcmeError> {
    let updated = super::query(
        "UPDATE mtc_cosignatures SET signature_der = ?, created = ?
         WHERE checkpoint_id = ? AND cosigner_url = ?",
    )
    .bind(signature_der)
    .bind(created)
    .bind(checkpoint_id)
    .bind(cosigner_url)
    .execute(pool)
    .await?
    .rows_affected();

    if updated == 0 {
        super::query(
            "INSERT INTO mtc_cosignatures (ca_id, checkpoint_id, cosigner_url, signature_der, created)
             SELECT ?, ?, ?, ?, ?
             WHERE NOT EXISTS (
                 SELECT 1 FROM mtc_cosignatures
                 WHERE checkpoint_id = ? AND cosigner_url = ?
             )",
        )
        .bind(ca_id)
        .bind(checkpoint_id)
        .bind(cosigner_url)
        .bind(signature_der)
        .bind(created)
        .bind(checkpoint_id)
        .bind(cosigner_url)
        .execute(pool)
        .await?;
    }

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
    let rows = super::query_as::<CosignatureRow>(
        "SELECT id, checkpoint_id, cosigner_url, signature_der, created
         FROM mtc_cosignatures WHERE checkpoint_id = ?",
    )
    .bind(checkpoint_id)
    .fetch_all(executor)
    .await?;
    Ok(rows)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::checkpoints;

    async fn open_db() -> crate::db::Db {
        crate::db::install_drivers();
        crate::db::open("sqlite::memory:", 1, false).await.unwrap()
    }

    async fn insert_checkpoint(db: &crate::db::Db, ca_id: &str, tree_size: i64) -> i64 {
        checkpoints::upsert(db, ca_id, tree_size, "aabb", b"sig", tree_size * 100)
            .await
            .unwrap();
        checkpoints::get_latest(db, ca_id)
            .await
            .unwrap()
            .unwrap()
            .id
    }

    #[tokio::test]
    async fn upsert_and_retrieve() {
        let db = open_db().await;
        let chk_id = insert_checkpoint(&db, "ca1", 10).await;

        upsert(
            &db,
            "ca1",
            chk_id,
            "https://cosigner.example",
            b"cosig1",
            1000,
        )
        .await
        .unwrap();

        let rows = get_by_checkpoint(&db, chk_id).await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].cosigner_url, "https://cosigner.example");
        assert_eq!(rows[0].signature_der, b"cosig1");
    }

    #[tokio::test]
    async fn upsert_updates_existing_signature() {
        let db = open_db().await;
        let chk_id = insert_checkpoint(&db, "ca1", 10).await;

        upsert(&db, "ca1", chk_id, "https://cosigner.example", b"old", 1000)
            .await
            .unwrap();
        upsert(&db, "ca1", chk_id, "https://cosigner.example", b"new", 2000)
            .await
            .unwrap();

        let rows = get_by_checkpoint(&db, chk_id).await.unwrap();
        assert_eq!(rows.len(), 1, "should not duplicate");
        assert_eq!(rows[0].signature_der, b"new", "should update to new sig");
    }

    #[tokio::test]
    async fn cosignatures_cascade_on_checkpoint_prune() {
        let db = open_db().await;

        let old_id = insert_checkpoint(&db, "ca1", 10).await;
        insert_checkpoint(&db, "ca1", 20).await;
        upsert(&db, "ca1", old_id, "https://cosigner.example", b"sig", 1000)
            .await
            .unwrap();

        checkpoints::prune_oldest(&db, "ca1", 1).await.unwrap();
        assert!(
            get_by_checkpoint(&db, old_id).await.unwrap().is_empty(),
            "cosignature should be removed by cascade"
        );
    }

    #[tokio::test]
    async fn prune_orphaned_is_noop_when_cascade_cleaned() {
        let db = open_db().await;

        let old_id = insert_checkpoint(&db, "ca1", 10).await;
        insert_checkpoint(&db, "ca1", 20).await;
        upsert(&db, "ca1", old_id, "https://cosigner.example", b"sig", 1000)
            .await
            .unwrap();

        checkpoints::prune_oldest(&db, "ca1", 1).await.unwrap();

        let deleted = prune_orphaned(&db).await.unwrap();
        assert_eq!(deleted, 0, "cascade already cleaned up the cosignature");
    }
}
