use crate::db::schema::CheckpointRow;
use crate::error::AcmeError;

/// Delete the oldest checkpoints for a given CA, keeping only the most recent
/// `keep_count`.
///
/// Call `cosignatures::prune_orphaned` after this to remove cosignatures whose
/// checkpoint row has been deleted.  Returns the number of deleted rows.
pub async fn prune_oldest(
    executor: impl sqlx::Executor<'_, Database = sqlx::Any>,
    ca_id: &str,
    keep_count: u32,
) -> Result<u64, AcmeError> {
    if keep_count == 0 {
        return Ok(0);
    }
    let result = super::query(
        "DELETE FROM mtc_checkpoints
         WHERE ca_id = ? AND id NOT IN (
             SELECT id FROM (
                 SELECT id FROM mtc_checkpoints
                 WHERE ca_id = ?
                 ORDER BY tree_size DESC
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

/// Return the checkpoint with the highest `tree_size` for a given CA, or `None`
/// if no checkpoint has been produced yet.
pub async fn get_latest(
    executor: impl sqlx::Executor<'_, Database = sqlx::Any>,
    ca_id: &str,
) -> Result<Option<CheckpointRow>, AcmeError> {
    let row = super::query_as::<CheckpointRow>(
        "SELECT id, ca_id, tree_size, root_hex, signature, created
         FROM mtc_checkpoints
         WHERE ca_id = ?
         ORDER BY tree_size DESC
         LIMIT 1",
    )
    .bind(ca_id)
    .fetch_optional(executor)
    .await?;
    Ok(row)
}

/// Insert a checkpoint for `tree_size`.  If a row with the same `(ca_id,
/// tree_size)` already exists it is left unchanged (idempotent).
pub async fn upsert(
    executor: impl sqlx::Executor<'_, Database = sqlx::Any>,
    ca_id: &str,
    tree_size: i64,
    root_hex: &str,
    signature: &[u8],
    created: i64,
) -> Result<(), AcmeError> {
    super::query(
        "INSERT INTO mtc_checkpoints (ca_id, tree_size, root_hex, signature, created)
         SELECT ?, ?, ?, ?, ?
         WHERE NOT EXISTS (SELECT 1 FROM mtc_checkpoints WHERE ca_id = ? AND tree_size = ?)",
    )
    .bind(ca_id)
    .bind(tree_size)
    .bind(root_hex)
    .bind(signature)
    .bind(created)
    .bind(ca_id)
    .bind(tree_size)
    .execute(executor)
    .await?;
    Ok(())
}

/// Return the checkpoint with the given `tree_size` for a given CA, or `None`
/// if not found.
pub async fn get_by_tree_size(
    executor: impl sqlx::Executor<'_, Database = sqlx::Any>,
    ca_id: &str,
    tree_size: i64,
) -> Result<Option<CheckpointRow>, AcmeError> {
    let row = super::query_as::<CheckpointRow>(
        "SELECT id, ca_id, tree_size, root_hex, signature, created
         FROM mtc_checkpoints WHERE ca_id = ? AND tree_size = ?",
    )
    .bind(ca_id)
    .bind(tree_size)
    .fetch_optional(executor)
    .await?;
    Ok(row)
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn open_db() -> crate::db::Db {
        crate::db::install_drivers();
        crate::db::open("sqlite::memory:", 1, false).await.unwrap()
    }

    #[tokio::test]
    async fn upsert_and_get_latest() {
        let db = open_db().await;

        assert!(get_latest(&db, "ca1").await.unwrap().is_none());

        upsert(&db, "ca1", 10, "aabbcc", b"sig1", 1000)
            .await
            .unwrap();
        let row = get_latest(&db, "ca1").await.unwrap().unwrap();
        assert_eq!(row.tree_size, 10);
        assert_eq!(row.root_hex, "aabbcc");
        assert_eq!(row.signature, b"sig1");

        upsert(&db, "ca1", 20, "ddeeff", b"sig2", 2000)
            .await
            .unwrap();
        let latest = get_latest(&db, "ca1").await.unwrap().unwrap();
        assert_eq!(latest.tree_size, 20);
    }

    #[tokio::test]
    async fn upsert_is_idempotent() {
        let db = open_db().await;
        upsert(&db, "ca1", 5, "aabb", b"sig", 100).await.unwrap();
        upsert(&db, "ca1", 5, "ccdd", b"sig2", 200).await.unwrap();
        let row = get_latest(&db, "ca1").await.unwrap().unwrap();
        assert_eq!(row.root_hex, "aabb", "second upsert should not overwrite");
    }

    #[tokio::test]
    async fn different_cas_are_independent() {
        let db = open_db().await;
        upsert(&db, "ca1", 10, "aa", b"s1", 100).await.unwrap();
        upsert(&db, "ca2", 10, "bb", b"s2", 200).await.unwrap();

        let r1 = get_latest(&db, "ca1").await.unwrap().unwrap();
        let r2 = get_latest(&db, "ca2").await.unwrap().unwrap();
        assert_eq!(r1.root_hex, "aa");
        assert_eq!(r2.root_hex, "bb");
    }

    #[tokio::test]
    async fn prune_oldest_keeps_most_recent() {
        let db = open_db().await;
        for i in 1i64..=5 {
            upsert(&db, "ca1", i * 10, &format!("{i:064x}"), b"s", i * 100)
                .await
                .unwrap();
        }
        let deleted = prune_oldest(&db, "ca1", 3).await.unwrap();
        assert_eq!(deleted, 2, "should delete 2 of 5 rows");
        let latest = get_latest(&db, "ca1").await.unwrap().unwrap();
        assert_eq!(latest.tree_size, 50, "latest should survive pruning");
    }

    #[tokio::test]
    async fn prune_oldest_keep_count_zero_is_noop() {
        let db = open_db().await;
        upsert(&db, "ca1", 1, "aa", b"s", 1).await.unwrap();
        let deleted = prune_oldest(&db, "ca1", 0).await.unwrap();
        assert_eq!(deleted, 0);
        assert!(get_latest(&db, "ca1").await.unwrap().is_some());
    }
}
