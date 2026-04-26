use crate::db::schema::CheckpointRow;
use crate::error::AcmeError;

/// Delete the oldest checkpoints, keeping only the most recent `keep_count`.
///
/// Call `cosignatures::prune_orphaned` after this to remove cosignatures whose
/// checkpoint row has been deleted.  Returns the number of deleted rows.
pub async fn prune_oldest(
    executor: impl sqlx::Executor<'_, Database = sqlx::Any>,
    keep_count: u32,
) -> Result<u64, AcmeError> {
    if keep_count == 0 {
        return Ok(0);
    }
    let result = sqlx::query(
        "DELETE FROM mtc_checkpoints
         WHERE id NOT IN (
             SELECT id FROM (
                 SELECT id FROM mtc_checkpoints
                 ORDER BY tree_size DESC
                 LIMIT ?
             ) _keep
         )",
    )
    .bind(keep_count as i64)
    .execute(executor)
    .await?;
    Ok(result.rows_affected())
}

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
         SELECT ?, ?, ?, ?
         WHERE NOT EXISTS (SELECT 1 FROM mtc_checkpoints WHERE tree_size = ?)",
    )
    .bind(tree_size)
    .bind(root_hex)
    .bind(signature)
    .bind(created)
    .bind(tree_size)
    .execute(executor)
    .await?;
    Ok(())
}

/// Return the checkpoint with the given `tree_size`, or `None` if not found.
///
/// Prefer this over `get_latest` when you know the exact tree size (e.g. after
/// an upsert), to avoid a race with concurrent checkpoint inserts.
pub async fn get_by_tree_size(
    executor: impl sqlx::Executor<'_, Database = sqlx::Any>,
    tree_size: i64,
) -> Result<Option<CheckpointRow>, AcmeError> {
    let row = sqlx::query_as::<_, CheckpointRow>(
        "SELECT id, tree_size, root_hex, signature, created
         FROM mtc_checkpoints WHERE tree_size = ?",
    )
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
        crate::db::open("sqlite::memory:", 1, "./migrations/sqlite")
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn upsert_and_get_latest() {
        let db = open_db().await;

        assert!(get_latest(&db).await.unwrap().is_none());

        upsert(&db, 10, "aabbcc", b"sig1", 1000).await.unwrap();
        let row = get_latest(&db).await.unwrap().unwrap();
        assert_eq!(row.tree_size, 10);
        assert_eq!(row.root_hex, "aabbcc");
        assert_eq!(row.signature, b"sig1");

        upsert(&db, 20, "ddeeff", b"sig2", 2000).await.unwrap();
        let latest = get_latest(&db).await.unwrap().unwrap();
        assert_eq!(latest.tree_size, 20);
    }

    #[tokio::test]
    async fn upsert_is_idempotent() {
        let db = open_db().await;
        upsert(&db, 5, "aabb", b"sig", 100).await.unwrap();
        upsert(&db, 5, "ccdd", b"sig2", 200).await.unwrap(); // same tree_size — ignored
        let row = get_latest(&db).await.unwrap().unwrap();
        assert_eq!(row.root_hex, "aabb", "second upsert should not overwrite");
    }

    #[tokio::test]
    async fn prune_oldest_keeps_most_recent() {
        let db = open_db().await;
        for i in 1i64..=5 {
            upsert(&db, i * 10, &format!("{i:064x}"), b"s", i * 100)
                .await
                .unwrap();
        }
        let deleted = prune_oldest(&db, 3).await.unwrap();
        assert_eq!(deleted, 2, "should delete 2 of 5 rows");
        let latest = get_latest(&db).await.unwrap().unwrap();
        assert_eq!(latest.tree_size, 50, "latest should survive pruning");
    }

    #[tokio::test]
    async fn prune_oldest_keep_count_zero_is_noop() {
        let db = open_db().await;
        upsert(&db, 1, "aa", b"s", 1).await.unwrap();
        let deleted = prune_oldest(&db, 0).await.unwrap();
        assert_eq!(deleted, 0);
        assert!(get_latest(&db).await.unwrap().is_some());
    }
}
