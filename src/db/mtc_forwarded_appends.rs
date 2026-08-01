//! Idempotency cache for MTC leaf-appends forwarded to this node's writer
//! election (see `gossip::mtc_forward`).
//!
//! `append_cert_to_log` has no natural idempotency — each call assigns the
//! next sequential leaf index regardless of whether it's a retry, so a
//! naively-retried forward would permanently duplicate a leaf. Callers must
//! check this cache before appending and record the result afterward.

use crate::db::schema::MtcForwardedAppendRow;
use crate::error::AcmeError;

/// Return the cached result of a previous forward for `(ca_id,
/// serial_number)`, if any.
pub async fn get(
    executor: impl sqlx::Executor<'_, Database = sqlx::Any>,
    ca_id: &str,
    serial_number: &str,
) -> Result<Option<MtcForwardedAppendRow>, AcmeError> {
    let row = super::query_as::<MtcForwardedAppendRow>(
        "SELECT leaf_index, tree_size, proof_cbor FROM mtc_forwarded_appends \
         WHERE ca_id = ? AND serial_number = ?",
    )
    .bind(ca_id)
    .bind(serial_number)
    .fetch_optional(executor)
    .await?;
    Ok(row)
}

/// Record the result of appending `serial_number`'s leaf for `ca_id`.
///
/// Uses a portable `WHERE NOT EXISTS` sub-query — the same technique as
/// `db::tkauth::insert_jti` — so two racing retries of the same forward
/// request are both safe: whichever lands first wins, the other is a no-op.
pub async fn insert_if_absent(
    executor: impl sqlx::Executor<'_, Database = sqlx::Any>,
    ca_id: &str,
    serial_number: &str,
    leaf_index: i64,
    tree_size: i64,
    proof_cbor: &[u8],
    created: i64,
) -> Result<(), AcmeError> {
    super::query(
        "INSERT INTO mtc_forwarded_appends \
         (ca_id, serial_number, leaf_index, tree_size, proof_cbor, created) \
         SELECT ?, ?, ?, ?, ?, ? \
         WHERE NOT EXISTS ( \
             SELECT 1 FROM mtc_forwarded_appends WHERE ca_id = ? AND serial_number = ? \
         )",
    )
    .bind(ca_id)
    .bind(serial_number)
    .bind(leaf_index)
    .bind(tree_size)
    .bind(proof_cbor)
    .bind(created)
    .bind(ca_id)
    .bind(serial_number)
    .execute(executor)
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn open_db() -> crate::db::Db {
        crate::db::install_drivers();
        crate::db::open("sqlite::memory:", 1, false).await.unwrap()
    }

    #[tokio::test]
    async fn get_returns_none_when_absent() {
        let db = open_db().await;
        assert!(get(&db, "ca1", "AA").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn insert_then_get_round_trips() {
        let db = open_db().await;
        insert_if_absent(&db, "ca1", "AA", 5, 6, b"\x80", 1000)
            .await
            .unwrap();
        let row = get(&db, "ca1", "AA").await.unwrap().unwrap();
        assert_eq!(row.leaf_index, 5);
        assert_eq!(row.tree_size, 6);
        assert_eq!(row.proof_cbor, b"\x80");
    }

    #[tokio::test]
    async fn insert_if_absent_is_idempotent() {
        let db = open_db().await;
        insert_if_absent(&db, "ca1", "AA", 5, 6, b"\x80", 1000)
            .await
            .unwrap();
        // A retried forward for the same cert must not overwrite the
        // original result with a second (would-be-duplicate) append.
        insert_if_absent(&db, "ca1", "AA", 99, 100, b"\x81", 2000)
            .await
            .unwrap();
        let row = get(&db, "ca1", "AA").await.unwrap().unwrap();
        assert_eq!(row.leaf_index, 5, "second insert must not overwrite");
    }

    #[tokio::test]
    async fn different_cas_are_independent() {
        let db = open_db().await;
        insert_if_absent(&db, "ca1", "AA", 1, 2, b"\x80", 100)
            .await
            .unwrap();
        insert_if_absent(&db, "ca2", "AA", 9, 10, b"\x81", 200)
            .await
            .unwrap();

        let r1 = get(&db, "ca1", "AA").await.unwrap().unwrap();
        let r2 = get(&db, "ca2", "AA").await.unwrap().unwrap();
        assert_eq!(r1.leaf_index, 1);
        assert_eq!(r2.leaf_index, 9);
    }
}
