use crate::db::schema::AccountRow;
use crate::error::AcmeError;

pub async fn insert(
    executor: impl sqlx::Executor<'_, Database = sqlx::Any>,
    row: AccountRow,
) -> Result<(), AcmeError> {
    sqlx::query(
        "INSERT INTO accounts (id, status, contact, public_key, jwk_thumbprint, created, updated)
         VALUES (?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&row.id)
    .bind(&row.status)
    .bind(&row.contact)
    .bind(&row.public_key)
    .bind(&row.jwk_thumbprint)
    .bind(row.created)
    .bind(row.updated)
    .execute(executor)
    .await?;
    Ok(())
}

pub async fn get_by_id(
    executor: impl sqlx::Executor<'_, Database = sqlx::Any>,
    id: &str,
) -> Result<Option<AccountRow>, AcmeError> {
    let row = sqlx::query_as::<_, AccountRow>(
        "SELECT id, status, contact, public_key, jwk_thumbprint, created, updated
         FROM accounts WHERE id = ?",
    )
    .bind(id)
    .fetch_optional(executor)
    .await?;
    Ok(row)
}

pub async fn get_by_thumbprint(
    executor: impl sqlx::Executor<'_, Database = sqlx::Any>,
    thumbprint: &str,
) -> Result<Option<AccountRow>, AcmeError> {
    let row = sqlx::query_as::<_, AccountRow>(
        "SELECT id, status, contact, public_key, jwk_thumbprint, created, updated
         FROM accounts WHERE jwk_thumbprint = ?",
    )
    .bind(thumbprint)
    .fetch_optional(executor)
    .await?;
    Ok(row)
}

pub async fn update_contact(
    executor: impl sqlx::Executor<'_, Database = sqlx::Any>,
    id: &str,
    contact: Option<String>,
    now: i64,
) -> Result<bool, AcmeError> {
    let n = sqlx::query(
        "UPDATE accounts SET contact = ?, updated = ? WHERE id = ? AND status = 'valid'",
    )
    .bind(contact)
    .bind(now)
    .bind(id)
    .execute(executor)
    .await?
    .rows_affected();
    Ok(n > 0)
}

pub async fn update_status(
    executor: impl sqlx::Executor<'_, Database = sqlx::Any>,
    id: &str,
    status: &str,
    now: i64,
) -> Result<bool, AcmeError> {
    let n = sqlx::query("UPDATE accounts SET status = ?, updated = ? WHERE id = ?")
        .bind(status)
        .bind(now)
        .bind(id)
        .execute(executor)
        .await?
        .rows_affected();
    Ok(n > 0)
}

/// Update the account's JWK thumbprint and public key (for key rollover).
pub async fn update_key(
    executor: impl sqlx::Executor<'_, Database = sqlx::Any>,
    id: &str,
    public_key: Vec<u8>,
    jwk_thumbprint: String,
    now: i64,
) -> Result<bool, AcmeError> {
    let n = sqlx::query(
        "UPDATE accounts SET public_key = ?, jwk_thumbprint = ?, updated = ?
         WHERE id = ? AND status = 'valid'",
    )
    .bind(&public_key)
    .bind(&jwk_thumbprint)
    .bind(now)
    .bind(id)
    .execute(executor)
    .await?
    .rows_affected();
    Ok(n > 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::Db;

    async fn open_db() -> Db {
        crate::db::install_drivers();
        crate::db::open("sqlite::memory:", 1, "./migrations/sqlite")
            .await
            .unwrap()
    }

    fn sample_account(id: &str) -> AccountRow {
        AccountRow {
            id: id.to_string(),
            status: "valid".to_string(),
            contact: None,
            public_key: vec![0u8; 4],
            jwk_thumbprint: format!("thumb-{id}"),
            created: 1_700_000_000,
            updated: 1_700_000_000,
        }
    }

    #[tokio::test]
    async fn insert_and_get_by_id() {
        let db = open_db().await;
        insert(&db, sample_account("acct-1")).await.unwrap();
        let row = get_by_id(&db, "acct-1").await.unwrap().unwrap();
        assert_eq!(row.id, "acct-1");
        assert_eq!(row.status, "valid");
    }

    #[tokio::test]
    async fn get_by_id_missing_returns_none() {
        let db = open_db().await;
        let result = get_by_id(&db, "nonexistent").await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn get_by_thumbprint_finds_account() {
        let db = open_db().await;
        insert(&db, sample_account("acct-2")).await.unwrap();
        let row = get_by_thumbprint(&db, "thumb-acct-2")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(row.id, "acct-2");
    }

    #[tokio::test]
    async fn get_by_thumbprint_missing_returns_none() {
        let db = open_db().await;
        let result = get_by_thumbprint(&db, "nonexistent-thumb").await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn update_contact_valid_account() {
        let db = open_db().await;
        insert(&db, sample_account("acct-3")).await.unwrap();

        let changed = update_contact(
            &db,
            "acct-3",
            Some("[\"mailto:a@b.com\"]".into()),
            1_700_000_001,
        )
        .await
        .unwrap();
        assert!(
            changed,
            "update_contact should return true for valid account"
        );

        let row = get_by_id(&db, "acct-3").await.unwrap().unwrap();
        assert_eq!(row.contact, Some("[\"mailto:a@b.com\"]".to_string()));
    }

    #[tokio::test]
    async fn update_contact_nonexistent_returns_false() {
        let db = open_db().await;
        let changed = update_contact(&db, "nonexistent", None, 1_700_000_001)
            .await
            .unwrap();
        assert!(!changed);
    }

    #[tokio::test]
    async fn update_contact_deactivated_returns_false() {
        let db = open_db().await;
        insert(&db, sample_account("acct-4")).await.unwrap();
        update_status(&db, "acct-4", "deactivated", 1_700_000_001)
            .await
            .unwrap();

        let changed = update_contact(&db, "acct-4", None, 1_700_000_002)
            .await
            .unwrap();
        assert!(!changed, "update_contact should fail for non-valid account");
    }

    #[tokio::test]
    async fn update_status_changes_status() {
        let db = open_db().await;
        insert(&db, sample_account("acct-5")).await.unwrap();

        let changed = update_status(&db, "acct-5", "deactivated", 1_700_000_001)
            .await
            .unwrap();
        assert!(changed);

        let row = get_by_id(&db, "acct-5").await.unwrap().unwrap();
        assert_eq!(row.status, "deactivated");
    }

    #[tokio::test]
    async fn update_status_nonexistent_returns_false() {
        let db = open_db().await;
        let changed = update_status(&db, "nonexistent", "revoked", 1_700_000_001)
            .await
            .unwrap();
        assert!(!changed);
    }

    #[tokio::test]
    async fn update_key_valid_account() {
        let db = open_db().await;
        insert(&db, sample_account("acct-6")).await.unwrap();

        let changed = update_key(
            &db,
            "acct-6",
            vec![0xDE, 0xAD, 0xBE, 0xEF],
            "new-thumb".into(),
            1_700_000_001,
        )
        .await
        .unwrap();
        assert!(changed);

        let row = get_by_id(&db, "acct-6").await.unwrap().unwrap();
        assert_eq!(row.jwk_thumbprint, "new-thumb");
        assert_eq!(row.public_key, vec![0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[tokio::test]
    async fn update_key_nonexistent_returns_false() {
        let db = open_db().await;
        let changed = update_key(&db, "nonexistent", vec![], "thumb".into(), 0)
            .await
            .unwrap();
        assert!(!changed);
    }

    #[tokio::test]
    async fn update_key_deactivated_returns_false() {
        let db = open_db().await;
        insert(&db, sample_account("acct-7")).await.unwrap();
        update_status(&db, "acct-7", "deactivated", 1_700_000_001)
            .await
            .unwrap();

        let changed = update_key(&db, "acct-7", vec![], "thumb".into(), 0)
            .await
            .unwrap();
        assert!(!changed, "update_key should fail for non-valid account");
    }

    /// Cover the error propagation path in each function by calling them on a
    /// pool that has no schema (no tables). Every DB operation will fail with
    /// "no such table", which exercises the error-return paths.
    #[tokio::test]
    async fn db_error_paths_no_table() {
        crate::db::install_drivers();
        // Raw pool — no migrations run, so no tables exist.
        let raw: Db = sqlx::any::AnyPoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();

        let row = sample_account("err-acct");
        assert!(
            insert(&raw, row).await.is_err(),
            "insert should fail on no-table DB"
        );

        assert!(get_by_id(&raw, "any").await.is_err());
        assert!(get_by_thumbprint(&raw, "any").await.is_err());
        assert!(update_contact(&raw, "any", None, 0).await.is_err());
        assert!(update_status(&raw, "any", "deactivated", 0).await.is_err());
        assert!(update_key(&raw, "any", vec![], "thumb".into(), 0)
            .await
            .is_err());
    }
}
