use tokio_rusqlite::Connection;

use crate::db::schema::AccountRow;
use crate::error::AcmeError;

fn row_from(row: &rusqlite::Row<'_>) -> rusqlite::Result<AccountRow> {
    Ok(AccountRow {
        id: row.get(0)?,
        status: row.get(1)?,
        contact: row.get(2)?,
        public_key: row.get(3)?,
        jwk_thumbprint: row.get(4)?,
        created: row.get(5)?,
        updated: row.get(6)?,
    })
}

pub async fn insert(db: &Connection, row: AccountRow) -> Result<(), AcmeError> {
    db.call(move |conn| {
        conn.execute(
            "INSERT INTO accounts (id, status, contact, public_key, jwk_thumbprint, created, updated)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            rusqlite::params![
                row.id,
                row.status,
                row.contact,
                row.public_key,
                row.jwk_thumbprint,
                row.created,
                row.updated,
            ],
        )?;
        Ok(())
    })
    .await
    .map_err(AcmeError::from)
}

pub async fn get_by_id(db: &Connection, id: &str) -> Result<Option<AccountRow>, AcmeError> {
    let id = id.to_string();
    db.call(move |conn| {
        let mut stmt = conn.prepare(
            "SELECT id, status, contact, public_key, jwk_thumbprint, created, updated
             FROM accounts WHERE id = ?1",
        )?;
        let mut rows = stmt.query(rusqlite::params![id])?;
        if let Some(row) = rows.next()? {
            Ok(Some(row_from(row)?))
        } else {
            Ok(None)
        }
    })
    .await
    .map_err(AcmeError::from)
}

pub async fn get_by_thumbprint(
    db: &Connection,
    thumbprint: &str,
) -> Result<Option<AccountRow>, AcmeError> {
    let thumbprint = thumbprint.to_string();
    db.call(move |conn| {
        let mut stmt = conn.prepare(
            "SELECT id, status, contact, public_key, jwk_thumbprint, created, updated
             FROM accounts WHERE jwk_thumbprint = ?1",
        )?;
        let mut rows = stmt.query(rusqlite::params![thumbprint])?;
        if let Some(row) = rows.next()? {
            Ok(Some(row_from(row)?))
        } else {
            Ok(None)
        }
    })
    .await
    .map_err(AcmeError::from)
}

pub async fn update_contact(
    db: &Connection,
    id: &str,
    contact: Option<String>,
    now: i64,
) -> Result<bool, AcmeError> {
    let id = id.to_string();
    db.call(move |conn| {
        let n = conn.execute(
            "UPDATE accounts SET contact = ?1, updated = ?2 WHERE id = ?3 AND status = 'valid'",
            rusqlite::params![contact, now, id],
        )?;
        Ok(n > 0)
    })
    .await
    .map_err(AcmeError::from)
}

pub async fn update_status(
    db: &Connection,
    id: &str,
    status: &str,
    now: i64,
) -> Result<bool, AcmeError> {
    let id = id.to_string();
    let status = status.to_string();
    db.call(move |conn| {
        let n = conn.execute(
            "UPDATE accounts SET status = ?1, updated = ?2 WHERE id = ?3",
            rusqlite::params![status, now, id],
        )?;
        Ok(n > 0)
    })
    .await
    .map_err(AcmeError::from)
}

/// Update the account's JWK thumbprint and public key (for key rollover).
pub async fn update_key(
    db: &Connection,
    id: &str,
    public_key: Vec<u8>,
    jwk_thumbprint: String,
    now: i64,
) -> Result<bool, AcmeError> {
    let id = id.to_string();
    db.call(move |conn| {
        let n = conn.execute(
            "UPDATE accounts SET public_key = ?1, jwk_thumbprint = ?2, updated = ?3
             WHERE id = ?4 AND status = 'valid'",
            rusqlite::params![public_key, jwk_thumbprint, now, id],
        )?;
        Ok(n > 0)
    })
    .await
    .map_err(AcmeError::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    async fn open_db() -> Arc<Connection> {
        Arc::new(crate::db::open(":memory:").await.unwrap())
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
    /// connection that has no schema (no tables).  Every DB operation inside the
    /// closure will fail with "no such table", which exercises the `)?;` early-
    /// return paths that are normally never triggered in happy-path tests.
    #[tokio::test]
    async fn db_error_paths_no_table() {
        // Raw connection — no migrations run, so no tables exist.
        let raw = Arc::new(tokio_rusqlite::Connection::open_in_memory().await.unwrap());

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
