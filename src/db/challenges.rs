use tokio_rusqlite::Connection;

use crate::db::schema::ChallengeRow;
use crate::error::AcmeError;

fn row_from(row: &rusqlite::Row<'_>) -> rusqlite::Result<ChallengeRow> {
    Ok(ChallengeRow {
        id: row.get(0)?,
        authz_id: row.get(1)?,
        r#type: row.get(2)?,
        status: row.get(3)?,
        token: row.get(4)?,
        validated: row.get(5)?,
        error: row.get(6)?,
        created: row.get(7)?,
        updated: row.get(8)?,
    })
}

pub async fn insert(db: &Connection, row: ChallengeRow) -> Result<(), AcmeError> {
    db.call(move |conn| {
        conn.execute(
            "INSERT INTO challenges (id, authz_id, type, status, token, validated, error, created, updated)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            rusqlite::params![
                row.id,
                row.authz_id,
                row.r#type,
                row.status,
                row.token,
                row.validated,
                row.error,
                row.created,
                row.updated,
            ],
        )?;
        Ok(())
    })
    .await
    .map_err(AcmeError::from)
}

pub async fn get_by_id(db: &Connection, id: &str) -> Result<Option<ChallengeRow>, AcmeError> {
    let id = id.to_string();
    db.call(move |conn| {
        let mut stmt = conn.prepare(
            "SELECT id, authz_id, type, status, token, validated, error, created, updated
             FROM challenges WHERE id = ?1",
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

pub async fn list_by_authz(
    db: &Connection,
    authz_id: &str,
) -> Result<Vec<ChallengeRow>, AcmeError> {
    let authz_id = authz_id.to_string();
    db.call(move |conn| {
        let mut stmt = conn.prepare(
            "SELECT id, authz_id, type, status, token, validated, error, created, updated
             FROM challenges WHERE authz_id = ?1",
        )?;
        let rows = stmt
            .query_map(rusqlite::params![authz_id], |row| row_from(row))?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    })
    .await
    .map_err(AcmeError::from)
}

pub async fn set_processing(db: &Connection, id: &str, now: i64) -> Result<(), AcmeError> {
    let id = id.to_string();
    db.call(move |conn| {
        conn.execute(
            "UPDATE challenges SET status = 'processing', updated = ?1 WHERE id = ?2",
            rusqlite::params![now, id],
        )?;
        Ok(())
    })
    .await
    .map_err(AcmeError::from)
}

pub async fn set_valid(db: &Connection, id: &str, validated: i64) -> Result<(), AcmeError> {
    let id = id.to_string();
    db.call(move |conn| {
        conn.execute(
            "UPDATE challenges SET status = 'valid', validated = ?1, updated = ?1 WHERE id = ?2",
            rusqlite::params![validated, id],
        )?;
        Ok(())
    })
    .await
    .map_err(AcmeError::from)
}

pub async fn set_invalid(
    db: &Connection,
    id: &str,
    error: String,
    now: i64,
) -> Result<(), AcmeError> {
    let id = id.to_string();
    db.call(move |conn| {
        conn.execute(
            "UPDATE challenges SET status = 'invalid', error = ?1, updated = ?2 WHERE id = ?3",
            rusqlite::params![error, now, id],
        )?;
        Ok(())
    })
    .await
    .map_err(AcmeError::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use crate::db::schema::{AccountRow, AuthorizationRow, OrderRow};

    async fn open_db() -> Arc<Connection> {
        Arc::new(crate::db::open(":memory:").await.unwrap())
    }

    async fn insert_parents(db: &Connection, account_id: &str, order_id: &str, authz_id: &str) {
        crate::db::accounts::insert(db, AccountRow {
            id: account_id.to_string(),
            status: "valid".to_string(),
            contact: None,
            public_key: vec![0u8; 4],
            jwk_thumbprint: format!("thumb-{account_id}"),
            created: 1_700_000_000,
            updated: 1_700_000_000,
        }).await.unwrap();

        crate::db::orders::insert(db, OrderRow {
            id: order_id.to_string(),
            account_id: account_id.to_string(),
            status: "pending".to_string(),
            expires: None,
            identifiers: "[]".to_string(),
            not_before: None,
            not_after: None,
            error: None,
            certificate_id: None,
            created: 1_700_000_000,
            updated: 1_700_000_000,
        }).await.unwrap();

        crate::db::authz::insert(db, AuthorizationRow {
            id: authz_id.to_string(),
            order_id: order_id.to_string(),
            account_id: account_id.to_string(),
            status: "pending".to_string(),
            identifier: "{\"type\":\"dns\",\"value\":\"example.com\"}".to_string(),
            expires: None,
            wildcard: false,
            created: 1_700_000_000,
            updated: 1_700_000_000,
        }).await.unwrap();
    }

    fn sample_challenge(id: &str, authz_id: &str) -> ChallengeRow {
        ChallengeRow {
            id: id.to_string(),
            authz_id: authz_id.to_string(),
            r#type: "http-01".to_string(),
            status: "pending".to_string(),
            token: format!("token-{id}"),
            validated: None,
            error: None,
            created: 1_700_000_000,
            updated: 1_700_000_000,
        }
    }

    async fn insert_challenge(db: &Connection, id: &str, account_id: &str, order_id: &str, authz_id: &str) {
        insert_parents(db, account_id, order_id, authz_id).await;
        insert(db, sample_challenge(id, authz_id)).await.unwrap();
    }

    #[tokio::test]
    async fn insert_and_get_by_id() {
        let db = open_db().await;
        insert_challenge(&db, "chall-1", "acct-1", "order-1", "authz-1").await;

        let row = get_by_id(&db, "chall-1").await.unwrap().unwrap();
        assert_eq!(row.id, "chall-1");
        assert_eq!(row.status, "pending");
        assert_eq!(row.r#type, "http-01");
    }

    #[tokio::test]
    async fn get_by_id_missing_returns_none() {
        let db = open_db().await;
        let result = get_by_id(&db, "nonexistent").await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn list_by_authz_returns_challenges() {
        let db = open_db().await;
        insert_parents(&db, "acct-2", "order-2", "authz-2").await;
        insert(&db, sample_challenge("chall-2a", "authz-2")).await.unwrap();
        insert(&db, ChallengeRow {
            id: "chall-2b".to_string(),
            authz_id: "authz-2".to_string(),
            r#type: "dns-01".to_string(),
            status: "pending".to_string(),
            token: "token-2b".to_string(),
            validated: None,
            error: None,
            created: 1_700_000_000,
            updated: 1_700_000_000,
        }).await.unwrap();

        let challenges = list_by_authz(&db, "authz-2").await.unwrap();
        assert_eq!(challenges.len(), 2);
        let types: Vec<_> = challenges.iter().map(|c| c.r#type.as_str()).collect();
        assert!(types.contains(&"http-01"));
        assert!(types.contains(&"dns-01"));
    }

    #[tokio::test]
    async fn list_by_authz_empty_for_no_challenges() {
        let db = open_db().await;
        insert_parents(&db, "acct-3", "order-3", "authz-3").await;

        let challenges = list_by_authz(&db, "authz-3").await.unwrap();
        assert!(challenges.is_empty());
    }

    #[tokio::test]
    async fn set_processing_updates_status() {
        let db = open_db().await;
        insert_challenge(&db, "chall-4", "acct-4", "order-4", "authz-4").await;

        set_processing(&db, "chall-4", 1_700_000_001).await.unwrap();

        let row = get_by_id(&db, "chall-4").await.unwrap().unwrap();
        assert_eq!(row.status, "processing");
        assert_eq!(row.updated, 1_700_000_001);
    }

    #[tokio::test]
    async fn set_valid_updates_status_and_validated() {
        let db = open_db().await;
        insert_challenge(&db, "chall-5", "acct-5", "order-5", "authz-5").await;

        set_valid(&db, "chall-5", 1_700_000_002).await.unwrap();

        let row = get_by_id(&db, "chall-5").await.unwrap().unwrap();
        assert_eq!(row.status, "valid");
        assert_eq!(row.validated, Some(1_700_000_002));
    }

    #[tokio::test]
    async fn set_invalid_updates_status_and_error() {
        let db = open_db().await;
        insert_challenge(&db, "chall-6", "acct-6", "order-6", "authz-6").await;

        set_invalid(&db, "chall-6", "{\"type\":\"connection\"}".into(), 1_700_000_003).await.unwrap();

        let row = get_by_id(&db, "chall-6").await.unwrap().unwrap();
        assert_eq!(row.status, "invalid");
        assert_eq!(row.error, Some("{\"type\":\"connection\"}".to_string()));
    }

    #[tokio::test]
    async fn db_error_paths_no_table() {
        let raw = Arc::new(tokio_rusqlite::Connection::open_in_memory().await.unwrap());
        assert!(insert(&raw, sample_challenge("err-chall", "err-authz")).await.is_err());
        assert!(get_by_id(&raw, "any").await.is_err());
        assert!(list_by_authz(&raw, "any").await.is_err());
        assert!(set_processing(&raw, "any", 0).await.is_err());
        assert!(set_valid(&raw, "any", 0).await.is_err());
        assert!(set_invalid(&raw, "any", "{}".into(), 0).await.is_err());
    }
}
