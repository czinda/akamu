use tokio_rusqlite::Connection;

use crate::db::schema::AuthorizationRow;
use crate::error::AcmeError;

fn row_from(row: &rusqlite::Row<'_>) -> rusqlite::Result<AuthorizationRow> {
    Ok(AuthorizationRow {
        id: row.get(0)?,
        order_id: row.get(1)?,
        account_id: row.get(2)?,
        status: row.get(3)?,
        identifier: row.get(4)?,
        expires: row.get(5)?,
        wildcard: row.get::<_, i64>(6)? != 0,
        created: row.get(7)?,
        updated: row.get(8)?,
    })
}

pub async fn insert(db: &Connection, row: AuthorizationRow) -> Result<(), AcmeError> {
    db.call(move |conn| {
        conn.execute(
            "INSERT INTO authorizations
             (id, order_id, account_id, status, identifier, expires, wildcard, created, updated)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            rusqlite::params![
                row.id,
                row.order_id,
                row.account_id,
                row.status,
                row.identifier,
                row.expires,
                row.wildcard as i64,
                row.created,
                row.updated,
            ],
        )?;
        Ok(())
    })
    .await
    .map_err(AcmeError::from)
}

pub async fn get_by_id(db: &Connection, id: &str) -> Result<Option<AuthorizationRow>, AcmeError> {
    let id = id.to_string();
    db.call(move |conn| {
        let mut stmt = conn.prepare(
            "SELECT id, order_id, account_id, status, identifier, expires, wildcard, created, updated
             FROM authorizations WHERE id = ?1",
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

pub async fn list_by_order(
    db: &Connection,
    order_id: &str,
) -> Result<Vec<AuthorizationRow>, AcmeError> {
    let order_id = order_id.to_string();
    db.call(move |conn| {
        let mut stmt = conn.prepare(
            "SELECT id, order_id, account_id, status, identifier, expires, wildcard, created, updated
             FROM authorizations WHERE order_id = ?1",
        )?;
        let rows = stmt
            .query_map(rusqlite::params![order_id], row_from)?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    })
    .await
    .map_err(AcmeError::from)
}

pub async fn update_status(
    db: &Connection,
    id: &str,
    status: &str,
    now: i64,
) -> Result<(), AcmeError> {
    let id = id.to_string();
    let status = status.to_string();
    db.call(move |conn| {
        conn.execute(
            "UPDATE authorizations SET status = ?1, updated = ?2 WHERE id = ?3",
            rusqlite::params![status, now, id],
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

    use crate::db::schema::{AccountRow, OrderRow};

    async fn open_db() -> Arc<Connection> {
        Arc::new(crate::db::open(":memory:").await.unwrap())
    }

    async fn insert_parents(db: &Connection, account_id: &str, order_id: &str) {
        crate::db::accounts::insert(
            db,
            AccountRow {
                id: account_id.to_string(),
                status: "valid".to_string(),
                contact: None,
                public_key: vec![0u8; 4],
                jwk_thumbprint: format!("thumb-{account_id}"),
                created: 1_700_000_000,
                updated: 1_700_000_000,
            },
        )
        .await
        .unwrap();

        crate::db::orders::insert(
            db,
            OrderRow {
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
            },
        )
        .await
        .unwrap();
    }

    fn sample_authz(id: &str, order_id: &str, account_id: &str) -> AuthorizationRow {
        AuthorizationRow {
            id: id.to_string(),
            order_id: order_id.to_string(),
            account_id: account_id.to_string(),
            status: "pending".to_string(),
            identifier: "{\"type\":\"dns\",\"value\":\"example.com\"}".to_string(),
            expires: None,
            wildcard: false,
            created: 1_700_000_000,
            updated: 1_700_000_000,
        }
    }

    #[tokio::test]
    async fn insert_and_get_by_id() {
        let db = open_db().await;
        insert_parents(&db, "acct-1", "order-1").await;
        insert(&db, sample_authz("authz-1", "order-1", "acct-1"))
            .await
            .unwrap();

        let row = get_by_id(&db, "authz-1").await.unwrap().unwrap();
        assert_eq!(row.id, "authz-1");
        assert_eq!(row.status, "pending");
        assert!(!row.wildcard);
    }

    #[tokio::test]
    async fn get_by_id_missing_returns_none() {
        let db = open_db().await;
        let result = get_by_id(&db, "nonexistent").await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn list_by_order_returns_authzs() {
        let db = open_db().await;
        insert_parents(&db, "acct-2", "order-2").await;
        insert(&db, sample_authz("authz-2a", "order-2", "acct-2"))
            .await
            .unwrap();
        insert(
            &db,
            AuthorizationRow {
                id: "authz-2b".to_string(),
                order_id: "order-2".to_string(),
                account_id: "acct-2".to_string(),
                status: "valid".to_string(),
                identifier: "{\"type\":\"dns\",\"value\":\"other.com\"}".to_string(),
                expires: None,
                wildcard: true,
                created: 1_700_000_000,
                updated: 1_700_000_000,
            },
        )
        .await
        .unwrap();

        let authzs = list_by_order(&db, "order-2").await.unwrap();
        assert_eq!(authzs.len(), 2);
        let ids: Vec<_> = authzs.iter().map(|a| a.id.as_str()).collect();
        assert!(ids.contains(&"authz-2a"));
        assert!(ids.contains(&"authz-2b"));
    }

    #[tokio::test]
    async fn list_by_order_empty_for_no_authzs() {
        let db = open_db().await;
        insert_parents(&db, "acct-3", "order-3").await;

        let authzs = list_by_order(&db, "order-3").await.unwrap();
        assert!(authzs.is_empty());
    }

    #[tokio::test]
    async fn update_status_changes_status() {
        let db = open_db().await;
        insert_parents(&db, "acct-4", "order-4").await;
        insert(&db, sample_authz("authz-4", "order-4", "acct-4"))
            .await
            .unwrap();

        update_status(&db, "authz-4", "valid", 1_700_000_001)
            .await
            .unwrap();

        let row = get_by_id(&db, "authz-4").await.unwrap().unwrap();
        assert_eq!(row.status, "valid");
        assert_eq!(row.updated, 1_700_000_001);
    }

    #[tokio::test]
    async fn db_error_paths_no_table() {
        let raw = Arc::new(tokio_rusqlite::Connection::open_in_memory().await.unwrap());
        let row = sample_authz("err-authz", "err-order", "err-acct");
        assert!(insert(&raw, row).await.is_err());
        assert!(get_by_id(&raw, "any").await.is_err());
        assert!(list_by_order(&raw, "any").await.is_err());
        assert!(update_status(&raw, "any", "valid", 0).await.is_err());
    }
}
