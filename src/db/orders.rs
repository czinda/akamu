use tokio_rusqlite::Connection;

use crate::db::schema::OrderRow;
use crate::error::AcmeError;

fn row_from(row: &rusqlite::Row<'_>) -> rusqlite::Result<OrderRow> {
    Ok(OrderRow {
        id: row.get(0)?,
        account_id: row.get(1)?,
        status: row.get(2)?,
        expires: row.get(3)?,
        identifiers: row.get(4)?,
        not_before: row.get(5)?,
        not_after: row.get(6)?,
        error: row.get(7)?,
        certificate_id: row.get(8)?,
        replaces: row.get(9)?,
        created: row.get(10)?,
        updated: row.get(11)?,
        star_start_date: row.get(12)?,
        star_end_date: row.get(13)?,
        star_lifetime_secs: row.get(14)?,
        star_lifetime_adjust_secs: row.get::<_, Option<i64>>(15)?.unwrap_or(0),
        star_allow_cert_get: row.get::<_, i64>(16).map(|v| v != 0).unwrap_or(false),
        star_canceled_at: row.get(17)?,
        star_csr_der: row.get(18)?,
    })
}

pub async fn insert(db: &Connection, row: OrderRow) -> Result<(), AcmeError> {
    db.call(move |conn| {
        conn.prepare_cached(
            "INSERT INTO orders (id, account_id, status, expires, identifiers,
             not_before, not_after, error, certificate_id, replaces, created, updated,
             star_start_date, star_end_date, star_lifetime_secs, star_lifetime_adjust_secs,
             star_allow_cert_get, star_canceled_at, star_csr_der)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12,
                     ?13, ?14, ?15, ?16, ?17, ?18, ?19)",
        )?
        .execute(rusqlite::params![
            row.id,
            row.account_id,
            row.status,
            row.expires,
            row.identifiers,
            row.not_before,
            row.not_after,
            row.error,
            row.certificate_id,
            row.replaces,
            row.created,
            row.updated,
            row.star_start_date,
            row.star_end_date,
            row.star_lifetime_secs,
            row.star_lifetime_adjust_secs,
            row.star_allow_cert_get as i64,
            row.star_canceled_at,
            row.star_csr_der,
        ])?;
        Ok(())
    })
    .await
    .map_err(AcmeError::from)
}

/// Cancel a STAR order by setting star_canceled_at to the current timestamp.
pub async fn cancel_star(db: &Connection, id: &str, now: i64) -> Result<(), AcmeError> {
    let id = id.to_string();
    db.call(move |conn| {
        conn.prepare_cached(
            "UPDATE orders SET star_canceled_at = ?1, updated = ?2 WHERE id = ?3",
        )?
        .execute(rusqlite::params![now, now, id])?;
        Ok(())
    })
    .await
    .map_err(AcmeError::from)
}

/// List all active STAR orders (star_end_date set, not canceled, status = 'valid').
pub async fn list_active_star(db: &Connection) -> Result<Vec<OrderRow>, AcmeError> {
    db.call(move |conn| {
        let mut stmt = conn.prepare_cached(
            "SELECT id, account_id, status, expires, identifiers,
             not_before, not_after, error, certificate_id, replaces, created, updated,
             star_start_date, star_end_date, star_lifetime_secs, star_lifetime_adjust_secs,
             star_allow_cert_get, star_canceled_at, star_csr_der
             FROM orders
             WHERE star_end_date IS NOT NULL AND star_canceled_at IS NULL AND status = 'valid'",
        )?;
        let rows = stmt
            .query_map([], row_from)?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    })
    .await
    .map_err(AcmeError::from)
}

/// Store the CSR DER on an order (set during finalize for STAR orders).
pub async fn set_star_csr(db: &Connection, id: &str, csr_der: Vec<u8>) -> Result<(), AcmeError> {
    let id = id.to_string();
    db.call(move |conn| {
        conn.prepare_cached("UPDATE orders SET star_csr_der = ?1 WHERE id = ?2")?
            .execute(rusqlite::params![csr_der, id])?;
        Ok(())
    })
    .await
    .map_err(AcmeError::from)
}

pub async fn get_by_id(db: &Connection, id: &str) -> Result<Option<OrderRow>, AcmeError> {
    let id = id.to_string();
    db.call(move |conn| {
        let mut stmt = conn.prepare_cached(
            "SELECT id, account_id, status, expires, identifiers,
             not_before, not_after, error, certificate_id, replaces, created, updated,
             star_start_date, star_end_date, star_lifetime_secs, star_lifetime_adjust_secs,
             star_allow_cert_get, star_canceled_at, star_csr_der
             FROM orders WHERE id = ?1",
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

pub async fn update_status(
    db: &Connection,
    id: &str,
    status: &str,
    error: Option<String>,
    now: i64,
) -> Result<(), AcmeError> {
    let id = id.to_string();
    let status = status.to_string();
    db.call(move |conn| {
        conn.prepare_cached(
            "UPDATE orders SET status = ?1, error = ?2, updated = ?3 WHERE id = ?4",
        )?
        .execute(rusqlite::params![status, error, now, id])?;
        Ok(())
    })
    .await
    .map_err(AcmeError::from)
}

pub async fn set_certificate(
    db: &Connection,
    id: &str,
    certificate_id: &str,
    now: i64,
) -> Result<(), AcmeError> {
    let id = id.to_string();
    let certificate_id = certificate_id.to_string();
    db.call(move |conn| {
        conn.prepare_cached(
            "UPDATE orders SET status = 'valid', certificate_id = ?1, updated = ?2 WHERE id = ?3",
        )?
        .execute(rusqlite::params![certificate_id, now, id])?;
        Ok(())
    })
    .await
    .map_err(AcmeError::from)
}

/// Fetch an order and its authorization IDs in a single database call.
///
/// Returns `None` if no order with `order_id` exists.
pub async fn get_with_authz_ids(
    db: &Connection,
    order_id: &str,
) -> Result<Option<(OrderRow, Vec<String>)>, AcmeError> {
    let id = order_id.to_string();
    db.call(move |conn| {
        let order = {
            let mut stmt = conn.prepare_cached(
                "SELECT id, account_id, status, expires, identifiers,
                 not_before, not_after, error, certificate_id, replaces, created, updated,
                 star_start_date, star_end_date, star_lifetime_secs, star_lifetime_adjust_secs,
                 star_allow_cert_get, star_canceled_at, star_csr_der
                 FROM orders WHERE id = ?1",
            )?;
            let mut rows = stmt.query(rusqlite::params![id])?;
            if let Some(row) = rows.next()? {
                row_from(row)?
            } else {
                return Ok(None);
            }
        };
        let authz_ids = {
            let mut stmt =
                conn.prepare_cached("SELECT id FROM authorizations WHERE order_id = ?1")?;
            let ids = stmt
                .query_map(rusqlite::params![id], |row| row.get::<_, String>(0))?
                .collect::<Result<Vec<_>, _>>()?;
            drop(stmt);
            ids
        };
        Ok(Some((order, authz_ids)))
    })
    .await
    .map_err(AcmeError::from)
}

/// List all authorization IDs belonging to an order.
pub async fn list_authz_ids(db: &Connection, order_id: &str) -> Result<Vec<String>, AcmeError> {
    let order_id = order_id.to_string();
    db.call(move |conn| {
        let mut stmt = conn.prepare_cached("SELECT id FROM authorizations WHERE order_id = ?1")?;
        let ids = stmt
            .query_map(rusqlite::params![order_id], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(ids)
    })
    .await
    .map_err(AcmeError::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use crate::db::schema::AccountRow;

    async fn open_db() -> Arc<Connection> {
        Arc::new(crate::db::open(":memory:").await.unwrap())
    }

    async fn insert_account(db: &Connection, account_id: &str) {
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
    }

    fn sample_order(id: &str, account_id: &str) -> OrderRow {
        OrderRow {
            id: id.to_string(),
            account_id: account_id.to_string(),
            status: "pending".to_string(),
            expires: None,
            identifiers: "[{\"type\":\"dns\",\"value\":\"example.com\"}]".to_string(),
            not_before: None,
            not_after: None,
            error: None,
            certificate_id: None,
            replaces: None,
            created: 1_700_000_000,
            updated: 1_700_000_000,
            star_start_date: None,
            star_end_date: None,
            star_lifetime_secs: None,
            star_lifetime_adjust_secs: 0,
            star_allow_cert_get: false,
            star_canceled_at: None,
            star_csr_der: None,
        }
    }

    #[tokio::test]
    async fn insert_and_get_by_id() {
        let db = open_db().await;
        insert_account(&db, "acct-1").await;
        insert(&db, sample_order("order-1", "acct-1"))
            .await
            .unwrap();

        let row = get_by_id(&db, "order-1").await.unwrap().unwrap();
        assert_eq!(row.id, "order-1");
        assert_eq!(row.status, "pending");
    }

    #[tokio::test]
    async fn get_by_id_missing_returns_none() {
        let db = open_db().await;
        let result = get_by_id(&db, "nonexistent").await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn update_status_changes_status() {
        let db = open_db().await;
        insert_account(&db, "acct-2").await;
        insert(&db, sample_order("order-2", "acct-2"))
            .await
            .unwrap();

        update_status(&db, "order-2", "ready", None, 1_700_000_001)
            .await
            .unwrap();

        let row = get_by_id(&db, "order-2").await.unwrap().unwrap();
        assert_eq!(row.status, "ready");
        assert!(row.error.is_none());
    }

    #[tokio::test]
    async fn update_status_with_error() {
        let db = open_db().await;
        insert_account(&db, "acct-3").await;
        insert(&db, sample_order("order-3", "acct-3"))
            .await
            .unwrap();

        update_status(
            &db,
            "order-3",
            "invalid",
            Some("{\"type\":\"error\"}".to_string()),
            1_700_000_001,
        )
        .await
        .unwrap();

        let row = get_by_id(&db, "order-3").await.unwrap().unwrap();
        assert_eq!(row.status, "invalid");
        assert!(row.error.is_some());
    }

    #[tokio::test]
    async fn set_certificate_marks_valid() {
        let db = open_db().await;
        insert_account(&db, "acct-4").await;
        insert(&db, sample_order("order-4", "acct-4"))
            .await
            .unwrap();

        set_certificate(&db, "order-4", "cert-xyz", 1_700_000_001)
            .await
            .unwrap();

        let row = get_by_id(&db, "order-4").await.unwrap().unwrap();
        assert_eq!(row.status, "valid");
        assert_eq!(row.certificate_id, Some("cert-xyz".to_string()));
    }

    #[tokio::test]
    async fn list_authz_ids_empty_for_no_authzs() {
        let db = open_db().await;
        insert_account(&db, "acct-5").await;
        insert(&db, sample_order("order-5", "acct-5"))
            .await
            .unwrap();

        let ids = list_authz_ids(&db, "order-5").await.unwrap();
        assert!(ids.is_empty());
    }

    #[tokio::test]
    async fn list_authz_ids_returns_authz_ids() {
        use crate::db::schema::AuthorizationRow;

        let db = open_db().await;
        insert_account(&db, "acct-6").await;
        insert(&db, sample_order("order-6", "acct-6"))
            .await
            .unwrap();

        crate::db::authz::insert(
            &db,
            AuthorizationRow {
                id: "authz-a".to_string(),
                order_id: "order-6".to_string(),
                account_id: "acct-6".to_string(),
                status: "pending".to_string(),
                identifier: "{\"type\":\"dns\",\"value\":\"example.com\"}".to_string(),
                expires: None,
                wildcard: false,
                subdomain_auth_allowed: false,
                created: 1_700_000_000,
                updated: 1_700_000_000,
            },
        )
        .await
        .unwrap();

        let ids = list_authz_ids(&db, "order-6").await.unwrap();
        assert_eq!(ids, vec!["authz-a"]);
    }

    #[tokio::test]
    async fn db_error_paths_no_table() {
        let raw = Arc::new(tokio_rusqlite::Connection::open_in_memory().await.unwrap());
        assert!(insert(&raw, sample_order("err-order", "err-acct"))
            .await
            .is_err());
        assert!(get_by_id(&raw, "any").await.is_err());
        assert!(update_status(&raw, "any", "invalid", None, 0)
            .await
            .is_err());
        assert!(set_certificate(&raw, "any", "cert-id", 0).await.is_err());
        assert!(list_authz_ids(&raw, "any").await.is_err());
    }

    #[tokio::test]
    async fn replaces_round_trip_some() {
        let db = open_db().await;
        insert_account(&db, "acct-rpl").await;
        let mut order = sample_order("order-rpl", "acct-rpl");
        order.replaces = Some("akiABC.serialXYZ".to_string());
        insert(&db, order).await.unwrap();

        let row = get_by_id(&db, "order-rpl").await.unwrap().unwrap();
        assert_eq!(row.replaces.as_deref(), Some("akiABC.serialXYZ"));
    }

    #[tokio::test]
    async fn replaces_round_trip_none() {
        let db = open_db().await;
        insert_account(&db, "acct-nrpl").await;
        insert(&db, sample_order("order-nrpl", "acct-nrpl"))
            .await
            .unwrap();

        let row = get_by_id(&db, "order-nrpl").await.unwrap().unwrap();
        assert!(row.replaces.is_none());
    }
}
