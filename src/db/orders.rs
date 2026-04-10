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
        created: row.get(9)?,
        updated: row.get(10)?,
    })
}

pub async fn insert(db: &Connection, row: OrderRow) -> Result<(), AcmeError> {
    db.call(move |conn| {
        conn.execute(
            "INSERT INTO orders (id, account_id, status, expires, identifiers,
             not_before, not_after, error, certificate_id, created, updated)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            rusqlite::params![
                row.id,
                row.account_id,
                row.status,
                row.expires,
                row.identifiers,
                row.not_before,
                row.not_after,
                row.error,
                row.certificate_id,
                row.created,
                row.updated,
            ],
        )?;
        Ok(())
    })
    .await
    .map_err(AcmeError::from)
}

pub async fn get_by_id(db: &Connection, id: &str) -> Result<Option<OrderRow>, AcmeError> {
    let id = id.to_string();
    db.call(move |conn| {
        let mut stmt = conn.prepare(
            "SELECT id, account_id, status, expires, identifiers,
             not_before, not_after, error, certificate_id, created, updated
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
        conn.execute(
            "UPDATE orders SET status = ?1, error = ?2, updated = ?3 WHERE id = ?4",
            rusqlite::params![status, error, now, id],
        )?;
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
        conn.execute(
            "UPDATE orders SET status = 'valid', certificate_id = ?1, updated = ?2 WHERE id = ?3",
            rusqlite::params![certificate_id, now, id],
        )?;
        Ok(())
    })
    .await
    .map_err(AcmeError::from)
}

/// List all authorization IDs belonging to an order.
pub async fn list_authz_ids(db: &Connection, order_id: &str) -> Result<Vec<String>, AcmeError> {
    let order_id = order_id.to_string();
    db.call(move |conn| {
        let mut stmt =
            conn.prepare("SELECT id FROM authorizations WHERE order_id = ?1")?;
        let ids = stmt
            .query_map(rusqlite::params![order_id], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(ids)
    })
    .await
    .map_err(AcmeError::from)
}
