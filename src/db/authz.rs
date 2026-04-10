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
            .query_map(rusqlite::params![order_id], |row| row_from(row))?
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
