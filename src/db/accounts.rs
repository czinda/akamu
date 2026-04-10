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
