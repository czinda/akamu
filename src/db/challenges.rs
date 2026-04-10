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
