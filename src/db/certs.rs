use tokio_rusqlite::Connection;

use crate::db::schema::CertificateRow;
use crate::error::AcmeError;

fn row_from(row: &rusqlite::Row<'_>) -> rusqlite::Result<CertificateRow> {
    Ok(CertificateRow {
        id: row.get(0)?,
        order_id: row.get(1)?,
        account_id: row.get(2)?,
        serial_number: row.get(3)?,
        status: row.get(4)?,
        der: row.get(5)?,
        pem: row.get(6)?,
        not_before: row.get(7)?,
        not_after: row.get(8)?,
        revoked_at: row.get(9)?,
        revocation_reason: row.get(10)?,
        mtc_log_index: row.get(11)?,
        created: row.get(12)?,
        suggested_window_start: row.get(13)?,
        suggested_window_end: row.get(14)?,
    })
}

pub async fn insert(db: &Connection, row: CertificateRow) -> Result<(), AcmeError> {
    db.call(move |conn| {
        conn.execute(
            "INSERT INTO certificates
             (id, order_id, account_id, serial_number, status, der, pem,
              not_before, not_after, revoked_at, revocation_reason, mtc_log_index, created,
              suggested_window_start, suggested_window_end)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
            rusqlite::params![
                row.id,
                row.order_id,
                row.account_id,
                row.serial_number,
                row.status,
                row.der,
                row.pem,
                row.not_before,
                row.not_after,
                row.revoked_at,
                row.revocation_reason,
                row.mtc_log_index,
                row.created,
                row.suggested_window_start,
                row.suggested_window_end,
            ],
        )?;
        Ok(())
    })
    .await
    .map_err(AcmeError::from)
}

pub async fn get_by_id(db: &Connection, id: &str) -> Result<Option<CertificateRow>, AcmeError> {
    let id = id.to_string();
    db.call(move |conn| {
        let mut stmt = conn.prepare(
            "SELECT id, order_id, account_id, serial_number, status, der, pem,
             not_before, not_after, revoked_at, revocation_reason, mtc_log_index, created,
             suggested_window_start, suggested_window_end
             FROM certificates WHERE id = ?1",
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

pub async fn get_by_serial(
    db: &Connection,
    serial: &str,
) -> Result<Option<CertificateRow>, AcmeError> {
    let serial = serial.to_string();
    db.call(move |conn| {
        let mut stmt = conn.prepare(
            "SELECT id, order_id, account_id, serial_number, status, der, pem,
             not_before, not_after, revoked_at, revocation_reason, mtc_log_index, created,
             suggested_window_start, suggested_window_end
             FROM certificates WHERE serial_number = ?1",
        )?;
        let mut rows = stmt.query(rusqlite::params![serial])?;
        if let Some(row) = rows.next()? {
            Ok(Some(row_from(row)?))
        } else {
            Ok(None)
        }
    })
    .await
    .map_err(AcmeError::from)
}

/// Set a certificate as revoked.
pub async fn revoke(
    db: &Connection,
    id: &str,
    reason: Option<i64>,
    now: i64,
) -> Result<bool, AcmeError> {
    let id = id.to_string();
    db.call(move |conn| {
        let n = conn.execute(
            "UPDATE certificates SET status = 'revoked', revoked_at = ?1, revocation_reason = ?2
             WHERE id = ?3 AND status = 'valid'",
            rusqlite::params![now, reason, id],
        )?;
        Ok(n > 0)
    })
    .await
    .map_err(AcmeError::from)
}

/// Update the MTC log index after appending the certificate to the transparency log.
pub async fn set_mtc_log_index(
    db: &Connection,
    id: &str,
    index: i64,
) -> Result<(), AcmeError> {
    let id = id.to_string();
    db.call(move |conn| {
        conn.execute(
            "UPDATE certificates SET mtc_log_index = ?1 WHERE id = ?2",
            rusqlite::params![index, id],
        )?;
        Ok(())
    })
    .await
    .map_err(AcmeError::from)
}

/// Set renewal window (RFC 9773 ARI).
pub async fn set_renewal_window(
    db: &Connection,
    id: &str,
    start: i64,
    end: i64,
) -> Result<(), AcmeError> {
    let id = id.to_string();
    db.call(move |conn| {
        conn.execute(
            "UPDATE certificates SET suggested_window_start = ?1, suggested_window_end = ?2
             WHERE id = ?3",
            rusqlite::params![start, end, id],
        )?;
        Ok(())
    })
    .await
    .map_err(AcmeError::from)
}

/// List all revoked certificates (for CRL generation).
pub async fn list_revoked(db: &Connection) -> Result<Vec<CertificateRow>, AcmeError> {
    db.call(move |conn| {
        let mut stmt = conn.prepare(
            "SELECT id, order_id, account_id, serial_number, status, der, pem,
             not_before, not_after, revoked_at, revocation_reason, mtc_log_index, created,
             suggested_window_start, suggested_window_end
             FROM certificates WHERE status = 'revoked'",
        )?;
        let rows = stmt
            .query_map([], |row| row_from(row))?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    })
    .await
    .map_err(AcmeError::from)
}

/// List valid (non-revoked, non-expired) certificates for an account.
pub async fn list_valid_for_account(
    db: &Connection,
    account_id: &str,
    now: i64,
) -> Result<Vec<CertificateRow>, AcmeError> {
    let account_id = account_id.to_string();
    db.call(move |conn| {
        let mut stmt = conn.prepare(
            "SELECT id, order_id, account_id, serial_number, status, der, pem,
             not_before, not_after, revoked_at, revocation_reason, mtc_log_index, created,
             suggested_window_start, suggested_window_end
             FROM certificates
             WHERE account_id = ?1 AND status = 'valid' AND not_after > ?2",
        )?;
        let rows = stmt
            .query_map(rusqlite::params![account_id, now], |row| row_from(row))?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    })
    .await
    .map_err(AcmeError::from)
}
