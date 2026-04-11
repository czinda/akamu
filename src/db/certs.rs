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
        replaced_by: row.get(15)?,
    })
}

pub async fn insert(db: &Connection, row: CertificateRow) -> Result<(), AcmeError> {
    db.call(move |conn| {
        conn.prepare_cached(
            "INSERT INTO certificates
             (id, order_id, account_id, serial_number, status, der, pem,
              not_before, not_after, revoked_at, revocation_reason, mtc_log_index, created,
              suggested_window_start, suggested_window_end, replaced_by)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, NULL)",
        )?
        .execute(rusqlite::params![
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
        ])?;
        Ok(())
    })
    .await
    .map_err(AcmeError::from)
}

pub async fn get_by_id(db: &Connection, id: &str) -> Result<Option<CertificateRow>, AcmeError> {
    let id = id.to_string();
    db.call(move |conn| {
        let mut stmt = conn.prepare_cached(
            "SELECT id, order_id, account_id, serial_number, status, der, pem,
             not_before, not_after, revoked_at, revocation_reason, mtc_log_index, created,
             suggested_window_start, suggested_window_end, replaced_by
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
        let mut stmt = conn.prepare_cached(
            "SELECT id, order_id, account_id, serial_number, status, der, pem,
             not_before, not_after, revoked_at, revocation_reason, mtc_log_index, created,
             suggested_window_start, suggested_window_end, replaced_by
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

/// Look up a certificate by RFC 9773 ARI cert_id.
///
/// The cert_id format (RFC 9773 §4.1) is:
///   `base64url(AKI keyIdentifier) "." base64url(serial number bytes)`
///
/// Only the serial component is used for the DB lookup; the AKI component is
/// ignored (our CA issues one cert per serial and the AKI is always the same).
pub async fn get_by_cert_id(
    db: &Connection,
    cert_id: &str,
) -> Result<Option<CertificateRow>, AcmeError> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;

    let dot = cert_id
        .find('.')
        .ok_or_else(|| AcmeError::BadRequest("cert_id missing '.' separator".into()))?;
    let serial_b64 = &cert_id[dot + 1..];
    let serial_bytes = URL_SAFE_NO_PAD
        .decode(serial_b64)
        .map_err(|_| AcmeError::BadRequest("cert_id serial is not valid base64url".into()))?;
    // Convert bytes to lowercase hex — matches the format stored in serial_number.
    let serial_hex: String = serial_bytes.iter().map(|b| format!("{b:02x}")).collect();
    get_by_serial(db, &serial_hex).await
}

/// Mark a certificate as replaced by a new order.
///
/// Sets `replaced_by` to `replacing_order_id` only when it is currently NULL so
/// concurrent calls are idempotent (the first writer wins).  Returns whether a
/// row was actually updated.
pub async fn mark_replaced(
    db: &Connection,
    cert_uuid: &str,
    replacing_order_id: &str,
) -> Result<bool, AcmeError> {
    let cert_uuid = cert_uuid.to_string();
    let replacing_order_id = replacing_order_id.to_string();
    db.call(move |conn| {
        let n = conn
            .prepare_cached(
                "UPDATE certificates SET replaced_by = ?1 \
                 WHERE id = ?2 AND replaced_by IS NULL",
            )?
            .execute(rusqlite::params![replacing_order_id, cert_uuid])?;
        Ok(n > 0)
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
        let n = conn
            .prepare_cached(
                "UPDATE certificates SET status = 'revoked', revoked_at = ?1, revocation_reason = ?2
             WHERE id = ?3 AND status = 'valid'",
            )?
            .execute(rusqlite::params![now, reason, id])?;
        Ok(n > 0)
    })
    .await
    .map_err(AcmeError::from)
}

/// Update the MTC log index after appending the certificate to the transparency log.
pub async fn set_mtc_log_index(db: &Connection, id: &str, index: i64) -> Result<(), AcmeError> {
    let id = id.to_string();
    db.call(move |conn| {
        conn.prepare_cached("UPDATE certificates SET mtc_log_index = ?1 WHERE id = ?2")?
            .execute(rusqlite::params![index, id])?;
        Ok(())
    })
    .await
    .map_err(AcmeError::from)
}

/// Set renewal window (RFC 9773 ARI).
///
/// Returns `Err` if `start >= end` — a window must be a non-empty interval.
pub async fn set_renewal_window(
    db: &Connection,
    id: &str,
    start: i64,
    end: i64,
) -> Result<(), AcmeError> {
    if start >= end {
        return Err(AcmeError::BadRequest(format!(
            "renewal window start ({start}) must be before end ({end})"
        )));
    }
    let id = id.to_string();
    db.call(move |conn| {
        conn.prepare_cached(
            "UPDATE certificates SET suggested_window_start = ?1, suggested_window_end = ?2
             WHERE id = ?3",
        )?
        .execute(rusqlite::params![start, end, id])?;
        Ok(())
    })
    .await
    .map_err(AcmeError::from)
}

/// List all revoked certificates (for CRL generation).
pub async fn list_revoked(db: &Connection) -> Result<Vec<CertificateRow>, AcmeError> {
    db.call(move |conn| {
        let mut stmt = conn.prepare_cached(
            "SELECT id, order_id, account_id, serial_number, status, der, pem,
             not_before, not_after, revoked_at, revocation_reason, mtc_log_index, created,
             suggested_window_start, suggested_window_end, replaced_by
             FROM certificates WHERE status = 'revoked'",
        )?;
        let rows = stmt
            .query_map([], row_from)?
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
        let mut stmt = conn.prepare_cached(
            "SELECT id, order_id, account_id, serial_number, status, der, pem,
             not_before, not_after, revoked_at, revocation_reason, mtc_log_index, created,
             suggested_window_start, suggested_window_end, replaced_by
             FROM certificates
             WHERE account_id = ?1 AND status = 'valid' AND not_after > ?2",
        )?;
        let rows = stmt
            .query_map(rusqlite::params![account_id, now], row_from)?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
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

    /// Insert a minimal account + order so that foreign-key constraints pass.
    async fn insert_parent_rows(db: &Connection, account_id: &str, order_id: &str) {
        let acct = AccountRow {
            id: account_id.to_string(),
            status: "valid".to_string(),
            contact: None,
            public_key: vec![0u8; 4],
            jwk_thumbprint: format!("thumb-{account_id}"),
            created: 1_700_000_000,
            updated: 1_700_000_000,
        };
        crate::db::accounts::insert(db, acct).await.unwrap();

        let order = OrderRow {
            id: order_id.to_string(),
            account_id: account_id.to_string(),
            status: "valid".to_string(),
            expires: None,
            identifiers: "[]".to_string(),
            not_before: None,
            not_after: None,
            error: None,
            certificate_id: None,
            replaces: None,
            created: 1_700_000_000,
            updated: 1_700_000_000,
        };
        crate::db::orders::insert(db, order).await.unwrap();
    }

    fn sample_cert(id: &str, account_id: &str, status: &str, not_after: i64) -> CertificateRow {
        CertificateRow {
            id: id.to_string(),
            order_id: format!("order-{id}"),
            account_id: account_id.to_string(),
            serial_number: format!("serial-{id}"),
            status: status.to_string(),
            der: vec![0x30, 0x00],
            pem: "-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n".to_string(),
            not_before: 1_700_000_000,
            not_after,
            revoked_at: None,
            revocation_reason: None,
            mtc_log_index: None,
            created: 1_700_000_000,
            suggested_window_start: None,
            suggested_window_end: None,
            replaced_by: None,
        }
    }

    /// Helper: insert parent rows + cert together.
    async fn insert_cert(
        db: &Connection,
        id: &str,
        account_id: &str,
        status: &str,
        not_after: i64,
    ) {
        insert_parent_rows(db, account_id, &format!("order-{id}")).await;
        insert(db, sample_cert(id, account_id, status, not_after))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn insert_and_get_by_id() {
        let db = open_db().await;
        insert_cert(&db, "cert-1", "acct-1", "valid", 1_800_000_000).await;

        let result = get_by_id(&db, "cert-1").await.unwrap();
        assert!(result.is_some());
        let row = result.unwrap();
        assert_eq!(row.id, "cert-1");
        assert_eq!(row.account_id, "acct-1");
        assert_eq!(row.status, "valid");
    }

    #[tokio::test]
    async fn get_by_id_missing_returns_none() {
        let db = open_db().await;
        let result = get_by_id(&db, "nonexistent").await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn get_by_serial_finds_cert() {
        let db = open_db().await;
        insert_cert(&db, "cert-2", "acct-2", "valid", 1_800_000_000).await;

        let result = get_by_serial(&db, "serial-cert-2").await.unwrap();
        assert!(result.is_some());
        assert_eq!(result.unwrap().id, "cert-2");
    }

    #[tokio::test]
    async fn get_by_serial_missing_returns_none() {
        let db = open_db().await;
        let result = get_by_serial(&db, "nonexistent-serial").await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn revoke_valid_cert_returns_true() {
        let db = open_db().await;
        insert_cert(&db, "cert-3", "acct-3", "valid", 1_800_000_000).await;

        let changed = revoke(&db, "cert-3", Some(1), 1_700_500_000).await.unwrap();
        assert!(changed, "revoke should return true when cert was valid");

        let row = get_by_id(&db, "cert-3").await.unwrap().unwrap();
        assert_eq!(row.status, "revoked");
        assert_eq!(row.revoked_at, Some(1_700_500_000));
        assert_eq!(row.revocation_reason, Some(1));
    }

    #[tokio::test]
    async fn revoke_already_revoked_returns_false() {
        let db = open_db().await;
        insert_cert(&db, "cert-4", "acct-4", "valid", 1_800_000_000).await;

        // First revocation succeeds.
        revoke(&db, "cert-4", None, 1_700_500_000).await.unwrap();
        // Second revocation returns false (already revoked, status != 'valid').
        let changed = revoke(&db, "cert-4", None, 1_700_600_000).await.unwrap();
        assert!(
            !changed,
            "revoke should return false when cert is already revoked"
        );
    }

    #[tokio::test]
    async fn revoke_nonexistent_returns_false() {
        let db = open_db().await;
        let changed = revoke(&db, "nonexistent-cert", None, 1_700_500_000)
            .await
            .unwrap();
        assert!(!changed, "revoke should return false for nonexistent cert");
    }

    #[tokio::test]
    async fn revoke_without_reason() {
        let db = open_db().await;
        insert_cert(&db, "cert-5", "acct-5", "valid", 1_800_000_000).await;

        let changed = revoke(&db, "cert-5", None, 1_700_500_000).await.unwrap();
        assert!(changed);

        let row = get_by_id(&db, "cert-5").await.unwrap().unwrap();
        assert_eq!(row.revocation_reason, None);
    }

    #[tokio::test]
    async fn set_mtc_log_index_updates_cert() {
        let db = open_db().await;
        insert_cert(&db, "cert-6", "acct-6", "valid", 1_800_000_000).await;

        assert!(get_by_id(&db, "cert-6")
            .await
            .unwrap()
            .unwrap()
            .mtc_log_index
            .is_none());

        set_mtc_log_index(&db, "cert-6", 42).await.unwrap();

        let row = get_by_id(&db, "cert-6").await.unwrap().unwrap();
        assert_eq!(row.mtc_log_index, Some(42));
    }

    #[tokio::test]
    async fn set_mtc_log_index_nonexistent_is_ok() {
        // Should not error even if no row is updated.
        let db = open_db().await;
        set_mtc_log_index(&db, "nonexistent", 99).await.unwrap();
    }

    #[tokio::test]
    async fn set_renewal_window_updates_cert() {
        let db = open_db().await;
        insert_cert(&db, "cert-7", "acct-7", "valid", 1_800_000_000).await;

        set_renewal_window(&db, "cert-7", 1_750_000_000, 1_760_000_000)
            .await
            .unwrap();

        let row = get_by_id(&db, "cert-7").await.unwrap().unwrap();
        assert_eq!(row.suggested_window_start, Some(1_750_000_000));
        assert_eq!(row.suggested_window_end, Some(1_760_000_000));
    }

    #[tokio::test]
    async fn set_renewal_window_nonexistent_is_ok() {
        let db = open_db().await;
        set_renewal_window(&db, "nonexistent", 100, 200)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn list_revoked_returns_only_revoked() {
        let db = open_db().await;
        insert_cert(&db, "cert-8", "acct-8a", "valid", 1_800_000_000).await;
        insert_cert(&db, "cert-9", "acct-8b", "valid", 1_800_000_000).await;

        revoke(&db, "cert-9", Some(4), 1_700_500_000).await.unwrap();

        let revoked = list_revoked(&db).await.unwrap();
        assert_eq!(revoked.len(), 1);
        assert_eq!(revoked[0].id, "cert-9");
        assert_eq!(revoked[0].status, "revoked");
    }

    #[tokio::test]
    async fn list_revoked_empty_when_none_revoked() {
        let db = open_db().await;
        insert_cert(&db, "cert-10", "acct-10", "valid", 1_800_000_000).await;

        let revoked = list_revoked(&db).await.unwrap();
        assert!(revoked.is_empty());
    }

    #[tokio::test]
    async fn list_valid_for_account_filters_correctly() {
        let db = open_db().await;
        let now = 1_700_000_000i64;

        // Valid, not expired, correct account → should appear.
        insert_cert(&db, "cert-a", "acct-xa", "valid", now + 10_000).await;
        // Valid but expired → should NOT appear.
        insert_cert(&db, "cert-b", "acct-xb", "valid", now - 1).await;
        // Valid, not expired, different account → should NOT appear.
        insert_cert(&db, "cert-c", "acct-y", "valid", now + 10_000).await;

        // Move cert-b to same account as cert-a by using same account_id in insert:
        // Actually we can't reuse account_id easily (FK requires unique account per insert_parent).
        // Instead, let's insert cert-b directly with acct-xa.
        insert_parent_rows(&db, "acct-xa-extra", &format!("order-cert-b2")).await;
        insert(
            &db,
            CertificateRow {
                id: "cert-b2".to_string(),
                order_id: "order-cert-b2".to_string(),
                account_id: "acct-xa".to_string(),
                serial_number: "serial-cert-b2".to_string(),
                status: "valid".to_string(),
                der: vec![0x30, 0x00],
                pem: "-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n".to_string(),
                not_before: 1_700_000_000,
                not_after: now - 1, // expired
                revoked_at: None,
                revocation_reason: None,
                mtc_log_index: None,
                created: 1_700_000_000,
                suggested_window_start: None,
                suggested_window_end: None,
                replaced_by: None,
            },
        )
        .await
        .unwrap();

        let results = list_valid_for_account(&db, "acct-xa", now).await.unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].id, "cert-a");
    }

    #[tokio::test]
    async fn list_valid_for_account_excludes_revoked() {
        let db = open_db().await;
        let now = 1_700_000_000i64;

        insert_cert(&db, "cert-rev", "acct-z", "valid", now + 10_000).await;
        revoke(&db, "cert-rev", None, now).await.unwrap();

        let results = list_valid_for_account(&db, "acct-z", now).await.unwrap();
        assert!(
            results.is_empty(),
            "revoked cert should not appear in valid list"
        );
    }

    #[tokio::test]
    async fn db_error_paths_no_table() {
        let raw = Arc::new(tokio_rusqlite::Connection::open_in_memory().await.unwrap());
        let now = 1_700_000_000i64;
        let row = CertificateRow {
            id: "err-cert".into(),
            order_id: "err-order".into(),
            account_id: "err-acct".into(),
            serial_number: "ff".into(),
            status: "valid".into(),
            der: vec![],
            pem: String::new(),
            not_before: now,
            not_after: now + 86400,
            revoked_at: None,
            revocation_reason: None,
            mtc_log_index: None,
            created: now,
            suggested_window_start: None,
            suggested_window_end: None,
            replaced_by: None,
        };
        assert!(insert(&raw, row).await.is_err());
        assert!(get_by_id(&raw, "any").await.is_err());
        assert!(get_by_serial(&raw, "any").await.is_err());
        assert!(revoke(&raw, "any", None, now).await.is_err());
        assert!(set_mtc_log_index(&raw, "any", 0).await.is_err());
        assert!(set_renewal_window(&raw, "any", now, now + 86400)
            .await
            .is_err());
        assert!(list_revoked(&raw).await.is_err());
        assert!(list_valid_for_account(&raw, "any", now).await.is_err());
    }

    /// Build a base64url-encoded cert_id from AKI and serial hex.
    ///
    /// The serial hex must have even length; each pair of chars is one byte.
    fn make_cert_id(aki_bytes: &[u8], serial_hex: &str) -> String {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;
        let serial_bytes: Vec<u8> = (0..serial_hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&serial_hex[i..i + 2], 16).unwrap())
            .collect();
        format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(aki_bytes),
            URL_SAFE_NO_PAD.encode(serial_bytes)
        )
    }

    #[tokio::test]
    async fn get_by_cert_id_valid_hit() {
        let db = open_db().await;
        // Use a simple hex serial matching the serial stored in the DB.
        let serial_hex = "0a0b0c0d0e0f";
        // sample_cert sets order_id = "order-cert-gcid"; insert_parent_rows must match.
        insert_parent_rows(&db, "acct-gcid", "order-cert-gcid").await;
        let mut cert = sample_cert("cert-gcid", "acct-gcid", "valid", 1_800_000_000);
        cert.serial_number = serial_hex.to_string();
        insert(&db, cert).await.unwrap();

        let cert_id = make_cert_id(b"aki-bytes", serial_hex);
        let result = get_by_cert_id(&db, &cert_id).await.unwrap();
        assert!(result.is_some());
        assert_eq!(result.unwrap().serial_number, serial_hex);
    }

    #[tokio::test]
    async fn get_by_cert_id_no_dot_returns_bad_request() {
        let db = open_db().await;
        let result = get_by_cert_id(&db, "nodothere").await;
        assert!(matches!(
            result,
            Err(crate::error::AcmeError::BadRequest(_))
        ));
    }

    #[tokio::test]
    async fn get_by_cert_id_bad_base64_returns_bad_request() {
        let db = open_db().await;
        let result = get_by_cert_id(&db, "aki.!!!notbase64!!!").await;
        assert!(matches!(
            result,
            Err(crate::error::AcmeError::BadRequest(_))
        ));
    }

    #[tokio::test]
    async fn get_by_cert_id_unknown_serial_returns_none() {
        let db = open_db().await;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;
        let cert_id = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(b"aki"),
            URL_SAFE_NO_PAD.encode(b"\xde\xad")
        );
        let result = get_by_cert_id(&db, &cert_id).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn mark_replaced_sets_field() {
        let db = open_db().await;
        insert_cert(&db, "cert-mr1", "acct-mr1", "valid", 1_800_000_000).await;

        let changed = mark_replaced(&db, "cert-mr1", "order-new-1").await.unwrap();
        assert!(changed);

        let row = get_by_id(&db, "cert-mr1").await.unwrap().unwrap();
        assert_eq!(row.replaced_by.as_deref(), Some("order-new-1"));
    }

    #[tokio::test]
    async fn mark_replaced_idempotent() {
        let db = open_db().await;
        insert_cert(&db, "cert-mr2", "acct-mr2", "valid", 1_800_000_000).await;

        mark_replaced(&db, "cert-mr2", "order-new-2").await.unwrap();
        // Second call with a different order_id must not overwrite the first.
        let changed = mark_replaced(&db, "cert-mr2", "order-other").await.unwrap();
        assert!(!changed);

        let row = get_by_id(&db, "cert-mr2").await.unwrap().unwrap();
        assert_eq!(row.replaced_by.as_deref(), Some("order-new-2"));
    }
}
