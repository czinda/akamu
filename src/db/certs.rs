use sqlx::SqliteConnection;

use crate::db::schema::CertificateRow;
use crate::error::AcmeError;

pub async fn insert(conn: &mut SqliteConnection, row: CertificateRow) -> Result<(), AcmeError> {
    sqlx::query(
        "INSERT INTO certificates
         (id, order_id, account_id, serial_number, status, der, pem,
          not_before, not_after, revoked_at, revocation_reason, mtc_log_index, created,
          suggested_window_start, suggested_window_end, replaced_by)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, NULL)",
    )
    .bind(&row.id)
    .bind(&row.order_id)
    .bind(&row.account_id)
    .bind(&row.serial_number)
    .bind(&row.status)
    .bind(&row.der)
    .bind(&row.pem)
    .bind(row.not_before)
    .bind(row.not_after)
    .bind(row.revoked_at)
    .bind(row.revocation_reason)
    .bind(row.mtc_log_index)
    .bind(row.created)
    .bind(row.suggested_window_start)
    .bind(row.suggested_window_end)
    .execute(&mut *conn)
    .await
    .map_err(|e| AcmeError::Database(e.to_string()))?;
    Ok(())
}

pub async fn get_by_id(
    conn: &mut SqliteConnection,
    id: &str,
) -> Result<Option<CertificateRow>, AcmeError> {
    let row = sqlx::query_as::<_, CertificateRow>(
        "SELECT id, order_id, account_id, serial_number, status, der, pem,
         not_before, not_after, revoked_at, revocation_reason, mtc_log_index, created,
         suggested_window_start, suggested_window_end, replaced_by
         FROM certificates WHERE id = ?1",
    )
    .bind(id)
    .fetch_optional(&mut *conn)
    .await
    .map_err(|e| AcmeError::Database(e.to_string()))?;
    Ok(row)
}

pub async fn get_by_serial(
    conn: &mut SqliteConnection,
    serial: &str,
) -> Result<Option<CertificateRow>, AcmeError> {
    let row = sqlx::query_as::<_, CertificateRow>(
        "SELECT id, order_id, account_id, serial_number, status, der, pem,
         not_before, not_after, revoked_at, revocation_reason, mtc_log_index, created,
         suggested_window_start, suggested_window_end, replaced_by
         FROM certificates WHERE serial_number = ?1",
    )
    .bind(serial)
    .fetch_optional(&mut *conn)
    .await
    .map_err(|e| AcmeError::Database(e.to_string()))?;
    Ok(row)
}

/// Look up a certificate by RFC 9773 ARI cert_id.
pub async fn get_by_cert_id(
    conn: &mut SqliteConnection,
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
    let serial_hex: String = serial_bytes.iter().map(|b| format!("{b:02x}")).collect();
    get_by_serial(conn, &serial_hex).await
}

/// Mark a certificate as replaced by a new order.
pub async fn mark_replaced(
    conn: &mut SqliteConnection,
    cert_uuid: &str,
    replacing_order_id: &str,
) -> Result<bool, AcmeError> {
    let result = sqlx::query(
        "UPDATE certificates SET replaced_by = ?1 \
         WHERE id = ?2 AND replaced_by IS NULL",
    )
    .bind(replacing_order_id)
    .bind(cert_uuid)
    .execute(&mut *conn)
    .await
    .map_err(|e| AcmeError::Database(e.to_string()))?;
    Ok(result.rows_affected() > 0)
}

/// Set a certificate as revoked.
pub async fn revoke(
    conn: &mut SqliteConnection,
    id: &str,
    reason: Option<i64>,
    now: i64,
) -> Result<bool, AcmeError> {
    let result = sqlx::query(
        "UPDATE certificates SET status = 'revoked', revoked_at = ?1, revocation_reason = ?2
         WHERE id = ?3 AND status = 'valid'",
    )
    .bind(now)
    .bind(reason)
    .bind(id)
    .execute(&mut *conn)
    .await
    .map_err(|e| AcmeError::Database(e.to_string()))?;
    Ok(result.rows_affected() > 0)
}

/// Update the MTC log index after appending the certificate to the transparency log.
pub async fn set_mtc_log_index(
    conn: &mut SqliteConnection,
    id: &str,
    index: i64,
) -> Result<(), AcmeError> {
    sqlx::query("UPDATE certificates SET mtc_log_index = ?1 WHERE id = ?2")
        .bind(index)
        .bind(id)
        .execute(&mut *conn)
        .await
        .map_err(|e| AcmeError::Database(e.to_string()))?;
    Ok(())
}

/// Set renewal window (RFC 9773 ARI).
pub async fn set_renewal_window(
    conn: &mut SqliteConnection,
    id: &str,
    start: i64,
    end: i64,
) -> Result<(), AcmeError> {
    if start >= end {
        return Err(AcmeError::BadRequest(format!(
            "renewal window start ({start}) must be before end ({end})"
        )));
    }
    sqlx::query(
        "UPDATE certificates SET suggested_window_start = ?1, suggested_window_end = ?2
         WHERE id = ?3",
    )
    .bind(start)
    .bind(end)
    .bind(id)
    .execute(&mut *conn)
    .await
    .map_err(|e| AcmeError::Database(e.to_string()))?;
    Ok(())
}

/// List all revoked certificates (for CRL generation).
pub async fn list_revoked(conn: &mut SqliteConnection) -> Result<Vec<CertificateRow>, AcmeError> {
    let rows = sqlx::query_as::<_, CertificateRow>(
        "SELECT id, order_id, account_id, serial_number, status, der, pem,
         not_before, not_after, revoked_at, revocation_reason, mtc_log_index, created,
         suggested_window_start, suggested_window_end, replaced_by
         FROM certificates WHERE status = 'revoked'",
    )
    .fetch_all(&mut *conn)
    .await
    .map_err(|e| AcmeError::Database(e.to_string()))?;
    Ok(rows)
}

/// List valid (non-revoked, non-expired) certificates for an account.
pub async fn list_valid_for_account(
    conn: &mut SqliteConnection,
    account_id: &str,
    now: i64,
) -> Result<Vec<CertificateRow>, AcmeError> {
    let rows = sqlx::query_as::<_, CertificateRow>(
        "SELECT id, order_id, account_id, serial_number, status, der, pem,
         not_before, not_after, revoked_at, revocation_reason, mtc_log_index, created,
         suggested_window_start, suggested_window_end, replaced_by
         FROM certificates
         WHERE account_id = ?1 AND status = 'valid' AND not_after > ?2",
    )
    .bind(account_id)
    .bind(now)
    .fetch_all(&mut *conn)
    .await
    .map_err(|e| AcmeError::Database(e.to_string()))?;
    Ok(rows)
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::db::schema::{AccountRow, OrderRow};

    async fn open_db() -> crate::db::Db {
        crate::db::open(":memory:").await.unwrap()
    }

    macro_rules! conn {
        ($db:expr) => {
            &mut *$db.acquire().await.unwrap()
        };
    }

    /// Insert a minimal account + order so that foreign-key constraints pass.
    async fn insert_parent_rows(db: &crate::db::Db, account_id: &str, order_id: &str) {
        let acct = AccountRow {
            id: account_id.to_string(),
            status: "valid".to_string(),
            contact: None,
            public_key: vec![0u8; 4],
            jwk_thumbprint: format!("thumb-{account_id}"),
            created: 1_700_000_000,
            updated: 1_700_000_000,
        };
        crate::db::accounts::insert(conn!(db), acct).await.unwrap();

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
            star_start_date: None,
            star_end_date: None,
            star_lifetime_secs: None,
            star_lifetime_adjust_secs: 0,
            star_allow_cert_get: false,
            star_canceled_at: None,
            star_csr_der: None,
            profile: None,
        };
        crate::db::orders::insert(conn!(db), order).await.unwrap();
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
        db: &crate::db::Db,
        id: &str,
        account_id: &str,
        status: &str,
        not_after: i64,
    ) {
        insert_parent_rows(db, account_id, &format!("order-{id}")).await;
        insert(conn!(db), sample_cert(id, account_id, status, not_after))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn insert_and_get_by_id() {
        let db = open_db().await;
        insert_cert(&db, "cert-1", "acct-1", "valid", 1_800_000_000).await;

        let result = get_by_id(conn!(db), "cert-1").await.unwrap();
        assert!(result.is_some());
        let row = result.unwrap();
        assert_eq!(row.id, "cert-1");
        assert_eq!(row.account_id, "acct-1");
        assert_eq!(row.status, "valid");
    }

    #[tokio::test]
    async fn get_by_id_missing_returns_none() {
        let db = open_db().await;
        let result = get_by_id(conn!(db), "nonexistent").await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn get_by_serial_finds_cert() {
        let db = open_db().await;
        insert_cert(&db, "cert-2", "acct-2", "valid", 1_800_000_000).await;

        let result = get_by_serial(conn!(db), "serial-cert-2").await.unwrap();
        assert!(result.is_some());
        assert_eq!(result.unwrap().id, "cert-2");
    }

    #[tokio::test]
    async fn get_by_serial_missing_returns_none() {
        let db = open_db().await;
        let result = get_by_serial(conn!(db), "nonexistent-serial").await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn revoke_valid_cert_returns_true() {
        let db = open_db().await;
        insert_cert(&db, "cert-3", "acct-3", "valid", 1_800_000_000).await;

        let changed = revoke(conn!(db), "cert-3", Some(1), 1_700_500_000).await.unwrap();
        assert!(changed, "revoke should return true when cert was valid");

        let row = get_by_id(conn!(db), "cert-3").await.unwrap().unwrap();
        assert_eq!(row.status, "revoked");
        assert_eq!(row.revoked_at, Some(1_700_500_000));
        assert_eq!(row.revocation_reason, Some(1));
    }

    #[tokio::test]
    async fn revoke_already_revoked_returns_false() {
        let db = open_db().await;
        insert_cert(&db, "cert-4", "acct-4", "valid", 1_800_000_000).await;

        revoke(conn!(db), "cert-4", None, 1_700_500_000).await.unwrap();
        let changed = revoke(conn!(db), "cert-4", None, 1_700_600_000).await.unwrap();
        assert!(
            !changed,
            "revoke should return false when cert is already revoked"
        );
    }

    #[tokio::test]
    async fn revoke_nonexistent_returns_false() {
        let db = open_db().await;
        let changed = revoke(conn!(db), "nonexistent-cert", None, 1_700_500_000)
            .await
            .unwrap();
        assert!(!changed, "revoke should return false for nonexistent cert");
    }

    #[tokio::test]
    async fn revoke_without_reason() {
        let db = open_db().await;
        insert_cert(&db, "cert-5", "acct-5", "valid", 1_800_000_000).await;

        let changed = revoke(conn!(db), "cert-5", None, 1_700_500_000).await.unwrap();
        assert!(changed);

        let row = get_by_id(conn!(db), "cert-5").await.unwrap().unwrap();
        assert_eq!(row.revocation_reason, None);
    }

    #[tokio::test]
    async fn set_mtc_log_index_updates_cert() {
        let db = open_db().await;
        insert_cert(&db, "cert-6", "acct-6", "valid", 1_800_000_000).await;

        assert!(get_by_id(conn!(db), "cert-6")
            .await
            .unwrap()
            .unwrap()
            .mtc_log_index
            .is_none());

        set_mtc_log_index(conn!(db), "cert-6", 42).await.unwrap();

        let row = get_by_id(conn!(db), "cert-6").await.unwrap().unwrap();
        assert_eq!(row.mtc_log_index, Some(42));
    }

    #[tokio::test]
    async fn set_mtc_log_index_nonexistent_is_ok() {
        let db = open_db().await;
        set_mtc_log_index(conn!(db), "nonexistent", 99).await.unwrap();
    }

    #[tokio::test]
    async fn set_renewal_window_updates_cert() {
        let db = open_db().await;
        insert_cert(&db, "cert-7", "acct-7", "valid", 1_800_000_000).await;

        set_renewal_window(conn!(db), "cert-7", 1_750_000_000, 1_760_000_000)
            .await
            .unwrap();

        let row = get_by_id(conn!(db), "cert-7").await.unwrap().unwrap();
        assert_eq!(row.suggested_window_start, Some(1_750_000_000));
        assert_eq!(row.suggested_window_end, Some(1_760_000_000));
    }

    #[tokio::test]
    async fn set_renewal_window_nonexistent_is_ok() {
        let db = open_db().await;
        set_renewal_window(conn!(db), "nonexistent", 100, 200)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn list_revoked_returns_only_revoked() {
        let db = open_db().await;
        insert_cert(&db, "cert-8", "acct-8a", "valid", 1_800_000_000).await;
        insert_cert(&db, "cert-9", "acct-8b", "valid", 1_800_000_000).await;

        revoke(conn!(db), "cert-9", Some(4), 1_700_500_000).await.unwrap();

        let revoked = list_revoked(conn!(db)).await.unwrap();
        assert_eq!(revoked.len(), 1);
        assert_eq!(revoked[0].id, "cert-9");
        assert_eq!(revoked[0].status, "revoked");
    }

    #[tokio::test]
    async fn list_revoked_empty_when_none_revoked() {
        let db = open_db().await;
        insert_cert(&db, "cert-10", "acct-10", "valid", 1_800_000_000).await;

        let revoked = list_revoked(conn!(db)).await.unwrap();
        assert!(revoked.is_empty());
    }

    #[tokio::test]
    async fn list_valid_for_account_filters_correctly() {
        let db = open_db().await;
        let now = 1_700_000_000i64;

        insert_cert(&db, "cert-a", "acct-xa", "valid", now + 10_000).await;
        insert_cert(&db, "cert-b", "acct-xb", "valid", now - 1).await;
        insert_cert(&db, "cert-c", "acct-y", "valid", now + 10_000).await;

        insert_parent_rows(&db, "acct-xa-extra", "order-cert-b2").await;
        insert(
            conn!(db),
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

        let results = list_valid_for_account(conn!(db), "acct-xa", now).await.unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].id, "cert-a");
    }

    #[tokio::test]
    async fn list_valid_for_account_excludes_revoked() {
        let db = open_db().await;
        let now = 1_700_000_000i64;

        insert_cert(&db, "cert-rev", "acct-z", "valid", now + 10_000).await;
        revoke(conn!(db), "cert-rev", None, now).await.unwrap();

        let results = list_valid_for_account(conn!(db), "acct-z", now).await.unwrap();
        assert!(
            results.is_empty(),
            "revoked cert should not appear in valid list"
        );
    }

    #[tokio::test]
    async fn db_error_paths_no_table() {
        use sqlx::Connection as _;
        let mut raw: sqlx::SqliteConnection =
            sqlx::SqliteConnection::connect("sqlite::memory:").await.unwrap();
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
        assert!(insert(&mut raw, row).await.is_err());
        assert!(get_by_id(&mut raw, "any").await.is_err());
        assert!(get_by_serial(&mut raw, "any").await.is_err());
        assert!(revoke(&mut raw, "any", None, now).await.is_err());
        assert!(set_mtc_log_index(&mut raw, "any", 0).await.is_err());
        assert!(set_renewal_window(&mut raw, "any", now, now + 86400)
            .await
            .is_err());
        assert!(list_revoked(&mut raw).await.is_err());
        assert!(list_valid_for_account(&mut raw, "any", now).await.is_err());
    }

    /// Build a base64url-encoded cert_id from AKI and serial hex.
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
        let serial_hex = "0a0b0c0d0e0f";
        insert_parent_rows(&db, "acct-gcid", "order-cert-gcid").await;
        let mut cert = sample_cert("cert-gcid", "acct-gcid", "valid", 1_800_000_000);
        cert.serial_number = serial_hex.to_string();
        insert(conn!(db), cert).await.unwrap();

        let cert_id = make_cert_id(b"aki-bytes", serial_hex);
        let result = get_by_cert_id(conn!(db), &cert_id).await.unwrap();
        assert!(result.is_some());
        assert_eq!(result.unwrap().serial_number, serial_hex);
    }

    #[tokio::test]
    async fn get_by_cert_id_no_dot_returns_bad_request() {
        let db = open_db().await;
        let result = get_by_cert_id(conn!(db), "nodothere").await;
        assert!(matches!(
            result,
            Err(crate::error::AcmeError::BadRequest(_))
        ));
    }

    #[tokio::test]
    async fn get_by_cert_id_bad_base64_returns_bad_request() {
        let db = open_db().await;
        let result = get_by_cert_id(conn!(db), "aki.!!!notbase64!!!").await;
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
        let result = get_by_cert_id(conn!(db), &cert_id).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn mark_replaced_sets_field() {
        let db = open_db().await;
        insert_cert(&db, "cert-mr1", "acct-mr1", "valid", 1_800_000_000).await;

        let changed = mark_replaced(conn!(db), "cert-mr1", "order-new-1").await.unwrap();
        assert!(changed);

        let row = get_by_id(conn!(db), "cert-mr1").await.unwrap().unwrap();
        assert_eq!(row.replaced_by.as_deref(), Some("order-new-1"));
    }

    #[tokio::test]
    async fn mark_replaced_idempotent() {
        let db = open_db().await;
        insert_cert(&db, "cert-mr2", "acct-mr2", "valid", 1_800_000_000).await;

        mark_replaced(conn!(db), "cert-mr2", "order-new-2").await.unwrap();
        let changed = mark_replaced(conn!(db), "cert-mr2", "order-other").await.unwrap();
        assert!(!changed);

        let row = get_by_id(conn!(db), "cert-mr2").await.unwrap().unwrap();
        assert_eq!(row.replaced_by.as_deref(), Some("order-new-2"));
    }
}
