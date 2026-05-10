use crate::db::schema::{CertForStandalone, CertificateRow, CrlEntry};
use crate::error::AcmeError;

pub async fn insert(
    executor: impl sqlx::Executor<'_, Database = sqlx::Any>,
    row: CertificateRow,
) -> Result<(), AcmeError> {
    super::query(
        "INSERT INTO certificates
         (id, order_id, account_id, serial_number, status, der, pem,
          not_before, not_after, revoked_at, revocation_reason, mtc_log_index, created,
          suggested_window_start, suggested_window_end, replaced_by, subject_dn, ca_id)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, ?)",
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
    .bind(&row.subject_dn)
    .bind(&row.ca_id)
    .execute(executor)
    .await?;
    Ok(())
}

pub async fn get_by_id(
    executor: impl sqlx::Executor<'_, Database = sqlx::Any>,
    id: &str,
) -> Result<Option<CertificateRow>, AcmeError> {
    let row = super::query_as::<CertificateRow>(
        "SELECT id, order_id, account_id, serial_number, status, der, pem,
         not_before, not_after, revoked_at, revocation_reason, mtc_log_index, created,
         suggested_window_start, suggested_window_end, replaced_by, subject_dn, ca_id
         FROM certificates WHERE id = ?",
    )
    .bind(id)
    .fetch_optional(executor)
    .await?;
    Ok(row)
}

pub async fn get_by_serial(
    executor: impl sqlx::Executor<'_, Database = sqlx::Any>,
    serial: &str,
) -> Result<Option<CertificateRow>, AcmeError> {
    let row = super::query_as::<CertificateRow>(
        "SELECT id, order_id, account_id, serial_number, status, der, pem,
         not_before, not_after, revoked_at, revocation_reason, mtc_log_index, created,
         suggested_window_start, suggested_window_end, replaced_by, subject_dn, ca_id
         FROM certificates WHERE serial_number = ?",
    )
    .bind(serial)
    .fetch_optional(executor)
    .await?;
    Ok(row)
}

/// Look up a certificate by RFC 9773 ARI cert_id.
///
/// The cert_id format (RFC 9773 §4.1) is:
///   `base64url(AKI keyIdentifier) "." base64url(serial number bytes)`
///
/// Only the serial component is used for the DB lookup.  The AKI is validated
/// against the resolved CA in `renewal_info.rs` after the row is fetched, so
/// a cert_id referencing the wrong CA returns 404 rather than the wrong cert.
pub async fn get_by_cert_id(
    executor: impl sqlx::Executor<'_, Database = sqlx::Any>,
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
    get_by_serial(executor, &serial_hex).await
}

/// Mark a certificate as replaced by a new order.
///
/// Sets `replaced_by` to `replacing_order_id` only when it is currently NULL so
/// concurrent calls are idempotent (the first writer wins).  Returns whether a
/// row was actually updated.
pub async fn mark_replaced(
    executor: impl sqlx::Executor<'_, Database = sqlx::Any>,
    cert_uuid: &str,
    replacing_order_id: &str,
) -> Result<bool, AcmeError> {
    let n = super::query(
        "UPDATE certificates SET replaced_by = ? \
         WHERE id = ? AND replaced_by IS NULL",
    )
    .bind(replacing_order_id)
    .bind(cert_uuid)
    .execute(executor)
    .await?
    .rows_affected();
    Ok(n > 0)
}

/// Set a certificate as revoked.
pub async fn revoke(
    executor: impl sqlx::Executor<'_, Database = sqlx::Any>,
    id: &str,
    reason: Option<i64>,
    now: i64,
) -> Result<bool, AcmeError> {
    let n = super::query(
        "UPDATE certificates SET status = 'revoked', revoked_at = ?, revocation_reason = ?
         WHERE id = ? AND status = 'valid'",
    )
    .bind(now)
    .bind(reason)
    .bind(id)
    .execute(executor)
    .await?
    .rows_affected();
    Ok(n > 0)
}

/// Update the MTC log index after appending the certificate to the transparency log.
pub async fn set_mtc_log_index(
    executor: impl sqlx::Executor<'_, Database = sqlx::Any>,
    id: &str,
    index: i64,
) -> Result<(), AcmeError> {
    let result = super::query("UPDATE certificates SET mtc_log_index = ? WHERE id = ?")
        .bind(index)
        .bind(id)
        .execute(executor)
        .await?;
    if result.rows_affected() == 0 {
        return Err(AcmeError::Database(format!(
            "set_mtc_log_index: certificate '{id}' not found"
        )));
    }
    Ok(())
}

/// Set renewal window (RFC 9773 ARI).
///
/// Returns `Err` if `start >= end` — a window must be a non-empty interval.
pub async fn set_renewal_window(
    executor: impl sqlx::Executor<'_, Database = sqlx::Any>,
    id: &str,
    start: i64,
    end: i64,
) -> Result<(), AcmeError> {
    if start >= end {
        return Err(AcmeError::BadRequest(format!(
            "renewal window start ({start}) must be before end ({end})"
        )));
    }
    let result = super::query(
        "UPDATE certificates SET suggested_window_start = ?, suggested_window_end = ?
         WHERE id = ?",
    )
    .bind(start)
    .bind(end)
    .bind(id)
    .execute(executor)
    .await?;
    if result.rows_affected() == 0 {
        return Err(AcmeError::Database(format!(
            "set_renewal_window: certificate '{id}' not found"
        )));
    }
    Ok(())
}

/// Maximum number of revoked certificates loaded per CRL generation.
///
/// CRLs must list all unexpired revocations; exceeding this limit returns an
/// error so operators know to implement delta CRLs rather than silently
/// producing a truncated (incorrect) CRL.
const MAX_CRL_ENTRIES: i64 = 500_000;

/// List revoked certificates for a specific CA (for CRL generation).
///
/// Only certificates issued by `ca_id` are included so each CA's CRL contains
/// only its own revocations.  Returns a narrow projection (`CrlEntry`) to avoid
/// loading DER/PEM blobs — the CRL builder only needs serial, timestamp, and reason.
///
/// Returns `AcmeError::Database` if the revocation set exceeds `MAX_CRL_ENTRIES`
/// to prevent unbounded memory growth.  Operators should enable delta CRLs
/// when revocation counts approach this threshold.
pub async fn list_revoked(
    executor: impl sqlx::Executor<'_, Database = sqlx::Any>,
    ca_id: &str,
) -> Result<Vec<CrlEntry>, AcmeError> {
    let rows = super::query_as::<CrlEntry>(
        "SELECT serial_number, revoked_at, revocation_reason
         FROM certificates WHERE status = 'revoked' AND ca_id = ?
         LIMIT ?",
    )
    .bind(ca_id)
    .bind(MAX_CRL_ENTRIES + 1)
    .fetch_all(executor)
    .await?;
    if rows.len() as i64 > MAX_CRL_ENTRIES {
        return Err(AcmeError::Database(format!(
            "CA '{ca_id}' has more than {MAX_CRL_ENTRIES} revoked certificates; \
             CRL generation aborted to prevent OOM — implement delta CRLs"
        )));
    }
    Ok(rows)
}

/// List valid (non-revoked, non-expired) certificates for an account.
pub async fn list_valid_for_account(
    executor: impl sqlx::Executor<'_, Database = sqlx::Any>,
    account_id: &str,
    now: i64,
) -> Result<Vec<CertificateRow>, AcmeError> {
    let rows = super::query_as::<CertificateRow>(
        "SELECT id, order_id, account_id, serial_number, status, der, pem,
         not_before, not_after, revoked_at, revocation_reason, mtc_log_index, created,
         suggested_window_start, suggested_window_end, replaced_by, subject_dn, ca_id
         FROM certificates
         WHERE account_id = ? AND status = 'valid' AND not_after > ?",
    )
    .bind(account_id)
    .bind(now)
    .fetch_all(executor)
    .await?;
    Ok(rows)
}

/// Return the most recently issued certificate for a given order.
///
/// Used by the STAR certificate endpoint (RFC 8739 §3.3) to serve the current
/// certificate without embedding the query directly in the route handler.
pub async fn get_latest_for_order(
    executor: impl sqlx::Executor<'_, Database = sqlx::Any>,
    order_id: &str,
) -> Result<Option<CertificateRow>, AcmeError> {
    let row = super::query_as::<CertificateRow>(
        "SELECT id, order_id, account_id, serial_number, status, der, pem,
         not_before, not_after, revoked_at, revocation_reason, mtc_log_index, created,
         suggested_window_start, suggested_window_end, replaced_by, subject_dn, ca_id
         FROM certificates
         WHERE order_id = ?
         ORDER BY created DESC
         LIMIT 1",
    )
    .bind(order_id)
    .fetch_optional(executor)
    .await?;
    Ok(row)
}

/// Return certificates whose leaf index is covered by a checkpoint but that do not
/// yet have a standalone DER built.  Only certs with `mtc_log_index < max_leaf_index`
/// are returned so the results are consistent with a specific checkpoint boundary.
pub async fn get_pending_standalone(
    executor: impl sqlx::Executor<'_, Database = sqlx::Any>,
    max_leaf_index: i64,
) -> Result<Vec<CertForStandalone>, AcmeError> {
    let rows = super::query_as::<CertForStandalone>(
        "SELECT id, der, mtc_log_index FROM certificates
         WHERE mtc_log_index IS NOT NULL
           AND mtc_log_index < ?
           AND mtc_standalone_der IS NULL
         ORDER BY mtc_log_index ASC
         LIMIT 500",
    )
    .bind(max_leaf_index)
    .fetch_all(executor)
    .await?;
    Ok(rows)
}

/// Persist the DER-encoded `StandaloneCertificate` for a certificate row.
pub async fn set_mtc_standalone_der(
    executor: impl sqlx::Executor<'_, Database = sqlx::Any>,
    id: &str,
    der: &[u8],
) -> Result<(), AcmeError> {
    let result = super::query("UPDATE certificates SET mtc_standalone_der = ? WHERE id = ?")
        .bind(der)
        .bind(id)
        .execute(executor)
        .await?;
    if result.rows_affected() == 0 {
        return Err(AcmeError::Database(format!(
            "set_mtc_standalone_der: certificate '{id}' not found"
        )));
    }
    Ok(())
}

/// Return any certificate whose `mtc_log_index` is strictly less than `max_leaf_index`.
///
/// Used by landmark allocation to pick a representative leaf for `LandmarkCertificateBuilder`.
/// Returns `None` when no certificate has been appended to the MTC log yet.
pub async fn get_representative_for_landmark(
    executor: impl sqlx::Executor<'_, Database = sqlx::Any>,
    max_leaf_index: i64,
) -> Result<Option<CertificateRow>, AcmeError> {
    let row = super::query_as::<CertificateRow>(
        "SELECT id, order_id, account_id, serial_number, status, der, pem,
         not_before, not_after, revoked_at, revocation_reason, mtc_log_index, created,
         suggested_window_start, suggested_window_end, replaced_by, subject_dn, ca_id
         FROM certificates
         WHERE mtc_log_index IS NOT NULL AND mtc_log_index < ?
         ORDER BY mtc_log_index ASC
         LIMIT 1",
    )
    .bind(max_leaf_index)
    .fetch_optional(executor)
    .await?;
    Ok(row)
}

/// Retrieve the DER-encoded `StandaloneCertificate` for a certificate, if built.
pub async fn get_mtc_standalone_der(
    executor: impl sqlx::Executor<'_, Database = sqlx::Any>,
    id: &str,
) -> Result<Option<Vec<u8>>, AcmeError> {
    let row: Option<(Vec<u8>,)> =
        super::query_as("SELECT mtc_standalone_der FROM certificates WHERE id = ? AND mtc_standalone_der IS NOT NULL")
            .bind(id)
            .fetch_optional(executor)
            .await?;
    Ok(row.map(|(der,)| der))
}

// ── Admin search ──────────────────────────────────────────────────────────────

/// Filtered, paginated search used by `GET /admin/certs`.
/// Filter parameters for [`search`].
pub struct CertSearchParams<'a> {
    pub serial: Option<&'a str>,
    pub account_id: Option<&'a str>,
    pub status: Option<&'a str>,
    pub subject_dn: Option<&'a str>,
    pub ca_id: Option<&'a str>,
    pub limit: i64,
    pub offset: i64,
}

/// Search certificates with optional filters.
///
/// Uses `QueryBuilder` so optional filters only emit bind parameters when
/// present, avoiding the `(? IS NULL OR ...)` pattern that misfires on
/// Postgres with untyped NULL placeholders.
pub async fn search(
    executor: impl sqlx::Executor<'_, Database = sqlx::Any>,
    params: CertSearchParams<'_>,
) -> Result<Vec<CertificateRow>, crate::error::AcmeError> {
    let CertSearchParams {
        serial,
        account_id,
        status,
        subject_dn,
        ca_id,
        limit,
        offset,
    } = params;
    let mut qb = super::DynQueryBuilder::new(
        "SELECT id, order_id, account_id, serial_number, status, der, pem, \
                not_before, not_after, revoked_at, revocation_reason, mtc_log_index, created, \
                suggested_window_start, suggested_window_end, replaced_by, subject_dn, ca_id \
         FROM certificates WHERE 1=1",
    );
    if let Some(s) = serial {
        qb.push(" AND serial_number = ");
        qb.push_bind(s);
    }
    if let Some(a) = account_id {
        qb.push(" AND account_id = ");
        qb.push_bind(a);
    }
    if let Some(st) = status {
        qb.push(" AND status = ");
        qb.push_bind(st);
    }
    if let Some(dn) = subject_dn {
        let escaped = dn.replace('!', "!!").replace('%', "!%").replace('_', "!_");
        qb.push(" AND subject_dn LIKE ");
        qb.push_bind(format!("%{escaped}%"));
        qb.push(" ESCAPE '!'");
    }
    if let Some(ca) = ca_id {
        qb.push(" AND ca_id = ");
        qb.push_bind(ca);
    }
    qb.push(" ORDER BY created DESC LIMIT ");
    qb.push_bind(limit);
    qb.push(" OFFSET ");
    qb.push_bind(offset);

    let rows = qb.fetch_all::<_, CertificateRow>(executor).await?;
    Ok(rows)
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::db::schema::{AccountRow, OrderRow};
    use crate::db::Db;

    async fn open_db() -> Db {
        crate::db::install_drivers();
        crate::db::open("sqlite::memory:", 1, false).await.unwrap()
    }

    /// Insert a minimal account + order so that foreign-key constraints pass.
    async fn insert_parent_rows(db: &Db, account_id: &str, order_id: &str) {
        let acct = AccountRow {
            id: account_id.to_string(),
            status: "valid".to_string(),
            contact: None,
            public_key: vec![0u8; 4],
            jwk_thumbprint: format!("thumb-{account_id}"),
            created: 1_700_000_000,
            updated: 1_700_000_000,
            profile_grants: None,
            ca_id: String::new(),
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
            star_start_date: None,
            star_end_date: None,
            star_lifetime_secs: None,
            star_lifetime_adjust_secs: 0,
            star_allow_cert_get: 0,
            star_canceled_at: None,
            star_csr_der: None,
            profile: None,
            ca_id: "default".to_string(),
            delegation_id: None,
            allow_cert_get: 0,
            upstream_order_url: None,
            upstream_cert_url: None,
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
            subject_dn: None,
            ca_id: "default".to_string(),
        }
    }

    /// Helper: insert parent rows + cert together.
    async fn insert_cert(db: &Db, id: &str, account_id: &str, status: &str, not_after: i64) {
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
    async fn set_mtc_log_index_nonexistent_is_err() {
        let db = open_db().await;
        assert!(
            set_mtc_log_index(&db, "nonexistent", 99).await.is_err(),
            "set_mtc_log_index on nonexistent cert must return Err"
        );
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
    async fn set_renewal_window_nonexistent_is_err() {
        let db = open_db().await;
        assert!(
            set_renewal_window(&db, "nonexistent", 100, 200)
                .await
                .is_err(),
            "set_renewal_window on nonexistent cert must return Err"
        );
    }

    #[tokio::test]
    async fn list_revoked_returns_only_revoked() {
        let db = open_db().await;
        insert_cert(&db, "cert-8", "acct-8a", "valid", 1_800_000_000).await;
        insert_cert(&db, "cert-9", "acct-8b", "valid", 1_800_000_000).await;

        revoke(&db, "cert-9", Some(4), 1_700_500_000).await.unwrap();

        let revoked = list_revoked(&db, "default").await.unwrap();
        assert_eq!(revoked.len(), 1);
        assert_eq!(revoked[0].serial_number, "serial-cert-9");
    }

    #[tokio::test]
    async fn list_revoked_empty_when_none_revoked() {
        let db = open_db().await;
        insert_cert(&db, "cert-10", "acct-10", "valid", 1_800_000_000).await;

        let revoked = list_revoked(&db, "default").await.unwrap();
        assert!(revoked.is_empty());
    }

    #[tokio::test]
    async fn list_revoked_filters_by_ca_id() {
        let db = open_db().await;

        // Insert parent rows for two separate CA environments.
        // insert_parent_rows creates account + order; sample_cert sets order_id = "order-{id}",
        // so the parent order ID must match.
        insert_parent_rows(&db, "acct-ca-a", "order-cert-ca-a").await;
        let mut cert_a = sample_cert("cert-ca-a", "acct-ca-a", "valid", 1_800_000_000);
        cert_a.ca_id = "ca-a".to_string();
        insert(&db, cert_a).await.unwrap();

        insert_parent_rows(&db, "acct-ca-b", "order-cert-ca-b").await;
        let mut cert_b = sample_cert("cert-ca-b", "acct-ca-b", "valid", 1_800_000_000);
        cert_b.ca_id = "ca-b".to_string();
        insert(&db, cert_b).await.unwrap();

        // Revoke both.
        revoke(&db, "cert-ca-a", Some(1), 1_700_500_000)
            .await
            .unwrap();
        revoke(&db, "cert-ca-b", Some(2), 1_700_500_001)
            .await
            .unwrap();

        // list_revoked("ca-a") must return only cert-ca-a.
        let revoked_a = list_revoked(&db, "ca-a").await.unwrap();
        assert_eq!(
            revoked_a.len(),
            1,
            "ca-a CRL must contain exactly one entry"
        );
        assert_eq!(revoked_a[0].serial_number, "serial-cert-ca-a");

        // list_revoked("ca-b") must return only cert-ca-b.
        let revoked_b = list_revoked(&db, "ca-b").await.unwrap();
        assert_eq!(
            revoked_b.len(),
            1,
            "ca-b CRL must contain exactly one entry"
        );
        assert_eq!(revoked_b[0].serial_number, "serial-cert-ca-b");

        // list_revoked("default") must return nothing (no certs with ca_id = 'default').
        let revoked_default = list_revoked(&db, "default").await.unwrap();
        assert!(revoked_default.is_empty());
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
        insert_parent_rows(&db, "acct-xa-extra", "order-cert-b2").await;
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
                subject_dn: None,
                ca_id: "default".to_string(),
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
        crate::db::install_drivers();
        let raw: Db = sqlx::any::AnyPoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
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
            subject_dn: None,
            ca_id: "default".to_string(),
        };
        assert!(insert(&raw, row).await.is_err());
        assert!(get_by_id(&raw, "any").await.is_err());
        assert!(get_by_serial(&raw, "any").await.is_err());
        assert!(revoke(&raw, "any", None, now).await.is_err());
        assert!(set_mtc_log_index(&raw, "any", 0).await.is_err());
        assert!(set_renewal_window(&raw, "any", now, now + 86400)
            .await
            .is_err());
        assert!(list_revoked(&raw, "default").await.is_err());
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

    #[tokio::test]
    async fn get_latest_for_order_returns_most_recent() {
        let db = open_db().await;
        insert_parent_rows(&db, "acct-star", "order-star").await;

        // Insert two certs for the same order with different created timestamps.
        let mut cert_old = sample_cert("cert-old", "acct-star", "valid", 1_800_000_000);
        cert_old.order_id = "order-star".to_string();
        cert_old.created = 1_700_000_000;
        cert_old.serial_number = "serial-old".to_string();
        insert(&db, cert_old).await.unwrap();

        let mut cert_new = sample_cert("cert-new", "acct-star", "valid", 1_800_100_000);
        cert_new.order_id = "order-star".to_string();
        cert_new.created = 1_700_100_000;
        cert_new.serial_number = "serial-new".to_string();
        insert(&db, cert_new).await.unwrap();

        let result = get_latest_for_order(&db, "order-star").await.unwrap();
        assert!(result.is_some());
        assert_eq!(result.unwrap().id, "cert-new");
    }

    #[tokio::test]
    async fn get_latest_for_order_none_when_no_certs() {
        let db = open_db().await;
        let result = get_latest_for_order(&db, "nonexistent-order")
            .await
            .unwrap();
        assert!(result.is_none());
    }
}

/// Count certificates matching the same filters as [`search`], without LIMIT/OFFSET.
pub async fn count_search(
    executor: impl sqlx::Executor<'_, Database = sqlx::Any>,
    params: CertSearchParams<'_>,
) -> Result<i64, crate::error::AcmeError> {
    let CertSearchParams {
        serial,
        account_id,
        status,
        subject_dn,
        ca_id,
        ..
    } = params;
    let mut qb = super::DynQueryBuilder::new("SELECT COUNT(*) FROM certificates WHERE 1=1");
    if let Some(s) = serial {
        qb.push(" AND serial_number = ");
        qb.push_bind(s);
    }
    if let Some(a) = account_id {
        qb.push(" AND account_id = ");
        qb.push_bind(a);
    }
    if let Some(st) = status {
        qb.push(" AND status = ");
        qb.push_bind(st);
    }
    if let Some(dn) = subject_dn {
        let escaped = dn.replace('!', "!!").replace('%', "!%").replace('_', "!_");
        qb.push(" AND subject_dn LIKE ");
        qb.push_bind(format!("%{escaped}%"));
        qb.push(" ESCAPE '!'");
    }
    if let Some(ca) = ca_id {
        qb.push(" AND ca_id = ");
        qb.push_bind(ca);
    }
    let row: (i64,) = qb.fetch_one(executor).await?;
    Ok(row.0)
}
