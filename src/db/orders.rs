use crate::db::schema::OrderRow;
use crate::error::AcmeError;

pub async fn insert(
    executor: impl sqlx::Executor<'_, Database = sqlx::Any>,
    row: OrderRow,
) -> Result<(), AcmeError> {
    super::query(
        "INSERT INTO orders (id, account_id, status, expires, identifiers,
         not_before, not_after, error, certificate_id, replaces, created, updated,
         star_start_date, star_end_date, star_lifetime_secs, star_lifetime_adjust_secs,
         star_allow_cert_get, star_canceled_at, star_csr_der, profile, ca_id,
         delegation_id, allow_cert_get, upstream_order_url, upstream_cert_url)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&row.id)
    .bind(&row.account_id)
    .bind(&row.status)
    .bind(row.expires)
    .bind(&row.identifiers)
    .bind(row.not_before)
    .bind(row.not_after)
    .bind(&row.error)
    .bind(&row.certificate_id)
    .bind(&row.replaces)
    .bind(row.created)
    .bind(row.updated)
    .bind(row.star_start_date)
    .bind(row.star_end_date)
    .bind(row.star_lifetime_secs)
    .bind(row.star_lifetime_adjust_secs)
    .bind(row.star_allow_cert_get)
    .bind(row.star_canceled_at)
    .bind(&row.star_csr_der)
    .bind(&row.profile)
    .bind(&row.ca_id)
    .bind(&row.delegation_id)
    .bind(row.allow_cert_get)
    .bind(&row.upstream_order_url)
    .bind(&row.upstream_cert_url)
    .execute(executor)
    .await?;
    Ok(())
}

/// Cancel a STAR order by setting star_canceled_at to the current timestamp.
///
/// The WHERE guard `star_canceled_at IS NULL` makes this idempotent: concurrent
/// cancellation requests both run the UPDATE but only the first one makes a
/// change.  Subsequent calls silently succeed with 0 rows affected.
pub async fn cancel_star(
    executor: impl sqlx::Executor<'_, Database = sqlx::Any>,
    id: &str,
    now: i64,
) -> Result<(), AcmeError> {
    super::query(
        "UPDATE orders SET star_canceled_at = ?, updated = ? WHERE id = ? AND star_canceled_at IS NULL",
    )
    .bind(now)
    .bind(now)
    .bind(id)
    .execute(executor)
    .await?;
    Ok(())
}

/// List all active STAR orders (star_end_date set, not canceled, status = 'valid').
pub async fn list_active_star(
    executor: impl sqlx::Executor<'_, Database = sqlx::Any>,
) -> Result<Vec<OrderRow>, AcmeError> {
    let rows = super::query_as::<OrderRow>(
        "SELECT id, account_id, status, expires, identifiers,
         not_before, not_after, error, certificate_id, replaces, created, updated,
         star_start_date, star_end_date, star_lifetime_secs, star_lifetime_adjust_secs,
         star_allow_cert_get, star_canceled_at, star_csr_der, profile, ca_id,
         delegation_id, allow_cert_get, upstream_order_url, upstream_cert_url
         FROM orders
         WHERE star_end_date IS NOT NULL AND star_canceled_at IS NULL AND status = 'valid'",
    )
    .fetch_all(executor)
    .await?;
    Ok(rows)
}

/// Store the CSR DER on an order (set during finalize for STAR orders).
pub async fn set_star_csr(
    executor: impl sqlx::Executor<'_, Database = sqlx::Any>,
    id: &str,
    csr_der: Vec<u8>,
) -> Result<(), AcmeError> {
    let result = super::query("UPDATE orders SET star_csr_der = ? WHERE id = ?")
        .bind(&csr_der)
        .bind(id)
        .execute(executor)
        .await?;
    if result.rows_affected() == 0 {
        return Err(AcmeError::NotFound);
    }
    Ok(())
}

pub async fn get_by_id(
    executor: impl sqlx::Executor<'_, Database = sqlx::Any>,
    id: &str,
) -> Result<Option<OrderRow>, AcmeError> {
    let row = super::query_as::<OrderRow>(
        "SELECT id, account_id, status, expires, identifiers,
         not_before, not_after, error, certificate_id, replaces, created, updated,
         star_start_date, star_end_date, star_lifetime_secs, star_lifetime_adjust_secs,
         star_allow_cert_get, star_canceled_at, star_csr_der, profile, ca_id,
         delegation_id, allow_cert_get, upstream_order_url, upstream_cert_url
         FROM orders WHERE id = ?",
    )
    .bind(id)
    .fetch_optional(executor)
    .await?;
    Ok(row)
}

pub async fn update_status(
    executor: impl sqlx::Executor<'_, Database = sqlx::Any>,
    id: &str,
    status: &str,
    error: Option<String>,
    now: i64,
) -> Result<(), AcmeError> {
    let result = super::query("UPDATE orders SET status = ?, error = ?, updated = ? WHERE id = ?")
        .bind(status)
        .bind(error)
        .bind(now)
        .bind(id)
        .execute(executor)
        .await?;
    if result.rows_affected() == 0 {
        return Err(AcmeError::NotFound);
    }
    Ok(())
}

pub async fn set_certificate(
    executor: impl sqlx::Executor<'_, Database = sqlx::Any>,
    id: &str,
    certificate_id: &str,
    now: i64,
) -> Result<(), AcmeError> {
    // AND status = 'ready' is an atomic finalization guard: if a concurrent
    // request already committed this order to 'valid', rows_affected == 0 and
    // we return Conflict instead of silently overwriting the certificate_id.
    let result = super::query(
        "UPDATE orders SET status = 'valid', certificate_id = ?, updated = ? \
         WHERE id = ? AND status = 'ready'",
    )
    .bind(certificate_id)
    .bind(now)
    .bind(id)
    .execute(executor)
    .await?;
    if result.rows_affected() == 0 {
        return Err(AcmeError::Conflict("order already finalized".into()));
    }
    Ok(())
}

/// Atomically transition a delegation order from `ready` to `processing` and store the CSR.
///
/// Combines the status transition and CSR storage into a single UPDATE so a crash between
/// the two operations cannot leave the order in `processing` without a CSR to finalize with.
/// The `AND status = 'ready'` guard prevents double-advancing under concurrent requests.
///
/// Returns `Conflict` when the order was already advanced past `ready`.
pub async fn set_processing_with_csr_der(
    executor: impl sqlx::Executor<'_, Database = sqlx::Any>,
    id: &str,
    csr_der: &[u8],
    now: i64,
) -> Result<(), AcmeError> {
    let result = super::query(
        "UPDATE orders SET status = 'processing', star_csr_der = ?, updated = ? \
         WHERE id = ? AND status = 'ready'",
    )
    .bind(csr_der)
    .bind(now)
    .bind(id)
    .execute(executor)
    .await?;
    if result.rows_affected() == 0 {
        return Err(AcmeError::Conflict(
            "order already advanced past ready".into(),
        ));
    }
    Ok(())
}

/// Transition a delegation order from `ready` to `processing`.
///
/// Used by the finalize handler when an upstream CA handles issuance and the
/// result is polled asynchronously.  The `AND status = 'ready'` guard prevents
/// a concurrent request from double-advancing the order.
///
/// Returns `Conflict` when the order was already advanced past `ready`.
pub async fn set_status_processing(
    executor: impl sqlx::Executor<'_, Database = sqlx::Any>,
    id: &str,
    now: i64,
) -> Result<(), AcmeError> {
    let result = super::query(
        "UPDATE orders SET status = 'processing', updated = ? WHERE id = ? AND status = 'ready'",
    )
    .bind(now)
    .bind(id)
    .execute(executor)
    .await?;
    if result.rows_affected() == 0 {
        return Err(AcmeError::Conflict(
            "order already advanced past ready".into(),
        ));
    }
    Ok(())
}

/// Transition a delegation order from `processing` to `valid` and set its
/// certificate_id.  Used by the delegation upstream task after downloading and
/// storing the upstream certificate locally.
pub async fn set_valid_with_certificate(
    executor: impl sqlx::Executor<'_, Database = sqlx::Any>,
    id: &str,
    certificate_id: &str,
    now: i64,
) -> Result<(), AcmeError> {
    let result = super::query(
        "UPDATE orders SET status = 'valid', certificate_id = ?, updated = ? \
         WHERE id = ? AND status = 'processing'",
    )
    .bind(certificate_id)
    .bind(now)
    .bind(id)
    .execute(executor)
    .await?;
    if result.rows_affected() == 0 {
        return Err(AcmeError::Conflict("order not in processing state".into()));
    }
    Ok(())
}

/// Update the `certificate_id` on a STAR order, guarded against canceled orders.
///
/// Returns `true` if the order was found and updated, `false` if it was already
/// canceled (`star_canceled_at IS NOT NULL`) or does not exist.
pub async fn update_star_certificate(
    executor: impl sqlx::Executor<'_, Database = sqlx::Any>,
    id: &str,
    certificate_id: &str,
    now: i64,
) -> Result<bool, AcmeError> {
    let n = super::query(
        "UPDATE orders SET certificate_id = ?, updated = ? \
         WHERE id = ? AND star_canceled_at IS NULL",
    )
    .bind(certificate_id)
    .bind(now)
    .bind(id)
    .execute(executor)
    .await?
    .rows_affected();
    Ok(n > 0)
}

/// Fetch an order and its authorization IDs in a single JOIN round-trip.
///
/// Returns `None` if no order with `order_id` exists.
///
/// Accepts `impl Executor` (single query), so callers can pass either `&pool`
/// or `&mut *tx`.  The previous two-query implementation required `&Db`.
pub async fn get_with_authz_ids(
    executor: impl sqlx::Executor<'_, Database = sqlx::Any>,
    order_id: &str,
) -> Result<Option<(OrderRow, Vec<String>)>, AcmeError> {
    // One LEFT JOIN returns N rows (one per authz, or 1 row with NULL authz_id
    // when no authzs exist yet).  All order columns are the same across rows;
    // we read them from the first row and collect the authz IDs from all rows.
    #[derive(sqlx::FromRow)]
    struct OrderAuthzRow {
        // Order columns
        id: String,
        account_id: String,
        status: String,
        expires: Option<i64>,
        identifiers: String,
        not_before: Option<i64>,
        not_after: Option<i64>,
        error: Option<String>,
        certificate_id: Option<String>,
        replaces: Option<String>,
        created: i64,
        updated: i64,
        star_start_date: Option<i64>,
        star_end_date: Option<i64>,
        star_lifetime_secs: Option<i64>,
        star_lifetime_adjust_secs: i64,
        star_allow_cert_get: i64,
        star_canceled_at: Option<i64>,
        star_csr_der: Option<Vec<u8>>,
        profile: Option<String>,
        ca_id: String,
        // RFC 9115 delegation columns
        delegation_id: Option<String>,
        allow_cert_get: i64,
        upstream_order_url: Option<String>,
        upstream_cert_url: Option<String>,
        // Authz column (NULL when no authorizations exist for this order)
        authz_id: Option<String>,
    }

    let rows = super::query_as::<OrderAuthzRow>(
        "SELECT
             o.id, o.account_id, o.status, o.expires, o.identifiers,
             o.not_before, o.not_after, o.error, o.certificate_id, o.replaces,
             o.created, o.updated,
             o.star_start_date, o.star_end_date, o.star_lifetime_secs,
             o.star_lifetime_adjust_secs, o.star_allow_cert_get, o.star_canceled_at,
             o.star_csr_der, o.profile, o.ca_id,
             o.delegation_id, o.allow_cert_get, o.upstream_order_url, o.upstream_cert_url,
             a.id AS authz_id
         FROM orders o
         LEFT JOIN authorizations a ON a.order_id = o.id
         WHERE o.id = ?
         ORDER BY a.id",
    )
    .bind(order_id)
    .fetch_all(executor)
    .await?;

    if rows.is_empty() {
        return Ok(None);
    }

    let first = &rows[0];
    let order = OrderRow {
        id: first.id.clone(),
        account_id: first.account_id.clone(),
        status: first.status.clone(),
        expires: first.expires,
        identifiers: first.identifiers.clone(),
        not_before: first.not_before,
        not_after: first.not_after,
        error: first.error.clone(),
        certificate_id: first.certificate_id.clone(),
        replaces: first.replaces.clone(),
        created: first.created,
        updated: first.updated,
        star_start_date: first.star_start_date,
        star_end_date: first.star_end_date,
        star_lifetime_secs: first.star_lifetime_secs,
        star_lifetime_adjust_secs: first.star_lifetime_adjust_secs,
        star_allow_cert_get: first.star_allow_cert_get,
        star_canceled_at: first.star_canceled_at,
        star_csr_der: first.star_csr_der.clone(),
        profile: first.profile.clone(),
        ca_id: first.ca_id.clone(),
        delegation_id: first.delegation_id.clone(),
        allow_cert_get: first.allow_cert_get,
        upstream_order_url: first.upstream_order_url.clone(),
        upstream_cert_url: first.upstream_cert_url.clone(),
    };
    let authz_ids: Vec<String> = rows.into_iter().filter_map(|r| r.authz_id).collect();
    Ok(Some((order, authz_ids)))
}

/// List orders with optional filters and pagination.
pub async fn list(
    executor: impl sqlx::Executor<'_, Database = sqlx::Any>,
    account_id: Option<&str>,
    status: Option<&str>,
    ca_id: Option<&str>,
    limit: i64,
    offset: i64,
) -> Result<Vec<OrderRow>, AcmeError> {
    let mut qb = super::DynQueryBuilder::new(
        "SELECT id, account_id, status, expires, identifiers, \
         not_before, not_after, error, certificate_id, replaces, created, updated, \
         star_start_date, star_end_date, star_lifetime_secs, star_lifetime_adjust_secs, \
         star_allow_cert_get, star_canceled_at, star_csr_der, profile, ca_id, \
         delegation_id, allow_cert_get, upstream_order_url, upstream_cert_url \
         FROM orders WHERE 1=1",
    );
    if let Some(a) = account_id {
        qb.push(" AND account_id = ");
        qb.push_bind(a);
    }
    if let Some(st) = status {
        qb.push(" AND status = ");
        qb.push_bind(st);
    }
    if let Some(ca) = ca_id {
        qb.push(" AND ca_id = ");
        qb.push_bind(ca);
    }
    qb.push(" ORDER BY created DESC LIMIT ");
    qb.push_bind(limit);
    qb.push(" OFFSET ");
    qb.push_bind(offset);

    let rows = qb.fetch_all::<_, OrderRow>(executor).await?;
    Ok(rows)
}

/// Attach a delegation to an order and record the allow-certificate-get flag.
pub async fn set_delegation(
    executor: impl sqlx::Executor<'_, Database = sqlx::Any>,
    id: &str,
    delegation_id: &str,
    allow_cert_get: i64,
    now: i64,
) -> Result<(), AcmeError> {
    let result = super::query(
        "UPDATE orders SET delegation_id = ?, allow_cert_get = ?, updated = ? WHERE id = ?",
    )
    .bind(delegation_id)
    .bind(allow_cert_get)
    .bind(now)
    .bind(id)
    .execute(executor)
    .await?;
    if result.rows_affected() == 0 {
        return Err(AcmeError::NotFound);
    }
    Ok(())
}

/// Record the Order2 URL returned by the upstream CA.
pub async fn set_upstream_order_url(
    executor: impl sqlx::Executor<'_, Database = sqlx::Any>,
    id: &str,
    url: &str,
    now: i64,
) -> Result<(), AcmeError> {
    let result = super::query("UPDATE orders SET upstream_order_url = ?, updated = ? WHERE id = ?")
        .bind(url)
        .bind(now)
        .bind(id)
        .execute(executor)
        .await?;
    if result.rows_affected() == 0 {
        return Err(AcmeError::NotFound);
    }
    Ok(())
}

/// Record the certificate URL returned by the upstream CA once the order is valid.
pub async fn set_upstream_cert_url(
    executor: impl sqlx::Executor<'_, Database = sqlx::Any>,
    id: &str,
    url: &str,
    now: i64,
) -> Result<(), AcmeError> {
    let result = super::query("UPDATE orders SET upstream_cert_url = ?, updated = ? WHERE id = ?")
        .bind(url)
        .bind(now)
        .bind(id)
        .execute(executor)
        .await?;
    if result.rows_affected() == 0 {
        return Err(AcmeError::NotFound);
    }
    Ok(())
}

/// List delegation orders that are in processing and have no upstream cert URL yet.
///
/// These are the orders the IdO→CA background task must drive to completion.
pub async fn list_pending_delegation_orders(
    executor: impl sqlx::Executor<'_, Database = sqlx::Any>,
) -> Result<Vec<OrderRow>, AcmeError> {
    let rows = super::query_as::<OrderRow>(
        "SELECT id, account_id, status, expires, identifiers,
         not_before, not_after, error, certificate_id, replaces, created, updated,
         star_start_date, star_end_date, star_lifetime_secs, star_lifetime_adjust_secs,
         star_allow_cert_get, star_canceled_at, star_csr_der, profile, ca_id,
         delegation_id, allow_cert_get, upstream_order_url, upstream_cert_url
         FROM orders
         WHERE delegation_id IS NOT NULL AND status = 'processing' AND upstream_cert_url IS NULL
         LIMIT 200",
    )
    .fetch_all(executor)
    .await?;
    Ok(rows)
}

/// List all authorization IDs belonging to an order.
pub async fn list_authz_ids(
    executor: impl sqlx::Executor<'_, Database = sqlx::Any>,
    order_id: &str,
) -> Result<Vec<String>, AcmeError> {
    let ids: Vec<(String,)> = super::query_as("SELECT id FROM authorizations WHERE order_id = ?")
        .bind(order_id)
        .fetch_all(executor)
        .await?;
    Ok(ids.into_iter().map(|(id,)| id).collect())
}

/// Count orders matching the same filters as [`list`], without LIMIT/OFFSET.
pub async fn count_list(
    executor: impl sqlx::Executor<'_, Database = sqlx::Any>,
    account_id: Option<&str>,
    status: Option<&str>,
    ca_id: Option<&str>,
) -> Result<i64, AcmeError> {
    let mut qb = super::DynQueryBuilder::new("SELECT COUNT(*) FROM orders WHERE 1=1");
    if let Some(a) = account_id {
        qb.push(" AND account_id = ");
        qb.push_bind(a);
    }
    if let Some(st) = status {
        qb.push(" AND status = ");
        qb.push_bind(st);
    }
    if let Some(ca) = ca_id {
        qb.push(" AND ca_id = ");
        qb.push_bind(ca);
    }
    let row: (i64,) = qb.fetch_one(executor).await?;
    Ok(row.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::db::schema::AccountRow;
    use crate::db::Db;

    async fn open_db() -> Db {
        crate::db::install_drivers();
        crate::db::open("sqlite::memory:", 1, false).await.unwrap()
    }

    async fn insert_account(db: &Db, account_id: &str) {
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
                profile_grants: None,
                ca_id: String::new(),
                kerberos_principal: None,
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
            star_allow_cert_get: 0,
            star_canceled_at: None,
            star_csr_der: None,
            profile: None,
            ca_id: "default".to_string(),
            delegation_id: None,
            allow_cert_get: 0,
            upstream_order_url: None,
            upstream_cert_url: None,
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
        // set_certificate requires status = 'ready'
        update_status(&db, "order-4", "ready", None, 1_700_000_000)
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
                wildcard: 0,
                subdomain_auth_allowed: 0,
                created: 1_700_000_000,
                updated: 1_700_000_000,
                ca_id: "default".to_string(),
            },
        )
        .await
        .unwrap();

        let ids = list_authz_ids(&db, "order-6").await.unwrap();
        assert_eq!(ids, vec!["authz-a"]);
    }

    #[tokio::test]
    async fn db_error_paths_no_table() {
        crate::db::install_drivers();
        let raw: Db = sqlx::any::AnyPoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        assert!(insert(&raw, sample_order("err-order", "err-acct"))
            .await
            .is_err());
        assert!(get_by_id(&raw, "any").await.is_err());
        assert!(update_status(&raw, "any", "invalid", None, 0)
            .await
            .is_err());
        assert!(set_certificate(&raw, "any", "cert-id", 0).await.is_err());
        assert!(list_authz_ids(&raw, "any").await.is_err());
        assert!(set_delegation(&raw, "any", "dlg-id", 0, 0).await.is_err());
        assert!(
            set_upstream_order_url(&raw, "any", "https://ca.example/order/1", 0)
                .await
                .is_err()
        );
        assert!(
            set_upstream_cert_url(&raw, "any", "https://ca.example/cert/1", 0)
                .await
                .is_err()
        );
        assert!(list_pending_delegation_orders(&raw).await.is_err());
    }

    #[tokio::test]
    async fn update_status_nonexistent_returns_not_found() {
        let db = open_db().await;
        let err = update_status(&db, "no-such-order", "invalid", None, 0)
            .await
            .unwrap_err();
        assert!(matches!(err, crate::error::AcmeError::NotFound));
    }

    #[tokio::test]
    async fn set_certificate_already_valid_returns_conflict() {
        let db = open_db().await;
        insert_account(&db, "acct-cf").await;
        insert(&db, sample_order("order-cf", "acct-cf"))
            .await
            .unwrap();
        update_status(&db, "order-cf", "ready", None, 1_700_000_000)
            .await
            .unwrap();
        set_certificate(&db, "order-cf", "cert-1", 1_700_000_001)
            .await
            .unwrap();
        let err = set_certificate(&db, "order-cf", "cert-2", 1_700_000_002)
            .await
            .unwrap_err();
        assert!(matches!(err, crate::error::AcmeError::Conflict(_)));
    }

    #[tokio::test]
    async fn set_delegation_round_trip() {
        let db = open_db().await;
        insert_account(&db, "acct-sd").await;
        // need a delegation row for FK
        crate::db::delegations::insert(
            &db,
            crate::db::schema::DelegationRow {
                id: "dlg-sd".to_string(),
                account_id: "acct-sd".to_string(),
                csr_template: "{}".to_string(),
                cname_map: None,
                created: 1_700_000_000,
                updated: 1_700_000_000,
            },
        )
        .await
        .unwrap();
        insert(&db, sample_order("order-sd", "acct-sd"))
            .await
            .unwrap();
        set_delegation(&db, "order-sd", "dlg-sd", 1, 1_700_000_001)
            .await
            .unwrap();
        let row = get_by_id(&db, "order-sd").await.unwrap().unwrap();
        assert_eq!(row.delegation_id.as_deref(), Some("dlg-sd"));
        assert_eq!(row.allow_cert_get, 1);
    }

    #[tokio::test]
    async fn set_delegation_nonexistent_order_returns_not_found() {
        let db = open_db().await;
        let err = set_delegation(&db, "no-such-order", "dlg-x", 0, 0)
            .await
            .unwrap_err();
        assert!(matches!(err, crate::error::AcmeError::NotFound));
    }

    #[tokio::test]
    async fn set_upstream_order_url_round_trip() {
        let db = open_db().await;
        insert_account(&db, "acct-uu").await;
        insert(&db, sample_order("order-uu", "acct-uu"))
            .await
            .unwrap();
        set_upstream_order_url(
            &db,
            "order-uu",
            "https://ca.example/order/42",
            1_700_000_001,
        )
        .await
        .unwrap();
        let row = get_by_id(&db, "order-uu").await.unwrap().unwrap();
        assert_eq!(
            row.upstream_order_url.as_deref(),
            Some("https://ca.example/order/42")
        );
    }

    #[tokio::test]
    async fn set_upstream_order_url_nonexistent_returns_not_found() {
        let db = open_db().await;
        let err = set_upstream_order_url(&db, "no-such", "https://ca.example/order/1", 0)
            .await
            .unwrap_err();
        assert!(matches!(err, crate::error::AcmeError::NotFound));
    }

    #[tokio::test]
    async fn set_upstream_cert_url_round_trip() {
        let db = open_db().await;
        insert_account(&db, "acct-cu").await;
        insert(&db, sample_order("order-cu", "acct-cu"))
            .await
            .unwrap();
        set_upstream_cert_url(&db, "order-cu", "https://ca.example/cert/99", 1_700_000_001)
            .await
            .unwrap();
        let row = get_by_id(&db, "order-cu").await.unwrap().unwrap();
        assert_eq!(
            row.upstream_cert_url.as_deref(),
            Some("https://ca.example/cert/99")
        );
    }

    #[tokio::test]
    async fn set_upstream_cert_url_nonexistent_returns_not_found() {
        let db = open_db().await;
        let err = set_upstream_cert_url(&db, "no-such", "https://ca.example/cert/1", 0)
            .await
            .unwrap_err();
        assert!(matches!(err, crate::error::AcmeError::NotFound));
    }

    #[tokio::test]
    async fn list_pending_delegation_orders_filters_correctly() {
        let db = open_db().await;
        insert_account(&db, "acct-pd").await;
        crate::db::delegations::insert(
            &db,
            crate::db::schema::DelegationRow {
                id: "dlg-pd".to_string(),
                account_id: "acct-pd".to_string(),
                csr_template: "{}".to_string(),
                cname_map: None,
                created: 1_700_000_000,
                updated: 1_700_000_000,
            },
        )
        .await
        .unwrap();

        // Order in 'processing' with delegation and no cert URL — should appear.
        let mut o1 = sample_order("ord-pd-1", "acct-pd");
        o1.status = "processing".to_string();
        o1.delegation_id = Some("dlg-pd".to_string());
        insert(&db, o1).await.unwrap();

        // Order in 'processing' with delegation and upstream_order_url but no cert URL — should appear.
        let mut o2 = sample_order("ord-pd-2", "acct-pd");
        o2.status = "processing".to_string();
        o2.delegation_id = Some("dlg-pd".to_string());
        insert(&db, o2).await.unwrap();
        set_upstream_order_url(&db, "ord-pd-2", "https://ca.example/order/2", 1_700_000_001)
            .await
            .unwrap();

        // Order in 'processing' with cert URL set — should NOT appear.
        let mut o3 = sample_order("ord-pd-3", "acct-pd");
        o3.status = "processing".to_string();
        o3.delegation_id = Some("dlg-pd".to_string());
        insert(&db, o3).await.unwrap();
        set_upstream_cert_url(&db, "ord-pd-3", "https://ca.example/cert/3", 1_700_000_001)
            .await
            .unwrap();

        // Non-delegation order in 'processing' — should NOT appear.
        let mut o4 = sample_order("ord-pd-4", "acct-pd");
        o4.status = "processing".to_string();
        insert(&db, o4).await.unwrap();

        // Delegation order in 'valid' — should NOT appear.
        let mut o5 = sample_order("ord-pd-5", "acct-pd");
        o5.status = "valid".to_string();
        o5.delegation_id = Some("dlg-pd".to_string());
        insert(&db, o5).await.unwrap();

        let pending = list_pending_delegation_orders(&db).await.unwrap();
        let ids: Vec<&str> = pending.iter().map(|r| r.id.as_str()).collect();
        assert!(
            ids.contains(&"ord-pd-1"),
            "processing+delegation+no cert url should appear"
        );
        assert!(
            ids.contains(&"ord-pd-2"),
            "mid-flight (has upstream_order_url but no cert url) should appear"
        );
        assert!(
            !ids.contains(&"ord-pd-3"),
            "order with cert url set should not appear"
        );
        assert!(
            !ids.contains(&"ord-pd-4"),
            "non-delegation order should not appear"
        );
        assert!(
            !ids.contains(&"ord-pd-5"),
            "valid delegation order should not appear"
        );
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
