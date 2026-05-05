use crate::db::schema::OrderRow;
use crate::error::AcmeError;

pub async fn insert(
    executor: impl sqlx::Executor<'_, Database = sqlx::Any>,
    row: OrderRow,
) -> Result<(), AcmeError> {
    sqlx::query(
        "INSERT INTO orders (id, account_id, status, expires, identifiers,
         not_before, not_after, error, certificate_id, replaces, created, updated,
         star_start_date, star_end_date, star_lifetime_secs, star_lifetime_adjust_secs,
         star_allow_cert_get, star_canceled_at, star_csr_der, profile, ca_id)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
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
    .execute(executor)
    .await?;
    Ok(())
}

/// Cancel a STAR order by setting star_canceled_at to the current timestamp.
pub async fn cancel_star(
    executor: impl sqlx::Executor<'_, Database = sqlx::Any>,
    id: &str,
    now: i64,
) -> Result<(), AcmeError> {
    sqlx::query("UPDATE orders SET star_canceled_at = ?, updated = ? WHERE id = ?")
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
    let rows = sqlx::query_as::<_, OrderRow>(
        "SELECT id, account_id, status, expires, identifiers,
         not_before, not_after, error, certificate_id, replaces, created, updated,
         star_start_date, star_end_date, star_lifetime_secs, star_lifetime_adjust_secs,
         star_allow_cert_get, star_canceled_at, star_csr_der, profile, ca_id
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
    sqlx::query("UPDATE orders SET star_csr_der = ? WHERE id = ?")
        .bind(&csr_der)
        .bind(id)
        .execute(executor)
        .await?;
    Ok(())
}

pub async fn get_by_id(
    executor: impl sqlx::Executor<'_, Database = sqlx::Any>,
    id: &str,
) -> Result<Option<OrderRow>, AcmeError> {
    let row = sqlx::query_as::<_, OrderRow>(
        "SELECT id, account_id, status, expires, identifiers,
         not_before, not_after, error, certificate_id, replaces, created, updated,
         star_start_date, star_end_date, star_lifetime_secs, star_lifetime_adjust_secs,
         star_allow_cert_get, star_canceled_at, star_csr_der, profile, ca_id
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
    let result = sqlx::query("UPDATE orders SET status = ?, error = ?, updated = ? WHERE id = ?")
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
    let result = sqlx::query(
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
    let n = sqlx::query(
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
        // Authz column (NULL when no authorizations exist for this order)
        authz_id: Option<String>,
    }

    let rows = sqlx::query_as::<_, OrderAuthzRow>(
        "SELECT
             o.id, o.account_id, o.status, o.expires, o.identifiers,
             o.not_before, o.not_after, o.error, o.certificate_id, o.replaces,
             o.created, o.updated,
             o.star_start_date, o.star_end_date, o.star_lifetime_secs,
             o.star_lifetime_adjust_secs, o.star_allow_cert_get, o.star_canceled_at,
             o.star_csr_der, o.profile, o.ca_id,
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
    let mut qb = sqlx::QueryBuilder::<sqlx::Any>::new(
        "SELECT id, account_id, status, expires, identifiers, \
         not_before, not_after, error, certificate_id, replaces, created, updated, \
         star_start_date, star_end_date, star_lifetime_secs, star_lifetime_adjust_secs, \
         star_allow_cert_get, star_canceled_at, star_csr_der, profile, ca_id \
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

    let rows = qb.build_query_as::<OrderRow>().fetch_all(executor).await?;
    Ok(rows)
}

/// List all authorization IDs belonging to an order.
pub async fn list_authz_ids(
    executor: impl sqlx::Executor<'_, Database = sqlx::Any>,
    order_id: &str,
) -> Result<Vec<String>, AcmeError> {
    let ids: Vec<(String,)> = sqlx::query_as("SELECT id FROM authorizations WHERE order_id = ?")
        .bind(order_id)
        .fetch_all(executor)
        .await?;
    Ok(ids.into_iter().map(|(id,)| id).collect())
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
