use sqlx::SqliteConnection;

use crate::db::schema::OrderRow;
use crate::error::AcmeError;

pub async fn insert(conn: &mut SqliteConnection, row: OrderRow) -> Result<(), AcmeError> {
    sqlx::query(
        "INSERT INTO orders (id, account_id, status, expires, identifiers,
         not_before, not_after, error, certificate_id, replaces, created, updated,
         star_start_date, star_end_date, star_lifetime_secs, star_lifetime_adjust_secs,
         star_allow_cert_get, star_canceled_at, star_csr_der, profile)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12,
                 ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20)",
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
    .execute(&mut *conn)
    .await
    .map_err(|e| AcmeError::Database(e.to_string()))?;
    Ok(())
}

/// Cancel a STAR order by setting star_canceled_at to the current timestamp.
pub async fn cancel_star(
    conn: &mut SqliteConnection,
    id: &str,
    now: i64,
) -> Result<(), AcmeError> {
    sqlx::query(
        "UPDATE orders SET star_canceled_at = ?1, updated = ?2 WHERE id = ?3",
    )
    .bind(now)
    .bind(now)
    .bind(id)
    .execute(&mut *conn)
    .await
    .map_err(|e| AcmeError::Database(e.to_string()))?;
    Ok(())
}

/// List all active STAR orders (star_end_date set, not canceled, status = 'valid').
pub async fn list_active_star(conn: &mut SqliteConnection) -> Result<Vec<OrderRow>, AcmeError> {
    let rows = sqlx::query_as::<_, OrderRow>(
        "SELECT id, account_id, status, expires, identifiers,
         not_before, not_after, error, certificate_id, replaces, created, updated,
         star_start_date, star_end_date, star_lifetime_secs, star_lifetime_adjust_secs,
         star_allow_cert_get, star_canceled_at, star_csr_der, profile
         FROM orders
         WHERE star_end_date IS NOT NULL AND star_canceled_at IS NULL AND status = 'valid'",
    )
    .fetch_all(&mut *conn)
    .await
    .map_err(|e| AcmeError::Database(e.to_string()))?;
    Ok(rows)
}

/// Store the CSR DER on an order (set during finalize for STAR orders).
pub async fn set_star_csr(
    conn: &mut SqliteConnection,
    id: &str,
    csr_der: Vec<u8>,
) -> Result<(), AcmeError> {
    sqlx::query("UPDATE orders SET star_csr_der = ?1 WHERE id = ?2")
        .bind(&csr_der)
        .bind(id)
        .execute(&mut *conn)
        .await
        .map_err(|e| AcmeError::Database(e.to_string()))?;
    Ok(())
}

pub async fn get_by_id(
    conn: &mut SqliteConnection,
    id: &str,
) -> Result<Option<OrderRow>, AcmeError> {
    let row = sqlx::query_as::<_, OrderRow>(
        "SELECT id, account_id, status, expires, identifiers,
         not_before, not_after, error, certificate_id, replaces, created, updated,
         star_start_date, star_end_date, star_lifetime_secs, star_lifetime_adjust_secs,
         star_allow_cert_get, star_canceled_at, star_csr_der, profile
         FROM orders WHERE id = ?1",
    )
    .bind(id)
    .fetch_optional(&mut *conn)
    .await
    .map_err(|e| AcmeError::Database(e.to_string()))?;
    Ok(row)
}

pub async fn update_status(
    conn: &mut SqliteConnection,
    id: &str,
    status: &str,
    error: Option<String>,
    now: i64,
) -> Result<(), AcmeError> {
    sqlx::query("UPDATE orders SET status = ?1, error = ?2, updated = ?3 WHERE id = ?4")
        .bind(status)
        .bind(&error)
        .bind(now)
        .bind(id)
        .execute(&mut *conn)
        .await
        .map_err(|e| AcmeError::Database(e.to_string()))?;
    Ok(())
}

pub async fn set_certificate(
    conn: &mut SqliteConnection,
    id: &str,
    certificate_id: &str,
    now: i64,
) -> Result<(), AcmeError> {
    sqlx::query(
        "UPDATE orders SET status = 'valid', certificate_id = ?1, updated = ?2 WHERE id = ?3",
    )
    .bind(certificate_id)
    .bind(now)
    .bind(id)
    .execute(&mut *conn)
    .await
    .map_err(|e| AcmeError::Database(e.to_string()))?;
    Ok(())
}

/// Fetch an order and its authorization IDs in two sequential queries on the
/// same connection.
///
/// Returns `None` if no order with `order_id` exists.
pub async fn get_with_authz_ids(
    conn: &mut SqliteConnection,
    order_id: &str,
) -> Result<Option<(OrderRow, Vec<String>)>, AcmeError> {
    let order = sqlx::query_as::<_, OrderRow>(
        "SELECT id, account_id, status, expires, identifiers,
         not_before, not_after, error, certificate_id, replaces, created, updated,
         star_start_date, star_end_date, star_lifetime_secs, star_lifetime_adjust_secs,
         star_allow_cert_get, star_canceled_at, star_csr_der, profile
         FROM orders WHERE id = ?1",
    )
    .bind(order_id)
    .fetch_optional(&mut *conn)
    .await
    .map_err(|e| AcmeError::Database(e.to_string()))?;

    let order = match order {
        Some(o) => o,
        None => return Ok(None),
    };

    let authz_ids: Vec<(String,)> =
        sqlx::query_as("SELECT id FROM authorizations WHERE order_id = ?1")
            .bind(order_id)
            .fetch_all(&mut *conn)
            .await
            .map_err(|e| AcmeError::Database(e.to_string()))?;

    Ok(Some((order, authz_ids.into_iter().map(|(id,)| id).collect())))
}

/// List all authorization IDs belonging to an order.
pub async fn list_authz_ids(
    conn: &mut SqliteConnection,
    order_id: &str,
) -> Result<Vec<String>, AcmeError> {
    let ids: Vec<(String,)> =
        sqlx::query_as("SELECT id FROM authorizations WHERE order_id = ?1")
            .bind(order_id)
            .fetch_all(&mut *conn)
            .await
            .map_err(|e| AcmeError::Database(e.to_string()))?;
    Ok(ids.into_iter().map(|(id,)| id).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::db::schema::AccountRow;

    async fn open_db() -> crate::db::Db {
        crate::db::open(":memory:").await.unwrap()
    }

    macro_rules! conn {
        ($db:expr) => {
            &mut *$db.acquire().await.unwrap()
        };
    }

    async fn insert_account(db: &crate::db::Db, account_id: &str) {
        crate::db::accounts::insert(
            conn!(db),
            AccountRow {
                id: account_id.to_string(),
                status: "valid".to_string(),
                contact: None,
                public_key: vec![0u8; 4],
                jwk_thumbprint: format!("thumb-{account_id}"),
                created: 1_700_000_000,
                updated: 1_700_000_000,
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
            star_allow_cert_get: false,
            star_canceled_at: None,
            star_csr_der: None,
            profile: None,
        }
    }

    #[tokio::test]
    async fn insert_and_get_by_id() {
        let db = open_db().await;
        insert_account(&db, "acct-1").await;
        insert(conn!(db), sample_order("order-1", "acct-1"))
            .await
            .unwrap();

        let row = get_by_id(conn!(db), "order-1").await.unwrap().unwrap();
        assert_eq!(row.id, "order-1");
        assert_eq!(row.status, "pending");
    }

    #[tokio::test]
    async fn get_by_id_missing_returns_none() {
        let db = open_db().await;
        let result = get_by_id(conn!(db), "nonexistent").await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn update_status_changes_status() {
        let db = open_db().await;
        insert_account(&db, "acct-2").await;
        insert(conn!(db), sample_order("order-2", "acct-2"))
            .await
            .unwrap();

        update_status(conn!(db), "order-2", "ready", None, 1_700_000_001)
            .await
            .unwrap();

        let row = get_by_id(conn!(db), "order-2").await.unwrap().unwrap();
        assert_eq!(row.status, "ready");
        assert!(row.error.is_none());
    }

    #[tokio::test]
    async fn update_status_with_error() {
        let db = open_db().await;
        insert_account(&db, "acct-3").await;
        insert(conn!(db), sample_order("order-3", "acct-3"))
            .await
            .unwrap();

        update_status(
            conn!(db),
            "order-3",
            "invalid",
            Some("{\"type\":\"error\"}".to_string()),
            1_700_000_001,
        )
        .await
        .unwrap();

        let row = get_by_id(conn!(db), "order-3").await.unwrap().unwrap();
        assert_eq!(row.status, "invalid");
        assert!(row.error.is_some());
    }

    #[tokio::test]
    async fn set_certificate_marks_valid() {
        let db = open_db().await;
        insert_account(&db, "acct-4").await;
        insert(conn!(db), sample_order("order-4", "acct-4"))
            .await
            .unwrap();

        set_certificate(conn!(db), "order-4", "cert-xyz", 1_700_000_001)
            .await
            .unwrap();

        let row = get_by_id(conn!(db), "order-4").await.unwrap().unwrap();
        assert_eq!(row.status, "valid");
        assert_eq!(row.certificate_id, Some("cert-xyz".to_string()));
    }

    #[tokio::test]
    async fn list_authz_ids_empty_for_no_authzs() {
        let db = open_db().await;
        insert_account(&db, "acct-5").await;
        insert(conn!(db), sample_order("order-5", "acct-5"))
            .await
            .unwrap();

        let ids = list_authz_ids(conn!(db), "order-5").await.unwrap();
        assert!(ids.is_empty());
    }

    #[tokio::test]
    async fn list_authz_ids_returns_authz_ids() {
        use crate::db::schema::AuthorizationRow;

        let db = open_db().await;
        insert_account(&db, "acct-6").await;
        insert(conn!(db), sample_order("order-6", "acct-6"))
            .await
            .unwrap();

        crate::db::authz::insert(
            conn!(db),
            AuthorizationRow {
                id: "authz-a".to_string(),
                order_id: "order-6".to_string(),
                account_id: "acct-6".to_string(),
                status: "pending".to_string(),
                identifier: "{\"type\":\"dns\",\"value\":\"example.com\"}".to_string(),
                expires: None,
                wildcard: false,
                subdomain_auth_allowed: false,
                created: 1_700_000_000,
                updated: 1_700_000_000,
            },
        )
        .await
        .unwrap();

        let ids = list_authz_ids(conn!(db), "order-6").await.unwrap();
        assert_eq!(ids, vec!["authz-a"]);
    }

    #[tokio::test]
    async fn db_error_paths_no_table() {
        use sqlx::Connection as _;
        let mut raw: sqlx::SqliteConnection =
            sqlx::SqliteConnection::connect("sqlite::memory:").await.unwrap();
        assert!(insert(&mut raw, sample_order("err-order", "err-acct"))
            .await
            .is_err());
        assert!(get_by_id(&mut raw, "any").await.is_err());
        assert!(update_status(&mut raw, "any", "invalid", None, 0)
            .await
            .is_err());
        assert!(set_certificate(&mut raw, "any", "cert-id", 0).await.is_err());
        assert!(list_authz_ids(&mut raw, "any").await.is_err());
    }

    #[tokio::test]
    async fn replaces_round_trip_some() {
        let db = open_db().await;
        insert_account(&db, "acct-rpl").await;
        let mut order = sample_order("order-rpl", "acct-rpl");
        order.replaces = Some("akiABC.serialXYZ".to_string());
        insert(conn!(db), order).await.unwrap();

        let row = get_by_id(conn!(db), "order-rpl").await.unwrap().unwrap();
        assert_eq!(row.replaces.as_deref(), Some("akiABC.serialXYZ"));
    }

    #[tokio::test]
    async fn replaces_round_trip_none() {
        let db = open_db().await;
        insert_account(&db, "acct-nrpl").await;
        insert(conn!(db), sample_order("order-nrpl", "acct-nrpl"))
            .await
            .unwrap();

        let row = get_by_id(conn!(db), "order-nrpl").await.unwrap().unwrap();
        assert!(row.replaces.is_none());
    }
}
