use crate::db::schema::{AuthorizationRow, ChallengeRow};
use crate::error::AcmeError;

pub async fn insert(
    executor: impl sqlx::Executor<'_, Database = sqlx::Any>,
    row: AuthorizationRow,
) -> Result<(), AcmeError> {
    sqlx::query(
        "INSERT INTO authorizations
         (id, order_id, account_id, status, identifier, expires, wildcard,
          subdomain_auth_allowed, created, updated, ca_id)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&row.id)
    .bind(&row.order_id)
    .bind(&row.account_id)
    .bind(&row.status)
    .bind(&row.identifier)
    .bind(row.expires)
    .bind(row.wildcard)
    .bind(row.subdomain_auth_allowed)
    .bind(row.created)
    .bind(row.updated)
    .bind(&row.ca_id)
    .execute(executor)
    .await?;
    Ok(())
}

pub async fn get_by_id(
    executor: impl sqlx::Executor<'_, Database = sqlx::Any>,
    id: &str,
) -> Result<Option<AuthorizationRow>, AcmeError> {
    let row = sqlx::query_as::<_, AuthorizationRow>(
        "SELECT id, order_id, account_id, status, identifier, expires, wildcard,
                subdomain_auth_allowed, created, updated, ca_id
         FROM authorizations WHERE id = ?",
    )
    .bind(id)
    .fetch_optional(executor)
    .await?;
    Ok(row)
}

pub async fn list_by_order(
    executor: impl sqlx::Executor<'_, Database = sqlx::Any>,
    order_id: &str,
) -> Result<Vec<AuthorizationRow>, AcmeError> {
    let rows = sqlx::query_as::<_, AuthorizationRow>(
        "SELECT id, order_id, account_id, status, identifier, expires, wildcard,
                subdomain_auth_allowed, created, updated, ca_id
         FROM authorizations WHERE order_id = ?",
    )
    .bind(order_id)
    .fetch_all(executor)
    .await?;
    Ok(rows)
}

/// Fetch an authorization and all its challenges in a single JOIN round-trip.
///
/// Returns `None` if no authorization with `authz_id` exists.
///
/// Accepts `impl Executor` (single query), so callers can pass either `&pool`
/// or `&mut *tx` — enabling transaction-scoped usage without an extra
/// `impl Executor` bound on the two-query wrapper that existed before.
pub async fn get_with_challenges(
    executor: impl sqlx::Executor<'_, Database = sqlx::Any>,
    authz_id: &str,
) -> Result<Option<(AuthorizationRow, Vec<ChallengeRow>)>, AcmeError> {
    #[derive(sqlx::FromRow)]
    struct AuthzChallRow {
        // Authorization columns (aliased to avoid conflicts with challenge columns)
        authz_id: String,
        order_id: Option<String>, // nullable for pre-authz (new-authz endpoint)
        account_id: String,
        authz_status: String,
        identifier: String,
        expires: Option<i64>,
        wildcard: i64,
        subdomain_auth_allowed: i64,
        authz_created: i64,
        authz_updated: i64,
        authz_ca_id: String,
        // Challenge columns (all nullable: LEFT JOIN returns NULL when no challenges)
        chall_id: Option<String>,
        chall_type: Option<String>,
        chall_status: Option<String>,
        token: Option<String>,
        validated: Option<i64>,
        error: Option<String>,
        chall_created: Option<i64>,
        chall_updated: Option<i64>,
    }

    let rows = sqlx::query_as::<_, AuthzChallRow>(
        "SELECT
             a.id          AS authz_id,
             a.order_id,
             a.account_id,
             a.status      AS authz_status,
             a.identifier,
             a.expires,
             a.wildcard,
             a.subdomain_auth_allowed,
             a.created     AS authz_created,
             a.updated     AS authz_updated,
             a.ca_id       AS authz_ca_id,
             c.id          AS chall_id,
             c.type        AS chall_type,
             c.status      AS chall_status,
             c.token,
             c.validated,
             c.error,
             c.created     AS chall_created,
             c.updated     AS chall_updated
         FROM authorizations a
         LEFT JOIN challenges c ON c.authz_id = a.id
         WHERE a.id = ?
         ORDER BY c.id",
    )
    .bind(authz_id)
    .fetch_all(executor)
    .await?;

    if rows.is_empty() {
        return Ok(None);
    }

    let first = &rows[0];
    let authz = AuthorizationRow {
        id: first.authz_id.clone(),
        order_id: first.order_id.clone().unwrap_or_default(),
        account_id: first.account_id.clone(),
        status: first.authz_status.clone(),
        identifier: first.identifier.clone(),
        expires: first.expires,
        wildcard: first.wildcard,
        subdomain_auth_allowed: first.subdomain_auth_allowed,
        created: first.authz_created,
        updated: first.authz_updated,
        ca_id: first.authz_ca_id.clone(),
    };

    let challenges: Vec<ChallengeRow> = rows
        .into_iter()
        .filter_map(|r| {
            Some(ChallengeRow {
                id: r.chall_id?,
                authz_id: authz.id.clone(),
                r#type: r.chall_type?,
                status: r.chall_status?,
                token: r.token?,
                validated: r.validated,
                error: r.error,
                created: r.chall_created?,
                updated: r.chall_updated?,
            })
        })
        .collect();

    Ok(Some((authz, challenges)))
}

/// Find a valid, unexpired authorization for a given account and identifier JSON string.
///
/// Returns the first matching row (status `pending` or `valid`, not yet expired),
/// or `None` if no such authorization exists. Used by `new-authz` to deduplicate.
pub async fn find_valid_by_account_and_identifier(
    executor: impl sqlx::Executor<'_, Database = sqlx::Any>,
    account_id: &str,
    identifier_json: &str,
    ca_id: &str,
    now: i64,
) -> Result<Option<AuthorizationRow>, AcmeError> {
    let row = sqlx::query_as::<_, AuthorizationRow>(
        "SELECT id, order_id, account_id, status, identifier, expires, wildcard,
                subdomain_auth_allowed, created, updated, ca_id
         FROM authorizations
         WHERE account_id = ?
           AND identifier = ?
           AND (ca_id = ? OR ca_id = 'default' OR ca_id = '')
           AND status IN ('pending', 'valid')
           AND (expires IS NULL OR expires > ?)
         LIMIT 1",
    )
    .bind(account_id)
    .bind(identifier_json)
    .bind(ca_id)
    .bind(now)
    .fetch_optional(executor)
    .await?;
    Ok(row)
}

pub async fn update_status(
    executor: impl sqlx::Executor<'_, Database = sqlx::Any>,
    id: &str,
    status: &str,
    now: i64,
) -> Result<(), AcmeError> {
    sqlx::query("UPDATE authorizations SET status = ?, updated = ? WHERE id = ?")
        .bind(status)
        .bind(now)
        .bind(id)
        .execute(executor)
        .await?;
    Ok(())
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

    async fn insert_parents(db: &Db, account_id: &str, order_id: &str) {
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

        crate::db::orders::insert(
            db,
            OrderRow {
                id: order_id.to_string(),
                account_id: account_id.to_string(),
                status: "pending".to_string(),
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
            },
        )
        .await
        .unwrap();
    }

    fn sample_authz(id: &str, order_id: &str, account_id: &str) -> AuthorizationRow {
        AuthorizationRow {
            id: id.to_string(),
            order_id: order_id.to_string(),
            account_id: account_id.to_string(),
            status: "pending".to_string(),
            identifier: "{\"type\":\"dns\",\"value\":\"example.com\"}".to_string(),
            expires: None,
            wildcard: 0,
            subdomain_auth_allowed: 0,
            created: 1_700_000_000,
            updated: 1_700_000_000,
            ca_id: "default".to_string(),
        }
    }

    #[tokio::test]
    async fn insert_and_get_by_id() {
        let db = open_db().await;
        insert_parents(&db, "acct-1", "order-1").await;
        insert(&db, sample_authz("authz-1", "order-1", "acct-1"))
            .await
            .unwrap();

        let row = get_by_id(&db, "authz-1").await.unwrap().unwrap();
        assert_eq!(row.id, "authz-1");
        assert_eq!(row.status, "pending");
        assert_eq!(row.wildcard, 0);
    }

    #[tokio::test]
    async fn get_by_id_missing_returns_none() {
        let db = open_db().await;
        let result = get_by_id(&db, "nonexistent").await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn list_by_order_returns_authzs() {
        let db = open_db().await;
        insert_parents(&db, "acct-2", "order-2").await;
        insert(&db, sample_authz("authz-2a", "order-2", "acct-2"))
            .await
            .unwrap();
        insert(
            &db,
            AuthorizationRow {
                id: "authz-2b".to_string(),
                order_id: "order-2".to_string(),
                account_id: "acct-2".to_string(),
                status: "valid".to_string(),
                identifier: "{\"type\":\"dns\",\"value\":\"other.com\"}".to_string(),
                expires: None,
                wildcard: 1,
                subdomain_auth_allowed: 0,
                created: 1_700_000_000,
                updated: 1_700_000_000,
                ca_id: "default".to_string(),
            },
        )
        .await
        .unwrap();

        let authzs = list_by_order(&db, "order-2").await.unwrap();
        assert_eq!(authzs.len(), 2);
        let ids: Vec<_> = authzs.iter().map(|a| a.id.as_str()).collect();
        assert!(ids.contains(&"authz-2a"));
        assert!(ids.contains(&"authz-2b"));
    }

    #[tokio::test]
    async fn list_by_order_empty_for_no_authzs() {
        let db = open_db().await;
        insert_parents(&db, "acct-3", "order-3").await;

        let authzs = list_by_order(&db, "order-3").await.unwrap();
        assert!(authzs.is_empty());
    }

    #[tokio::test]
    async fn update_status_changes_status() {
        let db = open_db().await;
        insert_parents(&db, "acct-4", "order-4").await;
        insert(&db, sample_authz("authz-4", "order-4", "acct-4"))
            .await
            .unwrap();

        update_status(&db, "authz-4", "valid", 1_700_000_001)
            .await
            .unwrap();

        let row = get_by_id(&db, "authz-4").await.unwrap().unwrap();
        assert_eq!(row.status, "valid");
        assert_eq!(row.updated, 1_700_000_001);
    }

    #[tokio::test]
    async fn db_error_paths_no_table() {
        crate::db::install_drivers();
        let raw: Db = sqlx::any::AnyPoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        let row = sample_authz("err-authz", "err-order", "err-acct");
        assert!(insert(&raw, row).await.is_err());
        assert!(get_by_id(&raw, "any").await.is_err());
        assert!(list_by_order(&raw, "any").await.is_err());
        assert!(update_status(&raw, "any", "valid", 0).await.is_err());
    }
}
