use crate::db::schema::{AuthorizationRow, ChallengeRow};
use crate::db::Db;
use crate::error::AcmeError;

pub async fn insert(db: &Db, row: AuthorizationRow) -> Result<(), AcmeError> {
    sqlx::query(
        "INSERT INTO authorizations
         (id, order_id, account_id, status, identifier, expires, wildcard,
          subdomain_auth_allowed, created, updated)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
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
    .execute(db)
    .await?;
    Ok(())
}

pub async fn get_by_id(db: &Db, id: &str) -> Result<Option<AuthorizationRow>, AcmeError> {
    let row = sqlx::query_as::<_, AuthorizationRow>(
        "SELECT id, order_id, account_id, status, identifier, expires, wildcard,
                subdomain_auth_allowed, created, updated
         FROM authorizations WHERE id = ?",
    )
    .bind(id)
    .fetch_optional(db)
    .await?;
    Ok(row)
}

pub async fn list_by_order(
    db: &Db,
    order_id: &str,
) -> Result<Vec<AuthorizationRow>, AcmeError> {
    let rows = sqlx::query_as::<_, AuthorizationRow>(
        "SELECT id, order_id, account_id, status, identifier, expires, wildcard,
                subdomain_auth_allowed, created, updated
         FROM authorizations WHERE order_id = ?",
    )
    .bind(order_id)
    .fetch_all(db)
    .await?;
    Ok(rows)
}

/// Fetch an authorization and all its challenges.
///
/// Returns `None` if no authorization with `authz_id` exists.
pub async fn get_with_challenges(
    db: &Db,
    authz_id: &str,
) -> Result<Option<(AuthorizationRow, Vec<ChallengeRow>)>, AcmeError> {
    let authz = match sqlx::query_as::<_, AuthorizationRow>(
        "SELECT id, order_id, account_id, status, identifier, expires, wildcard,
                subdomain_auth_allowed, created, updated
         FROM authorizations WHERE id = ?",
    )
    .bind(authz_id)
    .fetch_optional(db)
    .await?
    {
        Some(a) => a,
        None => return Ok(None),
    };

    let challenges = sqlx::query_as::<_, ChallengeRow>(
        "SELECT id, authz_id, type, status, token, validated, error, created, updated
         FROM challenges WHERE authz_id = ?",
    )
    .bind(authz_id)
    .fetch_all(db)
    .await?;

    Ok(Some((authz, challenges)))
}

/// Fetch an authorization with its challenges and atomically mark the specified
/// challenge type as "processing".
///
/// Returns `None` if no authorization with `authz_id` exists.
pub async fn get_with_challenges_mark_processing(
    db: &Db,
    authz_id: &str,
    chall_type: &str,
    now: i64,
) -> Result<Option<(AuthorizationRow, Vec<ChallengeRow>)>, AcmeError> {
    let mut tx = db.begin().await?;

    // Fetch authorization.
    let authz = match sqlx::query_as::<_, AuthorizationRow>(
        "SELECT id, order_id, account_id, status, identifier, expires, wildcard,
                subdomain_auth_allowed, created, updated
         FROM authorizations WHERE id = ?",
    )
    .bind(authz_id)
    .fetch_optional(&mut *tx)
    .await?
    {
        Some(a) => a,
        None => {
            tx.rollback().await?;
            return Ok(None);
        }
    };

    // Fetch all challenges for this authorization.
    let challenges = sqlx::query_as::<_, ChallengeRow>(
        "SELECT id, authz_id, type, status, token, validated, error, created, updated
         FROM challenges WHERE authz_id = ?",
    )
    .bind(authz_id)
    .fetch_all(&mut *tx)
    .await?;

    // Atomically mark the target challenge "processing". Only fires when the
    // challenge is still "pending"; a no-op for already-active challenges.
    sqlx::query(
        "UPDATE challenges SET status = 'processing', updated = ?
         WHERE authz_id = ? AND type = ? AND status = 'pending'",
    )
    .bind(now)
    .bind(authz_id)
    .bind(chall_type)
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;
    Ok(Some((authz, challenges)))
}

/// Find a valid, unexpired authorization for a given account and identifier JSON string.
///
/// Returns the first matching row (status `pending` or `valid`, not yet expired),
/// or `None` if no such authorization exists. Used by `new-authz` to deduplicate.
pub async fn find_valid_by_account_and_identifier(
    db: &Db,
    account_id: &str,
    identifier_json: &str,
    now: i64,
) -> Result<Option<AuthorizationRow>, AcmeError> {
    let row = sqlx::query_as::<_, AuthorizationRow>(
        "SELECT id, order_id, account_id, status, identifier, expires, wildcard,
                subdomain_auth_allowed, created, updated
         FROM authorizations
         WHERE account_id = ?
           AND identifier = ?
           AND status IN ('pending', 'valid')
           AND (expires IS NULL OR expires > ?)
         LIMIT 1",
    )
    .bind(account_id)
    .bind(identifier_json)
    .bind(now)
    .fetch_optional(db)
    .await?;
    Ok(row)
}

pub async fn update_status(db: &Db, id: &str, status: &str, now: i64) -> Result<(), AcmeError> {
    sqlx::query("UPDATE authorizations SET status = ?, updated = ? WHERE id = ?")
        .bind(status)
        .bind(now)
        .bind(id)
        .execute(db)
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::db::schema::{AccountRow, OrderRow};

    async fn open_db() -> Db {
        crate::db::open(":memory:").await.unwrap()
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
                star_allow_cert_get: false,
                star_canceled_at: None,
                star_csr_der: None,
                profile: None,
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
            wildcard: false,
            subdomain_auth_allowed: false,
            created: 1_700_000_000,
            updated: 1_700_000_000,
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
        assert!(!row.wildcard);
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
                wildcard: true,
                subdomain_auth_allowed: false,
                created: 1_700_000_000,
                updated: 1_700_000_000,
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
        use sqlx::sqlite::SqliteConnectOptions;
        use sqlx::sqlite::SqlitePoolOptions;

        let raw: Db = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(SqliteConnectOptions::new().in_memory(true))
            .await
            .unwrap();
        let row = sample_authz("err-authz", "err-order", "err-acct");
        assert!(insert(&raw, row).await.is_err());
        assert!(get_by_id(&raw, "any").await.is_err());
        assert!(list_by_order(&raw, "any").await.is_err());
        assert!(update_status(&raw, "any", "valid", 0).await.is_err());
    }
}
