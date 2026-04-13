use sqlx::SqliteConnection;

use crate::db::schema::{AuthorizationRow, ChallengeRow};
use crate::error::AcmeError;

pub async fn insert(conn: &mut SqliteConnection, row: AuthorizationRow) -> Result<(), AcmeError> {
    sqlx::query(
        "INSERT INTO authorizations
         (id, order_id, account_id, status, identifier, expires, wildcard,
          subdomain_auth_allowed, created, updated)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
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
    .execute(&mut *conn)
    .await
    .map_err(|e| AcmeError::Database(e.to_string()))?;
    Ok(())
}

pub async fn get_by_id(
    conn: &mut SqliteConnection,
    id: &str,
) -> Result<Option<AuthorizationRow>, AcmeError> {
    let row = sqlx::query_as::<_, AuthorizationRow>(
        "SELECT id, order_id, account_id, status, identifier, expires, wildcard,
                subdomain_auth_allowed, created, updated
         FROM authorizations WHERE id = ?1",
    )
    .bind(id)
    .fetch_optional(&mut *conn)
    .await
    .map_err(|e| AcmeError::Database(e.to_string()))?;
    Ok(row)
}

pub async fn list_by_order(
    conn: &mut SqliteConnection,
    order_id: &str,
) -> Result<Vec<AuthorizationRow>, AcmeError> {
    let rows = sqlx::query_as::<_, AuthorizationRow>(
        "SELECT id, order_id, account_id, status, identifier, expires, wildcard,
                subdomain_auth_allowed, created, updated
         FROM authorizations WHERE order_id = ?1",
    )
    .bind(order_id)
    .fetch_all(&mut *conn)
    .await
    .map_err(|e| AcmeError::Database(e.to_string()))?;
    Ok(rows)
}

/// Fetch an authorization and all its challenges in two sequential queries.
///
/// Returns `None` if no authorization with `authz_id` exists.
pub async fn get_with_challenges(
    conn: &mut SqliteConnection,
    authz_id: &str,
) -> Result<Option<(AuthorizationRow, Vec<ChallengeRow>)>, AcmeError> {
    let authz = sqlx::query_as::<_, AuthorizationRow>(
        "SELECT id, order_id, account_id, status, identifier, expires, wildcard,
                subdomain_auth_allowed, created, updated
         FROM authorizations WHERE id = ?1",
    )
    .bind(authz_id)
    .fetch_optional(&mut *conn)
    .await
    .map_err(|e| AcmeError::Database(e.to_string()))?;

    let authz = match authz {
        Some(a) => a,
        None => return Ok(None),
    };

    let challenges = sqlx::query_as::<_, ChallengeRow>(
        "SELECT id, authz_id, type, status, token, validated, error, created, updated
         FROM challenges WHERE authz_id = ?1",
    )
    .bind(authz_id)
    .fetch_all(&mut *conn)
    .await
    .map_err(|e| AcmeError::Database(e.to_string()))?;

    Ok(Some((authz, challenges)))
}

/// Fetch an authorization with its challenges and atomically mark the specified
/// challenge type as "processing".
///
/// Returns `None` if no authorization with `authz_id` exists. If the challenge
/// matching `chall_type` is already "processing" or "valid", the UPDATE is a
/// no-op; the caller inspects the returned `ChallengeRow.status` to decide
/// whether to proceed or return the current state.
pub async fn get_with_challenges_mark_processing(
    conn: &mut SqliteConnection,
    authz_id: &str,
    chall_type: &str,
    now: i64,
) -> Result<Option<(AuthorizationRow, Vec<ChallengeRow>)>, AcmeError> {
    // Fetch authorization.
    let authz = sqlx::query_as::<_, AuthorizationRow>(
        "SELECT id, order_id, account_id, status, identifier, expires, wildcard,
                subdomain_auth_allowed, created, updated
         FROM authorizations WHERE id = ?1",
    )
    .bind(authz_id)
    .fetch_optional(&mut *conn)
    .await
    .map_err(|e| AcmeError::Database(e.to_string()))?;

    let authz = match authz {
        Some(a) => a,
        None => return Ok(None),
    };

    // Fetch all challenges for this authorization.
    let challenges = sqlx::query_as::<_, ChallengeRow>(
        "SELECT id, authz_id, type, status, token, validated, error, created, updated
         FROM challenges WHERE authz_id = ?1",
    )
    .bind(authz_id)
    .fetch_all(&mut *conn)
    .await
    .map_err(|e| AcmeError::Database(e.to_string()))?;

    // Atomically mark the target challenge "processing". Only fires when the
    // challenge is still "pending"; a no-op for already-active challenges.
    sqlx::query(
        "UPDATE challenges SET status = 'processing', updated = ?1
         WHERE authz_id = ?2 AND type = ?3 AND status = 'pending'",
    )
    .bind(now)
    .bind(authz_id)
    .bind(chall_type)
    .execute(&mut *conn)
    .await
    .map_err(|e| AcmeError::Database(e.to_string()))?;

    Ok(Some((authz, challenges)))
}

/// Find a valid, unexpired authorization for a given account and identifier JSON string.
///
/// Returns the first matching row (status `pending` or `valid`, not yet expired),
/// or `None` if no such authorization exists. Used by `new-authz` to deduplicate.
pub async fn find_valid_by_account_and_identifier(
    conn: &mut SqliteConnection,
    account_id: &str,
    identifier_json: &str,
    now: i64,
) -> Result<Option<AuthorizationRow>, AcmeError> {
    let row = sqlx::query_as::<_, AuthorizationRow>(
        "SELECT id, order_id, account_id, status, identifier, expires, wildcard,
                subdomain_auth_allowed, created, updated
         FROM authorizations
         WHERE account_id = ?1
           AND identifier = ?2
           AND status IN ('pending', 'valid')
           AND (expires IS NULL OR expires > ?3)
         LIMIT 1",
    )
    .bind(account_id)
    .bind(identifier_json)
    .bind(now)
    .fetch_optional(&mut *conn)
    .await
    .map_err(|e| AcmeError::Database(e.to_string()))?;
    Ok(row)
}

pub async fn update_status(
    conn: &mut SqliteConnection,
    id: &str,
    status: &str,
    now: i64,
) -> Result<(), AcmeError> {
    sqlx::query(
        "UPDATE authorizations SET status = ?1, updated = ?2 WHERE id = ?3",
    )
    .bind(status)
    .bind(now)
    .bind(id)
    .execute(&mut *conn)
    .await
    .map_err(|e| AcmeError::Database(e.to_string()))?;
    Ok(())
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

    async fn insert_parents(db: &crate::db::Db, account_id: &str, order_id: &str) {
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

        crate::db::orders::insert(
            conn!(db),
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
        insert(conn!(db), sample_authz("authz-1", "order-1", "acct-1"))
            .await
            .unwrap();

        let row = get_by_id(conn!(db), "authz-1").await.unwrap().unwrap();
        assert_eq!(row.id, "authz-1");
        assert_eq!(row.status, "pending");
        assert!(!row.wildcard);
    }

    #[tokio::test]
    async fn get_by_id_missing_returns_none() {
        let db = open_db().await;
        let result = get_by_id(conn!(db), "nonexistent").await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn list_by_order_returns_authzs() {
        let db = open_db().await;
        insert_parents(&db, "acct-2", "order-2").await;
        insert(conn!(db), sample_authz("authz-2a", "order-2", "acct-2"))
            .await
            .unwrap();
        insert(
            conn!(db),
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

        let authzs = list_by_order(conn!(db), "order-2").await.unwrap();
        assert_eq!(authzs.len(), 2);
        let ids: Vec<_> = authzs.iter().map(|a| a.id.as_str()).collect();
        assert!(ids.contains(&"authz-2a"));
        assert!(ids.contains(&"authz-2b"));
    }

    #[tokio::test]
    async fn list_by_order_empty_for_no_authzs() {
        let db = open_db().await;
        insert_parents(&db, "acct-3", "order-3").await;

        let authzs = list_by_order(conn!(db), "order-3").await.unwrap();
        assert!(authzs.is_empty());
    }

    #[tokio::test]
    async fn update_status_changes_status() {
        let db = open_db().await;
        insert_parents(&db, "acct-4", "order-4").await;
        insert(conn!(db), sample_authz("authz-4", "order-4", "acct-4"))
            .await
            .unwrap();

        update_status(conn!(db), "authz-4", "valid", 1_700_000_001)
            .await
            .unwrap();

        let row = get_by_id(conn!(db), "authz-4").await.unwrap().unwrap();
        assert_eq!(row.status, "valid");
        assert_eq!(row.updated, 1_700_000_001);
    }

    #[tokio::test]
    async fn db_error_paths_no_table() {
        use sqlx::Connection as _;
        let mut raw: sqlx::SqliteConnection =
            sqlx::SqliteConnection::connect("sqlite::memory:").await.unwrap();
        let row = sample_authz("err-authz", "err-order", "err-acct");
        assert!(insert(&mut raw, row).await.is_err());
        assert!(get_by_id(&mut raw, "any").await.is_err());
        assert!(list_by_order(&mut raw, "any").await.is_err());
        assert!(update_status(&mut raw, "any", "valid", 0).await.is_err());
    }
}
