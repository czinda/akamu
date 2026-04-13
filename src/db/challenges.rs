use sqlx::SqliteConnection;

use crate::db::schema::ChallengeRow;
use crate::error::AcmeError;

pub async fn insert(conn: &mut SqliteConnection, row: ChallengeRow) -> Result<(), AcmeError> {
    sqlx::query(
        "INSERT INTO challenges (id, authz_id, type, status, token, validated, error, created, updated)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
    )
    .bind(&row.id)
    .bind(&row.authz_id)
    .bind(&row.r#type)
    .bind(&row.status)
    .bind(&row.token)
    .bind(row.validated)
    .bind(&row.error)
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
) -> Result<Option<ChallengeRow>, AcmeError> {
    let row = sqlx::query_as::<_, ChallengeRow>(
        "SELECT id, authz_id, type, status, token, validated, error, created, updated
         FROM challenges WHERE id = ?1",
    )
    .bind(id)
    .fetch_optional(&mut *conn)
    .await
    .map_err(|e| AcmeError::Database(e.to_string()))?;
    Ok(row)
}

pub async fn list_by_authz(
    conn: &mut SqliteConnection,
    authz_id: &str,
) -> Result<Vec<ChallengeRow>, AcmeError> {
    let rows = sqlx::query_as::<_, ChallengeRow>(
        "SELECT id, authz_id, type, status, token, validated, error, created, updated
         FROM challenges WHERE authz_id = ?1",
    )
    .bind(authz_id)
    .fetch_all(&mut *conn)
    .await
    .map_err(|e| AcmeError::Database(e.to_string()))?;
    Ok(rows)
}

pub async fn set_processing(
    conn: &mut SqliteConnection,
    id: &str,
    now: i64,
) -> Result<(), AcmeError> {
    sqlx::query(
        "UPDATE challenges SET status = 'processing', updated = ?1 WHERE id = ?2",
    )
    .bind(now)
    .bind(id)
    .execute(&mut *conn)
    .await
    .map_err(|e| AcmeError::Database(e.to_string()))?;
    Ok(())
}

pub async fn set_valid(
    conn: &mut SqliteConnection,
    id: &str,
    validated: i64,
) -> Result<(), AcmeError> {
    sqlx::query(
        "UPDATE challenges SET status = 'valid', validated = ?1, updated = ?1 WHERE id = ?2",
    )
    .bind(validated)
    .bind(id)
    .execute(&mut *conn)
    .await
    .map_err(|e| AcmeError::Database(e.to_string()))?;
    Ok(())
}

/// Return the challenge type of the single validated challenge for an
/// authorization, or `None` if no challenge is in the `"valid"` state yet.
pub async fn get_validated_type(
    conn: &mut SqliteConnection,
    authz_id: &str,
) -> Result<Option<String>, AcmeError> {
    let row: Option<(String,)> = sqlx::query_as(
        "SELECT type FROM challenges WHERE authz_id = ?1 AND status = 'valid' LIMIT 1",
    )
    .bind(authz_id)
    .fetch_optional(&mut *conn)
    .await
    .map_err(|e| AcmeError::Database(e.to_string()))?;
    Ok(row.map(|(t,)| t))
}

pub async fn set_invalid(
    conn: &mut SqliteConnection,
    id: &str,
    error: String,
    now: i64,
) -> Result<(), AcmeError> {
    sqlx::query(
        "UPDATE challenges SET status = 'invalid', error = ?1, updated = ?2 WHERE id = ?3",
    )
    .bind(&error)
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

    use crate::db::schema::{AccountRow, AuthorizationRow, OrderRow};

    async fn open_db() -> crate::db::Db {
        crate::db::open(":memory:").await.unwrap()
    }

    macro_rules! conn {
        ($db:expr) => {
            &mut *$db.acquire().await.unwrap()
        };
    }

    async fn insert_parents(db: &crate::db::Db, account_id: &str, order_id: &str, authz_id: &str) {
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

        crate::db::authz::insert(
            conn!(db),
            AuthorizationRow {
                id: authz_id.to_string(),
                order_id: order_id.to_string(),
                account_id: account_id.to_string(),
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
    }

    fn sample_challenge(id: &str, authz_id: &str) -> ChallengeRow {
        ChallengeRow {
            id: id.to_string(),
            authz_id: authz_id.to_string(),
            r#type: "http-01".to_string(),
            status: "pending".to_string(),
            token: format!("token-{id}"),
            validated: None,
            error: None,
            created: 1_700_000_000,
            updated: 1_700_000_000,
        }
    }

    async fn insert_challenge(
        db: &crate::db::Db,
        id: &str,
        account_id: &str,
        order_id: &str,
        authz_id: &str,
    ) {
        insert_parents(db, account_id, order_id, authz_id).await;
        insert(conn!(db), sample_challenge(id, authz_id)).await.unwrap();
    }

    #[tokio::test]
    async fn insert_and_get_by_id() {
        let db = open_db().await;
        insert_challenge(&db, "chall-1", "acct-1", "order-1", "authz-1").await;

        let row = get_by_id(conn!(db), "chall-1").await.unwrap().unwrap();
        assert_eq!(row.id, "chall-1");
        assert_eq!(row.status, "pending");
        assert_eq!(row.r#type, "http-01");
    }

    #[tokio::test]
    async fn get_by_id_missing_returns_none() {
        let db = open_db().await;
        let result = get_by_id(conn!(db), "nonexistent").await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn list_by_authz_returns_challenges() {
        let db = open_db().await;
        insert_parents(&db, "acct-2", "order-2", "authz-2").await;
        insert(conn!(db), sample_challenge("chall-2a", "authz-2"))
            .await
            .unwrap();
        insert(
            conn!(db),
            ChallengeRow {
                id: "chall-2b".to_string(),
                authz_id: "authz-2".to_string(),
                r#type: "dns-01".to_string(),
                status: "pending".to_string(),
                token: "token-2b".to_string(),
                validated: None,
                error: None,
                created: 1_700_000_000,
                updated: 1_700_000_000,
            },
        )
        .await
        .unwrap();

        let challenges = list_by_authz(conn!(db), "authz-2").await.unwrap();
        assert_eq!(challenges.len(), 2);
        let types: Vec<_> = challenges.iter().map(|c| c.r#type.as_str()).collect();
        assert!(types.contains(&"http-01"));
        assert!(types.contains(&"dns-01"));
    }

    #[tokio::test]
    async fn list_by_authz_empty_for_no_challenges() {
        let db = open_db().await;
        insert_parents(&db, "acct-3", "order-3", "authz-3").await;

        let challenges = list_by_authz(conn!(db), "authz-3").await.unwrap();
        assert!(challenges.is_empty());
    }

    #[tokio::test]
    async fn set_processing_updates_status() {
        let db = open_db().await;
        insert_challenge(&db, "chall-4", "acct-4", "order-4", "authz-4").await;

        set_processing(conn!(db), "chall-4", 1_700_000_001).await.unwrap();

        let row = get_by_id(conn!(db), "chall-4").await.unwrap().unwrap();
        assert_eq!(row.status, "processing");
        assert_eq!(row.updated, 1_700_000_001);
    }

    #[tokio::test]
    async fn set_valid_updates_status_and_validated() {
        let db = open_db().await;
        insert_challenge(&db, "chall-5", "acct-5", "order-5", "authz-5").await;

        set_valid(conn!(db), "chall-5", 1_700_000_002).await.unwrap();

        let row = get_by_id(conn!(db), "chall-5").await.unwrap().unwrap();
        assert_eq!(row.status, "valid");
        assert_eq!(row.validated, Some(1_700_000_002));
    }

    #[tokio::test]
    async fn set_invalid_updates_status_and_error() {
        let db = open_db().await;
        insert_challenge(&db, "chall-6", "acct-6", "order-6", "authz-6").await;

        set_invalid(
            conn!(db),
            "chall-6",
            "{\"type\":\"connection\"}".into(),
            1_700_000_003,
        )
        .await
        .unwrap();

        let row = get_by_id(conn!(db), "chall-6").await.unwrap().unwrap();
        assert_eq!(row.status, "invalid");
        assert_eq!(row.error, Some("{\"type\":\"connection\"}".to_string()));
    }

    #[tokio::test]
    async fn get_validated_type_returns_none_when_no_valid_challenge() {
        let db = open_db().await;
        insert_challenge(&db, "chall-v1", "acct-v1", "order-v1", "authz-v1").await;
        // Challenge is still "pending" — no valid type yet.
        let result = get_validated_type(conn!(db), "authz-v1").await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn get_validated_type_returns_type_after_set_valid() {
        let db = open_db().await;
        insert_parents(&db, "acct-v2", "order-v2", "authz-v2").await;
        insert(
            conn!(db),
            ChallengeRow {
                id: "chall-v2".to_string(),
                authz_id: "authz-v2".to_string(),
                r#type: "dns-01".to_string(),
                status: "pending".to_string(),
                token: "token-v2".to_string(),
                validated: None,
                error: None,
                created: 1_700_000_000,
                updated: 1_700_000_000,
            },
        )
        .await
        .unwrap();
        set_valid(conn!(db), "chall-v2", 1_700_000_099).await.unwrap();
        let result = get_validated_type(conn!(db), "authz-v2").await.unwrap();
        assert_eq!(result, Some("dns-01".to_string()));
    }

    #[tokio::test]
    async fn get_validated_type_no_such_authz_returns_none() {
        let db = open_db().await;
        let result = get_validated_type(conn!(db), "nonexistent-authz").await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn db_error_paths_no_table() {
        use sqlx::Connection as _;
        let mut raw: sqlx::SqliteConnection =
            sqlx::SqliteConnection::connect("sqlite::memory:").await.unwrap();
        assert!(insert(&mut raw, sample_challenge("err-chall", "err-authz"))
            .await
            .is_err());
        assert!(get_by_id(&mut raw, "any").await.is_err());
        assert!(list_by_authz(&mut raw, "any").await.is_err());
        assert!(set_processing(&mut raw, "any", 0).await.is_err());
        assert!(set_valid(&mut raw, "any", 0).await.is_err());
        assert!(set_invalid(&mut raw, "any", "{}".into(), 0).await.is_err());
    }
}
