use crate::db::schema::ChallengeRow;
use crate::error::AcmeError;

pub async fn insert(
    executor: impl sqlx::Executor<'_, Database = sqlx::Any>,
    row: ChallengeRow,
) -> Result<(), AcmeError> {
    super::query(
        "INSERT INTO challenges (id, authz_id, type, status, token, validated, error, created, updated)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
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
    .execute(executor)
    .await?;
    Ok(())
}

pub async fn get_by_id(
    executor: impl sqlx::Executor<'_, Database = sqlx::Any>,
    id: &str,
) -> Result<Option<ChallengeRow>, AcmeError> {
    let row = super::query_as::<ChallengeRow>(
        "SELECT id, authz_id, type, status, token, validated, error, created, updated
         FROM challenges WHERE id = ?",
    )
    .bind(id)
    .fetch_optional(executor)
    .await?;
    Ok(row)
}

pub async fn list_by_authz(
    executor: impl sqlx::Executor<'_, Database = sqlx::Any>,
    authz_id: &str,
) -> Result<Vec<ChallengeRow>, AcmeError> {
    let rows = super::query_as::<ChallengeRow>(
        "SELECT id, authz_id, type, status, token, validated, error, created, updated
         FROM challenges WHERE authz_id = ?",
    )
    .bind(authz_id)
    .fetch_all(executor)
    .await?;
    Ok(rows)
}

pub async fn set_processing(
    executor: impl sqlx::Executor<'_, Database = sqlx::Any>,
    id: &str,
    now: i64,
) -> Result<(), AcmeError> {
    super::query("UPDATE challenges SET status = 'processing', updated = ? WHERE id = ?")
        .bind(now)
        .bind(id)
        .execute(executor)
        .await?;
    Ok(())
}

/// Atomically flip a challenge from "pending" to "processing" without an
/// explicit transaction (autocommit).  Returns the number of rows updated:
/// 1 if the flip succeeded, 0 if the challenge was already processing/valid.
/// The conditional WHERE avoids double-processing under concurrent requests.
pub async fn set_processing_if_pending(
    executor: impl sqlx::Executor<'_, Database = sqlx::Any>,
    id: &str,
    now: i64,
) -> Result<u64, AcmeError> {
    let result =
        super::query("UPDATE challenges SET status = 'processing', updated = ? WHERE id = ? AND status = 'pending'")
            .bind(now)
            .bind(id)
            .execute(executor)
            .await?;
    Ok(result.rows_affected())
}

pub async fn set_valid(
    executor: impl sqlx::Executor<'_, Database = sqlx::Any>,
    id: &str,
    validated: i64,
) -> Result<(), AcmeError> {
    super::query("UPDATE challenges SET status = 'valid', validated = ?, updated = ? WHERE id = ?")
        .bind(validated)
        .bind(validated)
        .bind(id)
        .execute(executor)
        .await?;
    Ok(())
}

/// Return the challenge type (`"http-01"`, `"dns-01"`, etc.) of the single
/// validated challenge for an authorization, or `None` if no challenge is
/// in the `"valid"` state yet.
///
/// Used by the finalize handler to supply a real challenge type to the CAA
/// `validationmethods` check (RFC 8657).
pub async fn get_validated_type(
    executor: impl sqlx::Executor<'_, Database = sqlx::Any>,
    authz_id: &str,
) -> Result<Option<String>, AcmeError> {
    let row: Option<(String,)> = super::query_as(
        "SELECT type FROM challenges WHERE authz_id = ? AND status = 'valid' LIMIT 1",
    )
    .bind(authz_id)
    .fetch_optional(executor)
    .await?;
    Ok(row.map(|(t,)| t))
}

pub async fn set_invalid(
    executor: impl sqlx::Executor<'_, Database = sqlx::Any>,
    id: &str,
    error: String,
    now: i64,
) -> Result<(), AcmeError> {
    super::query("UPDATE challenges SET status = 'invalid', error = ?, updated = ? WHERE id = ?")
        .bind(&error)
        .bind(now)
        .bind(id)
        .execute(executor)
        .await?;
    Ok(())
}

/// Store the RFC 8823 email-reply-00 token-part1 and Message-ID after sending the
/// challenge email.  Called once per challenge trigger.
pub async fn set_email_token(
    executor: impl sqlx::Executor<'_, Database = sqlx::Any>,
    id: &str,
    token_part1: &str,
    message_id: &str,
    now: i64,
) -> Result<(), AcmeError> {
    let rows = super::query(
        "UPDATE challenges
         SET email_token_part1 = ?, email_message_id = ?, updated = ?
         WHERE id = ?",
    )
    .bind(token_part1)
    .bind(message_id)
    .bind(now)
    .bind(id)
    .execute(executor)
    .await?
    .rows_affected();

    if rows == 0 {
        return Err(AcmeError::Internal(format!(
            "set_email_token: challenge {id} not found"
        )));
    }
    Ok(())
}

/// Look up a pending email-reply-00 challenge by the Message-ID of the sent challenge email.
/// Used by the webhook endpoint to match an incoming reply to the originating challenge.
pub async fn get_by_email_message_id(
    executor: impl sqlx::Executor<'_, Database = sqlx::Any>,
    message_id: &str,
) -> Result<Option<ChallengeRow>, AcmeError> {
    let row = super::query_as::<ChallengeRow>(
        "SELECT id, authz_id, type, status, token,
                validated, error, created, updated,
                email_token_part1, email_message_id
         FROM challenges
         WHERE email_message_id = ? AND type = 'email-reply-00'
         LIMIT 1",
    )
    .bind(message_id)
    .fetch_optional(executor)
    .await?;
    Ok(row)
}

/// Batch-insert new challenges for a single authorization in one SQL round-trip.
///
/// `challenges` is a slice of `(id, type)` pairs; all rows share the same
/// `authz_id`, `token`, and timestamps.  A no-op when `challenges` is empty.
pub async fn insert_batch(
    executor: impl sqlx::Executor<'_, Database = sqlx::Any>,
    authz_id: &str,
    challenges: &[(String, String)],
    token: &str,
    now: i64,
) -> Result<(), AcmeError> {
    if challenges.is_empty() {
        return Ok(());
    }
    let mut qb = super::DynQueryBuilder::new(
        "INSERT INTO challenges \
         (id, authz_id, type, status, token, validated, error, created, updated) VALUES ",
    );
    qb.push_values(challenges.iter(), |b, (chall_id, chall_type)| {
        b.push_bind(chall_id.as_str())
            .push_bind(authz_id)
            .push_bind(chall_type.as_str())
            .push_bind("pending")
            .push_bind(token)
            .push_bind(None::<i64>)
            .push_bind(None::<String>)
            .push_bind(now)
            .push_bind(now);
    });
    qb.execute(executor).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::db::schema::{AccountRow, AuthorizationRow, OrderRow};
    use crate::db::Db;

    async fn open_db() -> Db {
        crate::db::install_drivers();
        crate::db::open("sqlite::memory:", 1, false).await.unwrap()
    }

    async fn insert_parents(db: &Db, account_id: &str, order_id: &str, authz_id: &str) {
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

        crate::db::authz::insert(
            db,
            AuthorizationRow {
                id: authz_id.to_string(),
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
            email_token_part1: None,
            email_message_id: None,
        }
    }

    async fn insert_challenge(db: &Db, id: &str, account_id: &str, order_id: &str, authz_id: &str) {
        insert_parents(db, account_id, order_id, authz_id).await;
        insert(db, sample_challenge(id, authz_id)).await.unwrap();
    }

    #[tokio::test]
    async fn insert_and_get_by_id() {
        let db = open_db().await;
        insert_challenge(&db, "chall-1", "acct-1", "order-1", "authz-1").await;

        let row = get_by_id(&db, "chall-1").await.unwrap().unwrap();
        assert_eq!(row.id, "chall-1");
        assert_eq!(row.status, "pending");
        assert_eq!(row.r#type, "http-01");
    }

    #[tokio::test]
    async fn get_by_id_missing_returns_none() {
        let db = open_db().await;
        let result = get_by_id(&db, "nonexistent").await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn list_by_authz_returns_challenges() {
        let db = open_db().await;
        insert_parents(&db, "acct-2", "order-2", "authz-2").await;
        insert(&db, sample_challenge("chall-2a", "authz-2"))
            .await
            .unwrap();
        insert(
            &db,
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
                email_token_part1: None,
                email_message_id: None,
            },
        )
        .await
        .unwrap();

        let challenges = list_by_authz(&db, "authz-2").await.unwrap();
        assert_eq!(challenges.len(), 2);
        let types: Vec<_> = challenges.iter().map(|c| c.r#type.as_str()).collect();
        assert!(types.contains(&"http-01"));
        assert!(types.contains(&"dns-01"));
    }

    #[tokio::test]
    async fn list_by_authz_empty_for_no_challenges() {
        let db = open_db().await;
        insert_parents(&db, "acct-3", "order-3", "authz-3").await;

        let challenges = list_by_authz(&db, "authz-3").await.unwrap();
        assert!(challenges.is_empty());
    }

    #[tokio::test]
    async fn set_processing_updates_status() {
        let db = open_db().await;
        insert_challenge(&db, "chall-4", "acct-4", "order-4", "authz-4").await;

        set_processing(&db, "chall-4", 1_700_000_001).await.unwrap();

        let row = get_by_id(&db, "chall-4").await.unwrap().unwrap();
        assert_eq!(row.status, "processing");
        assert_eq!(row.updated, 1_700_000_001);
    }

    #[tokio::test]
    async fn set_valid_updates_status_and_validated() {
        let db = open_db().await;
        insert_challenge(&db, "chall-5", "acct-5", "order-5", "authz-5").await;

        set_valid(&db, "chall-5", 1_700_000_002).await.unwrap();

        let row = get_by_id(&db, "chall-5").await.unwrap().unwrap();
        assert_eq!(row.status, "valid");
        assert_eq!(row.validated, Some(1_700_000_002));
    }

    #[tokio::test]
    async fn set_invalid_updates_status_and_error() {
        let db = open_db().await;
        insert_challenge(&db, "chall-6", "acct-6", "order-6", "authz-6").await;

        set_invalid(
            &db,
            "chall-6",
            "{\"type\":\"connection\"}".into(),
            1_700_000_003,
        )
        .await
        .unwrap();

        let row = get_by_id(&db, "chall-6").await.unwrap().unwrap();
        assert_eq!(row.status, "invalid");
        assert_eq!(row.error, Some("{\"type\":\"connection\"}".to_string()));
    }

    #[tokio::test]
    async fn get_validated_type_returns_none_when_no_valid_challenge() {
        let db = open_db().await;
        insert_challenge(&db, "chall-v1", "acct-v1", "order-v1", "authz-v1").await;
        // Challenge is still "pending" — no valid type yet.
        let result = get_validated_type(&db, "authz-v1").await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn get_validated_type_returns_type_after_set_valid() {
        let db = open_db().await;
        insert_parents(&db, "acct-v2", "order-v2", "authz-v2").await;
        insert(
            &db,
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
                email_token_part1: None,
                email_message_id: None,
            },
        )
        .await
        .unwrap();
        set_valid(&db, "chall-v2", 1_700_000_099).await.unwrap();
        let result = get_validated_type(&db, "authz-v2").await.unwrap();
        assert_eq!(result, Some("dns-01".to_string()));
    }

    #[tokio::test]
    async fn get_validated_type_no_such_authz_returns_none() {
        let db = open_db().await;
        let result = get_validated_type(&db, "nonexistent-authz").await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn set_processing_if_pending_returns_1_for_pending() {
        let db = open_db().await;
        insert_challenge(
            &db,
            "chall-sip-1",
            "acct-sip-1",
            "order-sip-1",
            "authz-sip-1",
        )
        .await;

        let affected = set_processing_if_pending(&db, "chall-sip-1", 1_700_000_010)
            .await
            .unwrap();
        assert_eq!(affected, 1, "should update one pending challenge");

        let row = get_by_id(&db, "chall-sip-1").await.unwrap().unwrap();
        assert_eq!(row.status, "processing");
        assert_eq!(row.updated, 1_700_000_010);
    }

    #[tokio::test]
    async fn set_processing_if_pending_returns_0_when_already_processing() {
        let db = open_db().await;
        insert_challenge(
            &db,
            "chall-sip-2",
            "acct-sip-2",
            "order-sip-2",
            "authz-sip-2",
        )
        .await;

        // First call flips to "processing".
        set_processing_if_pending(&db, "chall-sip-2", 1_700_000_010)
            .await
            .unwrap();

        // Second concurrent call must not double-process: WHERE status = 'pending' skips it.
        let affected = set_processing_if_pending(&db, "chall-sip-2", 1_700_000_020)
            .await
            .unwrap();
        assert_eq!(
            affected, 0,
            "already-processing challenge should not be updated"
        );

        // Status and timestamp must remain from the first flip.
        let row = get_by_id(&db, "chall-sip-2").await.unwrap().unwrap();
        assert_eq!(row.status, "processing");
        assert_eq!(
            row.updated, 1_700_000_010,
            "timestamp must not be overwritten"
        );
    }

    #[tokio::test]
    async fn set_processing_if_pending_returns_0_for_valid_challenge() {
        let db = open_db().await;
        insert_challenge(
            &db,
            "chall-sip-3",
            "acct-sip-3",
            "order-sip-3",
            "authz-sip-3",
        )
        .await;
        set_valid(&db, "chall-sip-3", 1_700_000_010).await.unwrap();

        let affected = set_processing_if_pending(&db, "chall-sip-3", 1_700_000_020)
            .await
            .unwrap();
        assert_eq!(
            affected, 0,
            "valid challenge must not be flipped to processing"
        );

        let row = get_by_id(&db, "chall-sip-3").await.unwrap().unwrap();
        assert_eq!(row.status, "valid", "valid status must not change");
    }

    #[tokio::test]
    async fn db_error_paths_no_table() {
        crate::db::install_drivers();
        let raw: Db = sqlx::any::AnyPoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        assert!(insert(&raw, sample_challenge("err-chall", "err-authz"))
            .await
            .is_err());
        assert!(get_by_id(&raw, "any").await.is_err());
        assert!(list_by_authz(&raw, "any").await.is_err());
        assert!(set_processing(&raw, "any", 0).await.is_err());
        assert!(set_valid(&raw, "any", 0).await.is_err());
        assert!(set_invalid(&raw, "any", "{}".into(), 0).await.is_err());
    }
}
