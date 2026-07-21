use crate::db::schema::AccountRow;
use crate::error::AcmeError;

pub async fn insert(
    executor: impl sqlx::Executor<'_, Database = sqlx::Any>,
    row: AccountRow,
) -> Result<(), AcmeError> {
    super::query(
        "INSERT INTO accounts \
         (id, status, contact, public_key, jwk_thumbprint, created, updated, profile_grants, ca_id, kerberos_principal)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&row.id)
    .bind(&row.status)
    .bind(&row.contact)
    .bind(&row.public_key)
    .bind(&row.jwk_thumbprint)
    .bind(row.created)
    .bind(row.updated)
    .bind(&row.profile_grants)
    .bind(&row.ca_id)
    .bind(&row.kerberos_principal)
    .execute(executor)
    .await?;
    Ok(())
}

pub async fn get_by_id(
    executor: impl sqlx::Executor<'_, Database = sqlx::Any>,
    id: &str,
) -> Result<Option<AccountRow>, AcmeError> {
    let row = super::query_as::<AccountRow>(
        "SELECT id, status, contact, public_key, jwk_thumbprint, created, updated, profile_grants, ca_id, kerberos_principal
         FROM accounts WHERE id = ?",
    )
    .bind(id)
    .fetch_optional(executor)
    .await?;
    Ok(row)
}

pub async fn get_by_thumbprint(
    executor: impl sqlx::Executor<'_, Database = sqlx::Any>,
    thumbprint: &str,
) -> Result<Option<AccountRow>, AcmeError> {
    let row = super::query_as::<AccountRow>(
        "SELECT id, status, contact, public_key, jwk_thumbprint, created, updated, profile_grants, ca_id, kerberos_principal
         FROM accounts WHERE jwk_thumbprint = ?",
    )
    .bind(thumbprint)
    .fetch_optional(executor)
    .await?;
    Ok(row)
}

pub async fn update_contact(
    executor: impl sqlx::Executor<'_, Database = sqlx::Any>,
    id: &str,
    contact: Option<String>,
    now: i64,
) -> Result<bool, AcmeError> {
    let n = super::query(
        "UPDATE accounts SET contact = ?, updated = ? WHERE id = ? AND status = 'valid'",
    )
    .bind(contact)
    .bind(now)
    .bind(id)
    .execute(executor)
    .await?
    .rows_affected();
    Ok(n > 0)
}

pub async fn update_status(
    executor: impl sqlx::Executor<'_, Database = sqlx::Any>,
    id: &str,
    status: &str,
    now: i64,
) -> Result<bool, AcmeError> {
    let n = super::query("UPDATE accounts SET status = ?, updated = ? WHERE id = ?")
        .bind(status)
        .bind(now)
        .bind(id)
        .execute(executor)
        .await?
        .rows_affected();
    Ok(n > 0)
}

/// Update the account's JWK thumbprint and public key (for key rollover).
pub async fn update_key(
    executor: impl sqlx::Executor<'_, Database = sqlx::Any>,
    id: &str,
    public_key: Vec<u8>,
    jwk_thumbprint: String,
    now: i64,
) -> Result<bool, AcmeError> {
    let n = super::query(
        "UPDATE accounts SET public_key = ?, jwk_thumbprint = ?, updated = ?
         WHERE id = ? AND status = 'valid'",
    )
    .bind(&public_key)
    .bind(&jwk_thumbprint)
    .bind(now)
    .bind(id)
    .execute(executor)
    .await?
    .rows_affected();
    Ok(n > 0)
}

/// Set or clear the `profile_grants` for an account.
///
/// `grants` is a JSON-serialised array of permitted profile IDs, e.g.
/// `Some("[\"tls-server\",\"mtc-tls\"]")`.  `None` clears the restriction
/// (account may request any profile).  Returns `true` when the account was
/// found and updated.
pub async fn set_profile_grants(
    executor: impl sqlx::Executor<'_, Database = sqlx::Any>,
    id: &str,
    grants: Option<&str>,
    now: i64,
) -> Result<bool, AcmeError> {
    let n = super::query(
        "UPDATE accounts SET profile_grants = ?, updated = ? WHERE id = ? AND status = 'valid'",
    )
    .bind(grants)
    .bind(now)
    .bind(id)
    .execute(executor)
    .await?
    .rows_affected();
    Ok(n > 0)
}

/// Fetch only the `profile_grants` column for an account.
///
/// Returns `Ok(None)` when the account is not found, `Ok(Some(None))` when
/// the account exists but has no grant restriction, and
/// `Ok(Some(Some(json)))` when grants are configured.
pub async fn get_profile_grants(
    executor: impl sqlx::Executor<'_, Database = sqlx::Any>,
    id: &str,
) -> Result<Option<Option<String>>, AcmeError> {
    let row: Option<(Option<String>,)> =
        super::query_as("SELECT profile_grants FROM accounts WHERE id = ?")
            .bind(id)
            .fetch_optional(executor)
            .await?;
    Ok(row.map(|(grants,)| grants))
}

/// Fetch the `kerberos_principal` for an account.
///
/// Returns `Ok(None)` when the account is not found or has no stored principal.
pub async fn get_kerberos_principal(
    executor: impl sqlx::Executor<'_, Database = sqlx::Any>,
    id: &str,
) -> Result<Option<String>, AcmeError> {
    let row: Option<(Option<String>,)> =
        super::query_as("SELECT kerberos_principal FROM accounts WHERE id = ?")
            .bind(id)
            .fetch_optional(executor)
            .await?;
    Ok(row.and_then(|(p,)| p))
}

/// List accounts with optional status filter and pagination.
pub async fn list(
    executor: impl sqlx::Executor<'_, Database = sqlx::Any>,
    status: Option<&str>,
    ca_id: Option<&str>,
    limit: i64,
    offset: i64,
) -> Result<Vec<AccountRow>, AcmeError> {
    let mut qb = super::DynQueryBuilder::new(
        "SELECT id, status, contact, public_key, jwk_thumbprint, created, updated, profile_grants, ca_id, kerberos_principal \
         FROM accounts WHERE 1=1",
    );
    if let Some(st) = status {
        qb.push(" AND status = ");
        qb.push_bind(st);
    }
    if let Some(ca) = ca_id {
        // Covers CA-scoped accounts (ca_id = ?) and server-scoped accounts that
        // have placed at least one order with this CA (subquery on orders).
        qb.push(" AND (ca_id = ");
        qb.push_bind(ca);
        qb.push(" OR id IN (SELECT DISTINCT account_id FROM orders WHERE ca_id = ");
        qb.push_bind(ca);
        qb.push("))");
    }
    qb.push(" ORDER BY created DESC LIMIT ");
    qb.push_bind(limit);
    qb.push(" OFFSET ");
    qb.push_bind(offset);

    let rows = qb.fetch_all::<_, AccountRow>(executor).await?;
    Ok(rows)
}

/// Count accounts matching the same filters as [`list`], without LIMIT/OFFSET.
pub async fn count_list(
    executor: impl sqlx::Executor<'_, Database = sqlx::Any>,
    status: Option<&str>,
    ca_id: Option<&str>,
) -> Result<i64, AcmeError> {
    let mut qb = super::DynQueryBuilder::new("SELECT COUNT(*) FROM accounts WHERE 1=1");
    if let Some(st) = status {
        qb.push(" AND status = ");
        qb.push_bind(st);
    }
    if let Some(ca) = ca_id {
        qb.push(" AND (ca_id = ");
        qb.push_bind(ca);
        qb.push(" OR id IN (SELECT DISTINCT account_id FROM orders WHERE ca_id = ");
        qb.push_bind(ca);
        qb.push("))");
    }
    let row: (i64,) = qb.fetch_one(executor).await?;
    Ok(row.0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::Db;

    async fn open_db() -> Db {
        crate::db::install_drivers();
        crate::db::open("sqlite::memory:", 1, false).await.unwrap()
    }

    fn sample_account(id: &str) -> AccountRow {
        AccountRow {
            id: id.to_string(),
            status: "valid".to_string(),
            contact: None,
            public_key: vec![0u8; 4],
            jwk_thumbprint: format!("thumb-{id}"),
            created: 1_700_000_000,
            updated: 1_700_000_000,
            profile_grants: None,
            ca_id: String::new(),
            kerberos_principal: None,
        }
    }

    #[tokio::test]
    async fn insert_and_get_by_id() {
        let db = open_db().await;
        insert(&db, sample_account("acct-1")).await.unwrap();
        let row = get_by_id(&db, "acct-1").await.unwrap().unwrap();
        assert_eq!(row.id, "acct-1");
        assert_eq!(row.status, "valid");
    }

    #[tokio::test]
    async fn get_by_id_missing_returns_none() {
        let db = open_db().await;
        let result = get_by_id(&db, "nonexistent").await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn get_by_thumbprint_finds_account() {
        let db = open_db().await;
        insert(&db, sample_account("acct-2")).await.unwrap();
        let row = get_by_thumbprint(&db, "thumb-acct-2")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(row.id, "acct-2");
    }

    #[tokio::test]
    async fn get_by_thumbprint_missing_returns_none() {
        let db = open_db().await;
        let result = get_by_thumbprint(&db, "nonexistent-thumb").await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn update_contact_valid_account() {
        let db = open_db().await;
        insert(&db, sample_account("acct-3")).await.unwrap();

        let changed = update_contact(
            &db,
            "acct-3",
            Some("[\"mailto:a@b.com\"]".into()),
            1_700_000_001,
        )
        .await
        .unwrap();
        assert!(
            changed,
            "update_contact should return true for valid account"
        );

        let row = get_by_id(&db, "acct-3").await.unwrap().unwrap();
        assert_eq!(row.contact, Some("[\"mailto:a@b.com\"]".to_string()));
    }

    #[tokio::test]
    async fn update_contact_nonexistent_returns_false() {
        let db = open_db().await;
        let changed = update_contact(&db, "nonexistent", None, 1_700_000_001)
            .await
            .unwrap();
        assert!(!changed);
    }

    #[tokio::test]
    async fn update_contact_deactivated_returns_false() {
        let db = open_db().await;
        insert(&db, sample_account("acct-4")).await.unwrap();
        update_status(&db, "acct-4", "deactivated", 1_700_000_001)
            .await
            .unwrap();

        let changed = update_contact(&db, "acct-4", None, 1_700_000_002)
            .await
            .unwrap();
        assert!(!changed, "update_contact should fail for non-valid account");
    }

    #[tokio::test]
    async fn update_status_changes_status() {
        let db = open_db().await;
        insert(&db, sample_account("acct-5")).await.unwrap();

        let changed = update_status(&db, "acct-5", "deactivated", 1_700_000_001)
            .await
            .unwrap();
        assert!(changed);

        let row = get_by_id(&db, "acct-5").await.unwrap().unwrap();
        assert_eq!(row.status, "deactivated");
    }

    #[tokio::test]
    async fn update_status_nonexistent_returns_false() {
        let db = open_db().await;
        let changed = update_status(&db, "nonexistent", "revoked", 1_700_000_001)
            .await
            .unwrap();
        assert!(!changed);
    }

    #[tokio::test]
    async fn update_key_valid_account() {
        let db = open_db().await;
        insert(&db, sample_account("acct-6")).await.unwrap();

        let changed = update_key(
            &db,
            "acct-6",
            vec![0xDE, 0xAD, 0xBE, 0xEF],
            "new-thumb".into(),
            1_700_000_001,
        )
        .await
        .unwrap();
        assert!(changed);

        let row = get_by_id(&db, "acct-6").await.unwrap().unwrap();
        assert_eq!(row.jwk_thumbprint, "new-thumb");
        assert_eq!(row.public_key, vec![0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[tokio::test]
    async fn update_key_nonexistent_returns_false() {
        let db = open_db().await;
        let changed = update_key(&db, "nonexistent", vec![], "thumb".into(), 0)
            .await
            .unwrap();
        assert!(!changed);
    }

    #[tokio::test]
    async fn update_key_deactivated_returns_false() {
        let db = open_db().await;
        insert(&db, sample_account("acct-7")).await.unwrap();
        update_status(&db, "acct-7", "deactivated", 1_700_000_001)
            .await
            .unwrap();

        let changed = update_key(&db, "acct-7", vec![], "thumb".into(), 0)
            .await
            .unwrap();
        assert!(!changed, "update_key should fail for non-valid account");
    }

    /// Cover the error propagation path in each function by calling them on a
    /// pool that has no schema (no tables). Every DB operation will fail with
    /// "no such table", which exercises the error-return paths.
    #[tokio::test]
    async fn db_error_paths_no_table() {
        crate::db::install_drivers();
        // Raw pool — no migrations run, so no tables exist.
        let raw: Db = sqlx::any::AnyPoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();

        let row = sample_account("err-acct");
        assert!(
            insert(&raw, row).await.is_err(),
            "insert should fail on no-table DB"
        );

        assert!(get_by_id(&raw, "any").await.is_err());
        assert!(get_by_thumbprint(&raw, "any").await.is_err());
        assert!(update_contact(&raw, "any", None, 0).await.is_err());
        assert!(update_status(&raw, "any", "deactivated", 0).await.is_err());
        assert!(update_key(&raw, "any", vec![], "thumb".into(), 0)
            .await
            .is_err());
        assert!(set_profile_grants(&raw, "any", None, 0).await.is_err());
        assert!(get_profile_grants(&raw, "any").await.is_err());
        assert!(get_kerberos_principal(&raw, "any").await.is_err());
    }

    #[tokio::test]
    async fn set_and_get_profile_grants() {
        let db = open_db().await;
        insert(&db, sample_account("pg-1")).await.unwrap();

        // Freshly inserted account has no grants.
        let g = get_profile_grants(&db, "pg-1").await.unwrap();
        assert_eq!(g, Some(None), "new account should have NULL profile_grants");

        // Set grants.
        let changed = set_profile_grants(&db, "pg-1", Some("[\"p1\",\"p2\"]"), 1_700_000_001)
            .await
            .unwrap();
        assert!(changed);
        let g = get_profile_grants(&db, "pg-1").await.unwrap();
        assert_eq!(
            g,
            Some(Some("[\"p1\",\"p2\"]".to_string())),
            "grants should be stored"
        );

        // Clear grants.
        let changed = set_profile_grants(&db, "pg-1", None, 1_700_000_002)
            .await
            .unwrap();
        assert!(changed);
        let g = get_profile_grants(&db, "pg-1").await.unwrap();
        assert_eq!(g, Some(None), "clearing grants should restore NULL");
    }

    #[tokio::test]
    async fn get_profile_grants_unknown_account() {
        let db = open_db().await;
        let g = get_profile_grants(&db, "nonexistent").await.unwrap();
        assert_eq!(g, None, "unknown account should return outer None");
    }

    #[tokio::test]
    async fn insert_propagates_profile_grants() {
        let db = open_db().await;
        let mut row = sample_account("pg-2");
        row.profile_grants = Some("[\"mtc-tls\"]".to_string());
        insert(&db, row).await.unwrap();

        let g = get_profile_grants(&db, "pg-2").await.unwrap();
        assert_eq!(
            g,
            Some(Some("[\"mtc-tls\"]".to_string())),
            "grants passed to insert should be persisted"
        );
    }

    #[tokio::test]
    async fn get_kerberos_principal_not_found_returns_none() {
        let db = open_db().await;
        let result = get_kerberos_principal(&db, "nonexistent").await.unwrap();
        assert!(result.is_none(), "missing account should return None");
    }

    #[tokio::test]
    async fn get_kerberos_principal_null_returns_none() {
        // sample_account sets kerberos_principal = None (NULL in DB).
        let db = open_db().await;
        insert(&db, sample_account("kpn-null")).await.unwrap();
        let result = get_kerberos_principal(&db, "kpn-null").await.unwrap();
        assert!(
            result.is_none(),
            "account with NULL kerberos_principal should return None"
        );
    }

    #[tokio::test]
    async fn get_kerberos_principal_stored_value_returned() {
        let db = open_db().await;
        let mut row = sample_account("kpn-set");
        row.kerberos_principal = Some("alice@EXAMPLE.COM".to_string());
        insert(&db, row).await.unwrap();
        let result = get_kerberos_principal(&db, "kpn-set").await.unwrap();
        assert_eq!(
            result.as_deref(),
            Some("alice@EXAMPLE.COM"),
            "stored principal should be returned verbatim"
        );
    }
}
