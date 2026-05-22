use crate::db::schema::DelegationRow;
use crate::error::AcmeError;

pub async fn insert(
    executor: impl sqlx::Executor<'_, Database = sqlx::Any>,
    row: DelegationRow,
) -> Result<(), AcmeError> {
    super::query(
        "INSERT INTO delegations (id, account_id, csr_template, cname_map, created, updated)
         VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(&row.id)
    .bind(&row.account_id)
    .bind(&row.csr_template)
    .bind(&row.cname_map)
    .bind(row.created)
    .bind(row.updated)
    .execute(executor)
    .await?;
    Ok(())
}

pub async fn get_by_id(
    executor: impl sqlx::Executor<'_, Database = sqlx::Any>,
    id: &str,
) -> Result<Option<DelegationRow>, AcmeError> {
    let row = super::query_as::<DelegationRow>(
        "SELECT id, account_id, csr_template, cname_map, created, updated
         FROM delegations WHERE id = ?",
    )
    .bind(id)
    .fetch_optional(executor)
    .await?;
    Ok(row)
}

pub async fn list_for_account(
    executor: impl sqlx::Executor<'_, Database = sqlx::Any>,
    account_id: &str,
) -> Result<Vec<DelegationRow>, AcmeError> {
    let rows = super::query_as::<DelegationRow>(
        "SELECT id, account_id, csr_template, cname_map, created, updated
         FROM delegations WHERE account_id = ? ORDER BY created DESC LIMIT 1000",
    )
    .bind(account_id)
    .fetch_all(executor)
    .await?;
    Ok(rows)
}

/// Update the CSR template and CNAME map for a delegation.
///
/// Returns `true` if the delegation was found and updated.
pub async fn update(
    executor: impl sqlx::Executor<'_, Database = sqlx::Any>,
    id: &str,
    csr_template: &str,
    cname_map: Option<&str>,
    now: i64,
) -> Result<bool, AcmeError> {
    let n = super::query(
        "UPDATE delegations SET csr_template = ?, cname_map = ?, updated = ? WHERE id = ?",
    )
    .bind(csr_template)
    .bind(cname_map)
    .bind(now)
    .bind(id)
    .execute(executor)
    .await?
    .rows_affected();
    Ok(n > 0)
}

/// Delete a delegation by ID.
///
/// Returns `true` if a row was deleted.  Fails with a DB constraint error if
/// any `orders.delegation_id` still references this delegation.
pub async fn delete(
    executor: impl sqlx::Executor<'_, Database = sqlx::Any>,
    id: &str,
) -> Result<bool, AcmeError> {
    let n = super::query("DELETE FROM delegations WHERE id = ?")
        .bind(id)
        .execute(executor)
        .await?
        .rows_affected();
    Ok(n > 0)
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

    fn sample_delegation(id: &str, account_id: &str) -> DelegationRow {
        DelegationRow {
            id: id.to_string(),
            account_id: account_id.to_string(),
            csr_template: r#"{"keyTypes":[{"type":"EC","curve":"P-256"}],"subject":{},"extensions":{"subjectAltName":{}}}"#.to_string(),
            cname_map: None,
            created: 1_700_000_000,
            updated: 1_700_000_000,
        }
    }

    #[tokio::test]
    async fn insert_and_get_by_id() {
        let db = open_db().await;
        insert_account(&db, "acct-1").await;
        insert(&db, sample_delegation("dlg-1", "acct-1"))
            .await
            .unwrap();

        let row = get_by_id(&db, "dlg-1").await.unwrap().unwrap();
        assert_eq!(row.id, "dlg-1");
        assert_eq!(row.account_id, "acct-1");
        assert!(row.cname_map.is_none());
    }

    #[tokio::test]
    async fn get_by_id_missing_returns_none() {
        let db = open_db().await;
        let result = get_by_id(&db, "nonexistent").await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn list_for_account_returns_delegations() {
        let db = open_db().await;
        insert_account(&db, "acct-2").await;
        insert(&db, sample_delegation("dlg-a", "acct-2"))
            .await
            .unwrap();
        insert(&db, sample_delegation("dlg-b", "acct-2"))
            .await
            .unwrap();

        let rows = list_for_account(&db, "acct-2").await.unwrap();
        assert_eq!(rows.len(), 2);
    }

    #[tokio::test]
    async fn list_for_account_empty_for_unknown_account() {
        let db = open_db().await;
        let rows = list_for_account(&db, "nonexistent").await.unwrap();
        assert!(rows.is_empty());
    }

    #[tokio::test]
    async fn update_changes_template_and_cname_map() {
        let db = open_db().await;
        insert_account(&db, "acct-3").await;
        insert(&db, sample_delegation("dlg-2", "acct-3"))
            .await
            .unwrap();

        let new_template = r#"{"keyTypes":[{"type":"RSA","keySize":2048}]}"#;
        let new_cmap = r#"{"foo.example":"_acme-challenge.foo.example"}"#;
        let changed = update(&db, "dlg-2", new_template, Some(new_cmap), 1_700_000_001)
            .await
            .unwrap();
        assert!(changed);

        let row = get_by_id(&db, "dlg-2").await.unwrap().unwrap();
        assert_eq!(row.csr_template, new_template);
        assert_eq!(row.cname_map.as_deref(), Some(new_cmap));
        assert_eq!(row.updated, 1_700_000_001);
    }

    #[tokio::test]
    async fn update_clears_cname_map() {
        let db = open_db().await;
        insert_account(&db, "acct-6").await;
        let mut row = sample_delegation("dlg-clr", "acct-6");
        row.cname_map = Some(r#"{"x.example":"_acme.x.example"}"#.to_string());
        insert(&db, row).await.unwrap();

        let changed = update(&db, "dlg-clr", "{}", None, 1_700_000_002)
            .await
            .unwrap();
        assert!(changed);

        let fetched = get_by_id(&db, "dlg-clr").await.unwrap().unwrap();
        assert!(fetched.cname_map.is_none());
    }

    #[tokio::test]
    async fn list_for_account_does_not_leak_other_accounts() {
        let db = open_db().await;
        insert_account(&db, "acct-x").await;
        insert_account(&db, "acct-y").await;
        insert(&db, sample_delegation("dlg-x", "acct-x"))
            .await
            .unwrap();
        insert(&db, sample_delegation("dlg-y", "acct-y"))
            .await
            .unwrap();

        let rows = list_for_account(&db, "acct-x").await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].account_id, "acct-x");
    }

    fn sample_order_for_delegation(id: &str, account_id: &str, delegation_id: &str) -> OrderRow {
        OrderRow {
            id: id.to_string(),
            account_id: account_id.to_string(),
            status: "pending".to_string(),
            expires: None,
            identifiers: r#"[{"type":"dns","value":"example.com"}]"#.to_string(),
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
            delegation_id: Some(delegation_id.to_string()),
            allow_cert_get: 0,
            upstream_order_url: None,
            upstream_cert_url: None,
        }
    }

    #[tokio::test]
    async fn delete_fails_when_orders_reference_delegation() {
        let db = open_db().await;
        insert_account(&db, "acct-fk").await;
        insert(&db, sample_delegation("dlg-fk", "acct-fk"))
            .await
            .unwrap();
        crate::db::orders::insert(
            &db,
            sample_order_for_delegation("ord-fk", "acct-fk", "dlg-fk"),
        )
        .await
        .unwrap();

        let result = delete(&db, "dlg-fk").await;
        assert!(
            result.is_err(),
            "delete should fail with a FK constraint error"
        );
    }

    #[tokio::test]
    async fn update_nonexistent_returns_false() {
        let db = open_db().await;
        let changed = update(&db, "nonexistent", "{}", None, 0).await.unwrap();
        assert!(!changed);
    }

    #[tokio::test]
    async fn delete_removes_delegation() {
        let db = open_db().await;
        insert_account(&db, "acct-4").await;
        insert(&db, sample_delegation("dlg-3", "acct-4"))
            .await
            .unwrap();

        let deleted = delete(&db, "dlg-3").await.unwrap();
        assert!(deleted);

        let row = get_by_id(&db, "dlg-3").await.unwrap();
        assert!(row.is_none());
    }

    #[tokio::test]
    async fn delete_nonexistent_returns_false() {
        let db = open_db().await;
        let deleted = delete(&db, "nonexistent").await.unwrap();
        assert!(!deleted);
    }

    #[tokio::test]
    async fn cname_map_round_trip() {
        let db = open_db().await;
        insert_account(&db, "acct-5").await;
        let mut row = sample_delegation("dlg-4", "acct-5");
        row.cname_map = Some(r#"{"a.example":"_acme.a.example"}"#.to_string());
        insert(&db, row).await.unwrap();

        let fetched = get_by_id(&db, "dlg-4").await.unwrap().unwrap();
        assert_eq!(
            fetched.cname_map.as_deref(),
            Some(r#"{"a.example":"_acme.a.example"}"#)
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
        assert!(insert(&raw, sample_delegation("err-dlg", "err-acct"))
            .await
            .is_err());
        assert!(get_by_id(&raw, "any").await.is_err());
        assert!(list_for_account(&raw, "any").await.is_err());
        assert!(update(&raw, "any", "{}", None, 0).await.is_err());
        assert!(delete(&raw, "any").await.is_err());
    }
}

/// Paginated list with optional account_id and ca_id filters.
///
/// When `ca_id` is `Some`, only delegations whose owning account has that
/// `ca_id` are returned (CA-scoped operator view).
pub async fn list(
    executor: impl sqlx::Executor<'_, Database = sqlx::Any>,
    account_id: Option<&str>,
    ca_id: Option<&str>,
    limit: i64,
    offset: i64,
) -> Result<Vec<DelegationRow>, AcmeError> {
    let mut qb = super::DynQueryBuilder::new(
        "SELECT d.id, d.account_id, d.csr_template, d.cname_map, d.created, d.updated \
         FROM delegations d JOIN accounts a ON d.account_id = a.id WHERE 1=1",
    );
    if let Some(acct) = account_id {
        qb.push(" AND d.account_id = ");
        qb.push_bind(acct);
    }
    if let Some(ca) = ca_id {
        qb.push(" AND a.ca_id = ");
        qb.push_bind(ca);
    }
    qb.push(" ORDER BY d.created DESC LIMIT ");
    qb.push_bind(limit);
    qb.push(" OFFSET ");
    qb.push_bind(offset);
    qb.fetch_all(executor).await
}

/// Count delegations matching the optional account_id and ca_id filters.
pub async fn count_list(
    executor: impl sqlx::Executor<'_, Database = sqlx::Any>,
    account_id: Option<&str>,
    ca_id: Option<&str>,
) -> Result<i64, AcmeError> {
    let mut qb = super::DynQueryBuilder::new(
        "SELECT COUNT(*) FROM delegations d JOIN accounts a ON d.account_id = a.id WHERE 1=1",
    );
    if let Some(acct) = account_id {
        qb.push(" AND d.account_id = ");
        qb.push_bind(acct);
    }
    if let Some(ca) = ca_id {
        qb.push(" AND a.ca_id = ");
        qb.push_bind(ca);
    }
    let row: (i64,) = qb.fetch_one(executor).await?;
    Ok(row.0)
}
