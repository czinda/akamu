use crate::error::AcmeError;

pub use super::schema::PolicyRuleRow;

pub async fn insert(
    executor: impl sqlx::Executor<'_, Database = sqlx::Any>,
    row: &PolicyRuleRow,
) -> Result<(), AcmeError> {
    super::query(
        "INSERT INTO policy_rules (id, scope, name, rule_json, enabled, created_at, updated_at, created_by) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&row.id)
    .bind(&row.scope)
    .bind(&row.name)
    .bind(&row.rule_json)
    .bind(row.enabled)
    .bind(&row.created_at)
    .bind(&row.updated_at)
    .bind(row.created_by.as_deref())
    .execute(executor)
    .await?;
    Ok(())
}

pub async fn delete(
    executor: impl sqlx::Executor<'_, Database = sqlx::Any>,
    id: &str,
) -> Result<bool, AcmeError> {
    let result = super::query("DELETE FROM policy_rules WHERE id = ?")
        .bind(id)
        .execute(executor)
        .await?;
    Ok(result.rows_affected() > 0)
}

pub async fn list_by_scope(
    executor: impl sqlx::Executor<'_, Database = sqlx::Any>,
    scope: &str,
) -> Result<Vec<PolicyRuleRow>, AcmeError> {
    let rows = super::query_as::<PolicyRuleRow>(
        "SELECT id, scope, name, rule_json, enabled, created_at, updated_at, created_by \
         FROM policy_rules WHERE scope = ? ORDER BY name",
    )
    .bind(scope)
    .fetch_all(executor)
    .await?;
    Ok(rows)
}

pub async fn get_by_id(
    executor: impl sqlx::Executor<'_, Database = sqlx::Any>,
    id: &str,
) -> Result<Option<PolicyRuleRow>, AcmeError> {
    let row = super::query_as::<PolicyRuleRow>(
        "SELECT id, scope, name, rule_json, enabled, created_at, updated_at, created_by \
         FROM policy_rules WHERE id = ?",
    )
    .bind(id)
    .fetch_optional(executor)
    .await?;
    Ok(row)
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn open_db() -> crate::db::Db {
        crate::db::install_drivers();
        crate::db::open("sqlite::memory:", 1, false).await.unwrap()
    }

    fn test_row(id: &str, scope: &str, name: &str) -> PolicyRuleRow {
        PolicyRuleRow {
            id: id.into(),
            scope: scope.into(),
            name: name.into(),
            rule_json: r#"{"name":"test","type":"deny"}"#.into(),
            enabled: 1,
            created_at: "2026-07-28T00:00:00Z".into(),
            updated_at: "2026-07-28T00:00:00Z".into(),
            created_by: Some("admin".into()),
        }
    }

    #[tokio::test]
    async fn insert_and_get_by_id() {
        let db = open_db().await;
        let row = test_row("r1", "issuance", "deny-all");
        insert(&db, &row).await.unwrap();

        let found = get_by_id(&db, "r1").await.unwrap();
        assert!(found.is_some());
        let found = found.unwrap();
        assert_eq!(found.name, "deny-all");
        assert_eq!(found.scope, "issuance");
    }

    #[tokio::test]
    async fn get_by_id_returns_none_for_missing() {
        let db = open_db().await;
        let found = get_by_id(&db, "nonexistent").await.unwrap();
        assert!(found.is_none());
    }

    #[tokio::test]
    async fn list_by_scope_filters_and_orders() {
        let db = open_db().await;
        insert(&db, &test_row("r1", "issuance", "zebra"))
            .await
            .unwrap();
        insert(&db, &test_row("r2", "issuance", "alpha"))
            .await
            .unwrap();
        insert(&db, &test_row("r3", "other", "beta")).await.unwrap();

        let rows = list_by_scope(&db, "issuance").await.unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].name, "alpha");
        assert_eq!(rows[1].name, "zebra");
    }

    #[tokio::test]
    async fn list_scopes_returns_distinct() {
        let db = open_db().await;
        insert(&db, &test_row("r1", "issuance", "a")).await.unwrap();
        insert(&db, &test_row("r2", "issuance", "b")).await.unwrap();
        insert(&db, &test_row("r3", "revocation", "c"))
            .await
            .unwrap();

        let scopes = list_scopes(&db).await.unwrap();
        assert_eq!(scopes, vec!["issuance", "revocation"]);
    }

    #[tokio::test]
    async fn delete_returns_true_for_existing() {
        let db = open_db().await;
        insert(&db, &test_row("r1", "issuance", "test"))
            .await
            .unwrap();

        assert!(delete(&db, "r1").await.unwrap());
        assert!(!delete(&db, "r1").await.unwrap());
    }

    #[tokio::test]
    async fn update_modifies_fields() {
        let db = open_db().await;
        insert(&db, &test_row("r1", "issuance", "old-name"))
            .await
            .unwrap();

        let updated = update(&db, "r1", "new-name", "{}", 0, "2026-07-29T00:00:00Z")
            .await
            .unwrap();
        assert!(updated);

        let row = get_by_id(&db, "r1").await.unwrap().unwrap();
        assert_eq!(row.name, "new-name");
        assert_eq!(row.enabled, 0);
    }

    #[tokio::test]
    async fn get_by_scope_and_name_finds_match() {
        let db = open_db().await;
        insert(&db, &test_row("r1", "issuance", "target"))
            .await
            .unwrap();
        insert(&db, &test_row("r2", "other", "target"))
            .await
            .unwrap();

        let found = get_by_scope_and_name(&db, "issuance", "target")
            .await
            .unwrap();
        assert!(found.is_some());
        assert_eq!(found.unwrap().id, "r1");

        let missing = get_by_scope_and_name(&db, "issuance", "nonexistent")
            .await
            .unwrap();
        assert!(missing.is_none());
    }
}
