//! Audit event persistence (FAU_STG.1).
//!
//! Records are append-only at the application level: this module contains no
//! UPDATE or DELETE on `audit_events` except `delete_oldest`, which is invoked
//! only by the overflow-management path in `crate::audit::record`.

use crate::error::AcmeError;

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct AuditEventRow {
    pub id: i64,
    pub occurred_at: String,
    pub event_type: String,
    pub subject: Option<String>,
    pub principal: Option<String>,
    pub outcome: String,
    pub detail: Option<String>,
}

pub async fn insert(
    executor: impl sqlx::Executor<'_, Database = sqlx::Any>,
    occurred_at: &str,
    event_type: &str,
    subject: Option<&str>,
    principal: Option<&str>,
    outcome: &str,
    detail: Option<&str>,
) -> Result<(), AcmeError> {
    sqlx::query(
        "INSERT INTO audit_events \
         (occurred_at, event_type, subject, principal, outcome, detail) \
         VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(occurred_at)
    .bind(event_type)
    .bind(subject)
    .bind(principal)
    .bind(outcome)
    .bind(detail)
    .execute(executor)
    .await?;
    Ok(())
}

/// Total number of audit event rows.
pub async fn count(
    executor: impl sqlx::Executor<'_, Database = sqlx::Any>,
) -> Result<i64, AcmeError> {
    let row: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM audit_events")
        .fetch_one(executor)
        .await?;
    Ok(row.0)
}

/// Count audit events within the last `window_secs` seconds.
pub async fn count_since(
    executor: impl sqlx::Executor<'_, Database = sqlx::Any>,
    since_rfc3339: &str,
) -> Result<i64, AcmeError> {
    let row: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM audit_events WHERE occurred_at >= ?",
    )
    .bind(since_rfc3339)
    .fetch_one(executor)
    .await?;
    Ok(row.0)
}

/// Delete the `n` oldest rows (lowest `id` values) to enforce the overflow cap.
pub async fn delete_oldest(
    executor: impl sqlx::Executor<'_, Database = sqlx::Any>,
    n: i64,
) -> Result<(), AcmeError> {
    // Wrap the inner SELECT in a derived-table alias so this works on
    // Postgres (rejects DELETE…WHERE id IN (SELECT…FROM same_table)) and
    // MariaDB (raises error 1093 for the same reason). SQLite accepts both.
    sqlx::query(
        "DELETE FROM audit_events WHERE id IN \
         (SELECT id FROM (SELECT id FROM audit_events ORDER BY id ASC LIMIT ?) AS _oldest)",
    )
    .bind(n)
    .execute(executor)
    .await?;
    Ok(())
}

/// Parameters for `query()`.  All filter fields are optional; omitting a field
/// means "no filter on this column".
pub struct AuditQuery<'a> {
    pub event_type: Option<&'a str>,
    pub subject: Option<&'a str>,
    pub from: Option<&'a str>,
    pub until: Option<&'a str>,
    pub outcome: Option<&'a str>,
    pub limit: i64,
    pub offset: i64,
}

/// Filtered, paginated query over `audit_events`.
///
/// Uses `sqlx::QueryBuilder` to emit bind parameters only for filters that are
/// `Some`, avoiding the `(? IS NULL OR col = ?)` pattern that misfires on
/// Postgres when an untyped NULL placeholder cannot be inferred.
pub async fn query(
    executor: impl sqlx::Executor<'_, Database = sqlx::Any>,
    q: &AuditQuery<'_>,
) -> Result<Vec<AuditEventRow>, AcmeError> {
    let mut qb = sqlx::QueryBuilder::<sqlx::Any>::new(
        "SELECT id, occurred_at, event_type, subject, principal, outcome, detail \
         FROM audit_events WHERE 1=1",
    );
    if let Some(t) = q.event_type {
        qb.push(" AND event_type = ");
        qb.push_bind(t);
    }
    if let Some(s) = q.subject {
        qb.push(" AND subject = ");
        qb.push_bind(s);
    }
    if let Some(f) = q.from {
        qb.push(" AND occurred_at >= ");
        qb.push_bind(f);
    }
    if let Some(u) = q.until {
        qb.push(" AND occurred_at <= ");
        qb.push_bind(u);
    }
    if let Some(o) = q.outcome {
        qb.push(" AND outcome = ");
        qb.push_bind(o);
    }
    qb.push(" ORDER BY id DESC LIMIT ");
    qb.push_bind(q.limit);
    qb.push(" OFFSET ");
    qb.push_bind(q.offset);

    let rows = qb
        .build_query_as::<AuditEventRow>()
        .fetch_all(executor)
        .await?;
    Ok(rows)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::Db;

    async fn open_db() -> Db {
        crate::db::install_drivers();
        crate::db::open("sqlite::memory:", 1).await.unwrap()
    }

    #[tokio::test]
    async fn insert_and_count() {
        let db = open_db().await;
        assert_eq!(count(&db).await.unwrap(), 0);
        insert(&db, "2026-01-01T00:00:00Z", "cert.issue", Some("acc1"), Some("alice"), "success", None)
            .await
            .unwrap();
        assert_eq!(count(&db).await.unwrap(), 1);
    }

    #[tokio::test]
    async fn delete_oldest_removes_rows() {
        let db = open_db().await;
        for i in 0..5i64 {
            insert(
                &db,
                &format!("2026-01-01T00:00:{:02}Z", i),
                "cert.issue",
                None,
                None,
                "success",
                None,
            )
            .await
            .unwrap();
        }
        assert_eq!(count(&db).await.unwrap(), 5);
        delete_oldest(&db, 2).await.unwrap();
        assert_eq!(count(&db).await.unwrap(), 3);
    }

    #[tokio::test]
    async fn query_filters_by_event_type() {
        let db = open_db().await;
        insert(&db, "2026-01-01T00:00:00Z", "cert.issue", None, None, "success", None)
            .await
            .unwrap();
        insert(&db, "2026-01-01T00:00:01Z", "auth.jws.fail", None, None, "failure", None)
            .await
            .unwrap();
        let q = AuditQuery {
            event_type: Some("cert.issue"),
            subject: None,
            from: None,
            until: None,
            outcome: None,
            limit: 100,
            offset: 0,
        };
        let rows = query(&db, &q).await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].event_type, "cert.issue");
    }

    #[tokio::test]
    async fn count_since_filters_by_time() {
        let db = open_db().await;
        insert(&db, "2026-01-01T00:00:00Z", "cert.issue", None, None, "success", None)
            .await
            .unwrap();
        insert(&db, "2026-06-01T00:00:00Z", "cert.issue", None, None, "success", None)
            .await
            .unwrap();
        let n = count_since(&db, "2026-06-01T00:00:00Z").await.unwrap();
        assert_eq!(n, 1);
    }
}
