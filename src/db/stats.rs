//! Server-wide aggregate statistics queries (for GET /admin/stats).

use crate::error::AcmeError;

pub struct StatsRow {
    pub account_total: i64,
    pub account_active: i64,
    pub cert_total: i64,
    pub cert_active: i64,
    pub cert_revoked: i64,
    pub eab_total: i64,
    pub eab_used: i64,
    pub audit_total: i64,
}

pub async fn summary(
    executor: impl sqlx::Executor<'_, Database = sqlx::Any>,
) -> Result<StatsRow, AcmeError> {
    // One round-trip instead of eight sequential COUNT queries.
    let row: (i64, i64, i64, i64, i64, i64, i64, i64) = sqlx::query_as(
        "SELECT \
           (SELECT COUNT(*) FROM accounts), \
           (SELECT COUNT(*) FROM accounts WHERE status = 'valid'), \
           (SELECT COUNT(*) FROM certificates), \
           (SELECT COUNT(*) FROM certificates WHERE status = 'valid'), \
           (SELECT COUNT(*) FROM certificates WHERE status = 'revoked'), \
           (SELECT COUNT(*) FROM eab_keys), \
           (SELECT COUNT(*) FROM eab_keys WHERE used_at IS NOT NULL), \
           (SELECT COUNT(*) FROM audit_events)",
    )
    .fetch_one(executor)
    .await?;

    Ok(StatsRow {
        account_total: row.0,
        account_active: row.1,
        cert_total: row.2,
        cert_active: row.3,
        cert_revoked: row.4,
        eab_total: row.5,
        eab_used: row.6,
        audit_total: row.7,
    })
}
