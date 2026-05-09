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
    /// Keys pre-allocated to a principal (bound_principal IS NOT NULL) but not
    /// yet consumed in an ACME new-account exchange (used_at IS NULL).
    pub eab_bound: i64,
    pub audit_total: i64,
}

pub async fn summary(
    executor: impl sqlx::Executor<'_, Database = sqlx::Any>,
) -> Result<StatsRow, AcmeError> {
    // One round-trip instead of sequential COUNT queries.
    let row: (i64, i64, i64, i64, i64, i64, i64, i64, i64) = sqlx::query_as(
        "SELECT \
           (SELECT COUNT(*) FROM accounts), \
           (SELECT COUNT(*) FROM accounts WHERE status = 'valid'), \
           (SELECT COUNT(*) FROM certificates), \
           (SELECT COUNT(*) FROM certificates WHERE status = 'valid'), \
           (SELECT COUNT(*) FROM certificates WHERE status = 'revoked'), \
           (SELECT COUNT(*) FROM eab_keys), \
           (SELECT COUNT(*) FROM eab_keys WHERE used_at IS NOT NULL), \
           (SELECT COUNT(*) FROM eab_keys WHERE bound_principal IS NOT NULL AND used_at IS NULL), \
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
        eab_bound: row.7,
        audit_total: row.8,
    })
}
