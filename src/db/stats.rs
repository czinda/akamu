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
    executor: impl sqlx::Executor<'_, Database = sqlx::Any> + Copy,
) -> Result<StatsRow, AcmeError> {
    let account_total: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM accounts")
        .fetch_one(executor)
        .await?;
    let account_active: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM accounts WHERE status = 'valid'")
            .fetch_one(executor)
            .await?;
    let cert_total: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM certificates")
        .fetch_one(executor)
        .await?;
    let cert_active: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM certificates WHERE status = 'valid'")
            .fetch_one(executor)
            .await?;
    let cert_revoked: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM certificates WHERE status = 'revoked'")
            .fetch_one(executor)
            .await?;
    let eab_total: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM eab_keys")
        .fetch_one(executor)
        .await?;
    let eab_used: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM eab_keys WHERE used_at IS NOT NULL")
            .fetch_one(executor)
            .await?;
    let audit_total: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM audit_events")
        .fetch_one(executor)
        .await?;

    Ok(StatsRow {
        account_total: account_total.0,
        account_active: account_active.0,
        cert_total: cert_total.0,
        cert_active: cert_active.0,
        cert_revoked: cert_revoked.0,
        eab_total: eab_total.0,
        eab_used: eab_used.0,
        audit_total: audit_total.0,
    })
}
