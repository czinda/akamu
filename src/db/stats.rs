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
    pool: &sqlx::AnyPool,
    ca_id_filter: Option<&str>,
) -> Result<StatsRow, AcmeError> {
    // Global counts that are never scoped to a single CA.
    let global: (i64, i64, i64, i64, i64, i64) = super::query_as(
        "SELECT \
           (SELECT COUNT(*) FROM accounts), \
           (SELECT COUNT(*) FROM accounts WHERE status = 'valid'), \
           (SELECT COUNT(*) FROM eab_keys), \
           (SELECT COUNT(*) FROM eab_keys WHERE used_at IS NOT NULL), \
           (SELECT COUNT(*) FROM eab_keys WHERE bound_principal IS NOT NULL AND used_at IS NULL), \
           (SELECT COUNT(*) FROM audit_events)",
    )
    .fetch_one(pool)
    .await?;

    // Cert counts, optionally scoped to a specific CA for ca_ra operators.
    let cert_total: (i64,) = {
        let mut qb = super::DynQueryBuilder::new("SELECT COUNT(*) FROM certificates WHERE 1=1");
        if let Some(ca_id) = ca_id_filter {
            qb.push(" AND ca_id = ");
            qb.push_bind(ca_id);
        }
        qb.fetch_one(pool).await?
    };
    let cert_active: (i64,) = {
        let mut qb =
            super::DynQueryBuilder::new("SELECT COUNT(*) FROM certificates WHERE status = 'valid'");
        if let Some(ca_id) = ca_id_filter {
            qb.push(" AND ca_id = ");
            qb.push_bind(ca_id);
        }
        qb.fetch_one(pool).await?
    };
    let cert_revoked: (i64,) = {
        let mut qb = super::DynQueryBuilder::new(
            "SELECT COUNT(*) FROM certificates WHERE status = 'revoked'",
        );
        if let Some(ca_id) = ca_id_filter {
            qb.push(" AND ca_id = ");
            qb.push_bind(ca_id);
        }
        qb.fetch_one(pool).await?
    };

    Ok(StatsRow {
        account_total: global.0,
        account_active: global.1,
        cert_total: cert_total.0,
        cert_active: cert_active.0,
        cert_revoked: cert_revoked.0,
        eab_total: global.2,
        eab_used: global.3,
        eab_bound: global.4,
        audit_total: global.5,
    })
}
