//! JTI replay-prevention cache for RFC 9447 tkauth-01 authority tokens.

use crate::db::Db;

/// Insert a JTI into the replay-prevention cache.
///
/// Returns `true` if the JTI was new (insertion succeeded), `false` if it was
/// already present (replay detected).  Uses a portable `WHERE NOT EXISTS`
/// sub-query — the same technique as `db::eab::insert_if_absent` — so it works
/// identically on SQLite, PostgreSQL, and MariaDB.
///
/// `tkvalue` is the base64url-encoded JWTClaimConstraints DER blob from `atc.tkvalue`,
/// stored only for encoder-backed identifier types (e.g., "dns") so finalize can
/// retrieve and apply claim encoders when issuing the certificate.
///
/// `ca_flag` is the boolean value of `atc.ca` from the authority token.  Stored so
/// finalize can verify it matches the CSR's BasicConstraints cA field per
/// draft-ietf-acme-authority-token-jwtclaimcon §6 step 8.
pub async fn insert_jti(
    db: &Db,
    jti: &str,
    authz_id: &str,
    expires: i64,
    now: i64,
    tkvalue: Option<&str>,
    ca_flag: bool,
) -> Result<bool, sqlx::Error> {
    let result = super::query(
        "INSERT INTO tkauth_jti_cache (jti, authz_id, expires, created, tkvalue, ca_flag) \
         SELECT ?, ?, ?, ?, ?, ? \
         WHERE NOT EXISTS (SELECT 1 FROM tkauth_jti_cache WHERE jti = ?)",
    )
    .bind(jti)
    .bind(authz_id)
    .bind(expires)
    .bind(now)
    .bind(tkvalue)
    .bind(ca_flag)
    .bind(jti)
    .execute(db)
    .await?;
    Ok(result.rows_affected() > 0)
}

/// Return `true` if any JTI entry for the given authz_ids has `ca_flag = true`.
///
/// Used at finalize time to check whether the authority token(s) assert CA cert
/// issuance, so the result can be matched against the CSR's BasicConstraints cA field.
pub async fn get_any_ca_flag_for_authzs(db: &Db, authz_ids: &[&str]) -> Result<bool, sqlx::Error> {
    for authz_id in authz_ids {
        let row: (i64,) = super::query_as(
            "SELECT COUNT(*) FROM tkauth_jti_cache WHERE authz_id = ? AND ca_flag = 1",
        )
        .bind(authz_id)
        .fetch_one(db)
        .await?;
        if row.0 > 0 {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Return the stored tkvalue for a given authz_id, or `None` if not present.
///
/// Used at finalize time to retrieve the JWTClaimConstraints DER blob stored
/// during tkauth-01 validation of encoder-backed identifier types (e.g., dns).
pub async fn get_tkvalue_for_authz(db: &Db, authz_id: &str) -> Result<Option<String>, sqlx::Error> {
    let row: Option<(Option<String>,)> = super::query_as(
        "SELECT tkvalue FROM tkauth_jti_cache \
         WHERE authz_id = ? AND tkvalue IS NOT NULL LIMIT 1",
    )
    .bind(authz_id)
    .fetch_optional(db)
    .await?;
    Ok(row.and_then(|(v,)| v))
}

/// Delete expired JTI entries. Returns the count of deleted rows.
pub async fn purge_expired(db: &Db, now: i64) -> Result<u64, sqlx::Error> {
    let result = super::query("DELETE FROM tkauth_jti_cache WHERE expires < ?")
        .bind(now)
        .execute(db)
        .await?;
    Ok(result.rows_affected())
}

/// Return the minimum `expires` across all JTI entries whose `authz_id` is in
/// `authz_ids`.  Returns `None` when the list is empty or no matching rows exist.
///
/// Used at finalize time to enforce RFC 9447's SHOULD NOT: issued certificates
/// should not outlive the authority tokens that authorized them.
pub async fn get_min_exp_for_authzs(
    db: &Db,
    authz_ids: &[&str],
) -> Result<Option<i64>, sqlx::Error> {
    let mut min_exp: Option<i64> = None;
    for authz_id in authz_ids {
        // MIN() on an empty set returns NULL → Option<i64>.
        let row: (Option<i64>,) =
            super::query_as("SELECT MIN(expires) FROM tkauth_jti_cache WHERE authz_id = ?")
                .bind(authz_id)
                .fetch_one(db)
                .await?;
        if let Some(exp) = row.0 {
            min_exp = Some(min_exp.map_or(exp, |m| m.min(exp)));
        }
    }
    Ok(min_exp)
}

/// Count expired JTI entries without deleting (for dry-run).
pub async fn count_expired(db: &Db, now: i64) -> Result<i64, sqlx::Error> {
    let row: (i64,) = super::query_as("SELECT COUNT(*) FROM tkauth_jti_cache WHERE expires < ?")
        .bind(now)
        .fetch_one(db)
        .await?;
    Ok(row.0)
}
