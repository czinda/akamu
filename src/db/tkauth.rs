//! JTI replay-prevention cache for RFC 9447 tkauth-01 authority tokens.

use crate::db::Db;
use crate::error::AcmeError;

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
///
/// Checks all `authz_ids` in a single `WHERE ... IN (...)` query instead of one
/// round-trip per authz_id.
pub async fn get_any_ca_flag_for_authzs(db: &Db, authz_ids: &[&str]) -> Result<bool, AcmeError> {
    if authz_ids.is_empty() {
        return Ok(false);
    }
    let mut qb = super::DynQueryBuilder::new(
        "SELECT COUNT(*) FROM tkauth_jti_cache WHERE ca_flag = 1 AND authz_id IN (",
    );
    for (i, authz_id) in authz_ids.iter().enumerate() {
        if i > 0 {
            qb.push(", ");
        }
        qb.push_bind(*authz_id);
    }
    qb.push(")");
    let row: (i64,) = qb.fetch_one(db).await?;
    Ok(row.0 > 0)
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
///
/// Checks all `authz_ids` in a single `WHERE ... IN (...)` query instead of one
/// round-trip per authz_id.
pub async fn get_min_exp_for_authzs(db: &Db, authz_ids: &[&str]) -> Result<Option<i64>, AcmeError> {
    if authz_ids.is_empty() {
        return Ok(None);
    }
    let mut qb = super::DynQueryBuilder::new(
        "SELECT MIN(expires) FROM tkauth_jti_cache WHERE authz_id IN (",
    );
    for (i, authz_id) in authz_ids.iter().enumerate() {
        if i > 0 {
            qb.push(", ");
        }
        qb.push_bind(*authz_id);
    }
    qb.push(")");
    // MIN() on an empty/all-NULL set returns NULL → Option<i64>.
    let row: (Option<i64>,) = qb.fetch_one(db).await?;
    Ok(row.0)
}

/// Count expired JTI entries without deleting (for dry-run).
pub async fn count_expired(db: &Db, now: i64) -> Result<i64, sqlx::Error> {
    let row: (i64,) = super::query_as("SELECT COUNT(*) FROM tkauth_jti_cache WHERE expires < ?")
        .bind(now)
        .fetch_one(db)
        .await?;
    Ok(row.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn open_db() -> Db {
        crate::db::install_drivers();
        crate::db::open("sqlite::memory:", 1, false).await.unwrap()
    }

    #[tokio::test]
    async fn get_any_ca_flag_for_authzs_empty_input_returns_false() {
        let db = open_db().await;
        assert!(!get_any_ca_flag_for_authzs(&db, &[]).await.unwrap());
    }

    #[tokio::test]
    async fn get_any_ca_flag_for_authzs_true_when_one_of_several_matches() {
        let db = open_db().await;
        insert_jti(&db, "jti-1", "authz-1", 2_000_000_000, 1_000, None, false)
            .await
            .unwrap();
        insert_jti(&db, "jti-2", "authz-2", 2_000_000_000, 1_000, None, true)
            .await
            .unwrap();

        // authz-1 has ca_flag=false, authz-3 has no entry at all — the batch
        // query must still find authz-2's ca_flag=true among the three.
        let result = get_any_ca_flag_for_authzs(&db, &["authz-1", "authz-2", "authz-3"])
            .await
            .unwrap();
        assert!(result);
    }

    #[tokio::test]
    async fn get_any_ca_flag_for_authzs_false_when_none_match() {
        let db = open_db().await;
        insert_jti(&db, "jti-3", "authz-4", 2_000_000_000, 1_000, None, false)
            .await
            .unwrap();

        let result = get_any_ca_flag_for_authzs(&db, &["authz-4", "authz-5"])
            .await
            .unwrap();
        assert!(!result);
    }

    #[tokio::test]
    async fn get_min_exp_for_authzs_empty_input_returns_none() {
        let db = open_db().await;
        assert_eq!(get_min_exp_for_authzs(&db, &[]).await.unwrap(), None);
    }

    #[tokio::test]
    async fn get_min_exp_for_authzs_returns_minimum_across_authzs() {
        let db = open_db().await;
        insert_jti(&db, "jti-4", "authz-6", 5_000, 1_000, None, false)
            .await
            .unwrap();
        insert_jti(&db, "jti-5", "authz-7", 3_000, 1_000, None, false)
            .await
            .unwrap();
        insert_jti(&db, "jti-6", "authz-7", 9_000, 1_000, None, false)
            .await
            .unwrap();

        // authz-6 contributes 5_000, authz-7 contributes min(3_000, 9_000);
        // authz-8 has no entries. The overall minimum must be 3_000.
        let result = get_min_exp_for_authzs(&db, &["authz-6", "authz-7", "authz-8"])
            .await
            .unwrap();
        assert_eq!(result, Some(3_000));
    }

    #[tokio::test]
    async fn get_min_exp_for_authzs_no_matching_rows_returns_none() {
        let db = open_db().await;
        let result = get_min_exp_for_authzs(&db, &["nonexistent"]).await.unwrap();
        assert_eq!(result, None);
    }
}
