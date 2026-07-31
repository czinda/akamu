//! Resolve a JWS `kid` URL to the account's SPKI DER bytes.

use crate::db;
use crate::db::Db;
use crate::error::AcmeError;
use crate::status::AccountStatus;

/// Extract the account ID from a `kid` URL of the form `<base_url>/acme/account/<id>`.
pub fn account_id_from_kid(base_url: &str, kid: &str) -> Result<String, AcmeError> {
    let prefix = format!("{}/acme/account/", base_url);
    if let Some(id) = kid.strip_prefix(&prefix) {
        if id.is_empty() {
            return Err(AcmeError::Unauthorized("kid account ID is empty".into()));
        }
        Ok(id.to_string())
    } else {
        Err(AcmeError::Unauthorized(format!(
            "kid '{}' does not match server base URL",
            kid
        )))
    }
}

/// Look up the SPKI DER bytes for the account referenced by `kid`.
///
/// Returns `Err(AcmeError::Unauthorized)` if the account does not exist,
/// is not active, or is deactivated.
pub async fn spki_for_kid(db: &Db, base_url: &str, kid: &str) -> Result<Vec<u8>, AcmeError> {
    let account_id = account_id_from_kid(base_url, kid)?;
    let account = db::accounts::get_by_id(db, &account_id)
        .await?
        .ok_or_else(|| AcmeError::Unauthorized("account not found".into()))?;

    if account.status.parse() != Ok(AccountStatus::Valid) {
        return Err(AcmeError::Unauthorized(format!(
            "account status is '{}'",
            account.status
        )));
    }

    Ok(account.public_key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn account_id_from_kid_valid() {
        let id = account_id_from_kid("https://acme.test", "https://acme.test/acme/account/abc123")
            .unwrap();
        assert_eq!(id, "abc123");
    }

    #[test]
    fn account_id_from_kid_wrong_base_url() {
        let result = account_id_from_kid(
            "https://acme.test",
            "https://other.example.com/acme/account/abc123",
        );
        assert!(result.is_err());
        match result.unwrap_err() {
            AcmeError::Unauthorized(msg) => assert!(msg.contains("does not match server base URL")),
            other => panic!("expected Unauthorized, got {other:?}"),
        }
    }

    #[test]
    fn account_id_from_kid_empty_id() {
        // URL matches prefix but account ID is empty.
        let result = account_id_from_kid("https://acme.test", "https://acme.test/acme/account/");
        assert!(result.is_err());
        match result.unwrap_err() {
            AcmeError::Unauthorized(msg) => assert!(msg.contains("empty")),
            other => panic!("expected Unauthorized, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn spki_for_kid_account_not_found() {
        crate::db::install_drivers();
        let db = crate::db::open("sqlite::memory:", 1, false).await.unwrap();
        let result = spki_for_kid(
            &db,
            "https://acme.test",
            "https://acme.test/acme/account/nonexistent",
        )
        .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            AcmeError::Unauthorized(msg) => assert!(msg.contains("account not found")),
            other => panic!("expected Unauthorized, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn spki_for_kid_deactivated_account_returns_error() {
        use crate::db::schema::AccountRow;
        crate::db::install_drivers();
        let db = crate::db::open("sqlite::memory:", 1, false).await.unwrap();
        crate::db::accounts::insert(
            &db,
            AccountRow {
                id: "deact-acct".to_string(),
                status: "deactivated".to_string(),
                contact: None,
                public_key: vec![0u8; 4],
                jwk_thumbprint: "thumb-deact".to_string(),
                created: 1_700_000_000,
                updated: 1_700_000_000,
                profile_grants: None,
                ca_id: String::new(),
                kerberos_principal: None,
            },
        )
        .await
        .unwrap();

        let result = spki_for_kid(
            &db,
            "https://acme.test",
            "https://acme.test/acme/account/deact-acct",
        )
        .await;
        assert!(result.is_err());
        match result.unwrap_err() {
            AcmeError::Unauthorized(msg) => assert!(msg.contains("deactivated")),
            other => panic!("expected Unauthorized, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn spki_for_kid_valid_account_returns_spki() {
        use crate::db::schema::AccountRow;
        crate::db::install_drivers();
        let db = crate::db::open("sqlite::memory:", 1, false).await.unwrap();
        let spki = vec![0xDE, 0xAD, 0xBE, 0xEF];
        crate::db::accounts::insert(
            &db,
            AccountRow {
                id: "valid-acct".to_string(),
                status: "valid".to_string(),
                contact: None,
                public_key: spki.clone(),
                jwk_thumbprint: "thumb-valid".to_string(),
                created: 1_700_000_000,
                updated: 1_700_000_000,
                profile_grants: None,
                ca_id: String::new(),
                kerberos_principal: None,
            },
        )
        .await
        .unwrap();

        let result = spki_for_kid(
            &db,
            "https://acme.test",
            "https://acme.test/acme/account/valid-acct",
        )
        .await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), spki);
    }
}
