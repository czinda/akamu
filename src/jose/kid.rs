//! Resolve a JWS `kid` URL to the account's SPKI DER bytes.

use tokio_rusqlite::Connection;

use crate::db;
use crate::error::AcmeError;

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
pub async fn spki_for_kid(
    db: &Connection,
    base_url: &str,
    kid: &str,
) -> Result<Vec<u8>, AcmeError> {
    let account_id = account_id_from_kid(base_url, kid)?;
    let account = db::accounts::get_by_id(db, &account_id)
        .await?
        .ok_or_else(|| AcmeError::Unauthorized("account not found".into()))?;

    if account.status != "valid" {
        return Err(AcmeError::Unauthorized(format!(
            "account status is '{}'",
            account.status
        )));
    }

    Ok(account.public_key)
}
