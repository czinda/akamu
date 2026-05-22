//! tkauth subcommands (akamuctl tkauth …).

use crate::client::AdminClient;
use crate::error::CtlError;

/// Delete expired entries from the tkauth JTI replay-prevention cache.
///
/// With `dry_run = true`, prints the count without deleting.
pub async fn prune_jti(client: &AdminClient, dry_run: bool) -> Result<(), CtlError> {
    let path = if dry_run {
        "/admin/tkauth/prune-jti?dry_run=true"
    } else {
        "/admin/tkauth/prune-jti"
    };
    let resp = client.post(path, None).await?;
    if dry_run {
        let n = resp["would_delete"].as_u64().unwrap_or(0);
        println!(
            "Would delete {n} expired JTI entr{}",
            if n == 1 { "y" } else { "ies" }
        );
    } else {
        let n = resp["deleted"].as_u64().unwrap_or(0);
        println!(
            "Deleted {n} expired JTI entr{}",
            if n == 1 { "y" } else { "ies" }
        );
    }
    Ok(())
}
