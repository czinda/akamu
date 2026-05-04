//! Session management subcommands (akamuctl login / logout).

use std::sync::{Arc, Mutex};

use crate::client::AdminClient;
use crate::config::SessionCache;
use crate::derive_spn;
use crate::error::CtlError;
use crate::output::{print, Format};

/// Authenticate to the server admin API and cache the resulting session token.
///
/// Uses GSSAPI/Negotiate when `gssapi` is `true`, otherwise relies on the mTLS
/// client certificate configured in the session cache or command-line flags.
pub async fn login(
    server_url: &str,
    ca_cert_bytes: Option<Vec<u8>>,
    session_cache: Arc<Mutex<SessionCache>>,
    gssapi: bool,
    gssapi_service: Option<String>,
    server_client: &AdminClient,
    fmt: &Format,
) -> Result<(), CtlError> {
    if gssapi {
        let spn = match gssapi_service {
            Some(s) => s,
            None => derive_spn(server_url).await,
        };
        let gss_client = AdminClient::new(
            server_url.to_owned(),
            ca_cert_bytes,
            None,
            None,
            session_cache,
            false,
            Some(spn),
        )?;
        let resp = gss_client.post("/admin/session", None).await?;
        print(fmt, &resp);
    } else {
        let resp = server_client.post("/admin/session", None).await?;
        print(fmt, &resp);
    }
    Ok(())
}

/// Invalidate the current server session and clear the local token cache.
pub async fn logout(client: &AdminClient) -> Result<(), CtlError> {
    client.delete("/admin/session").await?;
    client.clear_session();
    println!("logged out");
    Ok(())
}
