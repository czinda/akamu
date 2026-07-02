use akamu_client::AcmeClient;

use crate::args::{CaListArgs, CaShowArgs};

// ── ca list / ca show handlers ────────────────────────────────────────────────

pub(crate) async fn cmd_ca_list(args: CaListArgs) -> Result<(), String> {
    let base = strip_acme_path(&args.server);

    if args.admin_url.is_some() {
        eprintln!(
            "Note: admin CA listing requires akamuctl. \
             Showing the default CA reachable from the ACME directory."
        );
    }

    // Discover the default CA by fetching its directory.
    let dir_url = format!("{}/acme/directory", base);
    AcmeClient::new(&dir_url)
        .await
        .map_err(|e| format!("could not fetch directory at {dir_url}: {e}"))?;

    println!("{:<20} {:<8} DIRECTORY", "ID", "DEFAULT");
    println!("{:<20} {:<8} {}", "default", "yes", dir_url);
    println!();
    println!("Use 'akamuctl ca list' for a full CA list when multiple CAs are configured.");
    Ok(())
}

pub(crate) async fn cmd_ca_show(args: CaShowArgs) -> Result<(), String> {
    let base = strip_acme_path(&args.server);
    let dir_url = format!("{}/acme/{}/directory", base, args.ca);

    AcmeClient::new(&dir_url)
        .await
        .map_err(|e| format!("could not connect to CA '{}' at {dir_url}: {e}", args.ca))?;

    println!("CA:        {}", args.ca);
    println!("Directory: {}", dir_url);
    Ok(())
}

/// Strip the `/acme/...` suffix from a server URL to get the base URL.
///
/// `https://acme.example.com/acme/rsa/directory` → `https://acme.example.com`
/// `https://acme.example.com/acme/directory`      → `https://acme.example.com`
/// `https://acme.example.com`                     → `https://acme.example.com`
fn strip_acme_path(url: &str) -> String {
    // Find /acme/ prefix and strip everything from there.
    if let Some(idx) = url.find("/acme/") {
        url[..idx].to_string()
    } else if let Some(stripped) = url.strip_suffix("/acme") {
        stripped.to_string()
    } else {
        url.trim_end_matches('/').to_string()
    }
}
