//! `akamu-cli import` subcommand.

pub mod certbot;

use std::{
    fs,
    path::{Path, PathBuf},
};

use crate::write_private_file;

/// Copy `src` to `dst` with mode 0o600 on the destination.
fn copy_private_file(src: &Path, dst: &Path) -> Result<(), String> {
    let data = fs::read(src).map_err(|e| format!("read {}: {e}", src.display()))?;
    write_private_file(dst, &data)
}

use certbot::{
    build_renewal_config, discover_accounts, discover_renewals, jwk_to_account_key,
    live_cert_paths, pem_key_type,
};

// ── clap args ─────────────────────────────────────────────────────────────────

/// Arguments for `akamu-cli import certbot`.
#[derive(clap::Args)]
pub struct CertbotImportArgs {
    /// Certbot configuration directory
    #[arg(long, default_value = "/etc/letsencrypt")]
    certbot_dir: PathBuf,

    /// Output path for the imported account key PEM (required unless --list)
    #[arg(long, value_name = "FILE")]
    account_key: Option<PathBuf>,

    /// Import only the account registered with this ACME server
    #[arg(long)]
    server: Option<String>,

    /// Limit certificate import to this domain (may be repeated; default: all)
    #[arg(long = "domain", short = 'd')]
    domains: Vec<String>,

    /// Directory to write imported certificate chains and keys
    #[arg(long, value_name = "DIR")]
    cert_dir: Option<PathBuf>,

    /// Challenge type for DNS-based certbot configs
    #[arg(long, default_value = "dns-01", value_name = "TYPE")]
    dns_challenge: String,

    /// Hook script for DNS TXT record management (stored in renewal config)
    #[arg(long, value_name = "CMD")]
    dns_hook: Option<String>,

    /// Show what would be done without writing any files
    #[arg(long)]
    dry_run: bool,

    /// List discoverable accounts and certificates, then exit
    #[arg(long)]
    list: bool,
}

// ── command handler ───────────────────────────────────────────────────────────

pub async fn cmd_import_certbot(args: CertbotImportArgs) -> Result<(), String> {
    let accounts = discover_accounts(&args.certbot_dir);
    let renewals = discover_renewals(&args.certbot_dir);

    // --list mode: just print and exit.
    if args.list {
        println!("Accounts found in {}:", args.certbot_dir.display());
        if accounts.is_empty() {
            println!("  (none)");
        }
        for acct in &accounts {
            let url = acct.account_url.as_deref().unwrap_or("(no URL)");
            let dt = acct.creation_dt.as_deref().unwrap_or("unknown date");
            println!(
                "  CA: {}  ID: {}  URL: {}  created: {}",
                acct.ca_hostname, acct.account_id, url, dt
            );
        }
        println!();
        println!("Renewals found:");
        if renewals.is_empty() {
            println!("  (none)");
        }
        for r in &renewals {
            println!(
                "  domain: {}  server: {}  challenge: {}",
                r.domain, r.server, r.authenticator
            );
        }
        return Ok(());
    }

    // Filter accounts by --server.
    let matching_accounts: Vec<&certbot::CertbotAccount> = if let Some(ref srv) = args.server {
        accounts
            .iter()
            .filter(|a| {
                a.account_url
                    .as_deref()
                    .map(|u| u.contains(srv.trim_end_matches('/')))
                    .unwrap_or(false)
                    || a.ca_hostname.contains(
                        srv.trim_start_matches("https://")
                            .split('/')
                            .next()
                            .unwrap_or(""),
                    )
            })
            .collect()
    } else {
        accounts.iter().collect()
    };

    if matching_accounts.is_empty() {
        return Err("no certbot accounts found; check --certbot-dir and --server".into());
    }

    if matching_accounts.len() > 1 && args.server.is_none() {
        eprintln!("Multiple certbot accounts found. Specify --server to select one:");
        for acct in &matching_accounts {
            let url = acct.account_url.as_deref().unwrap_or("(no URL)");
            let dt = acct.creation_dt.as_deref().unwrap_or("unknown date");
            eprintln!(
                "  CA: {}  ID: {}  URL: {}  created: {}",
                acct.ca_hostname, acct.account_id, url, dt
            );
        }
        return Err("use --server <URL> to select an account".into());
    }

    let acct = matching_accounts[0];

    // Convert account key.
    let account_key_path = args
        .account_key
        .as_ref()
        .ok_or("--account-key <FILE> is required")?;

    if account_key_path.exists() {
        return Err(format!(
            "{} already exists; remove it or choose a different --account-key path",
            account_key_path.display()
        ));
    }

    let account_key =
        jwk_to_account_key(&acct.jwk_json).map_err(|e| format!("convert account key: {e}"))?;
    let pem = account_key
        .to_pem()
        .map_err(|e| format!("export account key PEM: {e}"))?;

    if args.dry_run {
        println!(
            "[dry-run] Would write account key to {}",
            account_key_path.display()
        );
    } else {
        write_private_file(account_key_path, &pem)?;
        println!("Account key written to {}", account_key_path.display());
    }

    // Write .account-url sidecar.
    if let Some(ref url) = acct.account_url {
        let mut sidecar = account_key_path.clone().into_os_string();
        sidecar.push(".account-url");
        let sidecar = PathBuf::from(sidecar);
        if args.dry_run {
            println!("[dry-run] Would write account URL to {}", sidecar.display());
        } else {
            write_private_file(&sidecar, url.as_bytes())?;
            println!("Account URL written to {}", sidecar.display());
        }
    } else {
        eprintln!(
            "Warning: no account URL found in regr.json for account {}; \
             you may need to re-register with the CA.",
            acct.account_id
        );
    }

    // Filter renewals by --domain.
    let matching_renewals: Vec<&certbot::CertbotRenewal> = renewals
        .iter()
        .filter(|r| args.domains.is_empty() || args.domains.contains(&r.domain))
        .collect();

    if matching_renewals.is_empty() {
        println!("No renewal configurations found to import.");
        return Ok(());
    }

    let cert_dir = args
        .cert_dir
        .as_ref()
        .ok_or_else(|| "--cert-dir <DIR> is required when importing certificates".to_string())?;

    if !args.dry_run {
        fs::create_dir_all(cert_dir).map_err(|e| format!("create {}: {e}", cert_dir.display()))?;
    }

    let mut certs_imported = 0usize;
    for r in &matching_renewals {
        let domain = if r.domain.starts_with("_wildcard.") {
            format!("*.{}", &r.domain["_wildcard.".len()..])
        } else {
            r.domain.clone()
        };

        let (src_chain, src_key) = live_cert_paths(&args.certbot_dir, &domain);
        let cert_path = cert_dir.join(format!("{}.pem", r.domain));
        let cert_key_path = cert_dir.join(format!("{}.pem.key.pem", r.domain));

        // Copy fullchain.pem.
        let chain_ok = if src_chain.exists() {
            if args.dry_run {
                println!(
                    "[dry-run] Would copy {} → {}",
                    src_chain.display(),
                    cert_path.display()
                );
            } else {
                fs::copy(&src_chain, &cert_path)
                    .map_err(|e| format!("copy {}: {e}", src_chain.display()))?;
            }
            true
        } else {
            eprintln!(
                "Warning: {} not found (may need root access); skipping certificate copy",
                src_chain.display()
            );
            false
        };

        // Copy privkey.pem.
        let key_ok = if src_key.exists() {
            if args.dry_run {
                println!(
                    "[dry-run] Would copy {} → {}",
                    src_key.display(),
                    cert_key_path.display()
                );
            } else {
                copy_private_file(&src_key, &cert_key_path)?;
            }
            true
        } else {
            eprintln!(
                "Warning: {} not found (may need root access); skipping key copy",
                src_key.display()
            );
            false
        };

        if !args.dry_run && (!chain_ok || !key_ok) {
            eprintln!(
                "Warning: skipping renewal config for {domain}: \
                 certificate or key not available (may need root access)"
            );
            continue;
        }

        // Build and write RenewalConfig.
        let cert_key_type = if src_key.exists() {
            pem_key_type(&fs::read(&src_key).unwrap_or_default())
        } else {
            "ec:P-256".into()
        };
        let (renewal_cfg, warning) = build_renewal_config(
            r,
            &acct.jwk_json,
            account_key_path,
            &cert_path,
            &cert_key_path,
            &cert_key_type,
            &acct.contacts,
            &args.dns_challenge,
            args.dns_hook.as_deref(),
        );

        if let Some(warn) = warning {
            eprintln!("Note for {}: {warn}", domain);
        }

        // Warn when a DNS challenge type is selected but no hook script was provided.
        // The renewal will block interactively without a hook.
        if !args.dry_run
            && (renewal_cfg.challenge_type == "dns-01"
                || renewal_cfg.challenge_type == "dns-persist-01")
            && renewal_cfg.dns_hook.is_none()
        {
            eprintln!(
                "Warning for {domain}: challenge type '{}' requires a DNS hook script. \
                 Re-import with --dns-hook <CMD> or add dns_hook to the renewal config before renewing.",
                renewal_cfg.challenge_type
            );
        }

        let toml_str = toml::to_string_pretty(&renewal_cfg)
            .map_err(|e| format!("serialize renewal config for {}: {e}", domain))?;

        let mut renewal_path = cert_path.clone().into_os_string();
        renewal_path.push(".renewal.toml");
        let renewal_path = PathBuf::from(renewal_path);

        if args.dry_run {
            println!(
                "[dry-run] Would write renewal config to {}",
                renewal_path.display()
            );
        } else {
            write_private_file(&renewal_path, toml_str.as_bytes())?;
            println!("  {}  →  {}", domain, renewal_path.display());
            println!(
                "    To renew: akamu-cli renew --renewal-config {}",
                renewal_path.display()
            );
        }

        certs_imported += 1;
    }

    if !args.dry_run {
        println!();
        println!("Import complete: 1 account, {certs_imported} certificate(s).");
    }
    Ok(())
}
