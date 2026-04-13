//! `akamu-cli` — ACME client CLI with ML-DSA account key support.
//!
//! # Commands
//!
//! ```text
//! akamu-cli account register  [--server <URL>] --account-key <FILE> ...
//! akamu-cli account deregister [--server <URL>] --account-key <FILE>
//! akamu-cli issue             [--server <URL>] --domain <DOMAIN> ...
//! akamu-cli renew             [--server <URL>] --domain <DOMAIN> ... [--cert <FILE>] [--force]
//! akamu-cli revoke            [--server <URL>] --account-key <FILE> --cert <FILE>
//! ```

use std::{
    fs,
    path::{Path, PathBuf},
    sync::Arc,
};

use akamu_client::{
    AccountKey, AccountOptions, AcmeClient, ChallengeSolver as _, Dns01Helper, DnsPersist01Helper,
    EabOptions, Http01Solver, Identifier, TlsAlpn01Solver,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use clap::{Parser, Subcommand};

// ── CLI definition ─────────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(
    name = "akamu-cli",
    about = "ACME client with ML-DSA account key support"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Account management (register / deregister)
    Account {
        #[command(subcommand)]
        cmd: AccountCommands,
    },
    /// Issue a certificate for one or more domains
    Issue(IssueArgs),
    /// Renew a certificate, checking ARI (RFC 9773) before issuing
    Renew(RenewArgs),
    /// Revoke an issued certificate
    Revoke(RevokeArgs),
}

#[derive(Subcommand)]
enum AccountCommands {
    /// Register a new ACME account
    Register(RegisterArgs),
    /// Deactivate an existing ACME account (RFC 8555 §7.3.7)
    Deregister(DeregisterArgs),
    /// Show current account details
    Show(ShowArgs),
    /// Update account contacts
    Update(UpdateArgs),
    /// Roll the account key to a new key
    KeyChange(KeyChangeArgs),
}

// ── Shared flags ──────────────────────────────────────────────────────────────

/// EAB flags — shared between `account register` and `issue` (inline registration).
#[derive(clap::Args, Default)]
struct EabFlags {
    /// External Account Binding key ID (required when server mandates EAB)
    #[arg(long)]
    eab_kid: Option<String>,

    /// EAB HMAC key, base64url-encoded (no padding)
    #[arg(long)]
    eab_key: Option<String>,

    /// EAB HMAC algorithm: HS256 | HS384 | HS512 (default: HS256)
    #[arg(long, default_value = "HS256")]
    eab_alg: String,
}

impl EabFlags {
    fn to_eab_options(&self) -> Result<Option<(String, Vec<u8>, String)>, String> {
        match (&self.eab_kid, &self.eab_key) {
            (Some(kid), Some(key_b64u)) => {
                let hmac_key = URL_SAFE_NO_PAD
                    .decode(key_b64u)
                    .map_err(|e| format!("--eab-key base64url decode: {e}"))?;
                Ok(Some((kid.clone(), hmac_key, self.eab_alg.clone())))
            }
            (None, None) => Ok(None),
            _ => Err("--eab-kid and --eab-key must both be provided".into()),
        }
    }
}

// ── register ──────────────────────────────────────────────────────────────────

#[derive(clap::Args)]
struct RegisterArgs {
    /// ACME directory URL
    #[arg(long, default_value = "https://acme-v02.api.letsencrypt.org/directory")]
    server: String,

    /// PEM file for the account key (generated and saved if absent)
    #[arg(long)]
    account_key: PathBuf,

    /// Account key type (used when generating a new key)
    #[arg(long, default_value = "ec:P-256")]
    key_type: String,

    /// Contact URI (e.g. "mailto:admin@example.com"); may be repeated
    #[arg(long = "contact")]
    contacts: Vec<String>,

    /// Agree to the server's terms of service
    #[arg(long)]
    agree_tos: bool,

    #[command(flatten)]
    eab: EabFlags,
}

// ── deregister ────────────────────────────────────────────────────────────────

#[derive(clap::Args)]
struct DeregisterArgs {
    /// ACME directory URL
    #[arg(long, default_value = "https://acme-v02.api.letsencrypt.org/directory")]
    server: String,

    /// PEM file for the account key
    #[arg(long)]
    account_key: PathBuf,
}

// ── show ──────────────────────────────────────────────────────────────────────

#[derive(clap::Args)]
struct ShowArgs {
    /// ACME directory URL
    #[arg(long, default_value = "https://acme-v02.api.letsencrypt.org/directory")]
    server: String,

    /// PEM file for the account key
    #[arg(long)]
    account_key: PathBuf,
}

// ── update ────────────────────────────────────────────────────────────────────

#[derive(clap::Args)]
struct UpdateArgs {
    /// ACME directory URL
    #[arg(long, default_value = "https://acme-v02.api.letsencrypt.org/directory")]
    server: String,

    /// PEM file for the account key
    #[arg(long)]
    account_key: PathBuf,

    /// New contact URI (e.g. "mailto:admin@example.com"); may be repeated; pass none to clear
    #[arg(long = "contact")]
    contacts: Vec<String>,
}

// ── key-change ────────────────────────────────────────────────────────────────

#[derive(clap::Args)]
struct KeyChangeArgs {
    /// ACME directory URL
    #[arg(long, default_value = "https://acme-v02.api.letsencrypt.org/directory")]
    server: String,

    /// Current account key PEM file
    #[arg(long)]
    account_key: PathBuf,

    /// New key PEM file; generated if absent
    #[arg(long)]
    new_key: PathBuf,

    /// Key type for generating a new key (ignored if --new-key file exists)
    #[arg(long, default_value = "ec:P-256")]
    new_key_type: String,
}

// ── issue ─────────────────────────────────────────────────────────────────────

#[derive(clap::Args)]
struct IssueArgs {
    /// ACME directory URL
    #[arg(long, default_value = "https://acme-v02.api.letsencrypt.org/directory")]
    server: String,

    /// Domain name; may be repeated (first domain → CN)
    #[arg(long = "domain", short = 'd')]
    domains: Vec<String>,

    /// Account key type (used when generating a new account key)
    #[arg(long, default_value = "ec:P-256")]
    key_type: String,

    /// PEM file for the account key (generated and saved if absent)
    #[arg(long)]
    account_key: PathBuf,

    /// Certificate key type (used when generating the CSR signing key)
    #[arg(long = "cert-key-type", default_value = "ec:P-256")]
    cert_key_type: String,

    /// Challenge type: http-01 | dns-01 | dns-persist-01 | tls-alpn-01 | onion-csr-01
    #[arg(long = "challenge", default_value = "http-01")]
    challenge_type: String,

    /// Port to serve http-01 challenges on (default 80)
    #[arg(long, default_value_t = 80)]
    http_port: u16,

    /// Port to serve tls-alpn-01 challenges on (default 443)
    #[arg(long, default_value_t = 443)]
    tls_port: u16,

    /// Ed25519 hidden-service key PEM file for onion-csr-01 challenges
    #[arg(long, value_name = "FILE")]
    onion_key: Option<std::path::PathBuf>,

    /// Maximum seconds to wait for order/challenge validation (default: 120)
    #[arg(long, default_value_t = 120)]
    poll_timeout: u64,

    /// PEM file for the certificate private key.
    /// Generated and saved as `<out>.key.pem` if absent; supply to reuse an existing key.
    #[arg(long)]
    cert_key: Option<PathBuf>,

    /// Write the PEM certificate chain to this file
    #[arg(long)]
    out: PathBuf,

    #[command(flatten)]
    eab: EabFlags,
}

// ── renew ─────────────────────────────────────────────────────────────────────

#[derive(clap::Args)]
struct RenewArgs {
    /// ACME directory URL
    #[arg(long, default_value = "https://acme-v02.api.letsencrypt.org/directory")]
    server: String,

    /// Domain name; may be repeated (first domain → CN)
    #[arg(long = "domain", short = 'd')]
    domains: Vec<String>,

    /// Account key type (used when generating a new account key)
    #[arg(long, default_value = "ec:P-256")]
    key_type: String,

    /// PEM file for the account key (generated and saved if absent)
    #[arg(long)]
    account_key: PathBuf,

    /// Certificate key type (used when generating the CSR signing key)
    #[arg(long = "cert-key-type", default_value = "ec:P-256")]
    cert_key_type: String,

    /// Challenge type: http-01 | dns-01 | dns-persist-01 | tls-alpn-01 | onion-csr-01
    #[arg(long = "challenge", default_value = "http-01")]
    challenge_type: String,

    /// Port to serve http-01 challenges on (default 80)
    #[arg(long, default_value_t = 80)]
    http_port: u16,

    /// Port to serve tls-alpn-01 challenges on (default 443)
    #[arg(long, default_value_t = 443)]
    tls_port: u16,

    /// Ed25519 hidden-service key PEM file for onion-csr-01 challenges
    #[arg(long, value_name = "FILE")]
    onion_key: Option<std::path::PathBuf>,

    /// Write the PEM certificate chain to this file
    #[arg(long)]
    out: PathBuf,

    /// Existing certificate PEM to check ARI renewal window against
    #[arg(long)]
    cert: Option<PathBuf>,

    /// Renew unconditionally, skipping the ARI window check
    #[arg(long)]
    force: bool,

    /// Maximum seconds to wait for order/challenge validation (default: 120)
    #[arg(long, default_value_t = 120)]
    poll_timeout: u64,

    #[command(flatten)]
    eab: EabFlags,
}

// ── revoke ────────────────────────────────────────────────────────────────────

#[derive(clap::Args)]
struct RevokeArgs {
    /// ACME directory URL
    #[arg(long, default_value = "https://acme-v02.api.letsencrypt.org/directory")]
    server: String,

    /// PEM file for the account key
    #[arg(long)]
    account_key: PathBuf,

    /// PEM file containing the certificate to revoke
    #[arg(long)]
    cert: PathBuf,

    /// CRL reason code (0–6, 8–10; omit for unspecified)
    #[arg(long)]
    reason: Option<u8>,

    /// PEM file for the certificate's private key (use instead of --account-key for self-revocation)
    #[arg(long)]
    cert_key: Option<PathBuf>,
}

// ── entry point ───────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("akamu_client=info".parse().unwrap()),
        )
        .init();

    let cli = Cli::parse();
    if let Err(e) = run(cli).await {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

async fn run(cli: Cli) -> Result<(), String> {
    match cli.command {
        Commands::Account { cmd } => match cmd {
            AccountCommands::Register(args) => cmd_register(args).await,
            AccountCommands::Deregister(args) => cmd_deregister(args).await,
            AccountCommands::Show(args) => cmd_show(args).await,
            AccountCommands::Update(args) => cmd_update(args).await,
            AccountCommands::KeyChange(args) => cmd_key_change(args).await,
        },
        Commands::Issue(args) => cmd_issue(args).await,
        Commands::Renew(args) => cmd_renew(args).await,
        Commands::Revoke(args) => cmd_revoke(args).await,
    }
}

// ── account register ──────────────────────────────────────────────────────────

async fn cmd_register(args: RegisterArgs) -> Result<(), String> {
    let key = load_or_generate_key(&args.account_key, &args.key_type)?;
    let key = Arc::new(key);

    let client = AcmeClient::new(&args.server)
        .await
        .map_err(|e| e.to_string())?;

    let eab = build_eab_options(&args.eab)?;
    let contact_refs: Vec<&str> = args.contacts.iter().map(String::as_str).collect();

    let opts = AccountOptions {
        contacts: &contact_refs,
        agree_tos: args.agree_tos,
        eab: eab.as_ref().map(|(kid, hmac, alg)| EabOptions {
            kid,
            hmac_key: hmac,
            alg,
        }),
    };

    let account = client
        .new_account(Arc::clone(&key), &opts)
        .await
        .map_err(|e| e.to_string())?;

    save_account_url(&args.account_key, &account.url)?;
    println!("Registered: {}", account.url);
    Ok(())
}

// ── account deregister ────────────────────────────────────────────────────────

async fn cmd_deregister(args: DeregisterArgs) -> Result<(), String> {
    let key = load_key(&args.account_key)?;
    let key = Arc::new(key);
    let account_url = load_account_url(&args.account_key)?;

    let client = AcmeClient::new(&args.server)
        .await
        .map_err(|e| e.to_string())?;

    // Reconstruct a minimal Account with the stored URL.
    let account = akamu_client::Account::new(account_url.clone(), "valid".to_string(), vec![], key);

    client
        .deactivate_account(&account)
        .await
        .map_err(|e| e.to_string())?;

    // Remove the stored account URL.
    let url_path = account_url_path(&args.account_key);
    let _ = fs::remove_file(&url_path);
    println!("Deactivated: {account_url}");
    Ok(())
}

// ── account show ──────────────────────────────────────────────────────────────

async fn cmd_show(args: ShowArgs) -> Result<(), String> {
    let key = load_key(&args.account_key)?;
    let key = Arc::new(key);
    let account_url = load_account_url(&args.account_key)?;

    let client = AcmeClient::new(&args.server)
        .await
        .map_err(|e| e.to_string())?;
    let account = akamu_client::Account::new(account_url, "valid".into(), vec![], key);
    let account = client
        .get_account(&account)
        .await
        .map_err(|e| e.to_string())?;

    println!("URL:     {}", account.url);
    println!("Status:  {}", account.status);
    if account.contacts.is_empty() {
        println!("Contact: (none)");
    } else {
        for c in &account.contacts {
            println!("Contact: {c}");
        }
    }
    Ok(())
}

// ── account update ────────────────────────────────────────────────────────────

async fn cmd_update(args: UpdateArgs) -> Result<(), String> {
    let key = load_key(&args.account_key)?;
    let key = Arc::new(key);
    let account_url = load_account_url(&args.account_key)?;

    let client = AcmeClient::new(&args.server)
        .await
        .map_err(|e| e.to_string())?;
    let account = akamu_client::Account::new(account_url, "valid".into(), vec![], key);
    let contact_refs: Vec<&str> = args.contacts.iter().map(String::as_str).collect();
    let updated = client
        .update_account(&account, &contact_refs)
        .await
        .map_err(|e| e.to_string())?;

    println!("Updated account: {}", updated.url);
    for c in &updated.contacts {
        println!("  Contact: {c}");
    }
    Ok(())
}

// ── account key-change ────────────────────────────────────────────────────────

async fn cmd_key_change(args: KeyChangeArgs) -> Result<(), String> {
    let old_key = load_key(&args.account_key)?;
    let old_key = Arc::new(old_key);
    let account_url = load_account_url(&args.account_key)?;

    let new_key = load_or_generate_key(&args.new_key, &args.new_key_type)?;
    let new_key = Arc::new(new_key);

    let client = AcmeClient::new(&args.server)
        .await
        .map_err(|e| e.to_string())?;
    let account = akamu_client::Account::new(account_url.clone(), "valid".into(), vec![], old_key);
    let _updated = client
        .key_change(&account, Arc::clone(&new_key))
        .await
        .map_err(|e| e.to_string())?;

    // Overwrite the account key file with the new key.
    let new_pem = new_key.to_pem().map_err(|e| e.to_string())?;
    fs::write(&args.account_key, &new_pem)
        .map_err(|e| format!("write {}: {e}", args.account_key.display()))?;
    // The account URL stays the same — sidecar file is unchanged.
    println!(
        "Key changed. New key written to {}",
        args.account_key.display()
    );
    println!("Account URL unchanged: {account_url}");
    Ok(())
}

// ── poll helper ───────────────────────────────────────────────────────────────

/// Poll for order completion with a configurable timeout.
async fn poll_with_timeout(
    client: &AcmeClient,
    account: &akamu_client::Account,
    order_url: &str,
    timeout_secs: u64,
) -> Result<akamu_client::Order, String> {
    tokio::time::timeout(
        tokio::time::Duration::from_secs(timeout_secs),
        client.poll_order(account, order_url),
    )
    .await
    .map_err(|_| format!("timed out after {timeout_secs}s waiting for order"))?
    .map_err(|e| e.to_string())
}

// ── issue ─────────────────────────────────────────────────────────────────────

async fn cmd_issue(args: IssueArgs) -> Result<(), String> {
    if args.domains.is_empty() {
        return Err("at least one --domain is required".into());
    }

    // Load or generate the account key.
    let key = load_or_generate_key(&args.account_key, &args.key_type)?;
    let key = Arc::new(key);

    let client = AcmeClient::new(&args.server)
        .await
        .map_err(|e| e.to_string())?;

    // Load existing account or register a new one.
    let account = if let Ok(url) = load_account_url(&args.account_key) {
        akamu_client::Account::new(url, "valid".to_string(), vec![], Arc::clone(&key))
    } else {
        let eab = build_eab_options(&args.eab)?;
        let opts = AccountOptions {
            contacts: &[],
            agree_tos: true,
            eab: eab.as_ref().map(|(kid, hmac, alg)| EabOptions {
                kid,
                hmac_key: hmac,
                alg,
            }),
        };
        let acct = client
            .new_account(Arc::clone(&key), &opts)
            .await
            .map_err(|e| format!("register: {e}"))?;
        save_account_url(&args.account_key, &acct.url)?;
        println!("Registered new account: {}", acct.url);
        acct
    };

    // Validate challenge type and wildcard compatibility.
    match args.challenge_type.as_str() {
        "http-01" | "tls-alpn-01" => {
            // http-01 and tls-alpn-01 cannot validate wildcard identifiers
            // (RFC 8555 §8.3 and RFC 8737 §3).
            let wildcards: Vec<&str> = args
                .domains
                .iter()
                .filter(|d| d.starts_with("*."))
                .map(String::as_str)
                .collect();
            if !wildcards.is_empty() {
                return Err(format!(
                    "{} cannot validate wildcard identifiers: {}; use --challenge dns-01",
                    args.challenge_type,
                    wildcards.join(", ")
                ));
            }
        }
        "dns-01" | "dns-persist-01" => {
            // DNS-based challenges work for both apex and wildcard domains.
        }
        "onion-csr-01" => {
            if args.onion_key.is_none() {
                return Err("--onion-key is required for onion-csr-01 challenges".to_string());
            }
        }
        other => {
            return Err(format!(
                "unsupported challenge type '{other}'; supported: http-01, dns-01, dns-persist-01, tls-alpn-01, onion-csr-01"
            ));
        }
    }

    // Start the http-01 challenge responder only when needed.
    let solver = if args.challenge_type == "http-01" {
        let s = Http01Solver::new(args.http_port);
        s.start()
            .await
            .map_err(|e| format!("start http-01 solver: {e}"))?;
        Some(s)
    } else {
        None
    };

    // Start the tls-alpn-01 challenge responder only when needed.
    let mut tls_solver: Option<TlsAlpn01Solver> = if args.challenge_type == "tls-alpn-01" {
        let mut s = TlsAlpn01Solver::new(args.tls_port);
        s.start()
            .await
            .map_err(|e| format!("start tls-alpn-01 solver: {e}"))?;
        Some(s)
    } else {
        None
    };

    // Place the order.
    let ids: Vec<Identifier> = args.domains.iter().map(Identifier::dns).collect();
    let order = client
        .new_order(&account, &ids)
        .await
        .map_err(|e| e.to_string())?;

    // Satisfy all authorizations.
    for authz_url in &order.authorizations {
        let authz = client
            .get_authorization(&account, authz_url)
            .await
            .map_err(|e| e.to_string())?;

        if authz.status == "valid" {
            continue; // already satisfied
        }

        match args.challenge_type.as_str() {
            "http-01" => {
                let chall = authz.find_challenge("http-01").ok_or_else(|| {
                    format!("no http-01 challenge for {}", authz.identifier.value)
                })?;
                let token = chall.token.as_deref().ok_or("challenge missing token")?;
                let key_auth = account.key_authorization(token);

                let s = solver.as_ref().unwrap();
                s.present(token, &key_auth)
                    .await
                    .map_err(|e| e.to_string())?;

                client
                    .trigger_challenge(&account, chall)
                    .await
                    .map_err(|e| e.to_string())?;

                let polled =
                    poll_with_timeout(&client, &account, &order.url, args.poll_timeout).await?;
                if polled.status == "invalid" {
                    return Err(format!(
                        "order invalid after http-01 challenge for {}",
                        authz.identifier.value
                    ));
                }

                s.cleanup(token).await.map_err(|e| e.to_string())?;
            }
            "dns-01" => {
                let chall = authz
                    .find_challenge("dns-01")
                    .ok_or_else(|| format!("no dns-01 challenge for {}", authz.identifier.value))?;
                let token = chall.token.as_deref().ok_or("challenge missing token")?;
                let key_auth = account.key_authorization(token);
                let txt_value = Dns01Helper::txt_value(&key_auth).map_err(|e| e.to_string())?;

                // Strip wildcard prefix for the DNS name.
                let base_domain = authz.identifier.value.trim_start_matches("*.");

                eprintln!();
                eprintln!("DNS-01 challenge for {}:", authz.identifier.value);
                eprintln!("  Name:  _acme-challenge.{}.", base_domain);
                eprintln!("  Type:  TXT");
                eprintln!("  Value: {}", txt_value);
                eprintln!();
                eprint!("Press Enter after the TXT record has propagated (Ctrl-C to abort)... ");
                {
                    use std::io::{self, BufRead};
                    let stdin = io::stdin();
                    stdin.lock().lines().next();
                }

                client
                    .trigger_challenge(&account, chall)
                    .await
                    .map_err(|e| e.to_string())?;

                let polled =
                    poll_with_timeout(&client, &account, &order.url, args.poll_timeout).await?;
                if polled.status == "invalid" {
                    return Err(format!(
                        "order invalid after dns-01 challenge for {}",
                        authz.identifier.value
                    ));
                }
            }
            "dns-persist-01" => {
                let chall = authz.find_challenge("dns-persist-01").ok_or_else(|| {
                    format!("no dns-persist-01 challenge for {}", authz.identifier.value)
                })?;
                let token = chall.token.as_deref().ok_or("challenge missing token")?;
                let key_auth = account.key_authorization(token);
                let txt_value =
                    DnsPersist01Helper::txt_value(&key_auth).map_err(|e| e.to_string())?;

                let base_domain = authz.identifier.value.trim_start_matches("*.");

                eprintln!();
                eprintln!("DNS-persist-01 challenge for {}:", authz.identifier.value);
                eprintln!("  Name:  _validation-persist.{}.", base_domain);
                eprintln!("  Type:  TXT");
                eprintln!("  Value: {}", txt_value);
                eprintln!();
                eprintln!("This is a long-lived TXT record; it only needs to be set once.");
                eprint!("Press Enter after the TXT record has propagated (Ctrl-C to abort)... ");
                {
                    use std::io::{self, BufRead};
                    let stdin = io::stdin();
                    stdin.lock().lines().next();
                }

                client
                    .trigger_challenge(&account, chall)
                    .await
                    .map_err(|e| e.to_string())?;

                let polled =
                    poll_with_timeout(&client, &account, &order.url, args.poll_timeout).await?;
                if polled.status == "invalid" {
                    return Err(format!(
                        "order invalid after dns-persist-01 challenge for {}",
                        authz.identifier.value
                    ));
                }
            }
            "tls-alpn-01" => {
                let chall = authz.find_challenge("tls-alpn-01").ok_or_else(|| {
                    format!("no tls-alpn-01 challenge for {}", authz.identifier.value)
                })?;
                let token = chall.token.as_deref().ok_or("challenge missing token")?;
                let key_auth = account.key_authorization(token);

                tls_solver
                    .as_ref()
                    .unwrap()
                    .present(&authz.identifier.value, &authz.identifier.r#type, &key_auth)
                    .await
                    .map_err(|e| format!("tls-alpn-01 present: {e}"))?;

                client
                    .trigger_challenge(&account, chall)
                    .await
                    .map_err(|e| format!("trigger tls-alpn-01: {e}"))?;

                let polled =
                    poll_with_timeout(&client, &account, &order.url, args.poll_timeout).await?;
                if polled.status == "invalid" {
                    return Err(format!(
                        "order invalid after tls-alpn-01 challenge for {}",
                        authz.identifier.value
                    ));
                }
            }
            "onion-csr-01" => {
                let chall = authz.find_challenge("onion-csr-01").ok_or_else(|| {
                    format!("no onion-csr-01 challenge for {}", authz.identifier.value)
                })?;
                let token = chall.token.as_deref().ok_or("challenge missing token")?;
                let key_auth = account.key_authorization(token);

                let onion_key_path = args.onion_key.as_ref().unwrap(); // guarded above
                let hs_pem = std::fs::read(onion_key_path)
                    .map_err(|e| format!("read onion key {}: {e}", onion_key_path.display()))?;
                let csr_der =
                    akamu_client::build_onion_csr(&authz.identifier.value, &key_auth, &hs_pem)
                        .map_err(|e| format!("build onion CSR: {e}"))?;

                client
                    .trigger_challenge_onion(&account, &chall.url, &csr_der)
                    .await
                    .map_err(|e| format!("trigger onion-csr-01: {e}"))?;

                let polled =
                    poll_with_timeout(&client, &account, &order.url, args.poll_timeout).await?;
                if polled.status == "invalid" {
                    return Err(format!(
                        "order invalid after onion-csr-01 challenge for {}",
                        authz.identifier.value
                    ));
                }
            }
            _ => unreachable!(),
        }
    }

    if let Some(mut s) = tls_solver.take() {
        s.cleanup();
    }

    // Load or generate the certificate private key.
    let cert_key_path: PathBuf = args.cert_key.clone().unwrap_or_else(|| {
        let mut p = args.out.clone();
        let mut name = p.file_name().unwrap_or_default().to_os_string();
        name.push(".key.pem");
        p.set_file_name(name);
        p
    });

    let cert_key = if cert_key_path.exists() {
        akamu_client::AccountKey::from_pem(
            &fs::read(&cert_key_path)
                .map_err(|e| format!("read {}: {e}", cert_key_path.display()))?,
        )
        .map_err(|e| e.to_string())?
    } else {
        let k = akamu_client::AccountKey::generate(&args.cert_key_type)
            .map_err(|e| format!("generate cert key: {e}"))?;
        let pem = k.to_pem().map_err(|e| e.to_string())?;
        fs::write(&cert_key_path, &pem)
            .map_err(|e| format!("write {}: {e}", cert_key_path.display()))?;
        println!("Certificate key saved to {}", cert_key_path.display());
        k
    };

    // Build the CSR.
    let domain_refs: Vec<&str> = args.domains.iter().map(String::as_str).collect();
    let csr_der =
        akamu_client::build_csr(&domain_refs, cert_key.private_key()).map_err(|e| e.to_string())?;

    // Finalize and download.
    let order = client
        .finalize(&account, &order, &csr_der)
        .await
        .map_err(|e| e.to_string())?;

    let order = if order.certificate.is_some() {
        order
    } else {
        poll_with_timeout(&client, &account, &order.url, args.poll_timeout).await?
    };

    let cert_url = order
        .certificate
        .as_deref()
        .ok_or("order has no certificate URL after finalization")?;

    let pem = client
        .download_certificate(&account, cert_url)
        .await
        .map_err(|e| e.to_string())?;

    fs::write(&args.out, &pem).map_err(|e| format!("write {}: {e}", args.out.display()))?;
    println!("Certificate written to {}", args.out.display());
    println!("Certificate key:  {}", cert_key_path.display());
    Ok(())
}

// ── renew ─────────────────────────────────────────────────────────────────────

/// Parse an RFC 3339 UTC timestamp string ("YYYY-MM-DDTHH:MM:SSZ") to Unix seconds.
fn parse_rfc3339_utc(s: &str) -> Option<u64> {
    // Accept "YYYY-MM-DDTHH:MM:SSZ" or "YYYY-MM-DDTHH:MM:SS.ffffffZ"
    let s = s.trim_end_matches('Z');
    let s = s.split('.').next()?; // drop sub-seconds
                                  // "YYYY-MM-DDTHH:MM:SS" = 19 chars
    if s.len() != 19 {
        return None;
    }
    let year: u64 = s[0..4].parse().ok()?;
    let month: u64 = s[5..7].parse().ok()?;
    let day: u64 = s[8..10].parse().ok()?;
    let hour: u64 = s[11..13].parse().ok()?;
    let min: u64 = s[14..16].parse().ok()?;
    let sec: u64 = s[17..19].parse().ok()?;
    // Days since Unix epoch (1970-01-01). Gregorian formula.
    let y = if month <= 2 { year - 1 } else { year };
    let m = if month <= 2 { month + 9 } else { month - 3 };
    let days = 365 * y + y / 4 - y / 100 + y / 400 + (153 * m + 2) / 5 + day - 1 - 719468;
    Some(days * 86400 + hour * 3600 + min * 60 + sec)
}

async fn cmd_renew(args: RenewArgs) -> Result<(), String> {
    if !args.force {
        if let Some(cert_path) = &args.cert {
            let client = AcmeClient::new(&args.server)
                .await
                .map_err(|e| e.to_string())?;
            let cert_pem =
                fs::read(cert_path).map_err(|e| format!("read {}: {e}", cert_path.display()))?;
            match client.get_renewal_info(&cert_pem).await {
                Ok(info) => {
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();
                    let start = parse_rfc3339_utc(&info.window_start).unwrap_or(0);
                    let end = parse_rfc3339_utc(&info.window_end).unwrap_or(u64::MAX);
                    if now < start {
                        println!(
                            "Renewal not yet suggested (window opens {}). Use --force to override.",
                            info.window_start
                        );
                        return Ok(());
                    }
                    if now > end {
                        eprintln!(
                            "Warning: past the ARI renewal window end ({}); renewing anyway.",
                            info.window_end
                        );
                    }
                    // Within (or past) window — proceed.
                    println!(
                        "ARI: renewal suggested (window {} – {})",
                        info.window_start, info.window_end
                    );
                }
                Err(e) => {
                    // ARI not supported or error — proceed with renewal.
                    eprintln!("ARI unavailable ({}); proceeding with renewal.", e);
                }
            }
        }
    }

    // Delegate to the issue flow by constructing IssueArgs.
    let issue_args = IssueArgs {
        server: args.server,
        domains: args.domains,
        key_type: args.key_type,
        account_key: args.account_key,
        cert_key_type: args.cert_key_type,
        challenge_type: args.challenge_type,
        http_port: args.http_port,
        tls_port: args.tls_port,
        onion_key: args.onion_key,
        out: args.out,
        cert_key: None,
        poll_timeout: args.poll_timeout,
        eab: args.eab,
    };
    cmd_issue(issue_args).await
}

// ── revoke ────────────────────────────────────────────────────────────────────

async fn cmd_revoke(args: RevokeArgs) -> Result<(), String> {
    // Validate reason code client-side for a better error message.
    if let Some(r) = args.reason {
        if r == 7 || r > 10 {
            return Err(format!("invalid reason code {r}; valid values: 0–6, 8–10"));
        }
    }

    // Read and decode the certificate PEM → DER.
    let cert_pem =
        fs::read(&args.cert).map_err(|e| format!("read {}: {e}", args.cert.display()))?;
    let cert_ders = akamu_client::pem_to_der(&cert_pem);
    let cert_der = cert_ders
        .into_iter()
        .next()
        .ok_or_else(|| format!("no certificate found in {}", args.cert.display()))?;

    let client = AcmeClient::new(&args.server)
        .await
        .map_err(|e| e.to_string())?;

    if let Some(cert_key_path) = &args.cert_key {
        // Self-revocation: sign with the certificate's own private key.
        let cert_key = load_key(cert_key_path)?;
        let cert_key = Arc::new(cert_key);
        client
            .revoke_certificate_with_cert_key(&cert_key, &cert_der, args.reason)
            .await
            .map_err(|e| e.to_string())?;
    } else {
        // Account-key revocation.
        let key = load_key(&args.account_key)?;
        let key = Arc::new(key);
        let account_url = load_account_url(&args.account_key)?;
        let account = akamu_client::Account::new(account_url, "valid".into(), vec![], key);
        client
            .revoke_certificate(&account, &cert_der, args.reason)
            .await
            .map_err(|e| e.to_string())?;
    }

    println!("Revoked: {}", args.cert.display());
    Ok(())
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn load_or_generate_key(path: &Path, key_type: &str) -> Result<AccountKey, String> {
    if path.exists() {
        load_key(path)
    } else {
        let key = AccountKey::generate(key_type).map_err(|e| e.to_string())?;
        let pem = key.to_pem().map_err(|e| e.to_string())?;
        fs::write(path, &pem).map_err(|e| format!("write {}: {e}", path.display()))?;
        println!("Generated new {} key → {}", key_type, path.display());
        Ok(key)
    }
}

fn load_key(path: &Path) -> Result<AccountKey, String> {
    let pem = fs::read(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    AccountKey::from_pem(&pem).map_err(|e| e.to_string())
}

fn account_url_path(key_path: &Path) -> PathBuf {
    let mut p = key_path.to_path_buf();
    let mut name = p.file_name().unwrap_or_default().to_os_string();
    name.push(".account-url");
    p.set_file_name(name);
    p
}

fn save_account_url(key_path: &Path, url: &str) -> Result<(), String> {
    let p = account_url_path(key_path);
    fs::write(&p, url).map_err(|e| format!("write {}: {e}", p.display()))
}

fn load_account_url(key_path: &Path) -> Result<String, String> {
    let p = account_url_path(key_path);
    fs::read_to_string(&p).map_err(|e| format!("read {}: {e}", p.display()))
}

fn build_eab_options(flags: &EabFlags) -> Result<Option<(String, Vec<u8>, String)>, String> {
    flags.to_eab_options()
}
