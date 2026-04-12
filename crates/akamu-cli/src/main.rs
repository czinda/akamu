//! `akamu-cli` — ACME client CLI with ML-DSA account key support.
//!
//! # Commands
//!
//! ```text
//! akamu-cli account register  [--server <URL>] --account-key <FILE> ...
//! akamu-cli account deregister [--server <URL>] --account-key <FILE>
//! akamu-cli issue             [--server <URL>] --domain <DOMAIN> ...
//! akamu-cli revoke            [--server <URL>] --account-key <FILE> --cert <FILE>
//! ```

use std::{
    fs,
    path::{Path, PathBuf},
    sync::Arc,
};

use akamu_client::{
    AccountKey, AccountOptions, AcmeClient, ChallengeSolver as _, EabOptions, Http01Solver,
    Identifier,
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
    /// Revoke an issued certificate
    Revoke(RevokeArgs),
}

#[derive(Subcommand)]
enum AccountCommands {
    /// Register a new ACME account
    Register(RegisterArgs),
    /// Deactivate an existing ACME account (RFC 8555 §7.3.7)
    Deregister(DeregisterArgs),
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

    /// Challenge type (only http-01 is built-in)
    #[arg(long = "challenge", default_value = "http-01")]
    challenge_type: String,

    /// Port to serve http-01 challenges on (default 80)
    #[arg(long, default_value_t = 80)]
    http_port: u16,

    /// PEM file for the certificate private key.
    /// Generated and saved as <out>.key.pem if absent; supply to reuse an existing key.
    #[arg(long)]
    cert_key: Option<PathBuf>,

    /// Write the PEM certificate chain to this file
    #[arg(long)]
    out: PathBuf,

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
        },
        Commands::Issue(args) => cmd_issue(args).await,
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

    // Start the http-01 challenge responder.
    if args.challenge_type != "http-01" {
        return Err(format!(
            "challenge type '{}' not supported; only http-01 is built-in",
            args.challenge_type
        ));
    }
    // http-01 cannot validate wildcard identifiers (RFC 8555 §8.3).
    if args.challenge_type == "http-01" {
        let wildcards: Vec<&str> = args.domains.iter()
            .filter(|d| d.starts_with("*."))
            .map(String::as_str)
            .collect();
        if !wildcards.is_empty() {
            return Err(format!(
                "http-01 cannot validate wildcard identifiers: {}; use --challenge dns-01",
                wildcards.join(", ")
            ));
        }
    }
    let solver = Http01Solver::new(args.http_port);
    solver
        .start()
        .await
        .map_err(|e| format!("start http-01 solver: {e}"))?;

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

        let chall = authz.find_challenge("http-01").ok_or_else(|| {
            format!(
                "no http-01 challenge in authz for {}",
                authz.identifier.value
            )
        })?;

        let token = chall.token.as_deref().ok_or("challenge missing token")?;
        let key_auth = account.key_authorization(token);

        solver
            .present(token, &key_auth)
            .await
            .map_err(|e| e.to_string())?;

        client
            .trigger_challenge(&account, chall)
            .await
            .map_err(|e| e.to_string())?;

        // Poll until the order is ready (all authorizations validated).
        let polled = client
            .poll_order(&account, &order.url)
            .await
            .map_err(|e| e.to_string())?;
        if polled.status == "invalid" {
            return Err(format!(
                "order became invalid during challenge validation for {}",
                authz.identifier.value
            ));
        }

        solver.cleanup(token).await.map_err(|e| e.to_string())?;
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
        client
            .poll_order(&account, &order.url)
            .await
            .map_err(|e| e.to_string())?
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

// ── revoke ────────────────────────────────────────────────────────────────────

async fn cmd_revoke(args: RevokeArgs) -> Result<(), String> {
    // Validate reason code client-side for a better error message.
    if let Some(r) = args.reason {
        if r == 7 || r > 10 {
            return Err(format!(
                "invalid reason code {r}; valid values: 0–6, 8–10"
            ));
        }
    }

    // Read and decode the certificate PEM → DER.
    let cert_pem = fs::read(&args.cert)
        .map_err(|e| format!("read {}: {e}", args.cert.display()))?;
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
