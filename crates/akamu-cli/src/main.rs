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
//! akamu-cli import certbot    [--certbot-dir <DIR>] --account-key <FILE> ...
//! ```

mod import;

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt as _;
use std::{
    fs,
    io::Write as _,
    path::{Path, PathBuf},
    sync::Arc,
};

use akamu_client::{
    fetch_eab_via_gssapi, AccountKey, AccountOptions, AcmeClient, Challenge, ChallengeSolver as _,
    Dns01Helper, DnsHookSolver, DnsPersist01Helper, EabOptions, Http01Solver, Identifier,
    RenewalConfig, TlsAlpn01Solver,
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
    /// Enable debug logging.  Pass twice (-vv) to include hyper/TLS internals.
    ///
    /// At -v, akamu-cli logs TLS certificate details (subject, issuer, validity,
    /// signature algorithm) for the ACME server and any CA certificates loaded
    /// via --server-ca.
    #[arg(short, long, action = clap::ArgAction::Count, global = true)]
    verbose: u8,

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
    /// Import configuration from another ACME client
    Import {
        #[command(subcommand)]
        source: ImportSource,
    },
    /// CA discovery (list available CAs, show CA details)
    Ca {
        #[command(subcommand)]
        cmd: CaCommands,
    },
    /// Install system integration files (systemd timer, etc.)
    Install {
        #[command(subcommand)]
        target: InstallTarget,
    },
}

#[derive(Subcommand)]
enum CaCommands {
    /// List CAs available on an akamu server
    List(CaListArgs),
    /// Show details for a specific CA
    Show(CaShowArgs),
}

#[derive(Subcommand)]
enum ImportSource {
    /// Import accounts and certificates from a certbot installation
    Certbot(import::CertbotImportArgs),
}

#[derive(Subcommand)]
enum InstallTarget {
    /// Generate and install a systemd .service and .timer unit for certificate renewal
    Timer(InstallTimerArgs),
}

#[derive(clap::Args)]
struct InstallTimerArgs {
    /// Renewal config TOML written by `akamu-cli issue` or `akamu-cli import certbot`
    #[arg(long, value_name = "FILE")]
    renewal_config: PathBuf,

    /// Override the generated unit name.
    /// Default: derived from the first domain (e.g. akamu-renew-example.com).
    #[arg(long, value_name = "NAME")]
    unit_name: Option<String>,

    /// Install as a user-level unit (~/.config/systemd/user/) even when running as root
    #[arg(long, conflicts_with = "system")]
    user: bool,

    /// Install as a system-wide unit (/etc/systemd/system/) even when running as non-root
    #[arg(long, conflicts_with = "user")]
    system: bool,

    /// systemd OnCalendar expression for the timer schedule
    #[arg(long, default_value = "daily", value_name = "SPEC")]
    on_calendar: String,

    /// Enable the timer after installation (`systemctl [--user] enable`)
    #[arg(long)]
    enable: bool,

    /// Start the timer immediately after enabling (implies --enable)
    #[arg(long)]
    now: bool,

    /// Print generated unit files to stdout without writing any files or calling systemctl
    #[arg(long)]
    print_only: bool,

    /// Overwrite existing unit files without prompting
    #[arg(long)]
    force: bool,
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

    /// Path to a Kerberos keytab for GSSAPI-authenticated EAB.
    /// Mutually exclusive with --eab-kid / --eab-key.
    #[arg(long, value_name = "PATH")]
    gssapi_keytab: Option<PathBuf>,
}

impl EabFlags {
    fn to_eab_options(&self) -> Result<Option<(String, Vec<u8>, String)>, String> {
        if self.gssapi_keytab.is_some() && (self.eab_kid.is_some() || self.eab_key.is_some()) {
            return Err("--gssapi-keytab cannot be combined with --eab-kid / --eab-key".into());
        }
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
    /// ACME directory URL (or base URL when --ca is also provided)
    #[arg(long, default_value = "https://acme-v02.api.letsencrypt.org/directory")]
    server: String,

    /// CA identifier for akamu multi-CA servers; derives directory URL as {server}/acme/{ca}/directory
    #[arg(long, value_name = "CA_ID")]
    ca: Option<String>,

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
    /// ACME directory URL (or base URL when --ca is also provided)
    #[arg(long, default_value = "https://acme-v02.api.letsencrypt.org/directory")]
    server: String,

    /// CA identifier for akamu multi-CA servers
    #[arg(long, value_name = "CA_ID")]
    ca: Option<String>,

    /// PEM file for the account key
    #[arg(long)]
    account_key: PathBuf,
}

// ── show ──────────────────────────────────────────────────────────────────────

#[derive(clap::Args)]
struct ShowArgs {
    /// ACME directory URL (or base URL when --ca is also provided)
    #[arg(long, default_value = "https://acme-v02.api.letsencrypt.org/directory")]
    server: String,

    /// CA identifier for akamu multi-CA servers
    #[arg(long, value_name = "CA_ID")]
    ca: Option<String>,

    /// PEM file for the account key
    #[arg(long)]
    account_key: PathBuf,
}

// ── update ────────────────────────────────────────────────────────────────────

#[derive(clap::Args)]
struct UpdateArgs {
    /// ACME directory URL (or base URL when --ca is also provided)
    #[arg(long, default_value = "https://acme-v02.api.letsencrypt.org/directory")]
    server: String,

    /// CA identifier for akamu multi-CA servers
    #[arg(long, value_name = "CA_ID")]
    ca: Option<String>,

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
    /// ACME directory URL (or base URL when --ca is also provided)
    #[arg(long, default_value = "https://acme-v02.api.letsencrypt.org/directory")]
    server: String,

    /// CA identifier for akamu multi-CA servers
    #[arg(long, value_name = "CA_ID")]
    ca: Option<String>,

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
    /// ACME directory URL (or base URL when --ca is also provided)
    #[arg(long, default_value = "https://acme-v02.api.letsencrypt.org/directory")]
    server: String,

    /// CA identifier for akamu multi-CA servers; derives directory URL as {server}/acme/{ca}/directory
    #[arg(long, value_name = "CA_ID")]
    ca: Option<String>,

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

    /// Hook script for DNS TXT record management (invoked as `<script> add|remove`
    /// with values in AKAMU_DOMAIN / AKAMU_TOKEN / AKAMU_TXT / AKAMU_KEY_AUTH env vars)
    #[arg(long, value_name = "CMD")]
    dns_hook: Option<String>,

    /// Certificate profile identifier (draft-aaron-acme-profiles-01)
    #[arg(long)]
    profile: Option<String>,

    /// Token Authority URL for tkauth-01 challenges (RFC 9447)
    #[arg(long, value_name = "URL")]
    tkauth_url: Option<String>,

    /// Keytab file for SPNEGO authentication to the Token Authority
    #[arg(long, value_name = "FILE")]
    tkauth_keytab: Option<PathBuf>,

    /// Base64url-encoded JWTClaimConstraints blob for tkauth-01 orders.
    /// When provided, the order uses a JWTClaimConstraints identifier instead
    /// of dns; --domain is ignored.
    #[arg(long, value_name = "B64URL")]
    jwtcc: Option<String>,

    /// PEM file of an extra CA certificate to trust for the ACME server's TLS connection.
    /// Use when the server uses a private CA not in the system trust store.
    #[arg(long, value_name = "FILE")]
    server_ca: Option<PathBuf>,

    #[command(flatten)]
    eab: EabFlags,
}

// ── renew ─────────────────────────────────────────────────────────────────────

#[derive(clap::Args)]
struct RenewArgs {
    /// ACME directory URL (or base URL when --ca is also provided)
    #[arg(long, default_value = "https://acme-v02.api.letsencrypt.org/directory")]
    server: String,

    /// CA identifier for akamu multi-CA servers; derives directory URL as {server}/acme/{ca}/directory
    #[arg(long, value_name = "CA_ID")]
    ca: Option<String>,

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

    /// Reuse an existing certificate private key file instead of generating a new one.
    /// Required for operators who pin keys via HPKP or TLSA records.
    #[arg(long, value_name = "FILE")]
    cert_key: Option<PathBuf>,

    /// Renew unconditionally, skipping the ARI window check
    #[arg(long)]
    force: bool,

    /// Maximum seconds to wait for order/challenge validation (default: 120)
    #[arg(long, default_value_t = 120)]
    poll_timeout: u64,

    /// Hook script for DNS TXT record management (invoked as `<script> add|remove`
    /// with values in AKAMU_DOMAIN / AKAMU_TOKEN / AKAMU_TXT / AKAMU_KEY_AUTH env vars)
    #[arg(long, value_name = "CMD")]
    dns_hook: Option<String>,

    /// Certificate profile identifier (draft-aaron-acme-profiles-01)
    #[arg(long)]
    profile: Option<String>,

    /// Token Authority URL for tkauth-01 challenges (RFC 9447)
    #[arg(long, value_name = "URL")]
    tkauth_url: Option<String>,

    /// Keytab file for SPNEGO authentication to the Token Authority
    #[arg(long, value_name = "FILE")]
    tkauth_keytab: Option<PathBuf>,

    /// Base64url-encoded JWTClaimConstraints blob for tkauth-01 orders.
    #[arg(long, value_name = "B64URL")]
    jwtcc: Option<String>,

    /// PEM file of an extra CA certificate to trust for the ACME server's TLS connection.
    /// Use when the server uses a private CA not in the system trust store.
    #[arg(long, value_name = "FILE")]
    server_ca: Option<PathBuf>,

    /// Load renewal configuration from a TOML file written by `akamu-cli issue`.
    /// When provided, all renewal parameters are taken from the file; other flags
    /// are ignored.
    #[arg(long, value_name = "FILE")]
    renewal_config: Option<PathBuf>,

    #[command(flatten)]
    eab: EabFlags,
}

// ── revoke ────────────────────────────────────────────────────────────────────

#[derive(clap::Args)]
struct RevokeArgs {
    /// ACME directory URL
    #[arg(long, default_value = "https://acme-v02.api.letsencrypt.org/directory")]
    server: String,

    /// CA identifier for multi-CA servers.
    /// When provided, the directory URL is derived as {server}/acme/{ca}/directory.
    /// Ignored when --server already contains a full directory URL.
    #[arg(long, value_name = "CA_ID")]
    ca: Option<String>,

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

// ── ca list / ca show ─────────────────────────────────────────────────────────

#[derive(clap::Args)]
struct CaListArgs {
    /// ACME server URL (base URL or full directory URL)
    #[arg(long, default_value = "https://acme-v02.api.letsencrypt.org/directory")]
    server: String,

    /// Admin API base URL (e.g. <https://admin.acme.example.com:9443>).
    /// When provided, attempts GET /admin/cas for a full CA list.
    #[arg(long)]
    admin_url: Option<String>,
}

#[derive(clap::Args)]
struct CaShowArgs {
    /// ACME server URL (base URL or full directory URL)
    #[arg(long, default_value = "https://acme-v02.api.letsencrypt.org/directory")]
    server: String,

    /// CA identifier to look up
    #[arg(long, value_name = "CA_ID")]
    ca: String,
}

// ── entry point ───────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    let filter = {
        let base = tracing_subscriber::EnvFilter::from_default_env();
        match cli.verbose {
            0 => base.add_directive("akamu_client=info".parse().unwrap()),
            1 => base.add_directive("akamu_client=debug".parse().unwrap()),
            _ => base
                .add_directive("akamu_client=debug".parse().unwrap())
                .add_directive("hyper_util=debug".parse().unwrap())
                .add_directive("rustls=debug".parse().unwrap()),
        }
    };
    tracing_subscriber::fmt().with_env_filter(filter).init();

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
        Commands::Import { source } => match source {
            ImportSource::Certbot(args) => import::cmd_import_certbot(args).await,
        },
        Commands::Ca { cmd } => match cmd {
            CaCommands::List(args) => cmd_ca_list(args).await,
            CaCommands::Show(args) => cmd_ca_show(args).await,
        },
        Commands::Install { target } => match target {
            InstallTarget::Timer(args) => cmd_install_timer(args),
        },
    }
}

// ── GSSAPI EAB helper ────────────────────────────────────────────────────────

async fn negotiate_gssapi_eab(
    keytab: &Path,
    dir_url: &str,
) -> Result<Option<(String, Vec<u8>, String)>, String> {
    let eab_url = derive_eab_url(dir_url)?;
    let result = fetch_eab_via_gssapi(
        &eab_url,
        keytab.to_str().ok_or("keytab path is not valid UTF-8")?,
    )
    .await
    .map_err(|e| e.to_string())?;
    eprintln!("GSSAPI authenticated as: {}", result.principal);
    match (result.kid, result.hmac_key, result.alg) {
        (Some(kid), Some(hmac_key_b64u), Some(alg)) => {
            let hmac_key = URL_SAFE_NO_PAD
                .decode(&hmac_key_b64u)
                .map_err(|e| format!("EAB hmac_key decode: {e}"))?;
            Ok(Some((kid, hmac_key, alg)))
        }
        _ => {
            eprintln!(
                "Note: server did not return EAB credentials \
                 (eab_master_secret not configured); proceeding without EAB."
            );
            Ok(None)
        }
    }
}

// ── account register ──────────────────────────────────────────────────────────

async fn cmd_register(args: RegisterArgs) -> Result<(), String> {
    let dir_url = resolve_directory_url(&args.server, args.ca.as_deref());
    let key = load_or_generate_key(&args.account_key, &args.key_type)?;
    let key = Arc::new(key);

    let client = AcmeClient::new(&dir_url).await.map_err(|e| e.to_string())?;

    let gssapi_eab = match args.eab.gssapi_keytab.as_ref() {
        Some(keytab) => negotiate_gssapi_eab(keytab, &dir_url).await?,
        None => None,
    };

    let cli_eab = build_eab_options(&args.eab)?;
    let eab = gssapi_eab.or(cli_eab);
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

    save_account_url_for_ca(&args.account_key, args.ca.as_deref(), &account.url)?;
    println!("Registered: {}", account.url);
    Ok(())
}

// ── account deregister ────────────────────────────────────────────────────────

async fn cmd_deregister(args: DeregisterArgs) -> Result<(), String> {
    let dir_url = resolve_directory_url(&args.server, args.ca.as_deref());
    let key = load_key(&args.account_key)?;
    let key = Arc::new(key);
    let account_url = load_account_url_for_ca(&args.account_key, args.ca.as_deref())?;

    let client = AcmeClient::new(&dir_url).await.map_err(|e| e.to_string())?;

    // Reconstruct a minimal Account with the stored URL.
    let account = akamu_client::Account::new(account_url.clone(), "valid".to_string(), vec![], key);

    client
        .deactivate_account(&account)
        .await
        .map_err(|e| e.to_string())?;

    // Remove the stored account URL.
    let url_path = account_url_path_for_ca(&args.account_key, args.ca.as_deref());
    if let Err(e) = fs::remove_file(&url_path) {
        if e.kind() != std::io::ErrorKind::NotFound {
            eprintln!(
                "Warning: account deactivated but could not remove sidecar {}: {e}. \
                 Future commands may attempt to use the deactivated account.",
                url_path.display()
            );
        }
    }
    println!("Deactivated: {account_url}");
    Ok(())
}

// ── account show ──────────────────────────────────────────────────────────────

async fn cmd_show(args: ShowArgs) -> Result<(), String> {
    let dir_url = resolve_directory_url(&args.server, args.ca.as_deref());
    let key = load_key(&args.account_key)?;
    let key = Arc::new(key);
    let account_url = load_account_url_for_ca(&args.account_key, args.ca.as_deref())?;

    let client = AcmeClient::new(&dir_url).await.map_err(|e| e.to_string())?;
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
    let dir_url = resolve_directory_url(&args.server, args.ca.as_deref());
    let key = load_key(&args.account_key)?;
    let key = Arc::new(key);
    let account_url = load_account_url_for_ca(&args.account_key, args.ca.as_deref())?;

    let client = AcmeClient::new(&dir_url).await.map_err(|e| e.to_string())?;
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
    let dir_url = resolve_directory_url(&args.server, args.ca.as_deref());
    let old_key = load_key(&args.account_key)?;
    let old_key = Arc::new(old_key);
    let account_url = load_account_url_for_ca(&args.account_key, args.ca.as_deref())?;

    let new_key = load_or_generate_key(&args.new_key, &args.new_key_type)?;
    let new_key = Arc::new(new_key);

    let client = AcmeClient::new(&dir_url).await.map_err(|e| e.to_string())?;
    let account = akamu_client::Account::new(account_url.clone(), "valid".into(), vec![], old_key);
    let _updated = client
        .key_change(&account, Arc::clone(&new_key))
        .await
        .map_err(|e| e.to_string())?;

    // Overwrite the account key file with the new key.
    let new_pem = new_key.to_pem().map_err(|e| e.to_string())?;
    write_private_file(&args.account_key, &new_pem)?;
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
    client
        .poll_order(
            account,
            order_url,
            std::time::Duration::from_secs(timeout_secs),
        )
        .await
        .map_err(|e| e.to_string())
}

// ── issue ─────────────────────────────────────────────────────────────────────

async fn cmd_issue(args: IssueArgs) -> Result<(), String> {
    let using_jwtcc = args.challenge_type == "tkauth-01" && args.jwtcc.is_some();
    if args.domains.is_empty() && !using_jwtcc {
        return Err("at least one --domain is required (or --jwtcc for tkauth-01)".into());
    }

    let dir_url = resolve_directory_url(&args.server, args.ca.as_deref());

    // Load or generate the account key.
    let key = load_or_generate_key(&args.account_key, &args.key_type)?;
    let key = Arc::new(key);

    let client = if let Some(ca_path) = &args.server_ca {
        let pem =
            fs::read(ca_path).map_err(|e| format!("--server-ca {}: {e}", ca_path.display()))?;
        AcmeClient::new_with_extra_root(&dir_url, &pem)
            .await
            .map_err(|e| e.to_string())?
    } else {
        AcmeClient::new(&dir_url).await.map_err(|e| e.to_string())?
    };

    // Load existing account or register a new one.
    let account = if let Ok(url) = load_account_url_for_ca(&args.account_key, args.ca.as_deref()) {
        akamu_client::Account::new(url, "valid".to_string(), vec![], Arc::clone(&key))
    } else {
        let gssapi_eab = match args.eab.gssapi_keytab.as_ref() {
            Some(keytab) => negotiate_gssapi_eab(keytab, &dir_url).await?,
            None => None,
        };
        let cli_eab = build_eab_options(&args.eab)?;
        let eab = gssapi_eab.or(cli_eab);
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
        save_account_url_for_ca(&args.account_key, args.ca.as_deref(), &acct.url)?;
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
        "tkauth-01" => {
            if args.tkauth_url.is_none() {
                return Err("--tkauth-url is required for tkauth-01 challenges".to_string());
            }
            if args.tkauth_keytab.is_none() {
                return Err("--tkauth-keytab is required for tkauth-01 challenges".to_string());
            }
        }
        other => {
            return Err(format!(
                "unsupported challenge type '{other}'; supported: http-01, dns-01, dns-persist-01, tls-alpn-01, onion-csr-01, tkauth-01"
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

    // Compute the RFC 9447 fingerprint once (needed per-authz for tkauth-01).
    let tkauth_fingerprint: Option<String> = if args.challenge_type == "tkauth-01" {
        Some(
            akamu_client::rfc9447_fingerprint(account.thumbprint())
                .map_err(|e| format!("rfc9447 fingerprint: {e}"))?,
        )
    } else {
        None
    };

    // Place the order.
    let ids: Vec<Identifier> = if using_jwtcc {
        vec![Identifier {
            r#type: "EnhancedJWTClaimConstraints".to_string(),
            value: args.jwtcc.clone().unwrap(),
        }]
    } else {
        args.domains.iter().map(Identifier::dns).collect()
    };
    let order = client
        .new_order_with_profile(&account, &ids, args.profile.as_deref())
        .await
        .map_err(|e| e.to_string())?;
    // Capture the server-echoed profile (may differ from args.profile if the server
    // auto-selected a default; used when writing the .renewal.toml sidecar).
    let server_profile = order.profile.clone();

    // Satisfy all authorizations.
    //
    // Phase 1: prepare (present/deploy) and trigger each challenge.  Manual
    // dns-01 / dns-persist-01 challenges prompt the user per-domain and defer
    // triggering until all TXT records are in place.
    let mut http01_tokens: Vec<String> = Vec::new();
    let mut dns01_cleanups: Vec<(String, String, String)> = Vec::new();
    let mut deferred_challenges: Vec<Challenge> = Vec::new();
    let mut any_challenged = false;

    for authz_url in &order.authorizations {
        let authz = client
            .get_authorization(&account, authz_url)
            .await
            .map_err(|e| e.to_string())?;

        if authz.status == "valid" {
            continue; // already satisfied
        }
        any_challenged = true;

        match args.challenge_type.as_str() {
            "http-01" => {
                let challenge = authz.find_challenge("http-01").ok_or_else(|| {
                    format!("no http-01 challenge for {}", authz.identifier.value)
                })?;
                let token = challenge
                    .token
                    .as_deref()
                    .ok_or("challenge missing token")?;
                let key_auth = account.key_authorization(token);

                let s = solver.as_ref().unwrap();
                s.present(token, &key_auth)
                    .await
                    .map_err(|e| e.to_string())?;

                client
                    .trigger_challenge(&account, challenge)
                    .await
                    .map_err(|e| e.to_string())?;

                http01_tokens.push(token.to_string());
            }
            "dns-01" => {
                let challenge = authz
                    .find_challenge("dns-01")
                    .ok_or_else(|| format!("no dns-01 challenge for {}", authz.identifier.value))?;
                let token = challenge
                    .token
                    .as_deref()
                    .ok_or("challenge missing token")?;
                let key_auth = account.key_authorization(token);
                let base_domain = authz.identifier.value.trim_start_matches("*.");

                if let Some(hook) = &args.dns_hook {
                    let s = DnsHookSolver::new(hook.clone());
                    s.deploy(base_domain, token, &key_auth)
                        .await
                        .map_err(|e| format!("dns hook deploy: {e}"))?;
                    client
                        .trigger_challenge(&account, challenge)
                        .await
                        .map_err(|e| e.to_string())?;
                    dns01_cleanups.push((base_domain.to_string(), token.to_string(), key_auth));
                } else {
                    let txt_value = Dns01Helper::txt_value(&key_auth).map_err(|e| e.to_string())?;
                    eprintln!();
                    eprintln!("DNS-01 challenge for {}:", authz.identifier.value);
                    eprintln!("  Name:  _acme-challenge.{}.", base_domain);
                    eprintln!("  Type:  TXT");
                    eprintln!("  Value: {}", txt_value);
                    eprintln!();
                    eprint!(
                        "Press Enter after the TXT record has propagated (Ctrl-C to abort)... "
                    );
                    tokio::task::spawn_blocking(|| -> Result<(), String> {
                        use std::io::{self, BufRead};
                        match io::stdin().lock().lines().next() {
                            Some(Ok(_)) => Ok(()),
                            Some(Err(e)) => Err(format!("dns-01 stdin read error: {e}")),
                            None => Err("stdin closed (EOF) — aborting dns-01 challenge".into()),
                        }
                    })
                    .await
                    .map_err(|e| format!("dns-01 stdin wait: {e}"))??;
                    deferred_challenges.push(challenge.clone());
                }
            }
            "dns-persist-01" => {
                let challenge = authz.find_challenge("dns-persist-01").ok_or_else(|| {
                    format!("no dns-persist-01 challenge for {}", authz.identifier.value)
                })?;
                let issuer_domain = challenge
                    .issuer_domain_names
                    .as_deref()
                    .and_then(|v| v.first())
                    .ok_or_else(|| {
                        format!(
                            "dns-persist-01 challenge for {} has no issuer-domain-names",
                            authz.identifier.value
                        )
                    })?;
                let is_wildcard = authz.identifier.value.starts_with("*.");
                let base_domain = authz.identifier.value.trim_start_matches("*.");
                let txt_record = if is_wildcard {
                    DnsPersist01Helper::txt_record_wildcard(issuer_domain, &account.url)
                } else {
                    DnsPersist01Helper::txt_record(issuer_domain, &account.url)
                };

                if let Some(hook) = &args.dns_hook {
                    let s = DnsHookSolver::new(hook.clone());
                    s.deploy_persist(base_domain, &txt_record)
                        .await
                        .map_err(|e| format!("dns hook deploy: {e}"))?;
                    client
                        .trigger_challenge(&account, challenge)
                        .await
                        .map_err(|e| e.to_string())?;
                } else {
                    eprintln!();
                    eprintln!("DNS-persist-01 challenge for {}:", authz.identifier.value);
                    eprintln!("  Name:  _validation-persist.{}.", base_domain);
                    eprintln!("  Type:  TXT");
                    eprintln!("  Value: {}", txt_record);
                    eprintln!();
                    eprintln!("This is a long-lived TXT record; it only needs to be set once.");
                    eprint!(
                        "Press Enter after the TXT record has propagated (Ctrl-C to abort)... "
                    );
                    tokio::task::spawn_blocking(|| -> Result<(), String> {
                        use std::io::{self, BufRead};
                        match io::stdin().lock().lines().next() {
                            Some(Ok(_)) => Ok(()),
                            Some(Err(e)) => Err(format!("dns-persist-01 stdin read error: {e}")),
                            None => {
                                Err("stdin closed (EOF) — aborting dns-persist-01 challenge".into())
                            }
                        }
                    })
                    .await
                    .map_err(|e| format!("dns-persist-01 stdin wait: {e}"))??;
                    deferred_challenges.push(challenge.clone());
                }
            }
            "tls-alpn-01" => {
                let challenge = authz.find_challenge("tls-alpn-01").ok_or_else(|| {
                    format!("no tls-alpn-01 challenge for {}", authz.identifier.value)
                })?;
                let token = challenge
                    .token
                    .as_deref()
                    .ok_or("challenge missing token")?;
                let key_auth = account.key_authorization(token);

                tls_solver
                    .as_ref()
                    .unwrap()
                    .present(&authz.identifier.value, &authz.identifier.r#type, &key_auth)
                    .await
                    .map_err(|e| format!("tls-alpn-01 present: {e}"))?;

                client
                    .trigger_challenge(&account, challenge)
                    .await
                    .map_err(|e| format!("trigger tls-alpn-01: {e}"))?;
            }
            "onion-csr-01" => {
                let challenge = authz.find_challenge("onion-csr-01").ok_or_else(|| {
                    format!("no onion-csr-01 challenge for {}", authz.identifier.value)
                })?;
                let token = challenge
                    .token
                    .as_deref()
                    .ok_or("challenge missing token")?;
                let key_auth = account.key_authorization(token);

                let onion_key_path = args.onion_key.as_ref().unwrap(); // guarded above
                let hs_pem = std::fs::read(onion_key_path)
                    .map_err(|e| format!("read onion key {}: {e}", onion_key_path.display()))?;
                let csr_der =
                    akamu_client::build_onion_csr(&authz.identifier.value, &key_auth, &hs_pem)
                        .map_err(|e| format!("build onion CSR: {e}"))?;

                client
                    .trigger_challenge_onion(&account, &challenge.url, &csr_der)
                    .await
                    .map_err(|e| format!("trigger onion-csr-01: {e}"))?;
            }
            "tkauth-01" => {
                let challenge = authz.find_challenge("tkauth-01").ok_or_else(|| {
                    format!("no tkauth-01 challenge for {}", authz.identifier.value)
                })?;
                // tkvalue is the ACME identifier value (the JWTClaimConstraints blob),
                // NOT the challenge token.  The TA echoes it in atc.tkvalue; the server
                // checks atc.tkvalue == id_value to bind the token to this order.
                let tkvalue = authz.identifier.value.as_str();
                let ta_url = args.tkauth_url.as_deref().unwrap(); // guarded above
                let keytab = args.tkauth_keytab.as_ref().unwrap(); // guarded above
                let fingerprint = tkauth_fingerprint.as_deref().unwrap(); // set when tkauth-01

                let jwt = akamu_client::fetch_authority_token(
                    ta_url,
                    tkvalue,
                    fingerprint,
                    keytab
                        .to_str()
                        .ok_or("tkauth-keytab path is not valid UTF-8")?,
                )
                .await
                .map_err(|e| format!("fetch authority token: {e}"))?;

                client
                    .trigger_challenge_tkauth(&account, &challenge.url, &jwt)
                    .await
                    .map_err(|e| format!("trigger tkauth-01: {e}"))?;
            }
            _ => unreachable!(),
        }
    }

    // Phase 2 + 3: trigger deferred challenges and poll.  Wrapped so that
    // Phase 4 cleanup always runs regardless of success or failure.
    let poll_result: Result<(), String> = async {
        // Phase 2: trigger deferred challenges (manual dns-01 / dns-persist-01).
        for challenge in &deferred_challenges {
            client
                .trigger_challenge(&account, challenge)
                .await
                .map_err(|e| e.to_string())?;
        }

        // Phase 3: poll the order once, after all challenges have been triggered.
        if any_challenged {
            poll_with_timeout(&client, &account, &order.url, args.poll_timeout).await?;
        }
        Ok(())
    }
    .await;

    // Phase 4: cleanup (always runs).
    if let Some(s) = solver.as_ref() {
        for token in &http01_tokens {
            let _ = s.cleanup(token).await;
        }
    }
    if let Some(hook) = &args.dns_hook {
        let s = DnsHookSolver::new(hook.clone());
        for (domain, token, key_auth) in &dns01_cleanups {
            let _ = s.clean(domain, token, key_auth).await;
        }
    }
    if let Some(mut s) = tls_solver.take() {
        s.cleanup();
    }

    poll_result?;

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
        write_private_file(&cert_key_path, &pem)?;
        println!("Certificate key saved to {}", cert_key_path.display());
        k
    };

    // Build the CSR.
    let csr_der = if using_jwtcc && args.domains.is_empty() {
        // JWTClaimConstraints-only orders: no DNS SANs in the CSR; the server
        // adds any claim-derived OtherName SANs during finalization.
        akamu_client::build_subject_only_csr("EnhancedJWTClaimConstraints", cert_key.private_key())
            .map_err(|e| e.to_string())?
    } else {
        let domain_refs: Vec<&str> = args.domains.iter().map(String::as_str).collect();
        akamu_client::build_csr(&domain_refs, cert_key.private_key()).map_err(|e| e.to_string())?
    };

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

    // Write .renewal.toml sidecar so `akamu-cli renew --renewal-config` can reload all settings.
    let renewal_config = RenewalConfig {
        server: args.server.clone(),
        ca: args.ca.clone(),
        domains: ids,
        account_key: args.account_key.clone(),
        account_key_type: args.key_type.clone(),
        cert_path: args.out.clone(),
        cert_key_path: cert_key_path.clone(),
        cert_key_type: args.cert_key_type.clone(),
        challenge_type: args.challenge_type.clone(),
        http_port: args.http_port,
        tls_port: args.tls_port,
        onion_key: args.onion_key.clone(),
        poll_timeout: args.poll_timeout,
        contacts: vec![],
        eab_kid: args.eab.eab_kid.clone(),
        eab_key: args.eab.eab_key.clone(),
        eab_alg: args.eab.eab_alg.clone(),
        gssapi_keytab: args.eab.gssapi_keytab.clone(),
        dns_hook: args.dns_hook.clone(),
        profile: args.profile.or(server_profile),
        tkauth_url: args.tkauth_url.clone(),
        tkauth_keytab: args.tkauth_keytab.clone(),
        jwtcc: args.jwtcc.clone(),
    };
    let toml_str = toml::to_string_pretty(&renewal_config)
        .map_err(|e| format!("serialize renewal config: {e}"))?;
    let mut renewal_path = args.out.clone().into_os_string();
    renewal_path.push(".renewal.toml");
    let renewal_path = std::path::PathBuf::from(renewal_path);
    write_private_file(&renewal_path, toml_str.as_bytes())?;
    println!("Renewal config:   {}", renewal_path.display());
    println!(
        "To renew: akamu-cli renew --renewal-config {}",
        renewal_path.display()
    );
    if args.eab.eab_key.is_some() {
        eprintln!(
            "Note: EAB HMAC key is NOT saved in the renewal config for security reasons. \
             Re-supply --eab-key on each renewal."
        );
    }
    Ok(())
}

// ── renew ─────────────────────────────────────────────────────────────────────

/// Parse an RFC 3339 UTC timestamp string to Unix seconds.
/// Accepts "Z", "+00:00", or "-00:00" as the UTC offset indicator.
fn parse_rfc3339_utc(s: &str) -> Option<u64> {
    // Strip UTC offset suffix, then drop optional sub-second fraction.
    let s = if let Some(stripped) = s
        .strip_suffix("+00:00")
        .or_else(|| s.strip_suffix("-00:00"))
    {
        stripped
    } else {
        s.trim_end_matches('Z')
    };
    let s = s.split('.').next()?; // drop sub-seconds
                                  // "YYYY-MM-DDTHH:MM:SS" = 19 chars
    if s.len() != 19 {
        return None;
    }
    let year: i64 = s[0..4].parse().ok()?;
    let month: i64 = s[5..7].parse().ok()?;
    let day: i64 = s[8..10].parse().ok()?;
    let hour: i64 = s[11..13].parse().ok()?;
    let min: i64 = s[14..16].parse().ok()?;
    let sec: i64 = s[17..19].parse().ok()?;
    if year < 1970
        || year > 9999
        || month < 1
        || month > 12
        || day < 1
        || hour > 23
        || min > 59
        || sec > 60
    {
        return None;
    }
    let is_leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
    let max_day: i64 = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap => 29,
        2 => 28,
        _ => return None,
    };
    if day > max_day {
        return None;
    }
    // Days since Unix epoch (1970-01-01). Gregorian formula (signed arithmetic).
    let y = if month <= 2 { year - 1 } else { year };
    let m = if month <= 2 { month + 9 } else { month - 3 };
    let days: i64 = 365 * y + y / 4 - y / 100 + y / 400 + (153 * m + 2) / 5 + day - 1 - 719468;
    let secs = days
        .checked_mul(86400)?
        .checked_add(hour * 3600 + min * 60 + sec)?;
    u64::try_from(secs).ok()
}

/// Check ARI renewal window (RFC 9773).
///
/// Returns `Ok(true)` if renewal should proceed (window open or past),
/// `Ok(false)` if the window hasn't opened yet,
/// or `Err(...)` if the certificate file cannot be read.
/// When the ARI endpoint is unavailable, logs a warning and returns `Ok(true)`.
/// Skips the check when `cert_path` does not exist.
async fn check_ari_window(dir_url: &str, cert_path: &Path) -> Result<bool, String> {
    if !cert_path.exists() {
        return Ok(true);
    }
    let client = AcmeClient::new(dir_url).await.map_err(|e| e.to_string())?;
    let cert_bytes =
        fs::read(cert_path).map_err(|e| format!("read {}: {e}", cert_path.display()))?;
    match client.get_renewal_info(&cert_bytes).await {
        Ok(info) => {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let start = parse_rfc3339_utc(&info.window_start).unwrap_or_else(|| {
                eprintln!(
                    "Warning: cannot parse ARI window_start '{}'; treating as epoch",
                    info.window_start
                );
                0
            });
            let end = parse_rfc3339_utc(&info.window_end).unwrap_or_else(|| {
                eprintln!(
                    "Warning: cannot parse ARI window_end '{}'; treating as max",
                    info.window_end
                );
                u64::MAX
            });
            if now < start {
                println!(
                    "Renewal not yet suggested (window opens {}). Use --force to override.",
                    info.window_start
                );
                return Ok(false);
            }
            if now > end {
                eprintln!(
                    "Warning: past the ARI renewal window end ({}); renewing anyway.",
                    info.window_end
                );
            }
            println!(
                "ARI: renewal suggested (window {} – {})",
                info.window_start, info.window_end
            );
            Ok(true)
        }
        Err(e) => {
            eprintln!("ARI unavailable ({}); proceeding with renewal.", e);
            Ok(true)
        }
    }
}

async fn cmd_renew(args: RenewArgs) -> Result<(), String> {
    // When --renewal-config is provided, load all settings from the TOML file
    // and delegate to cmd_issue directly.
    if let Some(ref config_path) = args.renewal_config {
        let toml_str = fs::read_to_string(config_path)
            .map_err(|e| format!("read {}: {e}", config_path.display()))?;
        let cfg: RenewalConfig = toml::from_str(&toml_str)
            .map_err(|e| format!("parse {}: {e}", config_path.display()))?;

        let cfg_dir_url = resolve_directory_url(&cfg.server, cfg.ca.as_deref());

        // Check ARI if --cert or cert_path from config exists and --force is not set.
        if !args.force {
            let cert_path = args.cert.as_deref().unwrap_or(&cfg.cert_path);
            if !check_ari_window(&cfg_dir_url, cert_path).await? {
                return Ok(());
            }
        }

        let eab = EabFlags {
            eab_kid: cfg.eab_kid,
            eab_key: cfg.eab_key,
            eab_alg: cfg.eab_alg,
            gssapi_keytab: cfg.gssapi_keytab,
        };
        let issue_args = IssueArgs {
            server: cfg.server,
            ca: cfg.ca,
            domains: cfg.domains.into_iter().map(|id| id.value).collect(),
            key_type: cfg.account_key_type,
            account_key: cfg.account_key,
            cert_key_type: cfg.cert_key_type,
            challenge_type: cfg.challenge_type,
            http_port: cfg.http_port,
            tls_port: cfg.tls_port,
            onion_key: cfg.onion_key,
            poll_timeout: cfg.poll_timeout,
            out: cfg.cert_path,
            cert_key: Some(cfg.cert_key_path),
            dns_hook: cfg.dns_hook,
            profile: cfg.profile,
            tkauth_url: cfg.tkauth_url,
            tkauth_keytab: cfg.tkauth_keytab,
            jwtcc: cfg.jwtcc,
            server_ca: args.server_ca.clone(),
            eab,
        };
        return cmd_issue(issue_args).await;
    }

    let dir_url = resolve_directory_url(&args.server, args.ca.as_deref());
    if !args.force {
        if let Some(ref cert_path) = args.cert {
            if !check_ari_window(&dir_url, cert_path).await? {
                return Ok(());
            }
        }
    }

    // Delegate to the issue flow by constructing IssueArgs.
    let issue_args = IssueArgs {
        server: args.server,
        ca: args.ca,
        domains: args.domains,
        key_type: args.key_type,
        account_key: args.account_key,
        cert_key_type: args.cert_key_type,
        challenge_type: args.challenge_type,
        http_port: args.http_port,
        tls_port: args.tls_port,
        onion_key: args.onion_key,
        out: args.out,
        cert_key: args.cert_key,
        poll_timeout: args.poll_timeout,
        dns_hook: args.dns_hook,
        profile: args.profile,
        tkauth_url: args.tkauth_url,
        tkauth_keytab: args.tkauth_keytab,
        jwtcc: args.jwtcc,
        server_ca: args.server_ca,
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

    let dir_url = resolve_directory_url(&args.server, args.ca.as_deref());
    let client = AcmeClient::new(&dir_url).await.map_err(|e| e.to_string())?;

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
        let account_url = load_account_url_for_ca(&args.account_key, args.ca.as_deref())?;
        let account = akamu_client::Account::new(account_url, "valid".into(), vec![], key);
        client
            .revoke_certificate(&account, &cert_der, args.reason)
            .await
            .map_err(|e| e.to_string())?;
    }

    println!("Revoked: {}", args.cert.display());
    Ok(())
}

// ── ca list / ca show handlers ────────────────────────────────────────────────

async fn cmd_ca_list(args: CaListArgs) -> Result<(), String> {
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

async fn cmd_ca_show(args: CaShowArgs) -> Result<(), String> {
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

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Derive the ACME directory URL for a specific CA.
///
/// When `ca` is provided and `server` does not already end in `/directory`,
/// returns `{server}/acme/{ca}/directory`.  Otherwise returns `server` as-is.
fn resolve_directory_url(server: &str, ca: Option<&str>) -> String {
    if server.ends_with("/directory") {
        return server.to_owned();
    }
    match ca {
        Some(ca_id) => {
            let base = server.trim_end_matches('/');
            format!("{base}/acme/{ca_id}/directory")
        }
        None => server.to_owned(),
    }
}

/// Return the account URL sidecar path for a given account key and CA.
///
/// When `ca` is `Some(id)` and `id != "default"`, produces
/// `<key>.<ca_id>.account-url` to isolate per-CA account registrations.
/// Otherwise produces the legacy `<key>.account-url`.
fn account_url_path_for_ca(key_path: &Path, ca: Option<&str>) -> PathBuf {
    let mut p = key_path.to_path_buf();
    let mut name = p.file_name().unwrap_or_default().to_os_string();
    match ca {
        Some(id) if id != "default" => {
            // Sanitize: strip any path separators or characters unsafe in filenames
            // so a server-supplied CA ID cannot escape the intended directory.
            let safe_id: String = id
                .chars()
                .map(|c| {
                    if c.is_alphanumeric() || c == '-' || c == '_' {
                        c
                    } else {
                        '_'
                    }
                })
                .collect();
            name.push(format!(".{safe_id}.account-url"));
        }
        _ => {
            name.push(".account-url");
        }
    }
    p.set_file_name(name);
    p
}

fn save_account_url_for_ca(key_path: &Path, ca: Option<&str>, url: &str) -> Result<(), String> {
    let p = account_url_path_for_ca(key_path, ca);
    write_private_file(&p, url.as_bytes())
}

fn load_account_url_for_ca(key_path: &Path, ca: Option<&str>) -> Result<String, String> {
    let p = account_url_path_for_ca(key_path, ca);
    fs::read_to_string(&p).map_err(|e| format!("read {}: {e}", p.display()))
}

fn load_or_generate_key(path: &Path, key_type: &str) -> Result<AccountKey, String> {
    if path.exists() {
        load_key(path)
    } else {
        let key = AccountKey::generate(key_type).map_err(|e| e.to_string())?;
        let pem = key.to_pem().map_err(|e| e.to_string())?;
        write_private_file(path, &pem)?;
        println!("Generated new {} key → {}", key_type, path.display());
        Ok(key)
    }
}

fn load_key(path: &Path) -> Result<AccountKey, String> {
    let pem = fs::read(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    AccountKey::from_pem(&pem).map_err(|e| e.to_string())
}

// ── install timer ─────────────────────────────────────────────────────────────

fn cmd_install_timer(args: InstallTimerArgs) -> Result<(), String> {
    let toml_str = fs::read_to_string(&args.renewal_config)
        .map_err(|e| format!("read {}: {e}", args.renewal_config.display()))?;
    let cfg: RenewalConfig = toml::from_str(&toml_str)
        .map_err(|e| format!("parse {}: {e}", args.renewal_config.display()))?;

    let first_domain = cfg
        .domains
        .first()
        .ok_or("renewal config has no domains")?
        .value
        .clone();

    let unit_base = args.unit_name.unwrap_or_else(|| {
        let sanitized = first_domain
            .strip_prefix("*.")
            .map(|rest| format!("wildcard-{rest}"))
            .unwrap_or_else(|| first_domain.clone());
        format!("akamu-renew-{sanitized}")
    });

    let config_path = args
        .renewal_config
        .canonicalize()
        .unwrap_or_else(|_| args.renewal_config.clone());

    let exe = std::env::current_exe()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| "akamu-cli".to_string());

    let service_name = format!("{unit_base}.service");
    let timer_name = format!("{unit_base}.timer");

    let service_content = format!(
        "[Unit]\n\
         Description=Renew ACME certificate for {first_domain}\n\
         After=network-online.target\n\
         Wants=network-online.target\n\
         \n\
         [Service]\n\
         Type=oneshot\n\
         ExecStart={exe} renew --renewal-config {config_path}\n",
        config_path = config_path.display(),
    );

    let timer_content = format!(
        "[Unit]\n\
         Description=Daily ACME certificate renewal for {first_domain}\n\
         \n\
         [Timer]\n\
         OnCalendar={on_calendar}\n\
         RandomizedDelaySec=1h\n\
         Persistent=true\n\
         \n\
         [Install]\n\
         WantedBy=timers.target\n",
        on_calendar = args.on_calendar,
    );

    if args.print_only {
        println!("# --- {service_name} ---");
        print!("{service_content}");
        println!("# --- {timer_name} ---");
        print!("{timer_content}");
        return Ok(());
    }

    let user_mode = if args.user {
        true
    } else if args.system {
        false
    } else {
        effective_uid() != 0
    };

    let unit_dir = if user_mode {
        let cfg_home = std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                let home = std::env::var_os("HOME")
                    .map(PathBuf::from)
                    .unwrap_or_else(|| PathBuf::from("/root"));
                home.join(".config")
            });
        cfg_home.join("systemd/user")
    } else {
        PathBuf::from("/etc/systemd/system")
    };

    fs::create_dir_all(&unit_dir).map_err(|e| format!("create {}: {e}", unit_dir.display()))?;

    let service_path = unit_dir.join(&service_name);
    let timer_path = unit_dir.join(&timer_name);

    if !args.force {
        for p in [&service_path, &timer_path] {
            if p.exists() {
                return Err(format!(
                    "{} already exists; use --force to overwrite",
                    p.display()
                ));
            }
        }
    }

    fs::write(&service_path, service_content.as_bytes())
        .map_err(|e| format!("write {}: {e}", service_path.display()))?;
    fs::write(&timer_path, timer_content.as_bytes())
        .map_err(|e| format!("write {}: {e}", timer_path.display()))?;
    println!("Written: {}", service_path.display());
    println!("Written: {}", timer_path.display());

    let sc_user_flag: &[&str] = if user_mode { &["--user"] } else { &[] };

    let run_systemctl = |extra: &[&str]| -> Result<(), String> {
        let status = std::process::Command::new("systemctl")
            .args(sc_user_flag)
            .args(extra)
            .status()
            .map_err(|e| format!("systemctl: {e}"))?;
        if !status.success() {
            return Err(format!("systemctl {} failed: {status}", extra.join(" ")));
        }
        Ok(())
    };

    run_systemctl(&["daemon-reload"])?;

    let do_enable = args.enable || args.now;
    if do_enable {
        run_systemctl(&["enable", &timer_name])?;
        println!("Enabled: {timer_name}");
    }
    if args.now {
        run_systemctl(&["start", &timer_name])?;
        println!("Started: {timer_name}");
    }

    if !do_enable {
        let sc = if user_mode {
            "systemctl --user"
        } else {
            "systemctl"
        };
        println!("\nTo enable automatic renewal:");
        println!("  {sc} enable --now {timer_name}");
    }

    Ok(())
}

/// Return the effective UID of the current process.
/// Reads /proc/self/status on Linux; returns 0 on any parse failure so that
/// the caller defaults to system-mode installation in ambiguous cases.
fn effective_uid() -> u32 {
    #[cfg(target_os = "linux")]
    {
        let Ok(status) = fs::read_to_string("/proc/self/status") else {
            eprintln!(
                "Warning: cannot read /proc/self/status; defaulting to system-mode installation"
            );
            return 0;
        };
        for line in status.lines() {
            if let Some(rest) = line.strip_prefix("Uid:") {
                // Fields: real effective saved fs — index 1 is effective UID.
                if let Some(euid) = rest.split_whitespace().nth(1).and_then(|s| s.parse().ok()) {
                    return euid;
                }
            }
        }
        eprintln!("Warning: cannot determine effective UID from /proc/self/status; defaulting to system-mode installation");
        0
    }
    #[cfg(not(target_os = "linux"))]
    {
        0
    }
}

/// Write `data` to `path` with mode 0o600 (owner-read/write only).
/// Enforces 0o600 even when overwriting a pre-existing file.
pub(crate) fn write_private_file(path: &Path, data: &[u8]) -> Result<(), String> {
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    opts.mode(0o600);
    let mut f = opts
        .open(path)
        .map_err(|e| format!("open {}: {e}", path.display()))?;
    f.write_all(data)
        .map_err(|e| format!("write {}: {e}", path.display()))?;
    // mode(0o600) only applies on O_CREAT; explicitly enforce on existing files.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("chmod {}: {e}", path.display()))?;
    }
    Ok(())
}

fn build_eab_options(flags: &EabFlags) -> Result<Option<(String, Vec<u8>, String)>, String> {
    flags.to_eab_options()
}

/// Construct the EAB identity URL from the ACME server directory URL.
///
/// Extracts the scheme + host (+ port) and appends `/acme/eab`.
fn derive_eab_url(server_url: &str) -> Result<String, String> {
    let without_scheme = server_url
        .split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or(server_url);
    let host_port = without_scheme.split('/').next().unwrap_or("");
    if host_port.is_empty() {
        return Err(format!(
            "cannot extract host from server URL '{server_url}'"
        ));
    }
    let scheme = server_url.split("://").next().unwrap_or("https");
    Ok(format!("{scheme}://{host_port}/acme/eab"))
}

#[cfg(test)]
mod tests {
    use super::parse_rfc3339_utc;

    #[test]
    fn rfc3339_utc_basic() {
        // 1970-01-01T00:00:00Z = 0
        assert_eq!(parse_rfc3339_utc("1970-01-01T00:00:00Z"), Some(0));
    }

    #[test]
    fn rfc3339_utc_known_timestamp() {
        // 2024-01-01T00:00:00Z = 1704067200
        assert_eq!(parse_rfc3339_utc("2024-01-01T00:00:00Z"), Some(1704067200));
    }

    #[test]
    fn rfc3339_utc_rejects_feb31() {
        assert_eq!(parse_rfc3339_utc("2025-02-31T00:00:00Z"), None);
    }

    #[test]
    fn rfc3339_utc_rejects_apr31() {
        assert_eq!(parse_rfc3339_utc("2025-04-31T00:00:00Z"), None);
    }

    #[test]
    fn rfc3339_utc_accepts_feb29_leap() {
        assert!(parse_rfc3339_utc("2024-02-29T00:00:00Z").is_some());
    }

    #[test]
    fn rfc3339_utc_rejects_feb29_non_leap() {
        assert_eq!(parse_rfc3339_utc("2025-02-29T00:00:00Z"), None);
    }

    #[test]
    fn rfc3339_utc_rejects_year_before_1970() {
        assert_eq!(parse_rfc3339_utc("1969-12-31T23:59:59Z"), None);
    }

    #[test]
    fn rfc3339_utc_rejects_year_after_9999() {
        assert_eq!(parse_rfc3339_utc("10000-01-01T00:00:00Z"), None);
    }

    #[test]
    fn rfc3339_utc_rejects_hour25() {
        assert_eq!(parse_rfc3339_utc("2025-01-01T25:00:00Z"), None);
    }

    #[test]
    fn rfc3339_utc_rejects_min60() {
        assert_eq!(parse_rfc3339_utc("2025-01-01T00:60:00Z"), None);
    }

    #[test]
    fn rfc3339_utc_subsecond_ignored() {
        let base = parse_rfc3339_utc("2024-06-15T12:30:45Z");
        let frac = parse_rfc3339_utc("2024-06-15T12:30:45.123456Z");
        assert_eq!(base, frac);
    }

    #[test]
    fn rfc3339_utc_accepts_plus_zero_offset() {
        let z = parse_rfc3339_utc("2024-01-01T00:00:00Z");
        let plus = parse_rfc3339_utc("2024-01-01T00:00:00+00:00");
        let minus = parse_rfc3339_utc("2024-01-01T00:00:00-00:00");
        assert!(z.is_some());
        assert_eq!(z, plus);
        assert_eq!(z, minus);
    }

    #[test]
    fn rfc3339_utc_accepts_subsecond_plus_offset() {
        let z = parse_rfc3339_utc("2024-06-15T12:30:45Z");
        let plus = parse_rfc3339_utc("2024-06-15T12:30:45.5+00:00");
        assert_eq!(z, plus);
    }

    #[test]
    fn rfc3339_utc_rejects_nonzero_offset() {
        assert_eq!(parse_rfc3339_utc("2024-01-01T00:00:00+05:30"), None);
        assert_eq!(parse_rfc3339_utc("2024-01-01T00:00:00-08:00"), None);
    }
}
