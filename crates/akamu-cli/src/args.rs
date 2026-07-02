use std::path::PathBuf;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use clap::{Parser, Subcommand};

// ── CLI definition ─────────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(
    name = "akamu-cli",
    about = "ACME client with ML-DSA account key support"
)]
pub(crate) struct Cli {
    /// Enable debug logging.  Pass twice (-vv) to include hyper/TLS internals.
    ///
    /// At -v, akamu-cli logs TLS certificate details (subject, issuer, validity,
    /// signature algorithm) for the ACME server and any CA certificates loaded
    /// via --server-ca.
    #[arg(short, long, action = clap::ArgAction::Count, global = true)]
    pub(crate) verbose: u8,

    #[command(subcommand)]
    pub(crate) command: Commands,
}

#[derive(Subcommand)]
pub(crate) enum Commands {
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
pub(crate) enum CaCommands {
    /// List CAs available on an akamu server
    List(CaListArgs),
    /// Show details for a specific CA
    Show(CaShowArgs),
}

#[derive(Subcommand)]
pub(crate) enum ImportSource {
    /// Import accounts and certificates from a certbot installation
    Certbot(crate::import::CertbotImportArgs),
}

#[derive(Subcommand)]
pub(crate) enum InstallTarget {
    /// Generate and install a systemd .service and .timer unit for certificate renewal
    Timer(InstallTimerArgs),
}

#[derive(clap::Args)]
pub(crate) struct InstallTimerArgs {
    /// Renewal config TOML written by `akamu-cli issue` or `akamu-cli import certbot`
    #[arg(long, value_name = "FILE")]
    pub(crate) renewal_config: PathBuf,

    /// Override the generated unit name.
    /// Default: derived from the first domain (e.g. akamu-renew-example.com).
    #[arg(long, value_name = "NAME")]
    pub(crate) unit_name: Option<String>,

    /// Install as a user-level unit (~/.config/systemd/user/) even when running as root
    #[arg(long, conflicts_with = "system")]
    pub(crate) user: bool,

    /// Install as a system-wide unit (/etc/systemd/system/) even when running as non-root
    #[arg(long, conflicts_with = "user")]
    pub(crate) system: bool,

    /// systemd OnCalendar expression for the timer schedule
    #[arg(long, default_value = "daily", value_name = "SPEC")]
    pub(crate) on_calendar: String,

    /// Enable the timer after installation (`systemctl [--user] enable`)
    #[arg(long)]
    pub(crate) enable: bool,

    /// Start the timer immediately after enabling (implies --enable)
    #[arg(long)]
    pub(crate) now: bool,

    /// Print generated unit files to stdout without writing any files or calling systemctl
    #[arg(long)]
    pub(crate) print_only: bool,

    /// Overwrite existing unit files without prompting
    #[arg(long)]
    pub(crate) force: bool,
}

#[derive(Subcommand)]
pub(crate) enum AccountCommands {
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
pub(crate) struct EabFlags {
    /// External Account Binding key ID (required when server mandates EAB)
    #[arg(long)]
    pub(crate) eab_kid: Option<String>,

    /// EAB HMAC key, base64url-encoded (no padding)
    #[arg(long)]
    pub(crate) eab_key: Option<String>,

    /// EAB HMAC algorithm: HS256 | HS384 | HS512 (default: HS256)
    #[arg(long, default_value = "HS256")]
    pub(crate) eab_alg: String,

    /// Path to a Kerberos keytab for GSSAPI-authenticated EAB.
    /// Mutually exclusive with --eab-kid / --eab-key.
    #[arg(long, value_name = "PATH")]
    pub(crate) gssapi_keytab: Option<PathBuf>,
}

impl EabFlags {
    pub(crate) fn to_eab_options(&self) -> Result<Option<(String, Vec<u8>, String)>, String> {
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
pub(crate) struct RegisterArgs {
    /// ACME directory URL (or base URL when --ca is also provided)
    #[arg(long, default_value = "https://acme-v02.api.letsencrypt.org/directory")]
    pub(crate) server: String,

    /// CA identifier for akamu multi-CA servers; derives directory URL as {server}/acme/{ca}/directory
    #[arg(long, value_name = "CA_ID")]
    pub(crate) ca: Option<String>,

    /// PEM file for the account key (generated and saved if absent)
    #[arg(long)]
    pub(crate) account_key: PathBuf,

    /// Account key type (used when generating a new key)
    #[arg(long, default_value = "ec:P-256")]
    pub(crate) key_type: String,

    /// Contact URI (e.g. "mailto:admin@example.com"); may be repeated
    #[arg(long = "contact")]
    pub(crate) contacts: Vec<String>,

    /// Agree to the server's terms of service
    #[arg(long)]
    pub(crate) agree_tos: bool,

    #[command(flatten)]
    pub(crate) eab: EabFlags,
}

// ── deregister ────────────────────────────────────────────────────────────────

#[derive(clap::Args)]
pub(crate) struct DeregisterArgs {
    /// ACME directory URL (or base URL when --ca is also provided)
    #[arg(long, default_value = "https://acme-v02.api.letsencrypt.org/directory")]
    pub(crate) server: String,

    /// CA identifier for akamu multi-CA servers
    #[arg(long, value_name = "CA_ID")]
    pub(crate) ca: Option<String>,

    /// PEM file for the account key
    #[arg(long)]
    pub(crate) account_key: PathBuf,
}

// ── show ──────────────────────────────────────────────────────────────────────

#[derive(clap::Args)]
pub(crate) struct ShowArgs {
    /// ACME directory URL (or base URL when --ca is also provided)
    #[arg(long, default_value = "https://acme-v02.api.letsencrypt.org/directory")]
    pub(crate) server: String,

    /// CA identifier for akamu multi-CA servers
    #[arg(long, value_name = "CA_ID")]
    pub(crate) ca: Option<String>,

    /// PEM file for the account key
    #[arg(long)]
    pub(crate) account_key: PathBuf,
}

// ── update ────────────────────────────────────────────────────────────────────

#[derive(clap::Args)]
pub(crate) struct UpdateArgs {
    /// ACME directory URL (or base URL when --ca is also provided)
    #[arg(long, default_value = "https://acme-v02.api.letsencrypt.org/directory")]
    pub(crate) server: String,

    /// CA identifier for akamu multi-CA servers
    #[arg(long, value_name = "CA_ID")]
    pub(crate) ca: Option<String>,

    /// PEM file for the account key
    #[arg(long)]
    pub(crate) account_key: PathBuf,

    /// New contact URI (e.g. "mailto:admin@example.com"); may be repeated; pass none to clear
    #[arg(long = "contact")]
    pub(crate) contacts: Vec<String>,
}

// ── key-change ────────────────────────────────────────────────────────────────

#[derive(clap::Args)]
pub(crate) struct KeyChangeArgs {
    /// ACME directory URL (or base URL when --ca is also provided)
    #[arg(long, default_value = "https://acme-v02.api.letsencrypt.org/directory")]
    pub(crate) server: String,

    /// CA identifier for akamu multi-CA servers
    #[arg(long, value_name = "CA_ID")]
    pub(crate) ca: Option<String>,

    /// Current account key PEM file
    #[arg(long)]
    pub(crate) account_key: PathBuf,

    /// New key PEM file; generated if absent
    #[arg(long)]
    pub(crate) new_key: PathBuf,

    /// Key type for generating a new key (ignored if --new-key file exists)
    #[arg(long, default_value = "ec:P-256")]
    pub(crate) new_key_type: String,
}

// ── common certificate args (shared by issue + renew) ────────────────────────

#[derive(clap::Args)]
pub(crate) struct CommonCertArgs {
    /// ACME directory URL (or base URL when --ca is also provided)
    #[arg(long, default_value = "https://acme-v02.api.letsencrypt.org/directory")]
    pub(crate) server: String,

    /// CA identifier for akamu multi-CA servers; derives directory URL as {server}/acme/{ca}/directory
    #[arg(long, value_name = "CA_ID")]
    pub(crate) ca: Option<String>,

    /// Domain name; may be repeated (first domain → CN)
    #[arg(long = "domain", short = 'd')]
    pub(crate) domains: Vec<String>,

    /// Account key type (used when generating a new account key)
    #[arg(long, default_value = "ec:P-256")]
    pub(crate) key_type: String,

    /// PEM file for the account key (generated and saved if absent)
    #[arg(long)]
    pub(crate) account_key: PathBuf,

    /// Certificate key type (used when generating the CSR signing key)
    #[arg(long = "cert-key-type", default_value = "ec:P-256")]
    pub(crate) cert_key_type: String,

    /// Challenge type: http-01 | dns-01 | dns-persist-01 | tls-alpn-01 | onion-csr-01
    #[arg(long = "challenge", default_value = "http-01")]
    pub(crate) challenge_type: String,

    /// Port to serve http-01 challenges on (default 80)
    #[arg(long, default_value_t = 80)]
    pub(crate) http_port: u16,

    /// Port to serve tls-alpn-01 challenges on (default 443)
    #[arg(long, default_value_t = 443)]
    pub(crate) tls_port: u16,

    /// Ed25519 hidden-service key PEM file for onion-csr-01 challenges
    #[arg(long, value_name = "FILE")]
    pub(crate) onion_key: Option<std::path::PathBuf>,

    /// Maximum seconds to wait for order/challenge validation (default: 120)
    #[arg(long, default_value_t = 120)]
    pub(crate) poll_timeout: u64,

    /// PEM file for the certificate private key.
    /// Generated and saved as `<out>.key.pem` if absent; supply to reuse an existing key.
    #[arg(long)]
    pub(crate) cert_key: Option<PathBuf>,

    /// Write the PEM certificate chain to this file
    #[arg(long)]
    pub(crate) out: PathBuf,

    /// Hook script for DNS TXT record management (invoked as `<script> add|remove`
    /// with values in AKAMU_DOMAIN / AKAMU_TOKEN / AKAMU_TXT / AKAMU_KEY_AUTH env vars)
    #[arg(long, value_name = "CMD")]
    pub(crate) dns_hook: Option<String>,

    /// Certificate profile identifier (draft-aaron-acme-profiles-01)
    #[arg(long)]
    pub(crate) profile: Option<String>,

    /// Token Authority URL for tkauth-01 challenges (RFC 9447)
    #[arg(long, value_name = "URL")]
    pub(crate) tkauth_url: Option<String>,

    /// Keytab file for SPNEGO authentication to the Token Authority
    #[arg(long, value_name = "FILE")]
    pub(crate) tkauth_keytab: Option<PathBuf>,

    /// Base64url-encoded JWTClaimConstraints blob for tkauth-01 orders.
    /// When provided, the order uses a JWTClaimConstraints identifier instead
    /// of dns; --domain is ignored.
    #[arg(long, value_name = "B64URL")]
    pub(crate) jwtcc: Option<String>,

    /// PEM file of an extra CA certificate to trust for the ACME server's TLS connection.
    /// Use when the server uses a private CA not in the system trust store.
    #[arg(long, value_name = "FILE")]
    pub(crate) server_ca: Option<PathBuf>,

    #[command(flatten)]
    pub(crate) eab: EabFlags,
}

// ── issue ─────────────────────────────────────────────────────────────────────

#[derive(clap::Args)]
pub(crate) struct IssueArgs {
    #[command(flatten)]
    pub(crate) common: CommonCertArgs,
}

// ── renew ─────────────────────────────────────────────────────────────────────

#[derive(clap::Args)]
pub(crate) struct RenewArgs {
    #[command(flatten)]
    pub(crate) common: CommonCertArgs,

    /// Existing certificate PEM to check ARI renewal window against
    #[arg(long)]
    pub(crate) cert: Option<PathBuf>,

    /// Renew unconditionally, skipping the ARI window check
    #[arg(long)]
    pub(crate) force: bool,

    /// Load renewal configuration from a TOML file written by `akamu-cli issue`.
    /// When provided, all renewal parameters are taken from the file; other flags
    /// are ignored.
    #[arg(long, value_name = "FILE")]
    pub(crate) renewal_config: Option<PathBuf>,
}

// ── revoke ────────────────────────────────────────────────────────────────────

#[derive(clap::Args)]
pub(crate) struct RevokeArgs {
    /// ACME directory URL
    #[arg(long, default_value = "https://acme-v02.api.letsencrypt.org/directory")]
    pub(crate) server: String,

    /// CA identifier for multi-CA servers.
    /// When provided, the directory URL is derived as {server}/acme/{ca}/directory.
    /// Ignored when --server already contains a full directory URL.
    #[arg(long, value_name = "CA_ID")]
    pub(crate) ca: Option<String>,

    /// PEM file for the account key
    #[arg(long)]
    pub(crate) account_key: PathBuf,

    /// PEM file containing the certificate to revoke
    #[arg(long)]
    pub(crate) cert: PathBuf,

    /// CRL reason code (0–6, 8–10; omit for unspecified)
    #[arg(long)]
    pub(crate) reason: Option<u8>,

    /// PEM file for the certificate's private key (use instead of --account-key for self-revocation)
    #[arg(long)]
    pub(crate) cert_key: Option<PathBuf>,
}

// ── ca list / ca show ─────────────────────────────────────────────────────────

#[derive(clap::Args)]
pub(crate) struct CaListArgs {
    /// ACME server URL (base URL or full directory URL)
    #[arg(long, default_value = "https://acme-v02.api.letsencrypt.org/directory")]
    pub(crate) server: String,

    /// Admin API base URL (e.g. <https://admin.acme.example.com:9443>).
    /// When provided, attempts GET /admin/cas for a full CA list.
    #[arg(long)]
    pub(crate) admin_url: Option<String>,
}

#[derive(clap::Args)]
pub(crate) struct CaShowArgs {
    /// ACME server URL (base URL or full directory URL)
    #[arg(long, default_value = "https://acme-v02.api.letsencrypt.org/directory")]
    pub(crate) server: String,

    /// CA identifier to look up
    #[arg(long, value_name = "CA_ID")]
    pub(crate) ca: String,
}
