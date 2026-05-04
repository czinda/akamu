//! akamuctl — akamu server administration CLI.
//!
//! Usage: `akamuctl [OPTIONS] <SUBCOMMAND>`
//!
//! Config file: `~/.config/akamu/akamuctl.toml`
//! Session cache: `~/.config/akamu/session.json`

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use clap::{Parser, Subcommand};

mod client;
mod commands;
mod config;
mod error;
mod output;

use client::AdminClient;
use config::{Config, SessionCache};
use error::CtlError;
use output::Format;

#[derive(Parser)]
#[command(name = "akamuctl", about = "akamu server administration CLI")]
struct Cli {
    /// Path to akamuctl.toml config file.
    #[arg(long, short = 'c', value_name = "FILE")]
    config: Option<PathBuf>,

    /// Server admin URL (overrides config).
    #[arg(long, value_name = "URL")]
    server_url: Option<String>,

    /// CA certificate for server TLS verification.
    #[arg(long, value_name = "FILE")]
    ca_cert: Option<PathBuf>,

    /// mTLS client certificate file.
    #[arg(long, value_name = "FILE")]
    cert: Option<PathBuf>,

    /// mTLS client private key file.
    #[arg(long, value_name = "FILE")]
    key: Option<PathBuf>,

    /// Output format: `table` (default) or `json`.
    #[arg(long, short = 'o', default_value = "table")]
    output: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Authenticate and cache session token.
    Login {
        /// Use GSSAPI/Kerberos (Negotiate) instead of mTLS.
        /// The service principal is taken from [server].gssapi_service in the
        /// config, or derived automatically as HTTP@<hostname> from the server URL.
        /// Requires a valid Kerberos TGT in the ccache (run kinit first).
        #[arg(long)]
        gssapi: bool,
    },
    /// Invalidate current session token.
    Logout,
    /// Print server and cosigner statistics.
    Stats,
    /// Query audit events.
    Audit {
        /// Filter by event type (e.g. cert.issue).
        #[arg(long)]
        r#type: Option<String>,
        /// Filter by subject (JWK thumbprint, serial, account UUID).
        #[arg(long)]
        subject: Option<String>,
        /// Filter from this RFC 3339 timestamp.
        #[arg(long)]
        from: Option<String>,
        /// Filter until this RFC 3339 timestamp.
        #[arg(long)]
        until: Option<String>,
        /// Filter by outcome: `success` or `failure`.
        #[arg(long)]
        outcome: Option<String>,
        /// Maximum number of results (default 100).
        #[arg(long, default_value = "100")]
        limit: u32,
        /// Offset for pagination (default 0).
        #[arg(long, default_value = "0")]
        offset: u32,
    },
    /// Manage operators.
    #[command(subcommand)]
    Operator(OperatorCmd),
    /// Manage EAB keys.
    #[command(subcommand)]
    Eab(EabCmd),
    /// Manage certificates.
    #[command(subcommand)]
    Cert(CertCmd),
    /// Manage accounts.
    #[command(subcommand)]
    Account(AccountCmd),
    /// Manage certificate profiles.
    #[command(subcommand)]
    Profile(ProfileCmd),
    /// Manage orders.
    #[command(subcommand)]
    Order(OrderCmd),
    /// Show redacted server configuration.
    ServerConfig,
    /// Revoke a certificate.
    Revoke {
        /// Certificate ID to revoke.
        cert_id: String,
        /// Revocation reason code (default 0 = unspecified).
        #[arg(long, default_value = "0")]
        reason: u8,
    },
    /// Force immediate CRL regeneration.
    CrlForce,
    /// Show cached session identity.
    Whoami,
    /// Cosigner administration.
    #[command(subcommand)]
    Cosigner(CosignerCmd),
    /// Configuration utilities.
    #[command(subcommand)]
    Config(ConfigCmd),
    /// Generate shell completions.
    Completions {
        /// Shell to generate completions for.
        shell: clap_complete::Shell,
    },
}

#[derive(Subcommand)]
enum ConfigCmd {
    /// Print an annotated example akamuctl.toml to stdout.
    ///
    /// Redirect to a file as a starting point:
    ///   akamuctl config generate > ~/.config/akamu/akamuctl.toml
    Generate,
    /// Validate the configuration file.
    Validate,
}

#[derive(Subcommand)]
enum OperatorCmd {
    /// List all operators.
    List,
    /// Show an operator's details.
    Show {
        /// Operator ID.
        id: i64,
    },
    /// Add a new operator.
    Add {
        #[arg(long)]
        name: String,
        #[arg(long)]
        role: String,
        /// Path to operator's client certificate (for fingerprint extraction).
        #[arg(long, value_name = "FILE")]
        cert_file: Option<PathBuf>,
        /// GSSAPI Kerberos principal.
        #[arg(long)]
        gssapi_principal: Option<String>,
    },
    /// Update an operator's fields.
    Update {
        /// Operator ID.
        id: i64,
        #[arg(long)]
        name: Option<String>,
        #[arg(long)]
        role: Option<String>,
        /// Path to operator's client certificate (for fingerprint extraction).
        #[arg(long, value_name = "FILE")]
        cert_file: Option<PathBuf>,
        /// GSSAPI Kerberos principal.
        #[arg(long)]
        gssapi_principal: Option<String>,
    },
    /// Deactivate an operator.
    Remove {
        /// Operator ID.
        id: i64,
    },
    /// Re-activate a previously deactivated operator.
    Activate {
        /// Operator ID.
        id: i64,
    },
}

#[derive(Subcommand)]
enum EabCmd {
    /// List EAB keys.
    List {
        #[arg(long)]
        used: bool,
        #[arg(long)]
        unused: bool,
    },
    /// Show an EAB key's details.
    Show { kid: String },
    /// Provision a new EAB key.
    Add {
        #[arg(long)]
        kid: Option<String>,
        #[arg(long)]
        hmac_key: Option<String>,
        #[arg(long = "profile", value_name = "PROFILE")]
        profiles: Vec<String>,
    },
    /// Deactivate an EAB key.
    Remove {
        kid: String,
    },
}

#[derive(Subcommand)]
enum CertCmd {
    /// List certificates.
    List {
        #[arg(long)]
        serial: Option<String>,
        #[arg(long)]
        subject: Option<String>,
        #[arg(long)]
        after: Option<String>,
        #[arg(long)]
        before: Option<String>,
        #[arg(long)]
        status: Option<String>,
        #[arg(long, default_value = "20")]
        limit: u32,
        #[arg(long, default_value = "0")]
        offset: u32,
    },
    /// Show a certificate's metadata.
    Show {
        /// Certificate ID (UUID).
        id: String,
    },
    /// Download a certificate as PEM or DER.
    Download {
        /// Certificate ID (UUID).
        id: String,
        /// Output format: pem (default) or der.
        #[arg(long, default_value = "pem")]
        format: String,
        /// Write to file instead of stdout.
        #[arg(long, short = 'o', value_name = "FILE")]
        output: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum AccountCmd {
    /// List accounts.
    List {
        /// Filter by status (valid, deactivated).
        #[arg(long)]
        status: Option<String>,
        #[arg(long, default_value = "100")]
        limit: u32,
        #[arg(long, default_value = "0")]
        offset: u32,
    },
    /// Show an account's details.
    Show {
        /// Account ID (UUID).
        id: String,
    },
    /// Admin-initiated account deactivation.
    Deactivate {
        /// Account ID (UUID).
        id: String,
    },
    /// Manage profile grants.
    #[command(subcommand)]
    Grants(AccountGrantsCmd),
}

#[derive(Subcommand)]
enum ProfileCmd {
    /// List loaded certificate profiles.
    List,
}

#[derive(Subcommand)]
enum OrderCmd {
    /// List orders.
    List {
        /// Filter by account ID.
        #[arg(long)]
        account_id: Option<String>,
        /// Filter by status.
        #[arg(long)]
        status: Option<String>,
        #[arg(long, default_value = "100")]
        limit: u32,
        #[arg(long, default_value = "0")]
        offset: u32,
    },
    /// Show an order's details.
    Show {
        /// Order ID (UUID).
        id: String,
    },
}

#[derive(Subcommand)]
enum AccountGrantsCmd {
    /// Show profile grants for an account.
    Get {
        id: String,
    },
    /// Set profile grants for an account.
    Set {
        id: String,
        #[arg(long = "profile", value_name = "PROFILE")]
        profiles: Vec<String>,
    },
    /// Clear all profile grants (unrestricted).
    Clear {
        id: String,
    },
}

#[derive(Subcommand)]
enum CosignerCmd {
    /// Authenticate and cache cosigner session token.
    Login,
    /// Invalidate cosigner session token.
    Logout,
    /// Cosigner status.
    Status,
    /// Cosigner statistics.
    Stats,
    /// Show redacted cosigner configuration.
    Config,
}

// ── Main ──────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    match run(cli).await {
        Ok(()) => {}
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(e.exit_code());
        }
    }
}

async fn run(cli: Cli) -> Result<(), CtlError> {
    // Load config.
    let config_path = cli
        .config
        .clone()
        .unwrap_or_else(Config::default_path);
    let cfg = if config_path.exists() {
        Config::from_file(&config_path).unwrap_or_default()
    } else {
        Config::default()
    };

    let fmt = cli.output.parse::<Format>().map_err(CtlError::Config)?;
    let session_cache = Arc::new(Mutex::new(SessionCache::load()));

    // Resolve server URL.
    let server_url = cli
        .server_url
        .or_else(|| cfg.server.url.clone())
        .unwrap_or_else(|| "https://localhost:9443".into());

    // Read cert/key/ca-cert bytes.
    let ca_cert_bytes = read_file_opt(cli.ca_cert.as_deref().or_else(|| cfg.server.ca_cert.as_deref().map(std::path::Path::new)))?;
    let cert_bytes = read_file_opt(cli.cert.as_deref().or_else(|| cfg.server.cert_file.as_deref().map(std::path::Path::new)))?;
    let key_bytes = read_file_opt(cli.key.as_deref().or_else(|| cfg.server.key_file.as_deref().map(std::path::Path::new)))?;

    let server_client = AdminClient::new(
        server_url.clone(),
        ca_cert_bytes.clone(),
        cert_bytes.clone(),
        key_bytes.clone(),
        Arc::clone(&session_cache),
        false,
        None, // gssapi_service resolved per-command below
    )?;

    match cli.command {
        Commands::Login { gssapi } => {
            commands::session::login(
                &server_url,
                ca_cert_bytes,
                Arc::clone(&session_cache),
                gssapi,
                cfg.server.gssapi_service.clone(),
                &server_client,
                &fmt,
            )
            .await?;
        }
        Commands::Logout => {
            commands::session::logout(&server_client).await?;
        }
        Commands::Stats => {
            commands::server::stats(&server_client, &fmt).await?;
        }
        Commands::Audit {
            r#type,
            subject,
            from,
            until,
            outcome,
            limit,
            offset,
        } => {
            commands::audit::query(
                &server_client,
                &fmt,
                r#type,
                subject,
                from,
                until,
                outcome,
                limit,
                offset,
            )
            .await?;
        }
        Commands::Operator(op_cmd) => match op_cmd {
            OperatorCmd::List => {
                commands::operator::list(&server_client, &fmt).await?;
            }
            OperatorCmd::Show { id } => {
                commands::operator::show(&server_client, &fmt, id).await?;
            }
            OperatorCmd::Add {
                name,
                role,
                cert_file,
                gssapi_principal,
            } => {
                commands::operator::add(
                    &server_client,
                    &fmt,
                    name,
                    role,
                    cert_file,
                    gssapi_principal,
                )
                .await?;
            }
            OperatorCmd::Update {
                id,
                name,
                role,
                cert_file,
                gssapi_principal,
            } => {
                commands::operator::update(
                    &server_client,
                    id,
                    name,
                    role,
                    cert_file,
                    gssapi_principal,
                )
                .await?;
            }
            OperatorCmd::Remove { id } => {
                commands::operator::remove(&server_client, &fmt, id).await?;
            }
            OperatorCmd::Activate { id } => {
                commands::operator::activate(&server_client, &fmt, id).await?;
            }
        },
        Commands::Eab(eab_cmd) => match eab_cmd {
            EabCmd::List { used, unused } => {
                commands::eab::list(&server_client, &fmt, used, unused).await?;
            }
            EabCmd::Add {
                kid,
                hmac_key,
                profiles,
            } => {
                commands::eab::add(&server_client, &fmt, kid, hmac_key, profiles).await?;
            }
            EabCmd::Show { kid } => {
                commands::eab::show(&server_client, &fmt, &kid).await?;
            }
            EabCmd::Remove { kid } => {
                commands::eab::remove(&server_client, &kid).await?;
            }
        },
        Commands::Cert(cert_cmd) => match cert_cmd {
            CertCmd::List {
                serial,
                subject,
                after,
                before,
                status,
                limit,
                offset,
            } => {
                commands::cert::list(
                    &server_client,
                    &fmt,
                    serial,
                    subject,
                    after,
                    before,
                    status,
                    limit,
                    offset,
                )
                .await?;
            }
            CertCmd::Show { id } => {
                commands::cert::show(&server_client, &fmt, &id).await?;
            }
            CertCmd::Download { id, format, output } => {
                commands::cert::download(&server_client, &id, &format, output.as_deref()).await?;
            }
        },
        Commands::Account(acct_cmd) => match acct_cmd {
            AccountCmd::List {
                status,
                limit,
                offset,
            } => {
                commands::account::list(&server_client, &fmt, status, limit, offset).await?;
            }
            AccountCmd::Show { id } => {
                commands::account::show(&server_client, &fmt, &id).await?;
            }
            AccountCmd::Deactivate { id } => {
                commands::account::deactivate(&server_client, &id).await?;
            }
            AccountCmd::Grants(grants_cmd) => match grants_cmd {
                AccountGrantsCmd::Get { id } => {
                    commands::account::grants_get(&server_client, &fmt, &id).await?;
                }
                AccountGrantsCmd::Set { id, profiles } => {
                    commands::account::grants_set(&server_client, &fmt, &id, profiles).await?;
                }
                AccountGrantsCmd::Clear { id } => {
                    commands::account::grants_clear(&server_client, &id).await?;
                }
            },
        },
        Commands::Profile(prof_cmd) => match prof_cmd {
            ProfileCmd::List => {
                commands::server::profile_list(&server_client, &fmt).await?;
            }
        },
        Commands::Order(order_cmd) => match order_cmd {
            OrderCmd::List {
                account_id,
                status,
                limit,
                offset,
            } => {
                commands::server::order_list(
                    &server_client,
                    &fmt,
                    account_id,
                    status,
                    limit,
                    offset,
                )
                .await?;
            }
            OrderCmd::Show { id } => {
                commands::server::order_show(&server_client, &fmt, &id).await?;
            }
        },
        Commands::ServerConfig => {
            commands::server::config(&server_client, &fmt).await?;
        }
        Commands::Revoke { cert_id, reason } => {
            commands::server::revoke(&server_client, &cert_id, reason).await?;
        }
        Commands::CrlForce => {
            commands::server::crl_force(&server_client).await?;
        }
        Commands::Whoami => {
            commands::config_cmd::whoami(&session_cache, &fmt);
        }
        Commands::Cosigner(cos_cmd) => {
            let cosigner_client = commands::cosigner::build_client(
                cfg.cosigner.as_ref(),
                ca_cert_bytes,
                cert_bytes,
                key_bytes,
                Arc::clone(&session_cache),
            )?;
            match cos_cmd {
                CosignerCmd::Login => {
                    commands::cosigner::login(&cosigner_client, &fmt).await?;
                }
                CosignerCmd::Logout => {
                    commands::cosigner::logout(&cosigner_client).await?;
                }
                CosignerCmd::Status => {
                    commands::cosigner::status(&cosigner_client, &fmt).await?;
                }
                CosignerCmd::Stats => {
                    commands::cosigner::stats(&cosigner_client, &fmt).await?;
                }
                CosignerCmd::Config => {
                    commands::cosigner::config(&cosigner_client, &fmt).await?;
                }
            }
        }
        Commands::Config(cfg_cmd) => match cfg_cmd {
            ConfigCmd::Generate => {
                commands::config_cmd::generate();
            }
            ConfigCmd::Validate => {
                commands::config_cmd::validate(&config_path, &cfg);
            }
        },
        Commands::Completions { shell } => {
            commands::config_cmd::completions(shell);
        }
    }

    Ok(())
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Build `HTTP@<hostname>` from a server URL for use as a GSSAPI SPN.
///
/// If the host portion of the URL is an IP address or a loopback name
/// ("localhost", "localhost.localdomain", "ip6-localhost", etc.):
/// - Loopback addresses / names are replaced with the machine's own FQDN.
/// - Other IPs are resolved to a hostname via reverse PTR lookup.
///
/// If reverse DNS fails, the raw IP is used and a warning is printed.
pub(crate) async fn derive_spn(url: &str) -> String {
    let host = url
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .split('/')
        .next()
        .unwrap_or(url)
        .split(':') // strip port
        .next()
        .unwrap_or(url);
    format!("HTTP@{}", resolve_host_for_spn(host).await)
}

/// Resolve a URL host component to a hostname suitable for a Kerberos SPN.
async fn resolve_host_for_spn(host: &str) -> String {
    use std::net::IpAddr;

    // Loopback hostnames — replace with the machine's own FQDN.
    let is_loopback_name = matches!(
        host,
        "localhost" | "localhost.localdomain" | "ip6-localhost" | "ip6-loopback"
    );
    if is_loopback_name {
        return system_fqdn().await.unwrap_or_else(|| host.to_owned());
    }

    // If the host is an IP address, perform loopback check or reverse PTR lookup.
    if let Ok(ip) = host.parse::<IpAddr>() {
        if ip.is_loopback() {
            return system_fqdn().await.unwrap_or_else(|| host.to_owned());
        }
        return ptr_lookup(ip).await.unwrap_or_else(|| {
            eprintln!("warning: reverse DNS for {ip} failed; SPN will use the IP address");
            host.to_owned()
        });
    }

    // Already a proper DNS hostname.
    host.to_owned()
}

/// Return the machine's fully-qualified hostname via `gethostname(2)`.
///
/// If the result contains no dot (a bare short name), performs a forward
/// lookup and then a reverse PTR lookup via hickory-resolver to obtain the FQDN.
async fn system_fqdn() -> Option<String> {
    use std::ffi::CStr;
    let mut buf = [0u8; 256];
    let ret = unsafe { libc::gethostname(buf.as_mut_ptr().cast(), buf.len()) };
    if ret != 0 {
        return None;
    }
    let name = CStr::from_bytes_until_nul(&buf).ok()?.to_str().ok()?.to_owned();
    if name.contains('.') {
        return Some(name);
    }
    // Short hostname — forward lookup then PTR to get the FQDN.
    let resolver = build_resolver();
    let lookup = resolver.lookup_ip(name.as_str()).await.ok()?;
    for ip in lookup {
        if let Some(fqdn) = ptr_lookup_with(ip, &resolver).await {
            if fqdn.contains('.') {
                return Some(fqdn);
            }
        }
    }
    Some(name)
}

/// Reverse-resolve an IP address to a hostname via a DNS PTR query.
async fn ptr_lookup(ip: std::net::IpAddr) -> Option<String> {
    ptr_lookup_with(ip, &build_resolver()).await
}

async fn ptr_lookup_with(
    ip: std::net::IpAddr,
    resolver: &hickory_resolver::TokioAsyncResolver,
) -> Option<String> {
    let lookup = resolver.reverse_lookup(ip).await.ok()?;
    let name = lookup.into_iter().next()?;
    let s = name.to_utf8();
    let s = s.trim_end_matches('.');
    if s.is_empty() || s == ip.to_string() { None } else { Some(s.to_owned()) }
}

/// Build a hickory resolver pointed at the system nameserver.
fn build_resolver() -> hickory_resolver::TokioAsyncResolver {
    use hickory_resolver::config::{NameServerConfig, Protocol, ResolverConfig, ResolverOpts};
    let mut ns = NameServerConfig::new(system_resolver_addr(), Protocol::Udp);
    ns.tls_dns_name = None;
    let mut config = ResolverConfig::new();
    config.add_name_server(ns);
    hickory_resolver::TokioAsyncResolver::tokio(config, ResolverOpts::default())
}

/// Return the first nameserver from `/etc/resolv.conf`, or the
/// systemd-resolved stub (`127.0.0.53:53`) as a fallback.
fn system_resolver_addr() -> std::net::SocketAddr {
    if let Ok(contents) = std::fs::read_to_string("/etc/resolv.conf") {
        for line in contents.lines() {
            let line = line.trim();
            if let Some(rest) = line.strip_prefix("nameserver") {
                if let Ok(ip) = rest.trim().parse::<std::net::IpAddr>() {
                    return std::net::SocketAddr::new(ip, 53);
                }
            }
        }
    }
    "127.0.0.53:53".parse().expect("hardcoded addr is valid")
}

pub(crate) fn read_file_opt(path: Option<&std::path::Path>) -> Result<Option<Vec<u8>>, CtlError> {
    let Some(p) = path else {
        return Ok(None);
    };
    Ok(Some(std::fs::read(p)?))
}

pub(crate) fn urlenc(s: &str) -> String {
    use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};
    utf8_percent_encode(s, NON_ALPHANUMERIC).to_string()
}

pub(crate) fn sha256_hex(data: &[u8]) -> Result<String, CtlError> {
    use native_ossl::digest::DigestAlg;
    let alg = DigestAlg::fetch(c"SHA2-256", None)
        .map_err(|e| CtlError::Config(format!("SHA2-256 fetch: {e}")))?;
    let mut ctx = alg
        .new_context()
        .map_err(|e| CtlError::Config(format!("digest context: {e}")))?;
    ctx.update(data)
        .map_err(|e| CtlError::Config(format!("digest update: {e}")))?;
    let mut out = [0u8; 32];
    ctx.finish(&mut out)
        .map_err(|e| CtlError::Config(format!("digest finish: {e}")))?;
    Ok(native_ossl::util::hex_encode(out))
}
