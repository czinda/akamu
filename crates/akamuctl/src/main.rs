//! akamuctl — akamu server administration CLI.
//!
//! Usage: `akamuctl [OPTIONS] <SUBCOMMAND>`
//!
//! Config file: `~/.config/akamu/akamuctl.toml`
//! Session cache: `~/.config/akamu/session.json`

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use clap::{Parser, Subcommand};
use serde_json::{json, Value};

mod client;
mod config;
mod error;
mod output;

use client::AdminClient;
use config::{Config, SessionCache};
use error::CtlError;
use output::{Format, print};

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
    Login,
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
    /// Manage account profile grants.
    #[command(subcommand)]
    Account(AccountCmd),
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
    /// Cosigner administration.
    #[command(subcommand)]
    Cosigner(CosignerCmd),
}

#[derive(Subcommand)]
enum OperatorCmd {
    /// List all operators.
    List,
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
}

#[derive(Subcommand)]
enum AccountCmd {
    #[command(subcommand)]
    Grants(AccountGrantsCmd),
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
    /// Cosigner status.
    Status,
    /// Cosigner statistics.
    Stats,
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

    let fmt = Format::from_str(&cli.output);
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
    )?;

    match cli.command {
        Commands::Login => {
            let resp = server_client.post("/admin/session", None).await?;
            print(&fmt, &resp);
        }
        Commands::Logout => {
            server_client.delete("/admin/session").await?;
            server_client.clear_session();
            if cfg!(not(test)) {
                println!("logged out");
            }
        }
        Commands::Stats => {
            let resp = server_client.get("/admin/stats").await?;
            print(&fmt, &resp);
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
            let mut path = format!("/admin/audit?limit={limit}&offset={offset}");
            if let Some(t) = &r#type {
                path.push_str(&format!("&type={}", urlenc(t)));
            }
            if let Some(s) = &subject {
                path.push_str(&format!("&subject={}", urlenc(s)));
            }
            if let Some(f) = &from {
                path.push_str(&format!("&from={}", urlenc(f)));
            }
            if let Some(u) = &until {
                path.push_str(&format!("&until={}", urlenc(u)));
            }
            if let Some(o) = &outcome {
                path.push_str(&format!("&outcome={}", urlenc(o)));
            }
            let resp = server_client.get(&path).await?;
            print(&fmt, &resp);
        }
        Commands::Operator(op_cmd) => match op_cmd {
            OperatorCmd::List => {
                let resp = server_client.get("/admin/operators").await?;
                print(&fmt, &resp);
            }
            OperatorCmd::Add {
                name,
                role,
                cert_file,
                gssapi_principal,
            } => {
                let cert_fp = if let Some(path) = cert_file {
                    let pem = std::fs::read(&path)?;
                    let ders = synta_certificate::pem_to_der(&pem);
                    let der = ders
                        .into_iter()
                        .next()
                        .ok_or_else(|| CtlError::Config("cert_file contains no certificate".into()))?;
                    Some(sha256_hex(&der)?)
                } else {
                    None
                };
                let body = json!({
                    "name": name,
                    "role": role,
                    "cert_fingerprint": cert_fp,
                    "gssapi_principal": gssapi_principal,
                });
                let resp = server_client.post("/admin/operators", Some(&body)).await?;
                print(&fmt, &resp);
            }
            OperatorCmd::Remove { id } => {
                let body = json!({"active": false});
                let resp = server_client
                    .patch(&format!("/admin/operators/{id}"), &body)
                    .await?;
                print(&fmt, &resp);
            }
            OperatorCmd::Activate { id } => {
                let body = json!({"active": true});
                let resp = server_client
                    .patch(&format!("/admin/operators/{id}"), &body)
                    .await?;
                print(&fmt, &resp);
            }
        },
        Commands::Eab(eab_cmd) => match eab_cmd {
            EabCmd::List { used, unused } => {
                let mut path = "/admin/eab".to_string();
                if used && !unused {
                    path.push_str("?used=true");
                } else if unused && !used {
                    path.push_str("?used=false");
                }
                let resp = server_client.get(&path).await?;
                print(&fmt, &resp);
            }
            EabCmd::Add {
                kid,
                hmac_key,
                profiles,
            } => {
                let mut body = json!({});
                if let Some(k) = kid {
                    body["kid"] = Value::String(k);
                }
                if let Some(h) = hmac_key {
                    body["hmac_key_b64u"] = Value::String(h);
                }
                if !profiles.is_empty() {
                    body["profile_grants"] = Value::Array(
                        profiles.into_iter().map(Value::String).collect(),
                    );
                }
                let resp = server_client.post("/admin/eab", Some(&body)).await?;
                print(&fmt, &resp);
            }
            EabCmd::Remove { kid } => {
                server_client
                    .delete(&format!("/admin/eab/{}", urlenc(&kid)))
                    .await?;
                println!("EAB key {} deactivated", kid);
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
                let mut path = format!("/admin/certs?limit={limit}&offset={offset}");
                if let Some(s) = &serial {
                    path.push_str(&format!("&serial={}", urlenc(s)));
                }
                if let Some(s) = &subject {
                    path.push_str(&format!("&subject={}", urlenc(s)));
                }
                if let Some(a) = &after {
                    path.push_str(&format!("&after={}", urlenc(a)));
                }
                if let Some(b) = &before {
                    path.push_str(&format!("&before={}", urlenc(b)));
                }
                if let Some(st) = &status {
                    path.push_str(&format!("&status={}", urlenc(st)));
                }
                let resp = server_client.get(&path).await?;
                print(&fmt, &resp);
            }
        },
        Commands::Account(acct_cmd) => match acct_cmd {
            AccountCmd::Grants(grants_cmd) => match grants_cmd {
                AccountGrantsCmd::Get { id } => {
                    let resp = server_client
                        .get(&format!("/admin/account/{}/profile-grants", urlenc(&id)))
                        .await?;
                    print(&fmt, &resp);
                }
                AccountGrantsCmd::Set { id, profiles } => {
                    let body = json!({"profiles": profiles});
                    let resp = server_client
                        .post(
                            &format!("/admin/account/{}/profile-grants", urlenc(&id)),
                            Some(&body),
                        )
                        .await?;
                    print(&fmt, &resp);
                }
                AccountGrantsCmd::Clear { id } => {
                    server_client
                        .delete(&format!("/admin/account/{}/profile-grants", urlenc(&id)))
                        .await?;
                    println!("profile grants cleared for account {id}");
                }
            },
        },
        Commands::Revoke { cert_id, reason } => {
            let body = json!({"cert_id": cert_id, "reason": reason});
            let resp = server_client.post("/admin/revoke", Some(&body)).await?;
            print(&fmt, &resp);
        }
        Commands::CrlForce => {
            let resp = server_client.post("/admin/crl/force", None).await?;
            print(&fmt, &resp);
        }
        Commands::Cosigner(cos_cmd) => {
            let cosigner_url = cfg
                .cosigner
                .as_ref()
                .and_then(|c| c.url.clone())
                .unwrap_or_else(|| "https://localhost:9444".into());
            let cos_ca = read_file_opt(
                cfg.cosigner
                    .as_ref()
                    .and_then(|c| c.ca_cert.as_deref())
                    .map(std::path::Path::new),
            )?
            .or(ca_cert_bytes);
            let cos_cert = read_file_opt(
                cfg.cosigner
                    .as_ref()
                    .and_then(|c| c.cert_file.as_deref())
                    .map(std::path::Path::new),
            )?
            .or(cert_bytes);
            let cos_key = read_file_opt(
                cfg.cosigner
                    .as_ref()
                    .and_then(|c| c.key_file.as_deref())
                    .map(std::path::Path::new),
            )?
            .or(key_bytes);
            let cosigner_client = AdminClient::new(
                cosigner_url,
                cos_ca,
                cos_cert,
                cos_key,
                Arc::clone(&session_cache),
                true,
            )?;
            match cos_cmd {
                CosignerCmd::Status => {
                    let resp = cosigner_client.get("/admin/status").await?;
                    print(&fmt, &resp);
                }
                CosignerCmd::Stats => {
                    let resp = cosigner_client.get("/admin/stats").await?;
                    print(&fmt, &resp);
                }
            }
        }
    }

    Ok(())
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn read_file_opt(path: Option<&std::path::Path>) -> Result<Option<Vec<u8>>, CtlError> {
    let Some(p) = path else {
        return Ok(None);
    };
    Ok(Some(std::fs::read(p)?))
}

fn urlenc(s: &str) -> String {
    s.bytes()
        .flat_map(|b| {
            if b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.' || b == b'~' {
                vec![b as char]
            } else {
                format!("%{b:02X}").chars().collect()
            }
        })
        .collect()
}

fn sha256_hex(data: &[u8]) -> Result<String, CtlError> {
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
    Ok(native_ossl::util::hex_encode(&out))
}
