//! akamuctl — akamu server administration CLI.
//!
//! Usage: `akamuctl [OPTIONS] <SUBCOMMAND>`
//!
//! Config file: `~/.config/akamu/akamuctl.toml`
//! Session cache: `~/.config/akamu/session.json`

use std::sync::{Arc, Mutex};

use clap::Parser;

mod cli;
mod client;
mod commands;
mod config;
mod dns;
mod error;
mod output;

use cli::*;
use client::AdminClient;
use config::{Config, SessionCache};
pub(crate) use dns::derive_spn;
use error::CtlError;
use output::Format;

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
    let config_path = cli.config.clone().unwrap_or_else(Config::default_path);
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
    let ca_cert_bytes = read_file_opt(
        cli.ca_cert
            .as_deref()
            .or_else(|| cfg.server.ca_cert.as_deref().map(std::path::Path::new)),
    )?;
    let cert_bytes = read_file_opt(
        cli.cert
            .as_deref()
            .or_else(|| cfg.server.cert_file.as_deref().map(std::path::Path::new)),
    )?;
    let key_bytes = read_file_opt(
        cli.key
            .as_deref()
            .or_else(|| cfg.server.key_file.as_deref().map(std::path::Path::new)),
    )?;

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
            OperatorCmd::Unlock { id } => {
                commands::operator::unlock(&server_client, &fmt, id).await?;
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
                ca,
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
                    ca,
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
            ProfileCmd::Add { id, params_file } => {
                commands::server::profile_add(&server_client, &fmt, &id, &params_file).await?;
            }
            ProfileCmd::Update { id, params_file } => {
                commands::server::profile_update(&server_client, &fmt, &id, &params_file).await?;
            }
            ProfileCmd::Remove { id } => {
                commands::server::profile_remove(&server_client, &fmt, &id).await?;
            }
            ProfileCmd::Show { id } => {
                commands::server::profile_show(&server_client, &fmt, &id).await?;
            }
        },
        Commands::Order(order_cmd) => match order_cmd {
            OrderCmd::List {
                account_id,
                status,
                ca,
                limit,
                offset,
            } => {
                commands::server::order_list(
                    &server_client,
                    &fmt,
                    account_id,
                    status,
                    ca,
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
        Commands::Ca(ca_cmd) => match ca_cmd {
            CaCmd::List => {
                commands::ca::list(&server_client, &fmt).await?;
            }
            CaCmd::Show { id } => {
                commands::ca::show(&server_client, &fmt, &id).await?;
            }
            CaCmd::Cert { id, output } => {
                commands::ca::cert(&server_client, &id, output).await?;
            }
            CaCmd::CrlForce { id } => {
                commands::ca::crl_force(&server_client, &id).await?;
            }
            CaCmd::CrossSign {
                issuer_id,
                subject_ca_id,
                subject_cert,
                validity_years,
            } => {
                commands::ca::cross_sign(
                    &server_client,
                    &fmt,
                    &issuer_id,
                    subject_ca_id,
                    subject_cert,
                    validity_years,
                )
                .await?;
            }
        },
        Commands::CrossCert(cc_cmd) => match cc_cmd {
            CrossCertCmd::List {
                issuer_ca,
                subject_ca,
                limit,
                offset,
            } => {
                commands::cross_cert::list(
                    &server_client,
                    &fmt,
                    issuer_ca,
                    subject_ca,
                    limit,
                    offset,
                )
                .await?;
            }
            CrossCertCmd::Download { id, output } => {
                commands::cross_cert::download(&server_client, &id, output).await?;
            }
            CrossCertCmd::Show { id } => {
                commands::cross_cert::show(&server_client, &fmt, &id).await?;
            }
        },
        Commands::Delegation(del_cmd) => match del_cmd {
            DelegationCmd::List { account_id } => {
                commands::delegation::list(&server_client, &fmt, account_id).await?;
            }
            DelegationCmd::Show { id } => {
                commands::delegation::show(&server_client, &fmt, &id).await?;
            }
            DelegationCmd::Add {
                account_id,
                csr_template,
                cname_map,
            } => {
                commands::delegation::add(
                    &server_client,
                    &fmt,
                    account_id,
                    &csr_template,
                    cname_map.as_deref(),
                )
                .await?;
            }
            DelegationCmd::Update {
                id,
                csr_template,
                cname_map,
                clear_cname_map,
            } => {
                commands::delegation::update(
                    &server_client,
                    &id,
                    &csr_template,
                    cname_map.as_deref(),
                    clear_cname_map,
                )
                .await?;
            }
            DelegationCmd::Remove { id } => {
                commands::delegation::remove(&server_client, &id).await?;
            }
        },
        Commands::Mtc(mtc_cmd) => match mtc_cmd {
            MtcCmd::TreeSize { ca } => {
                commands::mtc::tree_size(&server_client, &fmt, ca).await?;
            }
            MtcCmd::Root { ca } => {
                commands::mtc::root(&server_client, &fmt, ca).await?;
            }
            MtcCmd::Landmarks { ca } => {
                commands::mtc::landmarks(&server_client, &fmt, ca).await?;
            }
            MtcCmd::LandmarkList { ca } => {
                commands::mtc::landmark_list(&server_client, ca).await?;
            }
            MtcCmd::LandmarkCert { seq, ca, output } => {
                commands::mtc::landmark_cert(&server_client, seq, ca, output).await?;
            }
            MtcCmd::LandmarkCertShow { seq, ca } => {
                commands::mtc::landmark_cert_show(&server_client, seq, ca).await?;
            }
            MtcCmd::InclusionProof { cert_id } => {
                commands::mtc::inclusion_proof(&server_client, &fmt, &cert_id).await?;
            }
            MtcCmd::Standalone { cert_id, output } => {
                commands::mtc::standalone(&server_client, &cert_id, output).await?;
            }
            MtcCmd::ConsistencyProof { from, to, ca } => {
                commands::mtc::consistency_proof(&server_client, &fmt, from, to, ca).await?;
            }
            MtcCmd::SubtreeRoot { start, end, ca } => {
                commands::mtc::subtree_root(&server_client, &fmt, start, end, ca).await?;
            }
            MtcCmd::RevokedRanges { ca } => {
                commands::mtc::revoked_ranges(&server_client, &fmt, ca).await?;
            }
            MtcCmd::Checkpoint { ca } => {
                commands::mtc::checkpoint(&server_client, ca).await?;
            }
            MtcCmd::Cosignature { ca } => {
                commands::mtc::cosignature(&server_client, ca).await?;
            }
            MtcCmd::ForceCheckpoint { ca } => {
                commands::mtc::force_checkpoint(&server_client, &ca).await?;
            }
            MtcCmd::ForceLandmark { ca } => {
                commands::mtc::force_landmark(&server_client, &ca).await?;
            }
            MtcCmd::LogListEntry { ca } => {
                commands::mtc::log_list_entry(&server_client, &ca).await?;
            }
        },
        Commands::Config(cfg_cmd) => match cfg_cmd {
            ConfigCmd::Generate => {
                commands::config_cmd::generate();
            }
            ConfigCmd::Validate => {
                commands::config_cmd::validate(&config_path, &cfg);
            }
        },
        Commands::Tkauth(tkauth_cmd) => match tkauth_cmd {
            TkauthCmd::PruneJti { dry_run } => {
                commands::tkauth::prune_jti(&server_client, dry_run).await?;
            }
        },
        Commands::Completions { shell } => {
            commands::config_cmd::completions(shell);
        }
    }

    Ok(())
}

// ── Helpers ───────────────────────────────────────────────────────────────────

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
