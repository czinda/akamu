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

mod account;
mod args;
mod ca;
mod helpers;
mod import;
mod install;
mod issue;
mod mtc;
mod renew;
mod revoke;

use args::{AccountCommands, CaCommands, Cli, Commands, ImportSource, InstallTarget};
use clap::Parser;

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
            AccountCommands::Register(args) => account::cmd_register(args).await,
            AccountCommands::Deregister(args) => account::cmd_deregister(args).await,
            AccountCommands::Show(args) => account::cmd_show(args).await,
            AccountCommands::Update(args) => account::cmd_update(args).await,
            AccountCommands::KeyChange(args) => account::cmd_key_change(args).await,
        },
        Commands::Issue(args) => issue::cmd_issue(args.common).await,
        Commands::Renew(args) => renew::cmd_renew(args).await,
        Commands::Revoke(args) => revoke::cmd_revoke(args).await,
        Commands::Import { source } => match source {
            ImportSource::Certbot(args) => import::cmd_import_certbot(args).await,
        },
        Commands::Ca { cmd } => match cmd {
            CaCommands::List(args) => ca::cmd_ca_list(args).await,
            CaCommands::Show(args) => ca::cmd_ca_show(args).await,
        },
        Commands::Install { target } => match target {
            InstallTarget::Timer(args) => install::cmd_install_timer(args),
        },
        Commands::Mtc { cmd } => mtc::cmd_mtc(cmd).await.map_err(|e| e.to_string()),
    }
}
