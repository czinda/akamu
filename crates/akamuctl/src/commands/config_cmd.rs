//! Config subcommands (akamuctl config …).

use std::path::Path;
use std::sync::{Arc, Mutex};

use serde_json::json;

use crate::config::{self, Config, SessionCache};
use crate::output::{print, Format};

/// Print an annotated example akamuctl.toml to stdout.
pub fn generate() {
    print!("{}", config::EXAMPLE_CONFIG);
}

/// Validate an akamuctl.toml file and report problems.
pub fn validate(config_path: &Path, cfg: &Config) {
    println!("config: {}", config_path.display());

    let mut ok = true;

    if let Some(ref url) = cfg.server.url {
        if !url.starts_with("https://") && !url.starts_with("http://") {
            eprintln!("  [warn] server.url does not start with https://");
            ok = false;
        }
    } else {
        eprintln!("  [warn] server.url not set (will default to https://localhost:9443)");
    }

    if let Some(ref p) = cfg.server.ca_cert {
        if !Path::new(p).exists() {
            eprintln!("  [error] server.ca_cert '{}' does not exist", p);
            ok = false;
        }
    }
    if let Some(ref p) = cfg.server.cert_file {
        if !Path::new(p).exists() {
            eprintln!("  [error] server.cert_file '{}' does not exist", p);
            ok = false;
        }
    }
    if let Some(ref p) = cfg.server.key_file {
        if !Path::new(p).exists() {
            eprintln!("  [error] server.key_file '{}' does not exist", p);
            ok = false;
        }
    }

    if let Some(ref cos) = cfg.cosigner {
        if let Some(ref p) = cos.ca_cert {
            if !Path::new(p).exists() {
                eprintln!("  [error] cosigner.ca_cert '{}' does not exist", p);
                ok = false;
            }
        }
        if let Some(ref p) = cos.cert_file {
            if !Path::new(p).exists() {
                eprintln!("  [error] cosigner.cert_file '{}' does not exist", p);
                ok = false;
            }
        }
        if let Some(ref p) = cos.key_file {
            if !Path::new(p).exists() {
                eprintln!("  [error] cosigner.key_file '{}' does not exist", p);
                ok = false;
            }
        }
    }

    if ok {
        println!("  configuration is valid");
    }
}

/// Print information about the current session (server and cosigner).
pub fn whoami(session_cache: &Arc<Mutex<SessionCache>>, fmt: &Format) {
    let cache = session_cache.lock().unwrap_or_else(|e| e.into_inner());

    let server_info = cache.server.as_ref().map(|e| {
        json!({
            "url": e.url,
            "expires_at": e.expires_at,
        })
    });

    let cosigner_info = cache.cosigner.as_ref().map(|e| {
        json!({
            "url": e.url,
            "expires_at": e.expires_at,
        })
    });

    let info = json!({
        "server": server_info,
        "cosigner": cosigner_info,
    });

    print(fmt, &info);
}

/// Generate shell completion scripts for the given shell.
pub fn completions(shell: clap_complete::Shell) {
    use clap::CommandFactory;
    clap_complete::generate(
        shell,
        &mut crate::Cli::command(),
        "akamuctl",
        &mut std::io::stdout(),
    );
}
