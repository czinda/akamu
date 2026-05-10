//! akamu-seedgen — generates realistic PKI test data for Akamu.
#![allow(dead_code)] // binary crate; items used through call chain, not all reachable statically
//!
//! Runs an in-process Akamu ACME server, drives the full ACME protocol to
//! issue certificates, then post-processes the database to produce the full
//! range of PKI lifecycle states (expired, revoked, STAR, delegation, ARI).

mod acme;
mod challenge;
mod config_writer;
mod names;
mod postprocess;
mod scenarios;
mod server;
mod setup;
mod spec;
mod summary;

use clap::Parser;
use rand_chacha::ChaCha8Rng;
use rand::SeedableRng;

#[derive(Parser, Debug)]
#[command(name = "akamu-seedgen", about = "Generate realistic Akamu PKI test data")]
struct Cli {
    /// Population spec file (TOML). Omit to use built-in defaults.
    #[arg(short = 's', long, value_name = "FILE")]
    spec: Option<String>,

    /// Output SQLite database file.
    #[arg(short = 'o', long, default_value = "test-data.sqlite3")]
    output: Option<String>,

    /// Override the RNG seed from the spec.
    #[arg(long)]
    seed: Option<u64>,

    /// Print per-cert progress.
    #[arg(short = 'v', long)]
    verbose: bool,

    /// Output format: text or json.
    #[arg(long, default_value = "text")]
    output_format: String,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(if cli.verbose { "info".parse().unwrap() } else { "warn".parse().unwrap() }),
        )
        .init();

    if let Err(e) = run(cli).await {
        eprintln!("akamu-seedgen: error: {e}");
        std::process::exit(1);
    }
}

async fn run(cli: Cli) -> Result<(), String> {
    // Load spec.
    let mut seed_spec = match &cli.spec {
        Some(path) => spec::SeedSpec::load(path)?,
        None => spec::SeedSpec::built_in(),
    };

    // Override seed / output if provided on command line.
    if let Some(seed) = cli.seed {
        seed_spec.global.seed = seed;
    }
    let output_path = cli.output.as_deref().unwrap_or(&seed_spec.global.output).to_string();

    let seed = seed_spec.global.seed;
    let mut rng = ChaCha8Rng::seed_from_u64(seed);

    // Artifacts directory: output path with its extension stripped.
    // e.g. "test-data.sqlite3" → "test-data/" (sibling of the DB file).
    let artifacts_dir = std::path::Path::new(&output_path).with_extension("");
    std::fs::create_dir_all(&artifacts_dir)
        .map_err(|e| format!("create artifacts dir '{}': {e}", artifacts_dir.display()))?;

    tracing::info!(
        "starting akamu-seedgen (seed={seed}, output='{output_path}', artifacts='{}')",
        artifacts_dir.display()
    );

    // Remove any pre-existing output file so db::open() starts with a fresh schema.
    if std::path::Path::new(&output_path).exists() {
        std::fs::remove_file(&output_path)
            .map_err(|e| format!("remove existing output '{output_path}': {e}"))?;
    }
    // Also remove WAL/SHM files from any previous run.
    for suffix in &["-wal", "-shm"] {
        let sidecar = format!("{output_path}{suffix}");
        if std::path::Path::new(&sidecar).exists() {
            let _ = std::fs::remove_file(&sidecar);
        }
    }

    let db_url = format!("sqlite://{output_path}");

    // Start the HTTP-01 challenge responder.
    let responder = challenge::ChallengeResponder::start().await;

    // Start the in-process Akamu server.
    let server = server::start(&seed_spec.ca, responder.port(), &artifacts_dir, &db_url).await;

    // Register profiles and issue cross-certificates.
    setup::register_profiles(&server.state, &seed_spec.profile);
    let cross_count = setup::issue_cross_certs(&server.state, &seed_spec.cross_sign)
        .await
        .map_err(|e| format!("cross-cert setup: {e}"))?;
    tracing::info!("issued {cross_count} cross-certificate(s)");

    // Create the dev admin operator + EAB key for web UI login.
    let dev_creds = setup::create_dev_admin(&server.state, &mut rng).await?;

    // Run each scenario.
    let mut outcomes: Vec<scenarios::ScenarioOutcome> = Vec::new();
    for scenario in &seed_spec.scenario {
        tracing::info!("running scenario '{}'", scenario.name);
        let outcome = scenarios::run_scenario(
            &server,
            &responder,
            scenario,
            &mut rng,
            cli.verbose,
        )
        .await?;
        outcomes.push(outcome);
    }

    // Post-process: apply lifecycle state mutations and checkpoint WAL.
    let stats = postprocess::run(&server, &outcomes).await?;

    // Write akamu.toml so the output can be used directly as a running instance.
    let db_filename = std::path::Path::new(&output_path)
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| output_path.clone());
    config_writer::write(
        &artifacts_dir,
        &db_filename,
        &seed_spec,
        &server.state.config.cas,
    )?;

    // Print summary.
    let summary = summary::Summary::build(&seed_spec, &outcomes, &stats, &output_path, &dev_creds);
    match cli.output_format.as_str() {
        "json" => summary.print_json(),
        _ => summary.print_text(),
    }

    Ok(())
}
