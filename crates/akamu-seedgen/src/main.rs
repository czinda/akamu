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

use std::collections::HashSet;

use akamu::db;
use clap::Parser;
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;

#[derive(Parser, Debug)]
#[command(
    name = "akamu-seedgen",
    about = "Generate realistic Akamu PKI test data"
)]
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

    /// Resume an interrupted run — do not delete the existing database.
    /// Completed scenarios (recorded in _seedgen_progress) are skipped;
    /// previously issued certificates are preserved.
    #[arg(long)]
    resume: bool,

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
            tracing_subscriber::EnvFilter::from_default_env().add_directive(if cli.verbose {
                "info".parse().unwrap()
            } else {
                "warn".parse().unwrap()
            }),
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
    let output_path = cli
        .output
        .as_deref()
        .unwrap_or(&seed_spec.global.output)
        .to_string();

    let seed = seed_spec.global.seed;

    // Artifacts directory: output path with its extension stripped.
    // e.g. "test-data.sqlite3" → "test-data/" (sibling of the DB file).
    let artifacts_dir = std::path::Path::new(&output_path).with_extension("");
    std::fs::create_dir_all(&artifacts_dir)
        .map_err(|e| format!("create artifacts dir '{}': {e}", artifacts_dir.display()))?;

    tracing::info!(
        "starting akamu-seedgen (seed={seed}, output='{output_path}', artifacts='{}', resume={})",
        artifacts_dir.display(),
        cli.resume,
    );

    if cli.resume {
        eprintln!("akamu-seedgen: resuming from existing database '{output_path}'");
    } else {
        // Remove any pre-existing output file so db::open() starts with a fresh schema.
        if std::path::Path::new(&output_path).exists() {
            std::fs::remove_file(&output_path)
                .map_err(|e| format!("remove existing output '{output_path}': {e}"))?;
        }
        // Also remove WAL/SHM files from any previous run.
        for suffix in &["-wal", "-shm"] {
            let sidecar = format!("{output_path}{suffix}");
            if let Err(e) = std::fs::remove_file(&sidecar) {
                if e.kind() != std::io::ErrorKind::NotFound {
                    tracing::warn!(path = ?sidecar, error = %e, "could not remove WAL sidecar");
                }
            }
        }
    }

    let db_url = format!("sqlite://{output_path}");

    // Start the HTTP-01 challenge responder.
    let responder = challenge::ChallengeResponder::start().await;

    // Start the in-process Akamu server.
    let server = server::start(&seed_spec.ca, responder.port(), &artifacts_dir, &db_url).await;

    // Create the progress-tracking table (idempotent; exists on fresh and resumed runs alike).
    db::query(
        "CREATE TABLE IF NOT EXISTS _seedgen_progress \
         (scenario_name TEXT PRIMARY KEY, completed_at INTEGER NOT NULL)",
    )
    .execute(&server.db)
    .await
    .map_err(|e| format!("create _seedgen_progress table: {e}"))?;

    // Determine which scenarios are already complete.
    // On resume with an old DB (no _seedgen_progress rows), bootstrap completion
    // detection from cert counts: if a CA has ≥90% of its expected certs, consider done.
    let completed: HashSet<String> = if cli.resume {
        let recorded: HashSet<String> =
            db::query_scalar::<String>("SELECT scenario_name FROM _seedgen_progress")
                .fetch_all(&server.db)
                .await
                .map_err(|e| format!("read _seedgen_progress: {e}"))?
                .into_iter()
                .collect();

        let mut detected = recorded.clone();
        for scenario in &seed_spec.scenario {
            if detected.contains(&scenario.name) {
                continue;
            }
            let actual: i64 = db::query_scalar("SELECT COUNT(*) FROM certificates WHERE ca_id = ?")
                .bind(&scenario.ca_id)
                .fetch_one(&server.db)
                .await
                .map_err(|e| format!("count certs for CA '{}': {e}", scenario.ca_id))?;

            let sc = &scenario.certs;
            let expected = (sc.valid
                + sc.revoked
                + sc.expired
                + sc.near_expiry
                + sc.ari_chains * 3
                + sc.star_active
                + sc.star_canceled) as i64;

            // 90% threshold — tolerates a handful of invalid orders from a previous crash.
            let threshold = expected.saturating_sub(expected / 10);
            if actual >= threshold {
                tracing::info!(
                    scenario = %scenario.name,
                    ca_id = %scenario.ca_id,
                    found = actual,
                    expected = expected,
                    "auto-detected as complete (bootstrap); marking in _seedgen_progress",
                );
                let now = akamu::util::unix_now();
                db::query(
                    "INSERT OR IGNORE INTO _seedgen_progress (scenario_name, completed_at) VALUES (?, ?)",
                )
                .bind(&scenario.name)
                .bind(now)
                .execute(&server.db)
                .await
                .map_err(|e| format!("bootstrap _seedgen_progress for '{}': {e}", scenario.name))?;
                detected.insert(scenario.name.clone());
            }
        }
        detected
    } else {
        HashSet::new()
    };

    // Cross-cert setup — skip if already present in the DB (resume mode).
    let existing_cross_certs: i64 = db::query_scalar("SELECT COUNT(*) FROM cross_certs")
        .fetch_one(&server.db)
        .await
        .map_err(|e| format!("count cross_certs: {e}"))?;

    if existing_cross_certs == 0 {
        let cross_count = setup::issue_cross_certs(&server.state, &seed_spec.cross_sign)
            .await
            .map_err(|e| format!("cross-cert setup: {e}"))?;
        tracing::info!("issued {cross_count} cross-certificate(s)");
    } else {
        tracing::info!(
            count = existing_cross_certs,
            "skipping cross-cert setup — already present in DB"
        );
    }

    // Profile setup (warns+skips duplicates; safe to call on resume).
    setup::register_profiles(&server.state, &seed_spec.profile);

    // Global RNG — used only for create_dev_admin (32 bytes).
    // Always advanced by the same amount so the scenario seeds below are stable.
    let mut global_rng = ChaCha8Rng::seed_from_u64(seed);
    let dev_creds = setup::create_dev_admin(&server.state, &mut global_rng).await?;

    // Run scenarios — per-scenario seed derivation so each scenario is independent.
    // Skipping completed scenarios does NOT affect the RNG used by subsequent scenarios.
    let mut outcomes: Vec<scenarios::ScenarioOutcome> = Vec::new();
    let mut total_stats = postprocess::PostprocessStats::default();

    for (idx, scenario) in seed_spec.scenario.iter().enumerate() {
        if completed.contains(&scenario.name) {
            tracing::info!(scenario = %scenario.name, "skipping completed scenario");
            eprintln!(
                "akamu-seedgen: skip  [{}] (already complete)",
                scenario.name
            );
            continue;
        }

        eprintln!("akamu-seedgen: start [{}]", scenario.name);

        // Derive a per-scenario seed so each scenario is independently reproducible
        // and skipping a completed scenario does not shift subsequent scenarios' RNG.
        let scenario_seed = seed.wrapping_add((idx as u64 + 1).wrapping_mul(0x9e3779b97f4a7c15));
        let mut scenario_rng = ChaCha8Rng::seed_from_u64(scenario_seed);

        let outcome = scenarios::run_scenario(
            &server,
            &responder,
            scenario,
            &mut scenario_rng,
            cli.verbose,
        )
        .await?;

        // Post-process this scenario immediately so that on a future --resume
        // the mutations are already applied to the on-disk DB before we record
        // the scenario as complete.
        let stats = postprocess::run(&server, std::slice::from_ref(&outcome)).await?;
        total_stats.revoked += stats.revoked;
        total_stats.expired += stats.expired;
        total_stats.near_expiry += stats.near_expiry;
        total_stats.ari_chains_linked += stats.ari_chains_linked;
        total_stats.invalid_orders += stats.invalid_orders;

        // Record completion — only after both issuance and postprocess succeed.
        let now = akamu::util::unix_now();
        db::query(
            "INSERT OR REPLACE INTO _seedgen_progress (scenario_name, completed_at) VALUES (?, ?)",
        )
        .bind(&scenario.name)
        .bind(now)
        .execute(&server.db)
        .await
        .map_err(|e| format!("record scenario '{}' completion: {e}", scenario.name))?;

        eprintln!("akamu-seedgen: done  [{}]", scenario.name);
        outcomes.push(outcome);
    }

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

    // Print summary (only covers scenarios run in this invocation).
    let summary = summary::Summary::build(
        &seed_spec,
        &outcomes,
        &total_stats,
        &output_path,
        &dev_creds,
    );
    match cli.output_format.as_str() {
        "json" => summary.print_json(),
        _ => summary.print_text(),
    }

    Ok(())
}
