//! akamu-mtc-validator — MTC test vector generation and validation tool.

use std::path::{Path, PathBuf};

use clap::{Parser, Subcommand};

use akamu_mtc_validator::{build_artifacts, validate_layer_a, validate_layer_b, MtcVectors};

/// Default path to the bundled test vectors relative to the repo root.
const DEFAULT_VECTORS: &str = "contrib/test-vectors/mtc/mtc.json";
/// Default path to pre-generated Go reference artifacts.
const DEFAULT_REFERENCE: &str = "contrib/test-vectors/mtc/reference";

#[derive(Parser)]
#[command(name = "akamu-mtc-validator", about = "MTC test vector validator")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generate MTC artifacts from mtc.json and print a summary.
    Generate {
        #[arg(long, default_value = DEFAULT_VECTORS)]
        vectors: PathBuf,
    },
    /// Run Layer B internal consistency checks on generated artifacts.
    Check {
        #[arg(long, default_value = DEFAULT_VECTORS)]
        vectors: PathBuf,
        /// Also run Layer A comparison against reference artifacts.
        #[arg(long)]
        reference: Option<PathBuf>,
        /// Exit with non-zero code on any failure.
        #[arg(long)]
        fail_fast: bool,
    },
    /// Run Layer A byte comparison against pre-generated Go reference artifacts.
    Validate {
        #[arg(long, default_value = DEFAULT_VECTORS)]
        vectors: PathBuf,
        #[arg(long, default_value = DEFAULT_REFERENCE)]
        reference: PathBuf,
    },
}

fn main() {
    let cli = Cli::parse();
    let result = match cli.command {
        Command::Generate { vectors } => cmd_generate(&vectors),
        Command::Check {
            vectors,
            reference,
            fail_fast,
        } => cmd_check(&vectors, reference.as_deref(), fail_fast),
        Command::Validate { vectors, reference } => cmd_validate(&vectors, &reference),
    };
    if let Err(e) = result {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

fn cmd_generate(vectors_path: &Path) -> akamu_mtc_validator::Result<()> {
    let vectors = MtcVectors::load(vectors_path)?;
    let artifacts = build_artifacts(&vectors)?;
    println!("tree_size:  {}", artifacts.tree_size);
    println!("certs:      {}", artifacts.certs.len());
    println!("leaf[0]:    {}", hex_str(&artifacts.leaf_hashes[0]));
    if let Ok(root) = artifacts.compute_root() {
        println!("root:       {}", hex_str(&root));
    }
    Ok(())
}

fn cmd_check(
    vectors_path: &Path,
    reference: Option<&Path>,
    fail_fast: bool,
) -> akamu_mtc_validator::Result<()> {
    let vectors = MtcVectors::load(vectors_path)?;
    let artifacts = build_artifacts(&vectors)?;

    let mut report = validate_layer_b(&vectors, &artifacts)?;
    if let Some(ref_dir) = reference {
        let layer_a = validate_layer_a(&artifacts, ref_dir)?;
        report.checks.extend(layer_a.checks);
    }

    report.print();
    if fail_fast && !report.all_pass() {
        std::process::exit(1);
    }
    Ok(())
}

fn cmd_validate(vectors_path: &Path, reference: &Path) -> akamu_mtc_validator::Result<()> {
    let vectors = MtcVectors::load(vectors_path)?;
    let artifacts = build_artifacts(&vectors)?;
    let report = validate_layer_a(&artifacts, reference)?;
    report.print();
    if !report.all_pass() {
        std::process::exit(1);
    }
    Ok(())
}

fn hex_str(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
