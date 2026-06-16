//! MTC RFC draft validation and test vector tool for akamu.
//!
//! Generates MTC log artifacts from `mtc.json` test vectors and validates them
//! for internal consistency (Layer B) and byte-for-byte comparison against Go
//! reference artifacts (Layer A).

pub mod generate;
pub mod validate;
pub mod vectors;

use thiserror::Error;

/// Errors produced by this crate.
#[derive(Debug, Error)]
pub enum Error {
    #[error("I/O error: {0}")]
    Io(String),
    #[error("parse error: {0}")]
    Parse(String),
    #[error("crypto error: {0}")]
    Crypto(String),
    #[error("subtree alignment error: {0}")]
    SubtreeAlignment(String),
}

pub type Result<T> = std::result::Result<T, Error>;

pub use generate::{build_artifacts, GeneratedArtifacts};
pub use validate::{validate_layer_a, validate_layer_b, CheckResult, ValidationReport};
pub use vectors::MtcVectors;
