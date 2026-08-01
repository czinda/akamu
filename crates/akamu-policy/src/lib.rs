//! `akamu-policy` — ABAC issuance policy engine for the akamu ACME server.
//!
//! Wraps [`abac_rs`] to evaluate certificate-issuance requests against a set
//! of allow/deny rules keyed on account, profile, CA, key type, account
//! group, and per-SAN identifier. Rules come from two sources merged at
//! build time: static rules in the server's TOML config and dynamic rules
//! stored in the database (editable via the admin API), the latter with a
//! shadow/enforce mode so a rule set can be validated against real traffic
//! before it starts blocking issuance.

pub mod compat;
pub mod config;
pub(crate) mod dimension;
pub mod engine;
pub(crate) mod matcher;
pub mod request;

pub use abac_rs::Decision;

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum PolicyError {
    #[error("request error: {0}")]
    Request(#[from] abac_rs::RequestError),
    #[error("policy error: {0}")]
    Policy(#[from] abac_rs::policy::PolicyError),
    #[error("invalid rule: {0}")]
    InvalidRule(String),
    #[error("regex error: {0}")]
    Regex(#[from] regex::Error),
    #[error("temporal error: {0}")]
    Temporal(#[from] abac_rs::TemporalError),
    #[error("validation error: {0}")]
    Validation(String),
}
