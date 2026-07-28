pub mod compat;
pub mod config;
pub(crate) mod dimension;
pub mod engine;
pub(crate) mod matcher;
pub mod request;

#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    #[error("request error: {0}")]
    Request(#[from] abac_rs::RequestError),
    #[error("policy error: {0}")]
    Policy(#[from] abac_rs::policy::PolicyError),
    #[error("invalid rule: {0}")]
    InvalidRule(String),
    #[error("regex error: {0}")]
    Regex(#[from] regex::Error),
}
