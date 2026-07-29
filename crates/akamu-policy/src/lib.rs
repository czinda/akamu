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
