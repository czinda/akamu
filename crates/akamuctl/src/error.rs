//! akamuctl error types.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum CtlError {
    #[error("configuration error: {0}")]
    Config(String),
    #[error("authentication error: {0}")]
    Auth(String),
    #[error("HTTP error: {0}")]
    Http(String),
    #[error("TLS error: {0}")]
    Tls(String),
    #[error("API error: {0}")]
    Api(String),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

impl CtlError {
    /// Return the exit code to use for this error.
    pub fn exit_code(&self) -> i32 {
        match self {
            CtlError::Auth(_) => 2,
            CtlError::Config(_) => 3,
            _ => 1,
        }
    }
}
