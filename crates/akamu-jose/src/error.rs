//! Error type for akamu-jose — no axum or rusqlite dependency.

/// Errors produced by JWK/JWS operations.
#[derive(Debug, thiserror::Error)]
pub enum JoseError {
    #[error("bad request: {0}")]
    BadRequest(String),

    #[error("crypto error: {0}")]
    Crypto(String),

    #[error("unsupported algorithm: {0}")]
    UnsupportedAlgorithm(String),

    #[error("base64: {0}")]
    Base64(#[from] base64::DecodeError),

    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
}
