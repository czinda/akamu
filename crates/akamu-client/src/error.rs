use akamu_jose::JoseError;

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error(transparent)]
    Jose(#[from] JoseError),
    #[error("HTTP error: {0}")]
    Http(String),
    #[error("ACME error {acme_type}: {detail}")]
    Acme { acme_type: String, detail: String },
    #[error("crypto error: {0}")]
    Crypto(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("GSSAPI error: {0}")]
    Gssapi(String),
}
