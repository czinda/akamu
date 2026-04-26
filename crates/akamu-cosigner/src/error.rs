use thiserror::Error;

#[derive(Debug, Error)]
pub enum CosignerError {
    #[error("bad request: {0}")]
    BadRequest(String),

    #[error("crypto error: {0}")]
    Crypto(String),

    #[error("config error: {0}")]
    Config(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("ASN.1 error: {0}")]
    Asn1(String),

    #[error("ACME error: {0}")]
    Acme(String),

    #[error("no challenge of type '{0}' offered by server")]
    NoChallengeType(String),

    #[error("unknown challenge type '{0}'")]
    UnknownChallengeType(String),

    #[error("TLS config error: {0}")]
    Tls(String),
}

impl From<synta::Error> for CosignerError {
    fn from(e: synta::Error) -> Self {
        CosignerError::Asn1(e.to_string())
    }
}

impl From<akamu::error::AcmeError> for CosignerError {
    fn from(e: akamu::error::AcmeError) -> Self {
        CosignerError::Crypto(e.to_string())
    }
}

impl From<akamu_client::ClientError> for CosignerError {
    fn from(e: akamu_client::ClientError) -> Self {
        CosignerError::Acme(e.to_string())
    }
}

impl axum::response::IntoResponse for CosignerError {
    fn into_response(self) -> axum::response::Response {
        use axum::http::StatusCode;
        let status = match &self {
            CosignerError::BadRequest(_) => StatusCode::BAD_REQUEST,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        };
        (status, self.to_string()).into_response()
    }
}
