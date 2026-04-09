use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;

/// ACME problem+json error (RFC 7807 / RFC 8555 §6.7)
#[derive(Debug, thiserror::Error)]
pub enum AcmeError {
    // ── ACME-specific errors (urn:ietf:params:acme:error:*) ──────────────────

    #[error("bad nonce")]
    BadNonce,

    #[error("bad signature algorithm: {0}")]
    BadSignatureAlgorithm(String),

    #[error("unauthorized: {0}")]
    Unauthorized(String),

    #[error("account does not exist")]
    AccountDoesNotExist,

    #[error("account already exists")]
    AccountAlreadyExists,

    #[error("invalid contact: {0}")]
    InvalidContact(String),

    #[error("unsupported contact")]
    UnsupportedContact,

    #[error("user action required: {0}")]
    UserActionRequired(String),

    #[error("rejected identifier: {0}")]
    RejectedIdentifier(String),

    #[error("unsupported identifier: {0}")]
    UnsupportedIdentifier(String),

    #[error("order not ready")]
    OrderNotReady,

    #[error("bad CSR: {0}")]
    BadCsr(String),

    #[error("bad revocation reason")]
    BadRevocationReason,

    #[error("certificate revoked")]
    AlreadyRevoked,

    #[error("CAA check failed: {0}")]
    Caa(String),

    #[error("connection error during challenge: {0}")]
    Connection(String),

    #[error("DNS error: {0}")]
    Dns(String),

    #[error("incorrect response during challenge: {0}")]
    IncorrectResponse(String),

    #[error("TLS error: {0}")]
    Tls(String),

    // ── Generic HTTP-mapped errors ────────────────────────────────────────────

    #[error("not found")]
    NotFound,

    #[error("method not allowed")]
    MethodNotAllowed,

    #[error("conflict: {0}")]
    Conflict(String),

    #[error("unsupported media type")]
    UnsupportedMediaType,

    #[error("request entity too large")]
    PayloadTooLarge,

    #[error("bad request: {0}")]
    BadRequest(String),

    // ── Internal errors ───────────────────────────────────────────────────────

    #[error("database error: {0}")]
    Database(String),

    #[error("crypto error: {0}")]
    Crypto(String),

    #[error("certificate builder error: {0}")]
    Builder(String),

    #[error("MTC error: {0}")]
    Mtc(String),

    #[error("internal server error: {0}")]
    Internal(String),
}

impl From<tokio_rusqlite::Error> for AcmeError {
    fn from(e: tokio_rusqlite::Error) -> Self {
        AcmeError::Database(e.to_string())
    }
}

impl From<rusqlite::Error> for AcmeError {
    fn from(e: rusqlite::Error) -> Self {
        AcmeError::Database(e.to_string())
    }
}

impl AcmeError {
    fn acme_type(&self) -> &'static str {
        match self {
            AcmeError::BadNonce => "urn:ietf:params:acme:error:badNonce",
            AcmeError::BadSignatureAlgorithm(_) => "urn:ietf:params:acme:error:badSignatureAlgorithm",
            AcmeError::Unauthorized(_) => "urn:ietf:params:acme:error:unauthorized",
            AcmeError::AccountDoesNotExist => "urn:ietf:params:acme:error:accountDoesNotExist",
            AcmeError::AccountAlreadyExists => "urn:ietf:params:acme:error:accountAlreadyExists",
            AcmeError::InvalidContact(_) => "urn:ietf:params:acme:error:invalidContact",
            AcmeError::UnsupportedContact => "urn:ietf:params:acme:error:unsupportedContact",
            AcmeError::UserActionRequired(_) => "urn:ietf:params:acme:error:userActionRequired",
            AcmeError::RejectedIdentifier(_) => "urn:ietf:params:acme:error:rejectedIdentifier",
            AcmeError::UnsupportedIdentifier(_) => "urn:ietf:params:acme:error:unsupportedIdentifier",
            AcmeError::OrderNotReady => "urn:ietf:params:acme:error:orderNotReady",
            AcmeError::BadCsr(_) => "urn:ietf:params:acme:error:badCSR",
            AcmeError::BadRevocationReason => "urn:ietf:params:acme:error:badRevocationReason",
            AcmeError::AlreadyRevoked => "urn:ietf:params:acme:error:alreadyRevoked",
            AcmeError::Caa(_) => "urn:ietf:params:acme:error:caa",
            AcmeError::Connection(_) => "urn:ietf:params:acme:error:connection",
            AcmeError::Dns(_) => "urn:ietf:params:acme:error:dns",
            AcmeError::IncorrectResponse(_) => "urn:ietf:params:acme:error:incorrectResponse",
            AcmeError::Tls(_) => "urn:ietf:params:acme:error:tls",
            _ => "urn:ietf:params:acme:error:serverInternal",
        }
    }

    fn http_status(&self) -> StatusCode {
        match self {
            AcmeError::BadNonce => StatusCode::BAD_REQUEST,
            AcmeError::BadSignatureAlgorithm(_) => StatusCode::BAD_REQUEST,
            AcmeError::Unauthorized(_) => StatusCode::UNAUTHORIZED,
            AcmeError::AccountDoesNotExist => StatusCode::BAD_REQUEST,
            AcmeError::AccountAlreadyExists => StatusCode::CONFLICT,
            AcmeError::InvalidContact(_) => StatusCode::BAD_REQUEST,
            AcmeError::UnsupportedContact => StatusCode::BAD_REQUEST,
            AcmeError::UserActionRequired(_) => StatusCode::FORBIDDEN,
            AcmeError::RejectedIdentifier(_) => StatusCode::BAD_REQUEST,
            AcmeError::UnsupportedIdentifier(_) => StatusCode::BAD_REQUEST,
            AcmeError::OrderNotReady => StatusCode::FORBIDDEN,
            AcmeError::BadCsr(_) => StatusCode::BAD_REQUEST,
            AcmeError::BadRevocationReason => StatusCode::BAD_REQUEST,
            AcmeError::AlreadyRevoked => StatusCode::BAD_REQUEST,
            AcmeError::Caa(_) => StatusCode::FORBIDDEN,
            AcmeError::Connection(_) => StatusCode::BAD_REQUEST,
            AcmeError::Dns(_) => StatusCode::BAD_REQUEST,
            AcmeError::IncorrectResponse(_) => StatusCode::BAD_REQUEST,
            AcmeError::Tls(_) => StatusCode::BAD_REQUEST,
            AcmeError::NotFound => StatusCode::NOT_FOUND,
            AcmeError::MethodNotAllowed => StatusCode::METHOD_NOT_ALLOWED,
            AcmeError::Conflict(_) => StatusCode::CONFLICT,
            AcmeError::UnsupportedMediaType => StatusCode::UNSUPPORTED_MEDIA_TYPE,
            AcmeError::PayloadTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            AcmeError::BadRequest(_) => StatusCode::BAD_REQUEST,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

impl IntoResponse for AcmeError {
    fn into_response(self) -> Response {
        let status = self.http_status();
        let body = json!({
            "type": self.acme_type(),
            "status": status.as_u16(),
            "detail": self.to_string(),
        });
        let mut resp = (status, Json(body)).into_response();
        resp.headers_mut().insert(
            axum::http::header::CONTENT_TYPE,
            "application/problem+json".parse().unwrap(),
        );
        resp
    }
}
