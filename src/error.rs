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

    #[error("certificate has already been replaced")]
    CertAlreadyReplaced,

    #[error("bad CSR: {0}")]
    BadCsr(String),

    #[error("bad revocation reason")]
    BadRevocationReason,

    #[error("certificate revoked")]
    AlreadyRevoked,

    #[error("CAA check failed: {0}")]
    Caa(String),

    #[error("external account binding required")]
    ExternalAccountRequired,

    #[error("connection error during challenge: {0}")]
    Connection(String),

    #[error("DNS error: {0}")]
    Dns(String),

    #[error("incorrect response during challenge: {0}")]
    IncorrectResponse(String),

    #[error("TLS error: {0}")]
    Tls(String),

    // ── draft-aaron-acme-profiles-01 ─────────────────────────────────────────
    #[error("invalid profile: {0}")]
    InvalidProfile(String),

    // ── RFC 8739 STAR errors ──────────────────────────────────────────────────
    #[error("auto-renewal has been canceled")]
    AutoRenewalCanceled,

    #[error("auto-renewal cancellation invalid: order not in valid state")]
    AutoRenewalCancellationInvalid,

    #[error("auto-renewal certificates cannot be revoked")]
    AutoRenewalRevocationNotSupported,

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

impl From<akamu_jose::JoseError> for AcmeError {
    fn from(e: akamu_jose::JoseError) -> Self {
        match e {
            akamu_jose::JoseError::BadRequest(msg) => AcmeError::BadRequest(msg),
            akamu_jose::JoseError::Crypto(msg) => AcmeError::Crypto(msg),
            akamu_jose::JoseError::UnsupportedAlgorithm(msg) => {
                AcmeError::BadSignatureAlgorithm(msg)
            }
            akamu_jose::JoseError::Base64(e) => AcmeError::BadRequest(format!("base64 error: {e}")),
            akamu_jose::JoseError::Json(e) => AcmeError::BadRequest(format!("JSON error: {e}")),
        }
    }
}

impl From<sqlx::Error> for AcmeError {
    fn from(e: sqlx::Error) -> Self {
        AcmeError::Database(e.to_string())
    }
}

impl AcmeError {
    fn acme_type(&self) -> &'static str {
        match self {
            AcmeError::BadNonce => "urn:ietf:params:acme:error:badNonce",
            AcmeError::BadSignatureAlgorithm(_) => {
                "urn:ietf:params:acme:error:badSignatureAlgorithm"
            }
            AcmeError::Unauthorized(_) => "urn:ietf:params:acme:error:unauthorized",
            AcmeError::AccountDoesNotExist => "urn:ietf:params:acme:error:accountDoesNotExist",
            AcmeError::AccountAlreadyExists => "urn:ietf:params:acme:error:accountAlreadyExists",
            AcmeError::InvalidContact(_) => "urn:ietf:params:acme:error:invalidContact",
            AcmeError::UnsupportedContact => "urn:ietf:params:acme:error:unsupportedContact",
            AcmeError::UserActionRequired(_) => "urn:ietf:params:acme:error:userActionRequired",
            AcmeError::RejectedIdentifier(_) => "urn:ietf:params:acme:error:rejectedIdentifier",
            AcmeError::UnsupportedIdentifier(_) => {
                "urn:ietf:params:acme:error:unsupportedIdentifier"
            }
            AcmeError::OrderNotReady => "urn:ietf:params:acme:error:orderNotReady",
            AcmeError::CertAlreadyReplaced => "urn:ietf:params:acme:error:alreadyReplaced",
            AcmeError::BadCsr(_) => "urn:ietf:params:acme:error:badCSR",
            AcmeError::BadRevocationReason => "urn:ietf:params:acme:error:badRevocationReason",
            AcmeError::AlreadyRevoked => "urn:ietf:params:acme:error:alreadyRevoked",
            AcmeError::Caa(_) => "urn:ietf:params:acme:error:caa",
            AcmeError::Connection(_) => "urn:ietf:params:acme:error:connection",
            AcmeError::Dns(_) => "urn:ietf:params:acme:error:dns",
            AcmeError::IncorrectResponse(_) => "urn:ietf:params:acme:error:incorrectResponse",
            AcmeError::Tls(_) => "urn:ietf:params:acme:error:tls",
            AcmeError::ExternalAccountRequired => {
                "urn:ietf:params:acme:error:externalAccountRequired"
            }
            AcmeError::AutoRenewalCanceled => "urn:ietf:params:acme:error:autoRenewalCanceled",
            AcmeError::AutoRenewalCancellationInvalid => {
                "urn:ietf:params:acme:error:autoRenewalCancellationInvalid"
            }
            AcmeError::AutoRenewalRevocationNotSupported => {
                "urn:ietf:params:acme:error:autoRenewalRevocationNotSupported"
            }
            AcmeError::InvalidProfile(_) => "urn:ietf:params:acme:error:invalidProfile",
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
            AcmeError::CertAlreadyReplaced => StatusCode::CONFLICT,
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
            AcmeError::ExternalAccountRequired => StatusCode::FORBIDDEN,
            AcmeError::AutoRenewalCanceled => StatusCode::FORBIDDEN,
            AcmeError::AutoRenewalCancellationInvalid => StatusCode::BAD_REQUEST,
            AcmeError::AutoRenewalRevocationNotSupported => StatusCode::FORBIDDEN,
            AcmeError::InvalidProfile(_) => StatusCode::BAD_REQUEST,
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
            axum::http::HeaderValue::from_static("application/problem+json"),
        );
        resp
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::StatusCode;

    #[test]
    fn acme_type_strings() {
        assert_eq!(
            AcmeError::BadNonce.acme_type(),
            "urn:ietf:params:acme:error:badNonce"
        );
        assert_eq!(
            AcmeError::BadSignatureAlgorithm("x".into()).acme_type(),
            "urn:ietf:params:acme:error:badSignatureAlgorithm"
        );
        assert_eq!(
            AcmeError::Unauthorized("x".into()).acme_type(),
            "urn:ietf:params:acme:error:unauthorized"
        );
        assert_eq!(
            AcmeError::AccountDoesNotExist.acme_type(),
            "urn:ietf:params:acme:error:accountDoesNotExist"
        );
        assert_eq!(
            AcmeError::AccountAlreadyExists.acme_type(),
            "urn:ietf:params:acme:error:accountAlreadyExists"
        );
        assert_eq!(
            AcmeError::InvalidContact("x".into()).acme_type(),
            "urn:ietf:params:acme:error:invalidContact"
        );
        assert_eq!(
            AcmeError::UnsupportedContact.acme_type(),
            "urn:ietf:params:acme:error:unsupportedContact"
        );
        assert_eq!(
            AcmeError::UserActionRequired("x".into()).acme_type(),
            "urn:ietf:params:acme:error:userActionRequired"
        );
        assert_eq!(
            AcmeError::RejectedIdentifier("x".into()).acme_type(),
            "urn:ietf:params:acme:error:rejectedIdentifier"
        );
        assert_eq!(
            AcmeError::UnsupportedIdentifier("x".into()).acme_type(),
            "urn:ietf:params:acme:error:unsupportedIdentifier"
        );
        assert_eq!(
            AcmeError::OrderNotReady.acme_type(),
            "urn:ietf:params:acme:error:orderNotReady"
        );
        assert_eq!(
            AcmeError::CertAlreadyReplaced.acme_type(),
            "urn:ietf:params:acme:error:alreadyReplaced"
        );
        assert_eq!(
            AcmeError::BadCsr("x".into()).acme_type(),
            "urn:ietf:params:acme:error:badCSR"
        );
        assert_eq!(
            AcmeError::BadRevocationReason.acme_type(),
            "urn:ietf:params:acme:error:badRevocationReason"
        );
        assert_eq!(
            AcmeError::AlreadyRevoked.acme_type(),
            "urn:ietf:params:acme:error:alreadyRevoked"
        );
        assert_eq!(
            AcmeError::Caa("x".into()).acme_type(),
            "urn:ietf:params:acme:error:caa"
        );
        assert_eq!(
            AcmeError::Connection("x".into()).acme_type(),
            "urn:ietf:params:acme:error:connection"
        );
        assert_eq!(
            AcmeError::Dns("x".into()).acme_type(),
            "urn:ietf:params:acme:error:dns"
        );
        assert_eq!(
            AcmeError::IncorrectResponse("x".into()).acme_type(),
            "urn:ietf:params:acme:error:incorrectResponse"
        );
        assert_eq!(
            AcmeError::Tls("x".into()).acme_type(),
            "urn:ietf:params:acme:error:tls"
        );
        assert_eq!(
            AcmeError::ExternalAccountRequired.acme_type(),
            "urn:ietf:params:acme:error:externalAccountRequired"
        );
        assert_eq!(
            AcmeError::AutoRenewalCanceled.acme_type(),
            "urn:ietf:params:acme:error:autoRenewalCanceled"
        );
        assert_eq!(
            AcmeError::AutoRenewalCancellationInvalid.acme_type(),
            "urn:ietf:params:acme:error:autoRenewalCancellationInvalid"
        );
        assert_eq!(
            AcmeError::AutoRenewalRevocationNotSupported.acme_type(),
            "urn:ietf:params:acme:error:autoRenewalRevocationNotSupported"
        );
        assert_eq!(
            AcmeError::InvalidProfile("unknown".into()).acme_type(),
            "urn:ietf:params:acme:error:invalidProfile"
        );
        // Internal/generic errors fall through to serverInternal
        assert_eq!(
            AcmeError::NotFound.acme_type(),
            "urn:ietf:params:acme:error:serverInternal"
        );
        assert_eq!(
            AcmeError::Internal("x".into()).acme_type(),
            "urn:ietf:params:acme:error:serverInternal"
        );
        assert_eq!(
            AcmeError::Database("x".into()).acme_type(),
            "urn:ietf:params:acme:error:serverInternal"
        );
    }

    #[test]
    fn http_status_codes() {
        assert_eq!(AcmeError::BadNonce.http_status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            AcmeError::BadSignatureAlgorithm("x".into()).http_status(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            AcmeError::Unauthorized("x".into()).http_status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            AcmeError::AccountDoesNotExist.http_status(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            AcmeError::AccountAlreadyExists.http_status(),
            StatusCode::CONFLICT
        );
        assert_eq!(
            AcmeError::InvalidContact("x".into()).http_status(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            AcmeError::UnsupportedContact.http_status(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            AcmeError::UserActionRequired("x".into()).http_status(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            AcmeError::RejectedIdentifier("x".into()).http_status(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            AcmeError::UnsupportedIdentifier("x".into()).http_status(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            AcmeError::OrderNotReady.http_status(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            AcmeError::CertAlreadyReplaced.http_status(),
            StatusCode::CONFLICT
        );
        assert_eq!(
            AcmeError::BadCsr("x".into()).http_status(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            AcmeError::BadRevocationReason.http_status(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            AcmeError::AlreadyRevoked.http_status(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            AcmeError::Caa("x".into()).http_status(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            AcmeError::Connection("x".into()).http_status(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            AcmeError::Dns("x".into()).http_status(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            AcmeError::IncorrectResponse("x".into()).http_status(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            AcmeError::Tls("x".into()).http_status(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(AcmeError::NotFound.http_status(), StatusCode::NOT_FOUND);
        assert_eq!(
            AcmeError::MethodNotAllowed.http_status(),
            StatusCode::METHOD_NOT_ALLOWED
        );
        assert_eq!(
            AcmeError::Conflict("x".into()).http_status(),
            StatusCode::CONFLICT
        );
        assert_eq!(
            AcmeError::UnsupportedMediaType.http_status(),
            StatusCode::UNSUPPORTED_MEDIA_TYPE
        );
        assert_eq!(
            AcmeError::PayloadTooLarge.http_status(),
            StatusCode::PAYLOAD_TOO_LARGE
        );
        assert_eq!(
            AcmeError::BadRequest("x".into()).http_status(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            AcmeError::Internal("x".into()).http_status(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
        assert_eq!(
            AcmeError::Database("x".into()).http_status(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
        assert_eq!(
            AcmeError::Crypto("x".into()).http_status(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
        assert_eq!(
            AcmeError::Builder("x".into()).http_status(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
        assert_eq!(
            AcmeError::Mtc("x".into()).http_status(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
        assert_eq!(
            AcmeError::ExternalAccountRequired.http_status(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            AcmeError::AutoRenewalCanceled.http_status(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            AcmeError::AutoRenewalCancellationInvalid.http_status(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            AcmeError::AutoRenewalRevocationNotSupported.http_status(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            AcmeError::InvalidProfile("x".into()).http_status(),
            StatusCode::BAD_REQUEST
        );
    }

    #[test]
    fn display_messages() {
        assert_eq!(AcmeError::BadNonce.to_string(), "bad nonce");
        assert_eq!(AcmeError::NotFound.to_string(), "not found");
        assert_eq!(
            AcmeError::BadCsr("malformed".into()).to_string(),
            "bad CSR: malformed"
        );
        assert_eq!(
            AcmeError::Database("conn failed".into()).to_string(),
            "database error: conn failed"
        );
    }

    #[test]
    fn from_sqlx_error() {
        // sqlx::Error::RowNotFound is a simple variant that requires no external deps.
        let sqlx_err = sqlx::Error::RowNotFound;
        let acme_err = AcmeError::from(sqlx_err);
        assert!(matches!(acme_err, AcmeError::Database(_)));
    }

    #[test]
    fn into_response_has_problem_json_content_type() {
        let resp = AcmeError::BadNonce.into_response();
        assert_eq!(
            resp.headers()
                .get(axum::http::header::CONTENT_TYPE)
                .unwrap(),
            "application/problem+json"
        );
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }
}
