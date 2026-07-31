//! Shared error type for admin API handlers (`/admin/...`).
//!
//! Unlike [`crate::error::AcmeError`] (RFC 7807 `application/problem+json`
//! with ACME-protocol `type`/`title` fields), the admin API is not part of
//! the ACME protocol and has always returned a plain `{"status": N,
//! "detail": "..."}` body. This type preserves that exact shape while
//! letting handlers use `?` instead of hand-rolling
//! `(StatusCode, Json(json!(...))).into_response()` at every call site.
//!
//! Every 5xx variant is logged via `tracing::error!` on conversion to a
//! response — this closes the "some admin error paths never log" gap that
//! hand-rolled construction made easy to introduce by accident.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;

use crate::error::AcmeError;

#[derive(Debug, thiserror::Error)]
pub enum AdminApiError {
    #[error("{0}")]
    BadRequest(String),
    #[error("{0}")]
    Forbidden(String),
    #[error("{0}")]
    NotFound(String),
    #[error("{0}")]
    Conflict(String),
    #[error("{0}")]
    ServiceUnavailable(String),
    #[error("{0}")]
    Internal(String),
    /// Delegates to an [`AcmeError`]'s own status/detail/logging — used by
    /// admin handlers that call shared business logic (policy rebuild,
    /// `db::*` helpers) already returning `AcmeError`, so `?` composes
    /// without re-deriving a status mapping here.
    #[error(transparent)]
    Delegate(#[from] AcmeError),
}

impl From<sqlx::Error> for AdminApiError {
    fn from(e: sqlx::Error) -> Self {
        AdminApiError::Internal(format!("database error: {e}"))
    }
}

impl AdminApiError {
    fn status(&self) -> StatusCode {
        match self {
            AdminApiError::BadRequest(_) => StatusCode::BAD_REQUEST,
            AdminApiError::Forbidden(_) => StatusCode::FORBIDDEN,
            AdminApiError::NotFound(_) => StatusCode::NOT_FOUND,
            AdminApiError::Conflict(_) => StatusCode::CONFLICT,
            AdminApiError::ServiceUnavailable(_) => StatusCode::SERVICE_UNAVAILABLE,
            AdminApiError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
            AdminApiError::Delegate(e) => e.http_status(),
        }
    }
}

impl IntoResponse for AdminApiError {
    fn into_response(self) -> Response {
        if let AdminApiError::Delegate(e) = self {
            return e.into_response();
        }
        let status = self.status();
        if status.is_server_error() {
            tracing::error!(error = %self, status = status.as_u16(), "admin API internal error");
        }
        // 5xx detail is logged above but never sent to the client — same
        // redact-and-log pattern as AcmeError::into_response — since it may
        // carry raw DB/serialization error text (e.g. via `?` on a
        // `sqlx::Error`). 4xx variants are client-actionable and pass through
        // verbatim.
        let detail = if status.is_server_error() {
            "internal server error".to_string()
        } else {
            self.to_string()
        };
        (
            status,
            Json(json!({"status": status.as_u16(), "detail": detail})),
        )
            .into_response()
    }
}
