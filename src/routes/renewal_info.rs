//! GET /acme/renewal-info/{cert_id} — RFC 9773 (ARI)

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::json;

use crate::db;
use crate::error::AcmeError;
use crate::state::AppState;

use super::{fmt_time, unix_now};

pub async fn get_renewal_info(
    State(state): State<Arc<AppState>>,
    Path(cert_id): Path<String>,
) -> Result<Response, AcmeError> {
    // cert_id is base64url(AKI) "." base64url(serial bytes) per RFC 9773 §4.1
    let cert = db::certs::get_by_cert_id(&state.db, &cert_id)
        .await?
        .ok_or(AcmeError::NotFound)?;

    let now = unix_now();

    // Use explicitly set renewal window if available; otherwise compute a default.
    let (window_start, window_end) = match (cert.suggested_window_start, cert.suggested_window_end)
    {
        (Some(s), Some(e)) => (s, e),
        _ => {
            // Default: suggest renewal in the last third of the certificate's validity.
            let lifetime = cert.not_after - cert.not_before;
            let renewal_start = cert.not_before + (lifetime * 2 / 3);
            let renewal_end = cert.not_after - 86400; // 1 day before expiry
            (renewal_start.max(now), renewal_end.max(renewal_start))
        }
    };

    let obj = json!({
        "suggestedWindow": {
            "start": fmt_time(window_start),
            "end":   fmt_time(window_end),
        },
    });

    // Return 200 with renewal info and Retry-After (RFC 9773 §4.3).
    // ARI does not use the ACME JWS envelope.
    let mut resp = (StatusCode::OK, axum::Json(obj)).into_response();
    resp.headers_mut().insert(
        axum::http::header::CONTENT_TYPE,
        "application/json".parse().unwrap(),
    );
    resp.headers_mut().insert(
        axum::http::header::RETRY_AFTER,
        state
            .config
            .server
            .ari_retry_after_secs
            .to_string()
            .parse()
            .unwrap(),
    );
    Ok(resp)
}
