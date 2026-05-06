//! GET /acme/renewal-info/{cert_id} — RFC 9773 (ARI)

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::json;

use crate::db;
use crate::error::AcmeError;
use crate::state::AppState;

use super::{fmt_time, unix_now, CaId};

pub async fn get_renewal_info(
    State(state): State<Arc<AppState>>,
    ca_id: CaId,
    Path(cert_id): Path<String>,
) -> Result<Response, AcmeError> {
    let ca = state
        .get_ca(&ca_id.0)
        .ok_or_else(|| AcmeError::Internal(format!("no CA for id '{}'", ca_id.0)))?;

    // cert_id is base64url(AKI) "." base64url(serial bytes) per RFC 9773 §4.1.
    // Validate the AKI component against the CA's key identifier (RFC 9773 §4.1):
    // a cert-id whose AKI does not belong to this CA must return 404.
    {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;
        let dot = cert_id
            .find('.')
            .ok_or_else(|| AcmeError::BadRequest("cert_id missing '.' separator".into()))?;
        let aki_b64 = &cert_id[..dot];
        let aki_bytes = URL_SAFE_NO_PAD
            .decode(aki_b64)
            .map_err(|_| AcmeError::BadRequest("cert_id AKI is not valid base64url".into()))?;
        if aki_bytes != ca.aki_bytes {
            return Err(AcmeError::NotFound);
        }
    }

    let cert = db::certs::get_by_cert_id(&state.db_ro, &cert_id)
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

    let mut obj = json!({
        "suggestedWindow": {
            "start": fmt_time(window_start),
            "end":   fmt_time(window_end),
        },
    });
    if let Some(url) = &state.config.server.ari_explanation_url {
        obj["explanationURL"] = serde_json::Value::String(url.clone());
    }

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
