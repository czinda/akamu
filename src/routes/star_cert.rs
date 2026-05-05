//! GET /acme/cert/star/{order_id} — RFC 8739 §3.3 STAR certificate URL
//!
//! Returns the most recent certificate for an active STAR order.
//! If `allow_certificate_get` is set on the order, no authentication is required.

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};

use crate::db;
use crate::error::AcmeError;
use crate::state::AppState;

use super::{acme_prefix, parse_jws, unix_now, CaId};

/// GET handler — unauthenticated (allowed only when `allow_certificate_get = true`).
pub async fn star_cert_get(
    State(state): State<Arc<AppState>>,
    ca_id: CaId,
    Path(order_id): Path<String>,
) -> Result<Response, AcmeError> {
    // Server-level capability gate (RFC 8739 §3.1.3): reject if operator has
    // disabled unauthenticated certificate GET globally.
    if !state.config.server.star_allow_certificate_get {
        return Err(AcmeError::Unauthorized(
            "server does not permit unauthenticated STAR certificate GET".into(),
        ));
    }

    // Check order exists and has allow_certificate_get enabled.
    let order = db::orders::get_by_id(&state.db, &order_id)
        .await?
        .ok_or(AcmeError::NotFound)?;

    if order.star_allow_cert_get == 0 {
        return Err(AcmeError::Unauthorized(
            "unauthenticated GET not allowed for this STAR order".into(),
        ));
    }
    if order.ca_id != ca_id.0 {
        return Err(AcmeError::NotFound);
    }
    serve_star_cert(&state, &order).await
}

/// POST-as-GET handler — authenticated (always allowed for the order owner).
pub async fn star_cert_post(
    State(state): State<Arc<AppState>>,
    ca_id: CaId,
    Path(order_id): Path<String>,
    body: Bytes,
) -> Result<Response, AcmeError> {
    let pfx = acme_prefix(&state.config.base_url, &ca_id.0, &state.default_ca_id);
    let url = format!("{pfx}/cert/star/{order_id}");
    let ctx = parse_jws(&state, body, &url).await?;

    // POST-as-GET must have an empty payload.
    if !ctx.payload.is_empty() {
        return Err(AcmeError::BadRequest(
            "STAR certificate download: payload must be empty (POST-as-GET)".into(),
        ));
    }

    let account_id = ctx
        .account_id
        .ok_or_else(|| AcmeError::Unauthorized("kid required".into()))?;

    let order = db::orders::get_by_id(&state.db, &order_id)
        .await?
        .ok_or(AcmeError::NotFound)?;

    if order.account_id != account_id {
        return Err(AcmeError::Unauthorized(
            "order belongs to a different account".into(),
        ));
    }
    if order.ca_id != ca_id.0 {
        return Err(AcmeError::NotFound);
    }

    serve_star_cert(&state, &order).await
}

async fn serve_star_cert(
    state: &AppState,
    order: &crate::db::schema::OrderRow,
) -> Result<Response, AcmeError> {
    // RFC 8739: if canceled, return 403 autoRenewalCanceled.
    if order.star_canceled_at.is_some() {
        return Err(AcmeError::AutoRenewalCanceled);
    }

    // Order must be valid (has been finalized).
    if order.status != "valid" {
        return Err(AcmeError::BadRequest(format!(
            "STAR order is not yet valid (status: {})",
            order.status
        )));
    }

    // Find the most recent certificate for this order.
    let now = unix_now();
    let cert = db::certs::get_latest_for_order(&state.db, &order.id)
        .await?
        .ok_or(AcmeError::NotFound)?;

    // Check if the STAR period is still active.
    if let Some(end_date) = order.star_end_date {
        if now >= end_date {
            return Err(AcmeError::BadRequest(
                "STAR order end-date has passed".into(),
            ));
        }
    }

    // Build response with Cert-Not-Before / Cert-Not-After headers (RFC 8739 §3.3).
    let not_before_str = fmt_http_date(cert.not_before);
    let not_after_str = fmt_http_date(cert.not_after);

    let mut resp = (StatusCode::OK, cert.pem.into_bytes()).into_response();
    resp.headers_mut().insert(
        axum::http::header::CONTENT_TYPE,
        HeaderValue::from_static("application/pem-certificate-chain"),
    );
    if let Ok(v) = HeaderValue::from_str(&not_before_str) {
        resp.headers_mut().insert("cert-not-before", v);
    }
    if let Ok(v) = HeaderValue::from_str(&not_after_str) {
        resp.headers_mut().insert("cert-not-after", v);
    }
    Ok(resp)
}

/// Format a Unix timestamp as an HTTP-date string (RFC 7231 §7.1.1.1).
/// Format: "Day, DD Mon YYYY HH:MM:SS GMT"
fn fmt_http_date(unix: i64) -> String {
    let gt = synta::GeneralizedTime::from_unix(unix)
        .unwrap_or_else(|| synta::GeneralizedTime::from_unix(0).unwrap());
    // Compute day of week using Tomohiko Sakamoto's algorithm.
    let t = [0i32, 3, 2, 5, 0, 3, 5, 1, 4, 6, 2, 4];
    let y = if gt.month < 3 { gt.year - 1 } else { gt.year } as i32;
    let dow = (y + y / 4 - y / 100 + y / 400 + t[(gt.month as usize) - 1] + gt.day as i32) % 7;
    let days = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
    let months = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    format!(
        "{}, {:02} {} {:04} {:02}:{:02}:{:02} GMT",
        days[dow.unsigned_abs() as usize % 7],
        gt.day,
        months[(gt.month as usize) - 1],
        gt.year,
        gt.hour,
        gt.minute,
        gt.second,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fmt_http_date_epoch() {
        // Unix epoch = Thu, 01 Jan 1970 00:00:00 GMT
        let s = fmt_http_date(0);
        assert!(s.contains("1970"), "year not found: {s}");
        assert!(s.contains("Jan"), "month not found: {s}");
        assert!(s.contains("GMT"), "GMT not found: {s}");
    }

    #[test]
    fn fmt_http_date_known() {
        // 2024-01-15 12:00:00 UTC = 1705320000
        let s = fmt_http_date(1_705_320_000);
        assert!(s.contains("2024"), "year: {s}");
        assert!(s.contains("Jan"), "month: {s}");
        assert!(s.contains("15"), "day: {s}");
    }
}
