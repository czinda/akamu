//! POST /acme/order/{id}/finalize — RFC 8555 §7.4

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::Response;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::Deserialize;

use crate::ca;
use crate::db;
use crate::db::schema::CertificateRow;
use crate::error::AcmeError;
use crate::state::AppState;

use super::{json_response, parse_jws, require_payload, unix_now};
use super::order::order_json;

#[derive(Deserialize)]
struct FinalizePayload {
    csr: String, // base64url-encoded DER
}

pub async fn finalize_order(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    body: Bytes,
) -> Result<Response, AcmeError> {
    let url = format!("{}/acme/order/{}/finalize", state.config.base_url, id);
    let ctx = parse_jws(&state, body, &url).await?;

    let account_id = ctx.account_id.ok_or(AcmeError::Unauthorized("kid required".into()))?;

    let order = db::orders::get_by_id(&state.db, &id)
        .await?
        .ok_or(AcmeError::NotFound)?;

    if order.account_id != account_id {
        return Err(AcmeError::Unauthorized("order belongs to different account".into()));
    }
    if order.status != "ready" {
        return Err(AcmeError::OrderNotReady);
    }

    let payload: FinalizePayload = require_payload(&ctx.payload, "finalize")?;
    let csr_der = URL_SAFE_NO_PAD
        .decode(&payload.csr)
        .map_err(|e| AcmeError::BadCsr(format!("base64url decode: {e}")))?;

    // Parse order identifiers.
    let identifiers: Vec<serde_json::Value> =
        serde_json::from_str(&order.identifiers).unwrap_or_default();
    let allowed: Vec<(&str, &str)> = identifiers
        .iter()
        .filter_map(|id| {
            let t = id["type"].as_str()?;
            let v = id["value"].as_str()?;
            Some((t, v))
        })
        .collect();

    // Validate CSR.
    let validated_csr = ca::csr::validate_csr(&csr_der, &allowed)?;

    // Issue certificate.
    let ca = &state.ca;
    let issued = ca::issue::issue_certificate(
        &ca.key,
        &ca.cert_der,
        &ca.hash_alg,
        ca.validity_days,
        ca.crl_url.as_deref(),
        ca.ocsp_url.as_deref(),
        &validated_csr,
    )?;

    let now = unix_now();

    // Persist the certificate.
    db::certs::insert(
        &state.db,
        CertificateRow {
            id: issued.id.clone(),
            order_id: id.clone(),
            account_id: account_id.clone(),
            serial_number: issued.serial_hex.clone(),
            status: "valid".into(),
            der: issued.cert_der.clone(),
            pem: issued.cert_pem.clone(),
            not_before: issued.not_before,
            not_after: issued.not_after,
            revoked_at: None,
            revocation_reason: None,
            mtc_log_index: None,
            created: now,
            suggested_window_start: None,
            suggested_window_end: None,
        },
    )
    .await?;

    // Link certificate to order.
    db::orders::set_certificate(&state.db, &id, &issued.id, now).await?;

    // Optionally append to the MTC log.
    if state.mtc.is_enabled() {
        if let Some(log) = &state.mtc.log {
            let cert_der = issued.cert_der.clone();
            let log = Arc::clone(log);
            let db = Arc::clone(&state.db);
            let cert_id = issued.id.clone();
            let algorithm = state.mtc.algorithm;
            tokio::spawn(async move {
                match crate::mtc::log::append_cert_to_log(&log, cert_der, algorithm).await {
                    Ok(index) => {
                        let _ = db::certs::set_mtc_log_index(&db, &cert_id, index as i64).await;
                    }
                    Err(e) => {
                        tracing::warn!("MTC log append failed: {e}");
                    }
                }
            });
        }
    }

    // Return updated order.
    let updated_order = db::orders::get_by_id(&state.db, &id)
        .await?
        .ok_or(AcmeError::NotFound)?;
    let authz_ids = db::orders::list_authz_ids(&state.db, &id).await?;
    let authz_urls: Vec<_> = authz_ids
        .iter()
        .map(|aid| format!("{}/acme/authz/{}", state.config.base_url, aid))
        .collect();

    json_response(
        &state,
        StatusCode::OK,
        order_json(&updated_order, &authz_urls, &state.config.base_url),
    )
    .await
}
