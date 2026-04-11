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
use crate::error::AcmeError;
use crate::state::AppState;

use super::order::order_json;
use super::{json_response, parse_jws, require_payload, unix_now};

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

    let account_id = ctx
        .account_id
        .ok_or(AcmeError::Unauthorized("kid required".into()))?;

    let order = db::orders::get_by_id(&state.db, &id)
        .await?
        .ok_or(AcmeError::NotFound)?;

    if order.account_id != account_id {
        return Err(AcmeError::Unauthorized(
            "order belongs to different account".into(),
        ));
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

    // draft-aaron-acme-profiles-01: if the order carries a profile that the server
    // no longer advertises, reject at finalize time rather than issuing silently.
    if let Some(ref p) = order.profile {
        if !state.config.server.profiles.is_empty()
            && !state.config.server.profiles.contains_key(p.as_str())
        {
            return Err(AcmeError::InvalidProfile(format!(
                "profile '{p}' is no longer issued by this server"
            )));
        }
    }

    // CAA check (RFC 8659 + RFC 8657): only when caa_identities is configured.
    if !state.config.server.caa_identities.is_empty() {
        for (id_type, id_value) in &allowed {
            if *id_type == "dns" {
                let is_wildcard = id_value.starts_with("*.");
                let domain = if is_wildcard {
                    &id_value[2..]
                } else {
                    id_value
                };
                crate::validation::caa::check_caa(
                    domain,
                    &state.config.server.caa_identities,
                    is_wildcard,
                    "", // challenge_type not tracked per-authz at finalize time
                    state.config.server.dns_resolver_addr.as_deref(),
                )
                .await?;
            }
            // IP identifiers: CAA is not applicable per RFC 8659.
        }
    }

    // Issue certificate, honouring any notBefore/notAfter requested in the order
    // (RFC 8555 §7.1.3).
    let ca = &state.ca;
    let issued = ca::issue::issue_certificate(
        &ca.key,
        &ca.cert_der,
        &ca.hash_alg,
        ca.validity_days,
        ca.crl_url.as_deref(),
        ca.ocsp_url.as_deref(),
        &validated_csr,
        order.not_before,
        order.not_after,
    )?;

    let now = unix_now();

    // If this order carries a `replaces` cert_id, resolve the predecessor UUID
    // before entering the DB transaction (we need an async call for this).
    let pred_cert_uuid: Option<String> = if let Some(ref cid) = order.replaces {
        db::certs::get_by_cert_id(&state.db, cid)
            .await?
            .map(|c| c.id)
    } else {
        None
    };

    // Persist the certificate, update the order, and fetch authz IDs atomically
    // in a single db.call so that (a) a crash between the two writes cannot leave
    // the DB inconsistent, and (b) we avoid two extra channel round-trips that
    // would otherwise be needed to re-read the order and its authorizations.
    let cert_id = issued.id.clone();
    let order_id_clone = id.clone();
    let acct_id = account_id.clone();
    let serial = issued.serial_hex.clone();
    let cert_der = issued.cert_der.clone();
    let cert_pem = issued.cert_pem.clone();
    let not_before = issued.not_before;
    let not_after = issued.not_after;

    let authz_ids: Vec<String> = state
        .db
        .call(move |conn| {
            let tx = conn.transaction()?;
            tx.prepare_cached(
                "INSERT INTO certificates
                 (id, order_id, account_id, serial_number, status, der, pem,
                  not_before, not_after, revoked_at, revocation_reason,
                  mtc_log_index, created, suggested_window_start, suggested_window_end,
                  replaced_by)
                 VALUES (?1, ?2, ?3, ?4, 'valid', ?5, ?6, ?7, ?8,
                         NULL, NULL, NULL, ?9, NULL, NULL, NULL)",
            )?
            .execute(rusqlite::params![
                cert_id,
                order_id_clone,
                acct_id,
                serial,
                cert_der,
                cert_pem,
                not_before,
                not_after,
                now,
            ])?;
            tx.prepare_cached(
                "UPDATE orders SET status = 'valid', certificate_id = ?1, updated = ?2
                 WHERE id = ?3",
            )?
            .execute(rusqlite::params![cert_id, now, order_id_clone])?;
            // Mark predecessor certificate as replaced (RFC 9773 §5).
            if let Some(ref pred_uuid) = pred_cert_uuid {
                tx.prepare_cached(
                    "UPDATE certificates SET replaced_by = ?1 \
                     WHERE id = ?2 AND replaced_by IS NULL",
                )?
                .execute(rusqlite::params![order_id_clone, pred_uuid])?;
            }
            // Fetch authz IDs within the same db.call to avoid a separate round-trip.
            // drop(stmt) before tx.commit() so the borrow of tx is released.
            let mut stmt =
                tx.prepare_cached("SELECT id FROM authorizations WHERE order_id = ?1")?;
            let ids: Vec<String> = stmt
                .query_map(rusqlite::params![order_id_clone], |row| {
                    row.get::<_, String>(0)
                })?
                .collect::<Result<Vec<_>, _>>()?;
            drop(stmt);
            tx.commit()?;
            Ok(ids)
        })
        .await
        .map_err(AcmeError::from)?;

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
                        if let Err(e) =
                            db::certs::set_mtc_log_index(&db, &cert_id, index as i64).await
                        {
                            tracing::warn!(
                                "cert {cert_id}: MTC log index {index} not saved to DB: {e}"
                            );
                        }
                    }
                    Err(e) => {
                        tracing::warn!("MTC log append failed for cert {cert_id}: {e}");
                    }
                }
            });
        }
    }

    // For STAR orders, persist the CSR DER so the background task can reissue.
    if order.star_end_date.is_some() {
        if let Err(e) = db::orders::set_star_csr(&state.db, &id, csr_der.clone()).await {
            tracing::warn!("STAR order {id}: failed to store CSR DER: {e}");
        }
    }

    // Build the response from the known post-finalize state without a DB re-fetch.
    let mut updated_order = order;
    updated_order.status = "valid".to_string();
    updated_order.certificate_id = Some(issued.id.clone());
    updated_order.updated = now;

    let authz_urls: Vec<_> = authz_ids
        .iter()
        .map(|aid| format!("{}/acme/authz/{}", state.config.base_url, aid))
        .collect();

    json_response(
        &state,
        StatusCode::OK,
        order_json(&updated_order, &authz_urls, &state.config.base_url),
        &ctx.next_nonce,
    )
}
