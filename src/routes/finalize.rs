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
    // The authz lookup is deferred inside this block so that deployments without
    // CAA pay zero extra DB round-trips during finalization.  The account URL is
    // constructed here and passed to check_caa for RFC 8657 §4 accounturi enforcement.
    if !state.config.server.caa_identities.is_empty() {
        // Build identifier → authz_id map to look up the validated challenge type
        // for each authorization (RFC 8657 validationmethods check).
        let authz_rows = db::authz::list_by_order(&state.db, &id).await?;
        let mut identifier_to_authz: std::collections::HashMap<(String, String), String> =
            std::collections::HashMap::new();
        for authz in &authz_rows {
            if let Ok(id_obj) = serde_json::from_str::<serde_json::Value>(&authz.identifier) {
                if let (Some(t), Some(v)) = (id_obj["type"].as_str(), id_obj["value"].as_str()) {
                    identifier_to_authz.insert((t.to_string(), v.to_string()), authz.id.clone());
                }
            }
        }

        for (id_type, id_value) in &allowed {
            if *id_type == "dns" {
                let is_wildcard = id_value.starts_with("*.");
                let domain = if is_wildcard {
                    &id_value[2..]
                } else {
                    id_value
                };
                let challenge_type = if let Some(authz_id) =
                    identifier_to_authz.get(&(id_type.to_string(), id_value.to_string()))
                {
                    db::challenges::get_validated_type(&state.db, authz_id)
                        .await?
                        .unwrap_or_default()
                } else {
                    String::new()
                };
                let account_url = format!("{}/acme/account/{}", state.config.base_url, account_id);
                crate::validation::caa::check_caa(
                    domain,
                    &state.config.server.caa_identities,
                    is_wildcard,
                    &challenge_type,
                    Some(account_url.as_str()),
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
    // in a single transaction so that a crash between writes cannot leave the DB
    // inconsistent.
    let cert_id = issued.id.clone();

    // The transaction returns (authz_ids, pred_already_replaced) so we can signal
    // a concurrent alreadyReplaced conflict (RFC 9773 §5) without a separate
    // DB round-trip.  The bool is true when the predecessor's replaced_by was
    // already set by another concurrent finalization.
    let (authz_ids, pred_already_replaced) = {
        let mut tx = db::begin_write(&state.db, state.db_kind).await?;

        db::certs::insert(
            &mut *tx,
            CertificateRow {
                id: issued.id.clone(),
                order_id: id.clone(),
                account_id: account_id.clone(),
                serial_number: issued.serial_hex.clone(),
                status: "valid".to_string(),
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
                replaced_by: None,
            },
        )
        .await?;

        db::orders::set_certificate(&mut *tx, &id, &cert_id, now).await?;

        // Mark predecessor certificate as replaced (RFC 9773 §5).
        let pred_already_replaced = if let Some(ref pred_uuid) = pred_cert_uuid {
            !db::certs::mark_replaced(&mut *tx, pred_uuid, &id).await?
        } else {
            false
        };

        // Fetch authz IDs within the same transaction to avoid a separate round-trip.
        let authz_ids = db::orders::list_authz_ids(&mut *tx, &id).await?;

        tx.commit().await.map_err(AcmeError::from)?;
        (authz_ids, pred_already_replaced)
    };

    // RFC 9773 §5: return 409 alreadyReplaced if another order concurrently
    // replaced the same predecessor certificate during this finalization.
    if pred_already_replaced {
        return Err(AcmeError::CertAlreadyReplaced);
    }

    // Optionally append to the MTC log.
    if state.mtc.is_enabled() {
        if let Some(log) = &state.mtc.log {
            let cert_der = issued.cert_der.clone();
            let log = Arc::clone(log);
            let db = state.db.clone();
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
