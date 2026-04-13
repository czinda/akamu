//! POST /acme/order/{id}/finalize — RFC 8555 §7.4

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::Response;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::Deserialize;

use sqlx::Connection as _;

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

    let mut conn = state.db.acquire().await?;

    let order = db::orders::get_by_id(&mut *conn, &id)
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

    // Build identifier → authz_id map so we can look up the validated challenge
    // type for each authorization during the CAA validationmethods check (RFC 8657).
    let authz_rows = db::authz::list_by_order(&mut *conn, &id).await?;
    let mut identifier_to_authz: std::collections::HashMap<(String, String), String> =
        std::collections::HashMap::new();
    for authz in &authz_rows {
        if let Ok(id_obj) = serde_json::from_str::<serde_json::Value>(&authz.identifier) {
            if let (Some(t), Some(v)) = (id_obj["type"].as_str(), id_obj["value"].as_str()) {
                identifier_to_authz.insert((t.to_string(), v.to_string()), authz.id.clone());
            }
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
                let challenge_type = if let Some(authz_id) =
                    identifier_to_authz.get(&(id_type.to_string(), id_value.to_string()))
                {
                    db::challenges::get_validated_type(&mut *conn, authz_id)
                        .await?
                        .unwrap_or_default()
                } else {
                    String::new()
                };
                crate::validation::caa::check_caa(
                    domain,
                    &state.config.server.caa_identities,
                    is_wildcard,
                    &challenge_type,
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
        db::certs::get_by_cert_id(&mut *conn, cid)
            .await?
            .map(|c| c.id)
    } else {
        None
    };

    // Persist the certificate, update the order, and fetch authz IDs atomically.
    let cert_id = issued.id.clone();
    let order_id_clone = id.clone();
    let serial = issued.serial_hex.clone();
    let cert_der = issued.cert_der.clone();
    let cert_pem = issued.cert_pem.clone();
    let not_before = issued.not_before;
    let not_after = issued.not_after;

    // The transaction returns (authz_ids, pred_already_replaced) so we can detect
    // a concurrent alreadyReplaced conflict (RFC 9773 §5) without a separate round-trip.
    let (authz_ids, pred_already_replaced): (Vec<String>, bool) = {
        let mut tx = conn
            .begin()
            .await
            .map_err(|e| AcmeError::Database(e.to_string()))?;

        sqlx::query(
            "INSERT INTO certificates
             (id, order_id, account_id, serial_number, status, der, pem,
              not_before, not_after, revoked_at, revocation_reason,
              mtc_log_index, created, suggested_window_start, suggested_window_end,
              replaced_by)
             VALUES (?1, ?2, ?3, ?4, 'valid', ?5, ?6, ?7, ?8,
                     NULL, NULL, NULL, ?9, NULL, NULL, NULL)",
        )
        .bind(&cert_id)
        .bind(&order_id_clone)
        .bind(&account_id)
        .bind(&serial)
        .bind(&cert_der)
        .bind(&cert_pem)
        .bind(not_before)
        .bind(not_after)
        .bind(now)
        .execute(&mut *tx)
        .await
        .map_err(|e| AcmeError::Database(e.to_string()))?;

        sqlx::query(
            "UPDATE orders SET status = 'valid', certificate_id = ?1, updated = ?2 WHERE id = ?3",
        )
        .bind(&cert_id)
        .bind(now)
        .bind(&order_id_clone)
        .execute(&mut *tx)
        .await
        .map_err(|e| AcmeError::Database(e.to_string()))?;

        // Mark predecessor certificate as replaced (RFC 9773 §5).
        // WHERE replaced_by IS NULL ensures a concurrent replacement produces 0 rows.
        let pred_already_replaced = if let Some(ref pred_uuid) = pred_cert_uuid {
            let result = sqlx::query(
                "UPDATE certificates SET replaced_by = ?1 \
                 WHERE id = ?2 AND replaced_by IS NULL",
            )
            .bind(&order_id_clone)
            .bind(pred_uuid)
            .execute(&mut *tx)
            .await
            .map_err(|e| AcmeError::Database(e.to_string()))?;
            result.rows_affected() == 0
        } else {
            false
        };

        // Fetch authz IDs within the same transaction.
        let ids: Vec<(String,)> =
            sqlx::query_as("SELECT id FROM authorizations WHERE order_id = ?1")
                .bind(&order_id_clone)
                .fetch_all(&mut *tx)
                .await
                .map_err(|e| AcmeError::Database(e.to_string()))?;

        tx.commit()
            .await
            .map_err(|e| AcmeError::Database(e.to_string()))?;

        (ids.into_iter().map(|(id,)| id).collect(), pred_already_replaced)
    };
    // All work using `conn` is done; drop it now so subsequent acquire() calls in
    // this handler (STAR CSR storage) and in spawned tasks (MTC logging) don't deadlock
    // against the in-memory Mutex<SqliteConnection>.
    drop(conn);

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
                        match db.acquire().await {
                            Ok(mut c) => {
                                if let Err(e) = db::certs::set_mtc_log_index(
                                    &mut *c,
                                    &cert_id,
                                    index as i64,
                                )
                                .await
                                {
                                    tracing::warn!(
                                        "cert {cert_id}: MTC log index {index} not saved to DB: {e}"
                                    );
                                }
                            }
                            Err(e) => {
                                tracing::warn!(
                                    "cert {cert_id}: db acquire for MTC index failed: {e}"
                                );
                            }
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
        match state.db.acquire().await {
            Ok(mut c) => {
                if let Err(e) = db::orders::set_star_csr(&mut *c, &id, csr_der.clone()).await {
                    tracing::warn!("STAR order {id}: failed to store CSR DER: {e}");
                }
            }
            Err(e) => {
                tracing::warn!("STAR order {id}: db acquire for CSR DER failed: {e}");
            }
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
