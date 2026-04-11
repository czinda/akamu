//! RFC 8739 ACME STAR — background certificate reissuance task.
//!
//! Spawned once at startup; wakes every 60 seconds (configurable) and:
//! 1. Queries all active STAR orders (valid, not canceled, end_date in the future).
//! 2. For each order: if the current cert is in the second half of its validity
//!    period, issues a new certificate from the stored CSR DER.
//! 3. Inserts the new cert and updates the order's certificate_id.
//!
//! Any errors are logged with `tracing::error!` — the task never panics.

use std::sync::Arc;
use std::time::Duration;

use crate::ca;
use crate::ca::csr::validate_csr;
use crate::db;
use crate::db::schema::CertificateRow;
use crate::state::AppState;

/// Interval between STAR renewal checks.
const POLL_INTERVAL_SECS: u64 = 60;

/// Spawn the background STAR reissuance task and return a handle to it.
pub fn spawn(state: Arc<AppState>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        run_loop(state).await;
    })
}

async fn run_loop(state: Arc<AppState>) {
    loop {
        tokio::time::sleep(Duration::from_secs(POLL_INTERVAL_SECS)).await;
        run_once(&state).await;
    }
}

/// Run one iteration of the STAR reissuance check.
async fn run_once(state: &Arc<AppState>) {
    let orders = match db::orders::list_active_star(&state.db).await {
        Ok(v) => v,
        Err(e) => {
            tracing::error!("STAR reissuance: failed to list active STAR orders: {e}");
            return;
        }
    };

    let now = unix_now();

    for order in orders {
        // Skip if end_date has passed.
        let end_date = match order.star_end_date {
            Some(ts) => ts,
            None => continue,
        };
        if now >= end_date {
            tracing::debug!(
                "STAR order {}: end_date {} has passed, skipping",
                order.id,
                end_date
            );
            continue;
        }

        // We need the stored CSR DER to reissue.
        let csr_der = match &order.star_csr_der {
            Some(der) => der.clone(),
            None => {
                tracing::debug!("STAR order {}: no CSR DER stored yet, skipping", order.id);
                continue;
            }
        };

        let lifetime_secs = match order.star_lifetime_secs {
            Some(s) => s,
            None => {
                tracing::warn!("STAR order {}: missing lifetime_secs, skipping", order.id);
                continue;
            }
        };

        // Find the most recent certificate for this order.
        let order_id = order.id.clone();
        let latest_cert = match state
            .db
            .call(move |conn| {
                let mut stmt = conn.prepare_cached(
                    "SELECT id, order_id, account_id, serial_number, status, der, pem,
                     not_before, not_after, revoked_at, revocation_reason, mtc_log_index, created,
                     suggested_window_start, suggested_window_end, replaced_by
                     FROM certificates
                     WHERE order_id = ?1
                     ORDER BY created DESC
                     LIMIT 1",
                )?;
                let mut rows = stmt.query(rusqlite::params![order_id])?;
                if let Some(row) = rows.next()? {
                    Ok(Some(CertificateRow {
                        id: row.get(0)?,
                        order_id: row.get(1)?,
                        account_id: row.get(2)?,
                        serial_number: row.get(3)?,
                        status: row.get(4)?,
                        der: row.get(5)?,
                        pem: row.get(6)?,
                        not_before: row.get(7)?,
                        not_after: row.get(8)?,
                        revoked_at: row.get(9)?,
                        revocation_reason: row.get(10)?,
                        mtc_log_index: row.get(11)?,
                        created: row.get(12)?,
                        suggested_window_start: row.get(13)?,
                        suggested_window_end: row.get(14)?,
                        replaced_by: row.get(15)?,
                    }))
                } else {
                    Ok(None)
                }
            })
            .await
        {
            Ok(c) => c,
            Err(e) => {
                tracing::error!("STAR order {}: failed to fetch latest cert: {e}", order.id);
                continue;
            }
        };

        let cert = match latest_cert {
            Some(c) => c,
            None => {
                tracing::debug!(
                    "STAR order {}: no certificate yet, waiting for finalize",
                    order.id
                );
                continue;
            }
        };

        // Reissue if we are in the second half of the cert's validity period.
        // Threshold: not_after - lifetime_secs * 0.5
        let reissue_threshold = cert.not_after - lifetime_secs / 2;
        if now < reissue_threshold {
            // Still in first half — no action needed.
            continue;
        }

        tracing::info!(
            "STAR order {}: reissuing certificate (not_after={}, threshold={})",
            order.id,
            cert.not_after,
            reissue_threshold
        );

        // Parse the stored CSR DER to get the identifiers.
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

        let validated_csr = match validate_csr(&csr_der, &allowed) {
            Ok(v) => v,
            Err(e) => {
                tracing::error!("STAR order {}: CSR validation failed: {e}", order.id);
                continue;
            }
        };

        // Calculate the validity window for the new cert.
        // notBefore = now, notAfter = min(now + lifetime_secs, end_date).
        let not_before = Some(now);
        let not_after_raw = now + lifetime_secs;
        let not_after = Some(not_after_raw.min(end_date));

        let ca = &state.ca;
        let issued = match ca::issue::issue_certificate(
            &ca.key,
            &ca.cert_der,
            &ca.hash_alg,
            ca.validity_days,
            ca.crl_url.as_deref(),
            ca.ocsp_url.as_deref(),
            &validated_csr,
            not_before,
            not_after,
        ) {
            Ok(i) => i,
            Err(e) => {
                tracing::error!("STAR order {}: certificate issuance failed: {e}", order.id);
                continue;
            }
        };

        // Persist the new cert and update the order's certificate_id.
        let cert_id = issued.id.clone();
        let order_id2 = order.id.clone();
        let account_id = order.account_id.clone();
        let serial = issued.serial_hex.clone();
        let cert_der_bytes = issued.cert_der.clone();
        let cert_pem = issued.cert_pem.clone();
        let new_not_before = issued.not_before;
        let new_not_after = issued.not_after;

        if let Err(e) = state
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
                    order_id2,
                    account_id,
                    serial,
                    cert_der_bytes,
                    cert_pem,
                    new_not_before,
                    new_not_after,
                    now,
                ])?;
                tx.prepare_cached(
                    "UPDATE orders SET certificate_id = ?1, updated = ?2 WHERE id = ?3",
                )?
                .execute(rusqlite::params![cert_id, now, order_id2])?;
                tx.commit()?;
                Ok(())
            })
            .await
        {
            tracing::error!(
                "STAR order {}: failed to persist reissued certificate: {e}",
                order.id
            );
        } else {
            tracing::info!(
                "STAR order {}: reissued certificate {} (valid until {})",
                order.id,
                issued.serial_hex,
                new_not_after
            );
        }
    }
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}
