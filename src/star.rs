//! RFC 8739 ACME STAR — background certificate reissuance task.
//!
//! Spawned once at startup; wakes every 60 seconds (configurable) and:
//! 1. Queries all active STAR orders (valid, not canceled, end_date in the future).
//! 2. For each order: if the current cert is in the second half of its validity
//!    period, issues a new certificate from the stored CSR DER.  The new cert's
//!    `notBefore` is set to `previous_notAfter - lifetime_adjust_secs` when the
//!    order carries a non-zero `lifetime-adjust` (RFC 8739 §3.1.1), creating a
//!    renewal overlap window; otherwise `notBefore` is the current time.
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
use crate::util::unix_now;

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
        let latest_cert = match db::certs::get_latest_for_order(&state.db, &order.id).await {
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
        let identifiers: Vec<serde_json::Value> = match serde_json::from_str(&order.identifiers) {
            Ok(v) => v,
            Err(e) => {
                tracing::error!(
                    order_id = %order.id, error = %e,
                    "STAR order has malformed identifiers JSON; skipping reissuance"
                );
                continue;
            }
        };
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
        // RFC 8739 §3.1.1: when lifetime-adjust is non-zero, pre-date notBefore
        // relative to the previous certificate's notAfter to create a renewal
        // overlap window (both old and new cert are valid simultaneously).
        // When lifetime-adjust is 0 (the default), use "now" as notBefore.
        let adjust = order.star_lifetime_adjust_secs;
        let not_before_ts = if adjust > 0 {
            cert.not_after - adjust
        } else {
            now
        };
        let not_before = Some(not_before_ts);
        let not_after_raw = not_before_ts + lifetime_secs;
        let not_after = Some(not_after_raw.min(end_date));

        let Some(ca) = state.get_ca(&order.ca_id) else {
            tracing::error!(
                "STAR order {}: unknown ca_id '{}', skipping",
                order.id,
                order.ca_id
            );
            continue;
        };
        let issued = match ca::issue::issue_certificate(ca::issue::IssueCertParams {
            ca_key: &ca.key,
            ca_cert_der: &ca.cert_der,
            hash_alg: &ca.hash_alg,
            validity_days: ca.validity_days,
            crl_url: ca.crl_url.as_deref(),
            ocsp_url: ca.ocsp_url.as_deref(),
            csr: &validated_csr,
            not_before_override: not_before,
            not_after_override: not_after,
        }) {
            Ok(i) => i,
            Err(e) => {
                tracing::error!("STAR order {}: certificate issuance failed: {e}", order.id);
                continue;
            }
        };

        // Persist the new cert and update the order's certificate_id.
        let cert_id = issued.id.clone();
        let serial = issued.serial_hex.clone();
        let new_not_before = issued.not_before;
        let new_not_after = issued.not_after;

        let subject_dn = {
            let mut dec = synta::Decoder::new(&issued.cert_der, synta::Encoding::Der);
            dec.decode::<synta_certificate::Certificate>()
                .ok()
                .map(|cert| synta_certificate::format_dn(cert.tbs_certificate.subject.as_bytes()))
        };

        let persist_result: Result<(), crate::error::AcmeError> = async {
            let mut tx = db::begin_write(&state.db, state.db_kind).await?;
            db::certs::insert(
                &mut *tx,
                CertificateRow {
                    id: cert_id.clone(),
                    order_id: order.id.clone(),
                    account_id: order.account_id.clone(),
                    serial_number: serial.clone(),
                    status: "valid".to_string(),
                    der: issued.cert_der.clone(),
                    pem: issued.cert_pem.clone(),
                    not_before: new_not_before,
                    not_after: new_not_after,
                    revoked_at: None,
                    revocation_reason: None,
                    mtc_log_index: None,
                    created: now,
                    suggested_window_start: None,
                    suggested_window_end: None,
                    replaced_by: None,
                    subject_dn,
                    ca_id: order.ca_id.clone(),
                },
            )
            .await?;
            let updated =
                db::orders::update_star_certificate(&mut *tx, &order.id, &cert_id, now).await?;
            if !updated {
                tracing::info!(
                    "STAR order {}: order was canceled during reissuance, discarding new cert",
                    order.id
                );
                return Ok(());
            }
            tx.commit().await.map_err(crate::error::AcmeError::from)?;
            Ok(())
        }
        .await;

        if let Err(e) = persist_result {
            tracing::error!(
                "STAR order {}: failed to persist reissued certificate: {e}",
                order.id
            );
        } else {
            tracing::info!(
                "STAR order {}: reissued certificate {} (valid until {})",
                order.id,
                serial,
                new_not_after
            );
        }
    }
}
