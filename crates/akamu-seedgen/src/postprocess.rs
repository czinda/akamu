//! Direct DB mutations for non-ACME-achievable lifecycle states.
//!
//! Consumes the `ScenarioOutcome`s from `scenarios.rs` and applies:
//! - Cert revocation
//! - Cert validity backdating (expired) and near-expiry adjustment
//! - ARI replacement chain linkage (certificates.replaced_by, orders.replaces)
//! - Order invalidation (status → invalid, expires → past)
//! - Final VACUUM INTO to persist the in-memory DB to disk

use crate::{
    scenarios::{ScenarioOutcome, TargetState},
    server::SeedServer,
};
use akamu::db;

/// Counts of mutations applied (returned to `summary.rs`).
#[derive(Debug, Default)]
pub struct PostprocessStats {
    pub revoked: usize,
    pub expired: usize,
    pub near_expiry: usize,
    pub ari_chains_linked: usize,
    pub invalid_orders: usize,
}

/// Apply all post-processing state mutations to the database.
pub async fn run(
    server: &SeedServer,
    outcomes: &[ScenarioOutcome],
) -> Result<PostprocessStats, String> {
    let mut stats = PostprocessStats::default();
    let now = unix_now();

    for outcome in outcomes {
        // ── Regular cert state mutations ──────────────────────────────────────

        // Collect ARI chain groups: chain_index → sorted (position, cert).
        let mut ari_groups: std::collections::BTreeMap<
            usize,
            Vec<(usize, &crate::acme::IssuedCert)>,
        > = std::collections::BTreeMap::new();

        for (i, (cert, state)) in outcome.issued.iter().enumerate() {
            match state {
                TargetState::Valid => {
                    // Nothing to do — cert is already in `valid` status in the DB.
                }
                TargetState::Revoked { reason } => {
                    db::certs::revoke(&server.db, &cert.cert_id, Some(*reason as i64), now)
                        .await
                        .map_err(|e| format!("revoke cert {}: {e}", cert.cert_id))?;
                    stats.revoked += 1;
                }
                TargetState::Expired => {
                    // Backdate validity: 1–2 years ago depending on cert index.
                    let offset_secs = (365 + (i % 365) as i64) * 86400;
                    let new_not_before = now - offset_secs - 180 * 86400;
                    let new_not_after = now - offset_secs;
                    db::query("UPDATE certificates SET not_before = ?, not_after = ? WHERE id = ?")
                        .bind(new_not_before)
                        .bind(new_not_after)
                        .bind(&cert.cert_id)
                        .execute(&server.db)
                        .await
                        .map_err(|e| format!("backdate cert {}: {e}", cert.cert_id))?;
                    stats.expired += 1;
                }
                TargetState::NearExpiry => {
                    // Set not_after to 3–30 days from now (staggered by cert index).
                    let days_remaining = 3 + (i % 27) as i64;
                    let new_not_after = now + days_remaining * 86400;
                    db::query("UPDATE certificates SET not_after = ? WHERE id = ?")
                        .bind(new_not_after)
                        .bind(&cert.cert_id)
                        .execute(&server.db)
                        .await
                        .map_err(|e| format!("near-expiry cert {}: {e}", cert.cert_id))?;
                    stats.near_expiry += 1;
                }
                TargetState::AriChain {
                    chain_index,
                    position,
                } => {
                    ari_groups
                        .entry(*chain_index)
                        .or_default()
                        .push((*position, cert));
                }
            }
        }

        // ── ARI replacement chain linkage ─────────────────────────────────────

        for (chain_idx, mut members) in ari_groups {
            members.sort_by_key(|(pos, _)| *pos);
            if members.len() != 3 {
                return Err(format!(
                    "scenario '{}' ARI chain {chain_idx} has {} members (expected 3)",
                    outcome.name,
                    members.len()
                ));
            }
            let (_, cert_a) = members[0];
            let (_, cert_b) = members[1];
            let (_, cert_c) = members[2];

            // cert_A → replaced by order_B
            db::certs::mark_replaced(&server.db, &cert_a.cert_id, &cert_b.order_url)
                .await
                .map_err(|e| format!("ARI mark_replaced A→B: {e}"))?;
            // cert_B → replaced by order_C
            db::certs::mark_replaced(&server.db, &cert_b.cert_id, &cert_c.order_url)
                .await
                .map_err(|e| format!("ARI mark_replaced B→C: {e}"))?;

            // order_B.replaces = cert_A.id
            db::query("UPDATE orders SET replaces = ? WHERE id = ?")
                .bind(&cert_a.cert_id)
                .bind(&cert_b.order_url)
                .execute(&server.db)
                .await
                .map_err(|e| format!("ARI set order_B.replaces: {e}"))?;
            // order_C.replaces = cert_B.id
            db::query("UPDATE orders SET replaces = ? WHERE id = ?")
                .bind(&cert_b.cert_id)
                .bind(&cert_c.order_url)
                .execute(&server.db)
                .await
                .map_err(|e| format!("ARI set order_C.replaces: {e}"))?;

            stats.ari_chains_linked += 1;
        }

        // ── Invalid orders ────────────────────────────────────────────────────

        for order_url in &outcome.invalid_order_urls {
            db::query(
                "UPDATE orders SET status = 'invalid', expires = ?, updated = ? WHERE id = ?",
            )
            .bind(now - 1)
            .bind(now)
            .bind(order_url)
            .execute(&server.db)
            .await
            .map_err(|e| format!("invalidate order {order_url}: {e}"))?;
            stats.invalid_orders += 1;
        }
    }

    // ── Checkpoint the WAL so all writes are in the main database file ─────────

    db::query("PRAGMA wal_checkpoint(TRUNCATE)")
        .execute(&server.db)
        .await
        .map_err(|e| format!("wal_checkpoint: {e}"))?;

    Ok(stats)
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock is set to before the Unix epoch")
        .as_secs() as i64
}
