//! GET /ca/crl — serve the current Certificate Revocation List (RFC 5280).
//!
//! The CRL is built on each request from the revoked certificates table.
//! For expected issuance volumes this is fast enough; no caching is needed.

use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

use crate::ca::revoke::{build_crl, RevokedEntry};
use crate::db;
use crate::error::AcmeError;
use crate::state::AppState;

/// Serve the DER-encoded CRL.
///
/// Returns `application/pkix-crl` (RFC 5280 §A.1).  No authentication is
/// required — CRLs are public documents per RFC 5280.
pub async fn get_crl(State(state): State<Arc<AppState>>) -> Result<Response, AcmeError> {
    let rows = db::certs::list_revoked(&state.db).await?;

    let entries: Vec<RevokedEntry> = rows
        .iter()
        .filter_map(|r| {
            let serial_bytes = match decode_hex(&r.serial_number) {
                Ok(b) => b,
                Err(e) => {
                    tracing::warn!(
                        serial = %r.serial_number,
                        "CRL: skipping revoked cert with malformed serial in DB: {e}"
                    );
                    return None;
                }
            };
            let revoked_at = match r.revoked_at {
                Some(ts) => ts,
                None => {
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs() as i64;
                    tracing::warn!(
                        serial = %r.serial_number,
                        "CRL: revoked_at is NULL; using current timestamp"
                    );
                    now
                }
            };
            Some(RevokedEntry {
                serial_bytes,
                revoked_at,
                reason: r.revocation_reason.map(|v| v as u8),
            })
        })
        .collect();

    let (crl_der, _) = build_crl(
        &state.ca.key,
        &state.ca.cert_der,
        &state.ca.hash_alg,
        &entries,
        state.config.ca.crl_next_update_secs,
    )?;

    Ok((
        StatusCode::OK,
        [("Content-Type", "application/pkix-crl")],
        crl_der,
    )
        .into_response())
}

/// Decode a lowercase hex string to bytes (same encoding used by `serial_number` column).
///
/// Returns an error when `hex` has odd length or contains non-hex characters.
fn decode_hex(hex: &str) -> Result<Vec<u8>, String> {
    if hex.len() % 2 != 0 {
        return Err(format!("odd-length hex string ({} chars)", hex.len()));
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&hex[i..i + 2], 16)
                .map_err(|_| format!("invalid hex byte at offset {i}: '{}'", &hex[i..i + 2]))
        })
        .collect()
}
