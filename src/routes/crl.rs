//! GET /ca/crl — serve the current Certificate Revocation List (RFC 5280).
//!
//! The CRL is signed once and cached for half of `crl_next_update_secs`.
//! Serving a stale-but-valid CRL is RFC-conforming; the cache prevents
//! repeated asymmetric signing on every unauthenticated request.

use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::State;
use axum::http::header::{CACHE_CONTROL, CONTENT_TYPE};
use axum::http::{HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};

use crate::ca::revoke::{build_crl, RevokedEntry};
use crate::db;
use crate::error::AcmeError;
use crate::state::AppState;

/// Serve the DER-encoded CRL.
///
/// Returns `application/pkix-crl` (RFC 5280 §A.1).  No authentication is
/// required — CRLs are public documents per RFC 5280.
///
/// The signed CRL is cached in `AppState::crl_cache` for
/// `crl_next_update_secs / 2` seconds (minimum 30 s) to avoid re-signing on
/// every unauthenticated GET.  A `Cache-Control: max-age` header is emitted
/// so downstream proxies and clients can cache the response independently.
pub async fn get_crl(State(state): State<Arc<AppState>>) -> Result<Response, AcmeError> {
    let validity_secs = state.config.ca.crl_next_update_secs;
    // Cache for half the CRL validity period, at least 30 s.
    let cache_ttl = Duration::from_secs((validity_secs / 2).max(30));

    // ── Fast path: serve from cache if still valid ────────────────────────────
    {
        let guard = state
            .crl_cache
            .lock()
            .map_err(|_| AcmeError::Internal("CRL cache mutex poisoned".into()))?;
        if let Some((ref der, ref expires_at)) = *guard {
            if Instant::now() < *expires_at {
                let remaining = expires_at.duration_since(Instant::now()).as_secs();
                let mut resp = (StatusCode::OK, der.clone()).into_response();
                resp.headers_mut().insert(
                    CONTENT_TYPE,
                    HeaderValue::from_static("application/pkix-crl"),
                );
                resp.headers_mut().insert(
                    CACHE_CONTROL,
                    HeaderValue::from_str(&format!("public, max-age={remaining}")).unwrap(),
                );
                return Ok(resp);
            }
        }
    } // lock released before async DB call

    // ── Slow path: rebuild ────────────────────────────────────────────────────
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
                    let now = crate::util::unix_now();
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
        validity_secs,
    )?;

    // Store in cache.
    {
        let mut guard = state
            .crl_cache
            .lock()
            .map_err(|_| AcmeError::Internal("CRL cache mutex poisoned".into()))?;
        *guard = Some((crl_der.clone(), Instant::now() + cache_ttl));
    }
    crate::audit::record_or_log(
        &state.db,
        &state.audit,
        &state.audit_policy,
        crate::audit::AuditEvent::success(crate::audit::AuditEventType::CrlGenerate),
    )
    .await;

    let max_age = cache_ttl.as_secs();
    let mut resp = (StatusCode::OK, crl_der).into_response();
    resp.headers_mut().insert(
        CONTENT_TYPE,
        HeaderValue::from_static("application/pkix-crl"),
    );
    resp.headers_mut().insert(
        CACHE_CONTROL,
        HeaderValue::from_str(&format!("public, max-age={max_age}")).unwrap(),
    );
    Ok(resp)
}

/// Decode a lowercase hex string to bytes (same encoding used by `serial_number` column).
///
/// Returns an error when `hex` has odd length or contains non-hex characters.
fn decode_hex(hex: &str) -> Result<Vec<u8>, String> {
    if !hex.len().is_multiple_of(2) {
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
