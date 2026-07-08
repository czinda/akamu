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

use super::CaId;

/// Serve the DER-encoded CRL.
///
/// Returns `application/pkix-crl` (RFC 5280 §A.1).  No authentication is
/// required — CRLs are public documents per RFC 5280.
///
/// The signed CRL is cached in `AppState::crl_cache` for
/// `crl_next_update_secs / 2` seconds (minimum 30 s) to avoid re-signing on
/// every unauthenticated GET.  A `Cache-Control: max-age` header is emitted
/// so downstream proxies and clients can cache the response independently.
pub async fn get_crl(
    State(state): State<Arc<AppState>>,
    ca_id: CaId,
) -> Result<Response, AcmeError> {
    let ca = state
        .get_ca(&ca_id.0)
        .ok_or_else(|| AcmeError::Internal(format!("no CA for id '{}'", ca_id.0)))?;
    if !ca.has_local_key() {
        tracing::debug!(ca_id = %ca_id.0, "CRL not available: CA uses an external signer");
        return Err(AcmeError::NotFound);
    }
    let validity_secs = ca.crl_next_update_secs;
    // Cache for half the CRL validity period, at least 30 s.
    let cache_ttl = Duration::from_secs((validity_secs / 2).max(30));

    let crl_cache = state
        .get_crl_cache(&ca.id)
        .ok_or_else(|| AcmeError::Internal("CRL cache not found for CA".into()))?;

    // ── Fast path: serve from cache if still valid ────────────────────────────
    {
        let guard = crl_cache
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
    let rows = db::certs::list_revoked(&state.db, &ca.id).await?;

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
                reason: r.revocation_reason.and_then(|v| {
                    u8::try_from(v).ok().or_else(|| {
                        tracing::warn!(
                            serial = %r.serial_number,
                            reason = v,
                            "CRL: revocation_reason out of range (0–10); treating as unspecified"
                        );
                        None
                    })
                }),
            })
        })
        .collect();

    let ca_key = ca
        .local_key()
        .ok_or_else(|| AcmeError::Internal("CRL: CA has no local key".into()))?;
    let (crl_der, _) = build_crl(ca_key, &ca.cert_der, &ca.hash_alg, &entries, validity_secs)?;

    // Store in cache.
    {
        let mut guard = crl_cache
            .lock()
            .map_err(|_| AcmeError::Internal("CRL cache mutex poisoned".into()))?;
        *guard = Some((crl_der.clone(), Instant::now() + cache_ttl));
    }
    state
        .record_audit(crate::audit::AuditEvent::success(
            crate::audit::AuditEventType::CrlGenerate,
        ))
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

/// `GET /ca/{ca_id}/cross-certs` (also `/ca/cross-certs` for the default CA)
///
/// Returns the JSON list of cross-certificates for which this CA is the subject
/// (i.e. cross-certs issued by another CA for this CA's public key, enabling
/// alternative trust chains).  No authentication required — cross-certs are
/// public PKI documents.
pub async fn get_cross_certs(State(state): State<Arc<AppState>>, ca_id: CaId) -> Response {
    // Verify the CA exists (CaId extractor already returns 404 for unknown CAs,
    // but the legacy /ca/cross-certs route uses the default CA, so this is a
    // belt-and-suspenders check).
    if state.get_ca(&ca_id.0).is_none() {
        return StatusCode::NOT_FOUND.into_response();
    }

    match db::cross_certs::list_by_subject_ca(&state.db, &ca_id.0).await {
        Ok(rows) => {
            let items: Vec<_> = rows
                .into_iter()
                .map(|r| {
                    serde_json::json!({
                        "id": r.id,
                        "issuer_ca_id": r.issuer_ca_id,
                        "subject_dn": r.subject_dn,
                        "serial_number": r.serial_number,
                        "not_before": r.not_before,
                        "not_after": r.not_after,
                        "cross_cert_pem": r.cross_cert_pem,
                        "created": r.created,
                    })
                })
                .collect();
            (
                StatusCode::OK,
                axum::Json(serde_json::json!({ "cross_certs": items })),
            )
                .into_response()
        }
        Err(e) => {
            tracing::error!(error = %e, "get_cross_certs DB query failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
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
