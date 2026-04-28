//! GET /ca/ocsp/{request} and POST /ca/ocsp — RFC 6960 OCSP responder.
//!
//! Both handlers decode an OCSPRequest, look up the status of each requested
//! certificate in the DB, and return a signed OCSPResponse.
//!
//! The GET form accepts a base64url-encoded DER OCSPRequest in the URL path
//! (RFC 6960 §A.1).  The POST form accepts the DER body directly.
//!
//! No authentication is required — OCSP is a public protocol (RFC 6960).

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;

use synta_certificate::{CertificateSigner, OCSPResponseBuilder, PrivateKey, SingleResponseSpec};

use crate::ca::init::unix_to_generalized_time;
use crate::ca::revoke::extract_ca_subject_der;
use crate::db;
use crate::error::AcmeError;
use crate::routes::unix_now;
use crate::state::AppState;

/// GET /ca/ocsp/{request}
///
/// `{request}` is a base64url-encoded DER OCSPRequest (RFC 6960 §A.1).
pub async fn get_ocsp(
    State(state): State<Arc<AppState>>,
    Path(request): Path<String>,
) -> Result<Response, AcmeError> {
    let der = URL_SAFE_NO_PAD
        .decode(request.as_bytes())
        .map_err(|_| AcmeError::BadRequest("OCSP GET: invalid base64url in path".into()))?;
    let ocsp_der = handle_ocsp_request(&der, &state).await?;
    Ok(ocsp_response(ocsp_der))
}

/// POST /ca/ocsp
///
/// Body is a DER-encoded OCSPRequest; `Content-Type: application/ocsp-request`.
pub async fn post_ocsp(
    State(state): State<Arc<AppState>>,
    body: Bytes,
) -> Result<Response, AcmeError> {
    let ocsp_der = handle_ocsp_request(&body, &state).await?;
    Ok(ocsp_response(ocsp_der))
}

// ── Shared logic ──────────────────────────────────────────────────────────────

/// One parsed cert-ID entry, extracted into owned data before any await.
struct CertEntry {
    hash_alg_der: Vec<u8>,
    serial_hex: String,
    serial_bytes: Vec<u8>,
    issuer_name_hash: Vec<u8>,
    issuer_key_hash: Vec<u8>,
}

async fn handle_ocsp_request(der: &[u8], state: &AppState) -> Result<Vec<u8>, AcmeError> {
    use synta_certificate::ocsp_2024_88_types::OCSPRequest;

    // ── Step 1: parse request and extract all data into owned types ───────────
    // All borrowed data from the DER buffer is converted to Vec<u8> / String
    // here, so no non-Send reference crosses the first await point.
    let entries: Vec<CertEntry> = {
        let req = OCSPRequest::from_der(der)
            .map_err(|e| AcmeError::BadRequest(format!("invalid OCSPRequest: {e}")))?;

        req.tbs_request
            .request_list
            .iter()
            .map(|single_req| {
                let cert_id = &single_req.req_cert;
                let hash_alg_der = cert_id
                    .hash_algorithm
                    .to_der()
                    .map_err(|e| AcmeError::Internal(format!("OCSP hash alg encode: {e}")))?;
                let serial_bytes = cert_id.serial_number.as_bytes().to_vec();
                let serial_hex: String =
                    serial_bytes.iter().map(|b| format!("{b:02x}")).collect();
                let issuer_name_hash = cert_id.issuer_name_hash.as_bytes().to_vec();
                let issuer_key_hash = cert_id.issuer_key_hash.as_bytes().to_vec();
                Ok::<_, AcmeError>(CertEntry {
                    hash_alg_der,
                    serial_hex,
                    serial_bytes,
                    issuer_name_hash,
                    issuer_key_hash,
                })
            })
            .collect::<Result<Vec<_>, _>>()?
        // `req` dropped here — no borrowed data escapes this block
    };

    let now = unix_now();
    let this_update = unix_to_generalized_time(now);
    let next_update = unix_to_generalized_time(now + 86400);
    let subject_der = extract_ca_subject_der(&state.ca.cert_der)?;

    // ── Step 2: DB lookups (async, no signer held) ────────────────────────────
    let mut statuses: Vec<u8> = Vec::with_capacity(entries.len());
    for entry in &entries {
        let row = db::certs::get_by_serial(&state.db, &entry.serial_hex).await?;
        let status: u8 = match &row {
            None => 2,                             // unknown
            Some(r) if r.status == "revoked" => 1, // revoked
            _ => 0,                                // good
        };
        statuses.push(status);
    }

    // ── Step 3: build and sign the response (synchronous, signer not held across await) ──
    let mut builder = OCSPResponseBuilder::new()
        .responder_name(&subject_der)
        .produced_at(&this_update);

    for (entry, &status) in entries.iter().zip(statuses.iter()) {
        builder = builder.add_response(SingleResponseSpec {
            hash_algorithm_der: &entry.hash_alg_der,
            issuer_name_hash: &entry.issuer_name_hash,
            issuer_key_hash: &entry.issuer_key_hash,
            serial: &entry.serial_bytes,
            status,
            this_update: &this_update,
            next_update: Some(&next_update),
        });
    }

    let tbs_der = builder
        .build_tbs()
        .map_err(|e| AcmeError::Builder(format!("OCSP TBS: {e}")))?;

    let signer = state.ca.key.as_signer(&state.ca.hash_alg);
    let sig_alg_der = signer
        .signature_algorithm_der()
        .map_err(|e| AcmeError::Crypto(format!("OCSP sig alg: {e}")))?;
    let signature = signer
        .sign_tbs(&tbs_der)
        .map_err(|e| AcmeError::Crypto(format!("OCSP sign: {e}")))?;

    OCSPResponseBuilder::assemble(&tbs_der, &sig_alg_der, &signature)
        .map_err(|e| AcmeError::Builder(format!("OCSP assemble: {e}")))
}

fn ocsp_response(der: Vec<u8>) -> Response {
    (
        StatusCode::OK,
        [("Content-Type", "application/ocsp-response")],
        der,
    )
        .into_response()
}
