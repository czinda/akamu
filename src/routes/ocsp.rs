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
use axum::http::header::CONTENT_TYPE;
use axum::http::{HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;

use synta_certificate::ocsp::{OCSPResponse, OCSPResponseStatus};
use synta_certificate::{
    default_key_id_hasher, CertificateSigner, KeyIdHasher, OCSPResponseBuilder, PrivateKey,
    SingleResponseSpec,
};

use crate::ca::init::unix_to_generalized_time;
use crate::db;
use crate::error::AcmeError;
use crate::routes::{unix_now, CaId};
use crate::state::{AppState, CaState};
use crate::util::extract_ca_subject_der;

/// GET /ca/ocsp/{request}
///
/// `{request}` is a base64url-encoded DER OCSPRequest (RFC 6960 §A.1).
pub async fn get_ocsp(
    State(state): State<Arc<AppState>>,
    ca_id: CaId,
    Path(request): Path<String>,
) -> Result<Response, AcmeError> {
    let ca = state
        .get_ca(&ca_id.0)
        .ok_or_else(|| AcmeError::Internal(format!("no CA for id '{}'", ca_id.0)))?;
    let der = URL_SAFE_NO_PAD
        .decode(request.as_bytes())
        .map_err(|_| AcmeError::BadRequest("OCSP GET: invalid base64url in path".into()))?;
    let ocsp_der = handle_ocsp_request(&der, &state, ca).await?;
    Ok(ocsp_response(ocsp_der))
}

/// Maximum DER body size accepted for an OCSP POST request.
///
/// An OCSPRequest for a single certificate is < 200 bytes; 64 KiB is
/// generous enough to cover any realistic request while blocking amplification
/// attacks from unauthenticated callers.
const MAX_OCSP_POST_BYTES: usize = 65_536;

/// Maximum number of `Request` entries processed in one OCSPRequest.
///
/// RFC 6960 does not impose a limit, but serving thousands of DB lookups per
/// unauthenticated request can saturate the connection pool.
const MAX_OCSP_ENTRIES: usize = 10;

/// RFC 6960 §2.2 certificate status values.
const OCSP_GOOD: u8 = 0;
const OCSP_REVOKED: u8 = 1;
const OCSP_UNKNOWN: u8 = 2;

/// POST /ca/ocsp
///
/// Body is a DER-encoded OCSPRequest; `Content-Type: application/ocsp-request`.
pub async fn post_ocsp(
    State(state): State<Arc<AppState>>,
    ca_id: CaId,
    body: Bytes,
) -> Result<Response, AcmeError> {
    let ca = state
        .get_ca(&ca_id.0)
        .ok_or_else(|| AcmeError::Internal(format!("no CA for id '{}'", ca_id.0)))?;
    if body.len() > MAX_OCSP_POST_BYTES {
        return Err(AcmeError::BadRequest(format!(
            "OCSP POST body too large ({} bytes; max {MAX_OCSP_POST_BYTES})",
            body.len()
        )));
    }
    let ocsp_der = handle_ocsp_request(&body, &state, ca).await?;
    Ok(ocsp_response(ocsp_der))
}

// ── Shared logic ──────────────────────────────────────────────────────────────

/// One parsed cert-ID entry, extracted into owned data before any await.
struct CertEntry {
    hash_alg_der: Vec<u8>,
    /// OID component array from the CertID hash algorithm — used to compute
    /// the CA's own issuer hashes for validation.
    hash_alg_oid: Vec<u32>,
    serial_hex: String,
    serial_bytes: Vec<u8>,
    issuer_name_hash: Vec<u8>,
    issuer_key_hash: Vec<u8>,
}

async fn handle_ocsp_request(der: &[u8], state: &AppState, ca: &CaState) -> Result<Vec<u8>, AcmeError> {
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
                let hash_alg_oid = cert_id.hash_algorithm.algorithm.components().to_vec();
                let serial_bytes = cert_id.serial_number.as_bytes().to_vec();
                let serial_hex: String = serial_bytes.iter().map(|b| format!("{b:02x}")).collect();
                let issuer_name_hash = cert_id.issuer_name_hash.as_bytes().to_vec();
                let issuer_key_hash = cert_id.issuer_key_hash.as_bytes().to_vec();
                Ok::<_, AcmeError>(CertEntry {
                    hash_alg_der,
                    hash_alg_oid,
                    serial_hex,
                    serial_bytes,
                    issuer_name_hash,
                    issuer_key_hash,
                })
            })
            .collect::<Result<Vec<_>, _>>()?
        // `req` dropped here — no borrowed data escapes this block
    };

    if entries.len() > MAX_OCSP_ENTRIES {
        return Err(AcmeError::BadRequest(format!(
            "OCSPRequest contains {} entries; max allowed is {MAX_OCSP_ENTRIES}",
            entries.len()
        )));
    }

    let now = unix_now();
    let this_update = unix_to_generalized_time(now);
    let next_update = unix_to_generalized_time(now + 86400);
    let subject_der = extract_ca_subject_der(&ca.cert_der)?;

    // ── Step 1b: validate issuer hashes against this CA ──────────────────────
    // RFC 6960 §4.1.1: the client computes issuerNameHash and issuerKeyHash
    // using the CA's subject Name DER and subjectPublicKey BIT STRING value.
    // A client supplying arbitrary hashes could construct an OCSP signing oracle
    // (we'd sign a response that appears to be for a different CA).  Reject any
    // request whose hashes don't match our CA's actual values for that algorithm.
    for entry in &entries {
        let (expected_name_hash, expected_key_hash) =
            compute_issuer_hashes(&ca.cert_der, &entry.hash_alg_oid)?;

        if entry.issuer_name_hash != expected_name_hash
            || entry.issuer_key_hash != expected_key_hash
        {
            tracing::warn!(
                "OCSP: request with issuer hashes that do not match this CA; returning unauthorized"
            );
            let der = build_error_response_der(OCSPResponseStatus::Unauthorized)?;
            return Ok(der);
        }
    }

    // ── Step 2: DB lookups (async, no signer held) ────────────────────────────
    let mut statuses: Vec<u8> = Vec::with_capacity(entries.len());
    for entry in &entries {
        let row = db::certs::get_by_serial(&state.db, &entry.serial_hex).await?;
        let status: u8 = match &row {
            None => OCSP_UNKNOWN,
            Some(r) if r.status == "revoked" => OCSP_REVOKED,
            _ => OCSP_GOOD,
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

    let signer = ca.key.as_signer(&ca.hash_alg);
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
    let mut resp = (StatusCode::OK, der).into_response();
    resp.headers_mut().insert(
        CONTENT_TYPE,
        HeaderValue::from_static("application/ocsp-response"),
    );
    resp
}

/// Build a minimal DER-encoded `OCSPResponse` with the given error status
/// (e.g. `OCSPResponseStatus::Unauthorized`).  No `responseBytes` are present.
fn build_error_response_der(status: OCSPResponseStatus) -> Result<Vec<u8>, AcmeError> {
    let resp = OCSPResponse {
        response_status: status,
        response_bytes: None,
    };
    resp.to_der()
        .map_err(|e| AcmeError::Builder(format!("OCSP error response encode: {e}")))
}

/// Compute the RFC 6960 §4.1.1 `issuerNameHash` and `issuerKeyHash` for the
/// CA certificate using the hash algorithm OID `hash_oid`.
///
/// - `issuerNameHash` = hash of the DER-encoded subject Name.
/// - `issuerKeyHash`  = hash of the BIT STRING *value* of subjectPublicKey
///   (first byte is the unused-bits count, typically 0x00, followed by the
///   raw public key bytes).
fn compute_issuer_hashes(
    ca_cert_der: &[u8],
    hash_oid: &[u32],
) -> Result<(Vec<u8>, Vec<u8>), AcmeError> {
    use synta_certificate::Certificate;

    let cert = Certificate::from_der(ca_cert_der)
        .map_err(|e| AcmeError::Internal(format!("OCSP: re-decode CA cert: {e}")))?;

    let subject_der = cert.tbs_certificate.subject.0;

    // The issuerKeyHash input is the BIT STRING *value*: unused-bits byte (0x00)
    // followed by the actual key bytes.  `as_bytes()` omits the unused-bits byte,
    // so prepend it explicitly.
    let key_bytes = cert
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .as_bytes();
    let mut key_hash_input = Vec::with_capacity(key_bytes.len() + 1);
    key_hash_input.push(0u8); // unused bits = 0
    key_hash_input.extend_from_slice(key_bytes);

    let hasher = default_key_id_hasher();
    let name_hash = hasher
        .hash(hash_oid, subject_der)
        .map_err(|e| AcmeError::Crypto(format!("OCSP: issuerNameHash: {e}")))?;
    let key_hash = hasher
        .hash(hash_oid, &key_hash_input)
        .map_err(|e| AcmeError::Crypto(format!("OCSP: issuerKeyHash: {e}")))?;

    Ok((name_hash, key_hash))
}
