//! CRL (Certificate Revocation List) generation.
//!
//! `build_crl` builds a v2 CRL signed by the CA key over all currently
//! revoked certificates.  The CRL is rebuilt on every revocation; for this
//! server's expected issuance volume that is simpler than incremental CRL
//! management.

use synta::{Decoder, Encoding};
use synta_certificate::{
    Certificate, CertificateListBuilder, CertificateSigner, der_to_pem, oids, PrivateKey,
};

use crate::error::AcmeError;

use super::init::unix_to_generalized_time;

/// One revoked certificate entry, as loaded from the DB.
pub struct RevokedEntry {
    /// Raw bytes of the serial number (big-endian positive two's complement).
    pub serial_bytes: Vec<u8>,
    /// Unix timestamp of revocation.
    pub revoked_at: i64,
    /// RFC 5280 reason code (0–10, except 7).  `None` = unspecified.
    pub reason: Option<u8>,
}

/// Build a DER-encoded CRL covering the supplied revoked entries.
///
/// Returns both the DER and PEM representations so callers can store or
/// serve either form.
pub fn build_crl(
    ca_key: &synta_certificate::BackendPrivateKey,
    ca_cert_der: &[u8],
    hash_alg: &str,
    revoked: &[RevokedEntry],
    next_update_secs: u64,
) -> Result<(Vec<u8>, String), AcmeError> {
    // Extract the CA's subject Name DER for the CRL issuer field.
    let issuer_name_der = extract_ca_subject_der(ca_cert_der)?;

    // Determine thisUpdate and nextUpdate.
    let now = unix_now();
    let this_update_str = unix_to_generalized_time(now);
    let next_update_str = unix_to_generalized_time(now + next_update_secs as i64);

    // Obtain the signature algorithm DER from the signer.
    let signer = ca_key.as_signer(hash_alg);
    let sig_alg_der = signer
        .signature_algorithm_der()
        .map_err(|e| AcmeError::Crypto(format!("CRL sig alg: {e}")))?;

    // Build the TBSCertList.
    let mut builder = CertificateListBuilder::new()
        .issuer(&issuer_name_der)
        .this_update(&this_update_str)
        .next_update(&next_update_str)
        .signature_algorithm(&sig_alg_der);

    for entry in revoked {
        builder = builder.revoke(
            &entry.serial_bytes,
            &unix_to_generalized_time(entry.revoked_at),
            entry.reason,
        );
    }

    // Add CRL Number extension (required for v2 CRL by RFC 5280 §5.2.3).
    // Use the current Unix timestamp as a monotonically increasing CRL number.
    let crl_number_der = encode_integer_der(now as u64);
    builder = builder.add_crl_extension(oids::CRL_NUMBER, false, &crl_number_der);

    let tbs_der = builder.build().map_err(|e| AcmeError::Builder(format!("CRL TBS: {e}")))?;

    // Sign the TBS.
    let signature = signer
        .sign_tbs(&tbs_der)
        .map_err(|e| AcmeError::Crypto(format!("CRL sign: {e}")))?;

    // Assemble the outer CertificateList SEQUENCE.
    let crl_der = CertificateListBuilder::assemble(&tbs_der, &sig_alg_der, &signature)
        .map_err(|e| AcmeError::Builder(format!("CRL assemble: {e}")))?;

    let crl_pem_bytes = der_to_pem("X509 CRL", &crl_der);
    let crl_pem = String::from_utf8(crl_pem_bytes)
        .map_err(|_| AcmeError::Internal("CRL PEM contains invalid UTF-8".into()))?;
    Ok((crl_der, crl_pem))
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Extract the DER-encoded subject Name from a DER-encoded certificate.
fn extract_ca_subject_der(ca_cert_der: &[u8]) -> Result<Vec<u8>, AcmeError> {
    let mut dec = Decoder::new(ca_cert_der, Encoding::Der);
    let cert: Certificate =
        dec.decode().map_err(|e| AcmeError::Internal(format!("parse CA cert: {e}")))?;
    Ok(cert.tbs_certificate.subject.0.to_vec())
}

/// Encode a `u64` value as a DER `INTEGER` (positive, big-endian).
fn encode_integer_der(n: u64) -> Vec<u8> {
    let bytes = n.to_be_bytes();
    // Strip leading zero bytes but keep at least one.
    let start = bytes.iter().position(|&b| b != 0).unwrap_or(7);
    let trimmed = &bytes[start..];
    // Prepend 0x00 if the high bit is set (to keep it positive).
    let needs_pad = trimmed.first().map(|&b| b & 0x80 != 0).unwrap_or(false);

    let value_len = trimmed.len() + usize::from(needs_pad);
    let mut out = vec![0x02u8]; // INTEGER tag
    out.push(value_len as u8); // short-form length (value_len ≤ 127 here)
    if needs_pad {
        out.push(0x00);
    }
    out.extend_from_slice(trimmed);
    out
}

/// Return the current time as Unix seconds.
fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}
