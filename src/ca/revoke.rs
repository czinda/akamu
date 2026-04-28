//! CRL (Certificate Revocation List) generation.
//!
//! `build_crl` builds a v2 CRL signed by the CA key over all currently
//! revoked certificates.  The CRL is rebuilt on every revocation; for this
//! server's expected issuance volume that is simpler than incremental CRL
//! management.

use synta::{Decoder, Encoding};
use synta_certificate::{
    der_to_pem, oids, Certificate, CertificateListBuilder, CertificateSigner, PrivateKey,
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

    let tbs_der = builder
        .build()
        .map_err(|e| AcmeError::Builder(format!("CRL TBS: {e}")))?;

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
pub(crate) fn extract_ca_subject_der(ca_cert_der: &[u8]) -> Result<Vec<u8>, AcmeError> {
    let mut dec = Decoder::new(ca_cert_der, Encoding::Der);
    let cert: Certificate = dec
        .decode()
        .map_err(|e| AcmeError::Internal(format!("parse CA cert: {e}")))?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ca::init;

    fn make_ca() -> (synta_certificate::BackendPrivateKey, Vec<u8>) {
        let dir = tempfile::TempDir::new().unwrap();
        let config = crate::config::CaConfig {
            key_file: dir.path().join("ca.key").to_str().unwrap().into(),
            cert_file: dir.path().join("ca.crt").to_str().unwrap().into(),
            key_type: "ec:P-256".into(),
            hash_alg: "sha256".into(),
            validity_days: 90,
            crl_url: None,
            ocsp_url: None,
            common_name: "Test CA".into(),
            organization: "Test".into(),
            ca_validity_years: 10,
            crl_next_update_secs: 86400,
        };
        init::load_or_generate(&config).unwrap()
    }

    #[test]
    fn encode_integer_der_small_values() {
        // 0 → 02 01 00
        let enc = encode_integer_der(0);
        assert_eq!(enc, vec![0x02, 0x01, 0x00]);

        // 1 → 02 01 01
        let enc = encode_integer_der(1);
        assert_eq!(enc, vec![0x02, 0x01, 0x01]);

        // 127 → 02 01 7f
        let enc = encode_integer_der(127);
        assert_eq!(enc, vec![0x02, 0x01, 0x7f]);

        // 128 → 02 02 00 80 (needs zero-pad because high bit is set)
        let enc = encode_integer_der(128);
        assert_eq!(enc, vec![0x02, 0x02, 0x00, 0x80]);

        // 255 → 02 02 00 ff
        let enc = encode_integer_der(255);
        assert_eq!(enc, vec![0x02, 0x02, 0x00, 0xff]);

        // 256 → 02 02 01 00
        let enc = encode_integer_der(256);
        assert_eq!(enc, vec![0x02, 0x02, 0x01, 0x00]);
    }

    #[test]
    fn build_crl_empty_revoked() {
        let (ca_key, ca_cert_der) = make_ca();
        let (crl_der, crl_pem) = build_crl(&ca_key, &ca_cert_der, "sha256", &[], 86400).unwrap();
        assert!(!crl_der.is_empty(), "CRL DER should not be empty");
        assert!(
            crl_pem.contains("-----BEGIN X509 CRL-----"),
            "CRL PEM missing header"
        );
        assert!(
            crl_pem.contains("-----END X509 CRL-----"),
            "CRL PEM missing footer"
        );
    }

    #[test]
    fn build_crl_with_revoked_entries() {
        let (ca_key, ca_cert_der) = make_ca();
        let entries = vec![
            RevokedEntry {
                serial_bytes: vec![0x01],
                revoked_at: 1_700_000_000,
                reason: None,
            },
            RevokedEntry {
                serial_bytes: vec![0x00, 0x80], // needs zero-pad in DER
                revoked_at: 1_700_100_000,
                reason: Some(1), // keyCompromise
            },
        ];
        let (crl_der, crl_pem) =
            build_crl(&ca_key, &ca_cert_der, "sha256", &entries, 86400).unwrap();
        assert!(!crl_der.is_empty());
        assert!(crl_pem.contains("-----BEGIN X509 CRL-----"));
    }

    #[test]
    fn extract_ca_subject_der_valid() {
        let (_ca_key, ca_cert_der) = make_ca();
        let subject = extract_ca_subject_der(&ca_cert_der).unwrap();
        assert!(!subject.is_empty(), "subject DER should not be empty");
    }

    #[test]
    fn extract_ca_subject_der_invalid_input() {
        let result = extract_ca_subject_der(b"not a certificate");
        assert!(result.is_err(), "should fail on invalid DER");
    }

    #[test]
    fn build_crl_invalid_ca_cert() {
        let (ca_key, _) = make_ca();
        let result = build_crl(&ca_key, b"bad cert der", "sha256", &[], 86400);
        assert!(result.is_err(), "should fail with invalid CA cert");
    }
}
