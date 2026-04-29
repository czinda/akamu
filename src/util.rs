//! Shared utility functions used across multiple modules.

use synta::{Decoder, Encoding};
use synta_certificate::Certificate;

use crate::error::AcmeError;

/// Current Unix timestamp in whole seconds.
pub(crate) fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

/// Extract the DER-encoded subject Name from a DER-encoded certificate.
pub(crate) fn extract_ca_subject_der(ca_cert_der: &[u8]) -> Result<Vec<u8>, AcmeError> {
    let mut dec = Decoder::new(ca_cert_der, Encoding::Der);
    let cert: Certificate = dec
        .decode()
        .map_err(|e| AcmeError::Internal(format!("parse CA cert: {e}")))?;
    Ok(cert.tbs_certificate.subject.0.to_vec())
}
