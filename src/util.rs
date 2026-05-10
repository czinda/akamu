//! Shared utility functions used across multiple modules.

use synta::{Decoder, Encoding};
use synta_certificate::Certificate;

use crate::error::AcmeError;

/// Current Unix timestamp in whole seconds.
pub fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

/// RFC 3339 timestamp for a Unix epoch value (seconds precision, UTC, Z suffix).
pub fn unix_to_rfc3339(unix: i64) -> String {
    let gt = synta::GeneralizedTime::from_unix(unix).unwrap_or_else(|| {
        tracing::warn!("unix timestamp {unix} out of GeneralizedTime range; falling back to epoch");
        synta::GeneralizedTime::from_unix(0).unwrap()
    });
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        gt.year, gt.month, gt.day, gt.hour, gt.minute, gt.second
    )
}

/// RFC 3339 timestamp for the current moment (seconds precision, UTC, Z suffix).
pub fn rfc3339_now() -> String {
    unix_to_rfc3339(unix_now())
}

/// Compute the SHA-256 fingerprint of `data` and return it as a lowercase hex string.
pub fn sha256_hex(data: &[u8]) -> Result<String, String> {
    let alg = native_ossl::digest::DigestAlg::fetch(c"SHA2-256", None)
        .map_err(|e| format!("SHA2-256 fetch: {e}"))?;
    let mut ctx = alg
        .new_context()
        .map_err(|e| format!("digest context: {e}"))?;
    ctx.update(data)
        .map_err(|e| format!("digest update: {e}"))?;
    let mut out = [0u8; 32];
    ctx.finish(&mut out)
        .map_err(|e| format!("digest finish: {e}"))?;
    Ok(native_ossl::util::hex_encode(out))
}

/// Write a private key PEM to `path` with mode 0o640 (owner rw, group r, other none).
///
/// Group-readable so that services running as the `akamu` group can access keys
/// generated on first run.  Uses `OpenOptions` with an explicit mode rather than
/// `fs::write` to avoid the process umask widening the permissions.
pub fn write_key_file(path: &str, data: &[u8]) -> std::io::Result<()> {
    use std::io::Write as _;
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o640)
            .open(path)?;
        f.write_all(data)
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, data)
    }
}

/// Extract the DER-encoded subject Name from a DER-encoded certificate.
pub(crate) fn extract_ca_subject_der(ca_cert_der: &[u8]) -> Result<Vec<u8>, AcmeError> {
    let mut dec = Decoder::new(ca_cert_der, Encoding::Der);
    let cert: Certificate = dec
        .decode()
        .map_err(|e| AcmeError::Internal(format!("parse CA cert: {e}")))?;
    Ok(cert.tbs_certificate.subject.0.to_vec())
}
