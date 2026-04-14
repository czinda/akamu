//! CA key and certificate initialisation.
//!
//! On first run: generate a new CA key + self-signed certificate and write
//! them to the configured PEM files. On subsequent runs: load the existing
//! PEM files.

use std::path::Path;

use synta_certificate::{
    default_key_id_hasher, der_to_pem, encode_authority_key_identifier, encode_basic_constraints,
    encode_key_usage, encode_subject_key_identifier, oids, parse_time, BackendPrivateKey,
    CertificateBuilder, KeyIdMethod, NameBuilder, PrivateKey, KEY_USAGE_C_RLSIGN,
    KEY_USAGE_KEY_CERT_SIGN,
};

use crate::config::CaConfig;
use crate::error::AcmeError;

/// Load or auto-generate the CA key pair and certificate.
///
/// Returns `(key, cert_der)` where `cert_der` is the DER-encoded CA certificate.
pub fn load_or_generate(config: &CaConfig) -> Result<(BackendPrivateKey, Vec<u8>), AcmeError> {
    let key_exists = Path::new(&config.key_file).exists();
    let cert_exists = Path::new(&config.cert_file).exists();

    if key_exists && cert_exists {
        load(config)
    } else if !key_exists && !cert_exists {
        generate(config)
    } else {
        Err(AcmeError::Internal(
            "CA key and certificate files must both exist or both be absent".into(),
        ))
    }
}

fn load(config: &CaConfig) -> Result<(BackendPrivateKey, Vec<u8>), AcmeError> {
    let key_pem = std::fs::read(&config.key_file)
        .map_err(|e| AcmeError::Internal(format!("read CA key '{}': {}", config.key_file, e)))?;
    let cert_pem = std::fs::read(&config.cert_file)
        .map_err(|e| AcmeError::Internal(format!("read CA cert '{}': {}", config.cert_file, e)))?;

    let key = BackendPrivateKey::from_pem(&key_pem, None)
        .map_err(|e| AcmeError::Crypto(format!("parse CA key: {}", e)))?;

    let cert_ders = synta_certificate::pem_to_der(&cert_pem);
    let cert_der = cert_ders
        .into_iter()
        .next()
        .ok_or_else(|| AcmeError::Internal("CA certificate PEM has no blocks".into()))?;

    tracing::info!("Loaded CA key from {}", config.key_file);
    Ok((key, cert_der))
}

fn generate(config: &CaConfig) -> Result<(BackendPrivateKey, Vec<u8>), AcmeError> {
    tracing::info!(
        "Generating new CA key ({}) — writing to {} and {}",
        config.key_type,
        config.key_file,
        config.cert_file
    );

    // Parse key spec: "ec:P-256", "rsa:2048", "ed25519"
    // Generate BackendPrivateKey (used for both signing and PEM export).
    let backend_key = generate_backend_key(&config.key_type)?;

    // Write key PEM immediately so we have it on disk before building the cert.
    let key_pem_out = backend_key
        .to_pem(None)
        .map_err(|e| AcmeError::Crypto(format!("CA key to PEM: {}", e)))?;
    std::fs::write(&config.key_file, &key_pem_out)
        .map_err(|e| AcmeError::Internal(format!("write CA key '{}': {}", config.key_file, e)))?;

    let spki_der = backend_key
        .public_key()
        .map_err(|e| AcmeError::Crypto(format!("backend key public: {}", e)))?
        .spki_der()
        .to_vec();

    // Build CA distinguished name.
    let name_der = NameBuilder::new()
        .common_name(&config.common_name)
        .organization(&config.organization)
        .build()
        .map_err(|e| AcmeError::Builder(format!("CA name: {}", e)))?;

    // Validity dates.
    let years = config.ca_validity_years as i64;
    let now_str = format_now();
    let exp_str = format_future_years(years);
    let not_before =
        parse_time(&now_str).map_err(|e| AcmeError::Builder(format!("CA notBefore: {}", e)))?;
    let not_after =
        parse_time(&exp_str).map_err(|e| AcmeError::Builder(format!("CA notAfter: {}", e)))?;

    // Extensions.
    let hasher = default_key_id_hasher();
    let bc_der = encode_basic_constraints(true, None)
        .ok_or_else(|| AcmeError::Builder("encode BasicConstraints".into()))?;
    // keyUsage: keyCertSign + cRLSign
    let ku_der = encode_key_usage((1u16 << KEY_USAGE_KEY_CERT_SIGN) | (1u16 << KEY_USAGE_C_RLSIGN))
        .ok_or_else(|| AcmeError::Builder("encode KeyUsage".into()))?;
    let ski_der =
        encode_subject_key_identifier(&spki_der, KeyIdMethod::Rfc7093Method1Sha256, &hasher)
            .ok_or_else(|| AcmeError::Builder("encode SKI".into()))?;
    let aki_der =
        encode_authority_key_identifier(&spki_der, KeyIdMethod::Rfc7093Method1Sha256, &hasher)
            .ok_or_else(|| AcmeError::Builder("encode AKI".into()))?;

    let signer = backend_key.as_signer(&config.hash_alg);
    let cert_der = CertificateBuilder::new()
        .issuer_name(&name_der)
        .subject_name(&name_der)
        .public_key_der(&spki_der)
        .serial_number(synta::Integer::from_i64(1))
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension_oid(oids::BASIC_CONSTRAINTS, true, &bc_der)
        .add_extension_oid(oids::KEY_USAGE, true, &ku_der)
        .add_extension_oid(oids::SUBJECT_KEY_IDENTIFIER, false, &ski_der)
        .add_extension_oid(oids::AUTHORITY_KEY_IDENTIFIER, false, &aki_der)
        .sign(&signer)
        .map_err(|e| AcmeError::Builder(format!("sign CA cert: {}", e)))?;

    // Write certificate PEM
    let cert_pem = der_to_pem("CERTIFICATE", &cert_der);
    std::fs::write(&config.cert_file, &cert_pem)
        .map_err(|e| AcmeError::Internal(format!("write CA cert '{}': {}", config.cert_file, e)))?;

    tracing::info!(
        "Generated CA certificate ({}, {} years)",
        config.key_type,
        config.ca_validity_years
    );

    Ok((backend_key, cert_der))
}

/// Compute the AKI key-identifier bytes for the given SubjectPublicKeyInfo DER.
///
/// Uses RFC 7093 §2 Method 1: the leftmost 20 bytes of the SHA-256 hash of
/// the BIT STRING value of the public key.  This matches the
/// `KeyIdMethod::Rfc7093Method1Sha256` method used when encoding the CA
/// certificate's SKI / AKI extensions, so the result equals the
/// `keyIdentifier` stored in every issued certificate's AKI extension.
///
/// The value is used by the ARI (RFC 9773) handler to validate the first
/// component of the `cert_id` path parameter.
pub fn compute_aki_from_spki(spki_der: &[u8]) -> Option<Vec<u8>> {
    let hasher = default_key_id_hasher();
    // encode_subject_key_identifier returns the DER-encoded extension value,
    // which is a KeyIdentifier ::= OCTET STRING { hash }.
    // Wire format: 0x04 | length_bytes | hash_bytes
    let ski_val =
        encode_subject_key_identifier(spki_der, KeyIdMethod::Rfc7093Method1Sha256, &hasher)?;
    if ski_val.len() < 2 || ski_val[0] != 0x04 {
        return None;
    }
    // Parse DER length (20-byte output is always short-form; long-form handled generically).
    let (hash_start, hash_len) = if ski_val[1] & 0x80 == 0 {
        (2usize, ski_val[1] as usize)
    } else {
        let num_len = (ski_val[1] & 0x7f) as usize;
        if ski_val.len() < 2 + num_len {
            return None;
        }
        let mut len = 0usize;
        for &b in &ski_val[2..2 + num_len] {
            len = (len << 8) | b as usize;
        }
        (2 + num_len, len)
    };
    if ski_val.len() < hash_start + hash_len {
        return None;
    }
    Some(ski_val[hash_start..hash_start + hash_len].to_vec())
}

/// Generate a `BackendPrivateKey` using the synta-certificate crypto backend.
pub(crate) fn generate_backend_key(key_type: &str) -> Result<BackendPrivateKey, AcmeError> {
    let cry = |e: &dyn std::fmt::Display| AcmeError::Crypto(format!("generate {key_type}: {e}"));
    match key_type {
        "ec:P-256" | "P-256" => BackendPrivateKey::generate_ec("P-256").map_err(|e| cry(&e)),
        "ec:P-384" | "P-384" => BackendPrivateKey::generate_ec("P-384").map_err(|e| cry(&e)),
        "ec:P-521" | "P-521" => BackendPrivateKey::generate_ec("P-521").map_err(|e| cry(&e)),
        "rsa:2048" | "rsa2048" => BackendPrivateKey::generate_rsa(2048, 65537).map_err(|e| cry(&e)),
        "rsa:3072" | "rsa3072" => BackendPrivateKey::generate_rsa(3072, 65537).map_err(|e| cry(&e)),
        "rsa:4096" | "rsa4096" => BackendPrivateKey::generate_rsa(4096, 65537).map_err(|e| cry(&e)),
        "ed25519" => BackendPrivateKey::generate_ed25519().map_err(|e| cry(&e)),
        "ed448" => BackendPrivateKey::generate_ed448().map_err(|e| cry(&e)),
        // Post-quantum signature keys (FIPS 204, requires OpenSSL 3.5+).
        "ml-dsa-44" | "ML-DSA-44" => {
            BackendPrivateKey::generate_ml_dsa("ML-DSA-44").map_err(|e| cry(&e))
        }
        "ml-dsa-65" | "ML-DSA-65" => {
            BackendPrivateKey::generate_ml_dsa("ML-DSA-65").map_err(|e| cry(&e))
        }
        "ml-dsa-87" | "ML-DSA-87" => {
            BackendPrivateKey::generate_ml_dsa("ML-DSA-87").map_err(|e| cry(&e))
        }
        other => Err(AcmeError::Internal(format!(
            "unknown key type '{other}'; use 'ec:P-256', 'rsa:2048', 'ed25519', 'ml-dsa-44', etc."
        ))),
    }
}

/// Format the current time as a GeneralizedTime string `YYYYMMDDHHmmssZ`.
fn format_now() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    unix_to_generalized_time(secs as i64)
}

/// Format a time `years` years in the future.
fn format_future_years(years: i64) -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    // Approximate: 365.25 days/year × 86400 s/day
    unix_to_generalized_time(secs + years * 31_557_600)
}

pub(crate) fn unix_to_generalized_time(secs: i64) -> String {
    // Use synta's built-in Gregorian conversion (Hinnant algorithm, no extra deps).
    let gt = synta::GeneralizedTime::from_unix(secs)
        .unwrap_or_else(|| synta::GeneralizedTime::from_unix(0).unwrap());
    format!(
        "{:04}{:02}{:02}{:02}{:02}{:02}Z",
        gt.year, gt.month, gt.day, gt.hour, gt.minute, gt.second
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    use crate::config::CaConfig;

    fn make_config_with_paths(dir: &std::path::Path, key_type: &str) -> CaConfig {
        CaConfig {
            key_file: dir.join("ca.key").to_string_lossy().into_owned(),
            cert_file: dir.join("ca.crt").to_string_lossy().into_owned(),
            key_type: key_type.to_string(),
            hash_alg: "sha256".to_string(),
            validity_days: 90,
            crl_url: None,
            ocsp_url: None,
            common_name: "Test CA".to_string(),
            organization: "Test Org".to_string(),
            ca_validity_years: 1,
        }
    }

    #[test]
    fn generate_backend_key_ec_p256() {
        let key = generate_backend_key("ec:P-256").unwrap();
        assert!(!key.public_key().unwrap().spki_der().is_empty());
    }

    #[test]
    fn generate_backend_key_ec_p384() {
        let key = generate_backend_key("ec:P-384").unwrap();
        assert!(!key.public_key().unwrap().spki_der().is_empty());
    }

    #[test]
    fn generate_backend_key_ec_p521() {
        let key = generate_backend_key("ec:P-521").unwrap();
        assert!(!key.public_key().unwrap().spki_der().is_empty());
    }

    #[test]
    fn generate_backend_key_ed25519() {
        let key = generate_backend_key("ed25519").unwrap();
        assert!(!key.public_key().unwrap().spki_der().is_empty());
    }

    #[test]
    fn generate_backend_key_unknown_type_returns_error() {
        let result = generate_backend_key("bogus:key-type");
        assert!(result.is_err());
        match result.unwrap_err() {
            AcmeError::Internal(msg) => assert!(msg.contains("unknown key type")),
            other => panic!("expected Internal, got {other:?}"),
        }
    }

    #[test]
    fn unix_to_generalized_time_known_epoch() {
        // Unix epoch = 1970-01-01 00:00:00 UTC
        let result = unix_to_generalized_time(0);
        assert_eq!(result, "19700101000000Z");
    }

    #[test]
    fn unix_to_generalized_time_known_date() {
        // 2024-01-01 00:00:00 UTC = 1704067200
        let result = unix_to_generalized_time(1_704_067_200);
        assert_eq!(result, "20240101000000Z");
    }

    #[test]
    fn load_or_generate_creates_files() {
        let dir = tempdir().unwrap();
        let config = make_config_with_paths(dir.path(), "ec:P-256");

        // Neither file exists — should generate.
        let (_key, cert_der) = load_or_generate(&config).unwrap();
        assert!(!cert_der.is_empty());
        assert!(std::path::Path::new(&config.key_file).exists());
        assert!(std::path::Path::new(&config.cert_file).exists());

        // Both files now exist — should load.
        let (_key2, cert_der2) = load_or_generate(&config).unwrap();
        assert_eq!(
            cert_der, cert_der2,
            "loaded cert should match generated cert"
        );
    }

    #[test]
    fn load_or_generate_partial_files_returns_error() {
        let dir = tempdir().unwrap();
        let config = make_config_with_paths(dir.path(), "ec:P-256");

        // Only key file exists (cert missing) — should error.
        fs::write(&config.key_file, b"dummy").unwrap();
        let result = load_or_generate(&config);
        assert!(result.is_err());
        match result.unwrap_err() {
            AcmeError::Internal(msg) => assert!(msg.contains("both exist or both be absent")),
            other => panic!("expected Internal, got {other:?}"),
        }
    }
}
