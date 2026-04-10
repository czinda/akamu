//! CA key and certificate initialisation.
//!
//! On first run: generate a new CA key + self-signed certificate and write
//! them to the configured PEM files. On subsequent runs: load the existing
//! PEM files.

use std::path::Path;

use synta_certificate::{
    BackendPrivateKey, CertificateBuilder, KeyIdMethod, NameBuilder, PrivateKey,
    default_key_id_hasher, der_to_pem, encode_authority_key_identifier,
    encode_basic_constraints, encode_key_usage, encode_subject_key_identifier,
    KEY_USAGE_C_RLSIGN, KEY_USAGE_KEY_CERT_SIGN, oids, parse_time,
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
    let ski_der = encode_subject_key_identifier(&spki_der, KeyIdMethod::Rfc5280Sha1, &hasher)
        .ok_or_else(|| AcmeError::Builder("encode SKI".into()))?;
    let aki_der = encode_authority_key_identifier(&spki_der, KeyIdMethod::Rfc5280Sha1, &hasher)
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

/// Generate a `BackendPrivateKey` using the synta-certificate crypto backend.
fn generate_backend_key(key_type: &str) -> Result<BackendPrivateKey, AcmeError> {
    let result = match key_type {
        "ec:P-256" | "P-256" => BackendPrivateKey::generate_ec("P-256"),
        "ec:P-384" | "P-384" => BackendPrivateKey::generate_ec("P-384"),
        "ec:P-521" | "P-521" => BackendPrivateKey::generate_ec("P-521"),
        "rsa:2048" | "rsa2048" => BackendPrivateKey::generate_rsa(2048, 65537),
        "rsa:3072" | "rsa3072" => BackendPrivateKey::generate_rsa(3072, 65537),
        "rsa:4096" | "rsa4096" => BackendPrivateKey::generate_rsa(4096, 65537),
        "ed25519" => BackendPrivateKey::generate_ed25519(),
        "ed448" => BackendPrivateKey::generate_ed448(),
        other => {
            return Err(AcmeError::Internal(format!(
                "unknown key type '{}'; use 'ec:P-256', 'rsa:2048', 'ed25519', etc.",
                other
            )));
        }
    };
    result.map_err(|e| AcmeError::Crypto(format!("generate {key_type}: {e}")))
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
