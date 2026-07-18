//! CA key and certificate initialisation.
//!
//! Handles three distinct start-up scenarios:
//!
//! - **File key, first run** (neither key file nor cert file exists): generate
//!   a new CA private key and self-signed certificate, write both to disk.
//! - **File key, subsequent runs** (both files exist): load key and cert from
//!   disk.
//! - **PKCS#11 key** (key lives in an HSM token): if the cert file is absent
//!   generate a self-signed CA certificate signed by the token key and write
//!   it to `cert_file`; otherwise load the cert from disk.  Key material is
//!   never extracted from the token.

use std::path::Path;

use synta_certificate::{
    default_key_id_hasher, der_to_pem, encode_authority_key_identifier, encode_basic_constraints,
    encode_key_usage, encode_subject_key_identifier, oids, parse_time, BackendPrivateKey,
    CertificateBuilder, KeyIdMethod, NameBuilder, PrivateKey, KEY_USAGE_C_RLSIGN,
    KEY_USAGE_KEY_CERT_SIGN,
};

use synta_mtc::builder::{ca_extension::build_mtc_ca_extension_from_hash, MTC_CA_EXTENSION_OID};
use synta_mtc::crypto::HashAlgorithm;

use crate::config::CaConfig;
use crate::error::AcmeError;

/// Load or auto-generate the CA key pair and certificate.
///
/// Returns `(key, cert_der)` where `cert_der` is the DER-encoded CA certificate.
///
/// For file-based keys both the key file and the certificate file must either
/// both exist (load path) or both be absent (auto-generate path).
///
/// For PKCS#11 URI keys the key lives in the token and is never written to
/// disk.  If the certificate file is also absent a self-signed CA certificate
/// is generated and written to `cert_file` on the first run.
pub fn load_or_generate(config: &CaConfig) -> Result<(BackendPrivateKey, Vec<u8>), AcmeError> {
    use crate::ca::key_loader::CaKeyLoader;

    let key_file = config.key_file.as_deref().ok_or_else(|| {
        AcmeError::Config(format!(
            "CA '{}': key_file is required for local signing",
            config.id
        ))
    })?;
    let loader = CaKeyLoader::new(config);
    let cert_exists = Path::new(&config.cert_file).exists();

    if loader.can_generate() {
        // File-based key: both files must exist together or be absent together.
        let key_exists = Path::new(key_file).exists();
        if key_exists && cert_exists {
            load(config)
        } else if !key_exists && !cert_exists {
            generate(config)
        } else {
            Err(AcmeError::Internal(
                "CA key and certificate files must both exist or both be absent".into(),
            ))
        }
    } else {
        // PKCS#11 key: key lives in the token; only the certificate is on disk.
        if cert_exists {
            load_pkcs11(config, &loader)
        } else {
            generate_cert_for_hsm_key(config, &loader)
        }
    }
}

/// Load an existing file-based CA key and certificate from disk.
///
/// Reads `config.key_file` as an unencrypted PEM private key and
/// `config.cert_file` as a PEM certificate, returning the first PEM block
/// from the certificate file as DER bytes.
///
/// Called only when both files already exist (verified by the caller).
fn load(config: &CaConfig) -> Result<(BackendPrivateKey, Vec<u8>), AcmeError> {
    let key_path = config.key_file.as_deref().unwrap();
    let key_pem = std::fs::read(key_path)
        .map_err(|e| AcmeError::Internal(format!("read CA key '{}': {}", key_path, e)))?;
    let cert_pem = std::fs::read(&config.cert_file)
        .map_err(|e| AcmeError::Internal(format!("read CA cert '{}': {}", config.cert_file, e)))?;

    let key = BackendPrivateKey::from_pem(&key_pem, None)
        .map_err(|e| AcmeError::Crypto(format!("parse CA key: {}", e)))?;

    let cert_ders = synta_certificate::pem_to_der(&cert_pem);
    let cert_der = cert_ders
        .into_iter()
        .next()
        .ok_or_else(|| AcmeError::Internal("CA certificate PEM has no blocks".into()))?;

    tracing::info!("Loaded CA key from {}", key_path);
    Ok((key, cert_der))
}

/// Generate a new file-based CA private key and self-signed certificate.
///
/// Writes the private key to `config.key_file` (unencrypted PKCS#8 PEM) and
/// the self-signed CA certificate to `config.cert_file` (PEM) before
/// returning.  Key type is taken from `config.key_type` (`"ec:P-256"`,
/// `"rsa:2048"`, `"ed25519"`, `"ml-dsa-44"`, etc.).
///
/// Called only when neither file exists (verified by the caller).
fn generate(config: &CaConfig) -> Result<(BackendPrivateKey, Vec<u8>), AcmeError> {
    let key_path = config.key_file.as_deref().unwrap();
    tracing::info!(
        "Generating new CA key ({}) — writing to {} and {}",
        config.key_type,
        key_path,
        config.cert_file
    );

    // Parse key spec: "ec:P-256", "rsa:2048", "ed25519"
    // Generate BackendPrivateKey (used for both signing and PEM export).
    let backend_key = generate_backend_key(&config.key_type)?;

    // Write key PEM immediately so we have it on disk before building the cert.
    let key_pem_out = backend_key
        .to_pem(None)
        .map_err(|e| AcmeError::Crypto(format!("CA key to PEM: {}", e)))?;
    crate::util::write_key_file(key_path, &key_pem_out)
        .map_err(|e| AcmeError::Internal(format!("write CA key '{}': {}", key_path, e)))?;

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
    let mut builder = CertificateBuilder::new()
        .issuer_name(&name_der)
        .subject_name(&name_der)
        .public_key_der(&spki_der)
        .serial_number(synta::Integer::from_i64(1))
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension_oid(oids::BASIC_CONSTRAINTS, true, &bc_der)
        .add_extension_oid(oids::KEY_USAGE, true, &ku_der)
        .add_extension_oid(oids::SUBJECT_KEY_IDENTIFIER, false, &ski_der)
        .add_extension_oid(oids::AUTHORITY_KEY_IDENTIFIER, false, &aki_der);

    if let Some(ref mtc_cfg) = config.mtc {
        if let Some((ext_der, critical)) = build_mtc_extension_der(mtc_cfg)? {
            builder = builder.add_extension_oid(MTC_CA_EXTENSION_OID, critical, &ext_der);
        }
    }

    let cert_der = builder
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

/// Load a PKCS#11-backed CA key and its corresponding certificate from disk.
fn load_pkcs11(
    config: &CaConfig,
    loader: &crate::ca::key_loader::CaKeyLoader<'_>,
) -> Result<(BackendPrivateKey, Vec<u8>), AcmeError> {
    let key = loader.load_key()?;

    let cert_pem = std::fs::read(&config.cert_file)
        .map_err(|e| AcmeError::Internal(format!("read CA cert '{}': {}", config.cert_file, e)))?;
    let cert_der = synta_certificate::pem_to_der(&cert_pem)
        .into_iter()
        .next()
        .ok_or_else(|| AcmeError::Internal("CA certificate PEM has no blocks".into()))?;

    tracing::info!(
        "Loaded CA key via PKCS#11 URI {}",
        config.key_file.as_deref().unwrap()
    );
    Ok((key, cert_der))
}

/// Generate and write a self-signed CA certificate for a key that already
/// exists in a PKCS#11 token.  The key itself is never extracted from the token.
fn generate_cert_for_hsm_key(
    config: &CaConfig,
    loader: &crate::ca::key_loader::CaKeyLoader<'_>,
) -> Result<(BackendPrivateKey, Vec<u8>), AcmeError> {
    tracing::info!(
        "Generating CA certificate for PKCS#11 key {} — writing to {}",
        config.key_file.as_deref().unwrap(),
        config.cert_file
    );

    let backend_key = loader.load_key()?;

    let spki_der = backend_key
        .public_key()
        .map_err(|e| AcmeError::Crypto(format!("PKCS#11 key public: {}", e)))?
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
    let ku_der = encode_key_usage((1u16 << KEY_USAGE_KEY_CERT_SIGN) | (1u16 << KEY_USAGE_C_RLSIGN))
        .ok_or_else(|| AcmeError::Builder("encode KeyUsage".into()))?;
    let ski_der =
        encode_subject_key_identifier(&spki_der, KeyIdMethod::Rfc7093Method1Sha256, &hasher)
            .ok_or_else(|| AcmeError::Builder("encode SKI".into()))?;
    let aki_der =
        encode_authority_key_identifier(&spki_der, KeyIdMethod::Rfc7093Method1Sha256, &hasher)
            .ok_or_else(|| AcmeError::Builder("encode AKI".into()))?;

    let signer = backend_key.as_signer(&config.hash_alg);
    let mut builder = CertificateBuilder::new()
        .issuer_name(&name_der)
        .subject_name(&name_der)
        .public_key_der(&spki_der)
        .serial_number(synta::Integer::from_i64(1))
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension_oid(oids::BASIC_CONSTRAINTS, true, &bc_der)
        .add_extension_oid(oids::KEY_USAGE, true, &ku_der)
        .add_extension_oid(oids::SUBJECT_KEY_IDENTIFIER, false, &ski_der)
        .add_extension_oid(oids::AUTHORITY_KEY_IDENTIFIER, false, &aki_der);

    if let Some(ref mtc_cfg) = config.mtc {
        if let Some((ext_der, critical)) = build_mtc_extension_der(mtc_cfg)? {
            builder = builder.add_extension_oid(MTC_CA_EXTENSION_OID, critical, &ext_der);
        }
    }

    let cert_der = builder
        .sign(&signer)
        .map_err(|e| AcmeError::Builder(format!("sign CA cert: {}", e)))?;

    // Write certificate PEM only (key stays in the token).
    let cert_pem = der_to_pem("CERTIFICATE", &cert_der);
    std::fs::write(&config.cert_file, &cert_pem)
        .map_err(|e| AcmeError::Internal(format!("write CA cert '{}': {}", config.cert_file, e)))?;

    tracing::info!(
        "Generated CA certificate for PKCS#11 key ({} years)",
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
/// Extract the SubjectPublicKeyInfo DER bytes from a DER-encoded certificate.
///
/// Used for Dogtag-backed CAs where there is no local private key — the SPKI
/// is read from the CA certificate itself.
pub fn extract_spki_from_cert_der(cert_der: &[u8]) -> Option<Vec<u8>> {
    let ranges = synta_certificate::cert_byte_ranges(cert_der)?;
    Some(cert_der[ranges.subject_public_key_info].to_vec())
}

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

/// Map a `(key_type, hash_alg)` pair to the corresponding signature
/// `AlgorithmIdentifier` for the MTC CA extension.
fn mtc_sig_algorithm_id(
    key_type: &str,
    hash_alg: &str,
) -> Result<synta_certificate::AlgorithmIdentifier<'static>, AcmeError> {
    use synta::types::constructed::Element;
    use synta::types::primitive::Null;
    use synta::ObjectIdentifier;

    // Determine OID and whether the parameters field must be NULL or absent.
    // RFC 4055: RSA → parameters MUST be NULL.
    // RFC 5754 §3.2: ECDSA → parameters MUST be absent.
    // RFC 8410: Ed25519/Ed448 → parameters MUST be absent.
    // FIPS 204: ML-DSA → parameters SHOULD be absent.
    let (oid_components, params_null): (&[u32], bool) = match (key_type, hash_alg) {
        ("ec:P-256" | "P-256", "sha256") => (oids::ECDSA_WITH_SHA256, false),
        ("ec:P-384" | "P-384", "sha384") => (oids::ECDSA_WITH_SHA384, false),
        ("ec:P-521" | "P-521", "sha512") => (oids::ECDSA_WITH_SHA512, false),
        ("ed25519", _) => (oids::ED25519, false),
        ("ed448", _) => (oids::ED448, false),
        ("ml-dsa-44" | "ML-DSA-44", _) => (oids::ML_DSA_44, false),
        ("ml-dsa-65" | "ML-DSA-65", _) => (oids::ML_DSA_65, false),
        ("ml-dsa-87" | "ML-DSA-87", _) => (oids::ML_DSA_87, false),
        _ => {
            return Err(AcmeError::Internal(format!(
                "cannot derive MTC sigAlg for key_type='{key_type}', hash_alg='{hash_alg}'"
            )));
        }
    };

    let oid = ObjectIdentifier::new(oid_components)
        .map_err(|e| AcmeError::Internal(format!("invalid sigAlg OID: {e}")))?;

    let parameters = if params_null {
        Some(Element::Null(Null))
    } else {
        None
    };

    Ok(synta_certificate::AlgorithmIdentifier {
        algorithm: oid,
        parameters,
    })
}

/// Build the `id-pe-mtcCertificationAuthority` extension DER from MTC config.
///
/// Returns `None` when MTC is disabled or the signing key is not configured.
fn build_mtc_extension_der(
    mtc_cfg: &crate::config::MtcConfig,
) -> Result<Option<(Vec<u8>, bool)>, AcmeError> {
    if !mtc_cfg.enabled {
        return Ok(None);
    }
    let sk = match mtc_cfg.signing_key {
        Some(ref sk) => sk,
        None => return Ok(None),
    };

    let sig_alg = mtc_sig_algorithm_id(&sk.key_type, &sk.hash_alg)?;
    let log_hash: HashAlgorithm = mtc_cfg
        .hash_alg
        .parse()
        .map_err(|e| AcmeError::Internal(format!("MTC hash_alg parse: {e}")))?;
    let min_serial = (mtc_cfg.log_number as u64) << 48 | 1;
    // Per draft-05 §"Limiting Issuance Logs": cap serials at the top of this
    // log number's range so relying parties reject entries from future log numbers.
    let max_serial = ((mtc_cfg.log_number as u64 + 1) << 48) - 1;

    let der = build_mtc_ca_extension_from_hash(log_hash, &sig_alg, min_serial, max_serial)
        .map_err(|e| AcmeError::Builder(format!("build MTCCertificationAuthority: {e}")))?;

    Ok(Some((der, true))) // MTCCertificationAuthority is always critical per spec
}

/// Generate a `BackendPrivateKey` using the synta-certificate crypto backend.
pub fn generate_backend_key(key_type: &str) -> Result<BackendPrivateKey, AcmeError> {
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
        // Composite ML-DSA (draft-ietf-lamps-pq-composite-sigs-19, requires OpenSSL 3.5+).
        // Accept the COMPSIG-* domain-separation label (case-insensitive), with or without
        // the "COMPSIG-" prefix and with an optional "composite-" prefix substituted for it.
        // Example accepted forms for sub-arc 40:
        //   "composite-mldsa44-ecdsa-p256-sha256"
        //   "COMPSIG-MLDSA44-ECDSA-P256-SHA256"
        //   "mldsa44-ecdsa-p256-sha256"
        other => {
            if let Some(sub_arc) = composite_mldsa_sub_arc(other) {
                BackendPrivateKey::generate_composite_ml_dsa(sub_arc).map_err(|e| cry(&e))
            } else {
                Err(AcmeError::Internal(format!(
                    "unknown key type '{other}'; use 'ec:P-256', 'rsa:2048', 'ed25519', \
                     'ml-dsa-44', or 'composite-mldsa44-ecdsa-p256-sha256' etc."
                )))
            }
        }
    }
}

/// Resolve a composite ML-DSA sub-arc (37–54) from a `key_type` config string.
///
/// Accepts the COMPSIG-* domain-separation label in any case, with or without
/// the `COMPSIG-` prefix, and with `composite-` as an alternative prefix.
/// Returns `None` when `key_type` does not match any of the 18 composite variants.
fn composite_mldsa_sub_arc(key_type: &str) -> Option<u32> {
    let upper = key_type.to_ascii_uppercase();
    // Strip optional "COMPOSITE-" prefix (akamu convention) so that
    // "composite-mldsa44-ecdsa-p256-sha256" matches "MLDSA44-ECDSA-P256-SHA256".
    let candidate = upper.strip_prefix("COMPOSITE-").unwrap_or(&upper);
    for sub_arc in 37u32..=54 {
        if let Some(spec) = synta_certificate::crypto::composite_spec(sub_arc) {
            let label_upper = spec.label.to_ascii_uppercase();
            // Accept the full COMPSIG-* label or the label without the COMPSIG- prefix.
            let label_short = label_upper.strip_prefix("COMPSIG-").unwrap_or(&label_upper);
            if candidate == label_upper || candidate == label_short {
                return Some(sub_arc);
            }
        }
    }
    None
}

/// Return the current UTC time as a GeneralizedTime string `YYYYMMDDHHmmssZ`.
fn format_now() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    unix_to_generalized_time(secs as i64)
}

/// Return a UTC time `years` years in the future as a GeneralizedTime string `YYYYMMDDHHmmssZ`.
///
/// Uses the approximation of 365.25 days/year (31 557 600 seconds/year).
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
            id: "default".to_owned(),
            is_default: true,
            caa_identities: vec![],
            key_file: Some(dir.join("ca.key").to_string_lossy().into_owned()),
            cert_file: dir.join("ca.crt").to_string_lossy().into_owned(),
            key_type: key_type.to_string(),
            hash_alg: "sha256".to_string(),
            validity_days: 90,
            crl_url: None,
            ocsp_url: None,
            common_name: "Test CA".to_string(),
            organization: "Test Org".to_string(),
            ca_validity_years: 1,
            crl_next_update_secs: 86400,
            enforce_validity_cap: false,
            require_encrypted_key: false,
            key_password_file: None,
            mtc: None,
            default_linter: None,
            signer: None,
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
    fn generate_backend_key_composite_mldsa44_ecdsa_p256() {
        // sub-arc 40: COMPSIG-MLDSA44-ECDSA-P256-SHA256
        let key = generate_backend_key("composite-mldsa44-ecdsa-p256-sha256").unwrap();
        assert!(!key.public_key().unwrap().spki_der().is_empty());
    }

    #[test]
    fn generate_backend_key_composite_label_case_variants() {
        // Uppercase COMPSIG- prefix accepted.
        let k1 = generate_backend_key("COMPSIG-MLDSA44-ECDSA-P256-SHA256").unwrap();
        // Lowercase without prefix accepted.
        let k2 = generate_backend_key("mldsa44-ecdsa-p256-sha256").unwrap();
        assert!(!k1.public_key().unwrap().spki_der().is_empty());
        assert!(!k2.public_key().unwrap().spki_der().is_empty());
    }

    #[test]
    fn generate_backend_key_composite_mldsa65_ecdsa_p384() {
        // sub-arc 46: COMPSIG-MLDSA65-ECDSA-P384-SHA512
        let key = generate_backend_key("composite-mldsa65-ecdsa-p384-sha512").unwrap();
        assert!(!key.public_key().unwrap().spki_der().is_empty());
    }

    #[test]
    fn generate_backend_key_composite_sub_arc_lookup() {
        // Verify that composite_mldsa_sub_arc resolves all 18 defined variants.
        for sub_arc in 37u32..=54 {
            let spec = synta_certificate::crypto::composite_spec(sub_arc).unwrap();
            // All three label forms must resolve back to the same sub-arc.
            let full = spec.label; // "COMPSIG-MLDSA44-..."
            let without_prefix = full.strip_prefix("COMPSIG-").unwrap();
            let with_composite = format!("composite-{}", without_prefix.to_ascii_lowercase());
            assert_eq!(
                composite_mldsa_sub_arc(full),
                Some(sub_arc),
                "full label {full}"
            );
            assert_eq!(
                composite_mldsa_sub_arc(without_prefix),
                Some(sub_arc),
                "without prefix {without_prefix}"
            );
            assert_eq!(
                composite_mldsa_sub_arc(&with_composite),
                Some(sub_arc),
                "composite- prefix {with_composite}"
            );
        }
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
        assert!(std::path::Path::new(config.key_file.as_deref().unwrap()).exists());
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
        fs::write(config.key_file.as_deref().unwrap(), b"dummy").unwrap();
        let result = load_or_generate(&config);
        assert!(result.is_err());
        match result.unwrap_err() {
            AcmeError::Internal(msg) => assert!(msg.contains("both exist or both be absent")),
            other => panic!("expected Internal, got {other:?}"),
        }
    }
}
