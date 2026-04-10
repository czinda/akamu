//! End-entity certificate issuance.
//!
//! Takes a validated CSR and CA state and returns a DER + PEM certificate bundle.

use synta::{Decoder, Encoding};
use synta_certificate::{
    default_key_id_hasher, der_to_pem, encode_authority_key_identifier,
    encode_basic_constraints, encode_key_usage, encode_subject_key_identifier,
    AuthorityInformationAccessBuilder, CRLDistributionPointsBuilder, Certificate,
    CertificateBuilder, ExtendedKeyUsageBuilder, KeyIdMethod, PrivateKey,
    SubjectAlternativeNameBuilder, KEY_USAGE_DIGITAL_SIGNATURE, oids,
};

use crate::error::AcmeError;

use super::csr::ValidatedCsr;
use super::init::unix_to_generalized_time;

/// Output of a successful certificate issuance.
pub struct IssuedCert {
    /// Random UUID for the `certificates` table primary key.
    pub id: String,
    /// Hex-encoded serial number (stored in `certificates.serial_number`).
    pub serial_hex: String,
    /// Raw bytes of the serial number (big-endian, positive two's complement).
    pub serial_bytes: Vec<u8>,
    /// DER-encoded leaf certificate only (for the `certificates.der` column).
    pub cert_der: Vec<u8>,
    /// PEM chain: leaf + CA (for the `certificates.pem` column and download).
    pub cert_pem: String,
    /// `notBefore` as Unix timestamp (for `certificates.not_before`).
    pub not_before: i64,
    /// `notAfter` as Unix timestamp (for `certificates.not_after`).
    pub not_after: i64,
}

/// Issue an end-entity certificate.
///
/// Parameters:
/// - `ca_key`       — CA private key (signing).
/// - `ca_cert_der`  — CA certificate DER (for issuer name + AKI).
/// - `hash_alg`     — Digest algorithm: `"sha256"`, `"sha384"`, `"sha512"`.
/// - `validity_days`— Cert validity in days.
/// - `crl_url`      — Optional CRL distribution point URL.
/// - `ocsp_url`     — Optional OCSP responder URL.
/// - `csr`          — Validated CSR output from `ca::csr::validate_csr`.
pub fn issue_certificate(
    ca_key: &synta_certificate::BackendPrivateKey,
    ca_cert_der: &[u8],
    hash_alg: &str,
    validity_days: u32,
    crl_url: Option<&str>,
    ocsp_url: Option<&str>,
    csr: &ValidatedCsr,
) -> Result<IssuedCert, AcmeError> {
    // ── Extract CA name and SPKI DER from the CA certificate ─────────────────
    let ca_name_der = extract_ca_subject_der(ca_cert_der)?;
    let ca_spki_der = ca_key
        .public_key()
        .map_err(|e| AcmeError::Crypto(format!("CA public key: {e}")))?
        .spki_der()
        .to_vec();

    // ── Generate a random 16-byte positive serial number ─────────────────────
    let mut serial_bytes = [0u8; 16];
    getrandom::getrandom(&mut serial_bytes)
        .map_err(|e| AcmeError::Internal(format!("random serial: {e}")))?;
    serial_bytes[0] &= 0x7f; // ensure positive (clear sign bit)
    let serial = synta::Integer::from_bytes(&serial_bytes);
    let serial_hex = hex_encode(&serial_bytes);

    // ── Compute validity window ───────────────────────────────────────────────
    let now = unix_now();
    let not_before_unix = now;
    let not_after_unix = now + validity_days as i64 * 86400;
    let not_before_str = unix_to_generalized_time(not_before_unix);
    let not_after_str = unix_to_generalized_time(not_after_unix);
    let not_before = synta_certificate::parse_time(&not_before_str)
        .map_err(|e| AcmeError::Builder(format!("notBefore: {e}")))?;
    let not_after = synta_certificate::parse_time(&not_after_str)
        .map_err(|e| AcmeError::Builder(format!("notAfter: {e}")))?;

    // ── Build extensions ──────────────────────────────────────────────────────
    let hasher = default_key_id_hasher();

    // BasicConstraints: end-entity (cA=FALSE, omitted per DER DEFAULT rule).
    let bc_der = encode_basic_constraints(false, None)
        .ok_or_else(|| AcmeError::Builder("BasicConstraints encode".into()))?;

    // KeyUsage: digitalSignature (suitable for all modern key types).
    let ku_der = encode_key_usage(1u16 << KEY_USAGE_DIGITAL_SIGNATURE)
        .ok_or_else(|| AcmeError::Builder("KeyUsage encode".into()))?;

    // ExtendedKeyUsage: serverAuth.
    let eku_der = ExtendedKeyUsageBuilder::new()
        .server_auth()
        .build()
        .map_err(|e| AcmeError::Builder(format!("EKU: {e}")))?;

    // SubjectKeyIdentifier (from the end-entity public key in the CSR).
    let ski_der =
        encode_subject_key_identifier(&csr.spki_der, KeyIdMethod::Rfc5280Sha1, &hasher)
            .ok_or_else(|| AcmeError::Builder("SKI encode".into()))?;

    // AuthorityKeyIdentifier (from the CA's public key).
    let aki_der =
        encode_authority_key_identifier(&ca_spki_der, KeyIdMethod::Rfc5280Sha1, &hasher)
            .ok_or_else(|| AcmeError::Builder("AKI encode".into()))?;

    // SubjectAlternativeName: rebuild from the validated SANs.
    let mut san_builder = SubjectAlternativeNameBuilder::new();
    for san in &csr.sans {
        match san.san_type.as_str() {
            "dns" => {
                san_builder = san_builder.dns_name(&san.value);
            }
            "ip" => {
                let ip_bytes = ip_string_to_bytes(&san.value).ok_or_else(|| {
                    AcmeError::Builder(format!("invalid IP SAN: {}", san.value))
                })?;
                san_builder = san_builder.ip_address(&ip_bytes);
            }
            _ => {}
        }
    }
    let san_der = san_builder.build().map_err(|e| AcmeError::Builder(format!("SAN: {e}")))?;

    // ── Assemble the certificate ──────────────────────────────────────────────
    let signer = ca_key.as_signer(hash_alg);

    let mut builder = CertificateBuilder::new()
        .issuer_name(&ca_name_der)
        .subject_name(&csr.subject_der)
        .public_key_der(&csr.spki_der)
        .serial_number(serial)
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension_oid(oids::BASIC_CONSTRAINTS, false, &bc_der)
        .add_extension_oid(oids::KEY_USAGE, true, &ku_der)
        .add_extension_oid(oids::EXTENDED_KEY_USAGE, false, &eku_der)
        .add_extension_oid(oids::SUBJECT_KEY_IDENTIFIER, false, &ski_der)
        .add_extension_oid(oids::AUTHORITY_KEY_IDENTIFIER, false, &aki_der)
        .add_extension_oid(oids::SUBJECT_ALT_NAME, false, &san_der);

    if let Some(ocsp) = ocsp_url {
        let aia_der = AuthorityInformationAccessBuilder::new()
            .ocsp(ocsp)
            .build()
            .map_err(|e| AcmeError::Builder(format!("AIA: {e}")))?;
        builder = builder.add_extension_oid(oids::AUTHORITY_INFO_ACCESS, false, &aia_der);
    }

    if let Some(crl) = crl_url {
        let cdp_der = CRLDistributionPointsBuilder::new()
            .full_name_uri(crl)
            .build()
            .map_err(|e| AcmeError::Builder(format!("CDP: {e}")))?;
        builder = builder.add_extension_oid(oids::CRL_DISTRIBUTION_POINTS, false, &cdp_der);
    }

    let cert_der = builder
        .sign(&signer)
        .map_err(|e| AcmeError::Builder(format!("sign: {e}")))?;

    // ── Build PEM bundle: leaf + CA ────────────────────────────────────────────
    // der_to_pem returns Vec<u8> (ASCII PEM bytes); concatenate and convert.
    let mut pem_bytes = der_to_pem("CERTIFICATE", &cert_der);
    pem_bytes.extend_from_slice(&der_to_pem("CERTIFICATE", ca_cert_der));
    let cert_pem = String::from_utf8(pem_bytes)
        .map_err(|_| AcmeError::Internal("PEM contains invalid UTF-8".into()))?;

    Ok(IssuedCert {
        id: uuid::Uuid::new_v4().to_string(),
        serial_hex,
        serial_bytes: serial_bytes.to_vec(),
        cert_der,
        cert_pem,
        not_before: not_before_unix,
        not_after: not_after_unix,
    })
}

// ── Internal helpers ──────────────────────────────────────────────────────────

/// Extract the DER-encoded subject Name from a DER-encoded certificate.
fn extract_ca_subject_der(ca_cert_der: &[u8]) -> Result<Vec<u8>, AcmeError> {
    let mut dec = Decoder::new(ca_cert_der, Encoding::Der);
    let cert: Certificate =
        dec.decode().map_err(|e| AcmeError::Internal(format!("parse CA cert: {e}")))?;
    Ok(cert.tbs_certificate.subject.0.to_vec())
}

/// Return the current time as Unix seconds.
fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

/// Encode a byte slice as a lowercase hex string.
fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Convert a dotted-decimal IPv4 or colon-hex IPv6 string to raw bytes.
fn ip_string_to_bytes(s: &str) -> Option<Vec<u8>> {
    use std::net::IpAddr;
    match s.parse::<IpAddr>() {
        Ok(IpAddr::V4(v4)) => Some(v4.octets().to_vec()),
        Ok(IpAddr::V6(v6)) => Some(v6.octets().to_vec()),
        Err(_) => None,
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use synta::{Decoder, Encoding};
    use synta_certificate::{
        BackendPrivateKey, Certificate, CertificateBuilder, CsrBuilder, KeyIdMethod, NameBuilder,
        PrivateKey as _, default_key_id_hasher, encode_basic_constraints, encode_key_usage,
        encode_subject_key_identifier, encode_authority_key_identifier,
        KEY_USAGE_C_RLSIGN, KEY_USAGE_KEY_CERT_SIGN,
        SubjectAlternativeNameBuilder,
    };
    use synta_x509_verification::{
        ops::VerificationCertificate,
        policy::{PolicyDefinition, Subject},
        trust_store::Store,
        types::DNSName,
        verify, RevocationChecks,
    };
    use synta_certificate::OpensslSignatureVerifier;

    use crate::ca::csr::{validate_csr, ValidatedCsr};
    use super::issue_certificate;

    /// Build a minimal self-signed CA certificate DER for testing.
    fn make_test_ca() -> (BackendPrivateKey, Vec<u8>) {
        let key = BackendPrivateKey::generate_ec("P-256").unwrap();
        let spki = key.public_key().unwrap().spki_der().to_vec();
        let hasher = default_key_id_hasher();
        let name_der = NameBuilder::new().common_name("Test CA").build().unwrap();
        let now = crate::ca::init::unix_to_generalized_time(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64,
        );
        let exp = crate::ca::init::unix_to_generalized_time(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64
                + 86400 * 365 * 10,
        );
        use synta_certificate::parse_time;
        let not_before = parse_time(&now).unwrap();
        let not_after = parse_time(&exp).unwrap();
        let bc = encode_basic_constraints(true, None).unwrap();
        let ku = encode_key_usage(
            (1u16 << KEY_USAGE_KEY_CERT_SIGN) | (1u16 << KEY_USAGE_C_RLSIGN),
        ).unwrap();
        let ski = encode_subject_key_identifier(&spki, KeyIdMethod::Rfc5280Sha1, &hasher).unwrap();
        let aki =
            encode_authority_key_identifier(&spki, KeyIdMethod::Rfc5280Sha1, &hasher).unwrap();
        let signer = key.as_signer("sha256");
        let cert_der = CertificateBuilder::new()
            .issuer_name(&name_der)
            .subject_name(&name_der)
            .public_key_der(&spki)
            .serial_number(synta::Integer::from_i64(1))
            .not_valid_before(not_before)
            .not_valid_after(not_after)
            .add_extension_oid(synta_certificate::oids::BASIC_CONSTRAINTS, true, &bc)
            .add_extension_oid(synta_certificate::oids::KEY_USAGE, true, &ku)
            .add_extension_oid(synta_certificate::oids::SUBJECT_KEY_IDENTIFIER, false, &ski)
            .add_extension_oid(synta_certificate::oids::AUTHORITY_KEY_IDENTIFIER, false, &aki)
            .sign(&signer)
            .unwrap();
        (key, cert_der)
    }

    /// Build a minimal ValidatedCsr for "test.example.com" using CsrBuilder.
    fn make_test_csr(domain: &str) -> (BackendPrivateKey, ValidatedCsr) {
        let ee_key = BackendPrivateKey::generate_ec("P-256").unwrap();
        let spki_der = ee_key.public_key().unwrap().spki_der().to_vec();
        let name_der = NameBuilder::new().common_name(domain).build().unwrap();

        let san_der = SubjectAlternativeNameBuilder::new()
            .dns_name(domain)
            .build()
            .unwrap();

        let signer = ee_key.as_signer("sha256");
        let csr_der = CsrBuilder::new()
            .subject_name(&name_der)
            .public_key_der(&spki_der)
            .add_extension_oid(synta_certificate::oids::SUBJECT_ALT_NAME, false, &san_der)
            .sign(&signer)
            .unwrap();

        let allowed = &[("dns", domain)];
        let validated = validate_csr(&csr_der, allowed).unwrap();
        (ee_key, validated)
    }

    #[test]
    fn issue_cert_end_to_end() {
        let (ca_key, ca_cert_der) = make_test_ca();
        let domain = "test.example.com";
        let (_ee_key, validated_csr) = make_test_csr(domain);

        let issued = issue_certificate(
            &ca_key,
            &ca_cert_der,
            "sha256",
            90,
            None,
            None,
            &validated_csr,
        )
        .unwrap();

        // Cert DER should parse cleanly.
        let mut dec = Decoder::new(&issued.cert_der, Encoding::Der);
        let cert: Certificate = dec.decode().unwrap();

        // Serial should be a non-empty hex string.
        assert!(!issued.serial_hex.is_empty());

        // The parsed certificate's serial should match.
        let hex: String = cert
            .tbs_certificate
            .serial_number
            .as_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(hex, issued.serial_hex);

        // PEM bundle should contain two certificates.
        assert!(issued.cert_pem.contains("-----BEGIN CERTIFICATE-----"));
        let count = issued.cert_pem.matches("-----BEGIN CERTIFICATE-----").count();
        assert_eq!(count, 2, "PEM bundle must contain leaf + CA");

        // Chain verification with synta-x509-verification.
        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        let ca_parsed: Certificate =
            Decoder::new(&ca_cert_der, Encoding::Der).decode().unwrap();
        let ca_vcert = VerificationCertificate::new(ca_parsed, &ca_cert_der);
        let store = Store::new(vec![ca_vcert]);

        let leaf_parsed: Certificate =
            Decoder::new(&issued.cert_der, Encoding::Der).decode().unwrap();
        let leaf_vcert = VerificationCertificate::new(leaf_parsed, &issued.cert_der);

        let dns_name = DNSName::new(domain).unwrap();
        let policy = PolicyDefinition::new_server(
            OpensslSignatureVerifier,
            vec![Subject::Dns(dns_name)],
            now_unix,
        );

        verify(&leaf_vcert, &[], &policy, &store, RevocationChecks::default())
            .expect("certificate chain verification failed");
    }
}
