//! End-entity certificate issuance.
//!
//! Takes a validated CSR and CA state and returns a DER + PEM certificate bundle.

use synta::{Decoder, Encoding};
use synta_certificate::{
    default_key_id_hasher, der_to_pem, encode_authority_key_identifier, encode_basic_constraints,
    encode_key_usage, encode_subject_key_identifier, oids, AuthorityInformationAccessBuilder,
    CRLDistributionPointsBuilder, Certificate, CertificateBuilder, CertificatePoliciesBuilder,
    ExtendedKeyUsageBuilder, KeyIdMethod, NameBuilder, OpensslSignatureVerifier, PrivateKey,
    SubjectAlternativeNameBuilder, KEY_USAGE_C_RLSIGN, KEY_USAGE_DIGITAL_SIGNATURE,
    KEY_USAGE_KEY_CERT_SIGN,
};
use synta_x509_verification::{
    ops::VerificationCertificate,
    policy::{
        ExtensionPolicy, PolicyDefinition, ValidationProfile,
        WEBPKI_PERMITTED_SIGNATURE_ALGORITHMS_WITH_PQ, WEBPKI_PERMITTED_SPKI_ALGORITHMS_WITH_PQ,
    },
    OwnedStore, RevocationChecks,
};

use crate::error::AcmeError;
use crate::profiles::CertificateParameters;
use crate::state::CaState;
use crate::util::{extract_ca_subject_der, unix_now};

use super::csr::ValidatedCsr;
use super::init::unix_to_generalized_time;

/// Output of a successful certificate issuance.
#[derive(Debug)]
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

/// Parameters for [`issue_certificate`].
pub struct IssueCertParams<'a> {
    pub ca_key: &'a synta_certificate::BackendPrivateKey,
    pub ca_cert_der: &'a [u8],
    /// Digest algorithm: `"sha256"`, `"sha384"`, `"sha512"`.
    pub hash_alg: &'a str,
    /// Cert validity in days (used when `not_after_override` is `None`).
    pub validity_days: u32,
    pub crl_url: Option<&'a str>,
    pub ocsp_url: Option<&'a str>,
    pub csr: &'a ValidatedCsr,
    /// Optional Unix timestamp for notBefore (RFC 8555 §7.1.3).
    pub not_before_override: Option<i64>,
    /// Optional Unix timestamp for notAfter (RFC 8555 §7.1.3).
    pub not_after_override: Option<i64>,
}

/// Issue an end-entity certificate.
///
/// Validity window resolution:
/// - Both `None`: `now` → `now + validity_days * 86400`.
/// - Only `not_before_override` set: override → `override + validity_days * 86400`.
/// - Only `not_after_override` set: `now` → override.
/// - Both set: override → override.
///
/// Clamping: notBefore is clamped to `now - 300` (5-minute grace for clock skew).
/// A warning is logged if either bound is adjusted.
pub fn issue_certificate(params: IssueCertParams<'_>) -> Result<IssuedCert, AcmeError> {
    let IssueCertParams {
        ca_key,
        ca_cert_der,
        hash_alg,
        validity_days,
        crl_url,
        ocsp_url,
        csr,
        not_before_override,
        not_after_override,
    } = params;
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
    // Clear the sign bit (positive) and set the low bit so the first byte is
    // always in 0x01..0x7f — DER INTEGER must be minimal (no unnecessary leading
    // 0x00), and a zero first byte would be unnecessary when the next byte's MSB
    // is clear.  Forcing bit 0 avoids that case without reducing serial length.
    serial_bytes[0] = (serial_bytes[0] & 0x7f) | 0x01;
    let serial = synta::Integer::from_bytes(&serial_bytes);
    let serial_hex = hex_encode(&serial_bytes);

    // ── Compute validity window ───────────────────────────────────────────────
    let now = unix_now();

    // Resolve the raw requested notBefore.
    let raw_not_before = not_before_override.unwrap_or(now);

    // Clamp notBefore: must not be more than 5 minutes in the past.
    let earliest_allowed = now - 300;
    let not_before_unix = if raw_not_before < earliest_allowed {
        tracing::warn!(
            "issue_certificate: requested notBefore {} is before now-300 ({}); \
             clamping to {}",
            raw_not_before,
            earliest_allowed,
            earliest_allowed,
        );
        earliest_allowed
    } else {
        raw_not_before
    };

    // Resolve notAfter: explicit override, or computed from the (clamped) notBefore.
    let raw_not_after =
        not_after_override.unwrap_or(not_before_unix + validity_days as i64 * 86400);

    // notAfter must be strictly after notBefore.
    let not_after_unix = if raw_not_after <= not_before_unix {
        let fallback = not_before_unix + validity_days as i64 * 86400;
        tracing::warn!(
            "issue_certificate: requested notAfter {} is not after notBefore {}; \
             using fallback {}",
            raw_not_after,
            not_before_unix,
            fallback,
        );
        fallback
    } else {
        raw_not_after
    };
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
        encode_subject_key_identifier(&csr.spki_der, KeyIdMethod::Rfc7093Method1Sha256, &hasher)
            .ok_or_else(|| AcmeError::Builder("SKI encode".into()))?;

    // AuthorityKeyIdentifier (from the CA's public key).
    let aki_der =
        encode_authority_key_identifier(&ca_spki_der, KeyIdMethod::Rfc7093Method1Sha256, &hasher)
            .ok_or_else(|| AcmeError::Builder("AKI encode".into()))?;

    // SubjectAlternativeName: rebuild from the validated SANs.
    let mut san_builder = SubjectAlternativeNameBuilder::new();
    for san in &csr.sans {
        match san.san_type.as_str() {
            "dns" => {
                san_builder = san_builder.dns_name(&san.value);
            }
            "ip" => {
                let ip_bytes = ip_string_to_bytes(&san.value)
                    .ok_or_else(|| AcmeError::Builder(format!("invalid IP SAN: {}", san.value)))?;
                san_builder = san_builder.ip_address(&ip_bytes);
            }
            other => {
                tracing::warn!(
                    "issue_certificate: unrecognised SAN type '{}' — skipped",
                    other
                );
            }
        }
    }
    let san_der = san_builder
        .build()
        .map_err(|e| AcmeError::Builder(format!("SAN: {e}")))?;

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

    // Pre-issuance policy lint (CA/B Forum BR §4.3.1.2).
    lint_issued_cert(&cert_der, ca_cert_der, now)?;

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

// ── Profile-aware extension builders ─────────────────────────────────────────

/// Build an ExtendedKeyUsage DER value from a list of short names or OID strings.
///
/// Recognised short names: `server_auth`, `client_auth`, `code_signing`,
/// `email_protection`, `time_stamping`, `ocsp_signing`.
/// Dotted-decimal OID strings (e.g. `"1.3.6.1.5.5.7.3.1"`) are also accepted.
fn build_eku(ekus: &[String]) -> Result<Vec<u8>, AcmeError> {
    let mut builder = ExtendedKeyUsageBuilder::new();
    for eku in ekus {
        builder = match eku.as_str() {
            "server_auth" => builder.server_auth(),
            "client_auth" => builder.client_auth(),
            "code_signing" => builder.code_signing(),
            "email_protection" => builder.email_protection(),
            "time_stamping" => builder.time_stamping(),
            "ocsp_signing" => builder.ocsp_signing(),
            dotted => {
                // Parse dotted-decimal OID string into component array.
                let comps = parse_oid_str(dotted).ok_or_else(|| {
                    AcmeError::Builder(format!("invalid EKU OID string '{dotted}'"))
                })?;
                builder.add_oid(&comps)
            }
        };
    }
    builder
        .build()
        .map_err(|e| AcmeError::Builder(format!("EKU build: {e}")))
}

/// Build a CertificatePolicies DER value from `(OID, CPS URI)` pairs.
///
/// Each pair produces one `PolicyInformation` element in the extension.
/// When the CPS URI is `Some(uri)` and non-empty, an `id-qt-cps`
/// qualifier (OID 1.3.6.1.5.5.7.2.1) is attached to that policy entry.
/// When the CPS URI is `None` or an empty string, the policy is encoded
/// with no qualifiers.  Returns `Err` when any OID string fails to parse
/// as dotted-decimal, or when the underlying DER encoder fails.
fn build_certificate_policies(policies: &[(String, Option<String>)]) -> Result<Vec<u8>, AcmeError> {
    let mut builder = CertificatePoliciesBuilder::new();
    for (oid_str, cps_uri) in policies {
        let comps = parse_oid_str(oid_str)
            .ok_or_else(|| AcmeError::Builder(format!("invalid policy OID '{oid_str}'")))?;
        builder = match cps_uri.as_deref() {
            Some(uri) if !uri.is_empty() => builder.add_policy_cps(&comps, uri),
            _ => builder.add_policy(&comps),
        };
    }
    builder
        .build()
        .map_err(|e| AcmeError::Builder(format!("CertificatePolicies build: {e}")))
}

/// Parse a dotted-decimal OID string into a `Vec<u32>` component array.
///
/// Returns `None` when any component fails to parse as `u32`.
fn parse_oid_str(s: &str) -> Option<Vec<u32>> {
    s.split('.')
        .map(|part| part.parse::<u32>().ok())
        .collect::<Option<Vec<u32>>>()
        .filter(|v| !v.is_empty())
}

// ── Internal helpers ──────────────────────────────────────────────────────────

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

/// Issue an end-entity certificate using parameters derived from a profile.
///
/// This is the primary issuance path when the `[profiles]` subsystem is
/// configured.  The caller resolves a [`CertificateParameters`] from
/// [`crate::profiles::ProfileRegistry::resolve`] and passes it here;
/// `CaState` provides only the signing key and CA certificate — all issuance
/// policy (validity, key usage, EKU, CRL/OCSP URLs, certificate policies)
/// comes from `params`.
///
/// Extension building decisions:
/// - **KeyUsage**: encoded when `params.key_usage_bits != 0`; marked critical.
///   Zero bits means the extension is omitted entirely.
/// - **ExtendedKeyUsage**: encoded when `params.extended_key_usages` is
///   non-empty; non-critical.  Short names and raw OID strings are both
///   supported (see `build_eku`).
/// - **CRLDistributionPoints**: encoded only when `params.crl_url` is
///   `Some`; non-critical.
/// - **AuthorityInfoAccess**: encoded only when `params.ocsp_url` is
///   `Some`; non-critical.
/// - **CertificatePolicies**: encoded only when `params.certificate_policies`
///   is non-empty; non-critical.
///
/// Validity window resolution and notBefore clamping follow the same rules
/// as [`issue_certificate`].
///
/// For orders without a `profile` field, pass
/// `CertificateParameters::from_ca(ca)` to reproduce the pre-profile
/// behaviour (`digitalSignature` KeyUsage, `serverAuth` EKU, CA validity).
pub fn issue_with_params(
    ca: &CaState,
    csr: &ValidatedCsr,
    params: &CertificateParameters,
    not_before_override: Option<i64>,
    not_after_override: Option<i64>,
) -> Result<IssuedCert, AcmeError> {
    // ── Extract CA name and SPKI DER ─────────────────────────────────────────
    let ca_name_der = extract_ca_subject_der(&ca.cert_der)?;
    let ca_spki_der = ca
        .key
        .public_key()
        .map_err(|e| AcmeError::Crypto(format!("CA public key: {e}")))?
        .spki_der()
        .to_vec();

    // ── Random serial ────────────────────────────────────────────────────────
    let mut serial_bytes = [0u8; 16];
    getrandom::getrandom(&mut serial_bytes)
        .map_err(|e| AcmeError::Internal(format!("random serial: {e}")))?;
    serial_bytes[0] = (serial_bytes[0] & 0x7f) | 0x01;
    let serial = synta::Integer::from_bytes(&serial_bytes);
    let serial_hex = hex_encode(&serial_bytes);

    // ── Validity window ──────────────────────────────────────────────────────
    let now = unix_now();
    let raw_not_before = not_before_override.unwrap_or(now);
    let earliest_allowed = now - 300;
    let not_before_unix = if raw_not_before < earliest_allowed {
        tracing::warn!(
            "issue_with_params: notBefore {} before now-300 ({}); clamping",
            raw_not_before,
            earliest_allowed
        );
        earliest_allowed
    } else {
        raw_not_before
    };
    let raw_not_after =
        not_after_override.unwrap_or(not_before_unix + params.validity_days as i64 * 86400);
    let not_after_unix = if raw_not_after <= not_before_unix {
        let fallback = not_before_unix + params.validity_days as i64 * 86400;
        tracing::warn!(
            "issue_with_params: notAfter {} not after notBefore {}; using fallback {}",
            raw_not_after,
            not_before_unix,
            fallback,
        );
        fallback
    } else {
        raw_not_after
    };
    // CA/B Forum BR §6.3.2 hard cap at issuance when configured.
    if ca.enforce_validity_cap {
        let validity_secs = not_after_unix - not_before_unix;
        let validity_days_computed = validity_secs / 86400;
        if validity_days_computed > 200 {
            return Err(AcmeError::BadRequest(format!(
                "certificate validity {} days exceeds the 200-day CA/B Forum BR §6.3.2 limit; \
                 set ca.enforce_validity_cap = false to allow longer validity for private PKI",
                validity_days_computed
            )));
        }
    }

    let not_before =
        synta_certificate::parse_time(&super::init::unix_to_generalized_time(not_before_unix))
            .map_err(|e| AcmeError::Builder(format!("notBefore: {e}")))?;
    let not_after =
        synta_certificate::parse_time(&super::init::unix_to_generalized_time(not_after_unix))
            .map_err(|e| AcmeError::Builder(format!("notAfter: {e}")))?;

    // ── Extensions ───────────────────────────────────────────────────────────
    let hasher = default_key_id_hasher();

    let bc_der = encode_basic_constraints(false, None)
        .ok_or_else(|| AcmeError::Builder("BasicConstraints encode".into()))?;

    // KeyUsage from profile parameters (zero bits → omit the extension).
    let ku_der = if params.key_usage_bits != 0 {
        Some(
            encode_key_usage(params.key_usage_bits)
                .ok_or_else(|| AcmeError::Builder("KeyUsage encode".into()))?,
        )
    } else {
        None
    };

    // ExtendedKeyUsage from the profile's EKU list.
    let eku_der = if !params.extended_key_usages.is_empty() {
        Some(build_eku(&params.extended_key_usages)?)
    } else {
        None
    };

    let ski_der =
        encode_subject_key_identifier(&csr.spki_der, KeyIdMethod::Rfc7093Method1Sha256, &hasher)
            .ok_or_else(|| AcmeError::Builder("SKI encode".into()))?;
    let aki_der =
        encode_authority_key_identifier(&ca_spki_der, KeyIdMethod::Rfc7093Method1Sha256, &hasher)
            .ok_or_else(|| AcmeError::Builder("AKI encode".into()))?;

    let mut san_builder = SubjectAlternativeNameBuilder::new();
    for san in &csr.sans {
        match san.san_type.as_str() {
            "dns" => {
                san_builder = san_builder.dns_name(&san.value);
            }
            "ip" => {
                let ip_bytes = ip_string_to_bytes(&san.value)
                    .ok_or_else(|| AcmeError::Builder(format!("invalid IP SAN: {}", san.value)))?;
                san_builder = san_builder.ip_address(&ip_bytes);
            }
            other => {
                tracing::warn!(
                    "issue_with_params: unrecognised SAN type '{}' — skipped",
                    other
                );
            }
        }
    }
    let san_der = san_builder
        .build()
        .map_err(|e| AcmeError::Builder(format!("SAN: {e}")))?;

    // ── Assemble certificate ─────────────────────────────────────────────────
    let signer = ca.key.as_signer(&params.hash_alg);

    let mut builder = CertificateBuilder::new()
        .issuer_name(&ca_name_der)
        .subject_name(&csr.subject_der)
        .public_key_der(&csr.spki_der)
        .serial_number(serial)
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension_oid(oids::BASIC_CONSTRAINTS, false, &bc_der);

    if let Some(ku) = &ku_der {
        builder = builder.add_extension_oid(oids::KEY_USAGE, true, ku);
    }
    if let Some(eku) = &eku_der {
        builder = builder.add_extension_oid(oids::EXTENDED_KEY_USAGE, false, eku);
    }

    builder = builder
        .add_extension_oid(oids::SUBJECT_KEY_IDENTIFIER, false, &ski_der)
        .add_extension_oid(oids::AUTHORITY_KEY_IDENTIFIER, false, &aki_der)
        .add_extension_oid(oids::SUBJECT_ALT_NAME, false, &san_der);

    if let Some(ocsp) = &params.ocsp_url {
        let aia_der = AuthorityInformationAccessBuilder::new()
            .ocsp(ocsp)
            .build()
            .map_err(|e| AcmeError::Builder(format!("AIA: {e}")))?;
        builder = builder.add_extension_oid(oids::AUTHORITY_INFO_ACCESS, false, &aia_der);
    }
    if let Some(crl) = &params.crl_url {
        let cdp_der = CRLDistributionPointsBuilder::new()
            .full_name_uri(crl)
            .build()
            .map_err(|e| AcmeError::Builder(format!("CDP: {e}")))?;
        builder = builder.add_extension_oid(oids::CRL_DISTRIBUTION_POINTS, false, &cdp_der);
    }

    // CertificatePolicies — only added when the profile specifies at least one entry.
    if !params.certificate_policies.is_empty() {
        let cp_der = build_certificate_policies(&params.certificate_policies)?;
        builder = builder.add_extension_oid(oids::CERTIFICATE_POLICIES, false, &cp_der);
    }

    let cert_der = builder
        .sign(&signer)
        .map_err(|e| AcmeError::Builder(format!("sign: {e}")))?;

    // Pre-issuance policy lint (CA/B Forum BR §4.3.1.2).
    lint_issued_cert(&cert_der, &ca.cert_der, now)?;

    let mut pem_bytes = der_to_pem("CERTIFICATE", &cert_der);
    pem_bytes.extend_from_slice(&der_to_pem("CERTIFICATE", &ca.cert_der));
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

/// Issue a server TLS certificate for Akāmu itself (bootstrap / self-hosted TLS).
///
/// The certificate is signed by the Akāmu CA so that any client trusting the CA
/// will also trust the TLS connection without extra configuration.
///
/// Extensions: SAN dNSName=`server_name`, BasicConstraints CA:FALSE,
/// KeyUsage digitalSignature, ExtendedKeyUsage serverAuth, SKI, AKI.
/// Validity: `ca.validity_days` days (same as subscriber certs).
pub fn sign_server_cert(
    server_name: &str,
    server_key: &synta_certificate::BackendPrivateKey,
    ca: &CaState,
) -> Result<Vec<u8>, AcmeError> {
    // Extract CA subject name for the issuer field.
    let ca_name_der = extract_ca_subject_der(&ca.cert_der)?;

    // Server public key SPKI.
    let spki_der = server_key
        .public_key()
        .map_err(|e| AcmeError::Crypto(format!("server public key: {e}")))?
        .spki_der()
        .to_vec();

    // CA public key for AKI.
    let ca_spki_der = ca
        .key
        .public_key()
        .map_err(|e| AcmeError::Crypto(format!("CA public key for AKI: {e}")))?
        .spki_der()
        .to_vec();

    // Random 16-byte positive serial.
    let mut serial_bytes = [0u8; 16];
    getrandom::getrandom(&mut serial_bytes)
        .map_err(|e| AcmeError::Internal(format!("random serial: {e}")))?;
    serial_bytes[0] = (serial_bytes[0] & 0x7f) | 0x01; // positive, non-zero first byte
    let serial = synta::Integer::from_bytes(&serial_bytes);

    // Validity window.
    let now = unix_now();
    let not_before_str = unix_to_generalized_time(now);
    let not_after_str = unix_to_generalized_time(now + ca.validity_days as i64 * 86400);
    let not_before = synta_certificate::parse_time(&not_before_str)
        .map_err(|e| AcmeError::Builder(format!("notBefore: {e}")))?;
    let not_after = synta_certificate::parse_time(&not_after_str)
        .map_err(|e| AcmeError::Builder(format!("notAfter: {e}")))?;

    // Subject: CN=server_name.
    let subject_der = NameBuilder::new()
        .common_name(server_name)
        .build()
        .map_err(|e| AcmeError::Builder(format!("subject name: {e}")))?;

    // Extensions.
    let hasher = default_key_id_hasher();

    let bc_der = encode_basic_constraints(false, None)
        .ok_or_else(|| AcmeError::Builder("BasicConstraints".into()))?;

    let ku_der = encode_key_usage(1u16 << KEY_USAGE_DIGITAL_SIGNATURE)
        .ok_or_else(|| AcmeError::Builder("KeyUsage".into()))?;

    let eku_der = ExtendedKeyUsageBuilder::new()
        .server_auth()
        .build()
        .map_err(|e| AcmeError::Builder(format!("EKU: {e}")))?;

    let ski_der =
        encode_subject_key_identifier(&spki_der, KeyIdMethod::Rfc7093Method1Sha256, &hasher)
            .ok_or_else(|| AcmeError::Builder("SKI".into()))?;

    let aki_der =
        encode_authority_key_identifier(&ca_spki_der, KeyIdMethod::Rfc7093Method1Sha256, &hasher)
            .ok_or_else(|| AcmeError::Builder("AKI".into()))?;

    let san_der = SubjectAlternativeNameBuilder::new()
        .dns_name(server_name)
        .build()
        .map_err(|e| AcmeError::Builder(format!("SAN: {e}")))?;

    // Sign with the CA key.
    let signer = ca.key.as_signer(&ca.hash_alg);
    CertificateBuilder::new()
        .issuer_name(&ca_name_der)
        .subject_name(&subject_der)
        .public_key_der(&spki_der)
        .serial_number(serial)
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension_oid(oids::BASIC_CONSTRAINTS, false, &bc_der)
        .add_extension_oid(oids::KEY_USAGE, true, &ku_der)
        .add_extension_oid(oids::EXTENDED_KEY_USAGE, false, &eku_der)
        .add_extension_oid(oids::SUBJECT_KEY_IDENTIFIER, false, &ski_der)
        .add_extension_oid(oids::AUTHORITY_KEY_IDENTIFIER, false, &aki_der)
        .add_extension_oid(oids::SUBJECT_ALT_NAME, false, &san_der)
        .sign(&signer)
        .map_err(|e| AcmeError::Builder(format!("sign server cert: {e}")))
}

/// Issue a CA-signed client certificate for an admin operator.
///
/// Produces a certificate with `digitalSignature` KeyUsage and `clientAuth` EKU,
/// suitable for mTLS client authentication against the admin listener.
/// The SHA-256 fingerprint of the returned DER is the credential stored in
/// the `operators` table.
pub fn sign_admin_cert(
    operator_name: &str,
    operator_key: &synta_certificate::BackendPrivateKey,
    ca: &CaState,
) -> Result<Vec<u8>, AcmeError> {
    let ca_name_der = extract_ca_subject_der(&ca.cert_der)?;

    let spki_der = operator_key
        .public_key()
        .map_err(|e| AcmeError::Crypto(format!("operator public key: {e}")))?
        .spki_der()
        .to_vec();

    let ca_spki_der = ca
        .key
        .public_key()
        .map_err(|e| AcmeError::Crypto(format!("CA public key for AKI: {e}")))?
        .spki_der()
        .to_vec();

    let mut serial_bytes = [0u8; 16];
    getrandom::getrandom(&mut serial_bytes)
        .map_err(|e| AcmeError::Internal(format!("random serial: {e}")))?;
    serial_bytes[0] = (serial_bytes[0] & 0x7f) | 0x01;
    let serial = synta::Integer::from_bytes(&serial_bytes);

    let now = unix_now();
    let not_before_str = unix_to_generalized_time(now);
    let not_after_str = unix_to_generalized_time(now + ca.validity_days as i64 * 86400);
    let not_before = synta_certificate::parse_time(&not_before_str)
        .map_err(|e| AcmeError::Builder(format!("notBefore: {e}")))?;
    let not_after = synta_certificate::parse_time(&not_after_str)
        .map_err(|e| AcmeError::Builder(format!("notAfter: {e}")))?;

    let subject_der = NameBuilder::new()
        .common_name(operator_name)
        .build()
        .map_err(|e| AcmeError::Builder(format!("subject name: {e}")))?;

    let hasher = default_key_id_hasher();

    let bc_der = encode_basic_constraints(false, None)
        .ok_or_else(|| AcmeError::Builder("BasicConstraints".into()))?;
    let ku_der = encode_key_usage(1u16 << KEY_USAGE_DIGITAL_SIGNATURE)
        .ok_or_else(|| AcmeError::Builder("KeyUsage".into()))?;
    let eku_der = ExtendedKeyUsageBuilder::new()
        .client_auth()
        .build()
        .map_err(|e| AcmeError::Builder(format!("EKU: {e}")))?;
    let ski_der =
        encode_subject_key_identifier(&spki_der, KeyIdMethod::Rfc7093Method1Sha256, &hasher)
            .ok_or_else(|| AcmeError::Builder("SKI".into()))?;
    let aki_der =
        encode_authority_key_identifier(&ca_spki_der, KeyIdMethod::Rfc7093Method1Sha256, &hasher)
            .ok_or_else(|| AcmeError::Builder("AKI".into()))?;

    let signer = ca.key.as_signer(&ca.hash_alg);
    CertificateBuilder::new()
        .issuer_name(&ca_name_der)
        .subject_name(&subject_der)
        .public_key_der(&spki_der)
        .serial_number(serial)
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension_oid(oids::BASIC_CONSTRAINTS, false, &bc_der)
        .add_extension_oid(oids::KEY_USAGE, true, &ku_der)
        .add_extension_oid(oids::EXTENDED_KEY_USAGE, false, &eku_der)
        .add_extension_oid(oids::SUBJECT_KEY_IDENTIFIER, false, &ski_der)
        .add_extension_oid(oids::AUTHORITY_KEY_IDENTIFIER, false, &aki_der)
        .sign(&signer)
        .map_err(|e| AcmeError::Builder(format!("sign admin cert: {e}")))
}

/// Apply CA/B Forum BR §4.3.1.2 pre-issuance policy linting to a just-signed certificate.
///
/// Validates the DER-encoded leaf against the WebPKI profile (CABF BR) using
/// `synta_x509_verification::verify`.  The check covers:
/// - Algorithm compliance: no SHA-1, RSA ≥ 2048, EC named curves, PQ parameter rules.
/// - Structural: AKI present, `basicConstraints.cA=FALSE`, serial ≤ 20 octets, v3.
/// - Validity window: `notBefore ≤ now ≤ notAfter`.
/// - Signature: the CA signature on the leaf is re-verified against `ca_cert_der`.
///
/// SAN matching and EKU content checks are intentionally skipped — those are validated
/// during CSR processing and may be profile-specific (non-serverAuth EKUs are valid).
///
/// Returns `AcmeError::Internal` if any check fails.
fn lint_issued_cert(cert_der: &[u8], ca_cert_der: &[u8], now: i64) -> Result<(), AcmeError> {
    // Build a trust store containing the single CA trust anchor.
    let store = OwnedStore::try_new(std::iter::once(ca_cert_der))
        .map_err(|e| AcmeError::Internal(format!("lint: parse CA cert: {e}")))?;

    // Parse the just-issued leaf.
    let mut dec = Decoder::new(cert_der, Encoding::Der);
    let cert: Certificate = dec
        .decode()
        .map_err(|e| AcmeError::Internal(format!("lint: parse cert: {e}")))?;
    let leaf = VerificationCertificate::new(cert, cert_der);

    // WebPKI policy: PQ-extended algorithm lists; no SAN matching; no EKU enforcement.
    let mut policy = PolicyDefinition::new_server_pq(OpensslSignatureVerifier, vec![], now);
    // Profiles may use non-serverAuth EKUs — skip the EKU presence/content check.
    policy.extended_key_usage = None;
    policy.permitted_spki_algorithms = WEBPKI_PERMITTED_SPKI_ALGORITHMS_WITH_PQ;
    policy.permitted_signature_algorithms = WEBPKI_PERMITTED_SIGNATURE_ALGORITHMS_WITH_PQ;

    store
        .verify(&leaf, &[], &policy, RevocationChecks::default())
        .map(|_| ())
        .map_err(|e| AcmeError::Internal(format!("pre-issuance lint failed: {e}")))
}

/// Output of `issue_ca_cert`.
pub struct IssuedCaCert {
    /// Hex serial number (same format as `certificates.serial_number`).
    pub serial_hex: String,
    /// DER-encoded cross-certificate.
    pub cert_der: Vec<u8>,
    /// PEM-encoded cross-certificate (single block, no CA chain appended).
    pub cert_pem: String,
    /// notBefore as Unix timestamp.
    pub not_before: i64,
    /// notAfter as Unix timestamp.
    pub not_after: i64,
    /// DER-encoded SubjectPublicKeyInfo of the subject CA.
    pub subject_spki_der: Vec<u8>,
    /// RFC 4514 subject distinguished name string (for the DB row).
    pub subject_dn: String,
}

/// Verify that `cert_der` is a valid CA certificate (BasicConstraints.cA=TRUE).
///
/// Uses `ValidationProfile::Rfc5280` so the CABF WebPKI restriction that rejects
/// `cA=TRUE` on end-entity certs is bypassed, and applies `ee_extension_policy =
/// new_default_webpki_ca()` which explicitly requires `BasicConstraints.cA=TRUE`.
/// The cert is used as its own trust anchor (self-signed root CA scenario).
pub(crate) fn check_is_ca_cert(cert_der: &[u8], now: i64) -> Result<(), AcmeError> {
    use synta_certificate::OpensslSignatureVerifier;

    let store = OwnedStore::try_new(std::iter::once(cert_der))
        .map_err(|e| AcmeError::Internal(format!("check CA cert: parse trust anchor: {e}")))?;

    let mut dec = Decoder::new(cert_der, Encoding::Der);
    let cert: Certificate = dec
        .decode()
        .map_err(|e| AcmeError::Internal(format!("check CA cert: decode: {e}")))?;
    let leaf = VerificationCertificate::new(cert, cert_der);

    let mut policy = PolicyDefinition::new_server_pq(OpensslSignatureVerifier, vec![], now);
    // Use RFC 5280 profile: WebPKI profile hardcodes a rejection of cA=TRUE on leaves.
    policy.profile = ValidationProfile::Rfc5280;
    policy.extended_key_usage = None;
    // Apply CA extension policy to the "leaf" so cA=TRUE is required.
    policy.ee_extension_policy = ExtensionPolicy::new_default_webpki_ca();

    store
        .verify(&leaf, &[], &policy, RevocationChecks::default())
        .map(|_| ())
        .map_err(|e| {
            AcmeError::BadRequest(format!(
                "subject certificate is not a valid CA certificate: {e}"
            ))
        })
}

/// Lint a just-issued CA certificate by re-verifying it against the signing CA.
///
/// Analogous to `lint_issued_cert` but for CA certificates: uses
/// `ValidationProfile::Rfc5280` and `ee_extension_policy = new_default_webpki_ca()`
/// so that `BasicConstraints.cA=TRUE` and the CA key-usage set are required on
/// the issued cert while CABF EE restrictions are not applied.
fn lint_issued_ca_cert(cert_der: &[u8], ca_cert_der: &[u8], now: i64) -> Result<(), AcmeError> {
    use synta_certificate::OpensslSignatureVerifier;

    let store = OwnedStore::try_new(std::iter::once(ca_cert_der))
        .map_err(|e| AcmeError::Internal(format!("ca lint: parse CA cert: {e}")))?;

    let mut dec = Decoder::new(cert_der, Encoding::Der);
    let cert: Certificate = dec
        .decode()
        .map_err(|e| AcmeError::Internal(format!("ca lint: parse cert: {e}")))?;
    let leaf = VerificationCertificate::new(cert, cert_der);

    let mut policy = PolicyDefinition::new_server_pq(OpensslSignatureVerifier, vec![], now);
    policy.profile = ValidationProfile::Rfc5280;
    policy.extended_key_usage = None;
    policy.ee_extension_policy = ExtensionPolicy::new_default_webpki_ca();

    store
        .verify(&leaf, &[], &policy, RevocationChecks::default())
        .map(|_| ())
        .map_err(|e| AcmeError::Internal(format!("cross-cert pre-issuance lint failed: {e}")))
}

/// Issue a CA certificate signed by `issuer_ca` for the subject public key
/// extracted from `subject_cert_der`.
///
/// The issued certificate carries:
/// - BasicConstraints: cA=TRUE, pathLen=0 (subject CA may sign EE certs but not further CAs)
/// - KeyUsage: keyCertSign + cRLSign (critical)
/// - SubjectKeyIdentifier from the subject CA's SPKI
/// - AuthorityKeyIdentifier from the issuer CA's SPKI
///
/// Validity: `validity_years` years from now (no 5-minute backdate clamp —
/// cross-certs are operator-initiated, not time-sensitive).
pub fn issue_ca_cert(
    issuer_ca: &CaState,
    subject_cert_der: &[u8],
    validity_years: u32,
) -> Result<IssuedCaCert, AcmeError> {
    // Parse the subject CA cert to extract Subject DN and SPKI.
    let mut dec = Decoder::new(subject_cert_der, Encoding::Der);
    let subject_cert: Certificate = dec
        .decode()
        .map_err(|e| AcmeError::Internal(format!("parse subject CA cert: {e}")))?;
    let subject_name_der = subject_cert.tbs_certificate.subject.0.to_vec();

    // Extract the raw DER bytes of the SubjectPublicKeyInfo.
    let subject_cert_ranges = synta_certificate::cert_byte_ranges(subject_cert_der)
        .ok_or_else(|| AcmeError::Internal("malformed subject CA certificate".into()))?;
    let subject_spki_der = subject_cert_der[subject_cert_ranges.subject_public_key_info].to_vec();

    // Derive a human-readable subject DN for the DB row.
    let subject_dn = synta_certificate::format_dn(subject_cert.tbs_certificate.subject.as_bytes());

    // Extract issuer CA SPKI for AKI computation.
    let issuer_spki_der = issuer_ca
        .key
        .public_key()
        .map_err(|e| AcmeError::Crypto(format!("issuer CA public key: {e}")))?
        .spki_der()
        .to_vec();

    // Issuer Name from issuer CA cert.
    let issuer_name_der = extract_ca_subject_der(&issuer_ca.cert_der)?;

    // Generate a random 16-byte positive serial.
    let mut serial_bytes = [0u8; 16];
    getrandom::getrandom(&mut serial_bytes)
        .map_err(|e| AcmeError::Internal(format!("random serial: {e}")))?;
    serial_bytes[0] = (serial_bytes[0] & 0x7f) | 0x01;
    let serial = synta::Integer::from_bytes(&serial_bytes);
    let serial_hex = hex_encode(&serial_bytes);

    // Validity window: now to now + validity_years * 365.25 days.
    let now = unix_now();
    let not_before_unix = now;
    let not_after_unix =
        now + (validity_years as i64) * 365 * 86400 + (validity_years as i64) * 21600;

    let not_before_str = unix_to_generalized_time(not_before_unix);
    let not_after_str = unix_to_generalized_time(not_after_unix);
    let not_before_t = synta_certificate::parse_time(&not_before_str)
        .map_err(|e| AcmeError::Builder(format!("cross-cert notBefore: {e}")))?;
    let not_after_t = synta_certificate::parse_time(&not_after_str)
        .map_err(|e| AcmeError::Builder(format!("cross-cert notAfter: {e}")))?;

    // Build extensions.
    let hasher = default_key_id_hasher();

    let bc_der = encode_basic_constraints(true, Some(0))
        .ok_or_else(|| AcmeError::Builder("BasicConstraints encode".into()))?;

    let ku_der = encode_key_usage((1u16 << KEY_USAGE_KEY_CERT_SIGN) | (1u16 << KEY_USAGE_C_RLSIGN))
        .ok_or_else(|| AcmeError::Builder("KeyUsage encode".into()))?;

    let ski_der = encode_subject_key_identifier(
        &subject_spki_der,
        KeyIdMethod::Rfc7093Method1Sha256,
        &hasher,
    )
    .ok_or_else(|| AcmeError::Builder("SKI encode".into()))?;

    let aki_der = encode_authority_key_identifier(
        &issuer_spki_der,
        KeyIdMethod::Rfc7093Method1Sha256,
        &hasher,
    )
    .ok_or_else(|| AcmeError::Builder("AKI encode".into()))?;

    let signer = issuer_ca.key.as_signer(&issuer_ca.hash_alg);

    let cert_der = CertificateBuilder::new()
        .issuer_name(&issuer_name_der)
        .subject_name(&subject_name_der)
        .public_key_der(&subject_spki_der)
        .serial_number(serial)
        .not_valid_before(not_before_t)
        .not_valid_after(not_after_t)
        .add_extension_oid(oids::BASIC_CONSTRAINTS, true, &bc_der)
        .add_extension_oid(oids::KEY_USAGE, true, &ku_der)
        .add_extension_oid(oids::SUBJECT_KEY_IDENTIFIER, false, &ski_der)
        .add_extension_oid(oids::AUTHORITY_KEY_IDENTIFIER, false, &aki_der)
        .sign(&signer)
        .map_err(|e| AcmeError::Builder(format!("sign cross-cert: {e}")))?;

    lint_issued_ca_cert(&cert_der, &issuer_ca.cert_der, not_before_unix)?;

    let pem_bytes = der_to_pem("CERTIFICATE", &cert_der);
    let cert_pem = String::from_utf8(pem_bytes)
        .map_err(|_| AcmeError::Internal("cross-cert PEM contains invalid UTF-8".into()))?;

    Ok(IssuedCaCert {
        serial_hex,
        cert_der,
        cert_pem,
        not_before: not_before_unix,
        not_after: not_after_unix,
        subject_spki_der,
        subject_dn,
    })
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use synta::{Decoder, Encoding};
    use synta_certificate::OpensslSignatureVerifier;
    use synta_certificate::{
        default_key_id_hasher, encode_authority_key_identifier, encode_basic_constraints,
        encode_key_usage, encode_subject_key_identifier, BackendPrivateKey, Certificate,
        CertificateBuilder, CsrBuilder, KeyIdMethod, NameBuilder, PrivateKey as _,
        SubjectAlternativeNameBuilder, KEY_USAGE_C_RLSIGN, KEY_USAGE_KEY_CERT_SIGN,
    };
    use synta_x509_verification::{
        ops::VerificationCertificate,
        policy::{PolicyDefinition, Subject},
        trust_store::Store,
        types::DNSName,
        verify, RevocationChecks,
    };

    use super::{
        hex_encode, ip_string_to_bytes, issue_certificate, issue_with_params, IssueCertParams,
    };
    use crate::ca::csr::{validate_csr, SanEntry, ValidatedCsr};

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
        let ku = encode_key_usage((1u16 << KEY_USAGE_KEY_CERT_SIGN) | (1u16 << KEY_USAGE_C_RLSIGN))
            .unwrap();
        let ski = encode_subject_key_identifier(&spki, KeyIdMethod::Rfc7093Method1Sha256, &hasher)
            .unwrap();
        let aki =
            encode_authority_key_identifier(&spki, KeyIdMethod::Rfc7093Method1Sha256, &hasher)
                .unwrap();
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
            .add_extension_oid(
                synta_certificate::oids::AUTHORITY_KEY_IDENTIFIER,
                false,
                &aki,
            )
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

        let issued = issue_certificate(IssueCertParams {
            ca_key: &ca_key,
            ca_cert_der: &ca_cert_der,
            hash_alg: "sha256",
            validity_days: 90,
            crl_url: None,
            ocsp_url: None,
            csr: &validated_csr,
            not_before_override: None,
            not_after_override: None,
        })
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
        let count = issued
            .cert_pem
            .matches("-----BEGIN CERTIFICATE-----")
            .count();
        assert_eq!(count, 2, "PEM bundle must contain leaf + CA");

        // Chain verification with synta-x509-verification.
        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        let ca_parsed: Certificate = Decoder::new(&ca_cert_der, Encoding::Der).decode().unwrap();
        let ca_vcert = VerificationCertificate::new(ca_parsed, &ca_cert_der);
        let store = Store::new(vec![ca_vcert]);

        let leaf_parsed: Certificate = Decoder::new(&issued.cert_der, Encoding::Der)
            .decode()
            .unwrap();
        let leaf_vcert = VerificationCertificate::new(leaf_parsed, &issued.cert_der);

        let dns_name = DNSName::new(domain).unwrap();
        let policy = PolicyDefinition::new_server(
            OpensslSignatureVerifier,
            vec![Subject::Dns(dns_name)],
            now_unix,
        );

        verify(
            &leaf_vcert,
            &[],
            &policy,
            &store,
            RevocationChecks::default(),
        )
        .expect("certificate chain verification failed");
    }

    #[test]
    fn issue_cert_with_crl_and_ocsp_urls() {
        let (ca_key, ca_cert_der) = make_test_ca();
        let (_ee_key, validated_csr) = make_test_csr("crl-test.example.com");

        let issued = issue_certificate(IssueCertParams {
            ca_key: &ca_key,
            ca_cert_der: &ca_cert_der,
            hash_alg: "sha256",
            validity_days: 90,
            crl_url: Some("http://crl.example.com/ca.crl"),
            ocsp_url: Some("http://ocsp.example.com"),
            csr: &validated_csr,
            not_before_override: None,
            not_after_override: None,
        })
        .unwrap();

        assert!(!issued.cert_der.is_empty());
        assert!(issued.cert_pem.contains("-----BEGIN CERTIFICATE-----"));
    }

    #[test]
    fn issue_cert_with_ip_san() {
        let (ca_key, ca_cert_der) = make_test_ca();
        let ee_key = BackendPrivateKey::generate_ec("P-256").unwrap();
        let spki_der = ee_key.public_key().unwrap().spki_der().to_vec();
        let name_der = NameBuilder::new().common_name("ip-test").build().unwrap();

        // Build an IP SAN CSR using CsrBuilder.
        let ip_bytes = [127u8, 0, 0, 1];
        let san_der = SubjectAlternativeNameBuilder::new()
            .ip_address(&ip_bytes)
            .build()
            .unwrap();
        let signer = ee_key.as_signer("sha256");
        let csr_der = CsrBuilder::new()
            .subject_name(&name_der)
            .public_key_der(&spki_der)
            .add_extension_oid(synta_certificate::oids::SUBJECT_ALT_NAME, false, &san_der)
            .sign(&signer)
            .unwrap();

        let validated = validate_csr(&csr_der, &[("ip", "127.0.0.1")]).unwrap();

        let issued = issue_certificate(IssueCertParams {
            ca_key: &ca_key,
            ca_cert_der: &ca_cert_der,
            hash_alg: "sha256",
            validity_days: 90,
            crl_url: None,
            ocsp_url: None,
            csr: &validated,
            not_before_override: None,
            not_after_override: None,
        })
        .unwrap();

        assert!(!issued.cert_der.is_empty());
        assert!(issued.cert_pem.contains("-----BEGIN CERTIFICATE-----"));
    }

    #[test]
    fn ip_string_to_bytes_ipv4() {
        let bytes = ip_string_to_bytes("192.168.1.1").unwrap();
        assert_eq!(bytes, vec![192, 168, 1, 1]);
    }

    #[test]
    fn ip_string_to_bytes_ipv6() {
        let bytes = ip_string_to_bytes("::1").unwrap();
        assert_eq!(bytes.len(), 16);
        assert_eq!(bytes[15], 1);
    }

    #[test]
    fn ip_string_to_bytes_invalid_returns_none() {
        assert!(ip_string_to_bytes("not-an-ip").is_none());
    }

    #[test]
    fn hex_encode_empty() {
        assert_eq!(hex_encode(&[]), "");
    }

    #[test]
    fn hex_encode_bytes() {
        assert_eq!(hex_encode(&[0xde, 0xad, 0xbe, 0xef]), "deadbeef");
    }

    /// Construct a ValidatedCsr with a bogus "ip" SAN value.
    /// ip_string_to_bytes("not-an-ip") returns None → AcmeError::Builder → lines 119-120 covered.
    #[test]
    fn issue_cert_invalid_ip_san_returns_builder_error() {
        let (ca_key, ca_cert_der) = make_test_ca();
        let key = BackendPrivateKey::generate_ec("P-256").unwrap();
        let spki_der = key.public_key().unwrap().spki_der().to_vec();
        let name_der = NameBuilder::new().common_name("test").build().unwrap();
        let validated_csr = ValidatedCsr {
            spki_der,
            subject_der: name_der,
            sans: vec![SanEntry {
                san_type: "ip".into(),
                value: "not-an-ip".into(),
            }],
        };
        let result = issue_certificate(IssueCertParams {
            ca_key: &ca_key,
            ca_cert_der: &ca_cert_der,
            hash_alg: "sha256",
            validity_days: 90,
            crl_url: None,
            ocsp_url: None,
            csr: &validated_csr,
            not_before_override: None,
            not_after_override: None,
        });
        let Err(err) = result else {
            panic!("expected Builder error for invalid IP SAN")
        };
        assert!(
            matches!(err, crate::error::AcmeError::Builder(_)),
            "unexpected error: {err}"
        );
    }

    /// Construct a ValidatedCsr with an "email" SAN (unsupported type).
    /// The match in issue_certificate hits the `_ => {}` arm (line 123) → continues → cert issued.
    #[test]
    fn issue_cert_unknown_san_type_is_silently_skipped() {
        let (ca_key, ca_cert_der) = make_test_ca();
        let key = BackendPrivateKey::generate_ec("P-256").unwrap();
        let spki_der = key.public_key().unwrap().spki_der().to_vec();
        let name_der = NameBuilder::new().common_name("test").build().unwrap();
        let validated_csr = ValidatedCsr {
            spki_der,
            subject_der: name_der,
            sans: vec![SanEntry {
                san_type: "email".into(),
                value: "user@example.com".into(),
            }],
        };
        // The "email" type hits `_ => {}` (line 123) — SAN is ignored, cert issued with no SAN.
        let result = issue_certificate(IssueCertParams {
            ca_key: &ca_key,
            ca_cert_der: &ca_cert_der,
            hash_alg: "sha256",
            validity_days: 90,
            crl_url: None,
            ocsp_url: None,
            csr: &validated_csr,
            not_before_override: None,
            not_after_override: None,
        });
        assert!(
            result.is_ok(),
            "unknown SAN type should be skipped silently"
        );
    }

    /// Verify that `not_before_override` is honoured: the issued cert's `not_before`
    /// field matches the requested timestamp (RFC 8555 §7.1.3).
    #[test]
    fn issue_cert_not_before_override_is_used() {
        let (ca_key, ca_cert_der) = make_test_ca();
        let (_ee_key, validated_csr) = make_test_csr("nb-override.example.com");

        // Pick a notBefore that is "now" (within the 5-minute grace window).
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let requested_nb = now; // same second — well within the grace window

        let issued = issue_certificate(IssueCertParams {
            ca_key: &ca_key,
            ca_cert_der: &ca_cert_der,
            hash_alg: "sha256",
            validity_days: 30,
            crl_url: None,
            ocsp_url: None,
            csr: &validated_csr,
            not_before_override: Some(requested_nb),
            not_after_override: None,
        })
        .unwrap();

        assert_eq!(
            issued.not_before, requested_nb,
            "issued cert notBefore must equal the requested override"
        );
        // notAfter should be notBefore + 30 days (validity_days) when no notAfter override given.
        assert_eq!(
            issued.not_after,
            requested_nb + 30 * 86400,
            "issued cert notAfter must be notBefore + validity_days * 86400"
        );
    }

    /// Verify that both `not_before_override` and `not_after_override` are honoured.
    #[test]
    fn issue_cert_both_overrides_are_used() {
        let (ca_key, ca_cert_der) = make_test_ca();
        let (_ee_key, validated_csr) = make_test_csr("both-override.example.com");

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let requested_nb = now;
        let requested_na = now + 7 * 86400; // 7-day window

        let issued = issue_certificate(IssueCertParams {
            ca_key: &ca_key,
            ca_cert_der: &ca_cert_der,
            hash_alg: "sha256",
            validity_days: 90,
            crl_url: None,
            ocsp_url: None,
            csr: &validated_csr,
            not_before_override: Some(requested_nb),
            not_after_override: Some(requested_na),
        })
        .unwrap();

        assert_eq!(
            issued.not_before, requested_nb,
            "notBefore must match the requested override"
        );
        assert_eq!(
            issued.not_after, requested_na,
            "notAfter must match the requested override"
        );
    }

    /// Verify that a `not_before_override` earlier than `now - 300` is clamped
    /// and the function still succeeds (with a warning logged).
    #[test]
    fn issue_cert_not_before_too_far_past_is_clamped() {
        let (ca_key, ca_cert_der) = make_test_ca();
        let (_ee_key, validated_csr) = make_test_csr("clamp-nb.example.com");

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        // Request a notBefore 1 hour in the past — well outside the 5-min grace window.
        let too_early = now - 3600;

        let issued = issue_certificate(IssueCertParams {
            ca_key: &ca_key,
            ca_cert_der: &ca_cert_der,
            hash_alg: "sha256",
            validity_days: 90,
            crl_url: None,
            ocsp_url: None,
            csr: &validated_csr,
            not_before_override: Some(too_early),
            not_after_override: None,
        })
        .unwrap();

        let earliest_allowed = now - 300;
        // The clamped notBefore must be >= earliest_allowed and <= now.
        assert!(
            issued.not_before >= earliest_allowed,
            "notBefore {} must be >= earliest_allowed {}",
            issued.not_before,
            earliest_allowed,
        );
        assert!(
            issued.not_after > issued.not_before,
            "notAfter must be after notBefore"
        );
    }

    /// Verify that a `not_after_override` that is not after `not_before` is replaced
    /// by the fallback (notBefore + validity_days * 86400).
    #[test]
    fn issue_cert_not_after_not_after_not_before_falls_back() {
        let (ca_key, ca_cert_der) = make_test_ca();
        let (_ee_key, validated_csr) = make_test_csr("clamp-na.example.com");

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        // notAfter == notBefore → invalid, should fall back.
        let issued = issue_certificate(IssueCertParams {
            ca_key: &ca_key,
            ca_cert_der: &ca_cert_der,
            hash_alg: "sha256",
            validity_days: 90,
            crl_url: None,
            ocsp_url: None,
            csr: &validated_csr,
            not_before_override: Some(now),
            not_after_override: Some(now), // equal, not strictly after
        })
        .unwrap();

        // Fallback: notBefore + 90 days.
        assert_eq!(
            issued.not_after,
            issued.not_before + 90 * 86400,
            "notAfter must fall back to notBefore + validity_days * 86400 when override is invalid"
        );
    }

    /// `ca.enforce_validity_cap = true` rejects issuance when validity exceeds 200 days.
    #[test]
    fn issue_with_params_rejects_overlong_validity_when_cap_enabled() {
        let (ca_key, ca_cert_der) = make_test_ca();
        let (_ee_key, validated_csr) = make_test_csr("cap-test.example.com");

        let ca = crate::state::CaState {
            id: "test".into(),
            key_type: "ec:P-256".into(),
            key: ca_key,
            cert_der: ca_cert_der,
            hash_alg: "sha256".into(),
            validity_days: 90,
            crl_url: None,
            ocsp_url: None,
            aki_bytes: vec![],
            enforce_validity_cap: true,
            crl_next_update_secs: 86400,
            caa_identities: vec![],
        };

        let params = crate::profiles::CertificateParameters {
            validity_days: 201, // exceeds 200-day cap
            hash_alg: "sha256".into(),
            key_usage_bits: 1u16 << synta_certificate::KEY_USAGE_DIGITAL_SIGNATURE,
            extended_key_usages: vec!["server_auth".into()],
            crl_url: None,
            ocsp_url: None,
            allowed_key_types: vec![],
            certificate_policies: vec![],
            issue_as_mtc: false,
            allowed_identifier_patterns: vec![],
            identifier_match_all: true,
            auth_hook: None,
            auth_hook_timeout_secs: 30,
            require_account_grant: false,
            ca_ids: vec![],
        };

        let result = issue_with_params(&ca, &validated_csr, &params, None, None);
        assert!(
            result.is_err(),
            "expected Err when enforce_validity_cap=true and validity_days=201"
        );
        match result.unwrap_err() {
            crate::error::AcmeError::BadRequest(msg) => {
                assert!(
                    msg.contains("201") || msg.contains("200"),
                    "error message should mention the day count: {msg}"
                );
            }
            other => panic!("expected BadRequest, got {other:?}"),
        }
    }

    /// `ca.enforce_validity_cap = true` allows issuance at exactly 200 days.
    #[test]
    fn issue_with_params_allows_200_days_when_cap_enabled() {
        let (ca_key, ca_cert_der) = make_test_ca();
        let (_ee_key, validated_csr) = make_test_csr("cap-ok.example.com");

        let ca = crate::state::CaState {
            id: "test".into(),
            key_type: "ec:P-256".into(),
            key: ca_key,
            cert_der: ca_cert_der,
            hash_alg: "sha256".into(),
            validity_days: 90,
            crl_url: None,
            ocsp_url: None,
            aki_bytes: vec![],
            enforce_validity_cap: true,
            crl_next_update_secs: 86400,
            caa_identities: vec![],
        };

        let params = crate::profiles::CertificateParameters {
            validity_days: 200,
            hash_alg: "sha256".into(),
            key_usage_bits: 1u16 << synta_certificate::KEY_USAGE_DIGITAL_SIGNATURE,
            extended_key_usages: vec!["server_auth".into()],
            crl_url: None,
            ocsp_url: None,
            allowed_key_types: vec![],
            certificate_policies: vec![],
            issue_as_mtc: false,
            allowed_identifier_patterns: vec![],
            identifier_match_all: true,
            auth_hook: None,
            auth_hook_timeout_secs: 30,
            require_account_grant: false,
            ca_ids: vec![],
        };

        let result = issue_with_params(&ca, &validated_csr, &params, None, None);
        assert!(
            result.is_ok(),
            "expected Ok when enforce_validity_cap=true and validity_days=200: {result:?}"
        );
    }
}
