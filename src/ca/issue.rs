//! End-entity certificate issuance.
//!
//! Takes a validated CSR and CA state and returns a DER + PEM certificate bundle.

use crate::linter::{ExtPresence, ResolvedLinterProfile, WEBPKI_PROFILE};
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
        AlgorithmId, Criticality, ExtensionPolicy, ExtensionValidator, PolicyDefinition,
        ValidationProfile, WEBPKI_PERMITTED_SIGNATURE_ALGORITHMS_WITH_PQ,
        WEBPKI_PERMITTED_SPKI_ALGORITHMS_WITH_PQ,
    },
    OwnedStore, RevocationChecks,
};

use native_ossl::util::hex_encode;

use crate::error::AcmeError;
use crate::profiles::CertificateParameters;
use crate::state::CaState;
use crate::util::{extract_ca_subject_der, unix_now};

use super::csr::{SanEntry, ValidatedCsr};
use super::init::unix_to_generalized_time;

// ── Composite ML-DSA policy extension ────────────────────────────────────────
//
// synta-x509-verification < 0.2.4 does not include the 18 composite ML-DSA
// signature OIDs (draft-ietf-lamps-pq-composite-sigs-19) in its
// WEBPKI_PERMITTED_SIGNATURE_ALGORITHMS_WITH_PQ and
// WEBPKI_PERMITTED_SPKI_ALGORITHMS_WITH_PQ constants.  We detect this at
// first use and, when necessary, build extended slices that include all 18
// composite OIDs so that pre-issuance lint passes for composite CA keys.
//
// Once synta-x509-verification ships those OIDs natively, the OnceLock
// initialiser will detect their presence and fall back to the upstream static
// slices with no allocation overhead.

static COMPOSITE_SIG_ALGS: std::sync::OnceLock<Option<Vec<AlgorithmId>>> =
    std::sync::OnceLock::new();
static COMPOSITE_SPKI_ALGS: std::sync::OnceLock<Option<Vec<AlgorithmId>>> =
    std::sync::OnceLock::new();

/// Return the permitted signature algorithm list, extended with composite ML-DSA
/// OIDs when they are absent from the upstream constant.
fn permitted_sig_algs_with_composite() -> &'static [AlgorithmId] {
    let cached = COMPOSITE_SIG_ALGS.get_or_init(|| {
        let already = WEBPKI_PERMITTED_SIGNATURE_ALGORITHMS_WITH_PQ
            .iter()
            .any(|a| a.oid == oids::MLDSA44_RSA2048_PSS_SHA256);
        if already {
            return None;
        }
        let mut algs = WEBPKI_PERMITTED_SIGNATURE_ALGORITHMS_WITH_PQ.to_vec();
        algs.extend(composite_mldsa_algorithm_ids());
        Some(algs)
    });
    match cached {
        None => WEBPKI_PERMITTED_SIGNATURE_ALGORITHMS_WITH_PQ,
        Some(v) => v.as_slice(),
    }
}

/// Return the permitted SPKI algorithm list, extended with composite ML-DSA
/// OIDs when they are absent from the upstream constant.
fn permitted_spki_algs_with_composite() -> &'static [AlgorithmId] {
    let cached = COMPOSITE_SPKI_ALGS.get_or_init(|| {
        let already = WEBPKI_PERMITTED_SPKI_ALGORITHMS_WITH_PQ
            .iter()
            .any(|a| a.oid == oids::MLDSA44_RSA2048_PSS_SHA256);
        if already {
            return None;
        }
        let mut algs = WEBPKI_PERMITTED_SPKI_ALGORITHMS_WITH_PQ.to_vec();
        algs.extend(composite_mldsa_algorithm_ids());
        Some(algs)
    });
    match cached {
        None => WEBPKI_PERMITTED_SPKI_ALGORITHMS_WITH_PQ,
        Some(v) => v.as_slice(),
    }
}

/// All 18 composite ML-DSA `AlgorithmId` entries (sub-arcs 37–54).
fn composite_mldsa_algorithm_ids() -> [AlgorithmId; 18] {
    [
        AlgorithmId {
            oid: oids::MLDSA44_RSA2048_PSS_SHA256,
        }, // 37
        AlgorithmId {
            oid: oids::MLDSA44_RSA2048_PKCS15_SHA256,
        }, // 38
        AlgorithmId {
            oid: oids::MLDSA44_ED25519_SHA512,
        }, // 39
        AlgorithmId {
            oid: oids::MLDSA44_ECDSA_P256_SHA256,
        }, // 40
        AlgorithmId {
            oid: oids::MLDSA65_RSA3072_PSS_SHA512,
        }, // 41
        AlgorithmId {
            oid: oids::MLDSA65_RSA3072_PKCS15_SHA512,
        }, // 42
        AlgorithmId {
            oid: oids::MLDSA65_RSA4096_PSS_SHA512,
        }, // 43
        AlgorithmId {
            oid: oids::MLDSA65_RSA4096_PKCS15_SHA512,
        }, // 44
        AlgorithmId {
            oid: oids::MLDSA65_ECDSA_P256_SHA512,
        }, // 45
        AlgorithmId {
            oid: oids::MLDSA65_ECDSA_P384_SHA512,
        }, // 46
        AlgorithmId {
            oid: oids::MLDSA65_ECDSA_BRAINPOOL_P256R1_SHA512,
        }, // 47
        AlgorithmId {
            oid: oids::MLDSA65_ED25519_SHA512,
        }, // 48
        AlgorithmId {
            oid: oids::MLDSA87_ECDSA_P384_SHA512,
        }, // 49
        AlgorithmId {
            oid: oids::MLDSA87_ECDSA_BRAINPOOL_P384R1_SHA512,
        }, // 50
        AlgorithmId {
            oid: oids::MLDSA87_ED448_SHAKE256,
        }, // 51
        AlgorithmId {
            oid: oids::MLDSA87_RSA3072_PSS_SHA512,
        }, // 52
        AlgorithmId {
            oid: oids::MLDSA87_RSA4096_PSS_SHA512,
        }, // 53
        AlgorithmId {
            oid: oids::MLDSA87_ECDSA_P521_SHA512,
        }, // 54
    ]
}

// ── Shared issuance helpers ──────────────────────────────────────────────────
//
// Small building blocks reused across the issuance/signing entry points below
// (issue_certificate, issue_with_params, sign_server_cert, sign_admin_cert)
// to avoid re-deriving the same serial/validity/PEM logic per function.

/// Generate a random 16-byte positive certificate serial number.
///
/// Returns the raw bytes (for `certificates.serial_number` byte storage),
/// the `synta::Integer` for the builder, and the hex-encoded string.
fn generate_random_serial() -> Result<([u8; 16], synta::Integer, String), AcmeError> {
    let mut serial_bytes = [0u8; 16];
    native_ossl::rand::Rand::fill(&mut serial_bytes)
        .map_err(|e| AcmeError::Internal(format!("random serial: {e}")))?;
    // Clear the sign bit (positive) and set the low bit so the first byte is
    // always in 0x01..0x7f — DER INTEGER must be minimal (no unnecessary leading
    // 0x00), and a zero first byte would be unnecessary when the next byte's MSB
    // is clear.  Forcing bit 0 avoids that case without reducing serial length.
    serial_bytes[0] = (serial_bytes[0] & 0x7f) | 0x01;
    let serial = synta::Integer::from_bytes(&serial_bytes);
    let serial_hex = hex_encode(serial_bytes);
    Ok((serial_bytes, serial, serial_hex))
}

/// Resolve a requested notBefore/notAfter override pair into a clamped Unix
/// timestamp window.
///
/// - Both `None`: `now` → `now + validity_days * 86400`.
/// - Only `not_before_override` set: override → `override + validity_days * 86400`.
/// - Only `not_after_override` set: `now` → override.
/// - Both set: override → override.
///
/// notBefore is clamped to `now - 300` (5-minute grace for clock skew); a
/// requested notAfter that doesn't fall strictly after the (possibly
/// clamped) notBefore falls back to `notBefore + validity_days * 86400`. A
/// warning naming `log_prefix` is logged whenever either bound is adjusted.
fn resolve_clamped_validity(
    now: i64,
    not_before_override: Option<i64>,
    not_after_override: Option<i64>,
    validity_days: u32,
    log_prefix: &str,
) -> (i64, i64) {
    let raw_not_before = not_before_override.unwrap_or(now);

    let earliest_allowed = now - 300;
    let not_before_unix = if raw_not_before < earliest_allowed {
        tracing::warn!(
            "{log_prefix}: requested notBefore {} is before now-300 ({}); clamping to {}",
            raw_not_before,
            earliest_allowed,
            earliest_allowed,
        );
        earliest_allowed
    } else {
        raw_not_before
    };

    let raw_not_after =
        not_after_override.unwrap_or(not_before_unix + validity_days as i64 * 86400);
    let not_after_unix = if raw_not_after <= not_before_unix {
        let fallback = not_before_unix + validity_days as i64 * 86400;
        tracing::warn!(
            "{log_prefix}: requested notAfter {} is not after notBefore {}; using fallback {}",
            raw_not_after,
            not_before_unix,
            fallback,
        );
        fallback
    } else {
        raw_not_after
    };

    (not_before_unix, not_after_unix)
}

/// Parse a notBefore/notAfter Unix timestamp pair into `synta_certificate::Time`.
fn parse_validity_window(
    not_before_unix: i64,
    not_after_unix: i64,
) -> Result<(synta_certificate::Time, synta_certificate::Time), AcmeError> {
    let not_before = synta_certificate::parse_time(&unix_to_generalized_time(not_before_unix))
        .map_err(|e| AcmeError::Builder(format!("notBefore: {e}")))?;
    let not_after = synta_certificate::parse_time(&unix_to_generalized_time(not_after_unix))
        .map_err(|e| AcmeError::Builder(format!("notAfter: {e}")))?;
    Ok((not_before, not_after))
}

/// Build a PEM bundle of `leaf_der` followed by `ca_der` (leaf + CA chain).
fn bundle_leaf_and_ca_pem(leaf_der: &[u8], ca_der: &[u8]) -> Result<String, AcmeError> {
    let mut pem_bytes = der_to_pem("CERTIFICATE", leaf_der);
    pem_bytes.extend_from_slice(&der_to_pem("CERTIFICATE", ca_der));
    String::from_utf8(pem_bytes)
        .map_err(|_| AcmeError::Internal("PEM contains invalid UTF-8".into()))
}

/// Sign a "bootstrap" leaf certificate (self-hosted TLS server cert, admin
/// operator client cert) with the standard extension set: BasicConstraints
/// cA=FALSE, KeyUsage digitalSignature, the given EKU, SKI/AKI, and a single
/// SubjectAlternativeName. Shared by `sign_server_cert` and
/// `sign_admin_cert`, which differ only in subject/SAN construction and EKU
/// choice — validity is `ca.validity_days` days from now, no clamping (these
/// are operator/bootstrap-issued, not subscriber certs under RFC 8555
/// §7.1.3 override rules).
fn sign_standard_leaf(
    ca: &CaState,
    ca_name_der: &[u8],
    ca_spki_der: &[u8],
    subject_der: &[u8],
    spki_der: &[u8],
    san_der: &[u8],
    eku_der: &[u8],
) -> Result<Vec<u8>, AcmeError> {
    let (_serial_bytes, serial, _serial_hex) = generate_random_serial()?;
    let now = unix_now();
    let (not_before, not_after) =
        parse_validity_window(now, now + ca.validity_days as i64 * 86400)?;

    let hasher = default_key_id_hasher();
    let bc_der = encode_basic_constraints(false, None)
        .ok_or_else(|| AcmeError::Builder("BasicConstraints".into()))?;
    let ku_der = encode_key_usage(1u16 << KEY_USAGE_DIGITAL_SIGNATURE)
        .ok_or_else(|| AcmeError::Builder("KeyUsage".into()))?;
    let ski_der =
        encode_subject_key_identifier(spki_der, KeyIdMethod::Rfc7093Method1Sha256, &hasher)
            .ok_or_else(|| AcmeError::Builder("SKI".into()))?;
    let aki_der =
        encode_authority_key_identifier(ca_spki_der, KeyIdMethod::Rfc7093Method1Sha256, &hasher)
            .ok_or_else(|| AcmeError::Builder("AKI".into()))?;

    let ca_key = ca
        .local_key()
        .ok_or_else(|| AcmeError::Internal("sign_standard_leaf requires local CA key".into()))?;
    let signer = ca_key.as_signer(&ca.hash_alg);

    CertificateBuilder::new()
        .issuer_name(ca_name_der)
        .subject_name(subject_der)
        .public_key_der(spki_der)
        .serial_number(serial)
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension_oid(oids::BASIC_CONSTRAINTS, false, &bc_der)
        .add_extension_oid(oids::KEY_USAGE, true, &ku_der)
        .add_extension_oid(oids::EXTENDED_KEY_USAGE, false, eku_der)
        .add_extension_oid(oids::SUBJECT_KEY_IDENTIFIER, false, &ski_der)
        .add_extension_oid(oids::AUTHORITY_KEY_IDENTIFIER, false, &aki_der)
        .add_extension_oid(oids::SUBJECT_ALT_NAME, false, san_der)
        .sign(&signer)
        .map_err(|e| AcmeError::Builder(format!("sign leaf cert: {e}")))
}

/// Build a SubjectAlternativeName extension DER value from a CSR's parsed
/// SANs plus any additional other-name/dns-name entries.
///
/// Returns `None` when there are no recognised SAN entries at all (caller
/// should omit the extension); otherwise `Some((der, is_critical))`, where
/// `is_critical` follows RFC 5280 §4.1.2.6 (SAN MUST be critical when the
/// subject DN is empty).
fn build_san_from_csr(
    subject_der: &[u8],
    sans: &[SanEntry],
    extra_other_names: &[Vec<u8>],
    extra_dns_names: &[String],
    log_prefix: &str,
) -> Result<Option<(Vec<u8>, bool)>, AcmeError> {
    let mut san_has_entries = false;
    let mut san_builder = SubjectAlternativeNameBuilder::new();
    for san in sans {
        match san.san_type.as_str() {
            "dns" => {
                san_builder = san_builder.dns_name(&san.value);
                san_has_entries = true;
            }
            "ip" => {
                let ip_bytes = ip_string_to_bytes(&san.value)
                    .ok_or_else(|| AcmeError::Builder(format!("invalid IP SAN: {}", san.value)))?;
                san_builder = san_builder.ip_address(&ip_bytes);
                san_has_entries = true;
            }
            "email" => {
                san_builder = san_builder.rfc822_name(&san.value);
                san_has_entries = true;
            }
            other => {
                tracing::warn!("{log_prefix}: unrecognised SAN type '{}' — skipped", other);
            }
        }
    }
    for on_der in extra_other_names {
        san_builder = san_builder.other_name(on_der);
        san_has_entries = true;
    }
    for dns in extra_dns_names {
        san_builder = san_builder.dns_name(dns);
        san_has_entries = true;
    }
    if !san_has_entries {
        if !sans.is_empty() {
            return Err(AcmeError::BadRequest(
                "all requested SAN types are unrecognised; cannot issue certificate without SANs"
                    .into(),
            ));
        }
        return Ok(None);
    }
    let san_der = san_builder
        .build()
        .map_err(|e| AcmeError::Builder(format!("SAN: {e}")))?;
    let san_critical = subject_der == [0x30, 0x00];
    Ok(Some((san_der, san_critical)))
}

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
    let (serial_bytes, serial, serial_hex) = generate_random_serial()?;

    // ── Compute validity window ───────────────────────────────────────────────
    let now = unix_now();
    let (not_before_unix, not_after_unix) = resolve_clamped_validity(
        now,
        not_before_override,
        not_after_override,
        validity_days,
        "issue_certificate",
    );
    let (not_before, not_after) = parse_validity_window(not_before_unix, not_after_unix)?;

    // ── Build extensions ──────────────────────────────────────────────────────
    let hasher = default_key_id_hasher();

    // BasicConstraints: end-entity (cA=FALSE, omitted per DER DEFAULT rule).
    let bc_der = encode_basic_constraints(false, None)
        .ok_or_else(|| AcmeError::Builder("BasicConstraints encode".into()))?;

    // KeyUsage: digitalSignature (suitable for all modern key types).
    let ku_der = encode_key_usage(1u16 << KEY_USAGE_DIGITAL_SIGNATURE)
        .ok_or_else(|| AcmeError::Builder("KeyUsage encode".into()))?;

    // ExtendedKeyUsage: emailProtection for email SANs, serverAuth otherwise.
    let has_email_san = csr.sans.iter().any(|s| s.san_type == "email");
    let eku_der = if has_email_san {
        ExtendedKeyUsageBuilder::new()
            .email_protection()
            .build()
            .map_err(|e| AcmeError::Builder(format!("EKU: {e}")))?
    } else {
        ExtendedKeyUsageBuilder::new()
            .server_auth()
            .build()
            .map_err(|e| AcmeError::Builder(format!("EKU: {e}")))?
    };

    // SubjectKeyIdentifier (from the end-entity public key in the CSR).
    let ski_der =
        encode_subject_key_identifier(&csr.spki_der, KeyIdMethod::Rfc7093Method1Sha256, &hasher)
            .ok_or_else(|| AcmeError::Builder("SKI encode".into()))?;

    // AuthorityKeyIdentifier (from the CA's public key).
    let aki_der =
        encode_authority_key_identifier(&ca_spki_der, KeyIdMethod::Rfc7093Method1Sha256, &hasher)
            .ok_or_else(|| AcmeError::Builder("AKI encode".into()))?;

    // SubjectAlternativeName: rebuild from the validated SANs.
    let san_ext = build_san_from_csr(&csr.subject_der, &csr.sans, &[], &[], "issue_certificate")?;

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
        .add_extension_oid(oids::AUTHORITY_KEY_IDENTIFIER, false, &aki_der);

    if let Some((san_der, san_critical)) = &san_ext {
        builder = builder.add_extension_oid(oids::SUBJECT_ALT_NAME, *san_critical, san_der);
    }

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

    // Pre-issuance policy lint — STAR renewal always uses the built-in WebPKI profile.
    lint_issued_cert(&cert_der, ca_cert_der, now, &WEBPKI_PROFILE, None)?;

    // ── Build PEM bundle: leaf + CA ────────────────────────────────────────────
    let cert_pem = bundle_leaf_and_ca_pem(&cert_der, ca_cert_der)?;

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
/// Parameters for [`issue_with_params`].
pub struct IssueWithParamsArgs<'a> {
    pub ca: &'a CaState,
    pub csr: &'a ValidatedCsr,
    pub params: &'a CertificateParameters,
    pub not_before_override: Option<i64>,
    pub not_after_override: Option<i64>,
    pub extra_other_names: &'a [Vec<u8>],
    pub extra_dns_names: &'a [String],
    pub linter: &'a ResolvedLinterProfile,
}

/// For orders without a `profile` field, pass
/// `CertificateParameters::from_ca(ca)` to reproduce the pre-profile
/// behaviour (`digitalSignature` KeyUsage, `serverAuth` EKU, CA validity).
pub fn issue_with_params(args: IssueWithParamsArgs<'_>) -> Result<IssuedCert, AcmeError> {
    let IssueWithParamsArgs {
        ca,
        csr,
        params,
        not_before_override,
        not_after_override,
        extra_other_names,
        extra_dns_names,
        linter,
    } = args;
    // ── Extract CA name, SPKI DER, AKI DER (cached per CA in OnceLock) ─
    let cached = match ca.cached_der.get() {
        Some(c) => c,
        None => {
            let name = extract_ca_subject_der(&ca.cert_der)?;
            let ca_key = ca.local_key().ok_or_else(|| {
                AcmeError::Internal("issue_with_params called on non-local CA".into())
            })?;
            let spki = ca_key
                .public_key()
                .map_err(|e| AcmeError::Crypto(format!("CA public key: {e}")))?
                .spki_der()
                .to_vec();
            let hasher = default_key_id_hasher();
            let aki =
                encode_authority_key_identifier(&spki, KeyIdMethod::Rfc7093Method1Sha256, &hasher)
                    .ok_or_else(|| AcmeError::Builder("AKI encode".into()))?;
            let val = crate::state::CaCachedDer {
                name_der: name,
                spki_der: spki,
                aki_der: aki,
            };
            let _ = ca.cached_der.set(val);
            ca.cached_der.get().unwrap()
        }
    };
    let (ca_name_der, _ca_spki_der, ca_aki_der) =
        (&cached.name_der, &cached.spki_der, &cached.aki_der);

    // ── Random serial ────────────────────────────────────────────────────────
    let (serial_bytes, serial, serial_hex) = generate_random_serial()?;

    // ── Validity window ──────────────────────────────────────────────────────
    let now = unix_now();
    let (not_before_unix, not_after_unix) = resolve_clamped_validity(
        now,
        not_before_override,
        not_after_override,
        params.validity_days,
        "issue_with_params",
    );
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

    let (not_before, not_after) = parse_validity_window(not_before_unix, not_after_unix)?;

    // ── Extensions ───────────────────────────────────────────────────────────
    let hasher = default_key_id_hasher();

    static BC_DER: std::sync::OnceLock<Vec<u8>> = std::sync::OnceLock::new();
    let bc_der = BC_DER
        .get_or_init(|| encode_basic_constraints(false, None).expect("BasicConstraints encode"))
        .clone();

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
    let aki_der = ca_aki_der;

    let san_ext = build_san_from_csr(
        &csr.subject_der,
        &csr.sans,
        extra_other_names,
        extra_dns_names,
        "issue_with_params",
    )?;

    // ── Assemble certificate ─────────────────────────────────────────────────
    let ca_key = ca
        .local_key()
        .ok_or_else(|| AcmeError::Internal("issue_with_params called on non-local CA".into()))?;
    let signer = ca_key.as_signer(&params.hash_alg);

    let mut builder = CertificateBuilder::new()
        .issuer_name(ca_name_der)
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
        .add_extension_oid(oids::AUTHORITY_KEY_IDENTIFIER, false, aki_der);

    if let Some((san_der, san_critical)) = &san_ext {
        builder = builder.add_extension_oid(oids::SUBJECT_ALT_NAME, *san_critical, san_der);
    }

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

    // Pre-issuance policy lint using the resolved linter profile.
    lint_issued_cert(&cert_der, &ca.cert_der, now, linter, Some(&ca.lint_store))?;

    let cert_pem = bundle_leaf_and_ca_pem(&cert_der, &ca.cert_der)?;

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
    let ca_name_der = extract_ca_subject_der(&ca.cert_der)?;

    let spki_der = server_key
        .public_key()
        .map_err(|e| AcmeError::Crypto(format!("server public key: {e}")))?
        .spki_der()
        .to_vec();

    let ca_key = ca
        .local_key()
        .ok_or_else(|| AcmeError::Internal("sign_server_cert requires local CA key".into()))?;
    let ca_spki_der = ca_key
        .public_key()
        .map_err(|e| AcmeError::Crypto(format!("CA public key for AKI: {e}")))?
        .spki_der()
        .to_vec();

    // Subject: CN=server_name.
    let subject_der = NameBuilder::new()
        .common_name(server_name)
        .build()
        .map_err(|e| AcmeError::Builder(format!("subject name: {e}")))?;

    let eku_der = ExtendedKeyUsageBuilder::new()
        .server_auth()
        .build()
        .map_err(|e| AcmeError::Builder(format!("EKU: {e}")))?;

    let mut san_builder = SubjectAlternativeNameBuilder::new();
    san_builder = if let Some(ip_bytes) = ip_string_to_bytes(server_name) {
        san_builder.ip_address(&ip_bytes)
    } else {
        san_builder.dns_name(server_name)
    };
    let san_der = san_builder
        .build()
        .map_err(|e| AcmeError::Builder(format!("SAN: {e}")))?;

    sign_standard_leaf(
        ca,
        &ca_name_der,
        &ca_spki_der,
        &subject_der,
        &spki_der,
        &san_der,
        &eku_der,
    )
}

/// SAN type for an admin operator certificate, derived from prefix parsing.
#[derive(Debug)]
pub(crate) enum OperatorSanKind {
    Dns(String),
    Email(String),
    Ip(Vec<u8>),
    Uri(String),
    /// Reuse the Subject DN as a directoryName SAN.
    DirectoryName,
}

/// Parse an operator name with an optional type prefix into a (CN, SAN kind).
///
/// Supported prefixes: `dns:`, `email:`, `ip:`, `uri:`, `dn:`.
/// A bare name (no prefix) defaults to `DirectoryName`.
pub(crate) fn parse_operator_san(name: &str) -> Result<(&str, OperatorSanKind), AcmeError> {
    if name.is_empty() {
        return Err(AcmeError::Builder("operator name must not be empty".into()));
    }
    if let Some(val) = name.strip_prefix("dns:") {
        if val.is_empty() {
            return Err(AcmeError::Builder("empty value after 'dns:' prefix".into()));
        }
        Ok((val, OperatorSanKind::Dns(val.to_owned())))
    } else if let Some(val) = name.strip_prefix("email:") {
        if val.is_empty() {
            return Err(AcmeError::Builder(
                "empty value after 'email:' prefix".into(),
            ));
        }
        Ok((val, OperatorSanKind::Email(val.to_owned())))
    } else if let Some(val) = name.strip_prefix("ip:") {
        if val.is_empty() {
            return Err(AcmeError::Builder("empty value after 'ip:' prefix".into()));
        }
        let bytes = ip_string_to_bytes(val)
            .ok_or_else(|| AcmeError::Builder(format!("invalid IP in operator name: {val}")))?;
        Ok((val, OperatorSanKind::Ip(bytes)))
    } else if let Some(val) = name.strip_prefix("uri:") {
        if val.is_empty() {
            return Err(AcmeError::Builder("empty value after 'uri:' prefix".into()));
        }
        Ok((val, OperatorSanKind::Uri(val.to_owned())))
    } else if let Some(val) = name.strip_prefix("dn:") {
        if val.is_empty() {
            return Err(AcmeError::Builder("empty value after 'dn:' prefix".into()));
        }
        Ok((val, OperatorSanKind::DirectoryName))
    } else {
        Ok((name, OperatorSanKind::DirectoryName))
    }
}

/// Issue a CA-signed client certificate for an admin operator.
///
/// Produces a certificate with `digitalSignature` KeyUsage and `clientAuth` EKU,
/// suitable for mTLS client authentication against the admin listener.
/// The SHA-256 fingerprint of the returned DER is the credential stored in
/// the `operators` table.
///
/// `operator_name` may carry a type prefix (`dns:`, `email:`, `ip:`, `uri:`,
/// `dn:`) to select the SubjectAltName type.  A bare name defaults to a
/// directoryName SAN built from the Subject DN.
pub fn sign_admin_cert(
    operator_name: &str,
    operator_key: &synta_certificate::BackendPrivateKey,
    ca: &CaState,
) -> Result<Vec<u8>, AcmeError> {
    let (cn, san_kind) = parse_operator_san(operator_name)?;

    let ca_name_der = extract_ca_subject_der(&ca.cert_der)?;

    let spki_der = operator_key
        .public_key()
        .map_err(|e| AcmeError::Crypto(format!("operator public key: {e}")))?
        .spki_der()
        .to_vec();

    let ca_key = ca
        .local_key()
        .ok_or_else(|| AcmeError::Internal("sign_admin_cert requires local CA key".into()))?;
    let ca_spki_der = ca_key
        .public_key()
        .map_err(|e| AcmeError::Crypto(format!("CA public key for AKI: {e}")))?
        .spki_der()
        .to_vec();

    let subject_der = NameBuilder::new()
        .common_name(cn)
        .build()
        .map_err(|e| AcmeError::Builder(format!("subject name: {e}")))?;

    let eku_der = ExtendedKeyUsageBuilder::new()
        .client_auth()
        .build()
        .map_err(|e| AcmeError::Builder(format!("EKU: {e}")))?;

    let san_der = match &san_kind {
        OperatorSanKind::Dns(name) => SubjectAlternativeNameBuilder::new().dns_name(name),
        OperatorSanKind::Email(addr) => SubjectAlternativeNameBuilder::new().rfc822_name(addr),
        OperatorSanKind::Ip(bytes) => SubjectAlternativeNameBuilder::new().ip_address(bytes),
        OperatorSanKind::Uri(uri) => SubjectAlternativeNameBuilder::new().uri(uri),
        OperatorSanKind::DirectoryName => {
            SubjectAlternativeNameBuilder::new().directory_name(&subject_der)
        }
    }
    .build()
    .map_err(|e| AcmeError::Builder(format!("SAN: {e}")))?;

    sign_standard_leaf(
        ca,
        &ca_name_der,
        &ca_spki_der,
        &subject_der,
        &spki_der,
        &san_der,
        &eku_der,
    )
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
fn lint_issued_cert(
    cert_der: &[u8],
    ca_cert_der: &[u8],
    now: i64,
    profile: &ResolvedLinterProfile,
    store_cache: Option<&std::sync::OnceLock<std::sync::Arc<OwnedStore>>>,
) -> Result<(), AcmeError> {
    let store = if let Some(cache) = store_cache {
        match cache.get() {
            Some(s) => s.clone(),
            None => {
                let s = std::sync::Arc::new(
                    OwnedStore::try_new(std::iter::once(ca_cert_der))
                        .map_err(|e| AcmeError::Internal(format!("lint: parse CA cert: {e}")))?,
                );
                let _ = cache.set(s);
                cache.get().unwrap().clone()
            }
        }
    } else {
        std::sync::Arc::new(
            OwnedStore::try_new(std::iter::once(ca_cert_der))
                .map_err(|e| AcmeError::Internal(format!("lint: parse CA cert: {e}")))?,
        )
    };

    // Parse the just-issued leaf.
    let mut dec = Decoder::new(cert_der, Encoding::Der);
    let cert: Certificate = dec
        .decode()
        .map_err(|e| AcmeError::Internal(format!("lint: parse cert: {e}")))?;
    let leaf = VerificationCertificate::new(cert, cert_der);

    // Start from the PQ-extended server policy and apply the linter profile.
    let mut policy = PolicyDefinition::new_server_pq(OpensslSignatureVerifier, vec![], now);

    // Base validation profile (WebPki or Rfc5280).
    policy.profile = profile.base;

    // Profiles may use non-serverAuth EKUs — always skip the EKU check.
    policy.extended_key_usage = None;

    // Algorithm lists from the linter profile.  The composite-extension helper
    // is applied on top when the profile includes PQ algorithms.
    resolve_permitted_algorithms(&mut policy, profile);

    // RSA modulus floor.
    policy.minimum_rsa_modulus = profile.minimum_rsa_bits;

    // Per-extension policy overrides.
    apply_ext_presence(
        &mut policy.ee_extension_policy.subject_alt_name,
        profile.san,
    );
    apply_ext_presence(
        &mut policy.ee_extension_policy.name_constraints,
        profile.name_constraints,
    );

    verify_and_map_mtc_fallback(
        &store,
        &leaf,
        &policy,
        &[cert_der, ca_cert_der],
        "pre-issuance lint failed",
        AcmeError::Internal,
    )
}

/// Apply an [`ExtPresence`] override to an [`ExtensionValidator`] field,
/// preserving any inner content validator already attached.
fn apply_ext_presence<B: synta_x509_verification::ops::CryptoOps>(
    validator: &mut ExtensionValidator<'_, B>,
    presence: ExtPresence,
) {
    let inner = match std::mem::replace(validator, ExtensionValidator::NotPresent) {
        ExtensionValidator::Present { validator: v, .. }
        | ExtensionValidator::MaybePresent { validator: v, .. } => v,
        ExtensionValidator::NotPresent => None,
    };
    *validator = match presence {
        ExtPresence::Required => ExtensionValidator::Present {
            criticality: Criticality::Agnostic,
            validator: inner,
        },
        ExtPresence::Optional => ExtensionValidator::MaybePresent {
            criticality: Criticality::Agnostic,
            validator: inner,
        },
        ExtPresence::Absent => ExtensionValidator::NotPresent,
    };
}

/// Set `policy.permitted_spki_algorithms`/`permitted_signature_algorithms`
/// from the linter profile, extending with composite ML-DSA OIDs on top when
/// the profile requests them (see the `permitted_*_algs_with_composite`
/// helpers above).
fn resolve_permitted_algorithms<B: synta_x509_verification::ops::CryptoOps>(
    policy: &mut PolicyDefinition<'_, B>,
    profile: &ResolvedLinterProfile,
) {
    policy.permitted_spki_algorithms = if profile.include_composite_algs {
        permitted_spki_algs_with_composite()
    } else {
        profile.spki_algs
    };
    policy.permitted_signature_algorithms = if profile.include_composite_algs {
        permitted_sig_algs_with_composite()
    } else {
        profile.sig_algs
    };
}

/// Run `store.verify(...)` against `leaf` and, on failure, apply the
/// MTC-extension fallback shared by `check_is_ca_cert`, `lint_issued_cert`,
/// and `lint_issued_ca_cert`: an MTC-flavoured extension error is retried via
/// `validate_mtc_ca_extensions` (with `mtc_check_ders` as the cert set to
/// check — leaf alone for `check_is_ca_cert`, leaf + issuing CA for the two
/// lint functions) before giving up. `err_ctx` names the failure in the
/// final error message; `err_ctor` selects the `AcmeError` variant
/// (`Internal` for lint failures, `BadRequest` for the CA-cert-shape check).
fn verify_and_map_mtc_fallback<B: synta_x509_verification::ops::CryptoOps>(
    store: &OwnedStore,
    leaf: &VerificationCertificate<'_>,
    policy: &PolicyDefinition<'_, B>,
    mtc_check_ders: &[&[u8]],
    err_ctx: &str,
    err_ctor: fn(String) -> AcmeError,
) -> Result<(), AcmeError> {
    let result = store
        .verify(leaf, &[], policy, RevocationChecks::default())
        .map(|_| ());
    match result {
        Ok(()) => Ok(()),
        Err(e) => {
            let msg = e.to_string();
            if akamu_client::tls_verify::is_mtc_extension_error(&msg) {
                akamu_client::tls_verify::validate_mtc_ca_extensions(mtc_check_ders.iter().copied())
                    .map_err(|mtc_err| err_ctor(format!("{err_ctx}: {mtc_err}")))
            } else {
                Err(err_ctor(format!("{err_ctx}: {e}")))
            }
        }
    }
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

    verify_and_map_mtc_fallback(
        &store,
        &leaf,
        &policy,
        &[cert_der],
        "subject certificate is not a valid CA certificate",
        AcmeError::BadRequest,
    )
}

/// Lint a just-issued CA certificate by re-verifying it against the signing CA.
///
/// Analogous to `lint_issued_cert` but for CA certificates.
///
/// Always forces `ValidationProfile::Rfc5280` regardless of `profile.base` —
/// WebPKI rejects `cA=TRUE` on the "leaf" position, so a WebPKI-base profile
/// would cause every cross-cert to fail.  The configurable fields (SAN,
/// name-constraints, algorithms, RSA modulus) still apply.
fn lint_issued_ca_cert(
    cert_der: &[u8],
    ca_cert_der: &[u8],
    now: i64,
    profile: &ResolvedLinterProfile,
) -> Result<(), AcmeError> {
    use synta_certificate::OpensslSignatureVerifier;

    let store = OwnedStore::try_new(std::iter::once(ca_cert_der))
        .map_err(|e| AcmeError::Internal(format!("ca lint: parse CA cert: {e}")))?;

    let mut dec = Decoder::new(cert_der, Encoding::Der);
    let cert: Certificate = dec
        .decode()
        .map_err(|e| AcmeError::Internal(format!("ca lint: parse cert: {e}")))?;
    let leaf = VerificationCertificate::new(cert, cert_der);

    let mut policy = PolicyDefinition::new_server_pq(OpensslSignatureVerifier, vec![], now);
    // CA certs always use RFC 5280 regardless of the linter profile base.
    policy.profile = ValidationProfile::Rfc5280;
    policy.extended_key_usage = None;
    policy.ee_extension_policy = ExtensionPolicy::new_default_webpki_ca();

    // Apply configurable fields from the profile.
    policy.minimum_rsa_modulus = profile.minimum_rsa_bits;
    resolve_permitted_algorithms(&mut policy, profile);
    // CA certificates do not carry SAN — force Optional regardless of profile.
    apply_ext_presence(
        &mut policy.ee_extension_policy.subject_alt_name,
        ExtPresence::Optional,
    );
    apply_ext_presence(
        &mut policy.ee_extension_policy.name_constraints,
        profile.name_constraints,
    );

    verify_and_map_mtc_fallback(
        &store,
        &leaf,
        &policy,
        &[cert_der, ca_cert_der],
        "cross-cert pre-issuance lint failed",
        AcmeError::Internal,
    )
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
    linter: &ResolvedLinterProfile,
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
    let issuer_key = issuer_ca
        .local_key()
        .ok_or_else(|| AcmeError::Internal("issue_ca_cert requires local issuer key".into()))?;
    let issuer_spki_der = issuer_key
        .public_key()
        .map_err(|e| AcmeError::Crypto(format!("issuer CA public key: {e}")))?
        .spki_der()
        .to_vec();

    // Issuer Name from issuer CA cert.
    let issuer_name_der = extract_ca_subject_der(&issuer_ca.cert_der)?;

    // Generate a random 16-byte positive serial.
    let (_serial_bytes, serial, serial_hex) = generate_random_serial()?;

    // Validity window: now to now + validity_years * 365.25 days.
    let now = unix_now();
    let not_before_unix = now;
    let not_after_unix =
        now + (validity_years as i64) * 365 * 86400 + (validity_years as i64) * 21600;

    let (not_before_t, not_after_t) = parse_validity_window(not_before_unix, not_after_unix)?;

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

    let signer = issuer_key.as_signer(&issuer_ca.hash_alg);

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

    lint_issued_ca_cert(&cert_der, &issuer_ca.cert_der, not_before_unix, linter)?;

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

    use std::sync::Arc;

    use native_ossl::util::hex_encode;

    use super::{
        check_is_ca_cert, ip_string_to_bytes, issue_ca_cert, issue_certificate, issue_with_params,
        parse_operator_san, permitted_sig_algs_with_composite, permitted_spki_algs_with_composite,
        sign_admin_cert, sign_server_cert, IssueCertParams, IssueWithParamsArgs, OperatorSanKind,
    };
    use crate::ca::csr::{validate_csr, SanEntry, ValidatedCsr};
    use crate::linter::WEBPKI_PROFILE;
    use crate::state::MtcState;
    use synta_certificate::oids;

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
        assert_eq!(hex_encode([]), "");
    }

    #[test]
    fn hex_encode_bytes() {
        assert_eq!(hex_encode([0xde, 0xad, 0xbe, 0xef]), "deadbeef");
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
            ca_cert: false,
            key_type: None,
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

    #[test]
    fn issue_cert_with_email_san() {
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
            ca_cert: false,
            key_type: None,
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
        assert!(
            result.is_ok(),
            "email SAN type should produce a valid certificate: {result:?}"
        );
        // Verify the issued certificate contains the RFC822Name SAN.
        let issued = result.unwrap();
        let cert = synta_certificate::Certificate::from_der(&issued.cert_der).unwrap();
        let sans = cert.subject_alt_names();
        assert!(
            sans.iter().any(
                |(tag, content)| *tag == synta_certificate::general_name::RFC822_NAME
                    && content == b"user@example.com"
            ),
            "certificate should contain rfc822Name SAN 'user@example.com'"
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
            signing: crate::state::SigningBackend::Local {
                key: Box::new(ca_key),
            },
            cert_der: ca_cert_der,
            hash_alg: "sha256".into(),
            validity_days: 90,
            crl_url: None,
            ocsp_url: None,
            aki_bytes: vec![],
            enforce_validity_cap: true,
            crl_next_update_secs: 86400,
            caa_identities: vec![],
            mtc: Arc::new(MtcState::disabled()),
            default_linter: None,
            cached_der: std::sync::OnceLock::new(),
            lint_store: std::sync::OnceLock::new(),
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
            kpn_san_templates: vec![],
            ms_upn_san_template: None,
            inject_account_kpn: false,
            trust_jwks_urls: vec![],
            dogtag_profile_id: None,
            linter: None,
        };

        let result = issue_with_params(IssueWithParamsArgs {
            ca: &ca,
            csr: &validated_csr,
            params: &params,
            not_before_override: None,
            not_after_override: None,
            extra_other_names: &[],
            extra_dns_names: &[],
            linter: &WEBPKI_PROFILE,
        });
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
            signing: crate::state::SigningBackend::Local {
                key: Box::new(ca_key),
            },
            cert_der: ca_cert_der,
            hash_alg: "sha256".into(),
            validity_days: 90,
            crl_url: None,
            ocsp_url: None,
            aki_bytes: vec![],
            enforce_validity_cap: true,
            crl_next_update_secs: 86400,
            caa_identities: vec![],
            mtc: Arc::new(MtcState::disabled()),
            default_linter: None,
            cached_der: std::sync::OnceLock::new(),
            lint_store: std::sync::OnceLock::new(),
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
            kpn_san_templates: vec![],
            ms_upn_san_template: None,
            inject_account_kpn: false,
            trust_jwks_urls: vec![],
            dogtag_profile_id: None,
            linter: None,
        };

        let result = issue_with_params(IssueWithParamsArgs {
            ca: &ca,
            csr: &validated_csr,
            params: &params,
            not_before_override: None,
            not_after_override: None,
            extra_other_names: &[],
            extra_dns_names: &[],
            linter: &WEBPKI_PROFILE,
        });
        assert!(
            result.is_ok(),
            "expected Ok when enforce_validity_cap=true and validity_days=200: {result:?}"
        );
    }

    /// RFC 5280 §4.1.2.6: when the subject DN is empty the SAN MUST be critical.
    ///
    /// Regression test for the bug where issue_with_params always emitted a
    /// non-critical SAN regardless of the subject DN, causing the pre-issuance
    /// linter to reject the certificate with "SubjectAltName must be critical
    /// when subject is empty".
    #[test]
    fn issue_with_params_empty_subject_produces_critical_san() {
        let (_ca_key, _ca_cert_der) = make_test_ca();
        let ee_key = BackendPrivateKey::generate_ec("P-256").unwrap();
        let spki_der = ee_key.public_key().unwrap().spki_der().to_vec();

        // Empty subject DN: NameBuilder with no fields → DER SEQUENCE { } = 0x30 0x00
        let empty_subject_der = NameBuilder::new().build().unwrap();
        let san_der = SubjectAlternativeNameBuilder::new()
            .dns_name("empty-subject.example.com")
            .build()
            .unwrap();

        let signer = ee_key.as_signer("sha256");
        let csr_der = CsrBuilder::new()
            .subject_name(&empty_subject_der)
            .public_key_der(&spki_der)
            .add_extension_oid(oids::SUBJECT_ALT_NAME, true, &san_der)
            .sign(&signer)
            .unwrap();

        let allowed = &[("dns", "empty-subject.example.com")];
        let validated_csr = validate_csr(&csr_der, allowed).unwrap();

        let ca = make_test_ca_state();
        let params = crate::profiles::CertificateParameters::from_ca(&ca);

        let issued = issue_with_params(IssueWithParamsArgs {
            ca: &ca,
            csr: &validated_csr,
            params: &params,
            not_before_override: None,
            not_after_override: None,
            extra_other_names: &[],
            extra_dns_names: &[],
            linter: &WEBPKI_PROFILE,
        })
        .expect("issue_with_params must succeed for empty-subject CSR with critical SAN");

        // Verify the SAN extension is marked critical by scanning the raw DER.
        // In X.509 DER a critical extension has the structure:
        //   SEQUENCE { OID, BOOLEAN TRUE (01 01 ff), OCTET STRING }
        // A non-critical extension omits the BOOLEAN.
        // OID 2.5.29.17 (SubjectAltName) encodes as 06 03 55 1d 11.
        let san_oid: &[u8] = &[0x06, 0x03, 0x55, 0x1d, 0x11];
        let critical_bool: &[u8] = &[0x01, 0x01, 0xff];
        let mut san_is_critical = false;
        for i in 0..issued
            .cert_der
            .len()
            .saturating_sub(san_oid.len() + critical_bool.len())
        {
            if issued.cert_der[i..].starts_with(san_oid)
                && issued.cert_der[i + san_oid.len()..].starts_with(critical_bool)
            {
                san_is_critical = true;
                break;
            }
        }
        assert!(
            san_is_critical,
            "SAN must be critical when subject DN is empty (RFC 5280 §4.1.2.6)"
        );
    }

    /// The composite policy helpers must include all 18 composite ML-DSA OIDs in
    /// `permitted_signature_algorithms` and `permitted_spki_algorithms`.
    #[test]
    fn permitted_algs_with_composite_include_all_18_composite_oids() {
        let sig_algs = permitted_sig_algs_with_composite();
        let spki_algs = permitted_spki_algs_with_composite();

        for (sub_arc, oid) in [
            (37u32, oids::MLDSA44_RSA2048_PSS_SHA256),
            (38, oids::MLDSA44_RSA2048_PKCS15_SHA256),
            (39, oids::MLDSA44_ED25519_SHA512),
            (40, oids::MLDSA44_ECDSA_P256_SHA256),
            (41, oids::MLDSA65_RSA3072_PSS_SHA512),
            (42, oids::MLDSA65_RSA3072_PKCS15_SHA512),
            (43, oids::MLDSA65_RSA4096_PSS_SHA512),
            (44, oids::MLDSA65_RSA4096_PKCS15_SHA512),
            (45, oids::MLDSA65_ECDSA_P256_SHA512),
            (46, oids::MLDSA65_ECDSA_P384_SHA512),
            (47, oids::MLDSA65_ECDSA_BRAINPOOL_P256R1_SHA512),
            (48, oids::MLDSA65_ED25519_SHA512),
            (49, oids::MLDSA87_ECDSA_P384_SHA512),
            (50, oids::MLDSA87_ECDSA_BRAINPOOL_P384R1_SHA512),
            (51, oids::MLDSA87_ED448_SHAKE256),
            (52, oids::MLDSA87_RSA3072_PSS_SHA512),
            (53, oids::MLDSA87_RSA4096_PSS_SHA512),
            (54, oids::MLDSA87_ECDSA_P521_SHA512),
        ] {
            assert!(
                sig_algs.iter().any(|a| a.oid == oid),
                "composite sig alg sub-arc {sub_arc} missing from permitted_signature_algorithms"
            );
            assert!(
                spki_algs.iter().any(|a| a.oid == oid),
                "composite sig alg sub-arc {sub_arc} missing from permitted_spki_algorithms"
            );
        }
    }

    // ── parse_operator_san unit tests ──────────────────────────────────

    #[test]
    fn parse_operator_san_bare_name_defaults_to_directory() {
        let (cn, kind) = parse_operator_san("admin").unwrap();
        assert_eq!(cn, "admin");
        assert!(matches!(kind, OperatorSanKind::DirectoryName));
    }

    #[test]
    fn parse_operator_san_dn_prefix() {
        let (cn, kind) = parse_operator_san("dn:Operator").unwrap();
        assert_eq!(cn, "Operator");
        assert!(matches!(kind, OperatorSanKind::DirectoryName));
    }

    #[test]
    fn parse_operator_san_dns_prefix() {
        let (cn, kind) = parse_operator_san("dns:foo.example.com").unwrap();
        assert_eq!(cn, "foo.example.com");
        assert!(matches!(kind, OperatorSanKind::Dns(ref s) if s == "foo.example.com"));
    }

    #[test]
    fn parse_operator_san_email_prefix() {
        let (cn, kind) = parse_operator_san("email:a@b.com").unwrap();
        assert_eq!(cn, "a@b.com");
        assert!(matches!(kind, OperatorSanKind::Email(ref s) if s == "a@b.com"));
    }

    #[test]
    fn parse_operator_san_ip_v4() {
        let (cn, kind) = parse_operator_san("ip:192.168.1.1").unwrap();
        assert_eq!(cn, "192.168.1.1");
        assert!(matches!(kind, OperatorSanKind::Ip(ref b) if b == &[192, 168, 1, 1]));
    }

    #[test]
    fn parse_operator_san_ip_v6() {
        let (cn, kind) = parse_operator_san("ip:::1").unwrap();
        assert_eq!(cn, "::1");
        match kind {
            OperatorSanKind::Ip(ref b) => {
                assert_eq!(b.len(), 16);
                assert_eq!(b[15], 1);
            }
            _ => panic!("expected Ip variant"),
        }
    }

    #[test]
    fn parse_operator_san_ip_invalid() {
        let result = parse_operator_san("ip:not-an-ip");
        assert!(result.is_err());
    }

    #[test]
    fn parse_operator_san_uri_prefix() {
        let (cn, kind) = parse_operator_san("uri:https://example.com/admin").unwrap();
        assert_eq!(cn, "https://example.com/admin");
        assert!(matches!(kind, OperatorSanKind::Uri(ref s) if s == "https://example.com/admin"));
    }

    // ── sign_admin_cert integration tests ─────────────────────────────

    fn make_test_ca_state() -> crate::state::CaState {
        let (ca_key, ca_cert_der) = make_test_ca();
        crate::state::CaState {
            id: "test".into(),
            key_type: "ec:P-256".into(),
            signing: crate::state::SigningBackend::Local {
                key: Box::new(ca_key),
            },
            cert_der: ca_cert_der,
            hash_alg: "sha256".into(),
            validity_days: 90,
            crl_url: None,
            ocsp_url: None,
            aki_bytes: vec![],
            enforce_validity_cap: false,
            crl_next_update_secs: 86400,
            caa_identities: vec![],
            mtc: Arc::new(MtcState::disabled()),
            default_linter: None,
            cached_der: std::sync::OnceLock::new(),
            lint_store: std::sync::OnceLock::new(),
        }
    }

    #[test]
    fn admin_cert_default_passes_client_verification() {
        let ca = make_test_ca_state();
        let op_key = BackendPrivateKey::generate_ec("P-256").unwrap();
        let cert_der = sign_admin_cert("admin", &op_key, &ca).unwrap();

        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        let ca_parsed: Certificate = Decoder::new(&ca.cert_der, Encoding::Der).decode().unwrap();
        let ca_vcert = VerificationCertificate::new(ca_parsed, &ca.cert_der);
        let store = Store::new(vec![ca_vcert]);

        let leaf_parsed: Certificate = Decoder::new(&cert_der, Encoding::Der).decode().unwrap();
        let leaf_vcert = VerificationCertificate::new(leaf_parsed, &cert_der);

        let policy = PolicyDefinition::new_client(OpensslSignatureVerifier, now_unix);

        verify(
            &leaf_vcert,
            &[],
            &policy,
            &store,
            RevocationChecks::default(),
        )
        .expect("admin cert with directoryName SAN must pass client verification");
    }

    #[test]
    fn sign_server_cert_dns_name_passes_server_verification() {
        let ca = make_test_ca_state();
        let server_key = BackendPrivateKey::generate_ec("P-256").unwrap();
        let domain = "bootstrap.example.com";
        let cert_der = sign_server_cert(domain, &server_key, &ca).unwrap();

        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        let ca_parsed: Certificate = Decoder::new(&ca.cert_der, Encoding::Der).decode().unwrap();
        let ca_vcert = VerificationCertificate::new(ca_parsed, &ca.cert_der);
        let store = Store::new(vec![ca_vcert]);

        let leaf_parsed: Certificate = Decoder::new(&cert_der, Encoding::Der).decode().unwrap();
        let leaf_vcert = VerificationCertificate::new(leaf_parsed, &cert_der);

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
        .expect("bootstrap server cert must pass serverAuth chain verification");
    }

    #[test]
    fn sign_server_cert_ip_address_produces_ip_san() {
        let ca = make_test_ca_state();
        let server_key = BackendPrivateKey::generate_ec("P-256").unwrap();
        let cert_der = sign_server_cert("127.0.0.1", &server_key, &ca).unwrap();
        let cert = synta_certificate::Certificate::from_der(&cert_der).unwrap();
        let sans = cert.subject_alt_names();
        assert!(
            sans.iter().any(
                |(tag, val)| *tag == synta_certificate::general_name::IP_ADDRESS
                    && val == &[127, 0, 0, 1]
            ),
            "expected iPAddress SAN 127.0.0.1, got: {sans:?}"
        );
    }

    #[test]
    fn admin_cert_dns_prefix_has_dns_san() {
        let ca = make_test_ca_state();
        let op_key = BackendPrivateKey::generate_ec("P-256").unwrap();
        let cert_der = sign_admin_cert("dns:admin.example.com", &op_key, &ca).unwrap();
        let cert = synta_certificate::Certificate::from_der(&cert_der).unwrap();
        let sans = cert.subject_alt_names();
        assert!(
            sans.iter().any(
                |(tag, val)| *tag == synta_certificate::general_name::DNS_NAME
                    && val == b"admin.example.com"
            ),
            "expected dNSName SAN 'admin.example.com', got: {sans:?}"
        );
    }

    #[test]
    fn admin_cert_email_prefix_has_rfc822_san() {
        let ca = make_test_ca_state();
        let op_key = BackendPrivateKey::generate_ec("P-256").unwrap();
        let cert_der = sign_admin_cert("email:admin@example.com", &op_key, &ca).unwrap();
        let cert = synta_certificate::Certificate::from_der(&cert_der).unwrap();
        let sans = cert.subject_alt_names();
        assert!(
            sans.iter().any(
                |(tag, val)| *tag == synta_certificate::general_name::RFC822_NAME
                    && val == b"admin@example.com"
            ),
            "expected rfc822Name SAN 'admin@example.com', got: {sans:?}"
        );
    }

    #[test]
    fn admin_cert_ip_prefix_has_ip_san() {
        let ca = make_test_ca_state();
        let op_key = BackendPrivateKey::generate_ec("P-256").unwrap();
        let cert_der = sign_admin_cert("ip:127.0.0.1", &op_key, &ca).unwrap();
        let cert = synta_certificate::Certificate::from_der(&cert_der).unwrap();
        let sans = cert.subject_alt_names();
        assert!(
            sans.iter().any(
                |(tag, val)| *tag == synta_certificate::general_name::IP_ADDRESS
                    && val == &[127, 0, 0, 1]
            ),
            "expected iPAddress SAN 127.0.0.1, got: {sans:?}"
        );
    }

    #[test]
    fn admin_cert_uri_prefix_has_uri_san() {
        let ca = make_test_ca_state();
        let op_key = BackendPrivateKey::generate_ec("P-256").unwrap();
        let cert_der = sign_admin_cert("uri:https://example.com/admin", &op_key, &ca).unwrap();
        let cert = synta_certificate::Certificate::from_der(&cert_der).unwrap();
        let sans = cert.subject_alt_names();
        assert!(
            sans.iter()
                .any(|(tag, val)| *tag == synta_certificate::general_name::URI
                    && val == b"https://example.com/admin"),
            "expected URI SAN 'https://example.com/admin', got: {sans:?}"
        );
    }

    #[test]
    fn admin_cert_dn_prefix_has_directory_name_san() {
        let ca = make_test_ca_state();
        let op_key = BackendPrivateKey::generate_ec("P-256").unwrap();
        let cert_der = sign_admin_cert("dn:Operator", &op_key, &ca).unwrap();
        let cert = synta_certificate::Certificate::from_der(&cert_der).unwrap();
        let sans = cert.subject_alt_names();
        assert!(
            sans.iter()
                .any(|(tag, _)| *tag == synta_certificate::general_name::DIRECTORY_NAME),
            "expected directoryName SAN, got: {sans:?}"
        );
    }

    #[test]
    fn admin_cert_invalid_ip_returns_error() {
        let ca = make_test_ca_state();
        let op_key = BackendPrivateKey::generate_ec("P-256").unwrap();
        let result = sign_admin_cert("ip:not-an-ip", &op_key, &ca);
        let Err(err) = result else {
            panic!("expected error for invalid IP")
        };
        assert!(
            matches!(err, crate::error::AcmeError::Builder(ref msg) if msg.contains("invalid IP")),
            "unexpected error: {err}"
        );
    }

    // ── parse_operator_san empty-value edge cases ─────────────────────

    #[test]
    fn parse_operator_san_empty_string_rejected() {
        let result = parse_operator_san("");
        assert!(result.is_err());
    }

    #[test]
    fn parse_operator_san_empty_dns_rejected() {
        let result = parse_operator_san("dns:");
        assert!(result.is_err());
    }

    #[test]
    fn parse_operator_san_empty_email_rejected() {
        let result = parse_operator_san("email:");
        assert!(result.is_err());
    }

    #[test]
    fn parse_operator_san_empty_ip_rejected() {
        let result = parse_operator_san("ip:");
        assert!(result.is_err());
    }

    #[test]
    fn parse_operator_san_empty_uri_rejected() {
        let result = parse_operator_san("uri:");
        assert!(result.is_err());
    }

    #[test]
    fn parse_operator_san_empty_dn_rejected() {
        let result = parse_operator_san("dn:");
        assert!(result.is_err());
    }

    // ── CN verification in issued certificate ─────────────────────────

    #[test]
    fn admin_cert_dns_prefix_cn_is_stripped() {
        let ca = make_test_ca_state();
        let op_key = BackendPrivateKey::generate_ec("P-256").unwrap();
        let cert_der = sign_admin_cert("dns:admin.example.com", &op_key, &ca).unwrap();
        let mut dec = Decoder::new(&cert_der, Encoding::Der);
        let cert: Certificate = dec.decode().unwrap();
        let subject_dn =
            synta_certificate::name::format_dn(cert.tbs_certificate.subject.as_bytes());
        assert!(
            subject_dn.contains("admin.example.com"),
            "CN must be the stripped value, not the prefixed name; got: {subject_dn}"
        );
        assert!(
            !subject_dn.contains("dns:"),
            "CN must not contain the prefix; got: {subject_dn}"
        );
    }

    // ── IPv6 integration test ─────────────────────────────────────────

    #[test]
    fn admin_cert_ipv6_has_16_byte_san() {
        let ca = make_test_ca_state();
        let op_key = BackendPrivateKey::generate_ec("P-256").unwrap();
        let cert_der = sign_admin_cert("ip:::1", &op_key, &ca).unwrap();
        let cert = synta_certificate::Certificate::from_der(&cert_der).unwrap();
        let sans = cert.subject_alt_names();
        assert!(
            sans.iter().any(
                |(tag, val)| *tag == synta_certificate::general_name::IP_ADDRESS
                    && val.len() == 16
                    && val[15] == 1
            ),
            "expected 16-byte iPAddress SAN for ::1, got: {sans:?}"
        );
    }

    // ── Chain verification for DNS SAN type ───────────────────────────

    #[test]
    fn admin_cert_dns_passes_client_verification() {
        let ca = make_test_ca_state();
        let op_key = BackendPrivateKey::generate_ec("P-256").unwrap();
        let cert_der = sign_admin_cert("dns:admin.example.com", &op_key, &ca).unwrap();

        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        let ca_parsed: Certificate = Decoder::new(&ca.cert_der, Encoding::Der).decode().unwrap();
        let ca_vcert = VerificationCertificate::new(ca_parsed, &ca.cert_der);
        let store = Store::new(vec![ca_vcert]);

        let leaf_parsed: Certificate = Decoder::new(&cert_der, Encoding::Der).decode().unwrap();
        let leaf_vcert = VerificationCertificate::new(leaf_parsed, &cert_der);

        let policy = PolicyDefinition::new_client(OpensslSignatureVerifier, now_unix);

        verify(
            &leaf_vcert,
            &[],
            &policy,
            &store,
            RevocationChecks::default(),
        )
        .expect("admin cert with dNSName SAN must pass client verification");
    }

    #[test]
    fn check_is_ca_cert_accepts_a_real_ca_cert() {
        let (_ca_key, ca_cert_der) = make_test_ca();
        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        check_is_ca_cert(&ca_cert_der, now_unix)
            .expect("a real self-signed CA cert (cA=TRUE) must be accepted");
    }

    #[test]
    fn check_is_ca_cert_rejects_a_non_ca_cert() {
        let (ca_key, ca_cert_der) = make_test_ca();
        let domain = "not-a-ca.example.com";
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

        let err = check_is_ca_cert(&issued.cert_der, issued.not_before).unwrap_err();
        assert!(
            matches!(err, crate::error::AcmeError::BadRequest(_)),
            "expected BadRequest, got {err:?}"
        );
    }

    #[test]
    fn issue_ca_cert_end_to_end() {
        let issuer_ca = make_test_ca_state();
        // A second, independent CA cert stands in as the "subject" whose SPKI
        // and Subject DN get cross-certified — issue_ca_cert only reads those
        // two fields out of it, it doesn't require the subject cert to chain
        // to the issuer.
        let (_subject_key, subject_cert_der) = make_test_ca();

        let issued = issue_ca_cert(&issuer_ca, &subject_cert_der, 5, &WEBPKI_PROFILE).unwrap();

        assert!(!issued.serial_hex.is_empty());
        assert!(issued.cert_pem.contains("-----BEGIN CERTIFICATE-----"));
        assert!(issued.not_after > issued.not_before);

        // The cross-cert must verify as a CA cert issued by issuer_ca.
        let ca_parsed: Certificate = Decoder::new(&issuer_ca.cert_der, Encoding::Der)
            .decode()
            .unwrap();
        let ca_vcert = VerificationCertificate::new(ca_parsed, &issuer_ca.cert_der);
        let store = Store::new(vec![ca_vcert]);

        let leaf_parsed: Certificate = Decoder::new(&issued.cert_der, Encoding::Der)
            .decode()
            .unwrap();
        let leaf_vcert = VerificationCertificate::new(leaf_parsed, &issued.cert_der);

        let mut policy =
            PolicyDefinition::new_server_pq(OpensslSignatureVerifier, vec![], issued.not_before);
        policy.profile = synta_x509_verification::policy::ValidationProfile::Rfc5280;
        policy.extended_key_usage = None;
        policy.ee_extension_policy =
            synta_x509_verification::policy::ExtensionPolicy::new_default_webpki_ca();
        verify(
            &leaf_vcert,
            &[],
            &policy,
            &store,
            RevocationChecks::default(),
        )
        .expect("cross-cert must verify as a CA cert issued by issuer_ca");
    }
}
