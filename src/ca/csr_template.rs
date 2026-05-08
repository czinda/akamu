//! RFC 9115 CSR template validation.
//!
//! Types: [`CsrTemplate`], [`KeyTypeSpec`], [`FieldSpec`], [`DnTemplate`],
//! [`ExtensionsTemplate`].
//! Entry point: [`validate_csr_against_template`].

use serde::Deserialize;
use std::collections::BTreeSet;
use synta::traits::Encode;
use synta::{Decoder, Encoder, Encoding};
use synta_certificate::{
    csr::CertificationRequest, decode_extensions, key_usage_bit, oids, parse_name_attrs,
    BackendPublicKey, KeyUsage, KEY_USAGE_C_RLSIGN, KEY_USAGE_DATA_ENCIPHERMENT,
    KEY_USAGE_DECIPHER_ONLY, KEY_USAGE_DIGITAL_SIGNATURE, KEY_USAGE_ENCIPHER_ONLY,
    KEY_USAGE_KEY_AGREEMENT, KEY_USAGE_KEY_CERT_SIGN, KEY_USAGE_KEY_ENCIPHERMENT,
    KEY_USAGE_NON_REPUDIATION,
};

use crate::error::AcmeError;

// ── Template types ────────────────────────────────────────────────────────────

/// RFC 9115 §4 CSR template — constrains key type, subject DN, and extensions.
#[derive(Debug, Clone, Deserialize)]
pub struct CsrTemplate {
    #[serde(rename = "keyTypes")]
    pub key_types: Vec<KeyTypeSpec>,
    #[serde(default)]
    pub subject: DnTemplate,
    #[serde(default)]
    pub extensions: ExtensionsTemplate,
}

/// A single permitted key algorithm entry in the template's `keyTypes` array.
#[derive(Debug, Clone, Deserialize)]
pub struct KeyTypeSpec {
    /// `"EC"` or `"RSA"`.
    #[serde(rename = "type")]
    pub key_type: String,
    /// For EC keys: `"P-256"`, `"P-384"`, or `"P-521"`.  Absent means any curve.
    pub curve: Option<String>,
    /// For RSA keys: required modulus size in bits (e.g. `2048`).  Absent means any size.
    #[serde(rename = "keySize")]
    pub key_size: Option<u32>,
}

/// A constraint on one DN attribute in the template.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum FieldSpec {
    /// Value must equal this exact string.
    Literal(String),
    /// Field must be present but may have any value (`{}` in JSON).
    MandatoryWildcard,
    /// Field may be absent or present with any value (`null` in JSON).
    OptionalWildcard,
}

impl<'de> Deserialize<'de> for FieldSpec {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let v: serde_json::Value = Deserialize::deserialize(d)?;
        match v {
            serde_json::Value::String(s) => Ok(FieldSpec::Literal(s)),
            serde_json::Value::Object(m) if m.is_empty() => Ok(FieldSpec::MandatoryWildcard),
            serde_json::Value::Null => Ok(FieldSpec::OptionalWildcard),
            _ => Err(serde::de::Error::custom(
                "field spec must be a string, {}, or null",
            )),
        }
    }
}

/// Subject DN field constraints from the template.
///
/// A `None` field means "absent from template" → that attribute MUST NOT appear
/// in the CSR (when at least one field is constrained; otherwise the whole
/// subject is unconstrained).
#[derive(Debug, Clone, Deserialize, Default)]
pub struct DnTemplate {
    #[serde(rename = "commonName")]
    pub common_name: Option<FieldSpec>,
    pub country: Option<FieldSpec>,
    pub organization: Option<FieldSpec>,
    #[serde(rename = "organizationalUnit")]
    pub organizational_unit: Option<FieldSpec>,
    pub locality: Option<FieldSpec>,
    #[serde(rename = "stateOrProvince")]
    pub state_or_province: Option<FieldSpec>,
    #[serde(rename = "emailAddress")]
    pub email_address: Option<FieldSpec>,
}

impl DnTemplate {
    fn is_unconstrained(&self) -> bool {
        self.common_name.is_none()
            && self.country.is_none()
            && self.organization.is_none()
            && self.organizational_unit.is_none()
            && self.locality.is_none()
            && self.state_or_province.is_none()
            && self.email_address.is_none()
    }
}

/// Whether the `subjectAltName` extension is required or optional in the CSR.
///
/// Deserialises from JSON:
/// - `{}` → `Required` (SAN must be present)
/// - `null` → `Optional` (SAN may be present)
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SanSpec {
    Required,
    Optional,
}

impl<'de> Deserialize<'de> for SanSpec {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let v: serde_json::Value = Deserialize::deserialize(d)?;
        match v {
            serde_json::Value::Object(m) if m.is_empty() => Ok(SanSpec::Required),
            serde_json::Value::Null => Ok(SanSpec::Optional),
            _ => Err(serde::de::Error::custom(
                "subjectAltName spec must be {} (required) or null (optional)",
            )),
        }
    }
}

/// Extension constraints from the template.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct ExtensionsTemplate {
    /// `{}` → SAN must be present; `null` → SAN may be present; absent → SAN not allowed.
    #[serde(rename = "subjectAltName")]
    pub subject_alt_name: Option<SanSpec>,
    /// Exact set of KeyUsage bit names the CSR must contain (e.g. `["digitalSignature"]`).
    #[serde(rename = "keyUsage")]
    pub key_usage: Option<Vec<String>>,
    /// CSR's EKU OIDs must be a subset of these dotted-decimal OID strings.
    #[serde(rename = "extendedKeyUsage")]
    pub extended_key_usage: Option<Vec<String>>,
}

impl ExtensionsTemplate {
    fn is_unconstrained(&self) -> bool {
        self.subject_alt_name.is_none()
            && self.key_usage.is_none()
            && self.extended_key_usage.is_none()
    }
}

// ── Public validation entry point ─────────────────────────────────────────────

/// Validate a DER-encoded PKCS #10 CSR against an RFC 9115 CSR template.
///
/// Verifies the CSR self-signature before checking template constraints.
/// SAN content is NOT validated here — callers must also call [`crate::ca::csr::validate_csr`]
/// to ensure SANs match the authorised order identifiers.
///
/// Returns `Ok(())` if all template constraints are satisfied.
/// Returns `Err(AcmeError::BadCsr(...))` with the first violation found.
pub fn validate_csr_against_template(
    csr_der: &[u8],
    template: &CsrTemplate,
) -> Result<(), AcmeError> {
    if template.key_types.is_empty() {
        return Err(AcmeError::BadCsr("template keyTypes is empty".into()));
    }

    let mut decoder = Decoder::new(csr_der, Encoding::Der);
    let csr: CertificationRequest = decoder
        .decode()
        .map_err(|e| AcmeError::BadCsr(format!("CSR DER decoding failed: {e}")))?;

    verify_csr_signature(&csr)?;
    validate_key_type(&csr, &template.key_types)?;
    validate_subject(&csr, &template.subject)?;
    validate_extensions(&csr, &template.extensions)?;

    Ok(())
}

/// Verify the PKCS #10 self-signature so callers cannot spoof the SPKI.
fn verify_csr_signature(csr: &CertificationRequest) -> Result<(), AcmeError> {
    let mut enc = Encoder::new(Encoding::Der);
    csr.certification_request_info
        .encode(&mut enc)
        .map_err(|e| AcmeError::BadCsr(format!("CRI encode: {e}")))?;
    let cri_der = enc
        .finish()
        .map_err(|e| AcmeError::BadCsr(format!("CRI finish: {e}")))?;

    let mut enc = Encoder::new(Encoding::Der);
    csr.signature_algorithm
        .encode(&mut enc)
        .map_err(|e| AcmeError::BadCsr(format!("sig alg encode: {e}")))?;
    let sig_alg_der = enc
        .finish()
        .map_err(|e| AcmeError::BadCsr(format!("sig alg finish: {e}")))?;

    let mut enc = Encoder::new(Encoding::Der);
    csr.certification_request_info
        .subject_pkinfo
        .encode(&mut enc)
        .map_err(|e| AcmeError::BadCsr(format!("SPKI encode: {e}")))?;
    let spki_der = enc
        .finish()
        .map_err(|e| AcmeError::BadCsr(format!("SPKI finish: {e}")))?;

    let sig_bytes = csr.signature.as_bytes();
    BackendPublicKey::from_spki_der(spki_der)
        .verify_signature(&cri_der, &sig_alg_der, sig_bytes)
        .map_err(|e| AcmeError::BadCsr(format!("signature invalid: {e}")))
}

// ── Key type validation ───────────────────────────────────────────────────────

fn validate_key_type(
    csr: &CertificationRequest,
    key_types: &[KeyTypeSpec],
) -> Result<(), AcmeError> {
    let mut enc = Encoder::new(Encoding::Der);
    csr.certification_request_info
        .subject_pkinfo
        .encode(&mut enc)
        .map_err(|e| AcmeError::BadCsr(format!("SPKI encode: {e}")))?;
    let spki_der = enc
        .finish()
        .map_err(|e| AcmeError::BadCsr(format!("SPKI finish: {e}")))?;

    let pub_key = BackendPublicKey::from_spki_der(spki_der);
    let csr_key_type = pub_key.key_type(); // "rsa", "ec", "ed25519", …
    let bit_size = pub_key.key_bit_size();
    let ec_curve = pub_key.ec_curve_name().ok().flatten(); // "P-256", "P-384", "P-521"

    for spec in key_types {
        if key_type_matches(spec, csr_key_type, bit_size, ec_curve) {
            return Ok(());
        }
    }

    Err(AcmeError::BadCsr(format!(
        "CSR key type '{csr_key_type}' does not match template keyTypes"
    )))
}

fn key_type_matches(
    spec: &KeyTypeSpec,
    csr_type: &str,
    bit_size: Option<i64>,
    ec_curve: Option<&str>,
) -> bool {
    match spec.key_type.as_str() {
        "EC" | "ECDSA" if csr_type == "ec" => match &spec.curve {
            None => true,
            Some(template_curve) => ec_curve.is_some_and(|c| c == template_curve),
        },
        "RSA" if csr_type == "rsa" => match spec.key_size {
            None => true,
            // Use checked conversion to avoid silent wrap on malformed SPKI.
            Some(template_bits) => {
                bit_size.is_some_and(|b| u32::try_from(b).is_ok_and(|n| n == template_bits))
            }
        },
        _ => false,
    }
}

// ── Subject DN validation ─────────────────────────────────────────────────────

fn check_dn_field(
    attrs: &[(String, String)],
    oid: &str,
    spec: Option<&FieldSpec>,
) -> Result<(), AcmeError> {
    let values: Vec<&str> = attrs
        .iter()
        .filter(|(o, _)| o == oid)
        .map(|(_, v)| v.as_str())
        .collect();

    match (spec, values.as_slice()) {
        (None, [_, ..]) => Err(AcmeError::BadCsr(format!(
            "CSR subject contains field {oid} not permitted by template"
        ))),
        (Some(FieldSpec::MandatoryWildcard), []) => Err(AcmeError::BadCsr(format!(
            "CSR subject missing required field {oid}"
        ))),
        (Some(FieldSpec::Literal(expected)), []) => Err(AcmeError::BadCsr(format!(
            "CSR subject missing required field {oid}='{expected}'"
        ))),
        (Some(FieldSpec::Literal(expected)), vals) => {
            // Multi-valued attributes are rejected for literal fields to prevent bypass.
            if vals.len() > 1 {
                return Err(AcmeError::BadCsr(format!(
                    "CSR subject field {oid}: multiple values not permitted"
                )));
            }
            if vals[0] != expected {
                return Err(AcmeError::BadCsr(format!(
                    "CSR subject field {oid}: expected '{expected}', got '{}'",
                    vals[0]
                )));
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

/// Selector type: maps a DN OID string to the corresponding [`FieldSpec`] in a [`DnTemplate`].
type DnFieldSelector = fn(&DnTemplate) -> Option<&FieldSpec>;

/// Standard X.500 DN attribute OIDs checked against template fields.
const DN_OID_MAP: &[(&str, DnFieldSelector)] = &[
    ("2.5.4.3", |t: &DnTemplate| t.common_name.as_ref()),
    ("2.5.4.6", |t: &DnTemplate| t.country.as_ref()),
    ("2.5.4.10", |t: &DnTemplate| t.organization.as_ref()),
    ("2.5.4.11", |t: &DnTemplate| t.organizational_unit.as_ref()),
    ("2.5.4.7", |t: &DnTemplate| t.locality.as_ref()),
    ("2.5.4.8", |t: &DnTemplate| t.state_or_province.as_ref()),
    ("1.2.840.113549.1.9.1", |t: &DnTemplate| {
        t.email_address.as_ref()
    }),
];

fn validate_subject(csr: &CertificationRequest, template: &DnTemplate) -> Result<(), AcmeError> {
    if template.is_unconstrained() {
        return Ok(());
    }

    let mut enc = Encoder::new(Encoding::Der);
    csr.certification_request_info
        .subject
        .encode(&mut enc)
        .map_err(|e| AcmeError::BadCsr(format!("subject encode: {e}")))?;
    let subject_der = enc
        .finish()
        .map_err(|e| AcmeError::BadCsr(format!("subject finish: {e}")))?;

    let attrs = parse_name_attrs(&subject_der);

    // Check each known attribute against its template constraint.
    for (oid, get_spec) in DN_OID_MAP {
        check_dn_field(&attrs, oid, get_spec(template))?;
    }

    // Reject any attribute OID present in the CSR but not in the template.
    for (oid, _) in &attrs {
        if !DN_OID_MAP.iter().any(|(known, _)| *known == oid.as_str()) {
            return Err(AcmeError::BadCsr(format!(
                "CSR subject contains unknown field {oid} not recognised by template"
            )));
        }
    }

    Ok(())
}

// ── Extension validation ──────────────────────────────────────────────────────

/// Extracted CSR extension (OID arc components + raw extension value bytes).
struct CsrExt {
    oid_arcs: Vec<u32>,
    value_der: Vec<u8>,
}

fn extract_exts(csr: &CertificationRequest) -> Vec<CsrExt> {
    let Some(attributes) = &csr.certification_request_info.attributes else {
        return Vec::new();
    };
    for attr in attributes.elements() {
        if attr.attr_type.components() == oids::PKCS9_EXTENSION_REQUEST {
            if let Some(raw) = attr.attr_values.elements().first() {
                return decode_extensions(raw.0)
                    .into_iter()
                    .map(|ext| CsrExt {
                        oid_arcs: ext.extn_id.components().to_vec(),
                        value_der: ext.extn_value.as_bytes().to_vec(),
                    })
                    .collect();
            }
        }
    }
    Vec::new()
}

fn find_ext<'a>(exts: &'a [CsrExt], oid: &[u32]) -> Option<&'a [u8]> {
    exts.iter()
        .find(|e| e.oid_arcs.as_slice() == oid)
        .map(|e| e.value_der.as_slice())
}

fn validate_extensions(
    csr: &CertificationRequest,
    template: &ExtensionsTemplate,
) -> Result<(), AcmeError> {
    if template.is_unconstrained() {
        return Ok(());
    }

    let exts = extract_exts(csr);

    // Build allowed extension OID set from template.
    let mut allowed: Vec<&[u32]> = Vec::new();
    if template.subject_alt_name.is_some() {
        allowed.push(oids::SUBJECT_ALT_NAME);
    }
    if template.key_usage.is_some() {
        allowed.push(oids::KEY_USAGE);
    }
    if template.extended_key_usage.is_some() {
        allowed.push(oids::EXTENDED_KEY_USAGE);
    }

    // Reject CSR extensions not present in the template.
    for ext in &exts {
        if !allowed.contains(&ext.oid_arcs.as_slice()) {
            let dotted = ext
                .oid_arcs
                .iter()
                .map(|n| n.to_string())
                .collect::<Vec<_>>()
                .join(".");
            return Err(AcmeError::BadCsr(format!(
                "CSR contains extension {dotted} not permitted by template"
            )));
        }
    }

    // subjectAltName: mandatory when SanSpec::Required.
    if let Some(SanSpec::Required) = &template.subject_alt_name {
        if find_ext(&exts, oids::SUBJECT_ALT_NAME).is_none() {
            return Err(AcmeError::BadCsr(
                "CSR missing required subjectAltName extension".into(),
            ));
        }
    }

    // keyUsage: must match exactly.
    if let Some(template_ku) = &template.key_usage {
        match find_ext(&exts, oids::KEY_USAGE) {
            None => {
                return Err(AcmeError::BadCsr(
                    "CSR missing required keyUsage extension".into(),
                ))
            }
            Some(ku_der) => validate_key_usage(ku_der, template_ku)?,
        }
    }

    // extendedKeyUsage: CSR must be a subset of template list.
    if let Some(template_eku) = &template.extended_key_usage {
        match find_ext(&exts, oids::EXTENDED_KEY_USAGE) {
            None => {
                return Err(AcmeError::BadCsr(
                    "CSR missing required extendedKeyUsage extension".into(),
                ))
            }
            Some(eku_der) => validate_eku(eku_der, template_eku)?,
        }
    }

    Ok(())
}

/// Named-bit index → canonical RFC 5280 name.
const KU_BITS: &[(usize, &str)] = &[
    (KEY_USAGE_DIGITAL_SIGNATURE, "digitalSignature"),
    (KEY_USAGE_NON_REPUDIATION, "contentCommitment"),
    (KEY_USAGE_KEY_ENCIPHERMENT, "keyEncipherment"),
    (KEY_USAGE_DATA_ENCIPHERMENT, "dataEncipherment"),
    (KEY_USAGE_KEY_AGREEMENT, "keyAgreement"),
    (KEY_USAGE_KEY_CERT_SIGN, "keyCertSign"),
    (KEY_USAGE_C_RLSIGN, "cRLSign"),
    (KEY_USAGE_ENCIPHER_ONLY, "encipherOnly"),
    (KEY_USAGE_DECIPHER_ONLY, "decipherOnly"),
];

fn validate_key_usage(ext_der: &[u8], template_names: &[String]) -> Result<(), AcmeError> {
    let mut decoder = Decoder::new(ext_der, Encoding::Der);
    let ku: KeyUsage = decoder
        .decode()
        .map_err(|e| AcmeError::BadCsr(format!("keyUsage decode: {e}")))?;

    // Resolve template names → bit indices (accept "nonRepudiation" as alias).
    let mut template_bits = BTreeSet::new();
    for name in template_names {
        let canonical = if name == "nonRepudiation" {
            "contentCommitment"
        } else {
            name.as_str()
        };
        let bit = KU_BITS
            .iter()
            .find(|(_, n)| *n == canonical)
            .map(|(b, _)| *b)
            .ok_or_else(|| AcmeError::BadCsr(format!("unknown keyUsage name '{name}'")))?;
        template_bits.insert(bit);
    }

    // Collect CSR bit indices.
    let csr_bits: BTreeSet<usize> = KU_BITS
        .iter()
        .filter(|(idx, _)| key_usage_bit(&ku, *idx))
        .map(|(idx, _)| *idx)
        .collect();

    if csr_bits != template_bits {
        return Err(AcmeError::BadCsr(
            "CSR keyUsage bits do not exactly match template".into(),
        ));
    }

    Ok(())
}

fn validate_eku(ext_der: &[u8], template_oids: &[String]) -> Result<(), AcmeError> {
    let mut decoder = Decoder::new(ext_der, Encoding::Der);
    let eku: Vec<synta::ObjectIdentifier> = decoder
        .decode()
        .map_err(|e| AcmeError::BadCsr(format!("extendedKeyUsage decode: {e}")))?;

    for oid in &eku {
        let oid_str = oid.to_string();
        if !template_oids.iter().any(|t| t == &oid_str) {
            return Err(AcmeError::BadCsr(format!(
                "CSR extendedKeyUsage contains OID {oid_str} not permitted by template"
            )));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use synta_certificate::{
        encode_key_usage, BackendPrivateKey, CsrBuilder, ExtendedKeyUsageBuilder, NameBuilder,
        PrivateKey as _, SubjectAlternativeNameBuilder, KEY_USAGE_DIGITAL_SIGNATURE,
        KEY_USAGE_KEY_ENCIPHERMENT,
    };

    fn ec_p256_key() -> BackendPrivateKey {
        BackendPrivateKey::generate_ec("P-256").unwrap()
    }

    fn rsa_2048_key() -> BackendPrivateKey {
        BackendPrivateKey::generate_rsa(2048, 65537).unwrap()
    }

    fn make_csr(key: &BackendPrivateKey, domain: &str) -> Vec<u8> {
        let spki_der = key.public_key().unwrap().spki_der().to_vec();
        let name_der = NameBuilder::new().common_name(domain).build().unwrap();
        let san_der = SubjectAlternativeNameBuilder::new()
            .dns_name(domain)
            .build()
            .unwrap();
        let signer = key.as_signer("sha256");
        CsrBuilder::new()
            .subject_name(&name_der)
            .public_key_der(&spki_der)
            .add_extension_oid(oids::SUBJECT_ALT_NAME, false, &san_der)
            .sign(&signer)
            .unwrap()
    }

    fn default_ec_template() -> CsrTemplate {
        serde_json::from_str(
            r#"{"keyTypes":[{"type":"EC","curve":"P-256"}],"subject":{},"extensions":{"subjectAltName":{}}}"#,
        )
        .unwrap()
    }

    // ── Key type tests ────────────────────────────────────────────────────────

    #[test]
    fn ec_p256_matches_ec_p256_template() {
        let key = ec_p256_key();
        let csr = make_csr(&key, "example.com");
        let tpl = default_ec_template();
        assert!(validate_csr_against_template(&csr, &tpl).is_ok());
    }

    #[test]
    fn rsa_key_rejected_by_ec_template() {
        let key = rsa_2048_key();
        let csr = make_csr(&key, "example.com");
        let tpl = default_ec_template();
        let err = validate_csr_against_template(&csr, &tpl).unwrap_err();
        match err {
            AcmeError::BadCsr(msg) => assert!(msg.contains("key type"), "msg: {msg}"),
            other => panic!("expected BadCsr, got {other:?}"),
        }
    }

    #[test]
    fn rsa_2048_matches_rsa_2048_template() {
        let key = rsa_2048_key();
        let csr = make_csr(&key, "example.com");
        let tpl: CsrTemplate = serde_json::from_str(
            r#"{"keyTypes":[{"type":"RSA","keySize":2048}],"subject":{},"extensions":{"subjectAltName":{}}}"#,
        )
        .unwrap();
        assert!(validate_csr_against_template(&csr, &tpl).is_ok());
    }

    #[test]
    fn rsa_2048_rejected_by_rsa_4096_template() {
        let key = rsa_2048_key();
        let csr = make_csr(&key, "example.com");
        let tpl: CsrTemplate = serde_json::from_str(
            r#"{"keyTypes":[{"type":"RSA","keySize":4096}],"subject":{},"extensions":{"subjectAltName":{}}}"#,
        )
        .unwrap();
        let err = validate_csr_against_template(&csr, &tpl).unwrap_err();
        match err {
            AcmeError::BadCsr(msg) => assert!(msg.contains("key type"), "msg: {msg}"),
            other => panic!("expected BadCsr, got {other:?}"),
        }
    }

    #[test]
    fn multi_key_type_template_matches_either() {
        let ec_key = ec_p256_key();
        let rsa_key = rsa_2048_key();
        let tpl: CsrTemplate = serde_json::from_str(
            r#"{"keyTypes":[{"type":"EC","curve":"P-256"},{"type":"RSA","keySize":2048}],"subject":{},"extensions":{"subjectAltName":{}}}"#,
        )
        .unwrap();
        assert!(validate_csr_against_template(&make_csr(&ec_key, "a.com"), &tpl).is_ok());
        assert!(validate_csr_against_template(&make_csr(&rsa_key, "a.com"), &tpl).is_ok());
    }

    #[test]
    fn empty_key_types_returns_error() {
        let key = ec_p256_key();
        let csr = make_csr(&key, "example.com");
        let tpl: CsrTemplate = serde_json::from_str(
            r#"{"keyTypes":[],"subject":{},"extensions":{"subjectAltName":{}}}"#,
        )
        .unwrap();
        assert!(validate_csr_against_template(&csr, &tpl).is_err());
    }

    // ── Subject DN tests ──────────────────────────────────────────────────────

    #[test]
    fn unconstrained_subject_accepts_any_dn() {
        // "subject":{} → no constraints → any subject DN ok.
        let key = ec_p256_key();
        let spki_der = key.public_key().unwrap().spki_der().to_vec();
        let name_der = NameBuilder::new()
            .common_name("test.example")
            .build()
            .unwrap();
        let san_der = SubjectAlternativeNameBuilder::new()
            .dns_name("test.example")
            .build()
            .unwrap();
        let signer = key.as_signer("sha256");
        let csr = CsrBuilder::new()
            .subject_name(&name_der)
            .public_key_der(&spki_der)
            .add_extension_oid(oids::SUBJECT_ALT_NAME, false, &san_der)
            .sign(&signer)
            .unwrap();
        let tpl = default_ec_template();
        assert!(validate_csr_against_template(&csr, &tpl).is_ok());
    }

    #[test]
    fn literal_cn_match_passes() {
        let key = ec_p256_key();
        let spki_der = key.public_key().unwrap().spki_der().to_vec();
        let name_der = NameBuilder::new()
            .common_name("fixed.example")
            .build()
            .unwrap();
        let san_der = SubjectAlternativeNameBuilder::new()
            .dns_name("fixed.example")
            .build()
            .unwrap();
        let signer = key.as_signer("sha256");
        let csr = CsrBuilder::new()
            .subject_name(&name_der)
            .public_key_der(&spki_der)
            .add_extension_oid(oids::SUBJECT_ALT_NAME, false, &san_der)
            .sign(&signer)
            .unwrap();
        let tpl: CsrTemplate = serde_json::from_str(
            r#"{"keyTypes":[{"type":"EC","curve":"P-256"}],"subject":{"commonName":"fixed.example"},"extensions":{"subjectAltName":{}}}"#,
        )
        .unwrap();
        assert!(validate_csr_against_template(&csr, &tpl).is_ok());
    }

    #[test]
    fn literal_cn_mismatch_rejected() {
        let key = ec_p256_key();
        let spki_der = key.public_key().unwrap().spki_der().to_vec();
        let name_der = NameBuilder::new()
            .common_name("wrong.example")
            .build()
            .unwrap();
        let san_der = SubjectAlternativeNameBuilder::new()
            .dns_name("wrong.example")
            .build()
            .unwrap();
        let signer = key.as_signer("sha256");
        let csr = CsrBuilder::new()
            .subject_name(&name_der)
            .public_key_der(&spki_der)
            .add_extension_oid(oids::SUBJECT_ALT_NAME, false, &san_der)
            .sign(&signer)
            .unwrap();
        let tpl: CsrTemplate = serde_json::from_str(
            r#"{"keyTypes":[{"type":"EC","curve":"P-256"}],"subject":{"commonName":"fixed.example"},"extensions":{"subjectAltName":{}}}"#,
        )
        .unwrap();
        let err = validate_csr_against_template(&csr, &tpl).unwrap_err();
        match err {
            AcmeError::BadCsr(msg) => {
                assert!(msg.contains("expected 'fixed.example'"), "msg: {msg}")
            }
            other => panic!("expected BadCsr, got {other:?}"),
        }
    }

    #[test]
    fn mandatory_wildcard_cn_present_passes() {
        let key = ec_p256_key();
        let csr = make_csr(&key, "any.example");
        let tpl: CsrTemplate = serde_json::from_str(
            r#"{"keyTypes":[{"type":"EC","curve":"P-256"}],"subject":{"commonName":{}},"extensions":{"subjectAltName":{}}}"#,
        )
        .unwrap();
        assert!(validate_csr_against_template(&csr, &tpl).is_ok());
    }

    #[test]
    fn mandatory_wildcard_cn_absent_rejected() {
        let key = ec_p256_key();
        let spki_der = key.public_key().unwrap().spki_der().to_vec();
        // Build a CSR with an empty subject name.
        let name_der = NameBuilder::new().build().unwrap();
        let san_der = SubjectAlternativeNameBuilder::new()
            .dns_name("no-cn.example")
            .build()
            .unwrap();
        let signer = key.as_signer("sha256");
        let csr = CsrBuilder::new()
            .subject_name(&name_der)
            .public_key_der(&spki_der)
            .add_extension_oid(oids::SUBJECT_ALT_NAME, false, &san_der)
            .sign(&signer)
            .unwrap();
        let tpl: CsrTemplate = serde_json::from_str(
            r#"{"keyTypes":[{"type":"EC","curve":"P-256"}],"subject":{"commonName":{}},"extensions":{"subjectAltName":{}}}"#,
        )
        .unwrap();
        let err = validate_csr_against_template(&csr, &tpl).unwrap_err();
        match err {
            AcmeError::BadCsr(msg) => assert!(msg.contains("missing required field"), "msg: {msg}"),
            other => panic!("expected BadCsr, got {other:?}"),
        }
    }

    #[test]
    fn disallowed_dn_field_rejected() {
        let key = ec_p256_key();
        let csr = make_csr(&key, "blocked.example"); // CSR has CN via make_csr
                                                     // Template constrains only organization → CN is absent from template → disallowed.
        let tpl: CsrTemplate = serde_json::from_str(
            r#"{"keyTypes":[{"type":"EC","curve":"P-256"}],"subject":{"organization":"ExampleCorp"},"extensions":{"subjectAltName":{}}}"#,
        )
        .unwrap();
        let err = validate_csr_against_template(&csr, &tpl).unwrap_err();
        match err {
            AcmeError::BadCsr(msg) => {
                assert!(msg.contains("not permitted by template"), "msg: {msg}")
            }
            other => panic!("expected BadCsr, got {other:?}"),
        }
    }

    // ── Extension tests ───────────────────────────────────────────────────────

    #[test]
    fn san_required_present_passes() {
        let key = ec_p256_key();
        let csr = make_csr(&key, "present.example");
        let tpl = default_ec_template();
        assert!(validate_csr_against_template(&csr, &tpl).is_ok());
    }

    #[test]
    fn san_optional_absent_passes() {
        let key = ec_p256_key();
        let spki_der = key.public_key().unwrap().spki_der().to_vec();
        let name_der = NameBuilder::new().common_name("no-san").build().unwrap();
        let signer = key.as_signer("sha256");
        let csr = CsrBuilder::new()
            .subject_name(&name_der)
            .public_key_der(&spki_der)
            .sign(&signer)
            .unwrap();
        // Template with subjectAltName: null → SAN is optional.
        let tpl: CsrTemplate = serde_json::from_str(
            r#"{"keyTypes":[{"type":"EC","curve":"P-256"}],"subject":{},"extensions":{"subjectAltName":null}}"#,
        )
        .unwrap();
        assert!(validate_csr_against_template(&csr, &tpl).is_ok());
    }

    #[test]
    fn extra_extension_rejected() {
        let key = ec_p256_key();
        let spki_der = key.public_key().unwrap().spki_der().to_vec();
        let name_der = NameBuilder::new()
            .common_name("extra.example")
            .build()
            .unwrap();
        let san_der = SubjectAlternativeNameBuilder::new()
            .dns_name("extra.example")
            .build()
            .unwrap();
        // Add a keyUsage extension that the template doesn't allow.
        let ku_der = encode_key_usage(1 << KEY_USAGE_DIGITAL_SIGNATURE).unwrap();
        let signer = key.as_signer("sha256");
        let csr = CsrBuilder::new()
            .subject_name(&name_der)
            .public_key_der(&spki_der)
            .add_extension_oid(oids::SUBJECT_ALT_NAME, false, &san_der)
            .add_extension_oid(oids::KEY_USAGE, true, &ku_der)
            .sign(&signer)
            .unwrap();
        // Template only has subjectAltName → keyUsage is not permitted.
        let tpl = default_ec_template();
        let err = validate_csr_against_template(&csr, &tpl).unwrap_err();
        match err {
            AcmeError::BadCsr(msg) => {
                assert!(msg.contains("not permitted by template"), "msg: {msg}")
            }
            other => panic!("expected BadCsr, got {other:?}"),
        }
    }

    #[test]
    fn key_usage_exact_match_passes() {
        let key = ec_p256_key();
        let spki_der = key.public_key().unwrap().spki_der().to_vec();
        let name_der = NameBuilder::new()
            .common_name("ku.example")
            .build()
            .unwrap();
        let san_der = SubjectAlternativeNameBuilder::new()
            .dns_name("ku.example")
            .build()
            .unwrap();
        let ku_der = encode_key_usage(
            (1 << KEY_USAGE_DIGITAL_SIGNATURE) | (1 << KEY_USAGE_KEY_ENCIPHERMENT),
        )
        .unwrap();
        let signer = key.as_signer("sha256");
        let csr = CsrBuilder::new()
            .subject_name(&name_der)
            .public_key_der(&spki_der)
            .add_extension_oid(oids::SUBJECT_ALT_NAME, false, &san_der)
            .add_extension_oid(oids::KEY_USAGE, true, &ku_der)
            .sign(&signer)
            .unwrap();
        let tpl: CsrTemplate = serde_json::from_str(
            r#"{"keyTypes":[{"type":"EC","curve":"P-256"}],"subject":{},"extensions":{"subjectAltName":{},"keyUsage":["digitalSignature","keyEncipherment"]}}"#,
        )
        .unwrap();
        assert!(validate_csr_against_template(&csr, &tpl).is_ok());
    }

    #[test]
    fn key_usage_mismatch_rejected() {
        let key = ec_p256_key();
        let spki_der = key.public_key().unwrap().spki_der().to_vec();
        let name_der = NameBuilder::new()
            .common_name("ku.example")
            .build()
            .unwrap();
        let san_der = SubjectAlternativeNameBuilder::new()
            .dns_name("ku.example")
            .build()
            .unwrap();
        // CSR has only digitalSignature but template requires both.
        let ku_der = encode_key_usage(1 << KEY_USAGE_DIGITAL_SIGNATURE).unwrap();
        let signer = key.as_signer("sha256");
        let csr = CsrBuilder::new()
            .subject_name(&name_der)
            .public_key_der(&spki_der)
            .add_extension_oid(oids::SUBJECT_ALT_NAME, false, &san_der)
            .add_extension_oid(oids::KEY_USAGE, true, &ku_der)
            .sign(&signer)
            .unwrap();
        let tpl: CsrTemplate = serde_json::from_str(
            r#"{"keyTypes":[{"type":"EC","curve":"P-256"}],"subject":{},"extensions":{"subjectAltName":{},"keyUsage":["digitalSignature","keyEncipherment"]}}"#,
        )
        .unwrap();
        let err = validate_csr_against_template(&csr, &tpl).unwrap_err();
        match err {
            AcmeError::BadCsr(msg) => assert!(msg.contains("keyUsage"), "msg: {msg}"),
            other => panic!("expected BadCsr, got {other:?}"),
        }
    }

    #[test]
    fn eku_subset_passes() {
        let key = ec_p256_key();
        let spki_der = key.public_key().unwrap().spki_der().to_vec();
        let name_der = NameBuilder::new()
            .common_name("eku.example")
            .build()
            .unwrap();
        let san_der = SubjectAlternativeNameBuilder::new()
            .dns_name("eku.example")
            .build()
            .unwrap();
        // CSR has serverAuth EKU.
        let eku_der = ExtendedKeyUsageBuilder::new()
            .server_auth()
            .build()
            .unwrap();
        let signer = key.as_signer("sha256");
        let csr = CsrBuilder::new()
            .subject_name(&name_der)
            .public_key_der(&spki_der)
            .add_extension_oid(oids::SUBJECT_ALT_NAME, false, &san_der)
            .add_extension_oid(oids::EXTENDED_KEY_USAGE, false, &eku_der)
            .sign(&signer)
            .unwrap();
        // Template permits serverAuth and clientAuth.
        let tpl: CsrTemplate = serde_json::from_str(
            r#"{"keyTypes":[{"type":"EC","curve":"P-256"}],"subject":{},"extensions":{"subjectAltName":{},"extendedKeyUsage":["1.3.6.1.5.5.7.3.1","1.3.6.1.5.5.7.3.2"]}}"#,
        )
        .unwrap();
        assert!(validate_csr_against_template(&csr, &tpl).is_ok());
    }

    #[test]
    fn eku_not_subset_rejected() {
        let key = ec_p256_key();
        let spki_der = key.public_key().unwrap().spki_der().to_vec();
        let name_der = NameBuilder::new()
            .common_name("eku.example")
            .build()
            .unwrap();
        let san_der = SubjectAlternativeNameBuilder::new()
            .dns_name("eku.example")
            .build()
            .unwrap();
        // CSR has clientAuth EKU.
        let eku_der = ExtendedKeyUsageBuilder::new()
            .client_auth()
            .build()
            .unwrap();
        let signer = key.as_signer("sha256");
        let csr = CsrBuilder::new()
            .subject_name(&name_der)
            .public_key_der(&spki_der)
            .add_extension_oid(oids::SUBJECT_ALT_NAME, false, &san_der)
            .add_extension_oid(oids::EXTENDED_KEY_USAGE, false, &eku_der)
            .sign(&signer)
            .unwrap();
        // Template only permits serverAuth.
        let tpl: CsrTemplate = serde_json::from_str(
            r#"{"keyTypes":[{"type":"EC","curve":"P-256"}],"subject":{},"extensions":{"subjectAltName":{},"extendedKeyUsage":["1.3.6.1.5.5.7.3.1"]}}"#,
        )
        .unwrap();
        let err = validate_csr_against_template(&csr, &tpl).unwrap_err();
        match err {
            AcmeError::BadCsr(msg) => {
                assert!(msg.contains("extendedKeyUsage"), "msg: {msg}")
            }
            other => panic!("expected BadCsr, got {other:?}"),
        }
    }

    // ── Field spec deserialization ────────────────────────────────────────────

    #[test]
    fn field_spec_deserializes_literal() {
        let spec: FieldSpec = serde_json::from_str(r#""ExampleCorp""#).unwrap();
        assert!(matches!(spec, FieldSpec::Literal(s) if s == "ExampleCorp"));
    }

    #[test]
    fn field_spec_deserializes_mandatory_wildcard() {
        let spec: FieldSpec = serde_json::from_str("{}").unwrap();
        assert!(matches!(spec, FieldSpec::MandatoryWildcard));
    }

    #[test]
    fn field_spec_deserializes_optional_wildcard() {
        let spec: FieldSpec = serde_json::from_str("null").unwrap();
        assert!(matches!(spec, FieldSpec::OptionalWildcard));
    }

    #[test]
    fn field_spec_rejects_invalid_json() {
        assert!(serde_json::from_str::<FieldSpec>("42").is_err());
        assert!(serde_json::from_str::<FieldSpec>(r#"{"key":"val"}"#).is_err());
    }
}
