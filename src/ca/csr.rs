//! CSR (Certificate Signing Request) parsing and validation.
//!
//! Parses a PKCS #10 CSR (DER), verifies its self-signature, and checks
//! that the requested identifiers match those authorised by the ACME order.

use synta::traits::Encode;
use synta::{Decoder, Encoder, Encoding};
use synta_certificate::{
    csr::CertificationRequest, general_name, oids, parse_general_names, BackendPublicKey,
    BasicConstraints,
};

use crate::error::AcmeError;

/// Parsed identifier from a CSR SAN extension.
#[derive(Debug, Clone)]
pub struct SanEntry {
    /// `"dns"` or `"ip"`.
    pub san_type: String,
    /// Value as a string: DNS name or dotted-decimal / colon-hex IP address.
    pub value: String,
}

/// A validated CSR ready for certificate issuance.
#[derive(Debug)]
pub struct ValidatedCsr {
    /// SPKI DER from the CSR (for inclusion in the issued certificate).
    pub spki_der: Vec<u8>,
    /// Subject Name DER from the CSR.
    pub subject_der: Vec<u8>,
    /// Parsed SANs.
    pub sans: Vec<SanEntry>,
}

/// Parse and validate a DER-encoded PKCS #10 CSR.
///
/// Checks:
/// 1. Parses as a valid DER PKCS #10 structure.
/// 2. CSR self-signature is valid.
/// 3. No `BasicConstraints` with `cA=TRUE`.
/// 4. `allowed_identifiers` and CSR SANs are identical sets (bidirectional).
pub fn validate_csr(
    csr_der: &[u8],
    allowed_identifiers: &[(&str, &str)],
) -> Result<ValidatedCsr, AcmeError> {
    // 1. Parse the CSR.
    let mut decoder = Decoder::new(csr_der, Encoding::Der);
    let csr: CertificationRequest = decoder
        .decode()
        .map_err(|e| AcmeError::BadCsr(format!("parse: {e}")))?;

    // 2. Re-encode CertificationRequestInfo → TBS bytes.
    let mut enc = Encoder::new(Encoding::Der);
    csr.certification_request_info
        .encode(&mut enc)
        .map_err(|e| AcmeError::BadCsr(format!("CRI encode: {e}")))?;
    let cri_der = enc
        .finish()
        .map_err(|e| AcmeError::BadCsr(format!("CRI finish: {e}")))?;

    // 3. Re-encode the AlgorithmIdentifier.
    let mut enc = Encoder::new(Encoding::Der);
    csr.signature_algorithm
        .encode(&mut enc)
        .map_err(|e| AcmeError::BadCsr(format!("AlgId encode: {e}")))?;
    let sig_alg_der = enc
        .finish()
        .map_err(|e| AcmeError::BadCsr(format!("AlgId finish: {e}")))?;

    // 4. Re-encode SubjectPublicKeyInfo.
    let mut enc = Encoder::new(Encoding::Der);
    csr.certification_request_info
        .subject_pkinfo
        .encode(&mut enc)
        .map_err(|e| AcmeError::BadCsr(format!("SPKI encode: {e}")))?;
    let spki_der = enc
        .finish()
        .map_err(|e| AcmeError::BadCsr(format!("SPKI finish: {e}")))?;

    // 5. Verify self-signature.
    //    BitStringRef::as_bytes() strips the unused-bits leading octet.
    let sig_bytes = csr.signature.as_bytes();
    let pub_key = BackendPublicKey::from_spki_der(spki_der.clone());
    pub_key
        .verify_signature(&cri_der, &sig_alg_der, sig_bytes)
        .map_err(|e| AcmeError::BadCsr(format!("signature invalid: {e}")))?;

    // 6. Extract X.509 extensions from the extensionRequest attribute.
    let extensions = extract_csr_extensions(&csr)?;

    // 7. Reject CSRs that assert cA=TRUE in BasicConstraints.
    if let Some(bc_bytes) = find_ext_value(&extensions, oids::BASIC_CONSTRAINTS) {
        let mut bc_dec = Decoder::new(&bc_bytes, Encoding::Der);
        if let Ok(bc) = bc_dec.decode::<BasicConstraints>() {
            if bc.c_a.map(|b| b.0).unwrap_or(false) {
                return Err(AcmeError::BadCsr(
                    "cA=TRUE not allowed in end-entity CSR".into(),
                ));
            }
        }
    }

    // 8. Parse Subject Alternative Names.
    let mut sans: Vec<SanEntry> = Vec::new();
    if let Some(san_bytes) = find_ext_value(&extensions, oids::SUBJECT_ALT_NAME) {
        for (tag, content) in parse_general_names(&san_bytes) {
            match tag {
                general_name::DNS_NAME => {
                    let name = String::from_utf8(content)
                        .map_err(|_| AcmeError::BadCsr("SAN dNSName is not valid UTF-8".into()))?;
                    sans.push(SanEntry {
                        san_type: "dns".into(),
                        value: name,
                    });
                }
                general_name::IP_ADDRESS => {
                    let ip = bytes_to_ip_string(&content)
                        .ok_or_else(|| AcmeError::BadCsr("SAN iPAddress invalid length".into()))?;
                    sans.push(SanEntry {
                        san_type: "ip".into(),
                        value: ip,
                    });
                }
                general_name::RFC822_NAME => {
                    let addr = std::str::from_utf8(&content).map_err(|_| {
                        AcmeError::BadCsr("SAN rfc822Name is not valid UTF-8".into())
                    })?;
                    // Normalize domain to lowercase per RFC 5321 §2.4 (domain is
                    // case-insensitive); local-part is left as-is (case-sensitive).
                    let normalized = match addr.split_once('@') {
                        Some((local, domain)) => {
                            format!("{}@{}", local, domain.to_ascii_lowercase())
                        }
                        None => addr.to_owned(),
                    };
                    sans.push(SanEntry {
                        san_type: "email".into(),
                        value: normalized,
                    });
                }
                _ => {} // URI, directoryName, etc. — ignored for ACME
            }
        }
    }

    // 9. Bidirectional check: CSR SANs == allowed_identifiers (as sets).
    for san in &sans {
        if !allowed_identifiers
            .iter()
            .any(|(t, v)| *t == san.san_type.as_str() && *v == san.value.as_str())
        {
            return Err(AcmeError::BadCsr(format!(
                "SAN {}:{} not authorised by order",
                san.san_type, san.value
            )));
        }
    }
    for (t, v) in allowed_identifiers {
        if !sans.iter().any(|s| s.san_type == *t && s.value == *v) {
            return Err(AcmeError::BadCsr(format!(
                "order identifier {t}:{v} missing from CSR SANs"
            )));
        }
    }

    // 10. Re-encode subject Name DER.
    let mut enc = Encoder::new(Encoding::Der);
    csr.certification_request_info
        .subject
        .encode(&mut enc)
        .map_err(|e| AcmeError::BadCsr(format!("subject encode: {e}")))?;
    let subject_der = enc
        .finish()
        .map_err(|e| AcmeError::BadCsr(format!("subject finish: {e}")))?;

    Ok(ValidatedCsr {
        spki_der,
        subject_der,
        sans,
    })
}

// ── Internal helpers ──────────────────────────────────────────────────────────

/// Extracted extension (OID arc components + raw extension value DER bytes).
struct CsrExt {
    oid_arcs: Vec<u32>,
    /// Raw DER of the extension value (content inside the OCTET STRING).
    value_der: Vec<u8>,
}

/// Walk the CSR attributes and collect all extensions from the
/// `extensionRequest` attribute (OID 1.2.840.113549.1.9.14).
fn extract_csr_extensions<'a>(csr: &CertificationRequest<'a>) -> Result<Vec<CsrExt>, AcmeError> {
    let Some(attributes) = &csr.certification_request_info.attributes else {
        return Ok(Vec::new());
    };
    for attr in attributes.elements() {
        if attr.attr_type.components() == oids::PKCS9_EXTENSION_REQUEST {
            // attr_values is SET OF ANY; the single element is SEQUENCE OF Extension.
            if let Some(raw) = attr.attr_values.elements().first() {
                return Ok(synta_certificate::decode_extensions(raw.0)
                    .into_iter()
                    .map(|ext| CsrExt {
                        oid_arcs: ext.extn_id.components().to_vec(),
                        value_der: ext.extn_value.as_bytes().to_vec(),
                    })
                    .collect());
            }
        }
    }
    Ok(Vec::new())
}

/// Return the value DER for the first extension whose OID matches `oid`.
fn find_ext_value(exts: &[CsrExt], oid: &[u32]) -> Option<Vec<u8>> {
    exts.iter()
        .find(|e| e.oid_arcs.as_slice() == oid)
        .map(|e| e.value_der.clone())
}

/// Convert 4 (IPv4) or 16 (IPv6) raw bytes to a string.
fn bytes_to_ip_string(bytes: &[u8]) -> Option<String> {
    match bytes.len() {
        4 => Some(format!(
            "{}.{}.{}.{}",
            bytes[0], bytes[1], bytes[2], bytes[3]
        )),
        16 => {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(bytes);
            Some(std::net::Ipv6Addr::from(octets).to_string())
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use synta::{Decoder, Encoding};
    use synta_certificate::csr::CertificationRequest;
    use synta_certificate::oids;
    use synta_certificate::{
        BackendPrivateKey, CsrBuilder, NameBuilder, PrivateKey as _, SubjectAlternativeNameBuilder,
    };

    fn make_csr_der(key: &BackendPrivateKey, domain: &str, include_bc_ca_true: bool) -> Vec<u8> {
        let spki_der = key.public_key().unwrap().spki_der().to_vec();
        let name_der = NameBuilder::new().common_name(domain).build().unwrap();
        let san_der = SubjectAlternativeNameBuilder::new()
            .dns_name(domain)
            .build()
            .unwrap();
        let signer = key.as_signer("sha256");
        let mut builder = CsrBuilder::new()
            .subject_name(&name_der)
            .public_key_der(&spki_der)
            .add_extension_oid(oids::SUBJECT_ALT_NAME, false, &san_der);

        if include_bc_ca_true {
            // Build BasicConstraints with cA=TRUE.
            let bc = synta_certificate::encode_basic_constraints(true, None).unwrap();
            builder = builder.add_extension_oid(oids::BASIC_CONSTRAINTS, true, &bc);
        }

        builder.sign(&signer).unwrap()
    }

    fn make_ip_csr_der(key: &BackendPrivateKey, ip_bytes: &[u8]) -> Vec<u8> {
        let spki_der = key.public_key().unwrap().spki_der().to_vec();
        let name_der = NameBuilder::new()
            .common_name("ip-san-test")
            .build()
            .unwrap();
        let san_der = SubjectAlternativeNameBuilder::new()
            .ip_address(ip_bytes)
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

    #[test]
    fn valid_dns_csr_parses_correctly() {
        let key = BackendPrivateKey::generate_ec("P-256").unwrap();
        let csr_der = make_csr_der(&key, "example.com", false);
        let result = validate_csr(&csr_der, &[("dns", "example.com")]);
        assert!(result.is_ok(), "should parse valid CSR");
        let validated = result.unwrap();
        assert_eq!(validated.sans.len(), 1);
        assert_eq!(validated.sans[0].san_type, "dns");
        assert_eq!(validated.sans[0].value, "example.com");
        assert!(!validated.spki_der.is_empty());
        assert!(!validated.subject_der.is_empty());
    }

    #[test]
    fn invalid_der_returns_parse_error() {
        let result = validate_csr(b"not a csr", &[("dns", "example.com")]);
        assert!(result.is_err());
        match result.unwrap_err() {
            AcmeError::BadCsr(msg) => assert!(msg.contains("parse")),
            other => panic!("expected BadCsr, got {other:?}"),
        }
    }

    #[test]
    fn tampered_signature_rejected() {
        let key = BackendPrivateKey::generate_ec("P-256").unwrap();
        let mut csr_der = make_csr_der(&key, "example.com", false);
        // Flip last byte to corrupt signature.
        let last = csr_der.len() - 1;
        csr_der[last] ^= 0xff;
        let result = validate_csr(&csr_der, &[("dns", "example.com")]);
        assert!(result.is_err(), "tampered CSR should fail");
        match result.unwrap_err() {
            AcmeError::BadCsr(_) => {}
            other => panic!("expected BadCsr, got {other:?}"),
        }
    }

    #[test]
    fn ca_true_in_basic_constraints_rejected() {
        let key = BackendPrivateKey::generate_ec("P-256").unwrap();
        let csr_der = make_csr_der(&key, "example.com", true);
        let result = validate_csr(&csr_der, &[("dns", "example.com")]);
        assert!(result.is_err());
        match result.unwrap_err() {
            AcmeError::BadCsr(msg) => assert!(msg.contains("cA=TRUE")),
            other => panic!("expected BadCsr, got {other:?}"),
        }
    }

    #[test]
    fn san_not_in_allowed_identifiers_rejected() {
        let key = BackendPrivateKey::generate_ec("P-256").unwrap();
        let csr_der = make_csr_der(&key, "evil.com", false);
        // Only "example.com" is authorized, but CSR has "evil.com".
        let result = validate_csr(&csr_der, &[("dns", "example.com")]);
        assert!(result.is_err());
        match result.unwrap_err() {
            AcmeError::BadCsr(msg) => assert!(msg.contains("not authorised")),
            other => panic!("expected BadCsr, got {other:?}"),
        }
    }

    #[test]
    fn allowed_identifier_missing_from_csr_rejected() {
        let key = BackendPrivateKey::generate_ec("P-256").unwrap();
        let csr_der = make_csr_der(&key, "example.com", false);
        // CSR has only "example.com" but we require both.
        let result = validate_csr(&csr_der, &[("dns", "example.com"), ("dns", "other.com")]);
        assert!(result.is_err());
        match result.unwrap_err() {
            AcmeError::BadCsr(msg) => assert!(msg.contains("missing from CSR SANs")),
            other => panic!("expected BadCsr, got {other:?}"),
        }
    }

    #[test]
    fn ipv4_san_parses_correctly() {
        let key = BackendPrivateKey::generate_ec("P-256").unwrap();
        let ip_bytes = &[192u8, 0, 2, 1]; // 192.0.2.1
        let csr_der = make_ip_csr_der(&key, ip_bytes);
        let result = validate_csr(&csr_der, &[("ip", "192.0.2.1")]);
        assert!(result.is_ok(), "IPv4 SAN should parse");
        let validated = result.unwrap();
        assert_eq!(validated.sans[0].san_type, "ip");
        assert_eq!(validated.sans[0].value, "192.0.2.1");
    }

    #[test]
    fn ipv6_san_parses_correctly() {
        let key = BackendPrivateKey::generate_ec("P-256").unwrap();
        let ip_bytes = &[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1u8]; // 2001:db8::1
        let csr_der = make_ip_csr_der(&key, ip_bytes);
        let result = validate_csr(&csr_der, &[("ip", "2001:db8::1")]);
        assert!(result.is_ok(), "IPv6 SAN should parse");
    }

    #[test]
    fn bytes_to_ip_string_ipv4() {
        let bytes = [10u8, 0, 0, 1];
        assert_eq!(bytes_to_ip_string(&bytes), Some("10.0.0.1".to_string()));
    }

    #[test]
    fn bytes_to_ip_string_wrong_length_returns_none() {
        let bytes = [1u8, 2, 3]; // 3 bytes, not 4 or 16
        assert!(bytes_to_ip_string(&bytes).is_none());
    }

    #[test]
    fn csr_with_no_san_extension_validates_against_empty_identifiers() {
        // A CSR with no SAN extension should be valid if allowed_identifiers is also empty.
        // This exercises the "no SAN extension" path (extract_csr_extensions returning empty).
        let key = BackendPrivateKey::generate_ec("P-256").unwrap();
        let spki_der = key.public_key().unwrap().spki_der().to_vec();
        let name_der = NameBuilder::new().common_name("no-san").build().unwrap();
        let signer = key.as_signer("sha256");
        let csr_der = CsrBuilder::new()
            .subject_name(&name_der)
            .public_key_der(&spki_der)
            .sign(&signer)
            .unwrap();
        // No SANs in CSR and no required identifiers → should pass validation.
        let result = validate_csr(&csr_der, &[]);
        assert!(
            result.is_ok(),
            "CSR with no SAN should validate against empty identifiers: {result:?}"
        );
        let validated = result.unwrap();
        assert!(validated.sans.is_empty());
    }

    #[test]
    fn csr_with_email_san_is_parsed() {
        // CSR with rfc822Name (email) SAN — RFC 8823 support: the SAN must be
        // parsed and matched against the order's email identifier.
        let key = BackendPrivateKey::generate_ec("P-256").unwrap();
        let spki_der = key.public_key().unwrap().spki_der().to_vec();
        let name_der = NameBuilder::new().common_name("email-san").build().unwrap();

        // Manually construct SAN extension value with rfc822Name (tag 0x81).
        // DER: SEQUENCE { [1] IA5String "a@b.com" }
        let email = b"a@b.com";
        let mut san_der = vec![
            0x30,                    // SEQUENCE
            (email.len() + 2) as u8, // length
            0x81,                    // [1] IMPLICIT (rfc822Name)
            email.len() as u8,       // length of email
        ];
        san_der.extend_from_slice(email);

        let signer = key.as_signer("sha256");
        let csr_der = CsrBuilder::new()
            .subject_name(&name_der)
            .public_key_der(&spki_der)
            .add_extension_oid(oids::SUBJECT_ALT_NAME, false, &san_der)
            .sign(&signer)
            .unwrap();

        // RFC 8823: rfc822Name SAN must match the order's email identifier.
        let result = validate_csr(&csr_der, &[("email", "a@b.com")]);
        assert!(
            result.is_ok(),
            "rfc822Name SAN should validate against matching email identifier: {result:?}"
        );
        let validated = result.unwrap();
        assert_eq!(
            validated.sans.len(),
            1,
            "email SAN should be in parsed SANs"
        );
        assert_eq!(validated.sans[0].san_type, "email");
        assert_eq!(validated.sans[0].value, "a@b.com");

        // A CSR with an email SAN not in the order's identifiers must be rejected.
        let err = validate_csr(&csr_der, &[("dns", "example.com")]);
        assert!(
            err.is_err(),
            "email SAN not in order identifiers should be rejected"
        );
    }

    #[test]
    fn csr_with_mixed_case_email_domain_is_normalised() {
        // RFC 5321 §2.4: domain labels are case-insensitive; the CSR parser must
        // normalise the domain to lowercase so that "user@EXAMPLE.COM" in a SAN
        // matches the order identifier "user@example.com".
        let key = BackendPrivateKey::generate_ec("P-256").unwrap();
        let spki_der = key.public_key().unwrap().spki_der().to_vec();
        let name_der = NameBuilder::new()
            .common_name("email-mixed-case")
            .build()
            .unwrap();

        let email = b"user@EXAMPLE.COM";
        let mut san_der = vec![0x30, (email.len() + 2) as u8, 0x81, email.len() as u8];
        san_der.extend_from_slice(email);

        let signer = key.as_signer("sha256");
        let csr_der = CsrBuilder::new()
            .subject_name(&name_der)
            .public_key_der(&spki_der)
            .add_extension_oid(oids::SUBJECT_ALT_NAME, false, &san_der)
            .sign(&signer)
            .unwrap();

        // Order uses lowercase; CSR has uppercase domain — must be accepted.
        let result = validate_csr(&csr_der, &[("email", "user@example.com")]);
        assert!(
            result.is_ok(),
            "mixed-case domain in rfc822Name SAN must match lowercase identifier: {result:?}"
        );
        let validated = result.unwrap();
        assert_eq!(
            validated.sans[0].value, "user@example.com",
            "rfc822Name domain must be lowercased during parsing"
        );
    }

    /// Covers lines 173-176: extract_csr_extensions when CSR has attributes but
    /// none with the extensionRequest OID — the for loop completes without returning,
    /// falling through to `Ok(Vec::new())`.
    #[test]
    fn extract_csr_extensions_with_non_extensionrequest_attribute() {
        // Build a valid CSR that has an extensionRequest attribute.
        let key = BackendPrivateKey::generate_ec("P-256").unwrap();
        let csr_der = make_csr_der(&key, "example.com", false);

        // extensionRequest OID in DER: 06 09 2A 86 48 86 F7 0D 01 09 0E
        // Change the last byte (0x0E = extensionRequest) to 0x07 (challengePassword).
        // Both OIDs have the same DER encoding length, so structure stays valid.
        let ext_req_oid: &[u8] = &[
            0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x0E,
        ];
        let mut modified_der = csr_der.clone();
        if let Some(pos) = modified_der
            .windows(ext_req_oid.len())
            .position(|w| w == ext_req_oid)
        {
            modified_der[pos + ext_req_oid.len() - 1] = 0x07; // change to challengePassword OID
        } else {
            panic!("extensionRequest OID not found in CSR DER — test needs updating");
        }

        // Parse the modified DER. Signature will be invalid because CRI bytes changed,
        // but extract_csr_extensions does not check signatures.
        let mut decoder = Decoder::new(&modified_der, Encoding::Der);
        let csr: CertificationRequest = decoder
            .decode()
            .expect("modified CSR DER should still parse");

        // Call the private function directly — accessible from child test module.
        let result = super::extract_csr_extensions(&csr);
        assert!(result.is_ok(), "expected Ok from extract_csr_extensions");
        assert!(
            result.unwrap().is_empty(),
            "expected empty extensions when no extensionRequest attribute found"
        );
    }

    #[test]
    fn csr_with_basic_constraints_ca_false_is_accepted() {
        // CSR with BasicConstraints present but cA=FALSE — should pass the cA check.
        // This covers the closing braces of the inner `if bc.c_a...` block (lines 94-97)
        // reached when BasicConstraints is decoded successfully but cA is not TRUE.
        use synta_certificate::encode_basic_constraints;
        let key = BackendPrivateKey::generate_ec("P-256").unwrap();
        let spki_der = key.public_key().unwrap().spki_der().to_vec();
        let name_der = NameBuilder::new()
            .common_name("example.com")
            .build()
            .unwrap();
        let san_der = SubjectAlternativeNameBuilder::new()
            .dns_name("example.com")
            .build()
            .unwrap();
        let bc = encode_basic_constraints(false, None).unwrap();
        let signer = key.as_signer("sha256");
        let csr_der = CsrBuilder::new()
            .subject_name(&name_der)
            .public_key_der(&spki_der)
            .add_extension_oid(oids::SUBJECT_ALT_NAME, false, &san_der)
            .add_extension_oid(oids::BASIC_CONSTRAINTS, false, &bc)
            .sign(&signer)
            .unwrap();
        let result = validate_csr(&csr_der, &[("dns", "example.com")]);
        assert!(
            result.is_ok(),
            "CSR with cA=FALSE BasicConstraints should be accepted: {result:?}"
        );
    }
}
