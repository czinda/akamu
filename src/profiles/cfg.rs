//! Dogtag/IPAThinCA `.cfg` profile format parser and translator.
//!
//! Both Dogtag PKI and FreeIPA/IPAThinCA store certificate profiles as
//! Java-properties files (ASCII key=value, `#` comments, no sections).
//! Profile files are named `<profile_id>.cfg` on disk and stored verbatim in
//! the `certProfileConfig` LDAP attribute (`certProfile` object class).
//!
//! # Structure overview
//!
//! ```text
//! name=Server Certificate Enrollment
//! desc=Enroll a server certificate
//! enable=true
//! visible=true
//!
//! policyset.list=serverCertSet
//! policyset.serverCertSet.list=1,2,3,4,5,6
//!
//! policyset.serverCertSet.1.default.class_id=subjectNameDefaultImpl
//! policyset.serverCertSet.2.default.class_id=validityDefaultImpl
//! policyset.serverCertSet.2.default.params.range=365
//! policyset.serverCertSet.2.default.params.rangeUnit=day
//! policyset.serverCertSet.3.default.class_id=keyUsageExtDefaultImpl
//! policyset.serverCertSet.3.default.params.keyUsageDigitalSignature=true
//! policyset.serverCertSet.3.default.params.keyUsageKeyEncipherment=true
//! policyset.serverCertSet.4.default.class_id=extendedKeyUsageExtDefaultImpl
//! policyset.serverCertSet.4.default.params.exKeyUsageOIDs=1.3.6.1.5.5.7.3.1
//! ```
//!
//! # Translation
//!
//! [`parse_and_translate`] converts the properties map to
//! [`CertificateParameters`] by
//! walking the policy set entries and handling the plugin classes that affect
//! certificate content.  Unrecognised policy classes are silently ignored —
//! they may control Dogtag-specific behaviour that has no equivalent in akamu.

use std::collections::HashMap;

use synta_certificate::{
    KEY_USAGE_C_RLSIGN, KEY_USAGE_DATA_ENCIPHERMENT, KEY_USAGE_DECIPHER_ONLY,
    KEY_USAGE_DIGITAL_SIGNATURE, KEY_USAGE_ENCIPHER_ONLY, KEY_USAGE_KEY_AGREEMENT,
    KEY_USAGE_KEY_CERT_SIGN, KEY_USAGE_KEY_ENCIPHERMENT, KEY_USAGE_NON_REPUDIATION,
};

use crate::profiles::{CaDefaults, CertificateParameters};

/// Parse the raw `.cfg` text and return `(description, CertificateParameters)`.
///
/// `profile_id` is used only for log messages.
///
/// Returns `Err` when the properties file is malformed enough that the result
/// would not be meaningful (e.g. missing `policyset.list`).
pub fn parse_and_translate(
    content: &str,
    profile_id: &str,
    ca: &CaDefaults,
) -> Result<(String, CertificateParameters), String> {
    let props = parse_properties(content);

    // Human-readable description: prefer `name`, fall back to `desc`, then the ID.
    let description = props
        .get("name")
        .or_else(|| props.get("desc"))
        .cloned()
        .unwrap_or_else(|| profile_id.to_string());

    let params = translate(&props, profile_id, ca)?;
    Ok((description, params))
}

// ── Properties parser ─────────────────────────────────────────────────────────

/// Parse a Java-properties style file into a flat `key → value` map.
///
/// Rules:
/// - Lines beginning with `#` or `!` are comments.
/// - Blank lines are skipped.
/// - The first `=` on a line separates key from value; trailing whitespace
///   on each side is trimmed.
/// - Continuation lines (`\` at end of value) are NOT supported —
///   Dogtag profile files do not use them.
pub fn parse_properties(content: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for raw_line in content.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with('!') {
            continue;
        }
        if let Some(eq) = line.find('=') {
            let key = line[..eq].trim().to_string();
            let value = line[eq + 1..].trim().to_string();
            map.insert(key, value);
        }
    }
    map
}

// ── Translator ────────────────────────────────────────────────────────────────

/// Translate a parsed Dogtag Java-properties map into [`CertificateParameters`].
///
/// Walks the policy set entries and extracts parameters from the recognised
/// policy plugin classes.  Starts from CA defaults and overrides individual
/// fields as each matching class is encountered.  Unrecognised class IDs are
/// silently skipped — they may govern Dogtag-internal behaviour that has no
/// equivalent in akamu.
///
/// The `policyset.list` property must be present; if it is missing or empty
/// the function returns `Err`.  Only the first policy set listed is processed
/// (real-world Dogtag profiles use exactly one policy set).
fn translate(
    props: &HashMap<String, String>,
    profile_id: &str,
    ca: &CaDefaults,
) -> Result<CertificateParameters, String> {
    // Start with CA defaults; policy entries override individual fields.
    let mut validity_days = ca.validity_days;
    let hash_alg = ca.hash_alg.clone();
    let mut key_usage_bits: u16 = 1u16 << KEY_USAGE_DIGITAL_SIGNATURE; // safe default
    let mut extended_key_usages: Vec<String> = vec!["server_auth".to_string()];
    let mut crl_url = ca.crl_url.clone();
    let mut ocsp_url = ca.ocsp_url.clone();
    let mut key_usage_seen = false;
    let mut eku_seen = false;

    // Dogtag can define multiple policy sets, but in practice every profile
    // uses exactly one.  We process the first set listed in `policyset.list`.
    let set_name = match props.get("policyset.list") {
        Some(s) => s.split(',').next().map(str::trim).unwrap_or("").to_string(),
        None => {
            return Err(format!(
                "profile '{profile_id}': missing 'policyset.list' property"
            ))
        }
    };
    if set_name.is_empty() {
        return Err(format!("profile '{profile_id}': 'policyset.list' is empty"));
    }

    let policy_nums_key = format!("policyset.{set_name}.list");
    let policy_nums: Vec<&str> = props
        .get(&policy_nums_key)
        .map(|s| s.split(',').map(str::trim).collect())
        .unwrap_or_default();

    for num in policy_nums {
        let class_key = format!("policyset.{set_name}.{num}.default.class_id");
        let class = match props.get(&class_key) {
            Some(c) => c.as_str(),
            None => continue,
        };
        let pfx = format!("policyset.{set_name}.{num}.default.params");

        match class {
            "validityDefaultImpl" => {
                if let Some(range_str) = props.get(&format!("{pfx}.range")) {
                    if let Ok(range) = range_str.parse::<u32>() {
                        let unit = props
                            .get(&format!("{pfx}.rangeUnit"))
                            .map(String::as_str)
                            .unwrap_or("day");
                        validity_days = match unit {
                            "year" => range.saturating_mul(365),
                            "month" => range.saturating_mul(30),
                            _ => range, // "day" and anything unrecognised
                        };
                    }
                }
            }

            "keyUsageExtDefaultImpl" => {
                let mut bits: u16 = 0;
                let ku_map: &[(&str, usize)] = &[
                    ("keyUsageDigitalSignature", KEY_USAGE_DIGITAL_SIGNATURE),
                    ("keyUsageNonRepudiation", KEY_USAGE_NON_REPUDIATION),
                    ("keyUsageKeyEncipherment", KEY_USAGE_KEY_ENCIPHERMENT),
                    ("keyUsageDataEncipherment", KEY_USAGE_DATA_ENCIPHERMENT),
                    ("keyUsageKeyAgreement", KEY_USAGE_KEY_AGREEMENT),
                    ("keyUsageKeyCertSign", KEY_USAGE_KEY_CERT_SIGN),
                    ("keyUsageCrlSign", KEY_USAGE_C_RLSIGN),
                    ("keyUsageEncipherOnly", KEY_USAGE_ENCIPHER_ONLY),
                    ("keyUsageDecipherOnly", KEY_USAGE_DECIPHER_ONLY),
                ];
                for (param, bit_pos) in ku_map {
                    let key = format!("{pfx}.{param}");
                    if props.get(&key).map(|v| v == "true").unwrap_or(false) {
                        bits |= 1u16 << bit_pos;
                    }
                }
                // Only override the default when at least one bit is set; a
                // profile that has an empty keyUsageExtDefaultImpl is unusual
                // but should not clear all usage bits.
                if bits != 0 {
                    key_usage_bits = bits;
                    key_usage_seen = true;
                }
            }

            "extendedKeyUsageExtDefaultImpl" => {
                // exKeyUsageOIDs is a comma-separated list of dotted-decimal OIDs.
                let oids_key = format!("{pfx}.exKeyUsageOIDs");
                if let Some(oids_str) = props.get(&oids_key) {
                    let ekus: Vec<String> = oids_str
                        .split(',')
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        .map(String::from)
                        .collect();
                    if !ekus.is_empty() {
                        extended_key_usages = ekus;
                        eku_seen = true;
                    }
                }
            }

            // AIA extension — extract OCSP URL if present.
            "authInfoAccessExtDefaultImpl" => {
                // Dogtag numbers each AIA access description starting at _0.
                // We scan _0.._9 looking for an OCSP method.
                for i in 0..10usize {
                    let method_key = format!("{pfx}.authInfoAccessADMethod_{i}");
                    let loc_key = format!("{pfx}.authInfoAccessADLocation_{i}");
                    let enable_key = format!("{pfx}.authInfoAccessADEnable_{i}");

                    let enabled = props.get(&enable_key).map(|v| v == "true").unwrap_or(false);
                    if !enabled {
                        continue;
                    }
                    // id-ad-ocsp = 1.3.6.1.5.5.7.48.1
                    let is_ocsp = props
                        .get(&method_key)
                        .map(|v| v == "1.3.6.1.5.5.7.48.1")
                        .unwrap_or(false);
                    if is_ocsp {
                        if let Some(loc) = props.get(&loc_key) {
                            let loc = loc.trim();
                            // A non-empty URL overrides the CA default;
                            // an empty one suppresses the AIA extension.
                            ocsp_url = if loc.is_empty() {
                                None
                            } else {
                                Some(loc.to_string())
                            };
                        }
                        break;
                    }
                }
            }

            // CRL distribution points — extract the first URI.
            "crlDistributionPointsExtDefaultImpl" => {
                // Dogtag param: crlDistPointsPointName_0 (URI)
                let pt_key = format!("{pfx}.crlDistPointsPointName_0");
                if let Some(uri) = props.get(&pt_key) {
                    let uri = uri.trim();
                    crl_url = if uri.is_empty() {
                        None
                    } else {
                        Some(uri.to_string())
                    };
                }
            }

            // All other class IDs (subjectNameDefaultImpl, userKeyDefaultImpl,
            // authorityKeyIdentifierExtDefaultImpl, subjectAltNameExtDefaultImpl,
            // etc.) either have no bearing on CertificateParameters or are
            // handled entirely by akamu's standard issuance code.
            _ => {}
        }
    }

    if !key_usage_seen {
        tracing::debug!(
            "profile '{profile_id}': no keyUsageExtDefaultImpl found; \
             using digitalSignature default"
        );
    }
    if !eku_seen {
        tracing::debug!(
            "profile '{profile_id}': no extendedKeyUsageExtDefaultImpl found; \
             using serverAuth default"
        );
    }

    // Signing algorithm is not stored in Dogtag profile files — it is
    // determined by the CA key type at signing time.  Inherit from CA defaults.
    let _ = hash_alg; // already set to ca.hash_alg above

    Ok(CertificateParameters {
        validity_days,
        hash_alg: ca.hash_alg.clone(),
        key_usage_bits,
        extended_key_usages,
        crl_url,
        ocsp_url,
        // Dogtag profile files express no key-type constraint on the subscriber
        // CSR; any algorithm is accepted by akamu's CSR validation logic.
        allowed_key_types: vec![],
        // `certificatePoliciesExtDefaultImpl` is not yet translated.
        // When needed, parse `policyset.<set>.<n>.default.params.PolicyQualifiers*`
        // from the properties map and populate this field accordingly.
        certificate_policies: vec![],
        // Dogtag profiles always produce X.509; MTC issuance is builtin-only.
        issue_as_mtc: false,
        // Authorization controls are builtin-only; Dogtag/IPA profiles impose no
        // identifier restrictions.
        allowed_identifier_patterns: vec![],
        identifier_match_all: true,
    })
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn default_ca() -> CaDefaults {
        CaDefaults {
            validity_days: 90,
            hash_alg: "sha256".to_string(),
            crl_url: None,
            ocsp_url: None,
        }
    }

    const SAMPLE_CFG: &str = r#"
desc=Server Certificate Enrollment Profile
name=Server Certificate Enrollment
enable=true
visible=true
policyset.list=serverCertSet
policyset.serverCertSet.list=1,2,3,4
policyset.serverCertSet.1.default.class_id=subjectNameDefaultImpl
policyset.serverCertSet.1.default.params.name=
policyset.serverCertSet.2.default.class_id=validityDefaultImpl
policyset.serverCertSet.2.default.params.range=180
policyset.serverCertSet.2.default.params.rangeUnit=day
policyset.serverCertSet.3.default.class_id=keyUsageExtDefaultImpl
policyset.serverCertSet.3.default.params.keyUsageCritical=true
policyset.serverCertSet.3.default.params.keyUsageDigitalSignature=true
policyset.serverCertSet.3.default.params.keyUsageNonRepudiation=false
policyset.serverCertSet.3.default.params.keyUsageKeyEncipherment=true
policyset.serverCertSet.3.default.params.keyUsageDataEncipherment=false
policyset.serverCertSet.3.default.params.keyUsageKeyAgreement=false
policyset.serverCertSet.3.default.params.keyUsageKeyCertSign=false
policyset.serverCertSet.3.default.params.keyUsageCrlSign=false
policyset.serverCertSet.3.default.params.keyUsageEncipherOnly=false
policyset.serverCertSet.3.default.params.keyUsageDecipherOnly=false
policyset.serverCertSet.4.default.class_id=extendedKeyUsageExtDefaultImpl
policyset.serverCertSet.4.default.params.exKeyUsageCritical=false
policyset.serverCertSet.4.default.params.exKeyUsageOIDs=1.3.6.1.5.5.7.3.1,1.3.6.1.5.5.7.3.2
"#;

    #[test]
    fn parse_properties_basic() {
        let props = parse_properties(SAMPLE_CFG);
        assert_eq!(
            props.get("name").map(String::as_str),
            Some("Server Certificate Enrollment")
        );
        assert_eq!(
            props
                .get("policyset.serverCertSet.2.default.params.range")
                .map(String::as_str),
            Some("180")
        );
    }

    #[test]
    fn parse_properties_ignores_comments_and_blank_lines() {
        let text = "# comment\n\nkey=value\n! also comment\n";
        let props = parse_properties(text);
        assert_eq!(props.len(), 1);
        assert_eq!(props["key"], "value");
    }

    #[test]
    fn translate_sample_cfg() {
        let (desc, params) =
            parse_and_translate(SAMPLE_CFG, "caServerCert", &default_ca()).unwrap();
        assert_eq!(desc, "Server Certificate Enrollment");
        assert_eq!(params.validity_days, 180);

        // digitalSignature + keyEncipherment
        use synta_certificate::{KEY_USAGE_DIGITAL_SIGNATURE, KEY_USAGE_KEY_ENCIPHERMENT};
        assert!(params.key_usage_bits & (1u16 << KEY_USAGE_DIGITAL_SIGNATURE) != 0);
        assert!(params.key_usage_bits & (1u16 << KEY_USAGE_KEY_ENCIPHERMENT) != 0);

        // serverAuth + clientAuth OIDs
        assert!(params
            .extended_key_usages
            .iter()
            .any(|e| e == "1.3.6.1.5.5.7.3.1"));
        assert!(params
            .extended_key_usages
            .iter()
            .any(|e| e == "1.3.6.1.5.5.7.3.2"));
    }

    #[test]
    fn translate_validity_units() {
        let ca = default_ca();
        let test_cases = &[
            ("day", "30", 30u32),
            ("month", "6", 180),
            ("year", "2", 730),
        ];
        for (unit, range, expected_days) in test_cases {
            let cfg_text = format!(
                "name=test\npolicyset.list=s\npolicyset.s.list=1\n\
                 policyset.s.1.default.class_id=validityDefaultImpl\n\
                 policyset.s.1.default.params.range={range}\n\
                 policyset.s.1.default.params.rangeUnit={unit}\n"
            );
            let (_, params) = parse_and_translate(&cfg_text, "test", &ca).unwrap();
            assert_eq!(
                params.validity_days, *expected_days,
                "unit={unit} range={range}"
            );
        }
    }

    #[test]
    fn translate_missing_policyset_list_returns_error() {
        let bad = "name=test\n";
        assert!(parse_and_translate(bad, "bad", &default_ca()).is_err());
    }

    #[test]
    fn translate_inherits_ca_defaults_for_missing_policies() {
        let ca = CaDefaults {
            validity_days: 42,
            hash_alg: "sha384".to_string(),
            crl_url: Some("http://crl.example.com/ca.crl".to_string()),
            ocsp_url: Some("http://ocsp.example.com".to_string()),
        };
        // Profile with no validity, keyUsage, or EKU policy
        let cfg_text = "name=minimal\npolicyset.list=s\npolicyset.s.list=\n";
        let (_, params) = parse_and_translate(cfg_text, "minimal", &ca).unwrap();
        // Falls back to CA defaults
        assert_eq!(params.validity_days, 42);
        assert_eq!(params.hash_alg, "sha384");
        assert_eq!(
            params.crl_url.as_deref(),
            Some("http://crl.example.com/ca.crl")
        );
        assert_eq!(params.ocsp_url.as_deref(), Some("http://ocsp.example.com"));
    }
}
