//! Built-in TOML-configured profile provider.
//!
//! All profile parameters are declared inline in `config.toml` under
//! `[profiles.providers.<name>]` with `type = "builtin"`.  No external system
//! is consulted; akamu's own CA signs every certificate.

use std::collections::HashMap;

use synta_certificate::{
    KEY_USAGE_C_RLSIGN, KEY_USAGE_DATA_ENCIPHERMENT, KEY_USAGE_DECIPHER_ONLY,
    KEY_USAGE_DIGITAL_SIGNATURE, KEY_USAGE_ENCIPHER_ONLY, KEY_USAGE_KEY_AGREEMENT,
    KEY_USAGE_KEY_CERT_SIGN, KEY_USAGE_KEY_ENCIPHERMENT, KEY_USAGE_NON_REPUDIATION,
};

use crate::config::BuiltinProviderConfig;
use crate::profiles::{CaDefaults, CertificateParameters};

/// Load all profiles from a `builtin` provider configuration.
///
/// Returns a map of `profile_id → (description, parameters)`.
/// Unset optional fields inherit their values from `ca`.
pub fn load_builtin(
    cfg: &BuiltinProviderConfig,
    ca: &CaDefaults,
) -> HashMap<String, (String, CertificateParameters)> {
    let mut out = HashMap::new();

    for (id, pcfg) in &cfg.profiles {
        let validity_days = pcfg.validity_days.unwrap_or(ca.validity_days);
        let hash_alg = pcfg.hash_alg.clone().unwrap_or_else(|| ca.hash_alg.clone());

        // `None` = inherit from CA; `Some("")` = suppress; `Some(url)` = override.
        let crl_url = match &pcfg.crl_url {
            None => ca.crl_url.clone(),
            Some(s) if s.is_empty() => None,
            Some(s) => Some(s.clone()),
        };
        let ocsp_url = match &pcfg.ocsp_url {
            None => ca.ocsp_url.clone(),
            Some(s) if s.is_empty() => None,
            Some(s) => Some(s.clone()),
        };

        let key_usage_bits = key_usage_from_names(&pcfg.key_usage);
        let certificate_policies = pcfg
            .certificate_policies
            .iter()
            .map(|pe| (pe.oid.clone(), pe.cps_uri.clone()))
            .collect();

        let issue_as_mtc = matches!(pcfg.issue_as.as_deref(), Some("mtc"));
        let identifier_match_all = !matches!(pcfg.identifier_match.as_deref(), Some("any"));

        let params = CertificateParameters {
            validity_days,
            hash_alg,
            key_usage_bits,
            extended_key_usages: pcfg.eku.clone(),
            crl_url,
            ocsp_url,
            allowed_key_types: pcfg.allowed_key_types.clone(),
            certificate_policies,
            issue_as_mtc,
            allowed_identifier_patterns: pcfg.allowed_identifiers.clone(),
            identifier_match_all,
            auth_hook: pcfg.auth_hook.clone(),
            auth_hook_timeout_secs: pcfg.auth_hook_timeout_secs.unwrap_or(30),
        };

        out.insert(id.clone(), (pcfg.description.clone(), params));
    }

    out
}

/// Convert a list of key-usage short names to a KeyUsage bitmask.
///
/// Bit positions use `KEY_USAGE_*` constants from `synta_certificate`.
/// Unrecognised names are logged and skipped.
pub fn key_usage_from_names(names: &[String]) -> u16 {
    let mut bits: u16 = 0;
    for name in names {
        let bit: Option<usize> = match name.as_str() {
            "digital_signature" => Some(KEY_USAGE_DIGITAL_SIGNATURE),
            "non_repudiation" | "content_commitment" => Some(KEY_USAGE_NON_REPUDIATION),
            "key_encipherment" => Some(KEY_USAGE_KEY_ENCIPHERMENT),
            "data_encipherment" => Some(KEY_USAGE_DATA_ENCIPHERMENT),
            "key_agreement" => Some(KEY_USAGE_KEY_AGREEMENT),
            "key_cert_sign" => Some(KEY_USAGE_KEY_CERT_SIGN),
            "crl_sign" => Some(KEY_USAGE_C_RLSIGN),
            "encipher_only" => Some(KEY_USAGE_ENCIPHER_ONLY),
            "decipher_only" => Some(KEY_USAGE_DECIPHER_ONLY),
            other => {
                tracing::warn!(
                    "builtin profile: unknown key_usage name '{}'; ignored",
                    other
                );
                None
            }
        };
        if let Some(b) = bit {
            bits |= 1u16 << b;
        }
    }
    bits
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{BuiltinProfileConfig, PolicyEntry};

    fn default_ca() -> CaDefaults {
        CaDefaults {
            validity_days: 90,
            hash_alg: "sha256".to_string(),
            crl_url: None,
            ocsp_url: None,
        }
    }

    fn make_profile(desc: &str) -> BuiltinProfileConfig {
        BuiltinProfileConfig {
            description: desc.to_string(),
            validity_days: None,
            hash_alg: None,
            key_usage: vec![
                "digital_signature".to_string(),
                "key_encipherment".to_string(),
            ],
            eku: vec!["server_auth".to_string()],
            crl_url: None,
            ocsp_url: None,
            allowed_key_types: vec![],
            certificate_policies: vec![],
            issue_as: None,
            allowed_identifiers: vec![],
            identifier_match: None,
            auth_hook: None,
            auth_hook_timeout_secs: None,
        }
    }

    #[test]
    fn load_builtin_inherits_ca_defaults() {
        let mut profiles = HashMap::new();
        profiles.insert("tls".to_string(), make_profile("TLS"));
        let cfg = BuiltinProviderConfig { profiles };
        let ca = default_ca();
        let loaded = load_builtin(&cfg, &ca);
        let (desc, params) = &loaded["tls"];
        assert_eq!(desc, "TLS");
        assert_eq!(params.validity_days, 90);
        assert_eq!(params.hash_alg, "sha256");
        assert!(params.crl_url.is_none());
    }

    #[test]
    fn load_builtin_profile_overrides_validity() {
        let mut profiles = HashMap::new();
        let mut p = make_profile("Long-lived");
        p.validity_days = Some(365);
        profiles.insert("long".to_string(), p);
        let cfg = BuiltinProviderConfig { profiles };
        let loaded = load_builtin(&cfg, &default_ca());
        assert_eq!(loaded["long"].1.validity_days, 365);
    }

    #[test]
    fn load_builtin_empty_crl_suppresses_extension() {
        let mut profiles = HashMap::new();
        let mut p = make_profile("NoCRL");
        p.crl_url = Some(String::new()); // empty = suppress
        profiles.insert("nocrl".to_string(), p);
        let cfg = BuiltinProviderConfig { profiles };
        let ca = CaDefaults {
            crl_url: Some("http://crl.example.com/ca.crl".to_string()),
            ..default_ca()
        };
        let loaded = load_builtin(&cfg, &ca);
        assert!(
            loaded["nocrl"].1.crl_url.is_none(),
            "empty string should suppress CRL URL"
        );
    }

    #[test]
    fn load_builtin_certificate_policies() {
        let mut profiles = HashMap::new();
        let mut p = make_profile("Policy");
        p.certificate_policies = vec![PolicyEntry {
            oid: "2.23.140.1.2.1".to_string(),
            cps_uri: Some("https://example.com/cps".to_string()),
        }];
        profiles.insert("policy".to_string(), p);
        let cfg = BuiltinProviderConfig { profiles };
        let loaded = load_builtin(&cfg, &default_ca());
        let (oid, cps) = &loaded["policy"].1.certificate_policies[0];
        assert_eq!(oid, "2.23.140.1.2.1");
        assert_eq!(cps.as_deref(), Some("https://example.com/cps"));
    }

    #[test]
    fn key_usage_from_names_all_bits() {
        use synta_certificate::*;
        let names: Vec<String> = vec![
            "digital_signature",
            "non_repudiation",
            "key_encipherment",
            "data_encipherment",
            "key_agreement",
            "key_cert_sign",
            "crl_sign",
            "encipher_only",
            "decipher_only",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let bits = key_usage_from_names(&names);
        assert!(bits & (1u16 << KEY_USAGE_DIGITAL_SIGNATURE) != 0);
        assert!(bits & (1u16 << KEY_USAGE_NON_REPUDIATION) != 0);
        assert!(bits & (1u16 << KEY_USAGE_KEY_ENCIPHERMENT) != 0);
        assert!(bits & (1u16 << KEY_USAGE_DATA_ENCIPHERMENT) != 0);
        assert!(bits & (1u16 << KEY_USAGE_KEY_AGREEMENT) != 0);
        assert!(bits & (1u16 << KEY_USAGE_KEY_CERT_SIGN) != 0);
        assert!(bits & (1u16 << KEY_USAGE_C_RLSIGN) != 0);
        assert!(bits & (1u16 << KEY_USAGE_ENCIPHER_ONLY) != 0);
        assert!(bits & (1u16 << KEY_USAGE_DECIPHER_ONLY) != 0);
    }

    #[test]
    fn key_usage_from_names_content_commitment_alias() {
        use synta_certificate::KEY_USAGE_NON_REPUDIATION;
        let bits = key_usage_from_names(&["content_commitment".to_string()]);
        assert!(bits & (1u16 << KEY_USAGE_NON_REPUDIATION) != 0);
    }

    #[test]
    fn key_usage_from_names_unknown_is_ignored() {
        let bits = key_usage_from_names(&["totally_unknown_bit".to_string()]);
        assert_eq!(bits, 0, "unknown name should produce zero bits");
    }

    #[test]
    fn load_builtin_issue_as_mtc_sets_flag() {
        let mut profiles = HashMap::new();
        let mut p = make_profile("MTC cert");
        p.issue_as = Some("mtc".to_string());
        profiles.insert("mtc-tls".to_string(), p);
        let cfg = BuiltinProviderConfig { profiles };
        let loaded = load_builtin(&cfg, &default_ca());
        assert!(
            loaded["mtc-tls"].1.issue_as_mtc,
            "issue_as = 'mtc' must set issue_as_mtc"
        );
    }

    #[test]
    fn load_builtin_issue_as_x509_does_not_set_flag() {
        let mut profiles = HashMap::new();
        let mut p = make_profile("Standard cert");
        p.issue_as = Some("x509".to_string());
        profiles.insert("standard".to_string(), p);
        let cfg = BuiltinProviderConfig { profiles };
        let loaded = load_builtin(&cfg, &default_ca());
        assert!(
            !loaded["standard"].1.issue_as_mtc,
            "issue_as = 'x509' must not set issue_as_mtc"
        );
    }

    #[test]
    fn load_builtin_issue_as_absent_does_not_set_flag() {
        let mut profiles = HashMap::new();
        profiles.insert("default".to_string(), make_profile("Default"));
        let cfg = BuiltinProviderConfig { profiles };
        let loaded = load_builtin(&cfg, &default_ca());
        assert!(
            !loaded["default"].1.issue_as_mtc,
            "absent issue_as must default to false"
        );
    }
}
