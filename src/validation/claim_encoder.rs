//! Registry of JWT claim name → certificate extension DER encoder.
//!
//! Used at finalize time to convert validated `JWTClaimConstraints` claims into
//! OtherName SANs (or DNS SANs) in the issued certificate.
//!
//! # Extending the registry
//!
//! To add a new encoder (e.g. `"email-san"`):
//! 1. Add a variant to [`ClaimEncoder`].
//! 2. Add a match arm in [`ClaimEncoder::encode`].
//! 3. Add a match arm in [`build_registry`].
//! 4. Document the new encoder name string in [`crate::config::ClaimEncoderEntry`].
//!
//! No changes to `tkauth01.rs`, `finalize.rs`, config structs, or `AppState`.

use std::collections::HashMap;

/// The SAN produced by a [`ClaimEncoder`].
///
/// `OtherName` carries a DER-encoded OtherName SEQUENCE ready for
/// `SubjectAlternativeNameBuilder::other_name`.
/// `DnsName` carries a lowercase hostname string ready for
/// `SubjectAlternativeNameBuilder::dns_name`.
#[derive(Debug, Clone)]
pub enum EncodedSan {
    OtherName(Vec<u8>),
    DnsName(String),
}

/// One claim-to-extension encoder, parameterised with any config it needs.
///
/// Variants correspond to encoder names in `[tkauth.claim_encoders]`.
#[derive(Debug, Clone)]
pub enum ClaimEncoder {
    /// Encodes a Kerberos principal string as a KRB5PrincipalName OtherName SAN
    /// (OID id-pkinit-san 1.3.6.1.5.2.2, RFC 4556 §3.1).
    ///
    /// If the claim value contains no `@`, `default_realm` is appended as `value@REALM`.
    /// If `default_realm` is `None` and the value has no `@`, encoding fails.
    Krb5Kpn { default_realm: Option<String> },

    /// Encodes a string as an MS-UPN OtherName SAN
    /// (OID 1.3.6.1.4.1.311.20.2.3, UTF8String value).
    MsUpn,

    /// Adds the claim value as a dNSName SAN.
    ///
    /// The value must be a plain hostname (no wildcards, no empty string).
    /// It is lowercased before being added to the certificate.
    DnsSan,
}

impl ClaimEncoder {
    /// Return the ACME identifier type this encoder can authorize via a JWTClaimConstraints
    /// token, or `None` if it only produces SANs for non-standard identifier types.
    ///
    /// A `Some` return means tkauth-01 will be offered INSTEAD OF the normal challenge
    /// types for that identifier type when this encoder is configured.
    pub fn authorized_identifier_type(&self) -> Option<&'static str> {
        match self {
            ClaimEncoder::DnsSan => Some("dns"),
            ClaimEncoder::Krb5Kpn { .. } | ClaimEncoder::MsUpn => None,
        }
    }

    /// Produce an [`EncodedSan`] from a single claim value string.
    pub fn encode(&self, value: &str) -> Result<EncodedSan, String> {
        match self {
            ClaimEncoder::Krb5Kpn { default_realm } => {
                let principal = if value.contains('@') {
                    value.to_string()
                } else if let Some(realm) = default_realm {
                    format!("{value}@{realm}")
                } else {
                    return Err(format!(
                        "krb5-kpn: '{value}' contains no '@' and no default_realm is configured"
                    ));
                };
                crate::krb5_san::encode_principal_str_other_name(&principal)
                    .map(EncodedSan::OtherName)
            }
            ClaimEncoder::MsUpn => {
                crate::krb5_san::encode_ms_upn_other_name(value).map(EncodedSan::OtherName)
            }
            ClaimEncoder::DnsSan => {
                if value.is_empty() {
                    return Err("dns-san: empty DNS name".into());
                }
                if value.starts_with("*.") {
                    return Err(format!(
                        "dns-san: wildcard '{value}' is not permitted in claim constraints"
                    ));
                }
                Ok(EncodedSan::DnsName(value.to_lowercase()))
            }
        }
    }
}

/// Maps JWT claim names to their [`ClaimEncoder`].  Built once at startup from config.
pub type ClaimEncoderRegistry = HashMap<String, ClaimEncoder>;

/// Find the claim name in `registry` whose encoder authorizes the given ACME identifier type.
///
/// Returns `Some(claim_name)` when exactly one encoder is configured for that type.
/// Used by tkauth-01 validation to determine which claim in a JWTClaimConstraints blob
/// constrains the given identifier value.
pub fn find_claim_for_identifier_type<'a>(
    registry: &'a ClaimEncoderRegistry,
    id_type: &str,
) -> Option<&'a str> {
    registry.iter().find_map(|(claim, encoder)| {
        if encoder.authorized_identifier_type() == Some(id_type) {
            Some(claim.as_str())
        } else {
            None
        }
    })
}

/// Build a [`ClaimEncoderRegistry`] from the config entry list.
///
/// Returns `Err` when an encoder name is not recognised.
pub fn build_registry(
    entries: &[crate::config::ClaimEncoderEntry],
) -> Result<ClaimEncoderRegistry, String> {
    let mut registry = ClaimEncoderRegistry::new();
    for entry in entries {
        let encoder = match entry.encoder.as_str() {
            "krb5-kpn" => ClaimEncoder::Krb5Kpn {
                default_realm: entry.default_realm.clone(),
            },
            "ms-upn" => ClaimEncoder::MsUpn,
            "dns-san" => ClaimEncoder::DnsSan,
            other => {
                return Err(format!(
                    "tkauth.claim_encoders: unknown encoder '{}' for claim '{}'",
                    other, entry.claim
                ))
            }
        };
        registry.insert(entry.claim.clone(), encoder);
    }
    Ok(registry)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ClaimEncoderEntry;

    fn entry(claim: &str, encoder: &str, default_realm: Option<&str>) -> ClaimEncoderEntry {
        ClaimEncoderEntry {
            claim: claim.to_string(),
            encoder: encoder.to_string(),
            default_realm: default_realm.map(str::to_string),
        }
    }

    #[test]
    fn build_registry_known_encoders() {
        let entries = vec![
            entry("krb5-principal", "krb5-kpn", None),
            entry("ms-upn", "ms-upn", None),
            entry("dns", "dns-san", None),
        ];
        let reg = build_registry(&entries).unwrap();
        assert_eq!(reg.len(), 3);
        assert!(reg.contains_key("krb5-principal"));
        assert!(reg.contains_key("ms-upn"));
        assert!(reg.contains_key("dns"));
    }

    #[test]
    fn build_registry_unknown_encoder_returns_err() {
        let entries = vec![entry("foo", "nonexistent", None)];
        assert!(build_registry(&entries).is_err());
    }

    #[test]
    fn build_registry_empty_succeeds() {
        let reg = build_registry(&[]).unwrap();
        assert!(reg.is_empty());
    }

    #[test]
    fn krb5_kpn_with_full_principal() {
        let enc = ClaimEncoder::Krb5Kpn {
            default_realm: None,
        };
        let result = enc.encode("HTTP/web.example.com@EXAMPLE.COM").unwrap();
        let EncodedSan::OtherName(der) = result else {
            panic!("expected OtherName");
        };
        assert_eq!(der[0], 0x30, "expected SEQUENCE tag");
        assert!(der.len() > 10);
    }

    #[test]
    fn krb5_kpn_realm_appended_when_missing() {
        let enc = ClaimEncoder::Krb5Kpn {
            default_realm: Some("EXAMPLE.COM".into()),
        };
        let EncodedSan::OtherName(der_with_default) = enc.encode("user").unwrap() else {
            panic!("expected OtherName");
        };
        let enc2 = ClaimEncoder::Krb5Kpn {
            default_realm: None,
        };
        let EncodedSan::OtherName(der_explicit) = enc2.encode("user@EXAMPLE.COM").unwrap() else {
            panic!("expected OtherName");
        };
        assert_eq!(der_with_default, der_explicit);
    }

    #[test]
    fn krb5_kpn_no_realm_no_default_returns_err() {
        let enc = ClaimEncoder::Krb5Kpn {
            default_realm: None,
        };
        assert!(enc.encode("userwithoutrealm").is_err());
    }

    #[test]
    fn ms_upn_produces_der() {
        let enc = ClaimEncoder::MsUpn;
        let EncodedSan::OtherName(der) = enc.encode("alice@EXAMPLE.COM").unwrap() else {
            panic!("expected OtherName");
        };
        assert_eq!(der[0], 0x30, "expected SEQUENCE tag");
        assert!(der.len() > 10);
    }

    #[test]
    fn dns_san_produces_lowercase_dns_name() {
        let enc = ClaimEncoder::DnsSan;
        let EncodedSan::DnsName(name) = enc.encode("Web.Example.COM").unwrap() else {
            panic!("expected DnsName");
        };
        assert_eq!(name, "web.example.com");
    }

    #[test]
    fn dns_san_rejects_empty() {
        let enc = ClaimEncoder::DnsSan;
        assert!(enc.encode("").is_err());
    }

    #[test]
    fn dns_san_rejects_wildcard() {
        let enc = ClaimEncoder::DnsSan;
        assert!(enc.encode("*.example.com").is_err());
    }
}
