//! DER encoders for Kerberos OtherName SANs.
//!
//! Builds the raw OtherName DER bytes accepted by
//! `synta_certificate::SubjectAlternativeNameBuilder::other_name()`.
//!
//! Two OtherName types are supported:
//! - **KRB5PrincipalName** (id-pkinit-san, OID 1.3.6.1.5.2.2, RFC 4556 §3.1)
//! - **MS-UPN** (OID 1.3.6.1.4.1.311.20.2.3)
//!
//! # Template syntax (`expand_kpn_template`)
//!
//! Templates are expanded against DNS SAN values from the subscriber's CSR:
//!
//! ```text
//! "HTTP/{dns}@EXAMPLE.COM"   → NT-SRV-HST (3), components ["HTTP", <dns>]
//! "{dns}@EXAMPLE.COM"        → NT-PRINCIPAL (1), components [<dns>]
//! "host/server.example@REALM" → NT-SRV-HST (3), no substitution (static, injected once)
//! ```
//!
//! Templates containing `{dns}` produce one OtherName per DNS SAN in the CSR.
//! Templates without `{dns}` are static and produce exactly one OtherName regardless
//! of how many DNS SANs are present.

// ── OID DER content (without tag/length wrapper) ─────────────────────────────

/// DER content bytes for OID 1.3.6.1.5.2.2 (id-pkinit-san).
const OID_PKINIT_SAN: &[u8] = &[0x2B, 0x06, 0x01, 0x05, 0x02, 0x02];

/// DER content bytes for OID 1.3.6.1.4.1.311.20.2.3 (id-ms-san-upn).
const OID_MS_SAN_UPN: &[u8] = &[0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x14, 0x02, 0x03];

// Kerberos name-type constants (RFC 4120 §6.2).
const NT_PRINCIPAL: i32 = 1;
const NT_SRV_HST: i32 = 3;

// ── Public API ────────────────────────────────────────────────────────────────

/// Build a KRB5PrincipalName OtherName DER ready for
/// `SubjectAlternativeNameBuilder::other_name()`.
///
/// `name_type` should be one of the RFC 4120 NT-* constants (1 = NT-PRINCIPAL,
/// 3 = NT-SRV-HST, etc.). `components` are the parts of the principal name
/// (e.g. `["HTTP", "web.example.com"]` for an HTTP service principal).
pub fn encode_krb5_principal_other_name(
    realm: &str,
    name_type: i32,
    components: &[&str],
) -> Result<Vec<u8>, String> {
    if realm.is_empty() {
        return Err("KRB5PrincipalName: realm must not be empty".into());
    }
    if components.is_empty() {
        return Err("KRB5PrincipalName: at least one name component required".into());
    }

    // SEQUENCE OF KerberosString (the name-string field)
    let name_strings: Vec<u8> = components
        .iter()
        .flat_map(|c| der_general_string(c))
        .collect();
    let name_string_seq = der_sequence(&name_strings);

    // PrincipalName ::= SEQUENCE { name-type [0] INTEGER, name-string [1] SEQUENCE OF }
    let name_type_tlv = der_context_explicit(0, &der_integer_i32(name_type));
    let name_string_tlv = der_context_explicit(1, &name_string_seq);
    let mut principal_name_content = name_type_tlv;
    principal_name_content.extend_from_slice(&name_string_tlv);
    let principal_name = der_sequence(&principal_name_content);

    // KRB5PrincipalName ::= SEQUENCE { realm [0] Realm, principalName [1] PrincipalName }
    let realm_tlv = der_context_explicit(0, &der_general_string(realm));
    let pn_tlv = der_context_explicit(1, &principal_name);
    let mut krb5_pn_content = realm_tlv;
    krb5_pn_content.extend_from_slice(&pn_tlv);
    let krb5_pn = der_sequence(&krb5_pn_content);

    // OtherName ::= SEQUENCE { type-id OID, value [0] EXPLICIT ANY }
    build_other_name(OID_PKINIT_SAN, &krb5_pn)
}

/// Build an MS-UPN OtherName DER (OID 1.3.6.1.4.1.311.20.2.3, UTF8String value).
pub fn encode_ms_upn_other_name(upn: &str) -> Result<Vec<u8>, String> {
    if upn.is_empty() {
        return Err("MS-UPN: value must not be empty".into());
    }
    build_other_name(OID_MS_SAN_UPN, &der_utf8_string(upn))
}

/// Parse a Kerberos principal string and build a KRB5PrincipalName OtherName DER.
///
/// Format: `"service/host@REALM"` → NT-SRV-HST(3), components `["service", "host"]`
///         `"user@REALM"` → NT-PRINCIPAL(1), component `["user"]`
pub fn encode_principal_str_other_name(principal: &str) -> Result<Vec<u8>, String> {
    let (name_part, realm) = principal
        .rsplit_once('@')
        .ok_or_else(|| format!("Kerberos principal '{principal}' has no '@' separator"))?;
    if realm.is_empty() {
        return Err(format!(
            "Kerberos principal '{principal}': realm must not be empty"
        ));
    }
    let components: Vec<&str> = name_part.split('/').collect();
    let name_type = if components.len() > 1 {
        NT_SRV_HST
    } else {
        NT_PRINCIPAL
    };
    let component_refs: Vec<&str> = components.to_vec();
    encode_krb5_principal_other_name(realm, name_type, &component_refs)
}

/// Expand a KPN template against CSR DNS SAN values and return one OtherName DER
/// per expansion.
///
/// See module-level documentation for template syntax.
pub fn expand_kpn_template(template: &str, dns_sans: &[&str]) -> Result<Vec<Vec<u8>>, String> {
    let has_placeholder = template.contains("{dns}");

    // Split off the realm.
    let (name_part, realm) = template
        .rsplit_once('@')
        .ok_or_else(|| format!("KPN template '{template}' has no '@' separator"))?;

    let mut results = Vec::new();

    if has_placeholder {
        for &dns in dns_sans {
            let expanded = name_part.replace("{dns}", dns);
            let components: Vec<&str> = expanded.split('/').collect();
            let name_type = if components.len() > 1 {
                NT_SRV_HST
            } else {
                NT_PRINCIPAL
            };
            let refs: Vec<&str> = components.to_vec();
            results.push(encode_krb5_principal_other_name(realm, name_type, &refs)?);
        }
    } else {
        // Static template — no DNS substitution; inject exactly once.
        let components: Vec<&str> = name_part.split('/').collect();
        let name_type = if components.len() > 1 {
            NT_SRV_HST
        } else {
            NT_PRINCIPAL
        };
        let refs: Vec<&str> = components.to_vec();
        results.push(encode_krb5_principal_other_name(realm, name_type, &refs)?);
    }

    Ok(results)
}

/// Expand an MS-UPN template against the first CSR DNS SAN.
///
/// Template syntax: `"{dns}@example.com"` — `{dns}` is replaced with the first
/// DNS SAN value. Returns `None` if `dns_sans` is empty.
pub fn expand_ms_upn_template(
    template: &str,
    dns_sans: &[&str],
) -> Result<Option<Vec<u8>>, String> {
    if !template.contains("{dns}") {
        // Static UPN — inject regardless of DNS SANs.
        return encode_ms_upn_other_name(template).map(Some);
    }
    match dns_sans.first() {
        None => Ok(None),
        Some(&first) => {
            let upn = template.replace("{dns}", first);
            encode_ms_upn_other_name(&upn).map(Some)
        }
    }
}

// ── Internal DER helpers ──────────────────────────────────────────────────────

fn build_other_name(oid_content: &[u8], value_der: &[u8]) -> Result<Vec<u8>, String> {
    let oid_tlv = der_tag(0x06, oid_content);
    let value_tlv = der_context_explicit(0, value_der);
    let mut content = oid_tlv;
    content.extend_from_slice(&value_tlv);
    Ok(der_sequence(&content))
}

fn der_tag(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    encode_length(&mut out, content.len());
    out.extend_from_slice(content);
    out
}

fn der_sequence(content: &[u8]) -> Vec<u8> {
    der_tag(0x30, content)
}

/// Context-specific constructed explicit tag \[N\].
fn der_context_explicit(tag_num: u8, content: &[u8]) -> Vec<u8> {
    der_tag(0xA0 | tag_num, content)
}

fn der_general_string(s: &str) -> Vec<u8> {
    der_tag(0x1B, s.as_bytes())
}

fn der_utf8_string(s: &str) -> Vec<u8> {
    der_tag(0x0C, s.as_bytes())
}

fn der_integer_i32(n: i32) -> Vec<u8> {
    let bytes = n.to_be_bytes();
    // Minimal two's-complement DER INTEGER encoding.  Strip a leading byte only
    // when it is the sign extension of the byte that follows:
    //   0x00 prefix is redundant iff the next byte's high bit is 0 (positive).
    //   0xFF prefix is redundant iff the next byte's high bit is 1 (negative).
    let mut start = 0usize;
    while start < 3 {
        let hi = bytes[start];
        let next_msb = bytes[start + 1] & 0x80;
        // Strip the leading byte when it is a redundant sign extension.
        if (hi == 0x00 && next_msb == 0) || (hi == 0xFF && next_msb != 0) {
            start += 1;
        } else {
            break;
        }
    }
    der_tag(0x02, &bytes[start..])
}

fn encode_length(out: &mut Vec<u8>, len: usize) {
    if len < 128 {
        out.push(len as u8);
    } else if len < 256 {
        out.push(0x81);
        out.push(len as u8);
    } else {
        out.push(0x82);
        out.push((len >> 8) as u8);
        out.push((len & 0xFF) as u8);
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_http_service_principal() {
        let der = encode_krb5_principal_other_name(
            "EXAMPLE.COM",
            NT_SRV_HST,
            &["HTTP", "web.example.com"],
        )
        .unwrap();
        // Must start with SEQUENCE tag.
        assert_eq!(der[0], 0x30);
        // OID tag present somewhere near the start.
        assert_eq!(der[2], 0x06);
        // OID content matches id-pkinit-san.
        let oid_len = der[3] as usize;
        assert_eq!(&der[4..4 + oid_len], OID_PKINIT_SAN);
    }

    #[test]
    fn encode_ms_upn() {
        let der = encode_ms_upn_other_name("alice@EXAMPLE.COM").unwrap();
        assert_eq!(der[0], 0x30);
        assert_eq!(der[2], 0x06);
        let oid_len = der[3] as usize;
        assert_eq!(&der[4..4 + oid_len], OID_MS_SAN_UPN);
    }

    #[test]
    fn encode_principal_str_slash_gives_nt_srv_hst() {
        // "HTTP/web@REALM" → components ["HTTP", "web"], name_type=3
        let der = encode_principal_str_other_name("HTTP/web.example.com@EXAMPLE.COM").unwrap();
        assert!(der.len() > 10);
    }

    #[test]
    fn encode_principal_str_no_slash_gives_nt_principal() {
        let der = encode_principal_str_other_name("alice@EXAMPLE.COM").unwrap();
        assert!(der.len() > 10);
    }

    #[test]
    fn expand_template_with_dns_produces_one_per_san() {
        let dns = ["a.example.com", "b.example.com"];
        let results = expand_kpn_template("HTTP/{dns}@EXAMPLE.COM", &dns).unwrap();
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn expand_static_template_produces_one() {
        let dns = ["a.example.com", "b.example.com"];
        let results = expand_kpn_template("host/fixed.example.com@EXAMPLE.COM", &dns).unwrap();
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn expand_ms_upn_template_uses_first_dns() {
        let dns = ["web.example.com", "api.example.com"];
        let result = expand_ms_upn_template("{dns}@example.com", &dns).unwrap();
        assert!(result.is_some());
    }

    #[test]
    fn expand_ms_upn_static_ignores_dns() {
        let result = expand_ms_upn_template("service@example.com", &[]).unwrap();
        assert!(result.is_some());
    }

    #[test]
    fn expand_ms_upn_template_empty_dns_returns_none() {
        let result = expand_ms_upn_template("{dns}@example.com", &[]).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn missing_at_sign_returns_error() {
        assert!(encode_principal_str_other_name("no-at-sign").is_err());
        assert!(expand_kpn_template("HTTP/{dns}", &["x.example.com"]).is_err());
    }

    #[test]
    fn empty_realm_returns_error() {
        assert!(encode_krb5_principal_other_name("", NT_PRINCIPAL, &["user"]).is_err());
        assert!(encode_ms_upn_other_name("").is_err());
    }

    #[test]
    fn der_integer_i32_positive() {
        // 3 → 02 01 03
        let enc = der_integer_i32(3);
        assert_eq!(enc, &[0x02, 0x01, 0x03]);
    }

    #[test]
    fn der_integer_i32_needs_pad() {
        // 0x80 has high bit set → needs 0x00 pad: 02 02 00 80
        let enc = der_integer_i32(0x80);
        assert_eq!(enc, &[0x02, 0x02, 0x00, 0x80]);
    }
}
