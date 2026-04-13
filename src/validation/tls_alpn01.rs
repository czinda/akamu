//! tls-alpn-01 challenge validation (RFC 8737).
//!
//! Opens a TLS connection to `{domain}:443` with ALPN "acme-tls/1", captures
//! the presented certificate, and verifies:
//!   1. The SAN extension contains an entry matching the identifier: dNSName for
//!      DNS identifiers, iPAddress for IP identifiers (RFC 8738 §4).
//!   2. The id-pe-acmeIdentifier extension (OID 1.3.6.1.5.5.7.1.31, critical)
//!      is present and its value equals `SHA-256(keyAuthorization)`.
//!   3. The SAN extension contains exactly one GeneralName entry (RFC 8737 §3).

use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use synta_certificate::{default_data_hasher, DataHasher};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use crate::error::AcmeError;

/// Validate a tls-alpn-01 challenge.
///
/// * `id_type`  — `"dns"` or `"ip"`.
/// * `id_value` — the identifier value (DNS name or IP address string).
/// * `key_auth` — `{token}.{jwk_thumbprint}`.
///
/// For IP identifiers (RFC 8738 §4) the TLS SNI is sent as the reverse-DNS
/// form of the address (`n.n.n.n.in-addr.arpa` or nibble `.ip6.arpa`) rather
/// than the raw IP string.  The SAN check also uses the `iPAddress` general
/// name type (tag `0x87`) instead of `dNSName`.
pub async fn validate(id_type: &str, id_value: &str, key_auth: &str) -> Result<(), AcmeError> {
    validate_inner(id_type, id_value, key_auth, 443).await
}

/// Inner implementation that allows injecting a custom port for testing.
async fn validate_inner(
    id_type: &str,
    id_value: &str,
    key_auth: &str,
    port: u16,
) -> Result<(), AcmeError> {
    let expected_hash: [u8; 32] = default_data_hasher()
        .hash_data("sha256", key_auth.as_bytes())
        .map_err(|e| AcmeError::Crypto(format!("SHA-256: {e}")))?
        .try_into()
        .expect("SHA-256 always yields 32 bytes");

    // RFC 8738 §4: for IP identifiers the SNI MUST be the reverse-DNS name
    // of the address, not the raw IP string.
    let sni_string = if id_type == "ip" {
        ip_to_reverse_dns(id_value)?
    } else {
        id_value.to_string()
    };

    // Build a rustls ClientConfig that:
    //  - Accepts any server certificate (we do our own checking below).
    //  - Advertises ALPN "acme-tls/1" only.
    let crypto_provider = rustls::crypto::ring::default_provider();
    let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(crypto_provider))
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .map_err(|e| AcmeError::Tls(format!("rustls protocol config: {e}")))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyCert))
        .with_no_client_auth();

    config.alpn_protocols = vec![b"acme-tls/1".to_vec()];

    let connector = TlsConnector::from(Arc::new(config));

    // Resolve the server name (SNI).
    let server_name = ServerName::try_from(sni_string.clone())
        .map_err(|e| AcmeError::Tls(format!("invalid server name '{sni_string}': {e}")))?;

    // TCP connect to the actual IP / hostname (not the reverse-DNS SNI name).
    let tcp = TcpStream::connect((id_value, port))
        .await
        .map_err(|e| AcmeError::Connection(format!("TCP connect to {id_value}:{port}: {e}")))?;

    // TLS handshake (this also performs the ALPN negotiation).
    let tls_stream = connector
        .connect(server_name, tcp)
        .await
        .map_err(|e| AcmeError::Tls(format!("TLS handshake with {id_value}: {e}")))?;

    // Extract the peer certificate presented during the handshake.
    let (_, client_conn) = tls_stream.get_ref();
    let peer_certs = client_conn
        .peer_certificates()
        .ok_or_else(|| AcmeError::Tls("server presented no certificate".into()))?;

    let end_entity_der = peer_certs
        .first()
        .ok_or_else(|| AcmeError::Tls("server certificate chain is empty".into()))?
        .as_ref();

    verify_acme_cert(id_type, id_value, end_entity_der, &expected_hash)
}

/// Convert an IP address string to its reverse-DNS form per RFC 8738 §4.
///
/// IPv4: `1.2.3.4` → `4.3.2.1.in-addr.arpa`
/// IPv6: full nibble expansion → `<nibbles>.ip6.arpa`
fn ip_to_reverse_dns(ip_str: &str) -> Result<String, AcmeError> {
    if let Ok(ipv4) = ip_str.parse::<std::net::Ipv4Addr>() {
        let o = ipv4.octets();
        Ok(format!("{}.{}.{}.{}.in-addr.arpa", o[3], o[2], o[1], o[0]))
    } else if let Ok(ipv6) = ip_str.parse::<std::net::Ipv6Addr>() {
        let expanded = format!("{:032x}", u128::from(ipv6));
        let nibbles: String = expanded
            .chars()
            .rev()
            .flat_map(|c| [c, '.'])
            .collect::<String>()
            .trim_end_matches('.')
            .to_string();
        Ok(format!("{nibbles}.ip6.arpa"))
    } else {
        Err(AcmeError::Tls(format!(
            "tls-alpn-01: '{ip_str}' is not a valid IP address"
        )))
    }
}

// ── Certificate verification ──────────────────────────────────────────────────

/// Verify the presented certificate against the tls-alpn-01 requirements.
///
/// Checks (RFC 8737 §3 / RFC 8738 §4):
/// 1. The SAN extension contains the identifier: dNSName for DNS, iPAddress for IP.
/// 2. id-pe-acmeIdentifier extension is present and critical.
/// 3. Extension value = `OCTET STRING { expected_hash }`.
///    (The extnValue OCTET STRING wrapper is already stripped by the time we
///    see `ext_content`.)
/// 4. The SAN extension contains exactly one GeneralName entry (RFC 8737 §3).
fn verify_acme_cert(
    id_type: &str,
    identifier: &str,
    cert_der: &[u8],
    expected_hash: &[u8; 32],
) -> Result<(), AcmeError> {
    // OID 1.3.6.1.5.5.7.1.31 as DER — pre-computed.
    // Encoding: 06 08 2b 06 01 05 05 07 01 1f
    const ACME_ID_OID_DER: &[u8] = &[0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x1f];

    // OID 2.5.29.17 (subjectAltName) as DER — pre-computed.
    // Encoding: 06 03 55 1d 11
    const SAN_OID_DER: &[u8] = &[0x06, 0x03, 0x55, 0x1d, 0x11];

    // Walk the DER to find TBSCertificate → Extensions → the target extension.
    let (found_critical, ext_value) = find_extension_value(cert_der, ACME_ID_OID_DER)
        .map_err(|e| AcmeError::Tls(format!("cert parse for {identifier}: {e}")))?
        .ok_or_else(|| {
            AcmeError::IncorrectResponse(format!(
                "tls-alpn-01: certificate for '{identifier}' is missing id-pe-acmeIdentifier"
            ))
        })?;

    if !found_critical {
        return Err(AcmeError::IncorrectResponse(format!(
            "tls-alpn-01: id-pe-acmeIdentifier extension in '{identifier}' cert must be critical"
        )));
    }

    // The extension content (extnValue inner bytes) must be:
    //   OCTET STRING (tag 0x04, length 0x20) { <32 bytes> }
    // Per RFC 8737 §3: ACMEIdentifier ::= OCTET STRING (SIZE (32))
    if ext_value.len() != 34
        || ext_value[0] != 0x04   // OCTET STRING
        || ext_value[1] != 0x20   // length 32
        || &ext_value[2..] != expected_hash
    {
        return Err(AcmeError::IncorrectResponse(format!(
            "tls-alpn-01: id-pe-acmeIdentifier value mismatch in certificate for '{identifier}'"
        )));
    }

    // RFC 8737 §3 / RFC 8738 §4: The certificate MUST have exactly the
    // identifier being validated in its SAN extension — as dNSName for DNS
    // identifiers, or as iPAddress for IP identifiers.
    let (_, san_value) = find_extension_value(cert_der, SAN_OID_DER)
        .map_err(|e| AcmeError::Tls(format!("cert SAN parse for '{identifier}': {e}")))?
        .ok_or_else(|| {
            AcmeError::IncorrectResponse(format!(
                "tls-alpn-01: certificate for '{identifier}' is missing SAN extension"
            ))
        })?;

    // RFC 8737 §3: the certificate MUST contain exactly one entry in the SAN extension.
    let san_count = count_san_entries(san_value)
        .map_err(|e| AcmeError::Tls(format!("cert SAN count for '{identifier}': {e}")))?;
    if san_count != 1 {
        return Err(AcmeError::IncorrectResponse(format!(
            "tls-alpn-01: certificate for '{identifier}' must have exactly one SAN entry, found {san_count}"
        )));
    }

    if id_type == "ip" {
        verify_san_contains_ip(identifier, san_value).map_err(|reason| {
            AcmeError::IncorrectResponse(format!(
                "tls-alpn-01: certificate SAN does not match IP '{identifier}': {reason}"
            ))
        })?;
    } else {
        verify_san_contains_domain(identifier, san_value).map_err(|reason| {
            AcmeError::IncorrectResponse(format!(
                "tls-alpn-01: certificate SAN does not match '{identifier}': {reason}"
            ))
        })?;
    }

    Ok(())
}

/// Count the total number of GeneralName entries in a SAN extension value.
///
/// Used to enforce RFC 8737 §3's requirement that the certificate contains
/// exactly one SAN entry.
fn count_san_entries(san_seq: &[u8]) -> Result<usize, &'static str> {
    let seq_content = strip_sequence(san_seq)?;
    let mut remaining = seq_content;
    let mut count = 0usize;
    while !remaining.is_empty() {
        let (_, rest, _) = read_tlv(remaining)?;
        remaining = rest;
        count += 1;
    }
    Ok(count)
}

/// Check that `domain` appears as a dNSName ([2] IMPLICIT IA5String, tag 0x82)
/// in the raw SEQUENCE OF GeneralName bytes from the SAN extension value.
fn verify_san_contains_domain(domain: &str, san_seq: &[u8]) -> Result<(), &'static str> {
    // san_seq is the content of the SAN OCTET STRING — a SEQUENCE OF GeneralName.
    let seq_content = strip_sequence(san_seq)?;
    let mut remaining = seq_content;
    let mut found = false;
    while !remaining.is_empty() {
        let (tag, rest, content) = read_tlv(remaining)?;
        remaining = rest;
        // dNSName is [2] IMPLICIT IA5String → context-specific primitive tag 0x82.
        if tag == 0x82 {
            let name = std::str::from_utf8(content).map_err(|_| "dNSName is not valid UTF-8")?;
            if name.eq_ignore_ascii_case(domain) {
                found = true;
                break;
            }
        }
    }
    if found {
        Ok(())
    } else {
        Err("domain not present as dNSName in SAN")
    }
}

/// Check that `ip_str` appears as an iPAddress ([7] IMPLICIT OCTET STRING,
/// tag 0x87) in the raw SEQUENCE OF GeneralName bytes from the SAN extension
/// value.  Used by the IP-identifier validation path (RFC 8738 §4).
fn verify_san_contains_ip(ip_str: &str, san_seq: &[u8]) -> Result<(), &'static str> {
    // Parse the IP address to its raw bytes.
    let ip_bytes: Vec<u8> = if let Ok(ipv4) = ip_str.parse::<std::net::Ipv4Addr>() {
        ipv4.octets().to_vec()
    } else if let Ok(ipv6) = ip_str.parse::<std::net::Ipv6Addr>() {
        ipv6.octets().to_vec()
    } else {
        return Err("identifier is not a valid IP address");
    };

    let seq_content = strip_sequence(san_seq)?;
    let mut remaining = seq_content;
    while !remaining.is_empty() {
        let (tag, rest, content) = read_tlv(remaining)?;
        remaining = rest;
        // iPAddress is [7] IMPLICIT OCTET STRING → context-specific primitive tag 0x87.
        // IPv4: 4 bytes; IPv6: 16 bytes.
        if tag == 0x87 && content == ip_bytes.as_slice() {
            return Ok(());
        }
    }
    Err("IP address not present as iPAddress in SAN")
}

// ── Manual DER TLV walker ─────────────────────────────────────────────────────
//
// We walk the outer Certificate SEQUENCE by hand because synta's decoder
// requires knowing all field types at compile time.  The walk is minimal:
// we only need to find the Extensions sequence inside TBSCertificate.

/// Read a DER TLV header, returning `(tag, remaining_after_header, content)`.
fn read_tlv(der: &[u8]) -> Result<(u8, &[u8], &[u8]), &'static str> {
    if der.is_empty() {
        return Err("unexpected end of DER");
    }
    let tag = der[0];
    let (len, header_len) = decode_length(&der[1..]).ok_or("invalid DER length")?;
    let total = 1 + header_len + len;
    if der.len() < total {
        return Err("DER value truncated");
    }
    Ok((tag, &der[total..], &der[1 + header_len..total]))
}

fn decode_length(b: &[u8]) -> Option<(usize, usize)> {
    if b.is_empty() {
        return None;
    }
    if b[0] < 0x80 {
        return Some((b[0] as usize, 1));
    }
    let n = (b[0] & 0x7f) as usize;
    if n == 0 || n > 4 || b.len() < 1 + n {
        return None;
    }
    let mut len = 0usize;
    for &byte in &b[1..1 + n] {
        len = (len << 8) | byte as usize;
    }
    Some((len, 1 + n))
}

/// Strip a SEQUENCE tag and return its contents.
fn strip_sequence(der: &[u8]) -> Result<&[u8], &'static str> {
    let (tag, _, content) = read_tlv(der)?;
    if tag != 0x30 {
        return Err("expected SEQUENCE");
    }
    Ok(content)
}

/// Strip an OCTET STRING tag and return its inner bytes.
fn strip_octet_string(der: &[u8]) -> Result<&[u8], &'static str> {
    let (tag, _, content) = read_tlv(der)?;
    if tag != 0x04 {
        return Err("expected OCTET STRING");
    }
    Ok(content)
}

/// Skip a single TLV element and return the remaining slice.
fn skip_tlv(der: &[u8]) -> Result<&[u8], &'static str> {
    let (_, rest, _) = read_tlv(der)?;
    Ok(rest)
}

/// Check whether `haystack` starts with `needle`.
fn starts_with_oid(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.len() >= needle.len() && &haystack[..needle.len()] == needle
}

/// Walk a Certificate DER and find an extension by its OID DER bytes.
///
/// Returns `Some((critical, extn_value_content))` where `extn_value_content`
/// is the raw bytes *inside* the outer OCTET STRING wrapper (i.e. the actual
/// extension content ready for ASN.1 interpretation).
///
/// The Certificate structure:
/// ```text
/// Certificate  ::= SEQUENCE {
///   tbsCertificate   TBSCertificate,
///   signatureAlgorithm AlgorithmIdentifier,
///   signature        BIT STRING }
///
/// TBSCertificate ::= SEQUENCE {
///   version          [0] EXPLICIT INTEGER DEFAULT 0,
///   serialNumber     INTEGER,
///   signature        AlgorithmIdentifier,
///   issuer           Name,
///   validity         Validity,
///   subject          Name,
///   subjectPublicKeyInfo SubjectPublicKeyInfo,
///   issuerUniqueID   [1] IMPLICIT UniqueIdentifier OPTIONAL,
///   subjectUniqueID  [2] IMPLICIT UniqueIdentifier OPTIONAL,
///   extensions       [3] EXPLICIT Extensions OPTIONAL }
///
/// Extension ::= SEQUENCE {
///   extnID           OBJECT IDENTIFIER,
///   critical         BOOLEAN DEFAULT FALSE,
///   extnValue        OCTET STRING }
/// ```
fn find_extension_value<'a>(
    cert_der: &'a [u8],
    oid_der: &[u8],
) -> Result<Option<(bool, &'a [u8])>, &'static str> {
    // Certificate SEQUENCE
    let cert_seq = strip_sequence(cert_der)?;

    // TBSCertificate SEQUENCE (first element)
    let tbs_seq = strip_sequence(cert_seq)?;

    // Walk TBSCertificate fields to reach Extensions [3].
    let mut tbs = tbs_seq;

    // version [0] EXPLICIT
    if tbs.first() == Some(&0xa0) {
        tbs = skip_tlv(tbs)?;
    }
    // serialNumber
    tbs = skip_tlv(tbs)?;
    // signature AlgorithmIdentifier
    tbs = skip_tlv(tbs)?;
    // issuer Name
    tbs = skip_tlv(tbs)?;
    // validity Validity
    tbs = skip_tlv(tbs)?;
    // subject Name
    tbs = skip_tlv(tbs)?;
    // subjectPublicKeyInfo
    tbs = skip_tlv(tbs)?;
    // optional issuerUniqueID [1]
    if tbs.first() == Some(&0x81) {
        tbs = skip_tlv(tbs)?;
    }
    // optional subjectUniqueID [2]
    if tbs.first() == Some(&0x82) {
        tbs = skip_tlv(tbs)?;
    }
    // optional extensions [3] EXPLICIT
    if tbs.first() != Some(&0xa3) {
        return Ok(None); // no extensions
    }
    let (_, _, ext_wrapper) = read_tlv(tbs)?;
    // The [3] wraps a SEQUENCE OF Extension
    let extensions_seq = strip_sequence(ext_wrapper)?;

    let mut exts = extensions_seq;
    while !exts.is_empty() {
        // Each Extension is a SEQUENCE
        let (tag, rest, ext_content) = read_tlv(exts)?;
        if tag != 0x30 {
            return Err("expected Extension SEQUENCE");
        }
        exts = rest;

        // Extension fields: OID, [optional BOOLEAN critical], OCTET STRING
        let mut inner = ext_content;

        // OID
        let (oid_tag, after_oid, _oid_val) = read_tlv(inner)?;
        if oid_tag != 0x06 {
            return Err("expected OID in extension");
        }
        // Reconstruct the full OID TLV for comparison with oid_der.
        // oid_der already includes the tag+length prefix.
        let oid_tlv_len = inner.len() - after_oid.len();
        let oid_tlv = &inner[..oid_tlv_len];
        inner = after_oid;

        if !starts_with_oid(oid_tlv, oid_der) {
            continue; // wrong OID
        }

        // critical BOOLEAN (optional, default FALSE)
        let critical = if inner.first() == Some(&0x01) {
            let (_, after_bool, bool_val) = read_tlv(inner)?;
            inner = after_bool;
            bool_val.first() == Some(&0xff)
        } else {
            false
        };

        // extnValue OCTET STRING
        let content = strip_octet_string(inner)?;
        return Ok(Some((critical, content)));
    }

    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── decode_length ─────────────────────────────────────────────────────────

    #[test]
    fn decode_length_short_form() {
        assert_eq!(decode_length(&[0x00]), Some((0, 1)));
        assert_eq!(decode_length(&[0x01]), Some((1, 1)));
        assert_eq!(decode_length(&[0x7f]), Some((127, 1)));
    }

    #[test]
    fn decode_length_long_form_one_byte() {
        // 0x81 0x80 = 128
        assert_eq!(decode_length(&[0x81, 0x80]), Some((128, 2)));
        // 0x81 0xff = 255
        assert_eq!(decode_length(&[0x81, 0xff]), Some((255, 2)));
    }

    #[test]
    fn decode_length_long_form_two_bytes() {
        // 0x82 0x01 0x00 = 256
        assert_eq!(decode_length(&[0x82, 0x01, 0x00]), Some((256, 3)));
    }

    #[test]
    fn decode_length_empty_returns_none() {
        assert_eq!(decode_length(&[]), None);
    }

    #[test]
    fn decode_length_truncated_long_form_returns_none() {
        // 0x81 without a second byte
        assert_eq!(decode_length(&[0x81]), None);
    }

    #[test]
    fn decode_length_indefinite_form_returns_none() {
        // 0x80 = indefinite form (not supported)
        assert_eq!(decode_length(&[0x80]), None);
    }

    // ── read_tlv ─────────────────────────────────────────────────────────────

    #[test]
    fn read_tlv_simple_octet_string() {
        // 04 03 01 02 03 = OCTET STRING { 01 02 03 }
        let der = [0x04, 0x03, 0x01, 0x02, 0x03];
        let (tag, rest, content) = read_tlv(&der).unwrap();
        assert_eq!(tag, 0x04);
        assert!(rest.is_empty());
        assert_eq!(content, &[0x01, 0x02, 0x03]);
    }

    #[test]
    fn read_tlv_with_trailing_bytes() {
        let der = [0x02, 0x01, 0x42, 0xff]; // INTEGER { 0x42 } + trailing 0xff
        let (tag, rest, content) = read_tlv(&der).unwrap();
        assert_eq!(tag, 0x02);
        assert_eq!(rest, &[0xff]);
        assert_eq!(content, &[0x42]);
    }

    #[test]
    fn read_tlv_empty_returns_error() {
        assert!(read_tlv(&[]).is_err());
    }

    #[test]
    fn read_tlv_truncated_value_returns_error() {
        // 02 03 01 02 — says length 3, only 2 bytes of value
        assert!(read_tlv(&[0x02, 0x03, 0x01, 0x02]).is_err());
    }

    // ── strip_sequence / strip_octet_string / skip_tlv ────────────────────────

    #[test]
    fn strip_sequence_ok() {
        // 30 02 01 02 = SEQUENCE { 01 02 }
        let der = [0x30, 0x02, 0x01, 0x02];
        let content = strip_sequence(&der).unwrap();
        assert_eq!(content, &[0x01, 0x02]);
    }

    #[test]
    fn strip_sequence_wrong_tag_returns_error() {
        let der = [0x04, 0x01, 0xff];
        assert!(strip_sequence(&der).is_err());
    }

    #[test]
    fn strip_octet_string_ok() {
        let der = [0x04, 0x02, 0xde, 0xad];
        let content = strip_octet_string(&der).unwrap();
        assert_eq!(content, &[0xde, 0xad]);
    }

    #[test]
    fn strip_octet_string_wrong_tag_returns_error() {
        let der = [0x02, 0x01, 0x00];
        assert!(strip_octet_string(&der).is_err());
    }

    #[test]
    fn skip_tlv_advances_past_element() {
        // 02 01 42 03 01 FF = INTEGER { 0x42 }, then bogus
        let der = [0x02, 0x01, 0x42, 0x03, 0x01, 0xff];
        let rest = skip_tlv(&der).unwrap();
        assert_eq!(rest, &[0x03, 0x01, 0xff]);
    }

    // ── starts_with_oid ───────────────────────────────────────────────────────

    #[test]
    fn starts_with_oid_matching() {
        let needle = &[0x06, 0x03, 0x55, 0x04, 0x03];
        let haystack = &[0x06, 0x03, 0x55, 0x04, 0x03, 0xff];
        assert!(starts_with_oid(haystack, needle));
    }

    #[test]
    fn starts_with_oid_not_matching() {
        let needle = &[0x06, 0x03, 0x55, 0x04, 0x03];
        let haystack = &[0x06, 0x03, 0x55, 0x04, 0x06];
        assert!(!starts_with_oid(haystack, needle));
    }

    #[test]
    fn starts_with_oid_too_short() {
        let needle = &[0x06, 0x03, 0x55, 0x04, 0x03];
        let haystack = &[0x06, 0x03];
        assert!(!starts_with_oid(haystack, needle));
    }

    // ── find_extension_value / verify_acme_cert ───────────────────────────────

    #[test]
    fn find_extension_value_invalid_cert_returns_error() {
        let oid_der = &[0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x1f];
        assert!(find_extension_value(b"bad DER", oid_der).is_err());
    }

    #[test]
    fn verify_acme_cert_invalid_der_returns_error() {
        let result = verify_acme_cert("dns", "example.com", b"bad cert", &[0u8; 32]);
        assert!(result.is_err());
    }

    #[test]
    fn verify_acme_cert_correct_extension_succeeds() {
        // Build a minimal fake certificate DER with the id-pe-acmeIdentifier extension.
        // This is a hand-crafted DER structure; real certs use synta_certificate.
        // hash = SHA-256 of "test-key-auth"
        let key_auth = "test-key-auth";
        let expected_hash: [u8; 32] = synta_certificate::default_data_hasher()
            .hash_data("sha256", key_auth.as_bytes())
            .expect("SHA-256")
            .try_into()
            .expect("SHA-256 always yields 32 bytes");

        // Build the extension value: OCTET STRING { <hash> }
        let mut ext_value = vec![0x04, 0x20]; // OCTET STRING, length 32
        ext_value.extend_from_slice(&expected_hash);

        // Extension SEQUENCE: OID + critical TRUE + OCTET STRING { ext_value }
        // OID: 1.3.6.1.5.5.7.1.31 = 06 08 2b 06 01 05 05 07 01 1f
        let oid_bytes: &[u8] = &[0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x1f];
        let critical_bytes: &[u8] = &[0x01, 0x01, 0xff]; // BOOLEAN TRUE
                                                         // Wrap ext_value in OCTET STRING wrapper
        let mut ext_val_wrapper = vec![0x04u8, ext_value.len() as u8];
        ext_val_wrapper.extend_from_slice(&ext_value);
        let ext_inner_len = oid_bytes.len() + critical_bytes.len() + ext_val_wrapper.len();
        let mut ext_seq = vec![0x30, ext_inner_len as u8];
        ext_seq.extend_from_slice(oid_bytes);
        ext_seq.extend_from_slice(critical_bytes);
        ext_seq.extend_from_slice(&ext_val_wrapper);

        // SAN extension: OID 2.5.29.17 + OCTET STRING { SEQUENCE { dNSName "example.com" } }
        // dNSName [2] IMPLICIT IA5String, tag 0x82, "example.com" = 11 bytes
        let domain_bytes: &[u8] = b"example.com";
        let san_dns_len = domain_bytes.len() as u8; // 11 = 0x0b
        let mut san_dns = vec![0x82, san_dns_len];
        san_dns.extend_from_slice(domain_bytes);
        // SEQUENCE { dNSName }
        let mut san_inner_seq = vec![0x30, san_dns.len() as u8];
        san_inner_seq.extend_from_slice(&san_dns);
        // extnValue OCTET STRING
        let mut san_extn_value = vec![0x04, san_inner_seq.len() as u8];
        san_extn_value.extend_from_slice(&san_inner_seq);
        // Extension SEQUENCE: OID + OCTET STRING
        let san_oid_bytes: &[u8] = &[0x06, 0x03, 0x55, 0x1d, 0x11];
        let san_ext_inner = san_oid_bytes.len() + san_extn_value.len();
        let mut san_ext_seq = vec![0x30, san_ext_inner as u8];
        san_ext_seq.extend_from_slice(san_oid_bytes);
        san_ext_seq.extend_from_slice(&san_extn_value);

        // Extensions SEQUENCE OF (acmeIdentifier + SAN)
        let exts_inner_len = ext_seq.len() + san_ext_seq.len();
        let mut exts_seq = vec![0x30, exts_inner_len as u8];
        exts_seq.extend_from_slice(&ext_seq);
        exts_seq.extend_from_slice(&san_ext_seq);

        // Extensions [3] EXPLICIT
        let mut exts_a3 = vec![0xa3, exts_seq.len() as u8];
        exts_a3.extend_from_slice(&exts_seq);

        // Minimal fields for TBSCertificate (some are required):
        // version [0], serial, sig alg, issuer, validity, subject, SPKI, extensions
        // We use minimal/dummy placeholders since we only care about extension parsing.
        let version_a0: &[u8] = &[0xa0, 0x03, 0x02, 0x01, 0x02]; // version v3
        let serial: &[u8] = &[0x02, 0x01, 0x01]; // INTEGER { 1 }
        let sig_alg: &[u8] = &[
            0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02,
        ]; // ecdsaWithSHA256
        let issuer: &[u8] = &[0x30, 0x00]; // empty SEQUENCE
        let validity: &[u8] = &[0x30, 0x00]; // empty SEQUENCE
        let subject: &[u8] = &[0x30, 0x00]; // empty SEQUENCE
        let spki: &[u8] = &[0x30, 0x00]; // empty SEQUENCE

        let tbs_len = version_a0.len()
            + serial.len()
            + sig_alg.len()
            + issuer.len()
            + validity.len()
            + subject.len()
            + spki.len()
            + exts_a3.len();
        let mut tbs = vec![0x30, tbs_len as u8];
        tbs.extend_from_slice(version_a0);
        tbs.extend_from_slice(serial);
        tbs.extend_from_slice(sig_alg);
        tbs.extend_from_slice(issuer);
        tbs.extend_from_slice(validity);
        tbs.extend_from_slice(subject);
        tbs.extend_from_slice(spki);
        tbs.extend_from_slice(&exts_a3);

        // Outer Certificate SEQUENCE: TBS + signature alg + BIT STRING
        let sig_alg2: &[u8] = &[
            0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02,
        ];
        let bit_string: &[u8] = &[0x03, 0x01, 0x00]; // BIT STRING with 0 unused bits, empty

        let cert_inner_len = tbs.len() + sig_alg2.len() + bit_string.len();
        let mut cert_der = vec![0x30, cert_inner_len as u8];
        cert_der.extend_from_slice(&tbs);
        cert_der.extend_from_slice(sig_alg2);
        cert_der.extend_from_slice(bit_string);

        let result = verify_acme_cert("dns", "example.com", &cert_der, &expected_hash);
        assert!(
            result.is_ok(),
            "verify_acme_cert should succeed: {result:?}"
        );
    }

    #[test]
    fn verify_acme_cert_wrong_hash_returns_error() {
        let key_auth = "test-key-auth";
        let correct_hash: [u8; 32] = synta_certificate::default_data_hasher()
            .hash_data("sha256", key_auth.as_bytes())
            .expect("SHA-256")
            .try_into()
            .expect("SHA-256 always yields 32 bytes");
        let wrong_hash = [0u8; 32];

        // Re-use the same cert construction with correct_hash in the extension
        let mut ext_value = vec![0x04, 0x20];
        ext_value.extend_from_slice(&correct_hash);
        let oid_bytes: &[u8] = &[0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x1f];
        let critical_bytes: &[u8] = &[0x01, 0x01, 0xff];
        let mut ext_val_wrapper = vec![0x04u8, ext_value.len() as u8];
        ext_val_wrapper.extend_from_slice(&ext_value);
        let ext_inner_len = oid_bytes.len() + critical_bytes.len() + ext_val_wrapper.len();
        let mut ext_seq = vec![0x30, ext_inner_len as u8];
        ext_seq.extend_from_slice(oid_bytes);
        ext_seq.extend_from_slice(critical_bytes);
        ext_seq.extend_from_slice(&ext_val_wrapper);
        let mut exts_seq = vec![0x30, ext_seq.len() as u8];
        exts_seq.extend_from_slice(&ext_seq);
        let mut exts_a3 = vec![0xa3, exts_seq.len() as u8];
        exts_a3.extend_from_slice(&exts_seq);
        let version_a0: &[u8] = &[0xa0, 0x03, 0x02, 0x01, 0x02];
        let serial: &[u8] = &[0x02, 0x01, 0x01];
        let sig_alg: &[u8] = &[
            0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02,
        ];
        let empty_seq: &[u8] = &[0x30, 0x00];
        let tbs_len =
            version_a0.len() + serial.len() + sig_alg.len() + 4 * empty_seq.len() + exts_a3.len();
        let mut tbs = vec![0x30, tbs_len as u8];
        tbs.extend_from_slice(version_a0);
        tbs.extend_from_slice(serial);
        tbs.extend_from_slice(sig_alg);
        for _ in 0..4 {
            tbs.extend_from_slice(empty_seq);
        }
        tbs.extend_from_slice(&exts_a3);
        let sig_alg2: &[u8] = &[
            0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02,
        ];
        let bit_string: &[u8] = &[0x03, 0x01, 0x00];
        let cert_inner_len = tbs.len() + sig_alg2.len() + bit_string.len();
        let mut cert_der = vec![0x30, cert_inner_len as u8];
        cert_der.extend_from_slice(&tbs);
        cert_der.extend_from_slice(sig_alg2);
        cert_der.extend_from_slice(bit_string);

        // Verify with wrong_hash — should fail
        let result = verify_acme_cert("dns", "example.com", &cert_der, &wrong_hash);
        assert!(result.is_err(), "should fail with wrong hash");
    }

    #[test]
    fn verify_acme_cert_missing_extension_returns_error() {
        // Cert with no extensions
        let version_a0: &[u8] = &[0xa0, 0x03, 0x02, 0x01, 0x02];
        let serial: &[u8] = &[0x02, 0x01, 0x01];
        let sig_alg: &[u8] = &[
            0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02,
        ];
        let empty_seq: &[u8] = &[0x30, 0x00];
        let tbs_len = version_a0.len() + serial.len() + sig_alg.len() + 4 * empty_seq.len();
        let mut tbs = vec![0x30, tbs_len as u8];
        tbs.extend_from_slice(version_a0);
        tbs.extend_from_slice(serial);
        tbs.extend_from_slice(sig_alg);
        for _ in 0..4 {
            tbs.extend_from_slice(empty_seq);
        }
        let sig_alg2: &[u8] = &[
            0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02,
        ];
        let bit_string: &[u8] = &[0x03, 0x01, 0x00];
        let cert_inner_len = tbs.len() + sig_alg2.len() + bit_string.len();
        let mut cert_der = vec![0x30, cert_inner_len as u8];
        cert_der.extend_from_slice(&tbs);
        cert_der.extend_from_slice(sig_alg2);
        cert_der.extend_from_slice(bit_string);

        let result = verify_acme_cert("dns", "example.com", &cert_der, &[0u8; 32]);
        assert!(result.is_err(), "should fail when extension is missing");
    }

    #[test]
    fn verify_acme_cert_non_critical_extension_returns_error() {
        // Same as correct cert but without the critical BOOLEAN
        let expected_hash = [0u8; 32];
        let mut ext_value = vec![0x04, 0x20];
        ext_value.extend_from_slice(&expected_hash);
        let oid_bytes: &[u8] = &[0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x1f];
        let mut ext_val_wrapper = vec![0x04u8, ext_value.len() as u8];
        ext_val_wrapper.extend_from_slice(&ext_value);
        // No critical field this time
        let ext_inner_len = oid_bytes.len() + ext_val_wrapper.len();
        let mut ext_seq = vec![0x30, ext_inner_len as u8];
        ext_seq.extend_from_slice(oid_bytes);
        ext_seq.extend_from_slice(&ext_val_wrapper);
        let mut exts_seq = vec![0x30, ext_seq.len() as u8];
        exts_seq.extend_from_slice(&ext_seq);
        let mut exts_a3 = vec![0xa3, exts_seq.len() as u8];
        exts_a3.extend_from_slice(&exts_seq);
        let version_a0: &[u8] = &[0xa0, 0x03, 0x02, 0x01, 0x02];
        let serial: &[u8] = &[0x02, 0x01, 0x01];
        let sig_alg: &[u8] = &[
            0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02,
        ];
        let empty_seq: &[u8] = &[0x30, 0x00];
        let tbs_len =
            version_a0.len() + serial.len() + sig_alg.len() + 4 * empty_seq.len() + exts_a3.len();
        let mut tbs = vec![0x30, tbs_len as u8];
        tbs.extend_from_slice(version_a0);
        tbs.extend_from_slice(serial);
        tbs.extend_from_slice(sig_alg);
        for _ in 0..4 {
            tbs.extend_from_slice(empty_seq);
        }
        tbs.extend_from_slice(&exts_a3);
        let sig_alg2: &[u8] = &[
            0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02,
        ];
        let bit_string: &[u8] = &[0x03, 0x01, 0x00];
        let cert_inner_len = tbs.len() + sig_alg2.len() + bit_string.len();
        let mut cert_der = vec![0x30, cert_inner_len as u8];
        cert_der.extend_from_slice(&tbs);
        cert_der.extend_from_slice(sig_alg2);
        cert_der.extend_from_slice(bit_string);

        let result = verify_acme_cert("dns", "example.com", &cert_der, &expected_hash);
        assert!(
            result.is_err(),
            "should fail when extension is not critical"
        );
    }

    /// Covers find_extension_value line 286 (`continue; // wrong OID`).
    ///
    /// Build a certificate with two extensions: BasicConstraints (wrong OID) first,
    /// then id-pe-acmeIdentifier (correct OID) second. find_extension_value must
    /// skip the first extension via `continue` and return the second.
    #[test]
    fn find_extension_value_skips_non_matching_oid() {
        use synta::{Encode, Encoder, Encoding, ObjectIdentifier, OctetString};
        use synta_certificate::{
            acme_types::Authorization, encode_basic_constraints, BackendPrivateKey,
            CertificateBuilder, NameBuilder, PrivateKey as _,
        };

        let key = BackendPrivateKey::generate_ec("P-256").unwrap();
        let spki = key.public_key().unwrap().spki_der().to_vec();
        let name_der = NameBuilder::new()
            .common_name("example.com")
            .build()
            .unwrap();
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let not_before =
            synta_certificate::parse_time(&crate::ca::init::unix_to_generalized_time(now_secs))
                .unwrap();
        let not_after = synta_certificate::parse_time(&crate::ca::init::unix_to_generalized_time(
            now_secs + 86400,
        ))
        .unwrap();

        // BasicConstraints extension (wrong OID — must be skipped via `continue`)
        let bc = encode_basic_constraints(false, None).unwrap();

        // ACME id-pe-acmeIdentifier extension (correct OID — must be found)
        let digest = [0xab_u8; 32];
        let auth = Authorization::new_unchecked(OctetString::new(digest.to_vec()));
        let auth_der = auth.to_der().unwrap();

        let signer = key.as_signer("sha256");
        let cert_der = CertificateBuilder::new()
            .issuer_name(&name_der)
            .subject_name(&name_der)
            .public_key_der(&spki)
            .serial_number(synta::Integer::from_i64(1))
            .not_valid_before(not_before)
            .not_valid_after(not_after)
            .add_extension_oid(synta_certificate::oids::BASIC_CONSTRAINTS, false, &bc)
            .add_extension_oid(synta_certificate::oids::PE_ACME_IDENTIFIER, true, &auth_der)
            .sign(&signer)
            .unwrap();

        // Encode the ACME OID to DER using synta (produces 06 08 2b 06 01 05 05 07 01 1f)
        let acme_oid = ObjectIdentifier::new(synta_certificate::oids::PE_ACME_IDENTIFIER).unwrap();
        let mut enc = Encoder::new(Encoding::Der);
        acme_oid.encode(&mut enc).unwrap();
        let acme_oid_der = enc.finish().unwrap();

        let result = find_extension_value(&cert_der, &acme_oid_der);
        assert!(result.is_ok(), "expected Ok, got: {result:?}");
        assert!(
            result.unwrap().is_some(),
            "expected Some for the ACME extension"
        );
    }

    /// Covers find_extension_value line 303 (`Ok(None)`).
    ///
    /// Build a certificate with only BasicConstraints — no ACME extension.
    /// find_extension_value iterates all extensions, finds no match, and returns Ok(None).
    #[test]
    fn find_extension_value_no_matching_oid_returns_none() {
        use synta::{Encode, Encoder, Encoding, ObjectIdentifier};
        use synta_certificate::{
            encode_basic_constraints, BackendPrivateKey, CertificateBuilder, NameBuilder,
            PrivateKey as _,
        };

        let key = BackendPrivateKey::generate_ec("P-256").unwrap();
        let spki = key.public_key().unwrap().spki_der().to_vec();
        let name_der = NameBuilder::new()
            .common_name("example.com")
            .build()
            .unwrap();
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let not_before =
            synta_certificate::parse_time(&crate::ca::init::unix_to_generalized_time(now_secs))
                .unwrap();
        let not_after = synta_certificate::parse_time(&crate::ca::init::unix_to_generalized_time(
            now_secs + 86400,
        ))
        .unwrap();

        // Only BasicConstraints — no ACME extension
        let bc = encode_basic_constraints(false, None).unwrap();
        let signer = key.as_signer("sha256");
        let cert_der = CertificateBuilder::new()
            .issuer_name(&name_der)
            .subject_name(&name_der)
            .public_key_der(&spki)
            .serial_number(synta::Integer::from_i64(1))
            .not_valid_before(not_before)
            .not_valid_after(not_after)
            .add_extension_oid(synta_certificate::oids::BASIC_CONSTRAINTS, false, &bc)
            .sign(&signer)
            .unwrap();

        // Encode the ACME OID to DER using synta (produces 06 08 2b 06 01 05 05 07 01 1f)
        let acme_oid = ObjectIdentifier::new(synta_certificate::oids::PE_ACME_IDENTIFIER).unwrap();
        let mut enc = Encoder::new(Encoding::Der);
        acme_oid.encode(&mut enc).unwrap();
        let acme_oid_der = enc.finish().unwrap();

        let result = find_extension_value(&cert_der, &acme_oid_der);
        assert!(result.is_ok(), "should not error: {result:?}");
        assert!(
            result.unwrap().is_none(),
            "should return None when ACME extension is absent"
        );
    }

    // ── AcceptAnyCert ─────────────────────────────────────────────────────────

    #[test]
    fn accept_any_cert_supported_schemes_not_empty() {
        let verifier = AcceptAnyCert;
        let schemes = verifier.supported_verify_schemes();
        assert!(!schemes.is_empty());
    }

    /// AcceptAnyCert::verify_server_cert always returns Ok.
    /// Covers tls_alpn01.rs lines 646-655.
    #[test]
    fn accept_any_cert_verify_server_cert_returns_ok() {
        use rustls::pki_types::UnixTime;
        let verifier = AcceptAnyCert;
        let dummy_cert = CertificateDer::from(vec![0u8; 4]);
        let server_name = ServerName::try_from("example.com").unwrap();
        let result =
            verifier.verify_server_cert(&dummy_cert, &[], &server_name, &[], UnixTime::now());
        assert!(result.is_ok(), "verify_server_cert should always return Ok");
    }

    /// validate() fails with Tls error when given an invalid server name.
    /// Covers tls_alpn01.rs (ServerName::try_from error path).
    #[tokio::test]
    async fn validate_invalid_server_name_returns_error() {
        // An empty string is not a valid DNS name.
        let result = validate("dns", "", "token.thumbprint").await;
        assert!(result.is_err(), "expected error for invalid server name");
        match result.unwrap_err() {
            crate::error::AcmeError::Tls(_) => {}
            other => panic!("expected Tls error, got {other:?}"),
        }
    }

    /// validate() fails with Connection error when IP is unreachable.
    /// Covers tls_alpn01.rs (TCP connect error path via IP identifier).
    #[tokio::test]
    async fn validate_connection_refused_returns_error() {
        // 127.0.0.1:443 will be immediately refused on a test machine (no TLS server).
        let result = validate("ip", "127.0.0.1", "token.thumbprint").await;
        assert!(
            result.is_err(),
            "expected connection error for unreachable host"
        );
        // Should be either Connection or Tls error.
        match result.unwrap_err() {
            crate::error::AcmeError::Connection(_) | crate::error::AcmeError::Tls(_) => {}
            other => panic!("expected Connection or Tls error, got {other:?}"),
        }
    }

    /// Covers tls_alpn01.rs line 248 — `tbs = skip_tlv(tbs)?` for issuerUniqueID [1].
    ///
    /// Builds a minimal raw cert DER with an issuerUniqueID [1] field (tag 0x81) before
    /// the extensions [3] wrapper.  synta CertificateBuilder cannot produce issuerUniqueID,
    /// so raw bytes are used.  The OID is encoded via synta API.
    #[test]
    fn find_extension_value_skips_issuer_unique_id() {
        use synta::{Encode, Encoder, Encoding, ObjectIdentifier};
        use synta_certificate::oids;

        // TBSCertificate fields (6 mandatory skipped as INTEGER 0):
        let mandatory: &[u8] = &[
            0x02, 0x01, 0x00, // version (skipped — no [0] tag so code jumps to serial)
            0x02, 0x01, 0x00, // serialNumber
            0x02, 0x01, 0x00, // signature
            0x02, 0x01, 0x00, // issuer
            0x02, 0x01, 0x00, // validity
            0x02, 0x01,
            0x00, // subject
                  // subjectPublicKeyInfo (6th mandatory skip)
        ];
        // issuerUniqueID [1] IMPLICIT { 0xFF } — tag 0x81, length 1
        let issuer_uid: &[u8] = &[0x81, 0x01, 0xff];
        // extensions [3] EXPLICIT { SEQUENCE {} } — empty extension list → returns Ok(None)
        let exts: &[u8] = &[0xa3, 0x02, 0x30, 0x00];

        let tbs_content_len = mandatory.len() + issuer_uid.len() + exts.len();
        let mut tbs = vec![0x30, tbs_content_len as u8];
        tbs.extend_from_slice(mandatory);
        tbs.extend_from_slice(issuer_uid);
        tbs.extend_from_slice(exts);

        let mut cert = vec![0x30, tbs.len() as u8];
        cert.extend_from_slice(&tbs);

        let acme_oid = ObjectIdentifier::new(oids::PE_ACME_IDENTIFIER).unwrap();
        let mut enc = Encoder::new(Encoding::Der);
        acme_oid.encode(&mut enc).unwrap();
        let acme_oid_der = enc.finish().unwrap();

        // Should not error — returns Ok(None) because extensions list is empty.
        let result = find_extension_value(&cert, &acme_oid_der);
        assert!(
            result.is_ok(),
            "expected Ok for cert with issuerUniqueID: {result:?}"
        );
        assert!(
            result.unwrap().is_none(),
            "expected None — no matching extension"
        );
    }

    /// Covers tls_alpn01.rs line 252 — `tbs = skip_tlv(tbs)?` for subjectUniqueID [2].
    ///
    /// Same structure but uses tag 0x82 for subjectUniqueID.
    #[test]
    fn find_extension_value_skips_subject_unique_id() {
        use synta::{Encode, Encoder, Encoding, ObjectIdentifier};
        use synta_certificate::oids;

        let mandatory: &[u8] = &[
            0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x02, 0x01,
            0x00, 0x02, 0x01, 0x00,
        ];
        // subjectUniqueID [2] IMPLICIT { 0xFF } — tag 0x82, length 1
        let subject_uid: &[u8] = &[0x82, 0x01, 0xff];
        let exts: &[u8] = &[0xa3, 0x02, 0x30, 0x00];

        let tbs_content_len = mandatory.len() + subject_uid.len() + exts.len();
        let mut tbs = vec![0x30, tbs_content_len as u8];
        tbs.extend_from_slice(mandatory);
        tbs.extend_from_slice(subject_uid);
        tbs.extend_from_slice(exts);

        let mut cert = vec![0x30, tbs.len() as u8];
        cert.extend_from_slice(&tbs);

        let acme_oid = ObjectIdentifier::new(oids::PE_ACME_IDENTIFIER).unwrap();
        let mut enc = Encoder::new(Encoding::Der);
        acme_oid.encode(&mut enc).unwrap();
        let acme_oid_der = enc.finish().unwrap();

        let result = find_extension_value(&cert, &acme_oid_der);
        assert!(
            result.is_ok(),
            "expected Ok for cert with subjectUniqueID: {result:?}"
        );
        assert!(
            result.unwrap().is_none(),
            "expected None — no matching extension"
        );
    }

    /// Covers tls_alpn01.rs line 267 — `return Err("expected Extension SEQUENCE")`.
    ///
    /// The extensions SEQUENCE contains an INTEGER (tag 0x02) instead of a SEQUENCE
    /// (tag 0x30).  Uses synta API to encode the search OID; the certificate bytes
    /// are crafted only because no valid API produces malformed extension data.
    #[test]
    fn find_extension_value_non_sequence_in_extensions_returns_err() {
        use synta::{Encode, Encoder, Encoding, ObjectIdentifier};
        use synta_certificate::oids;

        // Build a minimal fake DER structure:
        //   SEQUENCE {                        -- outer Certificate
        //     SEQUENCE {                      -- TBSCertificate
        //       INTEGER 0  (×6 fake fields)   -- serial, sigAlg, issuer, validity, subject, spki
        //       [3] {                         -- extensions [3] EXPLICIT
        //         SEQUENCE {                  -- SEQUENCE OF Extension
        //           INTEGER 0                 -- ← NOT a SEQUENCE → triggers line 267
        //         }
        //       }
        //     }
        //   }
        let tbs_content: Vec<u8> = {
            let mut v = Vec::new();
            for _ in 0..6 {
                v.extend_from_slice(&[0x02, 0x01, 0x00]); // INTEGER 0
            }
            v.extend_from_slice(&[0xa3, 0x05, 0x30, 0x03, 0x02, 0x01, 0x00]);
            v
        };
        let mut tbs = vec![0x30, tbs_content.len() as u8];
        tbs.extend_from_slice(&tbs_content);
        let mut cert = vec![0x30, tbs.len() as u8];
        cert.extend_from_slice(&tbs);

        // Use synta API to encode the OID passed to find_extension_value.
        let acme_oid = ObjectIdentifier::new(oids::PE_ACME_IDENTIFIER).unwrap();
        let mut enc = Encoder::new(Encoding::Der);
        acme_oid.encode(&mut enc).unwrap();
        let acme_oid_der = enc.finish().unwrap();

        let result = find_extension_value(&cert, &acme_oid_der);
        assert!(
            result.is_err(),
            "expected Err for non-SEQUENCE extension element: {result:?}"
        );
    }

    /// Covers tls_alpn01.rs line 277 — `return Err("expected OID in extension")`.
    ///
    /// An extension SEQUENCE's first element is an INTEGER (tag 0x02) instead of an
    /// OID (tag 0x06).  Uses synta API to encode the search OID.
    #[test]
    fn find_extension_value_non_oid_first_element_returns_err() {
        use synta::{Encode, Encoder, Encoding, ObjectIdentifier};
        use synta_certificate::oids;

        // extensions content: SEQUENCE { SEQUENCE { INTEGER ... } }
        //                                           ↑ first element is INTEGER, not OID
        let tbs_content: Vec<u8> = {
            let mut v = Vec::new();
            for _ in 0..6 {
                v.extend_from_slice(&[0x02, 0x01, 0x00]); // INTEGER 0
            }
            // [3] EXPLICIT { SEQUENCE { SEQUENCE { INTEGER(3 bytes) } } }
            v.extend_from_slice(&[
                0xa3, 0x09, 0x30, 0x07, 0x30, 0x05, 0x02, 0x03, 0x00, 0x00, 0x00,
            ]);
            v
        };
        let mut tbs = vec![0x30, tbs_content.len() as u8];
        tbs.extend_from_slice(&tbs_content);
        let mut cert = vec![0x30, tbs.len() as u8];
        cert.extend_from_slice(&tbs);

        let acme_oid = ObjectIdentifier::new(oids::PE_ACME_IDENTIFIER).unwrap();
        let mut enc = Encoder::new(Encoding::Der);
        acme_oid.encode(&mut enc).unwrap();
        let acme_oid_der = enc.finish().unwrap();

        let result = find_extension_value(&cert, &acme_oid_der);
        assert!(
            result.is_err(),
            "expected Err for non-OID first element in extension: {result:?}"
        );
    }

    // ── TLS server helpers for validate_inner integration tests ───────────────

    /// Build a minimal self-signed certificate DER using synta.
    /// No ACME extension — keeps the cert valid for use in rustls server configs.
    fn build_simple_test_cert(key: &synta_certificate::BackendPrivateKey) -> Vec<u8> {
        use synta_certificate::{CertificateBuilder, NameBuilder, PrivateKey as _};

        let spki = key.public_key().unwrap().spki_der().to_vec();
        let name_der = NameBuilder::new().common_name("acme-test").build().unwrap();
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let not_before =
            synta_certificate::parse_time(&crate::ca::init::unix_to_generalized_time(now_secs))
                .unwrap();
        let not_after = synta_certificate::parse_time(&crate::ca::init::unix_to_generalized_time(
            now_secs + 86400,
        ))
        .unwrap();
        let signer = key.as_signer("sha256");
        CertificateBuilder::new()
            .issuer_name(&name_der)
            .subject_name(&name_der)
            .public_key_der(&spki)
            .serial_number(synta::Integer::from_i64(1))
            .not_valid_before(not_before)
            .not_valid_after(not_after)
            .sign(&signer)
            .unwrap()
    }

    /// Start a local TLS server on a random port, presenting `cert_der` signed by
    /// `key`, with ALPN "acme-tls/1".  Uses TLS 1.3 (the default).
    /// Returns the bound port.
    async fn start_acme_tls13_server(
        cert_der: Vec<u8>,
        key: &synta_certificate::BackendPrivateKey,
    ) -> u16 {
        use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
        use tokio::net::TcpListener;
        use tokio_rustls::TlsAcceptor;

        let pkcs8_der = key.to_der().unwrap();
        let private_key =
            rustls::pki_types::PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(pkcs8_der));
        let cert = CertificateDer::from(cert_der);

        let mut server_config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert], private_key)
        .unwrap();
        server_config.alpn_protocols = vec![b"acme-tls/1".to_vec()];

        let acceptor = TlsAcceptor::from(Arc::new(server_config));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        tokio::spawn(async move {
            if let Ok((stream, _)) = listener.accept().await {
                let _ = acceptor.accept(stream).await;
            }
        });
        port
    }

    /// Start a local TLS 1.2-only server on a random port.
    /// Returns the bound port.
    async fn start_acme_tls12_server(
        cert_der: Vec<u8>,
        key: &synta_certificate::BackendPrivateKey,
    ) -> u16 {
        use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
        use tokio::net::TcpListener;
        use tokio_rustls::TlsAcceptor;

        let pkcs8_der = key.to_der().unwrap();
        let private_key =
            rustls::pki_types::PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(pkcs8_der));
        let cert = CertificateDer::from(cert_der);

        let mut server_config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS12])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert], private_key)
        .unwrap();
        server_config.alpn_protocols = vec![b"acme-tls/1".to_vec()];

        let acceptor = TlsAcceptor::from(Arc::new(server_config));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        tokio::spawn(async move {
            if let Ok((stream, _)) = listener.accept().await {
                let _ = acceptor.accept(stream).await;
            }
        });
        port
    }

    /// Covers validate_inner TLS handshake lines 52-68 and verify_tls13_signature
    /// (lines 903-910).  The TLS 1.3 handshake succeeds; the server presents a cert
    /// without the ACME extension, so verify_acme_cert returns IncorrectResponse.
    #[tokio::test]
    async fn validate_inner_tls13_handshake_covers_lines_52_68() {
        use synta_certificate::BackendPrivateKey;

        let key = BackendPrivateKey::generate_ec("P-256").unwrap();
        let cert_der = build_simple_test_cert(&key);
        let port = start_acme_tls13_server(cert_der, &key).await;

        // TLS handshake succeeds (lines 52-68 covered).
        // verify_acme_cert returns IncorrectResponse because there is no ACME extension.
        let result = validate_inner("dns", "127.0.0.1", "token.thumbprint", port).await;
        assert!(
            matches!(
                result,
                Err(crate::error::AcmeError::IncorrectResponse(_))
                    | Err(crate::error::AcmeError::Tls(_))
            ),
            "expected IncorrectResponse or Tls error after TLS handshake: {result:?}"
        );
    }

    /// Covers verify_tls12_signature (lines 894-901).
    /// The client's AcceptAnyCert::verify_tls12_signature is called during the
    /// TLS 1.2 ServerKeyExchange message verification.
    #[tokio::test]
    async fn validate_inner_tls12_handshake_covers_verify_tls12_signature() {
        use synta_certificate::BackendPrivateKey;

        let key = BackendPrivateKey::generate_ec("P-256").unwrap();
        let cert_der = build_simple_test_cert(&key);
        let port = start_acme_tls12_server(cert_der, &key).await;

        // TLS 1.2 handshake: verify_tls12_signature is called (lines 894-901 covered).
        let result = validate_inner("dns", "127.0.0.1", "token.thumbprint", port).await;
        assert!(
            matches!(
                result,
                Err(crate::error::AcmeError::IncorrectResponse(_))
                    | Err(crate::error::AcmeError::Tls(_))
            ),
            "expected IncorrectResponse or Tls error after TLS 1.2 handshake: {result:?}"
        );
    }
}

// ── Custom ServerCertVerifier that accepts any certificate ────────────────────
//
// We perform our own extension-level verification; rustls's PKI verification
// is intentionally bypassed for this challenge type because the certificate
// is self-signed and issued by the ACME client for validation purposes only.

#[derive(Debug)]
struct AcceptAnyCert;

impl ServerCertVerifier for AcceptAnyCert {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
        ]
    }
}
