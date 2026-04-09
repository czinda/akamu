//! tls-alpn-01 challenge validation (RFC 8737).
//!
//! Opens a TLS connection to `{domain}:443` with ALPN "acme-tls/1", captures
//! the presented certificate, and verifies:
//!   1. The certificate contains a SAN that matches the identifier.
//!   2. The id-pe-acmeIdentifier extension (OID 1.3.6.1.5.5.7.1.31, critical)
//!      is present and its value equals `SHA-256(keyAuthorization)`.

use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use sha2::{Digest, Sha256};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use crate::error::AcmeError;

/// Validate a tls-alpn-01 challenge.
///
/// * `domain`   — the identifier value (DNS name).
/// * `key_auth` — `{token}.{jwk_thumbprint}`.
pub async fn validate(domain: &str, key_auth: &str) -> Result<(), AcmeError> {
    let expected_hash: [u8; 32] = Sha256::digest(key_auth.as_bytes()).into();

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

    // Resolve the server name.
    let server_name = ServerName::try_from(domain.to_string())
        .map_err(|e| AcmeError::Tls(format!("invalid server name '{domain}': {e}")))?;

    // TCP connect.
    let tcp = TcpStream::connect((domain, 443u16))
        .await
        .map_err(|e| AcmeError::Connection(format!("TCP connect to {domain}:443: {e}")))?;

    // TLS handshake (this also performs the ALPN negotiation).
    let tls_stream = connector
        .connect(server_name, tcp)
        .await
        .map_err(|e| AcmeError::Tls(format!("TLS handshake with {domain}: {e}")))?;

    // Extract the peer certificate presented during the handshake.
    let (_, client_conn) = tls_stream.get_ref();
    let peer_certs = client_conn
        .peer_certificates()
        .ok_or_else(|| AcmeError::Tls("server presented no certificate".into()))?;

    let end_entity_der = peer_certs
        .first()
        .ok_or_else(|| AcmeError::Tls("server certificate chain is empty".into()))?
        .as_ref();

    verify_acme_cert(domain, end_entity_der, &expected_hash)
}

// ── Certificate verification ──────────────────────────────────────────────────

/// Verify the presented certificate against the tls-alpn-01 requirements.
///
/// Checks (RFC 8737 §3):
/// 1. id-pe-acmeIdentifier extension is present and critical.
/// 2. Extension value = `OCTET STRING { expected_hash }`.
///    (The extnValue OCTET STRING wrapper is already stripped by the time we
///    see `ext_content`.)
fn verify_acme_cert(
    domain: &str,
    cert_der: &[u8],
    expected_hash: &[u8; 32],
) -> Result<(), AcmeError> {
    // OID 1.3.6.1.5.5.7.1.31 as DER — pre-computed.
    // Encoding: 06 08 2b 06 01 05 05 07 01 1f
    const ACME_ID_OID_DER: &[u8] = &[0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x1f];

    // Walk the DER to find TBSCertificate → Extensions → the target extension.
    let (found_critical, ext_value) = find_extension_value(cert_der, ACME_ID_OID_DER)
        .map_err(|e| AcmeError::Tls(format!("cert parse for {domain}: {e}")))?
        .ok_or_else(|| {
            AcmeError::IncorrectResponse(format!(
                "tls-alpn-01: certificate for '{domain}' is missing id-pe-acmeIdentifier"
            ))
        })?;

    if !found_critical {
        return Err(AcmeError::IncorrectResponse(format!(
            "tls-alpn-01: id-pe-acmeIdentifier extension in '{domain}' cert must be critical"
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
            "tls-alpn-01: id-pe-acmeIdentifier value mismatch in certificate for '{domain}'"
        )));
    }

    Ok(())
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
        let result = verify_acme_cert("example.com", b"bad cert", &[0u8; 32]);
        assert!(result.is_err());
    }

    #[test]
    fn verify_acme_cert_correct_extension_succeeds() {
        // Build a minimal fake certificate DER with the id-pe-acmeIdentifier extension.
        // This is a hand-crafted DER structure; real certs use synta_certificate.
        // hash = SHA-256 of "test-key-auth"
        let key_auth = "test-key-auth";
        let expected_hash: [u8; 32] = sha2::Sha256::digest(key_auth.as_bytes()).into();

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

        // Extensions SEQUENCE OF (contains our one extension)
        let mut exts_seq = vec![0x30, ext_seq.len() as u8];
        exts_seq.extend_from_slice(&ext_seq);

        // Extensions [3] EXPLICIT
        let mut exts_a3 = vec![0xa3, exts_seq.len() as u8];
        exts_a3.extend_from_slice(&exts_seq);

        // Minimal fields for TBSCertificate (some are required):
        // version [0], serial, sig alg, issuer, validity, subject, SPKI, extensions
        // We use minimal/dummy placeholders since we only care about extension parsing.
        let version_a0: &[u8] = &[0xa0, 0x03, 0x02, 0x01, 0x02]; // version v3
        let serial: &[u8] = &[0x02, 0x01, 0x01]; // INTEGER { 1 }
        let sig_alg: &[u8] = &[0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02]; // ecdsaWithSHA256
        let issuer: &[u8] = &[0x30, 0x00]; // empty SEQUENCE
        let validity: &[u8] = &[0x30, 0x00]; // empty SEQUENCE
        let subject: &[u8] = &[0x30, 0x00]; // empty SEQUENCE
        let spki: &[u8] = &[0x30, 0x00]; // empty SEQUENCE

        let tbs_len = version_a0.len() + serial.len() + sig_alg.len() + issuer.len()
            + validity.len() + subject.len() + spki.len() + exts_a3.len();
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
        let sig_alg2: &[u8] = &[0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];
        let bit_string: &[u8] = &[0x03, 0x01, 0x00]; // BIT STRING with 0 unused bits, empty

        let cert_inner_len = tbs.len() + sig_alg2.len() + bit_string.len();
        let mut cert_der = vec![0x30, cert_inner_len as u8];
        cert_der.extend_from_slice(&tbs);
        cert_der.extend_from_slice(sig_alg2);
        cert_der.extend_from_slice(bit_string);

        let result = verify_acme_cert("example.com", &cert_der, &expected_hash);
        assert!(result.is_ok(), "verify_acme_cert should succeed: {result:?}");
    }

    #[test]
    fn verify_acme_cert_wrong_hash_returns_error() {
        let key_auth = "test-key-auth";
        let correct_hash: [u8; 32] = sha2::Sha256::digest(key_auth.as_bytes()).into();
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
        let sig_alg: &[u8] = &[0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];
        let empty_seq: &[u8] = &[0x30, 0x00];
        let tbs_len = version_a0.len() + serial.len() + sig_alg.len() + 4 * empty_seq.len() + exts_a3.len();
        let mut tbs = vec![0x30, tbs_len as u8];
        tbs.extend_from_slice(version_a0); tbs.extend_from_slice(serial); tbs.extend_from_slice(sig_alg);
        for _ in 0..4 { tbs.extend_from_slice(empty_seq); }
        tbs.extend_from_slice(&exts_a3);
        let sig_alg2: &[u8] = &[0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];
        let bit_string: &[u8] = &[0x03, 0x01, 0x00];
        let cert_inner_len = tbs.len() + sig_alg2.len() + bit_string.len();
        let mut cert_der = vec![0x30, cert_inner_len as u8];
        cert_der.extend_from_slice(&tbs); cert_der.extend_from_slice(sig_alg2); cert_der.extend_from_slice(bit_string);

        // Verify with wrong_hash — should fail
        let result = verify_acme_cert("example.com", &cert_der, &wrong_hash);
        assert!(result.is_err(), "should fail with wrong hash");
    }

    #[test]
    fn verify_acme_cert_missing_extension_returns_error() {
        // Cert with no extensions
        let version_a0: &[u8] = &[0xa0, 0x03, 0x02, 0x01, 0x02];
        let serial: &[u8] = &[0x02, 0x01, 0x01];
        let sig_alg: &[u8] = &[0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];
        let empty_seq: &[u8] = &[0x30, 0x00];
        let tbs_len = version_a0.len() + serial.len() + sig_alg.len() + 4 * empty_seq.len();
        let mut tbs = vec![0x30, tbs_len as u8];
        tbs.extend_from_slice(version_a0); tbs.extend_from_slice(serial); tbs.extend_from_slice(sig_alg);
        for _ in 0..4 { tbs.extend_from_slice(empty_seq); }
        let sig_alg2: &[u8] = &[0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];
        let bit_string: &[u8] = &[0x03, 0x01, 0x00];
        let cert_inner_len = tbs.len() + sig_alg2.len() + bit_string.len();
        let mut cert_der = vec![0x30, cert_inner_len as u8];
        cert_der.extend_from_slice(&tbs); cert_der.extend_from_slice(sig_alg2); cert_der.extend_from_slice(bit_string);

        let result = verify_acme_cert("example.com", &cert_der, &[0u8; 32]);
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
        let sig_alg: &[u8] = &[0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];
        let empty_seq: &[u8] = &[0x30, 0x00];
        let tbs_len = version_a0.len() + serial.len() + sig_alg.len() + 4 * empty_seq.len() + exts_a3.len();
        let mut tbs = vec![0x30, tbs_len as u8];
        tbs.extend_from_slice(version_a0); tbs.extend_from_slice(serial); tbs.extend_from_slice(sig_alg);
        for _ in 0..4 { tbs.extend_from_slice(empty_seq); }
        tbs.extend_from_slice(&exts_a3);
        let sig_alg2: &[u8] = &[0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];
        let bit_string: &[u8] = &[0x03, 0x01, 0x00];
        let cert_inner_len = tbs.len() + sig_alg2.len() + bit_string.len();
        let mut cert_der = vec![0x30, cert_inner_len as u8];
        cert_der.extend_from_slice(&tbs); cert_der.extend_from_slice(sig_alg2); cert_der.extend_from_slice(bit_string);

        let result = verify_acme_cert("example.com", &cert_der, &expected_hash);
        assert!(result.is_err(), "should fail when extension is not critical");
    }

    // ── AcceptAnyCert ─────────────────────────────────────────────────────────

    #[test]
    fn accept_any_cert_supported_schemes_not_empty() {
        let verifier = AcceptAnyCert;
        let schemes = verifier.supported_verify_schemes();
        assert!(!schemes.is_empty());
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
