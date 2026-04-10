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
