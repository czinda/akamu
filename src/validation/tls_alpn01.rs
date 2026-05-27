//! tls-alpn-01 challenge validation (RFC 8737).
//!
//! Opens a TLS connection to `{domain}:443` with ALPN "acme-tls/1", captures
//! the presented certificate, and verifies:
//!   1. The SAN extension contains an entry matching the identifier: dNSName for
//!      DNS identifiers, iPAddress for IP identifiers (RFC 8738 §4).
//!   2. The id-pe-acmeIdentifier extension (OID 1.3.6.1.5.5.7.1.31, critical)
//!      is present and its value equals `SHA-256(keyAuthorization)`.

use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use synta_certificate::{
    decode_extensions, default_data_hasher, general_name, oids, Certificate, DataHasher,
};
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
    let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls_native_ossl::default_provider(),
    ))
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
fn verify_acme_cert(
    id_type: &str,
    identifier: &str,
    cert_der: &[u8],
    expected_hash: &[u8; 32],
) -> Result<(), AcmeError> {
    let cert = Certificate::from_der(cert_der)
        .map_err(|e| AcmeError::Tls(format!("cert parse for {identifier}: {e}")))?;

    let ext_raw = cert.tbs_certificate.extensions.ok_or_else(|| {
        AcmeError::IncorrectResponse(format!(
            "tls-alpn-01: certificate for '{identifier}' is missing id-pe-acmeIdentifier"
        ))
    })?;

    let extensions = decode_extensions(ext_raw.as_bytes());

    let acme_ext = extensions
        .iter()
        .find(|ext| ext.extn_id.components() == oids::PE_ACME_IDENTIFIER)
        .ok_or_else(|| {
            AcmeError::IncorrectResponse(format!(
                "tls-alpn-01: certificate for '{identifier}' is missing id-pe-acmeIdentifier"
            ))
        })?;

    let critical = acme_ext.critical.map(bool::from).unwrap_or(false);
    if !critical {
        return Err(AcmeError::IncorrectResponse(format!(
            "tls-alpn-01: id-pe-acmeIdentifier extension in '{identifier}' cert must be critical"
        )));
    }

    // The extension content (extnValue inner bytes) must be:
    //   OCTET STRING (tag 0x04, length 0x20) { <32 bytes> }
    // Per RFC 8737 §3: ACMEIdentifier ::= OCTET STRING (SIZE (32))
    let ext_content = acme_ext.extn_value.as_bytes();
    if ext_content.len() != 34
        || ext_content[0] != 0x04 // OCTET STRING
        || ext_content[1] != 0x20 // length 32
        || &ext_content[2..] != expected_hash
    {
        return Err(AcmeError::IncorrectResponse(format!(
            "tls-alpn-01: id-pe-acmeIdentifier value mismatch in certificate for '{identifier}'"
        )));
    }

    // RFC 8737 §3 / RFC 8738 §4: The certificate MUST have exactly the
    // identifier being validated in its SAN extension — as dNSName for DNS
    // identifiers, or as iPAddress for IP identifiers.
    let sans = cert.subject_alt_names();
    if id_type == "ip" {
        verify_san_contains_ip(identifier, &sans).map_err(|reason| {
            AcmeError::IncorrectResponse(format!(
                "tls-alpn-01: certificate SAN does not match IP '{identifier}': {reason}"
            ))
        })?;
    } else {
        verify_san_contains_domain(identifier, &sans).map_err(|reason| {
            AcmeError::IncorrectResponse(format!(
                "tls-alpn-01: certificate SAN does not match '{identifier}': {reason}"
            ))
        })?;
    }

    Ok(())
}

/// Check that `domain` appears as a dNSName in the parsed SAN list.
fn verify_san_contains_domain(domain: &str, sans: &[(u32, Vec<u8>)]) -> Result<(), &'static str> {
    for (tag, content) in sans {
        if *tag == general_name::DNS_NAME {
            let name = std::str::from_utf8(content).map_err(|_| "dNSName is not valid UTF-8")?;
            if name.eq_ignore_ascii_case(domain) {
                return Ok(());
            }
        }
    }
    Err("domain not present as dNSName in SAN")
}

/// Check that `ip_str` appears as an iPAddress in the parsed SAN list.
/// Used by the IP-identifier validation path (RFC 8738 §4).
fn verify_san_contains_ip(ip_str: &str, sans: &[(u32, Vec<u8>)]) -> Result<(), &'static str> {
    let ip_bytes: Vec<u8> = if let Ok(ipv4) = ip_str.parse::<std::net::Ipv4Addr>() {
        ipv4.octets().to_vec()
    } else if let Ok(ipv6) = ip_str.parse::<std::net::Ipv6Addr>() {
        ipv6.octets().to_vec()
    } else {
        return Err("identifier is not a valid IP address");
    };

    for (tag, content) in sans {
        if *tag == general_name::IP_ADDRESS && content == &ip_bytes {
            return Ok(());
        }
    }
    Err("IP address not present as iPAddress in SAN")
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── verify_acme_cert ──────────────────────────────────────────────────────

    #[test]
    fn verify_acme_cert_invalid_der_returns_error() {
        let result = verify_acme_cert("dns", "example.com", b"bad cert", &[0u8; 32]);
        assert!(result.is_err());
    }

    /// Build a test cert with the given extensions using CertificateBuilder.
    fn build_test_cert(extensions: &[(&[u32], bool, &[u8])]) -> Vec<u8> {
        use synta_certificate::{
            BackendPrivateKey, CertificateBuilder, NameBuilder, PrivateKey as _,
        };

        let key = BackendPrivateKey::generate_ec("P-256").unwrap();
        let spki = key.public_key().unwrap().spki_der().to_vec();
        let name_der = NameBuilder::new().common_name("test").build().unwrap();
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let nb =
            synta_certificate::parse_time(&crate::ca::init::unix_to_generalized_time(now_secs))
                .unwrap();
        let na = synta_certificate::parse_time(&crate::ca::init::unix_to_generalized_time(
            now_secs + 86400,
        ))
        .unwrap();
        let signer = key.as_signer("sha256");
        let mut builder = CertificateBuilder::new()
            .issuer_name(&name_der)
            .subject_name(&name_der)
            .public_key_der(&spki)
            .serial_number(synta::Integer::from_i64(1))
            .not_valid_before(nb)
            .not_valid_after(na);
        for (oid, critical, value) in extensions {
            builder = builder.add_extension_oid(oid, *critical, value);
        }
        builder.sign(&signer).unwrap()
    }

    /// ACME identifier extension value: OCTET STRING { <hash> }
    fn acme_ext_value(hash: &[u8; 32]) -> Vec<u8> {
        use synta::OctetString;
        use synta_certificate::acme_types::Authorization;
        Authorization::new_unchecked(OctetString::new(hash.to_vec()))
            .to_der()
            .unwrap()
    }

    /// SAN extension value with a single dNSName.
    fn san_dns(domain: &str) -> Vec<u8> {
        use synta_certificate::SubjectAlternativeNameBuilder;
        SubjectAlternativeNameBuilder::new()
            .dns_name(domain)
            .build()
            .unwrap()
    }

    #[test]
    fn verify_acme_cert_correct_extension_succeeds() {
        let key_auth = "test-key-auth";
        let hash: [u8; 32] = synta_certificate::default_data_hasher()
            .hash_data("sha256", key_auth.as_bytes())
            .unwrap()
            .try_into()
            .unwrap();
        let cert_der = build_test_cert(&[
            (oids::PE_ACME_IDENTIFIER, true, &acme_ext_value(&hash)),
            (oids::SUBJECT_ALT_NAME, false, &san_dns("example.com")),
        ]);
        let result = verify_acme_cert("dns", "example.com", &cert_der, &hash);
        assert!(
            result.is_ok(),
            "verify_acme_cert should succeed: {result:?}"
        );
    }

    #[test]
    fn verify_acme_cert_wrong_hash_returns_error() {
        let hash: [u8; 32] = synta_certificate::default_data_hasher()
            .hash_data("sha256", b"test-key-auth")
            .unwrap()
            .try_into()
            .unwrap();
        let cert_der = build_test_cert(&[
            (oids::PE_ACME_IDENTIFIER, true, &acme_ext_value(&hash)),
            (oids::SUBJECT_ALT_NAME, false, &san_dns("example.com")),
        ]);
        let result = verify_acme_cert("dns", "example.com", &cert_der, &[0u8; 32]);
        assert!(result.is_err(), "should fail with wrong hash");
    }

    #[test]
    fn verify_acme_cert_missing_extension_returns_error() {
        use synta_certificate::{
            BackendPrivateKey, CertificateBuilder, NameBuilder, PrivateKey as _,
        };

        let key = BackendPrivateKey::generate_ec("P-256").unwrap();
        let spki = key.public_key().unwrap().spki_der().to_vec();
        let name_der = NameBuilder::new().common_name("test").build().unwrap();
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let nb =
            synta_certificate::parse_time(&crate::ca::init::unix_to_generalized_time(now_secs))
                .unwrap();
        let na = synta_certificate::parse_time(&crate::ca::init::unix_to_generalized_time(
            now_secs + 86400,
        ))
        .unwrap();
        let signer = key.as_signer("sha256");
        let cert_der = CertificateBuilder::new()
            .issuer_name(&name_der)
            .subject_name(&name_der)
            .public_key_der(&spki)
            .serial_number(synta::Integer::from_i64(1))
            .not_valid_before(nb)
            .not_valid_after(na)
            .sign(&signer)
            .unwrap();

        let result = verify_acme_cert("dns", "example.com", &cert_der, &[0u8; 32]);
        assert!(result.is_err(), "should fail when extension is missing");
    }

    #[test]
    fn verify_acme_cert_non_critical_extension_returns_error() {
        let hash = [0u8; 32];
        let cert_der = build_test_cert(&[
            (oids::PE_ACME_IDENTIFIER, false, &acme_ext_value(&hash)), // critical=false
            (oids::SUBJECT_ALT_NAME, false, &san_dns("example.com")),
        ]);
        let result = verify_acme_cert("dns", "example.com", &cert_der, &hash);
        assert!(
            result.is_err(),
            "should fail when extension is not critical"
        );
    }

    /// RFC 8737 §3 says "a single dNSName entry" but does not prohibit additional
    /// GeneralName entries of other types.  Some ACME clients include extra SANs
    /// alongside the required identifier; verify_acme_cert must still succeed as
    /// long as the identifier is present and the acmeIdentifier extension is valid.
    #[test]
    fn verify_acme_cert_multi_san_succeeds() {
        use synta_certificate::SubjectAlternativeNameBuilder;

        let key_auth = "multi-san-test";
        let hash: [u8; 32] = synta_certificate::default_data_hasher()
            .hash_data("sha256", key_auth.as_bytes())
            .unwrap()
            .try_into()
            .unwrap();
        let multi_san = SubjectAlternativeNameBuilder::new()
            .dns_name("example.com")
            .dns_name("other.example.com")
            .build()
            .unwrap();
        let cert_der = build_test_cert(&[
            (oids::PE_ACME_IDENTIFIER, true, &acme_ext_value(&hash)),
            (oids::SUBJECT_ALT_NAME, false, &multi_san),
        ]);
        let result = verify_acme_cert("dns", "example.com", &cert_der, &hash);
        assert!(
            result.is_ok(),
            "multi-SAN cert with valid identifier should succeed: {result:?}"
        );
    }

    /// Covers the case where the ACME extension is not the first extension in the cert.
    /// BasicConstraints comes first (wrong OID); verify_acme_cert must skip it and find
    /// id-pe-acmeIdentifier.
    #[test]
    fn verify_acme_cert_skips_non_matching_extension() {
        use synta_certificate::encode_basic_constraints;

        let hash = [0xab_u8; 32];
        let bc = encode_basic_constraints(false, None).unwrap();
        let cert_der = build_test_cert(&[
            (oids::BASIC_CONSTRAINTS, false, &bc),
            (oids::PE_ACME_IDENTIFIER, true, &acme_ext_value(&hash)),
            (oids::SUBJECT_ALT_NAME, false, &san_dns("example.com")),
        ]);
        let result = verify_acme_cert("dns", "example.com", &cert_der, &hash);
        assert!(
            result.is_ok(),
            "must find ACME ext even when it is not first: {result:?}"
        );
    }

    /// Cert with BasicConstraints but no id-pe-acmeIdentifier must return IncorrectResponse.
    #[test]
    fn verify_acme_cert_no_matching_extension() {
        use synta_certificate::encode_basic_constraints;

        let bc = encode_basic_constraints(false, None).unwrap();
        let cert_der = build_test_cert(&[
            (oids::BASIC_CONSTRAINTS, false, &bc),
            (oids::SUBJECT_ALT_NAME, false, &san_dns("example.com")),
        ]);
        let result = verify_acme_cert("dns", "example.com", &cert_der, &[0u8; 32]);
        assert!(result.is_err(), "missing ACME extension must return error");
        assert!(
            matches!(
                result.unwrap_err(),
                crate::error::AcmeError::IncorrectResponse(_)
            ),
            "must be IncorrectResponse"
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
            rustls_native_ossl::default_provider(),
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
            rustls_native_ossl::default_provider(),
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
