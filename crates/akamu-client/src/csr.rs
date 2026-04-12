//! CSR builder — thin wrapper over `synta_certificate::{CsrBuilder, …}`.

use synta_certificate::{
    BackendPrivateKey, CsrBuilder, NameBuilder, PrivateKey as _, SubjectAlternativeNameBuilder,
};

use crate::error::ClientError;

/// Build a DER-encoded CSR for the given domains using `key`.
///
/// `domains[0]` is used as the Common Name; all domains are added as
/// dNSName SANs.  Wildcard labels (`"*.example.com"`) are valid in dNSName
/// SANs (RFC 5280 §4.2.1.6) and are passed through unchanged.
pub fn build_csr(domains: &[&str], key: &BackendPrivateKey) -> Result<Vec<u8>, ClientError> {
    let first = domains
        .first()
        .ok_or_else(|| ClientError::Crypto("no domains provided".into()))?;

    let pub_key = key
        .public_key()
        .map_err(|e| ClientError::Crypto(format!("public key: {e}")))?;
    let spki = pub_key.spki_der().to_vec();

    let name = NameBuilder::new()
        .common_name(first)
        .build()
        .map_err(|e| ClientError::Crypto(format!("CSR name: {e}")))?;

    let mut san_builder = SubjectAlternativeNameBuilder::new();
    for d in domains {
        san_builder = san_builder.dns_name(d);
    }
    let san = san_builder
        .build()
        .map_err(|e| ClientError::Crypto(format!("CSR SAN: {e}")))?;

    let signer = key.as_signer("sha256");
    CsrBuilder::new()
        .subject_name(&name)
        .public_key_der(&spki)
        .add_extension_oid(synta_certificate::oids::SUBJECT_ALT_NAME, false, &san)
        .sign(&signer)
        .map_err(|e| ClientError::Crypto(format!("CSR sign: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use synta_certificate::BackendPrivateKey;

    #[test]
    fn build_csr_single_domain() {
        let key = BackendPrivateKey::generate_ec("P-256").unwrap();
        let der = build_csr(&["example.com"], &key).unwrap();
        assert!(!der.is_empty());
        // DER CSR starts with SEQUENCE tag 0x30.
        assert_eq!(der[0], 0x30);
    }

    #[test]
    fn build_csr_multiple_domains() {
        let key = BackendPrivateKey::generate_ec("P-384").unwrap();
        let der = build_csr(&["example.com", "www.example.com"], &key).unwrap();
        assert!(!der.is_empty());
    }

    #[test]
    fn build_csr_no_domains_returns_error() {
        let key = BackendPrivateKey::generate_ec("P-256").unwrap();
        assert!(build_csr(&[], &key).is_err());
    }
}
