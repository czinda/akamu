//! onion-csr-01 CSR builder (RFC 9799 §3.2).
//!
//! Builds a DER-encoded CSR that satisfies the server-side validation
//! performed by `src/validation/onion_csr_01.rs`:
//!  - SAN dNSName contains the `.onion` domain.
//!  - `cabf-onion-csr-nonce` extension (OID 2.23.140.41) value is the
//!    key authorization as a DER UTF8String.
//!  - CSR is signed by the hidden-service Ed25519 private key.

use synta_certificate::{
    BackendPrivateKey, CsrBuilder, NameBuilder, PrivateKey as _, SubjectAlternativeNameBuilder,
};

use crate::error::ClientError;

/// OID 2.23.140.41 — CA/B Forum `cabf-onion-csr-nonce` extension.
const CABF_ONION_CSR_NONCE: &[u32] = &[2, 23, 140, 41];

/// Build a DER-encoded CSR for an onion-csr-01 challenge.
///
/// `domain` is the `.onion` domain being validated.
/// `key_auth` is the key authorization string (`token.thumbprint`).
/// `hs_key_pem` is the PEM-encoded Ed25519 hidden-service private key.
///
/// The CSR embeds the `cabf-onion-csr-nonce` extension (OID 2.23.140.41)
/// containing `key_auth` as a DER UTF8String, and is signed by the
/// hidden-service key.  Submit this CSR via
/// `AcmeClient::trigger_challenge_onion`.
pub fn build_onion_csr(
    domain: &str,
    key_auth: &str,
    hs_key_pem: &[u8],
) -> Result<Vec<u8>, ClientError> {
    // Load the hidden-service Ed25519 private key.
    let hs_key = BackendPrivateKey::from_pem(hs_key_pem, None)
        .map_err(|e| ClientError::Crypto(format!("HS key load: {e}")))?;
    let spki = hs_key
        .public_key()
        .map_err(|e| ClientError::Crypto(format!("HS public key: {e}")))?
        .spki_der()
        .to_vec();

    let name_der = NameBuilder::new()
        .common_name(domain)
        .build()
        .map_err(|e| ClientError::Crypto(format!("CSR name: {e}")))?;

    let san_der = SubjectAlternativeNameBuilder::new()
        .dns_name(domain)
        .build()
        .map_err(|e| ClientError::Crypto(format!("CSR SAN: {e}")))?;

    // cabf-onion-csr-nonce extension value: DER UTF8String wrapping key_auth.
    // key_auth is always well under 128 bytes, so single-byte length is safe.
    let ka_bytes = key_auth.as_bytes();
    let mut nonce_ext = vec![0x0Cu8, ka_bytes.len() as u8]; // UTF8String tag + len
    nonce_ext.extend_from_slice(ka_bytes);

    // Ed25519 signing (the HS key is always Ed25519 for v3 .onion addresses).
    let signer = hs_key.as_signer("sha512");

    CsrBuilder::new()
        .subject_name(&name_der)
        .public_key_der(&spki)
        .add_extension_oid(synta_certificate::oids::SUBJECT_ALT_NAME, false, &san_der)
        .add_extension_oid(CABF_ONION_CSR_NONCE, false, &nonce_ext)
        .sign(&signer)
        .map_err(|e| ClientError::Crypto(format!("onion CSR sign: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_onion_csr_produces_der() {
        let hs_key = BackendPrivateKey::generate_ed25519().unwrap();
        let pem = hs_key.to_pem(None).unwrap();
        let der = build_onion_csr("test.onion", "token.thumb", &pem).unwrap();
        assert!(!der.is_empty());
        // DER CSR starts with SEQUENCE tag 0x30.
        assert_eq!(der[0], 0x30);
    }
}
