//! HKDF-SHA256 (RFC 5869) credential derivation for `/acme/eab`.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use native_ossl::{digest::DigestAlg, kdf::HkdfBuilder};

use crate::error::AcmeError;

/// Derive a deterministic `(kid, hmac_key_b64u)` pair for `principal`.
///
/// Both values are base64url-encoded (no padding).  The same
/// `master_secret` + `principal` always yields the same `kid` and `hmac_key`.
pub fn derive_eab_credentials(
    master_secret: &[u8],
    principal: &str,
) -> Result<(String, String), AcmeError> {
    let sha256 = DigestAlg::fetch(c"SHA2-256", None)
        .map_err(|e| AcmeError::Internal(format!("HKDF digest fetch: {e}")))?;

    let mut kid_info = b"akamu-eab-v1-kid:".to_vec();
    kid_info.extend_from_slice(principal.as_bytes());

    let mut key_info = b"akamu-eab-v1-key:".to_vec();
    key_info.extend_from_slice(principal.as_bytes());

    // No explicit salt is provided; RFC 5869 §2.2 specifies that HKDF-Extract
    // uses a zero-length salt (i.e. 0^HashLen) in this case.  This is
    // acceptable here because `master_secret` is already a high-entropy IKM
    // (≥ 32 bytes of random data) that does not require salt-based extraction
    // to achieve uniform randomness.  The domain-separated `info` fields
    // (`akamu-eab-v1-kid:` / `akamu-eab-v1-key:` + principal) ensure key
    // separation between the kid and hmac_key outputs.
    let kid_raw = HkdfBuilder::new(&sha256)
        .key(master_secret)
        .info(&kid_info)
        .derive_to_vec(16)
        .map_err(|e| AcmeError::Internal(format!("HKDF kid derive: {e}")))?;

    let key_raw = HkdfBuilder::new(&sha256)
        .key(master_secret)
        .info(&key_info)
        .derive_to_vec(32)
        .map_err(|e| AcmeError::Internal(format!("HKDF key derive: {e}")))?;

    Ok((
        URL_SAFE_NO_PAD.encode(&kid_raw),
        URL_SAFE_NO_PAD.encode(&key_raw),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_produces_stable_kid() {
        let (kid, _) =
            derive_eab_credentials(b"secret_32_bytes_padding_XXXXXXXXX", "alice@REALM").unwrap();
        let (kid2, _) =
            derive_eab_credentials(b"secret_32_bytes_padding_XXXXXXXXX", "alice@REALM").unwrap();
        assert_eq!(kid, kid2, "derivation must be deterministic");
    }

    #[test]
    fn different_principals_yield_different_credentials() {
        let (kid_a, key_a) =
            derive_eab_credentials(b"secret_32_bytes_padding_XXXXXXXXX", "alice@REALM").unwrap();
        let (kid_b, key_b) =
            derive_eab_credentials(b"secret_32_bytes_padding_XXXXXXXXX", "bob@REALM").unwrap();
        assert_ne!(kid_a, kid_b);
        assert_ne!(key_a, key_b);
    }

    #[test]
    fn kid_is_22_chars_base64url() {
        let (kid, _) = derive_eab_credentials(b"testsecret_32bytesXXXXXXXXXXXXXX", "u@R").unwrap();
        // 16 raw bytes → 22 base64url chars (no padding)
        assert_eq!(kid.len(), 22);
        assert!(kid
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
    }

    #[test]
    fn key_is_43_chars_base64url() {
        let (_, key) = derive_eab_credentials(b"testsecret_32bytesXXXXXXXXXXXXXX", "u@R").unwrap();
        // 32 raw bytes → 43 base64url chars (no padding)
        assert_eq!(key.len(), 43);
    }
}
