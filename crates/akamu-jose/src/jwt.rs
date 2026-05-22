//! Compact JWT parsing for RFC 9447 authority tokens.
//!
//! Only decodes and verifies; does not produce JWTs.
//! Signature algorithms: ES256/384/512, RS256/384/512, PS256/384/512, EdDSA.

use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine,
};
use serde::Deserialize;

use crate::error::JoseError;

/// Decoded header of an RFC 9447 authority token (compact JWT).
#[derive(Debug, Deserialize)]
pub struct AuthorityTokenHeader {
    pub alg: String,
    /// HTTPS URL of the Token Authority signing certificate (RFC 7515 §4.1.5).
    pub x5u: Option<String>,
    /// Certificate chain as base64-std (not base64url) DER entries; first is the signing cert
    /// (RFC 7515 §4.1.6).
    pub x5c: Option<Vec<String>>,
}

/// Decoded and signature-verified authority token.
#[derive(Debug)]
pub struct AuthorityToken {
    pub header: AuthorityTokenHeader,
    /// Raw JSON payload; caller extracts `atc`, `exp`, `jti`.
    pub claims: serde_json::Value,
}

impl AuthorityToken {
    /// Decode the JWT header without verifying the signature or expiry.
    ///
    /// Use this to learn which certificate to fetch before calling
    /// [`decode_and_verify`].
    pub fn decode_header(token: &str) -> Result<AuthorityTokenHeader, JoseError> {
        let header_b64 = token
            .split('.')
            .next()
            .ok_or_else(|| JoseError::BadRequest("authority token: missing '.'".into()))?;
        let header_bytes = URL_SAFE_NO_PAD
            .decode(header_b64)
            .map_err(|e| JoseError::BadRequest(format!("authority token header base64: {e}")))?;
        serde_json::from_slice::<AuthorityTokenHeader>(&header_bytes)
            .map_err(|e| JoseError::BadRequest(format!("authority token header JSON: {e}")))
    }

    /// Decode and verify the JWT signature using `spki_der`.
    ///
    /// Checks:
    /// - Compact serialization has exactly 3 parts.
    /// - `exp` claim is present and has not elapsed.
    /// - Signature over `<header_b64>.<claims_b64>` verifies with `spki_der`.
    pub fn decode_and_verify(token: &str, spki_der: &[u8]) -> Result<Self, JoseError> {
        let parts: Vec<&str> = token.splitn(4, '.').collect();
        if parts.len() != 3 {
            return Err(JoseError::BadRequest(format!(
                "authority token: expected 3 '.' separated parts, got {}",
                parts.len()
            )));
        }

        let header_bytes = URL_SAFE_NO_PAD
            .decode(parts[0])
            .map_err(|e| JoseError::BadRequest(format!("authority token header base64: {e}")))?;
        let header = serde_json::from_slice::<AuthorityTokenHeader>(&header_bytes)
            .map_err(|e| JoseError::BadRequest(format!("authority token header JSON: {e}")))?;

        let claims_bytes = URL_SAFE_NO_PAD
            .decode(parts[1])
            .map_err(|e| JoseError::BadRequest(format!("authority token claims base64: {e}")))?;
        let claims: serde_json::Value = serde_json::from_slice(&claims_bytes)
            .map_err(|e| JoseError::BadRequest(format!("authority token claims JSON: {e}")))?;

        // Verify `exp` before doing crypto work.
        let exp = claims.get("exp").and_then(|v| v.as_i64()).ok_or_else(|| {
            JoseError::BadRequest("authority token: missing or non-integer 'exp' claim".into())
        })?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        if exp <= now {
            return Err(JoseError::BadRequest(format!(
                "authority token expired: exp={exp}, now={now}"
            )));
        }

        // Compact JWT signing input: ASCII bytes of "<header_b64url>.<claims_b64url>".
        let signing_input = format!("{}.{}", parts[0], parts[1]);
        let raw_sig = URL_SAFE_NO_PAD
            .decode(parts[2])
            .map_err(|e| JoseError::BadRequest(format!("authority token signature base64: {e}")))?;

        crate::jws::verify_with_spki(&header.alg, signing_input.as_bytes(), &raw_sig, spki_der)?;

        Ok(AuthorityToken { header, claims })
    }
}

/// Decode the signing certificate DER from a JWT header's `x5c` field.
///
/// Per RFC 7515 §4.1.6, `x5c` entries are base64 (standard, not base64url).
/// Returns the DER of the first (leaf / signing) certificate.
pub fn x5c_leaf_der(x5c: &[String]) -> Result<Vec<u8>, JoseError> {
    let first = x5c
        .first()
        .ok_or_else(|| JoseError::BadRequest("authority token: x5c array is empty".into()))?;
    STANDARD
        .decode(first.as_bytes())
        .map_err(|e| JoseError::BadRequest(format!("authority token: x5c[0] base64: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use synta_certificate::{BackendPrivateKey, CertificateSigner};

    fn make_token(
        key: &BackendPrivateKey,
        alg: &str,
        half: Option<usize>,
        hash: &str,
        exp_offset: i64,
    ) -> (String, Vec<u8>) {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;
        use synta_certificate::PrivateKey as _;

        let pub_key = key.public_key().unwrap();
        let spki_der = pub_key.spki_der().to_vec();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let exp = now + exp_offset;

        let header = format!(r#"{{"alg":"{alg}"}}"#);
        let claims = format!(r#"{{"exp":{exp},"jti":"test-jti"}}"#);

        let header_b64 = URL_SAFE_NO_PAD.encode(header.as_bytes());
        let claims_b64 = URL_SAFE_NO_PAD.encode(claims.as_bytes());
        let signing_input = format!("{header_b64}.{claims_b64}");

        let signer = key.as_signer(hash);
        let der_sig = signer.sign_tbs(signing_input.as_bytes()).unwrap();

        let raw_sig = if let Some(h) = half {
            crate::jws::ecdsa_der_to_p1363(&der_sig, h).expect("DER→P1363 failed")
        } else {
            der_sig
        };

        let sig_b64 = URL_SAFE_NO_PAD.encode(&raw_sig);
        let token = format!("{signing_input}.{sig_b64}");
        (token, spki_der)
    }

    #[test]
    fn decode_header_only() {
        let header = r#"{"alg":"ES256","x5u":"https://ta.example.com/cert.pem"}"#;
        let b64 = URL_SAFE_NO_PAD.encode(header.as_bytes());
        let token = format!("{b64}.claims.sig");
        let h = AuthorityToken::decode_header(&token).unwrap();
        assert_eq!(h.alg, "ES256");
        assert_eq!(h.x5u.as_deref(), Some("https://ta.example.com/cert.pem"));
        assert!(h.x5c.is_none());
    }

    #[test]
    fn decode_header_missing_dot_returns_error() {
        assert!(AuthorityToken::decode_header("nodot").is_err());
    }

    #[test]
    fn wrong_part_count_returns_error() {
        let claims = URL_SAFE_NO_PAD.encode(b"{}");
        let token = format!("header.{claims}"); // only 2 parts
        assert!(AuthorityToken::decode_and_verify(&token, &[]).is_err());
    }

    #[test]
    fn es256_sign_verify_roundtrip() {
        let key = BackendPrivateKey::generate_ec("P-256").unwrap();
        let (token, spki_der) = make_token(&key, "ES256", Some(32), "sha256", 3600);
        AuthorityToken::decode_and_verify(&token, &spki_der).unwrap();
    }

    #[test]
    fn es384_sign_verify_roundtrip() {
        let key = BackendPrivateKey::generate_ec("P-384").unwrap();
        let (token, spki_der) = make_token(&key, "ES384", Some(48), "sha384", 3600);
        AuthorityToken::decode_and_verify(&token, &spki_der).unwrap();
    }

    #[test]
    fn es512_sign_verify_roundtrip() {
        let key = BackendPrivateKey::generate_ec("P-521").unwrap();
        let (token, spki_der) = make_token(&key, "ES512", Some(66), "sha512", 3600);
        AuthorityToken::decode_and_verify(&token, &spki_der).unwrap();
    }

    #[test]
    fn expired_token_is_rejected() {
        let key = BackendPrivateKey::generate_ec("P-256").unwrap();
        let (token, spki_der) = make_token(&key, "ES256", Some(32), "sha256", -1);
        let err = AuthorityToken::decode_and_verify(&token, &spki_der).unwrap_err();
        assert!(matches!(err, JoseError::BadRequest(ref m) if m.contains("expired")));
    }

    #[test]
    fn tampered_signature_is_rejected() {
        let key = BackendPrivateKey::generate_ec("P-256").unwrap();
        let (mut token, spki_der) = make_token(&key, "ES256", Some(32), "sha256", 3600);
        // Corrupt the last character of the signature (third part).
        let last = token.pop().unwrap();
        token.push(if last == 'A' { 'B' } else { 'A' });
        assert!(AuthorityToken::decode_and_verify(&token, &spki_der).is_err());
    }

    #[test]
    fn x5c_leaf_der_decodes_standard_base64() {
        let der = vec![0x30u8, 0x82, 0x01, 0x00];
        let b64 = STANDARD.encode(&der);
        let decoded = x5c_leaf_der(&[b64]).unwrap();
        assert_eq!(decoded, der);
    }

    #[test]
    fn x5c_leaf_der_empty_returns_error() {
        assert!(x5c_leaf_der(&[]).is_err());
    }
}
