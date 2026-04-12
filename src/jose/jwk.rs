//! JWK (JSON Web Key) parsing, thumbprint computation, and SPKI DER conversion.
//!
//! No external JOSE crate: thumbprints use synta_certificate's DataHasher,
//! SPKI construction uses synta_certificate::BackendPublicKey factory methods.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::Deserialize;
use synta_certificate::{default_data_hasher, BackendPublicKey, DataHasher};

use crate::error::AcmeError;

/// A JWK public key as used in ACME protected headers and account objects.
///
/// Only the subset of fields required for ACME is parsed. The `d` (private
/// key component) field is intentionally ignored.
#[derive(Debug, Clone, Deserialize)]
pub struct JwkPublic {
    /// Key type: "RSA", "EC", "OKP"
    pub kty: String,

    // EC / OKP common
    /// Curve name: "P-256", "P-384", "P-521" (EC) or "Ed25519", "Ed448" (OKP)
    pub crv: Option<String>,
    /// X coordinate / public key bytes (base64url, no padding)
    pub x: Option<String>,
    /// Y coordinate (base64url, no padding) — EC only
    pub y: Option<String>,

    // RSA
    /// RSA modulus (base64url)
    pub n: Option<String>,
    /// RSA public exponent (base64url)
    pub e: Option<String>,
}

impl JwkPublic {
    /// Compute the RFC 7638 JWK thumbprint (SHA-256 of the canonical JSON form).
    ///
    /// Returns the base64url-encoded (no padding) thumbprint string.
    pub fn thumbprint(&self) -> Result<String, AcmeError> {
        // RFC 7638 §3.2: required members, lexicographically sorted, no whitespace
        let canonical = match self.kty.as_str() {
            "RSA" => {
                let n = self
                    .n
                    .as_deref()
                    .ok_or_else(|| AcmeError::BadRequest("RSA JWK missing 'n'".into()))?;
                let e = self
                    .e
                    .as_deref()
                    .ok_or_else(|| AcmeError::BadRequest("RSA JWK missing 'e'".into()))?;
                // Required members for RSA: e, kty, n (alphabetical order)
                format!(r#"{{"e":"{}","kty":"RSA","n":"{}"}}"#, e, n)
            }
            "EC" => {
                let crv = self
                    .crv
                    .as_deref()
                    .ok_or_else(|| AcmeError::BadRequest("EC JWK missing 'crv'".into()))?;
                let x = self
                    .x
                    .as_deref()
                    .ok_or_else(|| AcmeError::BadRequest("EC JWK missing 'x'".into()))?;
                let y = self
                    .y
                    .as_deref()
                    .ok_or_else(|| AcmeError::BadRequest("EC JWK missing 'y'".into()))?;
                // Required members for EC: crv, kty, x, y (alphabetical order)
                format!(r#"{{"crv":"{}","kty":"EC","x":"{}","y":"{}"}}"#, crv, x, y)
            }
            "OKP" => {
                let crv = self
                    .crv
                    .as_deref()
                    .ok_or_else(|| AcmeError::BadRequest("OKP JWK missing 'crv'".into()))?;
                let x = self
                    .x
                    .as_deref()
                    .ok_or_else(|| AcmeError::BadRequest("OKP JWK missing 'x'".into()))?;
                // Required members for OKP: crv, kty, x (alphabetical order)
                format!(r#"{{"crv":"{}","kty":"OKP","x":"{}"}}"#, crv, x)
            }
            kty => {
                return Err(AcmeError::BadSignatureAlgorithm(format!(
                    "unsupported JWK key type: {}",
                    kty
                )));
            }
        };

        let hash = default_data_hasher()
            .hash_data("sha256", canonical.as_bytes())
            .map_err(|e| AcmeError::Crypto(format!("SHA-256 thumbprint: {e}")))?;
        Ok(URL_SAFE_NO_PAD.encode(&hash))
    }

    /// Convert this JWK to DER-encoded SubjectPublicKeyInfo (SPKI).
    ///
    /// Uses synta_certificate's BackendPublicKey factory methods so the OpenSSL
    /// backend handles all key encoding internally — no direct openssl crate dep.
    pub fn to_spki_der(&self) -> Result<Vec<u8>, AcmeError> {
        match self.kty.as_str() {
            "RSA" => self.rsa_to_spki_der(),
            "EC" => self.ec_to_spki_der(),
            "OKP" => self.okp_to_spki_der(),
            kty => Err(AcmeError::BadSignatureAlgorithm(format!(
                "unsupported JWK key type: {}",
                kty
            ))),
        }
    }

    fn rsa_to_spki_der(&self) -> Result<Vec<u8>, AcmeError> {
        let n_b64 = self
            .n
            .as_deref()
            .ok_or_else(|| AcmeError::BadRequest("RSA JWK missing 'n'".into()))?;
        let e_b64 = self
            .e
            .as_deref()
            .ok_or_else(|| AcmeError::BadRequest("RSA JWK missing 'e'".into()))?;

        let n = URL_SAFE_NO_PAD
            .decode(n_b64)
            .map_err(|e| AcmeError::BadRequest(format!("JWK 'n' base64: {}", e)))?;
        let e = URL_SAFE_NO_PAD
            .decode(e_b64)
            .map_err(|e| AcmeError::BadRequest(format!("JWK 'e' base64: {}", e)))?;

        let key = BackendPublicKey::from_rsa_components(&n, &e)
            .map_err(|e| AcmeError::Crypto(format!("RSA key from JWK: {}", e)))?;
        Ok(key.spki_der().to_vec())
    }

    fn ec_to_spki_der(&self) -> Result<Vec<u8>, AcmeError> {
        let crv = self
            .crv
            .as_deref()
            .ok_or_else(|| AcmeError::BadRequest("EC JWK missing 'crv'".into()))?;
        let x_b64 = self
            .x
            .as_deref()
            .ok_or_else(|| AcmeError::BadRequest("EC JWK missing 'x'".into()))?;
        let y_b64 = self
            .y
            .as_deref()
            .ok_or_else(|| AcmeError::BadRequest("EC JWK missing 'y'".into()))?;

        let x = URL_SAFE_NO_PAD
            .decode(x_b64)
            .map_err(|e| AcmeError::BadRequest(format!("JWK 'x' base64: {}", e)))?;
        let y = URL_SAFE_NO_PAD
            .decode(y_b64)
            .map_err(|e| AcmeError::BadRequest(format!("JWK 'y' base64: {}", e)))?;

        // Map JWK curve names to synta convention
        let curve = match crv {
            "P-256" => "P-256",
            "P-384" => "P-384",
            "P-521" => "P-521",
            other => {
                return Err(AcmeError::BadSignatureAlgorithm(format!(
                    "unsupported EC curve: {}",
                    other
                )));
            }
        };

        let key = BackendPublicKey::from_ec_components(&x, &y, curve)
            .map_err(|e| AcmeError::Crypto(format!("EC key from JWK: {}", e)))?;
        Ok(key.spki_der().to_vec())
    }

    fn okp_to_spki_der(&self) -> Result<Vec<u8>, AcmeError> {
        let crv = self
            .crv
            .as_deref()
            .ok_or_else(|| AcmeError::BadRequest("OKP JWK missing 'crv'".into()))?;
        let x_b64 = self
            .x
            .as_deref()
            .ok_or_else(|| AcmeError::BadRequest("OKP JWK missing 'x'".into()))?;

        let x_bytes = URL_SAFE_NO_PAD
            .decode(x_b64)
            .map_err(|e| AcmeError::BadRequest(format!("JWK 'x' base64: {}", e)))?;

        match crv {
            "Ed25519" => build_okp_spki(&x_bytes, OKP_ED25519_SPKI_PREFIX),
            "Ed448" => build_okp_spki(&x_bytes, OKP_ED448_SPKI_PREFIX),
            other => Err(AcmeError::BadSignatureAlgorithm(format!(
                "unsupported OKP curve: {}",
                other
            ))),
        }
    }
}

// Fixed SPKI prefix bytes for EdDSA public keys.
// Ed25519 OID 1.3.101.112: 30 05 06 03 2b 65 70
// Ed448 OID 1.3.101.113: 30 05 06 03 2b 65 71
// Full SPKI: SEQUENCE { AlgorithmIdentifier, BIT STRING { 00 || key } }

/// SEQUENCE { SEQUENCE { OID 1.3.101.112 } } — Ed25519 AlgorithmIdentifier
const OKP_ED25519_SPKI_PREFIX: &[u8] = &[
    0x30, 0x2a, // SEQUENCE, length 42
    0x30, 0x05, // SEQUENCE (AlgorithmIdentifier), length 5
    0x06, 0x03, 0x2b, 0x65, 0x70, // OID 1.3.101.112 (Ed25519)
    0x03, 0x21, // BIT STRING, length 33
    0x00, // unused bits = 0
];

/// SEQUENCE { SEQUENCE { OID 1.3.101.113 } } — Ed448 AlgorithmIdentifier
const OKP_ED448_SPKI_PREFIX: &[u8] = &[
    0x30, 0x43, // SEQUENCE, length 67
    0x30, 0x05, // SEQUENCE (AlgorithmIdentifier), length 5
    0x06, 0x03, 0x2b, 0x65, 0x71, // OID 1.3.101.113 (Ed448)
    0x03, 0x39, // BIT STRING, length 57
    0x00, // unused bits = 0
];

fn build_okp_spki(x_bytes: &[u8], prefix: &[u8]) -> Result<Vec<u8>, AcmeError> {
    // Validate length: Ed25519 = 32, Ed448 = 57
    let expected_len = match prefix[8] {
        0x70 => 32usize, // Ed25519
        0x71 => 57usize, // Ed448
        _ => return Err(AcmeError::Internal("unknown OKP prefix".into())),
    };
    if x_bytes.len() != expected_len {
        return Err(AcmeError::BadRequest(format!(
            "OKP key x has wrong length: {} (expected {})",
            x_bytes.len(),
            expected_len
        )));
    }
    let mut spki = prefix.to_vec();
    spki.extend_from_slice(x_bytes);
    Ok(spki)
}

#[cfg(test)]
mod tests {
    use super::*;
    use synta_certificate::BackendPrivateKey;

    /// RFC 7638 §3.1 example thumbprint
    #[test]
    fn jwk_thumbprint_rfc7638_example() {
        let jwk = JwkPublic {
            kty: "RSA".to_string(),
            crv: None,
            x: None,
            y: None,
            n: Some(
                "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAt\
                VT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn6\
                4tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_F\
                DW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n9\
                1CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINH\
                aQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"
                    .to_string(),
            ),
            e: Some("AQAB".to_string()),
        };
        let thumb = jwk.thumbprint().unwrap();
        assert_eq!(thumb, "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs");
    }

    #[test]
    fn ec_p256_thumbprint_roundtrip() {
        let key = BackendPrivateKey::generate_ec("P-256").unwrap();
        let pub_key = key.public_key().unwrap();
        let (x_bytes, y_bytes) = pub_key.ec_affine_coordinates().unwrap().unwrap();
        let pad = |v: &[u8], len: usize| {
            let mut out = vec![0u8; len];
            let start = len.saturating_sub(v.len());
            out[start..].copy_from_slice(&v[v.len().saturating_sub(len)..]);
            URL_SAFE_NO_PAD.encode(&out)
        };
        let jwk = JwkPublic {
            kty: "EC".to_string(),
            crv: Some("P-256".to_string()),
            x: Some(pad(&x_bytes, 32)),
            y: Some(pad(&y_bytes, 32)),
            n: None,
            e: None,
        };
        // thumbprint should succeed
        let thumb = jwk.thumbprint().unwrap();
        assert!(!thumb.is_empty());
        // to_spki_der should succeed and return a non-empty DER
        let spki = jwk.to_spki_der().unwrap();
        assert!(!spki.is_empty());
    }

    #[test]
    fn ec_p384_thumbprint_and_spki() {
        let key = BackendPrivateKey::generate_ec("P-384").unwrap();
        let pub_key = key.public_key().unwrap();
        let (x_bytes, y_bytes) = pub_key.ec_affine_coordinates().unwrap().unwrap();
        let pad = |v: &[u8], len: usize| {
            let mut out = vec![0u8; len];
            let start = len.saturating_sub(v.len());
            out[start..].copy_from_slice(&v[v.len().saturating_sub(len)..]);
            URL_SAFE_NO_PAD.encode(&out)
        };
        let jwk = JwkPublic {
            kty: "EC".to_string(),
            crv: Some("P-384".to_string()),
            x: Some(pad(&x_bytes, 48)),
            y: Some(pad(&y_bytes, 48)),
            n: None,
            e: None,
        };
        let thumb = jwk.thumbprint().unwrap();
        assert!(!thumb.is_empty());
        let spki = jwk.to_spki_der().unwrap();
        assert!(!spki.is_empty());
    }

    #[test]
    fn ec_p521_spki() {
        let key = BackendPrivateKey::generate_ec("P-521").unwrap();
        let pub_key = key.public_key().unwrap();
        let (x_bytes, y_bytes) = pub_key.ec_affine_coordinates().unwrap().unwrap();
        let pad = |v: &[u8], len: usize| {
            let mut out = vec![0u8; len];
            let start = len.saturating_sub(v.len());
            out[start..].copy_from_slice(&v[v.len().saturating_sub(len)..]);
            URL_SAFE_NO_PAD.encode(&out)
        };
        let jwk = JwkPublic {
            kty: "EC".to_string(),
            crv: Some("P-521".to_string()),
            x: Some(pad(&x_bytes, 66)),
            y: Some(pad(&y_bytes, 66)),
            n: None,
            e: None,
        };
        let spki = jwk.to_spki_der().unwrap();
        assert!(!spki.is_empty());
    }

    #[test]
    fn okp_ed25519_thumbprint_and_spki() {
        // Ed25519 public key is 32 bytes
        let x_bytes = vec![0x42u8; 32];
        let jwk = JwkPublic {
            kty: "OKP".to_string(),
            crv: Some("Ed25519".to_string()),
            x: Some(URL_SAFE_NO_PAD.encode(&x_bytes)),
            y: None,
            n: None,
            e: None,
        };
        let thumb = jwk.thumbprint().unwrap();
        assert!(!thumb.is_empty());
        let spki = jwk.to_spki_der().unwrap();
        // Should be prefix (13 bytes) + key (32 bytes) = 45 bytes
        assert_eq!(spki.len(), OKP_ED25519_SPKI_PREFIX.len() + 32);
    }

    #[test]
    fn okp_ed448_spki() {
        // Ed448 public key is 57 bytes
        let x_bytes = vec![0x13u8; 57];
        let jwk = JwkPublic {
            kty: "OKP".to_string(),
            crv: Some("Ed448".to_string()),
            x: Some(URL_SAFE_NO_PAD.encode(&x_bytes)),
            y: None,
            n: None,
            e: None,
        };
        let spki = jwk.to_spki_der().unwrap();
        assert_eq!(spki.len(), OKP_ED448_SPKI_PREFIX.len() + 57);
    }

    #[test]
    fn okp_wrong_key_length_returns_error() {
        // Ed25519 expects 32 bytes; give it 31
        let x_bytes = vec![0x42u8; 31];
        let jwk = JwkPublic {
            kty: "OKP".to_string(),
            crv: Some("Ed25519".to_string()),
            x: Some(URL_SAFE_NO_PAD.encode(&x_bytes)),
            y: None,
            n: None,
            e: None,
        };
        assert!(jwk.to_spki_der().is_err());
    }

    #[test]
    fn okp_unsupported_curve_returns_error() {
        // X25519 is a valid OKP curve but not supported for SPKI construction
        let jwk = JwkPublic {
            kty: "OKP".to_string(),
            crv: Some("X25519".to_string()),
            x: Some(URL_SAFE_NO_PAD.encode(&[0u8; 32])),
            y: None,
            n: None,
            e: None,
        };
        // thumbprint for OKP doesn't validate curve, so it succeeds
        assert!(
            jwk.thumbprint().is_ok(),
            "OKP thumbprint should succeed for any curve"
        );
        // to_spki_der only supports Ed25519/Ed448
        assert!(jwk.to_spki_der().is_err());
    }

    #[test]
    fn unsupported_key_type_returns_error() {
        let jwk = JwkPublic {
            kty: "DH".to_string(),
            crv: None,
            x: None,
            y: None,
            n: None,
            e: None,
        };
        assert!(jwk.thumbprint().is_err());
        assert!(jwk.to_spki_der().is_err());
    }

    #[test]
    fn ec_missing_crv_returns_error() {
        let jwk = JwkPublic {
            kty: "EC".to_string(),
            crv: None,
            x: Some("AAAA".to_string()),
            y: Some("AAAA".to_string()),
            n: None,
            e: None,
        };
        assert!(jwk.thumbprint().is_err());
        assert!(jwk.to_spki_der().is_err());
    }

    #[test]
    fn ec_unsupported_curve_returns_error() {
        let jwk = JwkPublic {
            kty: "EC".to_string(),
            crv: Some("secp256k1".to_string()),
            x: Some(URL_SAFE_NO_PAD.encode(&[0u8; 32])),
            y: Some(URL_SAFE_NO_PAD.encode(&[0u8; 32])),
            n: None,
            e: None,
        };
        assert!(jwk.to_spki_der().is_err());
    }

    #[test]
    fn rsa_thumbprint_and_spki() {
        let jwk = JwkPublic {
            kty: "RSA".to_string(),
            crv: None,
            x: None,
            y: None,
            n: Some("0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw".to_string()),
            e: Some("AQAB".to_string()),
        };
        let thumb = jwk.thumbprint().unwrap();
        assert_eq!(thumb, "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs");
        // to_spki_der should succeed with valid RSA key components
        let spki = jwk.to_spki_der().unwrap();
        assert!(!spki.is_empty());
    }

    #[test]
    fn rsa_missing_n_returns_error() {
        let jwk = JwkPublic {
            kty: "RSA".to_string(),
            crv: None,
            x: None,
            y: None,
            n: None,
            e: Some("AQAB".to_string()),
        };
        assert!(jwk.thumbprint().is_err());
        assert!(jwk.to_spki_der().is_err());
    }

    #[test]
    fn rsa_missing_e_returns_error() {
        let jwk = JwkPublic {
            kty: "RSA".to_string(),
            crv: None,
            x: None,
            y: None,
            n: Some("AAAA".to_string()),
            e: None,
        };
        assert!(jwk.thumbprint().is_err());
        assert!(jwk.to_spki_der().is_err());
    }

    #[test]
    fn okp_missing_x_returns_error() {
        let jwk = JwkPublic {
            kty: "OKP".to_string(),
            crv: Some("Ed25519".to_string()),
            x: None,
            y: None,
            n: None,
            e: None,
        };
        assert!(jwk.thumbprint().is_err());
        assert!(jwk.to_spki_der().is_err());
    }

    #[test]
    fn ec_thumbprint_missing_x_returns_error() {
        // crv present but x is None → covers EC thumbprint missing-x closure
        let jwk = JwkPublic {
            kty: "EC".to_string(),
            crv: Some("P-256".to_string()),
            x: None,
            y: Some(URL_SAFE_NO_PAD.encode(&[0u8; 32])),
            n: None,
            e: None,
        };
        let err = jwk.thumbprint().unwrap_err();
        match err {
            AcmeError::BadRequest(msg) => assert!(msg.contains("EC JWK missing 'x'")),
            other => panic!("expected BadRequest, got {other:?}"),
        }
    }

    #[test]
    fn ec_thumbprint_missing_y_returns_error() {
        // crv and x present but y is None → covers EC thumbprint missing-y closure
        let jwk = JwkPublic {
            kty: "EC".to_string(),
            crv: Some("P-256".to_string()),
            x: Some(URL_SAFE_NO_PAD.encode(&[0u8; 32])),
            y: None,
            n: None,
            e: None,
        };
        let err = jwk.thumbprint().unwrap_err();
        match err {
            AcmeError::BadRequest(msg) => assert!(msg.contains("EC JWK missing 'y'")),
            other => panic!("expected BadRequest, got {other:?}"),
        }
    }

    #[test]
    fn okp_thumbprint_missing_crv_returns_error() {
        // kty=OKP but crv is None → covers OKP thumbprint missing-crv closure
        let jwk = JwkPublic {
            kty: "OKP".to_string(),
            crv: None,
            x: Some(URL_SAFE_NO_PAD.encode(&[0u8; 32])),
            y: None,
            n: None,
            e: None,
        };
        let err = jwk.thumbprint().unwrap_err();
        match err {
            AcmeError::BadRequest(msg) => assert!(msg.contains("OKP JWK missing 'crv'")),
            other => panic!("expected BadRequest, got {other:?}"),
        }
    }

    #[test]
    fn ec_spki_missing_x_returns_error() {
        // crv present but x is None → covers ec_to_spki_der missing-x closure
        let jwk = JwkPublic {
            kty: "EC".to_string(),
            crv: Some("P-256".to_string()),
            x: None,
            y: Some(URL_SAFE_NO_PAD.encode(&[0u8; 32])),
            n: None,
            e: None,
        };
        let err = jwk.to_spki_der().unwrap_err();
        match err {
            AcmeError::BadRequest(msg) => assert!(msg.contains("EC JWK missing 'x'")),
            other => panic!("expected BadRequest, got {other:?}"),
        }
    }

    #[test]
    fn ec_spki_missing_y_returns_error() {
        // crv and x present but y is None → covers ec_to_spki_der missing-y closure
        let jwk = JwkPublic {
            kty: "EC".to_string(),
            crv: Some("P-256".to_string()),
            x: Some(URL_SAFE_NO_PAD.encode(&[0u8; 32])),
            y: None,
            n: None,
            e: None,
        };
        let err = jwk.to_spki_der().unwrap_err();
        match err {
            AcmeError::BadRequest(msg) => assert!(msg.contains("EC JWK missing 'y'")),
            other => panic!("expected BadRequest, got {other:?}"),
        }
    }

    #[test]
    fn okp_spki_missing_crv_returns_error() {
        // kty=OKP but crv is None → covers okp_to_spki_der missing-crv closure
        let jwk = JwkPublic {
            kty: "OKP".to_string(),
            crv: None,
            x: Some(URL_SAFE_NO_PAD.encode(&[0u8; 32])),
            y: None,
            n: None,
            e: None,
        };
        let err = jwk.to_spki_der().unwrap_err();
        match err {
            AcmeError::BadRequest(msg) => assert!(msg.contains("OKP JWK missing 'crv'")),
            other => panic!("expected BadRequest, got {other:?}"),
        }
    }

    /// Covers jwk.rs line 215 — build_okp_spki `_` arm (unknown OKP prefix byte).
    #[test]
    fn build_okp_spki_unknown_prefix_returns_internal_error() {
        // Mutate the Ed25519 prefix so that prefix[8] is neither 0x70 nor 0x71.
        let mut bad_prefix = OKP_ED25519_SPKI_PREFIX.to_vec();
        bad_prefix[8] = 0xFF; // invalid OKP type byte
        let result = build_okp_spki(&[0u8; 32], &bad_prefix);
        assert!(
            matches!(result, Err(AcmeError::Internal(_))),
            "expected Internal error for unknown OKP prefix, got {result:?}"
        );
    }
}
