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
    /// Key type: "RSA", "EC", "OKP", "AKP"
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

    // AKP (ML-DSA per draft-ietf-cose-dilithium-11)
    /// Algorithm identifier: "ML-DSA-44", "ML-DSA-65", "ML-DSA-87"
    pub alg: Option<String>,
    /// Raw public key bytes (base64url, no padding) — `pub` in JSON
    #[serde(rename = "pub")]
    pub pub_key: Option<String>,
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
            "AKP" => {
                let alg = self
                    .alg
                    .as_deref()
                    .ok_or_else(|| AcmeError::BadRequest("AKP JWK missing 'alg'".into()))?;
                let pub_key = self
                    .pub_key
                    .as_deref()
                    .ok_or_else(|| AcmeError::BadRequest("AKP JWK missing 'pub'".into()))?;
                // draft-ietf-cose-dilithium-11 §6: alg, kty, pub (alphabetical order)
                format!(r#"{{"alg":"{}","kty":"AKP","pub":"{}"}}"#, alg, pub_key)
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
            "AKP" => self.ml_dsa_to_spki_der(),
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

    fn ml_dsa_to_spki_der(&self) -> Result<Vec<u8>, AcmeError> {
        let alg = self
            .alg
            .as_deref()
            .ok_or_else(|| AcmeError::BadRequest("AKP JWK missing 'alg'".into()))?;
        let pub_b64 = self
            .pub_key
            .as_deref()
            .ok_or_else(|| AcmeError::BadRequest("AKP JWK missing 'pub'".into()))?;

        let pub_bytes = URL_SAFE_NO_PAD
            .decode(pub_b64)
            .map_err(|e| AcmeError::BadRequest(format!("JWK 'pub' base64: {}", e)))?;

        // ML-DSA public key sizes per FIPS 204:
        // ML-DSA-44: 1312, ML-DSA-65: 1952, ML-DSA-87: 2592
        // OID bytes: 2.16.840.1.101.3.4.3.{17,18,19}
        let (expected_len, oid_bytes): (usize, &[u8]) = match alg {
            "ML-DSA-44" => (
                1312,
                &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x11],
            ),
            "ML-DSA-65" => (
                1952,
                &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x12],
            ),
            "ML-DSA-87" => (
                2592,
                &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x13],
            ),
            other => {
                return Err(AcmeError::BadSignatureAlgorithm(format!(
                    "unsupported AKP algorithm: {}",
                    other
                )));
            }
        };

        if pub_bytes.len() != expected_len {
            return Err(AcmeError::BadRequest(format!(
                "AKP '{}' public key has wrong length: {} (expected {})",
                alg,
                pub_bytes.len(),
                expected_len
            )));
        }

        Ok(build_ml_dsa_spki(oid_bytes, &pub_bytes))
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

/// Build a DER-encoded SubjectPublicKeyInfo for an ML-DSA key.
///
/// Structure: SEQUENCE { AlgorithmIdentifier { OID }, BIT STRING { 0x00 || key } }
/// No AlgorithmIdentifier parameters (ML-DSA uses absent parameters per FIPS 204).
fn build_ml_dsa_spki(oid_bytes: &[u8], pub_key: &[u8]) -> Vec<u8> {
    // OID TLV: 06 <len> <oid_bytes>  (oid_bytes.len() < 128 for all ML-DSA OIDs)
    let mut oid_tlv = vec![0x06u8, oid_bytes.len() as u8];
    oid_tlv.extend_from_slice(oid_bytes);

    // AlgorithmIdentifier SEQUENCE { OID } — no parameters
    let mut alg_id = vec![0x30u8];
    der_push_length(&mut alg_id, oid_tlv.len());
    alg_id.extend_from_slice(&oid_tlv);

    // BIT STRING: 0x00 (unused bits) || pub_key
    let bit_string_content_len = 1 + pub_key.len();
    let mut bit_string = vec![0x03u8]; // BIT STRING tag
    der_push_length(&mut bit_string, bit_string_content_len);
    bit_string.push(0x00); // unused bits = 0
    bit_string.extend_from_slice(pub_key);

    // Outer SEQUENCE { AlgorithmIdentifier, BIT STRING }
    let outer_content_len = alg_id.len() + bit_string.len();
    let mut spki = vec![0x30u8]; // SEQUENCE tag
    der_push_length(&mut spki, outer_content_len);
    spki.extend_from_slice(&alg_id);
    spki.extend_from_slice(&bit_string);
    spki
}

fn der_push_length(buf: &mut Vec<u8>, len: usize) {
    if len < 128 {
        buf.push(len as u8);
    } else if len < 256 {
        buf.push(0x81);
        buf.push(len as u8);
    } else {
        buf.push(0x82);
        buf.push((len >> 8) as u8);
        buf.push((len & 0xff) as u8);
    }
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
            alg: None,
            pub_key: None,
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
            alg: None,
            pub_key: None,
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
            alg: None,
            pub_key: None,
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
            alg: None,
            pub_key: None,
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
            alg: None,
            pub_key: None,
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
            alg: None,
            pub_key: None,
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
            alg: None,
            pub_key: None,
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
            alg: None,
            pub_key: None,
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
            alg: None,
            pub_key: None,
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
            alg: None,
            pub_key: None,
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
            alg: None,
            pub_key: None,
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
            alg: None,
            pub_key: None,
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
            alg: None,
            pub_key: None,
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
            alg: None,
            pub_key: None,
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
            alg: None,
            pub_key: None,
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
            alg: None,
            pub_key: None,
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
            alg: None,
            pub_key: None,
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
            alg: None,
            pub_key: None,
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
            alg: None,
            pub_key: None,
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
            alg: None,
            pub_key: None,
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
            alg: None,
            pub_key: None,
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

    // ── AKP (ML-DSA) tests ────────────────────────────────────────────────────

    /// draft-ietf-cose-dilithium-11 §6: thumbprint uses {"alg","kty","pub"} in
    /// lexicographic order. Verify the canonical form and that the hash succeeds.
    #[test]
    fn akp_ml_dsa_87_thumbprint_succeeds() {
        let pub_bytes = vec![0xABu8; 2592]; // synthetic ML-DSA-87 key bytes
        let jwk = JwkPublic {
            kty: "AKP".to_string(),
            crv: None,
            x: None,
            y: None,
            n: None,
            e: None,
            alg: Some("ML-DSA-87".to_string()),
            pub_key: Some(URL_SAFE_NO_PAD.encode(&pub_bytes)),
        };
        let thumb = jwk.thumbprint().unwrap();
        assert!(!thumb.is_empty(), "AKP thumbprint should be non-empty");
    }

    /// Verify that SPKI DER constructed from a real ML-DSA-87 key matches the
    /// key's own SPKI DER (round-trip through JWK).
    #[test]
    fn akp_ml_dsa_87_spki_roundtrip() {
        let priv_key = BackendPrivateKey::generate_ml_dsa("ML-DSA-87").unwrap();
        let pub_key = priv_key.public_key().unwrap();
        let spki_der = pub_key.spki_der().to_vec();

        // The ML-DSA SPKI header for all variants is exactly 22 bytes:
        // 30 82 XX XX  (4) — outer SEQUENCE
        // 30 0B        (2) — AlgId SEQUENCE
        // 06 09 OID    (11) — OID TLV
        // 03 82 XX XX  (4) — BIT STRING
        // 00           (1) — unused bits
        // Total: 22 bytes
        const SPKI_HEADER: usize = 22;
        assert!(
            spki_der.len() > SPKI_HEADER,
            "SPKI DER too short: {}",
            spki_der.len()
        );
        let raw_pub = &spki_der[SPKI_HEADER..];
        assert_eq!(
            raw_pub.len(),
            2592,
            "ML-DSA-87 raw pub key must be 2592 bytes"
        );

        let jwk = JwkPublic {
            kty: "AKP".to_string(),
            crv: None,
            x: None,
            y: None,
            n: None,
            e: None,
            alg: Some("ML-DSA-87".to_string()),
            pub_key: Some(URL_SAFE_NO_PAD.encode(raw_pub)),
        };

        let reconstructed = jwk.to_spki_der().unwrap();
        assert_eq!(
            reconstructed, spki_der,
            "reconstructed SPKI must match original"
        );
    }

    /// Same round-trip for ML-DSA-65.
    #[test]
    fn akp_ml_dsa_65_spki_roundtrip() {
        let priv_key = BackendPrivateKey::generate_ml_dsa("ML-DSA-65").unwrap();
        let pub_key = priv_key.public_key().unwrap();
        let spki_der = pub_key.spki_der().to_vec();

        const SPKI_HEADER: usize = 22;
        let raw_pub = &spki_der[SPKI_HEADER..];
        assert_eq!(
            raw_pub.len(),
            1952,
            "ML-DSA-65 raw pub key must be 1952 bytes"
        );

        let jwk = JwkPublic {
            kty: "AKP".to_string(),
            crv: None,
            x: None,
            y: None,
            n: None,
            e: None,
            alg: Some("ML-DSA-65".to_string()),
            pub_key: Some(URL_SAFE_NO_PAD.encode(raw_pub)),
        };

        let reconstructed = jwk.to_spki_der().unwrap();
        assert_eq!(
            reconstructed, spki_der,
            "reconstructed SPKI must match original"
        );
    }

    /// Same round-trip for ML-DSA-44.
    #[test]
    fn akp_ml_dsa_44_spki_roundtrip() {
        let priv_key = BackendPrivateKey::generate_ml_dsa("ML-DSA-44").unwrap();
        let pub_key = priv_key.public_key().unwrap();
        let spki_der = pub_key.spki_der().to_vec();

        const SPKI_HEADER: usize = 22;
        let raw_pub = &spki_der[SPKI_HEADER..];
        assert_eq!(
            raw_pub.len(),
            1312,
            "ML-DSA-44 raw pub key must be 1312 bytes"
        );

        let jwk = JwkPublic {
            kty: "AKP".to_string(),
            crv: None,
            x: None,
            y: None,
            n: None,
            e: None,
            alg: Some("ML-DSA-44".to_string()),
            pub_key: Some(URL_SAFE_NO_PAD.encode(raw_pub)),
        };

        let reconstructed = jwk.to_spki_der().unwrap();
        assert_eq!(
            reconstructed, spki_der,
            "reconstructed SPKI must match original"
        );
    }

    #[test]
    fn akp_missing_alg_returns_error() {
        let jwk = JwkPublic {
            kty: "AKP".to_string(),
            crv: None,
            x: None,
            y: None,
            n: None,
            e: None,
            alg: None,
            pub_key: Some(URL_SAFE_NO_PAD.encode(&[0u8; 2592])),
        };
        assert!(
            matches!(jwk.thumbprint(), Err(AcmeError::BadRequest(_))),
            "missing 'alg' should return BadRequest"
        );
        assert!(
            matches!(jwk.to_spki_der(), Err(AcmeError::BadRequest(_))),
            "missing 'alg' should return BadRequest"
        );
    }

    #[test]
    fn akp_missing_pub_returns_error() {
        let jwk = JwkPublic {
            kty: "AKP".to_string(),
            crv: None,
            x: None,
            y: None,
            n: None,
            e: None,
            alg: Some("ML-DSA-87".to_string()),
            pub_key: None,
        };
        assert!(
            matches!(jwk.thumbprint(), Err(AcmeError::BadRequest(_))),
            "missing 'pub' should return BadRequest"
        );
        assert!(
            matches!(jwk.to_spki_der(), Err(AcmeError::BadRequest(_))),
            "missing 'pub' should return BadRequest"
        );
    }

    #[test]
    fn akp_wrong_pub_length_returns_error() {
        // ML-DSA-87 expects 2592 bytes; give it 2591
        let jwk = JwkPublic {
            kty: "AKP".to_string(),
            crv: None,
            x: None,
            y: None,
            n: None,
            e: None,
            alg: Some("ML-DSA-87".to_string()),
            pub_key: Some(URL_SAFE_NO_PAD.encode(&[0u8; 2591])),
        };
        assert!(
            matches!(jwk.to_spki_der(), Err(AcmeError::BadRequest(_))),
            "wrong pub length should return BadRequest"
        );
    }

    #[test]
    fn akp_unsupported_alg_returns_error() {
        let jwk = JwkPublic {
            kty: "AKP".to_string(),
            crv: None,
            x: None,
            y: None,
            n: None,
            e: None,
            alg: Some("ML-KEM-768".to_string()),
            pub_key: Some(URL_SAFE_NO_PAD.encode(&[0u8; 1184])),
        };
        assert!(
            matches!(jwk.to_spki_der(), Err(AcmeError::BadSignatureAlgorithm(_))),
            "unsupported alg should return BadSignatureAlgorithm"
        );
    }
}
