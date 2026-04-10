//! JWK (JSON Web Key) parsing, thumbprint computation, and SPKI DER conversion.
//!
//! No external JOSE crate: thumbprints use sha2 (transitive via synta-mtc),
//! SPKI construction uses synta_certificate::BackendPublicKey factory methods.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use synta_certificate::BackendPublicKey;

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
                let n = self.n.as_deref().ok_or_else(|| {
                    AcmeError::BadRequest("RSA JWK missing 'n'".into())
                })?;
                let e = self.e.as_deref().ok_or_else(|| {
                    AcmeError::BadRequest("RSA JWK missing 'e'".into())
                })?;
                // Required members for RSA: e, kty, n (alphabetical order)
                format!(r#"{{"e":"{}","kty":"RSA","n":"{}"}}"#, e, n)
            }
            "EC" => {
                let crv = self.crv.as_deref().ok_or_else(|| {
                    AcmeError::BadRequest("EC JWK missing 'crv'".into())
                })?;
                let x = self.x.as_deref().ok_or_else(|| {
                    AcmeError::BadRequest("EC JWK missing 'x'".into())
                })?;
                let y = self.y.as_deref().ok_or_else(|| {
                    AcmeError::BadRequest("EC JWK missing 'y'".into())
                })?;
                // Required members for EC: crv, kty, x, y (alphabetical order)
                format!(
                    r#"{{"crv":"{}","kty":"EC","x":"{}","y":"{}"}}"#,
                    crv, x, y
                )
            }
            "OKP" => {
                let crv = self.crv.as_deref().ok_or_else(|| {
                    AcmeError::BadRequest("OKP JWK missing 'crv'".into())
                })?;
                let x = self.x.as_deref().ok_or_else(|| {
                    AcmeError::BadRequest("OKP JWK missing 'x'".into())
                })?;
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

        let hash = Sha256::digest(canonical.as_bytes());
        Ok(URL_SAFE_NO_PAD.encode(hash))
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
        let n_b64 = self.n.as_deref().ok_or_else(|| {
            AcmeError::BadRequest("RSA JWK missing 'n'".into())
        })?;
        let e_b64 = self.e.as_deref().ok_or_else(|| {
            AcmeError::BadRequest("RSA JWK missing 'e'".into())
        })?;

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
        let crv = self.crv.as_deref().ok_or_else(|| {
            AcmeError::BadRequest("EC JWK missing 'crv'".into())
        })?;
        let x_b64 = self.x.as_deref().ok_or_else(|| {
            AcmeError::BadRequest("EC JWK missing 'x'".into())
        })?;
        let y_b64 = self.y.as_deref().ok_or_else(|| {
            AcmeError::BadRequest("EC JWK missing 'y'".into())
        })?;

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
        let crv = self.crv.as_deref().ok_or_else(|| {
            AcmeError::BadRequest("OKP JWK missing 'crv'".into())
        })?;
        let x_b64 = self.x.as_deref().ok_or_else(|| {
            AcmeError::BadRequest("OKP JWK missing 'x'".into())
        })?;

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

    /// RFC 7638 §3.1 example thumbprint
    #[test]
    fn jwk_thumbprint_rfc7638_example() {
        let jwk = JwkPublic {
            kty: "RSA".to_string(),
            crv: None,
            x: None,
            y: None,
            n: Some("0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAt\
                VT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn6\
                4tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_F\
                DW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n9\
                1CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINH\
                aQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw".to_string()),
            e: Some("AQAB".to_string()),
        };
        let thumb = jwk.thumbprint().unwrap();
        assert_eq!(thumb, "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs");
    }
}
