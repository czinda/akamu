//! JWK (JSON Web Key) parsing, thumbprint computation, and SPKI DER conversion.
//!
//! No external JOSE crate: thumbprints use synta_certificate's DataHasher,
//! SPKI construction uses synta_certificate::BackendPublicKey factory methods.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::{Deserialize, Serialize};
use synta_certificate::{default_data_hasher, BackendPublicKey, DataHasher};

use crate::error::JoseError;

/// A JWK public key as used in ACME protected headers and account objects.
///
/// Only the subset of fields required for ACME is parsed. The `d` (private
/// key component) field is intentionally ignored.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct JwkPublic {
    /// Key type: "RSA", "EC", "OKP", "AKP"
    pub kty: String,

    // EC / OKP common
    /// Curve name: "P-256", "P-384", "P-521" (EC) or "Ed25519", "Ed448" (OKP)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub crv: Option<String>,
    /// X coordinate / public key bytes (base64url, no padding)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x: Option<String>,
    /// Y coordinate (base64url, no padding) — EC only
    #[serde(skip_serializing_if = "Option::is_none")]
    pub y: Option<String>,

    // RSA
    /// RSA modulus (base64url)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub n: Option<String>,
    /// RSA public exponent (base64url)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub e: Option<String>,

    // AKP (ML-DSA per draft-ietf-cose-dilithium-11)
    /// Algorithm identifier: "ML-DSA-44", "ML-DSA-65", "ML-DSA-87"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alg: Option<String>,
    /// Raw public key bytes (base64url, no padding) — `pub` in JSON
    #[serde(rename = "pub", skip_serializing_if = "Option::is_none")]
    pub pub_key: Option<String>,
}

impl JwkPublic {
    /// Compute the RFC 7638 JWK thumbprint (SHA-256 of the canonical JSON form).
    ///
    /// Returns the base64url-encoded (no padding) thumbprint string.
    pub fn thumbprint(&self) -> Result<String, JoseError> {
        // RFC 7638 §3.2: required members, lexicographically sorted, no whitespace
        let canonical = match self.kty.as_str() {
            "RSA" => {
                let n = self
                    .n
                    .as_deref()
                    .ok_or_else(|| JoseError::BadRequest("RSA JWK missing 'n'".into()))?;
                let e = self
                    .e
                    .as_deref()
                    .ok_or_else(|| JoseError::BadRequest("RSA JWK missing 'e'".into()))?;
                // Required members for RSA: e, kty, n (alphabetical order)
                format!(r#"{{"e":"{}","kty":"RSA","n":"{}"}}"#, e, n)
            }
            "EC" => {
                let crv = self
                    .crv
                    .as_deref()
                    .ok_or_else(|| JoseError::BadRequest("EC JWK missing 'crv'".into()))?;
                let x = self
                    .x
                    .as_deref()
                    .ok_or_else(|| JoseError::BadRequest("EC JWK missing 'x'".into()))?;
                let y = self
                    .y
                    .as_deref()
                    .ok_or_else(|| JoseError::BadRequest("EC JWK missing 'y'".into()))?;
                // Required members for EC: crv, kty, x, y (alphabetical order)
                format!(r#"{{"crv":"{}","kty":"EC","x":"{}","y":"{}"}}"#, crv, x, y)
            }
            "OKP" => {
                let crv = self
                    .crv
                    .as_deref()
                    .ok_or_else(|| JoseError::BadRequest("OKP JWK missing 'crv'".into()))?;
                let x = self
                    .x
                    .as_deref()
                    .ok_or_else(|| JoseError::BadRequest("OKP JWK missing 'x'".into()))?;
                // Required members for OKP: crv, kty, x (alphabetical order)
                format!(r#"{{"crv":"{}","kty":"OKP","x":"{}"}}"#, crv, x)
            }
            "AKP" => {
                let alg = self
                    .alg
                    .as_deref()
                    .ok_or_else(|| JoseError::BadRequest("AKP JWK missing 'alg'".into()))?;
                let pub_key = self
                    .pub_key
                    .as_deref()
                    .ok_or_else(|| JoseError::BadRequest("AKP JWK missing 'pub'".into()))?;
                // draft-ietf-cose-dilithium-11 §6: alg, kty, pub (alphabetical order)
                format!(r#"{{"alg":"{}","kty":"AKP","pub":"{}"}}"#, alg, pub_key)
            }
            kty => {
                return Err(JoseError::UnsupportedAlgorithm(format!(
                    "unsupported JWK key type: {}",
                    kty
                )));
            }
        };

        let hash = default_data_hasher()
            .hash_data("sha256", canonical.as_bytes())
            .map_err(|e| JoseError::Crypto(format!("SHA-256 thumbprint: {e}")))?;
        Ok(URL_SAFE_NO_PAD.encode(&hash))
    }

    /// Convert this JWK to DER-encoded SubjectPublicKeyInfo (SPKI).
    ///
    /// Uses synta_certificate's BackendPublicKey factory methods so the OpenSSL
    /// backend handles all key encoding internally — no direct openssl crate dep.
    pub fn to_spki_der(&self) -> Result<Vec<u8>, JoseError> {
        match self.kty.as_str() {
            "RSA" => self.rsa_to_spki_der(),
            "EC" => self.ec_to_spki_der(),
            "OKP" => self.okp_to_spki_der(),
            "AKP" => self.ml_dsa_to_spki_der(),
            kty => Err(JoseError::UnsupportedAlgorithm(format!(
                "unsupported JWK key type: {}",
                kty
            ))),
        }
    }

    /// Construct a `JwkPublic` from a synta `BackendPublicKey`.
    ///
    /// Handles EC (P-256/P-384/P-521), OKP (Ed25519/Ed448), AKP (ML-DSA-44/65/87),
    /// and RSA key types.
    pub fn from_public_key(key: &BackendPublicKey) -> Result<Self, JoseError> {
        match key.key_type() {
            "ec" => {
                let crv_raw = key
                    .ec_curve_name()
                    .map_err(|e| JoseError::Crypto(e.to_string()))?
                    .ok_or_else(|| JoseError::Crypto("EC key has no curve name".into()))?;
                let (crv, coord_size): (&str, usize) = match crv_raw {
                    "P-256" | "prime256v1" => ("P-256", 32),
                    "P-384" | "secp384r1" => ("P-384", 48),
                    "P-521" | "secp521r1" => ("P-521", 66),
                    other => {
                        return Err(JoseError::UnsupportedAlgorithm(format!(
                            "unsupported EC curve: {other}"
                        )));
                    }
                };
                let (x_raw, y_raw) = key
                    .ec_affine_coordinates()
                    .map_err(|e| JoseError::Crypto(e.to_string()))?
                    .ok_or_else(|| JoseError::Crypto("EC key has no affine coordinates".into()))?;
                Ok(JwkPublic {
                    kty: "EC".to_string(),
                    crv: Some(crv.to_string()),
                    x: Some(pad_coord(&x_raw, coord_size)),
                    y: Some(pad_coord(&y_raw, coord_size)),
                    n: None,
                    e: None,
                    alg: None,
                    pub_key: None,
                })
            }
            "rsa" => {
                let n_raw = key
                    .rsa_modulus()
                    .map_err(|e| JoseError::Crypto(e.to_string()))?
                    .ok_or_else(|| JoseError::Crypto("RSA key has no modulus".into()))?;
                let e_raw = key
                    .rsa_public_exponent()
                    .map_err(|e| JoseError::Crypto(e.to_string()))?
                    .ok_or_else(|| JoseError::Crypto("RSA key has no public exponent".into()))?;
                Ok(JwkPublic {
                    kty: "RSA".to_string(),
                    crv: None,
                    x: None,
                    y: None,
                    n: Some(URL_SAFE_NO_PAD.encode(&n_raw)),
                    e: Some(URL_SAFE_NO_PAD.encode(&e_raw)),
                    alg: None,
                    pub_key: None,
                })
            }
            "ed25519" => {
                // Ed25519 SPKI: 12-byte prefix + 32-byte key
                let spki = key.spki_der();
                if spki.len() < 12 + 32 {
                    return Err(JoseError::Crypto("Ed25519 SPKI DER too short".into()));
                }
                Ok(JwkPublic {
                    kty: "OKP".to_string(),
                    crv: Some("Ed25519".to_string()),
                    x: Some(URL_SAFE_NO_PAD.encode(&spki[12..])),
                    y: None,
                    n: None,
                    e: None,
                    alg: None,
                    pub_key: None,
                })
            }
            "ed448" => {
                // Ed448 SPKI: 12-byte prefix + 57-byte key
                let spki = key.spki_der();
                if spki.len() < 12 + 57 {
                    return Err(JoseError::Crypto("Ed448 SPKI DER too short".into()));
                }
                Ok(JwkPublic {
                    kty: "OKP".to_string(),
                    crv: Some("Ed448".to_string()),
                    x: Some(URL_SAFE_NO_PAD.encode(&spki[12..])),
                    y: None,
                    n: None,
                    e: None,
                    alg: None,
                    pub_key: None,
                })
            }
            _ => {
                // Check for ML-DSA via SPKI OID bytes.
                // ML-DSA SPKI layout:
                //   offset 0: 30 82 XX XX   outer SEQUENCE
                //   offset 4: 30 0B         AlgId SEQUENCE
                //   offset 6: 06 09         OID TLV (9 bytes)
                //   offset 8-16: OID bytes  (bytes 8-15 common; byte 16 = variant)
                //   offset 17+: BIT STRING + raw key
                //   offset 22+: raw public key bytes
                const ML_DSA_OID_PREFIX: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03];
                const SPKI_HEADER: usize = 22;

                let spki = key.spki_der();
                if spki.len() > 17 && spki[8..16] == *ML_DSA_OID_PREFIX {
                    let (alg_name, expected_pub_len): (&str, usize) = match spki[16] {
                        0x11 => ("ML-DSA-44", 1312),
                        0x12 => ("ML-DSA-65", 1952),
                        0x13 => ("ML-DSA-87", 2592),
                        b => {
                            return Err(JoseError::UnsupportedAlgorithm(format!(
                                "unknown ML-DSA OID variant: 0x{b:02x}"
                            )));
                        }
                    };
                    if spki.len() != SPKI_HEADER + expected_pub_len {
                        return Err(JoseError::Crypto(format!(
                            "ML-DSA SPKI length {} is wrong for {alg_name}",
                            spki.len()
                        )));
                    }
                    Ok(JwkPublic {
                        kty: "AKP".to_string(),
                        crv: None,
                        x: None,
                        y: None,
                        n: None,
                        e: None,
                        alg: Some(alg_name.to_string()),
                        pub_key: Some(URL_SAFE_NO_PAD.encode(&spki[SPKI_HEADER..])),
                    })
                } else {
                    Err(JoseError::UnsupportedAlgorithm(
                        "unknown public key type".into(),
                    ))
                }
            }
        }
    }

    fn rsa_to_spki_der(&self) -> Result<Vec<u8>, JoseError> {
        let n_b64 = self
            .n
            .as_deref()
            .ok_or_else(|| JoseError::BadRequest("RSA JWK missing 'n'".into()))?;
        let e_b64 = self
            .e
            .as_deref()
            .ok_or_else(|| JoseError::BadRequest("RSA JWK missing 'e'".into()))?;

        let n = URL_SAFE_NO_PAD
            .decode(n_b64)
            .map_err(|e| JoseError::BadRequest(format!("JWK 'n' base64: {}", e)))?;
        let e = URL_SAFE_NO_PAD
            .decode(e_b64)
            .map_err(|e| JoseError::BadRequest(format!("JWK 'e' base64: {}", e)))?;

        let key = BackendPublicKey::from_rsa_components(&n, &e)
            .map_err(|e| JoseError::Crypto(format!("RSA key from JWK: {}", e)))?;
        Ok(key.spki_der().to_vec())
    }

    fn ec_to_spki_der(&self) -> Result<Vec<u8>, JoseError> {
        let crv = self
            .crv
            .as_deref()
            .ok_or_else(|| JoseError::BadRequest("EC JWK missing 'crv'".into()))?;
        let x_b64 = self
            .x
            .as_deref()
            .ok_or_else(|| JoseError::BadRequest("EC JWK missing 'x'".into()))?;
        let y_b64 = self
            .y
            .as_deref()
            .ok_or_else(|| JoseError::BadRequest("EC JWK missing 'y'".into()))?;

        let x = URL_SAFE_NO_PAD
            .decode(x_b64)
            .map_err(|e| JoseError::BadRequest(format!("JWK 'x' base64: {}", e)))?;
        let y = URL_SAFE_NO_PAD
            .decode(y_b64)
            .map_err(|e| JoseError::BadRequest(format!("JWK 'y' base64: {}", e)))?;

        // Map JWK curve names to synta convention
        let curve = match crv {
            "P-256" => "P-256",
            "P-384" => "P-384",
            "P-521" => "P-521",
            other => {
                return Err(JoseError::UnsupportedAlgorithm(format!(
                    "unsupported EC curve: {}",
                    other
                )));
            }
        };

        let key = BackendPublicKey::from_ec_components(&x, &y, curve)
            .map_err(|e| JoseError::Crypto(format!("EC key from JWK: {}", e)))?;
        Ok(key.spki_der().to_vec())
    }

    fn okp_to_spki_der(&self) -> Result<Vec<u8>, JoseError> {
        let crv = self
            .crv
            .as_deref()
            .ok_or_else(|| JoseError::BadRequest("OKP JWK missing 'crv'".into()))?;
        let x_b64 = self
            .x
            .as_deref()
            .ok_or_else(|| JoseError::BadRequest("OKP JWK missing 'x'".into()))?;

        let x_bytes = URL_SAFE_NO_PAD
            .decode(x_b64)
            .map_err(|e| JoseError::BadRequest(format!("JWK 'x' base64: {}", e)))?;

        match crv {
            "Ed25519" => build_okp_spki(&x_bytes, OKP_ED25519_SPKI_PREFIX),
            "Ed448" => build_okp_spki(&x_bytes, OKP_ED448_SPKI_PREFIX),
            other => Err(JoseError::UnsupportedAlgorithm(format!(
                "unsupported OKP curve: {}",
                other
            ))),
        }
    }

    fn ml_dsa_to_spki_der(&self) -> Result<Vec<u8>, JoseError> {
        let alg = self
            .alg
            .as_deref()
            .ok_or_else(|| JoseError::BadRequest("AKP JWK missing 'alg'".into()))?;
        let pub_b64 = self
            .pub_key
            .as_deref()
            .ok_or_else(|| JoseError::BadRequest("AKP JWK missing 'pub'".into()))?;

        let pub_bytes = URL_SAFE_NO_PAD
            .decode(pub_b64)
            .map_err(|e| JoseError::BadRequest(format!("JWK 'pub' base64: {}", e)))?;

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
                return Err(JoseError::UnsupportedAlgorithm(format!(
                    "unsupported AKP algorithm: {}",
                    other
                )));
            }
        };

        if pub_bytes.len() != expected_len {
            return Err(JoseError::BadRequest(format!(
                "AKP '{}' public key has wrong length: {} (expected {})",
                alg,
                pub_bytes.len(),
                expected_len
            )));
        }

        Ok(build_ml_dsa_spki(oid_bytes, &pub_bytes))
    }
}

/// Find the JWK whose `kid` field matches `kid` in a raw JWKS JSON body.
///
/// Returns a deserialized `JwkPublic` so callers can call `.to_spki_der()`.
/// `JwkPublic` has no `kid` field; the lookup reads `kid` from raw JSON before
/// deserializing, so extra JWKS fields are silently ignored.
pub fn find_by_kid(jwks_bytes: &[u8], kid: &str) -> Result<JwkPublic, JoseError> {
    let jwks: serde_json::Value = serde_json::from_slice(jwks_bytes)
        .map_err(|e| JoseError::BadRequest(format!("JWKS JSON: {e}")))?;
    let keys = jwks["keys"]
        .as_array()
        .ok_or_else(|| JoseError::BadRequest("JWKS missing 'keys' array".into()))?;
    for entry in keys {
        if entry.get("kid").and_then(|k| k.as_str()) == Some(kid) {
            return serde_json::from_value::<JwkPublic>(entry.clone())
                .map_err(|e| JoseError::BadRequest(format!("JWKS entry for kid '{kid}': {e}")));
        }
    }
    Err(JoseError::BadRequest(format!(
        "kid '{kid}' not found in JWKS"
    )))
}

// ── SPKI helper for coordinate padding ────────────────────────────────────────

fn pad_coord(v: &[u8], size: usize) -> String {
    let mut out = vec![0u8; size];
    let start = size.saturating_sub(v.len());
    out[start..].copy_from_slice(&v[v.len().saturating_sub(size)..]);
    URL_SAFE_NO_PAD.encode(&out)
}

// ── Fixed SPKI prefix bytes for EdDSA public keys ─────────────────────────────
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

fn build_okp_spki(x_bytes: &[u8], prefix: &[u8]) -> Result<Vec<u8>, JoseError> {
    // Validate length: Ed25519 = 32, Ed448 = 57
    let expected_len = match prefix[8] {
        0x70 => 32usize, // Ed25519
        0x71 => 57usize, // Ed448
        _ => return Err(JoseError::Crypto("unknown OKP prefix".into())),
    };
    if x_bytes.len() != expected_len {
        return Err(JoseError::BadRequest(format!(
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
pub(crate) fn build_ml_dsa_spki(oid_bytes: &[u8], pub_key: &[u8]) -> Vec<u8> {
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

pub(crate) fn der_push_length(buf: &mut Vec<u8>, len: usize) {
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
        // Should be prefix (12 bytes) + key (32 bytes) = 44 bytes
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
            x: Some(URL_SAFE_NO_PAD.encode([0u8; 32])),
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
            x: Some(URL_SAFE_NO_PAD.encode([0u8; 32])),
            y: Some(URL_SAFE_NO_PAD.encode([0u8; 32])),
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
        let jwk = JwkPublic {
            kty: "EC".to_string(),
            crv: Some("P-256".to_string()),
            x: None,
            y: Some(URL_SAFE_NO_PAD.encode([0u8; 32])),
            n: None,
            e: None,
            alg: None,
            pub_key: None,
        };
        let err = jwk.thumbprint().unwrap_err();
        match err {
            JoseError::BadRequest(msg) => assert!(msg.contains("EC JWK missing 'x'")),
            other => panic!("expected BadRequest, got {other:?}"),
        }
    }

    #[test]
    fn ec_thumbprint_missing_y_returns_error() {
        let jwk = JwkPublic {
            kty: "EC".to_string(),
            crv: Some("P-256".to_string()),
            x: Some(URL_SAFE_NO_PAD.encode([0u8; 32])),
            y: None,
            n: None,
            e: None,
            alg: None,
            pub_key: None,
        };
        let err = jwk.thumbprint().unwrap_err();
        match err {
            JoseError::BadRequest(msg) => assert!(msg.contains("EC JWK missing 'y'")),
            other => panic!("expected BadRequest, got {other:?}"),
        }
    }

    #[test]
    fn okp_thumbprint_missing_crv_returns_error() {
        let jwk = JwkPublic {
            kty: "OKP".to_string(),
            crv: None,
            x: Some(URL_SAFE_NO_PAD.encode([0u8; 32])),
            y: None,
            n: None,
            e: None,
            alg: None,
            pub_key: None,
        };
        let err = jwk.thumbprint().unwrap_err();
        match err {
            JoseError::BadRequest(msg) => assert!(msg.contains("OKP JWK missing 'crv'")),
            other => panic!("expected BadRequest, got {other:?}"),
        }
    }

    #[test]
    fn ec_spki_missing_x_returns_error() {
        let jwk = JwkPublic {
            kty: "EC".to_string(),
            crv: Some("P-256".to_string()),
            x: None,
            y: Some(URL_SAFE_NO_PAD.encode([0u8; 32])),
            n: None,
            e: None,
            alg: None,
            pub_key: None,
        };
        let err = jwk.to_spki_der().unwrap_err();
        match err {
            JoseError::BadRequest(msg) => assert!(msg.contains("EC JWK missing 'x'")),
            other => panic!("expected BadRequest, got {other:?}"),
        }
    }

    #[test]
    fn ec_spki_missing_y_returns_error() {
        let jwk = JwkPublic {
            kty: "EC".to_string(),
            crv: Some("P-256".to_string()),
            x: Some(URL_SAFE_NO_PAD.encode([0u8; 32])),
            y: None,
            n: None,
            e: None,
            alg: None,
            pub_key: None,
        };
        let err = jwk.to_spki_der().unwrap_err();
        match err {
            JoseError::BadRequest(msg) => assert!(msg.contains("EC JWK missing 'y'")),
            other => panic!("expected BadRequest, got {other:?}"),
        }
    }

    #[test]
    fn okp_spki_missing_crv_returns_error() {
        let jwk = JwkPublic {
            kty: "OKP".to_string(),
            crv: None,
            x: Some(URL_SAFE_NO_PAD.encode([0u8; 32])),
            y: None,
            n: None,
            e: None,
            alg: None,
            pub_key: None,
        };
        let err = jwk.to_spki_der().unwrap_err();
        match err {
            JoseError::BadRequest(msg) => assert!(msg.contains("OKP JWK missing 'crv'")),
            other => panic!("expected BadRequest, got {other:?}"),
        }
    }

    #[test]
    fn build_okp_spki_unknown_prefix_returns_error() {
        let mut bad_prefix = OKP_ED25519_SPKI_PREFIX.to_vec();
        bad_prefix[8] = 0xFF; // invalid OKP type byte
        let result = build_okp_spki(&[0u8; 32], &bad_prefix);
        assert!(
            matches!(result, Err(JoseError::Crypto(_))),
            "expected Crypto error for unknown OKP prefix, got {result:?}"
        );
    }

    // ── AKP (ML-DSA) tests ────────────────────────────────────────────────────

    #[test]
    fn akp_ml_dsa_87_thumbprint_succeeds() {
        let pub_bytes = vec![0xABu8; 2592];
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

    #[test]
    fn akp_ml_dsa_87_spki_roundtrip() {
        let priv_key = BackendPrivateKey::generate_ml_dsa("ML-DSA-87").unwrap();
        let pub_key = priv_key.public_key().unwrap();
        let spki_der = pub_key.spki_der().to_vec();

        const SPKI_HEADER: usize = 22;
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
            pub_key: Some(URL_SAFE_NO_PAD.encode([0u8; 2592])),
        };
        assert!(
            matches!(jwk.thumbprint(), Err(JoseError::BadRequest(_))),
            "missing 'alg' should return BadRequest"
        );
        assert!(
            matches!(jwk.to_spki_der(), Err(JoseError::BadRequest(_))),
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
            matches!(jwk.thumbprint(), Err(JoseError::BadRequest(_))),
            "missing 'pub' should return BadRequest"
        );
        assert!(
            matches!(jwk.to_spki_der(), Err(JoseError::BadRequest(_))),
            "missing 'pub' should return BadRequest"
        );
    }

    #[test]
    fn akp_wrong_pub_length_returns_error() {
        let jwk = JwkPublic {
            kty: "AKP".to_string(),
            crv: None,
            x: None,
            y: None,
            n: None,
            e: None,
            alg: Some("ML-DSA-87".to_string()),
            pub_key: Some(URL_SAFE_NO_PAD.encode([0u8; 2591])),
        };
        assert!(
            matches!(jwk.to_spki_der(), Err(JoseError::BadRequest(_))),
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
            pub_key: Some(URL_SAFE_NO_PAD.encode([0u8; 1184])),
        };
        assert!(
            matches!(jwk.to_spki_der(), Err(JoseError::UnsupportedAlgorithm(_))),
            "unsupported alg should return UnsupportedAlgorithm"
        );
    }

    // ── from_public_key() tests ───────────────────────────────────────────────

    #[test]
    fn from_public_key_ec_p256_roundtrip() {
        let priv_key = BackendPrivateKey::generate_ec("P-256").unwrap();
        let pub_key = priv_key.public_key().unwrap();
        let jwk = JwkPublic::from_public_key(&pub_key).unwrap();
        assert_eq!(jwk.kty, "EC");
        assert_eq!(jwk.crv.as_deref(), Some("P-256"));
        assert!(jwk.x.is_some());
        assert!(jwk.y.is_some());
        // round-trip through SPKI DER
        let spki = jwk.to_spki_der().unwrap();
        assert_eq!(spki, pub_key.spki_der().to_vec());
    }

    #[test]
    fn from_public_key_ec_p384_roundtrip() {
        let priv_key = BackendPrivateKey::generate_ec("P-384").unwrap();
        let pub_key = priv_key.public_key().unwrap();
        let jwk = JwkPublic::from_public_key(&pub_key).unwrap();
        assert_eq!(jwk.kty, "EC");
        assert_eq!(jwk.crv.as_deref(), Some("P-384"));
        let spki = jwk.to_spki_der().unwrap();
        assert_eq!(spki, pub_key.spki_der().to_vec());
    }

    #[test]
    fn from_public_key_ml_dsa_87_roundtrip() {
        let priv_key = BackendPrivateKey::generate_ml_dsa("ML-DSA-87").unwrap();
        let pub_key = priv_key.public_key().unwrap();
        let jwk = JwkPublic::from_public_key(&pub_key).unwrap();
        assert_eq!(jwk.kty, "AKP");
        assert_eq!(jwk.alg.as_deref(), Some("ML-DSA-87"));
        assert!(jwk.pub_key.is_some());
        let spki = jwk.to_spki_der().unwrap();
        assert_eq!(spki, pub_key.spki_der().to_vec());
    }

    #[test]
    fn from_public_key_ml_dsa_65_roundtrip() {
        let priv_key = BackendPrivateKey::generate_ml_dsa("ML-DSA-65").unwrap();
        let pub_key = priv_key.public_key().unwrap();
        let jwk = JwkPublic::from_public_key(&pub_key).unwrap();
        assert_eq!(jwk.kty, "AKP");
        assert_eq!(jwk.alg.as_deref(), Some("ML-DSA-65"));
        let spki = jwk.to_spki_der().unwrap();
        assert_eq!(spki, pub_key.spki_der().to_vec());
    }

    #[test]
    fn from_public_key_ml_dsa_44_roundtrip() {
        let priv_key = BackendPrivateKey::generate_ml_dsa("ML-DSA-44").unwrap();
        let pub_key = priv_key.public_key().unwrap();
        let jwk = JwkPublic::from_public_key(&pub_key).unwrap();
        assert_eq!(jwk.kty, "AKP");
        assert_eq!(jwk.alg.as_deref(), Some("ML-DSA-44"));
        let spki = jwk.to_spki_der().unwrap();
        assert_eq!(spki, pub_key.spki_der().to_vec());
    }

    #[test]
    fn from_public_key_ed25519_roundtrip() {
        let priv_key = BackendPrivateKey::generate_ed25519().unwrap();
        let pub_key = priv_key.public_key().unwrap();
        let jwk = JwkPublic::from_public_key(&pub_key).unwrap();
        assert_eq!(jwk.kty, "OKP");
        assert_eq!(jwk.crv.as_deref(), Some("Ed25519"));
        assert!(jwk.x.is_some());
        let spki = jwk.to_spki_der().unwrap();
        assert_eq!(spki, pub_key.spki_der().to_vec());
    }

    #[test]
    fn from_public_key_rsa_roundtrip() {
        let priv_key = BackendPrivateKey::generate_rsa(2048, 65537).unwrap();
        let pub_key = priv_key.public_key().unwrap();
        let jwk = JwkPublic::from_public_key(&pub_key).unwrap();
        assert_eq!(jwk.kty, "RSA");
        assert!(jwk.n.is_some());
        assert!(jwk.e.is_some());
        let spki = jwk.to_spki_der().unwrap();
        assert_eq!(spki, pub_key.spki_der().to_vec());
    }

    #[test]
    fn jwk_serialize_omits_none_fields() {
        let jwk = JwkPublic {
            kty: "EC".to_string(),
            crv: Some("P-256".to_string()),
            x: Some("abc".to_string()),
            y: Some("def".to_string()),
            n: None,
            e: None,
            alg: None,
            pub_key: None,
        };
        let json = serde_json::to_string(&jwk).unwrap();
        assert!(json.contains("\"kty\""), "kty must be present");
        assert!(json.contains("\"crv\""), "crv must be present");
        assert!(!json.contains("\"n\""), "n must be absent");
        assert!(!json.contains("\"e\""), "e must be absent");
        assert!(!json.contains("\"alg\""), "alg must be absent");
    }

    // ── find_by_kid tests ─────────────────────────────────────────────────────

    #[test]
    fn find_by_kid_returns_matching_key() {
        let jwks = br#"{"keys":[
            {"kty":"EC","kid":"key-1","crv":"P-256","x":"AAAA","y":"BBBB"},
            {"kty":"EC","kid":"key-2","crv":"P-384","x":"CCCC","y":"DDDD"}
        ]}"#;
        let jwk = find_by_kid(jwks, "key-2").unwrap();
        assert_eq!(jwk.kty, "EC");
        assert_eq!(jwk.crv.as_deref(), Some("P-384"));
    }

    #[test]
    fn find_by_kid_absent_kid_returns_error() {
        let jwks = br#"{"keys":[{"kty":"EC","kid":"key-1","crv":"P-256","x":"A","y":"B"}]}"#;
        let err = find_by_kid(jwks, "key-99").unwrap_err();
        assert!(
            matches!(err, JoseError::BadRequest(ref m) if m.contains("key-99")),
            "expected error mentioning missing kid, got {err:?}"
        );
    }

    #[test]
    fn find_by_kid_missing_keys_array_returns_error() {
        let jwks = br#"{"not_keys":[]}"#;
        let err = find_by_kid(jwks, "any").unwrap_err();
        assert!(matches!(err, JoseError::BadRequest(_)));
    }

    #[test]
    fn find_by_kid_invalid_json_returns_error() {
        let err = find_by_kid(b"not json", "any").unwrap_err();
        assert!(matches!(err, JoseError::BadRequest(_)));
    }

    #[test]
    fn jwk_serialize_akp_uses_pub_field_name() {
        let jwk = JwkPublic {
            kty: "AKP".to_string(),
            crv: None,
            x: None,
            y: None,
            n: None,
            e: None,
            alg: Some("ML-DSA-44".to_string()),
            pub_key: Some("AAAA".to_string()),
        };
        let json = serde_json::to_string(&jwk).unwrap();
        assert!(
            json.contains("\"pub\""),
            "AKP field must serialize as 'pub'"
        );
        assert!(
            !json.contains("\"pub_key\""),
            "must not use Rust field name"
        );
    }
}
