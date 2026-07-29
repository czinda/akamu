//! Minimal JWS (JSON Web Signature) flattened-serialization: sign and verify.
//!
//! ACME uses JWS flattened JSON serialization (RFC 7515 §7.2.6).
//! Signing uses BackendPrivateKey from synta_certificate.
//! Verification uses BackendPublicKey::verify_signature.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::{Deserialize, Serialize};
use synta_certificate::{BackendPrivateKey, BackendPublicKey, CertificateSigner, PrivateKey as _};

use crate::error::JoseError;
use crate::jwk::JwkPublic;

/// JWS flattened JSON serialization (RFC 7515 §7.2.6).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct JwsFlattened {
    /// base64url-encoded protected header (no padding)
    pub protected: String,
    /// base64url-encoded payload (no padding), or empty string for POST-as-GET
    pub payload: String,
    /// base64url-encoded signature bytes (no padding)
    pub signature: String,
}

/// Decoded protected header fields used by ACME.
#[derive(Debug, Deserialize)]
pub struct JwsProtectedHeader {
    /// Signature algorithm: RS256, RS384, RS512, PS256, PS384, PS512,
    /// ES256, ES384, ES512, EdDSA,
    /// ML-DSA-44, ML-DSA-65, ML-DSA-87 (draft-ietf-cose-dilithium-11)
    pub alg: String,
    /// ACME anti-replay nonce
    pub nonce: String,
    /// URL that this request targets (must match request URL)
    pub url: String,
    /// Key reference: either `jwk` (new-account) or `kid` (existing account)
    #[serde(flatten)]
    pub key_ref: JwsKeyRef,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum JwsKeyRef {
    /// First-time request: includes the full public JWK
    Jwk { jwk: JwkPublic },
    /// Subsequent requests: account URL used as key ID
    Kid { kid: String },
}

impl JwsFlattened {
    /// Decode and return the parsed protected header without verifying the signature.
    pub fn decode_header(&self) -> Result<JwsProtectedHeader, JoseError> {
        let header_bytes = URL_SAFE_NO_PAD
            .decode(&self.protected)
            .map_err(|e| JoseError::BadRequest(format!("JWS protected header base64: {}", e)))?;
        serde_json::from_slice::<JwsProtectedHeader>(&header_bytes)
            .map_err(|e| JoseError::BadRequest(format!("JWS protected header JSON: {}", e)))
    }

    /// Decode the payload bytes (base64url → raw bytes).
    ///
    /// Returns an empty Vec for POST-as-GET (empty payload string).
    pub fn decode_payload(&self) -> Result<Vec<u8>, JoseError> {
        if self.payload.is_empty() {
            return Ok(vec![]);
        }
        URL_SAFE_NO_PAD
            .decode(&self.payload)
            .map_err(|e| JoseError::BadRequest(format!("JWS payload base64: {}", e)))
    }

    /// Verify the JWS signature over `<protected>.<payload>` using `spki_der`.
    ///
    /// `spki_der` is the DER-encoded SubjectPublicKeyInfo for the account key.
    pub fn verify(&self, spki_der: &[u8]) -> Result<(), JoseError> {
        let header = self.decode_header()?;

        // JWS signing input: ASCII bytes of "<b64url_protected>.<b64url_payload>"
        let signing_input = format!("{}.{}", self.protected, self.payload);
        let signing_input = signing_input.as_bytes();

        let raw_sig = URL_SAFE_NO_PAD
            .decode(&self.signature)
            .map_err(|e| JoseError::BadRequest(format!("JWS signature base64: {}", e)))?;

        let key = BackendPublicKey::from_spki_der(spki_der.to_vec());

        // draft-ietf-cose-dilithium-11 §4: ML-DSA signatures are raw bytes
        // (not DER), context MUST be empty, and they bypass the
        // verify_signature path entirely.
        if matches!(header.alg.as_str(), "ML-DSA-44" | "ML-DSA-65" | "ML-DSA-87") {
            let expected_sig_len: usize = match header.alg.as_str() {
                "ML-DSA-44" => 2420,
                "ML-DSA-65" => 3309,
                "ML-DSA-87" => 4627,
                _ => unreachable!(),
            };
            if raw_sig.len() != expected_sig_len {
                return Err(JoseError::BadRequest(format!(
                    "ML-DSA signature length {} is wrong for {} (expected {})",
                    raw_sig.len(),
                    header.alg,
                    expected_sig_len
                )));
            }
            return key
                .verify_ml_dsa_with_context(signing_input, &raw_sig, b"")
                .map_err(|e| JoseError::BadRequest(format!("JWS signature invalid: {}", e)));
        }

        verify_with_spki(&header.alg, signing_input, &raw_sig, spki_der).map_err(|e| match e {
            JoseError::UnsupportedAlgorithm(a) => {
                JoseError::UnsupportedAlgorithm(format!("unsupported JWS algorithm: {a}"))
            }
            other => other,
        })
    }

    /// Build and sign a JWS flattened JSON object.
    ///
    /// - `key` — the private key to sign with
    /// - `alg` — JWS algorithm string (e.g. "ES256", "ML-DSA-87")
    /// - `nonce` — ACME anti-replay nonce
    /// - `url` — request URL
    /// - `key_ref` — `JwsKeyRef::Jwk` for new-account, `JwsKeyRef::Kid` for signed requests
    /// - `payload` — raw payload bytes, or `None` for POST-as-GET (empty payload)
    pub fn sign(
        key: &BackendPrivateKey,
        alg: &str,
        nonce: &str,
        url: &str,
        key_ref: JwsKeyRef,
        payload: Option<&[u8]>,
    ) -> Result<Self, JoseError> {
        // Build the protected header JSON.
        let header_value = match &key_ref {
            JwsKeyRef::Jwk { jwk } => serde_json::json!({
                "alg": alg,
                "nonce": nonce,
                "url": url,
                "jwk": jwk,
            }),
            JwsKeyRef::Kid { kid } => serde_json::json!({
                "alg": alg,
                "nonce": nonce,
                "url": url,
                "kid": kid,
            }),
        };
        let header_json = serde_json::to_string(&header_value).map_err(JoseError::Json)?;
        let protected = URL_SAFE_NO_PAD.encode(header_json.as_bytes());

        // Encode the payload.
        let payload_b64 = match payload {
            Some(bytes) => URL_SAFE_NO_PAD.encode(bytes),
            None => String::new(),
        };

        // JWS signing input.
        let signing_input = format!("{}.{}", protected, payload_b64);
        let signing_bytes = signing_input.as_bytes();

        // Sign with the appropriate algorithm.
        let raw_sig: Vec<u8> = match alg {
            "ES256" => {
                let der = key
                    .as_signer("sha256")
                    .sign_tbs(signing_bytes)
                    .map_err(|e| JoseError::Crypto(e.to_string()))?;
                ecdsa_der_to_p1363(&der, 32)
                    .ok_or_else(|| JoseError::Crypto("DER→P1363 failed for ES256".into()))?
            }
            "ES384" => {
                let der = key
                    .as_signer("sha384")
                    .sign_tbs(signing_bytes)
                    .map_err(|e| JoseError::Crypto(e.to_string()))?;
                ecdsa_der_to_p1363(&der, 48)
                    .ok_or_else(|| JoseError::Crypto("DER→P1363 failed for ES384".into()))?
            }
            "ES512" => {
                let der = key
                    .as_signer("sha512")
                    .sign_tbs(signing_bytes)
                    .map_err(|e| JoseError::Crypto(e.to_string()))?;
                ecdsa_der_to_p1363(&der, 66)
                    .ok_or_else(|| JoseError::Crypto("DER→P1363 failed for ES512".into()))?
            }
            "RS256" => key
                .as_signer("sha256")
                .sign_tbs(signing_bytes)
                .map_err(|e| JoseError::Crypto(e.to_string()))?,
            "RS384" => key
                .as_signer("sha384")
                .sign_tbs(signing_bytes)
                .map_err(|e| JoseError::Crypto(e.to_string()))?,
            "RS512" => key
                .as_signer("sha512")
                .sign_tbs(signing_bytes)
                .map_err(|e| JoseError::Crypto(e.to_string()))?,
            "PS256" => key
                .as_signer("pss-sha256")
                .sign_tbs(signing_bytes)
                .map_err(|e| JoseError::Crypto(e.to_string()))?,
            "PS384" => key
                .as_signer("pss-sha384")
                .sign_tbs(signing_bytes)
                .map_err(|e| JoseError::Crypto(e.to_string()))?,
            "PS512" => key
                .as_signer("pss-sha512")
                .sign_tbs(signing_bytes)
                .map_err(|e| JoseError::Crypto(e.to_string()))?,
            "EdDSA" => key
                .as_signer("")
                .sign_tbs(signing_bytes)
                .map_err(|e| JoseError::Crypto(e.to_string()))?,
            "ML-DSA-44" | "ML-DSA-65" | "ML-DSA-87" => key
                .sign_ml_dsa_with_context(signing_bytes, b"")
                .map_err(|e| JoseError::Crypto(e.to_string()))?,
            alg => {
                return Err(JoseError::UnsupportedAlgorithm(format!(
                    "unsupported JWS algorithm for signing: {alg}"
                )));
            }
        };

        Ok(JwsFlattened {
            protected,
            payload: payload_b64,
            signature: URL_SAFE_NO_PAD.encode(&raw_sig),
        })
    }
}

/// Verify a signature over `signing_input` using `spki_der`.
///
/// `raw_sig` is IEEE P1363 for ECDSA algorithms and raw bytes for all others.
/// Shared between JWS flattened and compact JWT verification.
pub(crate) fn verify_with_spki(
    alg: &str,
    signing_input: &[u8],
    raw_sig: &[u8],
    spki_der: &[u8],
) -> Result<(), JoseError> {
    let key = BackendPublicKey::from_spki_der(spki_der.to_vec());
    let (sig_alg_der, verified_sig): (&[u8], Vec<u8>) = match alg {
        "RS256" => (RS256_ALG_DER, raw_sig.to_vec()),
        "RS384" => (RS384_ALG_DER, raw_sig.to_vec()),
        "RS512" => (RS512_ALG_DER, raw_sig.to_vec()),
        "PS256" => (PS256_ALG_DER, raw_sig.to_vec()),
        "PS384" => (PS384_ALG_DER, raw_sig.to_vec()),
        "PS512" => (PS512_ALG_DER, raw_sig.to_vec()),
        "ES256" => {
            let der_sig = p1363_to_der(raw_sig, 32)?;
            (ES256_ALG_DER, der_sig)
        }
        "ES384" => {
            let der_sig = p1363_to_der(raw_sig, 48)?;
            (ES384_ALG_DER, der_sig)
        }
        "ES512" => {
            let der_sig = p1363_to_der(raw_sig, 66)?;
            (ES512_ALG_DER, der_sig)
        }
        "EdDSA" => (EDDSA_ALG_DER, raw_sig.to_vec()),
        "ML-DSA-44" | "ML-DSA-65" | "ML-DSA-87" => {
            let expected_sig_len: usize = match alg {
                "ML-DSA-44" => 2420,
                "ML-DSA-65" => 3309,
                "ML-DSA-87" => 4627,
                _ => unreachable!(),
            };
            if raw_sig.len() != expected_sig_len {
                return Err(JoseError::BadRequest(format!(
                    "ML-DSA signature length {} is wrong for {} (expected {})",
                    raw_sig.len(),
                    alg,
                    expected_sig_len
                )));
            }
            return key
                .verify_ml_dsa_with_context(signing_input, raw_sig, b"")
                .map_err(|e| JoseError::BadRequest(format!("ML-DSA signature invalid: {e}")));
        }
        a => {
            return Err(JoseError::UnsupportedAlgorithm(format!(
                "unsupported algorithm: {a}"
            )));
        }
    };
    key.verify_signature(signing_input, sig_alg_der, &verified_sig)
        .map_err(|e| JoseError::BadRequest(format!("signature invalid: {e}")))
}

// ── DER-encoded AlgorithmIdentifier constants ─────────────────────────────────

/// SHA256WithRSAEncryption (1.2.840.113549.1.1.11) with NULL parameters
const RS256_ALG_DER: &[u8] = &[
    0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00,
];

/// SHA384WithRSAEncryption (1.2.840.113549.1.1.12) with NULL parameters
const RS384_ALG_DER: &[u8] = &[
    0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0c, 0x05, 0x00,
];

/// SHA512WithRSAEncryption (1.2.840.113549.1.1.13) with NULL parameters
const RS512_ALG_DER: &[u8] = &[
    0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0d, 0x05, 0x00,
];

/// RSASSA-PSS (1.2.840.113549.1.1.10) with SHA-256 / MGF1-SHA-256 / salt 32
const PS256_ALG_DER: &[u8] = &[
    0x30, 0x3d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a, 0x30, 0x30, 0xa0,
    0x0d, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0xa1, 0x1a,
    0x30, 0x18, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x08, 0x30, 0x0b, 0x06,
    0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0xa2, 0x03, 0x02, 0x01, 0x20,
];

/// RSASSA-PSS with SHA-384 / MGF1-SHA-384 / salt 48
const PS384_ALG_DER: &[u8] = &[
    0x30, 0x3d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a, 0x30, 0x30, 0xa0,
    0x0d, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0xa1, 0x1a,
    0x30, 0x18, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x08, 0x30, 0x0b, 0x06,
    0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0xa2, 0x03, 0x02, 0x01, 0x30,
];

/// RSASSA-PSS with SHA-512 / MGF1-SHA-512 / salt 64
const PS512_ALG_DER: &[u8] = &[
    0x30, 0x3d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a, 0x30, 0x30, 0xa0,
    0x0d, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0xa1, 0x1a,
    0x30, 0x18, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x08, 0x30, 0x0b, 0x06,
    0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0xa2, 0x03, 0x02, 0x01, 0x40,
];

/// ecdsaWithSHA256 (1.2.840.10045.4.3.2) — no parameters
const ES256_ALG_DER: &[u8] = &[
    0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02,
];

/// ecdsaWithSHA384 (1.2.840.10045.4.3.3) — no parameters
const ES384_ALG_DER: &[u8] = &[
    0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03,
];

/// ecdsaWithSHA512 (1.2.840.10045.4.3.4) — no parameters
const ES512_ALG_DER: &[u8] = &[
    0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x04,
];

/// Ed25519 OID 1.3.101.112
const EDDSA_ALG_DER: &[u8] = &[0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70];

// ── P1363 ↔ DER ECDSA signature conversion ──────────────────────────────────

/// Convert an IEEE P1363 ECDSA signature (r||s, fixed-length) to ASN.1 DER
/// SEQUENCE { r INTEGER, s INTEGER } as required by X.509 / OpenSSL.
///
/// `half` is the expected byte length of each component (32, 48, or 66).
pub fn p1363_to_der(sig: &[u8], half: usize) -> Result<Vec<u8>, JoseError> {
    if sig.len() != half * 2 {
        return Err(JoseError::BadRequest(format!(
            "ECDSA P1363 signature length {} is wrong for half-size {}",
            sig.len(),
            half
        )));
    }

    let r = encode_asn1_integer(&sig[..half]);
    let s = encode_asn1_integer(&sig[half..]);

    let content_len = r.len() + s.len();
    let mut out = Vec::with_capacity(2 + content_len);
    out.push(0x30); // SEQUENCE
    encode_asn1_length(&mut out, content_len);
    out.extend_from_slice(&r);
    out.extend_from_slice(&s);
    Ok(out)
}

/// Convert a DER-encoded ECDSA signature (SEQUENCE{r INTEGER, s INTEGER})
/// to the IEEE P1363 / JWS raw r||s format.
///
/// Returns `None` if the DER is malformed or a component exceeds `half` bytes.
pub fn ecdsa_der_to_p1363(der: &[u8], half: usize) -> Option<Vec<u8>> {
    let inner = strip_tlv(der, 0x30)?;
    let (r, rest) = strip_integer(inner)?;
    let (s, _) = strip_integer(rest)?;
    if r.len() > half || s.len() > half {
        return None;
    }
    let mut out = vec![0u8; half * 2];
    out[half - r.len()..half].copy_from_slice(r);
    out[half * 2 - s.len()..].copy_from_slice(s);
    Some(out)
}

fn strip_tlv(buf: &[u8], tag: u8) -> Option<&[u8]> {
    if *buf.first()? != tag {
        return None;
    }
    let (len, rest) = decode_der_len(&buf[1..])?;
    rest.get(..len)
}

fn strip_integer(buf: &[u8]) -> Option<(&[u8], &[u8])> {
    if *buf.first()? != 0x02 {
        return None;
    }
    let (len, rest) = decode_der_len(&buf[1..])?;
    let val = rest.get(..len)?;
    let rest = &rest[len..];
    let val = val.strip_prefix(&[0x00u8]).unwrap_or(val);
    Some((val, rest))
}

fn decode_der_len(buf: &[u8]) -> Option<(usize, &[u8])> {
    let first = *buf.first()?;
    if first < 0x80 {
        Some((first as usize, &buf[1..]))
    } else if first == 0x81 {
        Some((*buf.get(1)? as usize, &buf[2..]))
    } else if first == 0x82 {
        let len = (*buf.get(1)? as usize) << 8 | *buf.get(2)? as usize;
        Some((len, &buf[3..]))
    } else {
        None
    }
}

/// DER-encode a big-endian unsigned integer.
pub(crate) fn encode_asn1_integer(bytes: &[u8]) -> Vec<u8> {
    let start = bytes
        .iter()
        .position(|&b| b != 0)
        .unwrap_or(bytes.len() - 1);
    let trimmed = &bytes[start..];
    let needs_zero_pad = trimmed.first().map(|&b| b & 0x80 != 0).unwrap_or(false);
    let value_len = trimmed.len() + usize::from(needs_zero_pad);
    let mut out = vec![0x02u8];
    encode_asn1_length(&mut out, value_len);
    if needs_zero_pad {
        out.push(0x00);
    }
    out.extend_from_slice(trimmed);
    out
}

pub(crate) fn encode_asn1_length(buf: &mut Vec<u8>, len: usize) {
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

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

    /// Parse a flattened JWS protected header that carries a JWK key reference.
    #[test]
    fn decode_header_with_jwk() {
        let hdr = r#"{"alg":"ES256","nonce":"abc","url":"https://acme.test/new-account","jwk":{"kty":"EC","crv":"P-256","x":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","y":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}}"#;
        let protected = URL_SAFE_NO_PAD.encode(hdr.as_bytes());
        let jws = JwsFlattened {
            protected,
            payload: String::new(),
            signature: String::new(),
        };
        let h = jws.decode_header().unwrap();
        assert_eq!(h.alg, "ES256");
        assert_eq!(h.nonce, "abc");
        assert_eq!(h.url, "https://acme.test/new-account");
        match h.key_ref {
            JwsKeyRef::Jwk { jwk } => {
                assert_eq!(jwk.kty, "EC");
                assert_eq!(jwk.crv.as_deref(), Some("P-256"));
            }
            JwsKeyRef::Kid { .. } => panic!("expected Jwk, got Kid"),
        }
    }

    #[test]
    fn decode_header_with_kid() {
        let hdr = r#"{"alg":"ES256","nonce":"xyz","url":"https://acme.test/new-order","kid":"https://acme.test/account/42"}"#;
        let protected = URL_SAFE_NO_PAD.encode(hdr.as_bytes());
        let jws = JwsFlattened {
            protected,
            payload: String::new(),
            signature: String::new(),
        };
        let h = jws.decode_header().unwrap();
        assert_eq!(h.alg, "ES256");
        match h.key_ref {
            JwsKeyRef::Kid { kid } => assert_eq!(kid, "https://acme.test/account/42"),
            JwsKeyRef::Jwk { .. } => panic!("expected Kid, got Jwk"),
        }
    }

    fn ecdsa_test_roundtrip(curve: &str, alg: &str, half: usize, hash: &str) {
        let key = BackendPrivateKey::generate_ec(curve).unwrap();
        let spki_der = key.public_key().unwrap().spki_der().to_vec();

        let hdr = format!(
            r#"{{"alg":"{alg}","nonce":"testnonce","url":"https://acme.test/new-account","jwk":{{"kty":"EC","crv":"{curve}","x":"{}","y":"{}"}}}}"#,
            URL_SAFE_NO_PAD.encode(vec![0u8; half]),
            URL_SAFE_NO_PAD.encode(vec![0u8; half]),
        );
        let protected = URL_SAFE_NO_PAD.encode(hdr.as_bytes());
        let payload = URL_SAFE_NO_PAD.encode(b"{}");
        let signing_input = format!("{}.{}", protected, payload);

        let signer = key.as_signer(hash);
        let der_sig = signer.sign_tbs(signing_input.as_bytes()).unwrap();
        let p1363 = ecdsa_der_to_p1363(&der_sig, half).expect("DER→P1363 failed");
        let signature = URL_SAFE_NO_PAD.encode(&p1363);

        let jws = JwsFlattened {
            protected,
            payload,
            signature,
        };
        jws.verify(&spki_der).unwrap();
    }

    #[test]
    fn es256_sign_verify_roundtrip() {
        ecdsa_test_roundtrip("P-256", "ES256", 32, "sha256");
    }

    #[test]
    fn es384_sign_verify_roundtrip() {
        ecdsa_test_roundtrip("P-384", "ES384", 48, "sha384");
    }

    #[test]
    fn es512_sign_verify_roundtrip() {
        ecdsa_test_roundtrip("P-521", "ES512", 66, "sha512");
    }

    #[test]
    fn tampered_signature_is_rejected() {
        let key = BackendPrivateKey::generate_ec("P-256").unwrap();
        let spki_der = key.public_key().unwrap().spki_der().to_vec();

        let hdr = r#"{"alg":"ES256","nonce":"n","url":"https://acme.test/","jwk":{"kty":"EC","crv":"P-256","x":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","y":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}}"#;
        let protected = URL_SAFE_NO_PAD.encode(hdr.as_bytes());
        let payload = URL_SAFE_NO_PAD.encode(b"{}");
        let signing_input = format!("{}.{}", protected, payload);

        let signer = key.as_signer("sha256");
        let der_sig = signer.sign_tbs(signing_input.as_bytes()).unwrap();
        let mut p1363 = ecdsa_der_to_p1363(&der_sig, 32).unwrap();
        p1363[0] ^= 0xff;
        let signature = URL_SAFE_NO_PAD.encode(&p1363);

        let jws = JwsFlattened {
            protected,
            payload,
            signature,
        };
        assert!(jws.verify(&spki_der).is_err());
    }

    #[test]
    fn decode_payload_empty_returns_empty_vec() {
        let jws = JwsFlattened {
            protected: String::new(),
            payload: String::new(),
            signature: String::new(),
        };
        assert!(jws.decode_payload().unwrap().is_empty());
    }

    #[test]
    fn decode_payload_non_empty() {
        let jws = JwsFlattened {
            protected: String::new(),
            payload: URL_SAFE_NO_PAD.encode(b"{\"key\":\"value\"}"),
            signature: String::new(),
        };
        assert_eq!(jws.decode_payload().unwrap(), b"{\"key\":\"value\"}");
    }

    #[test]
    fn decode_payload_invalid_base64_returns_error() {
        let jws = JwsFlattened {
            protected: String::new(),
            payload: "!!!invalid!!!".to_string(),
            signature: String::new(),
        };
        assert!(jws.decode_payload().is_err());
    }

    #[test]
    fn p1363_to_der_wrong_length_returns_error() {
        let result = p1363_to_der(&[0u8; 32], 32);
        assert!(result.is_err());
        match result.unwrap_err() {
            JoseError::BadRequest(msg) => assert!(msg.contains("wrong for half-size")),
            other => panic!("expected BadRequest, got {other:?}"),
        }
    }

    #[test]
    fn p1363_to_der_all_zero_valid() {
        let sig = vec![0u8; 64];
        let der = p1363_to_der(&sig, 32).unwrap();
        assert_eq!(der[0], 0x30);
    }

    #[test]
    fn encode_asn1_integer_high_bit_needs_pad() {
        assert_eq!(encode_asn1_integer(&[0x80]), vec![0x02, 0x02, 0x00, 0x80]);
    }

    #[test]
    fn encode_asn1_integer_no_pad_needed() {
        assert_eq!(encode_asn1_integer(&[0x7f]), vec![0x02, 0x01, 0x7f]);
    }

    #[test]
    fn encode_asn1_length_forms() {
        let mut buf = Vec::new();
        encode_asn1_length(&mut buf, 127);
        assert_eq!(buf, vec![0x7f]);

        let mut buf = Vec::new();
        encode_asn1_length(&mut buf, 128);
        assert_eq!(buf, vec![0x81, 0x80]);

        let mut buf = Vec::new();
        encode_asn1_length(&mut buf, 256);
        assert_eq!(buf, vec![0x82, 0x01, 0x00]);
    }

    #[test]
    fn verify_unsupported_algorithm_returns_error() {
        let key = BackendPrivateKey::generate_ec("P-256").unwrap();
        let spki_der = key.public_key().unwrap().spki_der().to_vec();

        let hdr = r#"{"alg":"BOGUS","nonce":"n","url":"https://acme.test/","kid":"https://acme.test/account/1"}"#;
        let protected = URL_SAFE_NO_PAD.encode(hdr.as_bytes());
        let jws = JwsFlattened {
            protected,
            payload: URL_SAFE_NO_PAD.encode(b"{}"),
            signature: URL_SAFE_NO_PAD.encode([0u8; 64]),
        };
        assert!(matches!(
            jws.verify(&spki_der),
            Err(JoseError::UnsupportedAlgorithm(_))
        ));
    }

    #[test]
    fn verify_bad_protected_base64_returns_error() {
        let key = BackendPrivateKey::generate_ec("P-256").unwrap();
        let spki_der = key.public_key().unwrap().spki_der().to_vec();
        let jws = JwsFlattened {
            protected: "!!!not base64!!!".to_string(),
            payload: String::new(),
            signature: String::new(),
        };
        assert!(jws.verify(&spki_der).is_err());
    }

    #[test]
    fn ecdsa_der_to_p1363_r_too_large_returns_none() {
        let r = vec![0x42u8; 33];
        let s = vec![0x01u8; 32];
        let mut der = Vec::new();
        der.push(0x02);
        der.push(r.len() as u8);
        der.extend_from_slice(&r);
        der.push(0x02);
        der.push(s.len() as u8);
        der.extend_from_slice(&s);
        let mut seq = vec![0x30, der.len() as u8];
        seq.extend_from_slice(&der);
        assert!(ecdsa_der_to_p1363(&seq, 32).is_none());
    }

    #[test]
    fn decode_der_len_forms() {
        assert_eq!(decode_der_len(&[0x81, 0x80]).unwrap(), (128, [].as_ref()));
        assert_eq!(
            decode_der_len(&[0x82, 0x01, 0x00]).unwrap(),
            (256, [].as_ref())
        );
        assert!(decode_der_len(&[0x83, 0x01, 0x00, 0x01]).is_none());
    }

    // ── ML-DSA tests ──────────────────────────────────────────────────────────

    fn ml_dsa_raw_pub_from_spki(spki: &[u8]) -> &[u8] {
        &spki[22..]
    }

    fn ml_dsa_test_roundtrip(variant: &str) {
        let priv_key = BackendPrivateKey::generate_ml_dsa(variant).unwrap();
        let pub_key = priv_key.public_key().unwrap();
        let spki_der = pub_key.spki_der().to_vec();

        let raw_pub = ml_dsa_raw_pub_from_spki(&spki_der);
        let pub_b64 = URL_SAFE_NO_PAD.encode(raw_pub);

        let hdr = format!(
            r#"{{"alg":"{variant}","nonce":"n","url":"https://acme.test/","jwk":{{"kty":"AKP","alg":"{variant}","pub":"{pub_b64}"}}}}"#
        );
        let protected = URL_SAFE_NO_PAD.encode(hdr.as_bytes());
        let payload = URL_SAFE_NO_PAD.encode(b"{}");
        let signing_input = format!("{}.{}", protected, payload);

        let raw_sig = priv_key
            .sign_ml_dsa_with_context(signing_input.as_bytes(), b"")
            .unwrap();
        let jws = JwsFlattened {
            protected,
            payload,
            signature: URL_SAFE_NO_PAD.encode(&raw_sig),
        };
        jws.verify(&spki_der).unwrap();
    }

    #[test]
    fn ml_dsa_44_sign_verify_roundtrip() {
        ml_dsa_test_roundtrip("ML-DSA-44");
    }

    #[test]
    fn ml_dsa_65_sign_verify_roundtrip() {
        ml_dsa_test_roundtrip("ML-DSA-65");
    }

    #[test]
    fn ml_dsa_87_sign_verify_roundtrip() {
        ml_dsa_test_roundtrip("ML-DSA-87");
    }

    #[test]
    fn ml_dsa_87_tampered_signature_rejected() {
        let priv_key = BackendPrivateKey::generate_ml_dsa("ML-DSA-87").unwrap();
        let pub_key = priv_key.public_key().unwrap();
        let spki_der = pub_key.spki_der().to_vec();

        let raw_pub = ml_dsa_raw_pub_from_spki(&spki_der);
        let pub_b64 = URL_SAFE_NO_PAD.encode(raw_pub);
        let hdr = format!(
            r#"{{"alg":"ML-DSA-87","nonce":"n","url":"https://acme.test/","jwk":{{"kty":"AKP","alg":"ML-DSA-87","pub":"{pub_b64}"}}}}"#
        );
        let protected = URL_SAFE_NO_PAD.encode(hdr.as_bytes());
        let payload = URL_SAFE_NO_PAD.encode(b"{}");
        let signing_input = format!("{}.{}", protected, payload);

        let mut raw_sig = priv_key
            .sign_ml_dsa_with_context(signing_input.as_bytes(), b"")
            .unwrap();
        raw_sig[0] ^= 0xff;

        let jws = JwsFlattened {
            protected,
            payload,
            signature: URL_SAFE_NO_PAD.encode(&raw_sig),
        };
        assert!(jws.verify(&spki_der).is_err());
    }

    #[test]
    fn ml_dsa_wrong_signature_length_returns_error() {
        let priv_key = BackendPrivateKey::generate_ml_dsa("ML-DSA-87").unwrap();
        let spki_der = priv_key.public_key().unwrap().spki_der().to_vec();

        let hdr = r#"{"alg":"ML-DSA-87","nonce":"n","url":"https://acme.test/","kid":"https://acme.test/account/1"}"#;
        let protected = URL_SAFE_NO_PAD.encode(hdr.as_bytes());
        let jws = JwsFlattened {
            protected,
            payload: URL_SAFE_NO_PAD.encode(b"{}"),
            signature: URL_SAFE_NO_PAD.encode([0u8; 64]),
        };
        let result = jws.verify(&spki_der);
        assert!(matches!(result, Err(JoseError::BadRequest(_))));
    }

    // ── JwsFlattened::sign() tests ────────────────────────────────────────────

    #[test]
    fn sign_es256_and_verify() {
        let key = BackendPrivateKey::generate_ec("P-256").unwrap();
        let spki_der = key.public_key().unwrap().spki_der().to_vec();
        let jwk = crate::jwk::JwkPublic::from_public_key(&key.public_key().unwrap()).unwrap();

        let jws = JwsFlattened::sign(
            &key,
            "ES256",
            "testnonce",
            "https://acme.test/new-account",
            JwsKeyRef::Jwk { jwk },
            Some(b"{}"),
        )
        .unwrap();
        jws.verify(&spki_der).unwrap();
    }

    #[test]
    fn sign_ml_dsa_87_and_verify() {
        let key = BackendPrivateKey::generate_ml_dsa("ML-DSA-87").unwrap();
        let spki_der = key.public_key().unwrap().spki_der().to_vec();
        let jwk = crate::jwk::JwkPublic::from_public_key(&key.public_key().unwrap()).unwrap();

        let jws = JwsFlattened::sign(
            &key,
            "ML-DSA-87",
            "testnonce",
            "https://acme.test/new-account",
            JwsKeyRef::Jwk { jwk },
            Some(b"{}"),
        )
        .unwrap();
        jws.verify(&spki_der).unwrap();
    }

    #[test]
    fn sign_ps256_and_verify() {
        let key = BackendPrivateKey::generate_rsa(2048, 65537).unwrap();
        let spki_der = key.public_key().unwrap().spki_der().to_vec();
        let jwk = crate::jwk::JwkPublic::from_public_key(&key.public_key().unwrap()).unwrap();

        let jws = JwsFlattened::sign(
            &key,
            "PS256",
            "testnonce",
            "https://acme.test/new-account",
            JwsKeyRef::Jwk { jwk },
            Some(b"{}"),
        )
        .unwrap();
        jws.verify(&spki_der).unwrap();
    }

    #[test]
    fn sign_ps384_and_verify() {
        let key = BackendPrivateKey::generate_rsa(2048, 65537).unwrap();
        let spki_der = key.public_key().unwrap().spki_der().to_vec();
        let jwk = crate::jwk::JwkPublic::from_public_key(&key.public_key().unwrap()).unwrap();

        let jws = JwsFlattened::sign(
            &key,
            "PS384",
            "testnonce",
            "https://acme.test/new-account",
            JwsKeyRef::Jwk { jwk },
            Some(b"{}"),
        )
        .unwrap();
        jws.verify(&spki_der).unwrap();
    }

    #[test]
    fn sign_rs256_and_verify() {
        let key = BackendPrivateKey::generate_rsa(2048, 65537).unwrap();
        let spki_der = key.public_key().unwrap().spki_der().to_vec();
        let jwk = crate::jwk::JwkPublic::from_public_key(&key.public_key().unwrap()).unwrap();

        let jws = JwsFlattened::sign(
            &key,
            "RS256",
            "testnonce",
            "https://acme.test/new-account",
            JwsKeyRef::Jwk { jwk },
            Some(b"{}"),
        )
        .unwrap();
        jws.verify(&spki_der).unwrap();
    }

    #[test]
    fn sign_post_as_get_empty_payload() {
        let key = BackendPrivateKey::generate_ec("P-256").unwrap();
        let spki_der = key.public_key().unwrap().spki_der().to_vec();
        let jws = JwsFlattened::sign(
            &key,
            "ES256",
            "nonce",
            "https://acme.test/order/1",
            JwsKeyRef::Kid {
                kid: "https://acme.test/account/1".to_string(),
            },
            None,
        )
        .unwrap();
        assert!(
            jws.payload.is_empty(),
            "POST-as-GET must have empty payload"
        );
        jws.verify(&spki_der).unwrap();
    }

    #[test]
    fn sign_unsupported_algorithm_returns_error() {
        let key = BackendPrivateKey::generate_ec("P-256").unwrap();
        let result = JwsFlattened::sign(
            &key,
            "BOGUS",
            "nonce",
            "https://acme.test/",
            JwsKeyRef::Kid {
                kid: "https://acme.test/account/1".to_string(),
            },
            None,
        );
        assert!(matches!(result, Err(JoseError::UnsupportedAlgorithm(_))));
    }
}
