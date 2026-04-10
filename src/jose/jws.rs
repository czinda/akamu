//! Minimal JWS (JSON Web Signature) flattened-serialization verification.
//!
//! ACME uses JWS flattened JSON serialization (RFC 7515 §7.2.6).
//! Verification uses BackendPublicKey::verify_signature (synta_certificate)
//! so all crypto stays in the synta / OpenSSL backend.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::Deserialize;
use synta_certificate::BackendPublicKey;

use crate::error::AcmeError;
use super::jwk::JwkPublic;

/// JWS flattened JSON serialization (RFC 7515 §7.2.6).
#[derive(Debug, Deserialize)]
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
    /// ES256, ES384, ES512, EdDSA
    pub alg: String,
    /// ACME anti-replay nonce
    pub nonce: String,
    /// URL that this request targets (must match request URL)
    pub url: String,
    /// Key reference: either `jwk` (new-account) or `kid` (existing account)
    #[serde(flatten)]
    pub key_ref: JwsKeyRef,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum JwsKeyRef {
    /// First-time request: includes the full public JWK
    Jwk { jwk: JwkPublic },
    /// Subsequent requests: account URL used as key ID
    Kid { kid: String },
}

impl JwsFlattened {
    /// Decode and return the parsed protected header without verifying the signature.
    pub fn decode_header(&self) -> Result<JwsProtectedHeader, AcmeError> {
        let header_bytes = URL_SAFE_NO_PAD
            .decode(&self.protected)
            .map_err(|e| AcmeError::BadRequest(format!("JWS protected header base64: {}", e)))?;
        serde_json::from_slice::<JwsProtectedHeader>(&header_bytes)
            .map_err(|e| AcmeError::BadRequest(format!("JWS protected header JSON: {}", e)))
    }

    /// Decode the payload bytes (base64url → raw bytes).
    ///
    /// Returns an empty Vec for POST-as-GET (empty payload string).
    pub fn decode_payload(&self) -> Result<Vec<u8>, AcmeError> {
        if self.payload.is_empty() {
            return Ok(vec![]);
        }
        URL_SAFE_NO_PAD
            .decode(&self.payload)
            .map_err(|e| AcmeError::BadRequest(format!("JWS payload base64: {}", e)))
    }

    /// Verify the JWS signature over `<protected>.<payload>` using `spki_der`.
    ///
    /// `spki_der` is the DER-encoded SubjectPublicKeyInfo for the account key.
    pub fn verify(&self, spki_der: &[u8]) -> Result<(), AcmeError> {
        let header = self.decode_header()?;

        // JWS signing input: ASCII bytes of "<b64url_protected>.<b64url_payload>"
        let signing_input = format!("{}.{}", self.protected, self.payload);
        let signing_input = signing_input.as_bytes();

        let raw_sig = URL_SAFE_NO_PAD
            .decode(&self.signature)
            .map_err(|e| AcmeError::BadRequest(format!("JWS signature base64: {}", e)))?;

        let key = BackendPublicKey::from_spki_der(spki_der.to_vec());

        // For ECDSA algorithms, JWS uses IEEE P1363 encoding (raw r||s);
        // synta_certificate's verify_signature expects DER (SEQUENCE {r, s}).
        // Convert before verification.
        let (sig_alg_der, verified_sig) = match header.alg.as_str() {
            "RS256" => (RS256_ALG_DER, raw_sig),
            "RS384" => (RS384_ALG_DER, raw_sig),
            "RS512" => (RS512_ALG_DER, raw_sig),
            "PS256" => (PS256_ALG_DER, raw_sig),
            "PS384" => (PS384_ALG_DER, raw_sig),
            "PS512" => (PS512_ALG_DER, raw_sig),
            "ES256" => {
                let der_sig = p1363_to_der(&raw_sig, 32)?;
                (ES256_ALG_DER, der_sig)
            }
            "ES384" => {
                let der_sig = p1363_to_der(&raw_sig, 48)?;
                (ES384_ALG_DER, der_sig)
            }
            "ES512" => {
                let der_sig = p1363_to_der(&raw_sig, 66)?;
                (ES512_ALG_DER, der_sig)
            }
            "EdDSA" => (EDDSA_ALG_DER, raw_sig),
            alg => {
                return Err(AcmeError::BadSignatureAlgorithm(format!(
                    "unsupported JWS algorithm: {}",
                    alg
                )));
            }
        };

        key.verify_signature(signing_input, sig_alg_der, &verified_sig)
            .map_err(|e| AcmeError::Unauthorized(format!("JWS signature invalid: {}", e)))
    }
}

// ── DER-encoded AlgorithmIdentifier constants ─────────────────────────────────
//
// These are static DER byte sequences for each JWS algorithm identifier.
// Encoding: SEQUENCE { OID, [parameters] }

/// SHA256WithRSAEncryption (1.2.840.113549.1.1.11) with NULL parameters
const RS256_ALG_DER: &[u8] = &[
    0x30, 0x0d,
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b,
    0x05, 0x00,
];

/// SHA384WithRSAEncryption (1.2.840.113549.1.1.12) with NULL parameters
const RS384_ALG_DER: &[u8] = &[
    0x30, 0x0d,
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0c,
    0x05, 0x00,
];

/// SHA512WithRSAEncryption (1.2.840.113549.1.1.13) with NULL parameters
const RS512_ALG_DER: &[u8] = &[
    0x30, 0x0d,
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0d,
    0x05, 0x00,
];

/// RSASSA-PSS (1.2.840.113549.1.1.10) with SHA-256 parameters (PS256)
const PS256_ALG_DER: &[u8] = &[
    0x30, 0x41,
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a,
    0x30, 0x34,
    // hashAlgorithm [0] EXPLICIT: SHA-256
    0xa0, 0x0d, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
    // maskGenAlgorithm [1] EXPLICIT: MGF1 with SHA-256
    0xa1, 0x1a, 0x30, 0x18, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x08,
    0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
    // saltLength [2] EXPLICIT: 32
    0xa2, 0x03, 0x02, 0x01, 0x20,
    // trailerField [3] EXPLICIT: 1 (BC)
    0xa3, 0x03, 0x02, 0x01, 0x01,
];

/// RSASSA-PSS with SHA-384 parameters (PS384)
const PS384_ALG_DER: &[u8] = &[
    0x30, 0x41,
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a,
    0x30, 0x34,
    0xa0, 0x0d, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02,
    0xa1, 0x1a, 0x30, 0x18, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x08,
    0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02,
    0xa2, 0x03, 0x02, 0x01, 0x30, // saltLength = 48
    0xa3, 0x03, 0x02, 0x01, 0x01,
];

/// RSASSA-PSS with SHA-512 parameters (PS512)
const PS512_ALG_DER: &[u8] = &[
    0x30, 0x41,
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a,
    0x30, 0x34,
    0xa0, 0x0d, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03,
    0xa1, 0x1a, 0x30, 0x18, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x08,
    0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03,
    0xa2, 0x03, 0x02, 0x01, 0x40, // saltLength = 64
    0xa3, 0x03, 0x02, 0x01, 0x01,
];

/// ecdsaWithSHA256 (1.2.840.10045.4.3.2) — no parameters
const ES256_ALG_DER: &[u8] = &[
    0x30, 0x0a,
    0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02,
];

/// ecdsaWithSHA384 (1.2.840.10045.4.3.3) — no parameters
const ES384_ALG_DER: &[u8] = &[
    0x30, 0x0a,
    0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03,
];

/// ecdsaWithSHA512 (1.2.840.10045.4.3.4) — no parameters
const ES512_ALG_DER: &[u8] = &[
    0x30, 0x0a,
    0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x04,
];

/// Ed25519 / Ed448: OID 1.3.101.112 (Ed25519) — use key type from SPKI;
/// this is a placeholder; the actual algorithm for EdDSA is determined by
/// the key type embedded in the SPKI, so we pass the Ed25519 DER here and
/// rely on the backend to infer Ed448 from the key.
/// In practice, ACME's "EdDSA" alg is always Ed25519 (RFC 8037).
const EDDSA_ALG_DER: &[u8] = &[
    0x30, 0x05,
    0x06, 0x03, 0x2b, 0x65, 0x70, // OID 1.3.101.112 (Ed25519)
];

// ── P1363 → DER ECDSA signature conversion ──────────────────────────────────

/// Convert an IEEE P1363 ECDSA signature (r||s, fixed-length) to ASN.1 DER
/// SEQUENCE { r INTEGER, s INTEGER } as required by X.509 / OpenSSL.
///
/// `half` is the expected byte length of each component (32, 48, or 66).
fn p1363_to_der(sig: &[u8], half: usize) -> Result<Vec<u8>, AcmeError> {
    if sig.len() != half * 2 {
        return Err(AcmeError::BadRequest(format!(
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

/// DER-encode a big-endian unsigned integer:
/// strip leading zeros, prepend 0x00 if high bit is set, wrap in INTEGER TLV.
fn encode_asn1_integer(bytes: &[u8]) -> Vec<u8> {
    // Strip leading zero bytes
    let start = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len() - 1);
    let trimmed = &bytes[start..];

    // Prepend 0x00 if the high bit of the first content byte is set
    let needs_zero_pad = trimmed.first().map(|&b| b & 0x80 != 0).unwrap_or(false);

    let value_len = trimmed.len() + usize::from(needs_zero_pad);
    let mut out = vec![0x02u8]; // INTEGER tag
    encode_asn1_length(&mut out, value_len);
    if needs_zero_pad {
        out.push(0x00);
    }
    out.extend_from_slice(trimmed);
    out
}

fn encode_asn1_length(buf: &mut Vec<u8>, len: usize) {
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
    use synta_certificate::{BackendPrivateKey, CertificateSigner, PrivateKey as _};

    /// Parse a flattened JWS protected header that carries a JWK key reference.
    #[test]
    fn decode_header_with_jwk() {
        // 43 'A' chars = valid base64url for 32 zero bytes (P-256 coord placeholder)
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

    /// Parse a flattened JWS protected header that carries a `kid` key reference.
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
        assert_eq!(h.nonce, "xyz");
        match h.key_ref {
            JwsKeyRef::Kid { kid } => {
                assert_eq!(kid, "https://acme.test/account/42");
            }
            JwsKeyRef::Jwk { .. } => panic!("expected Kid, got Jwk"),
        }
    }

    /// Round-trip: sign an ES256 JWS with a fresh P-256 key and verify it.
    ///
    /// Uses synta_certificate's BackendPrivateKey for signing (produces DER ECDSA)
    /// then converts DER → P1363 (IEEE P1363 / JWS format) before encoding.
    #[test]
    fn es256_sign_verify_roundtrip() {
        let key = BackendPrivateKey::generate_ec("P-256").unwrap();
        let spki_der = key.public_key().unwrap().spki_der().to_vec();

        // Protected header: alg=ES256, placeholder JWK (verify() uses spki_der, not the JWK).
        let hdr = r#"{"alg":"ES256","nonce":"testnonce","url":"https://acme.test/new-account","jwk":{"kty":"EC","crv":"P-256","x":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","y":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}}"#;
        let protected = URL_SAFE_NO_PAD.encode(hdr.as_bytes());
        let payload = URL_SAFE_NO_PAD.encode(b"{}");
        let signing_input = format!("{}.{}", protected, payload);

        // Sign → DER ECDSA → convert to P1363 (r||s) for JWS.
        let signer = key.as_signer("sha256");
        let der_sig = signer.sign_tbs(signing_input.as_bytes()).unwrap();
        let p1363 = ecdsa_der_to_p1363(&der_sig, 32).expect("DER→P1363 conversion failed");
        let signature = URL_SAFE_NO_PAD.encode(&p1363);

        let jws = JwsFlattened { protected, payload, signature };
        jws.verify(&spki_der).unwrap();
    }

    /// Wrong signature must be rejected.
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
        // Flip one byte to corrupt the signature.
        p1363[0] ^= 0xff;
        let signature = URL_SAFE_NO_PAD.encode(&p1363);

        let jws = JwsFlattened { protected, payload, signature };
        assert!(jws.verify(&spki_der).is_err(), "tampered signature should fail");
    }

    /// Convert a DER-encoded ECDSA signature (SEQUENCE{r INTEGER, s INTEGER})
    /// to the IEEE P1363 / JWS raw r||s format.
    fn ecdsa_der_to_p1363(der: &[u8], half: usize) -> Option<Vec<u8>> {
        let inner = strip_tlv(der, 0x30)?;
        let (r, rest) = strip_integer(inner)?;
        let (s, _) = strip_integer(rest)?;
        if r.len() > half || s.len() > half {
            return None;
        }
        let mut out = vec![0u8; half * 2];
        // Right-align r into [0, half) and s into [half, 2*half).
        out[half - r.len()..half].copy_from_slice(r);
        out[half * 2 - s.len()..].copy_from_slice(s);
        Some(out)
    }

    fn strip_tlv<'a>(buf: &'a [u8], tag: u8) -> Option<&'a [u8]> {
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
        // Strip the leading 0x00 sign-padding byte that DER adds when the
        // high bit is set (to keep the integer positive).
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

    #[test]
    fn decode_payload_empty_returns_empty_vec() {
        let jws = JwsFlattened {
            protected: String::new(),
            payload: String::new(),
            signature: String::new(),
        };
        let result = jws.decode_payload().unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn decode_payload_non_empty() {
        let jws = JwsFlattened {
            protected: String::new(),
            payload: URL_SAFE_NO_PAD.encode(b"{\"key\":\"value\"}"),
            signature: String::new(),
        };
        let result = jws.decode_payload().unwrap();
        assert_eq!(result, b"{\"key\":\"value\"}");
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
        // ES256 expects 64 bytes (32+32), provide only 32.
        let short_sig = vec![0u8; 32];
        let result = p1363_to_der(&short_sig, 32);
        assert!(result.is_err());
        match result.unwrap_err() {
            AcmeError::BadRequest(msg) => assert!(msg.contains("wrong for half-size")),
            other => panic!("expected BadRequest, got {other:?}"),
        }
    }

    #[test]
    fn p1363_to_der_all_zero_valid() {
        // Zero signature bytes are valid P1363 input (mathematically nonsense, but structurally valid).
        let sig = vec![0u8; 64]; // 32+32 for ES256
        let result = p1363_to_der(&sig, 32);
        assert!(result.is_ok());
        let der = result.unwrap();
        // Should start with SEQUENCE tag 0x30.
        assert_eq!(der[0], 0x30);
    }

    #[test]
    fn encode_asn1_integer_high_bit_needs_pad() {
        // 0x80 needs zero-padding: result should be 02 02 00 80
        let result = encode_asn1_integer(&[0x80]);
        assert_eq!(result, vec![0x02, 0x02, 0x00, 0x80]);
    }

    #[test]
    fn encode_asn1_integer_no_pad_needed() {
        // 0x7f does not need padding: result should be 02 01 7f
        let result = encode_asn1_integer(&[0x7f]);
        assert_eq!(result, vec![0x02, 0x01, 0x7f]);
    }

    #[test]
    fn encode_asn1_length_short_form() {
        let mut buf = Vec::new();
        encode_asn1_length(&mut buf, 127);
        assert_eq!(buf, vec![0x7f]);
    }

    #[test]
    fn encode_asn1_length_two_byte_form() {
        let mut buf = Vec::new();
        encode_asn1_length(&mut buf, 128);
        assert_eq!(buf, vec![0x81, 0x80]);

        let mut buf = Vec::new();
        encode_asn1_length(&mut buf, 255);
        assert_eq!(buf, vec![0x81, 0xff]);
    }

    #[test]
    fn encode_asn1_length_three_byte_form() {
        let mut buf = Vec::new();
        encode_asn1_length(&mut buf, 256);
        assert_eq!(buf, vec![0x82, 0x01, 0x00]);

        let mut buf = Vec::new();
        encode_asn1_length(&mut buf, 0x1234);
        assert_eq!(buf, vec![0x82, 0x12, 0x34]);
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
            signature: URL_SAFE_NO_PAD.encode(&[0u8; 64]),
        };
        let result = jws.verify(&spki_der);
        assert!(result.is_err());
        match result.unwrap_err() {
            AcmeError::BadSignatureAlgorithm(_) => {}
            other => panic!("expected BadSignatureAlgorithm, got {other:?}"),
        }
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
    fn verify_bad_signature_base64_returns_error() {
        let key = BackendPrivateKey::generate_ec("P-256").unwrap();
        let spki_der = key.public_key().unwrap().spki_der().to_vec();

        let hdr = r#"{"alg":"ES256","nonce":"n","url":"https://acme.test/","kid":"https://acme.test/account/1"}"#;
        let protected = URL_SAFE_NO_PAD.encode(hdr.as_bytes());
        let jws = JwsFlattened {
            protected,
            payload: String::new(),
            signature: "!!!not base64!!!".to_string(),
        };
        assert!(jws.verify(&spki_der).is_err());
    }

    /// ES384 sign/verify round-trip using a P-384 key.
    /// Covers jws.rs lines 102-103 (ES384 path in JwsFlattened::verify).
    #[test]
    fn es384_sign_verify_roundtrip() {
        let key = BackendPrivateKey::generate_ec("P-384").unwrap();
        let spki_der = key.public_key().unwrap().spki_der().to_vec();

        let hdr = r#"{"alg":"ES384","nonce":"testnonce","url":"https://acme.test/new-account","kid":"https://acme.test/account/1"}"#;
        let protected = URL_SAFE_NO_PAD.encode(hdr.as_bytes());
        let payload = URL_SAFE_NO_PAD.encode(b"{}");
        let signing_input = format!("{}.{}", protected, payload);

        // P-384 signs with SHA-384; P1363 format needs 48 bytes per component.
        let signer = key.as_signer("sha384");
        let der_sig = signer.sign_tbs(signing_input.as_bytes()).unwrap();
        let p1363 = ecdsa_der_to_p1363(&der_sig, 48).expect("DER→P1363 for P-384 failed");
        let signature = URL_SAFE_NO_PAD.encode(&p1363);

        let jws = JwsFlattened { protected, payload, signature };
        jws.verify(&spki_der).unwrap();
    }

    /// ES512 sign/verify round-trip using a P-521 key.
    /// Covers jws.rs lines 106-107 (ES512 path in JwsFlattened::verify).
    #[test]
    fn es512_sign_verify_roundtrip() {
        let key = BackendPrivateKey::generate_ec("P-521").unwrap();
        let spki_der = key.public_key().unwrap().spki_der().to_vec();

        let hdr = r#"{"alg":"ES512","nonce":"testnonce","url":"https://acme.test/new-account","kid":"https://acme.test/account/1"}"#;
        let protected = URL_SAFE_NO_PAD.encode(hdr.as_bytes());
        let payload = URL_SAFE_NO_PAD.encode(b"{}");
        let signing_input = format!("{}.{}", protected, payload);

        // P-521 signs with SHA-512; P1363 format needs 66 bytes per component.
        let signer = key.as_signer("sha512");
        let der_sig = signer.sign_tbs(signing_input.as_bytes()).unwrap();
        let p1363 = ecdsa_der_to_p1363(&der_sig, 66).expect("DER→P1363 for P-521 failed");
        let signature = URL_SAFE_NO_PAD.encode(&p1363);

        let jws = JwsFlattened { protected, payload, signature };
        jws.verify(&spki_der).unwrap();
    }

    /// ecdsa_der_to_p1363 with r > half returns None.
    /// Covers jws.rs line 384.
    #[test]
    fn ecdsa_der_to_p1363_r_too_large_returns_none() {
        // Manually craft a DER ECDSA signature with r component of 33 non-zero bytes (> 32 for ES256).
        // strip_integer strips leading 0x00, so r must start with a non-zero byte.
        let mut r = vec![0x01u8; 33]; // 33 bytes, all non-zero — too large for half=32
        r[0] = 0x42; // ensure high bit clear so DER doesn't add extra pad
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
        let result = ecdsa_der_to_p1363(&seq, 32);
        assert!(result.is_none(), "expected None when r > half");
    }

    /// strip_tlv returns None when the first byte is not the expected tag.
    /// Covers jws.rs line 395.
    #[test]
    fn strip_tlv_wrong_tag_returns_none() {
        let buf = &[0x04u8, 0x02, 0x01, 0x02]; // tag 0x04 instead of 0x30
        assert!(strip_tlv(buf, 0x30).is_none());
    }

    /// strip_integer returns None when first byte is not 0x02.
    /// Covers jws.rs line 403.
    #[test]
    fn strip_integer_wrong_tag_returns_none() {
        let buf = &[0x04u8, 0x01, 0x00]; // tag 0x04 instead of 0x02
        assert!(strip_integer(buf).is_none());
    }

    /// decode_der_len handles 0x81 (one-byte length) form.
    /// Covers jws.rs lines 418-419.
    #[test]
    fn decode_der_len_0x81_form() {
        let buf = &[0x81u8, 0x80]; // 0x81 means 1 extra byte: length = 0x80 = 128
        let (len, rest) = decode_der_len(buf).unwrap();
        assert_eq!(len, 128);
        assert!(rest.is_empty());
    }

    /// decode_der_len handles 0x82 (two-byte length) form.
    /// Covers jws.rs lines 420-422.
    #[test]
    fn decode_der_len_0x82_form() {
        let buf = &[0x82u8, 0x01, 0x00]; // 0x82 means 2 extra bytes: length = 0x0100 = 256
        let (len, rest) = decode_der_len(buf).unwrap();
        assert_eq!(len, 256);
        assert!(rest.is_empty());
    }

    /// decode_der_len returns None for unsupported length encodings (e.g. 0x83+).
    /// Covers jws.rs line 424.
    #[test]
    fn decode_der_len_unsupported_form_returns_none() {
        let buf = &[0x83u8, 0x01, 0x00, 0x01]; // 0x83 = 3 extra bytes — not supported
        assert!(decode_der_len(buf).is_none());
    }
}
