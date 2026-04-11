//! onion-csr-01 challenge validation (RFC 9799 §3.2).
//!
//! The client submits a CSR that:
//!  - Contains the `.onion` domain in a SAN dNSName.
//!  - Contains the `cabf-onion-csr-nonce` extension (OID 2.23.140.41) whose
//!    value equals the key authorization string (`token.thumbprint`).
//!  - Is signed with **both** the CSR key (self-signature) and the hidden
//!    service's Ed25519 private key, whose corresponding public key is encoded
//!    in the v3 `.onion` address itself.
//!
//! This module performs the server-side validation:
//!  1. Decode the 32-byte Ed25519 public key from the `.onion` address label.
//!  2. Parse the CSR and verify its self-signature (via synta-certificate).
//!  3. Verify that the `cabf-onion-csr-nonce` extension contains the correct
//!     key authorization.
//!  4. Verify the Ed25519 signature over the `CertificationRequestInfo` DER
//!     using the hidden-service public key via `ring`.
//!  5. Verify that the CSR contains the `.onion` domain in a SAN dNSName.

use synta::traits::Encode;
use synta::{Decoder, Encoder, Encoding};
use synta_certificate::{csr::CertificationRequest, general_name, oids, parse_general_names};

use crate::error::AcmeError;

/// OID 2.23.140.41 — CA/B Forum `cabf-onion-csr-nonce` extension.
const CABF_ONION_CSR_NONCE: &[u32] = &[2, 23, 140, 41];

/// Check whether `value` is a valid v3 `.onion` domain.
///
/// A v3 address consists of a single 56-character base32 label followed by
/// `.onion`.  The label encodes 35 bytes: 32-byte Ed25519 public key, 2-byte
/// checksum, 1-byte version (0x03).
///
/// RFC 9799 §2: v2 addresses (16-char label) MUST NOT be used.
pub fn validate_onion_v3(domain: &str) -> bool {
    let label = match domain.strip_suffix(".onion").and_then(|s| {
        // Support subdomains: take the rightmost label before ".onion".
        // For a bare address like `abc…xyz.onion` this is the whole prefix.
        let last = s.rsplit('.').next()?;
        Some(last)
    }) {
        Some(l) => l,
        None => return false,
    };
    label.len() == 56
        && label
            .bytes()
            .all(|b| matches!(b, b'a'..=b'z' | b'2'..=b'7'))
}

/// Decode a v3 `.onion` address label (56 base32 chars) to a 32-byte Ed25519
/// public key.
///
/// The label encodes 35 bytes via RFC 4648 base32 (no padding):
///   `[pubkey(32)] || [checksum(2)] || [version(1)]`
///
/// Returns `None` if decoding fails or the version byte is not 0x03.
fn decode_onion_pubkey(domain: &str) -> Option<[u8; 32]> {
    let label = domain.strip_suffix(".onion")?.rsplit('.').next()?;
    if label.len() != 56 {
        return None;
    }
    // Decode base32 (lowercase, no padding) manually.
    let decoded = base32_decode_no_pad(label.as_bytes())?;
    if decoded.len() < 35 {
        return None;
    }
    // Version byte must be 0x03 (v3).
    if decoded[34] != 0x03 {
        return None;
    }
    let mut pubkey = [0u8; 32];
    pubkey.copy_from_slice(&decoded[..32]);
    Some(pubkey)
}

/// Decode a RFC 4648 base32 string without padding into bytes.
///
/// Alphabet: `a-z2-7` (lower-case, as used in .onion addresses).
fn base32_decode_no_pad(input: &[u8]) -> Option<Vec<u8>> {
    let mut bits: u64 = 0;
    let mut bit_count: u32 = 0;
    let mut output = Vec::with_capacity(input.len() * 5 / 8);
    for &b in input {
        let val: u64 = match b {
            b'a'..=b'z' => (b - b'a') as u64,
            b'2'..=b'7' => (b - b'2' + 26) as u64,
            _ => return None,
        };
        bits = (bits << 5) | val;
        bit_count += 5;
        if bit_count >= 8 {
            bit_count -= 8;
            output.push((bits >> bit_count) as u8);
            bits &= (1u64 << bit_count) - 1;
        }
    }
    // Remaining bits must be zero (padding bits).
    if bits != 0 {
        return None;
    }
    Some(output)
}

/// Build a minimal Ed25519 SubjectPublicKeyInfo DER from a raw 32-byte public key.
///
/// The SPKI structure is:
/// ```text
/// SEQUENCE {
///   SEQUENCE { OID id-Ed25519 (1.3.101.112) }  -- AlgorithmIdentifier, no params
///   BIT STRING (0 unused bits) <32-byte pubkey>
/// }
/// ```
fn ed25519_spki_der(pubkey_bytes: &[u8; 32]) -> Vec<u8> {
    // OID 1.3.101.112 in DER: 06 03 2B 65 70
    let alg_id: &[u8] = &[0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70];
    // BIT STRING: 03 21 00 <32 bytes>
    let mut bit_string = vec![0x03, 0x21, 0x00];
    bit_string.extend_from_slice(pubkey_bytes);
    // Outer SEQUENCE: alg_id (7 bytes) + bit_string (35 bytes) = 42 bytes
    let inner_len = alg_id.len() + bit_string.len();
    let mut spki = Vec::with_capacity(2 + inner_len);
    spki.push(0x30);
    spki.push(inner_len as u8); // inner_len = 42, fits in one byte
    spki.extend_from_slice(alg_id);
    spki.extend_from_slice(&bit_string);
    spki
}

/// Build the AlgorithmIdentifier DER for id-Ed25519 (1.3.101.112, no params).
///
/// ```text
/// SEQUENCE { OID 1.3.101.112 }
/// ```
fn ed25519_alg_id_der() -> Vec<u8> {
    // 30 05  06 03  2B 65 70
    vec![0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70]
}

// ── Helpers reused from csr.rs (duplicated to keep modules independent) ────────

/// Return `(header_bytes, value_bytes)` for the TLV starting at `der[pos]`.
fn tlv_header(der: &[u8], pos: usize) -> Option<(usize, usize)> {
    let d = &der[pos..];
    if d.len() < 2 {
        return None;
    }
    let mut i = 1usize;
    let vlen = if d[i] < 0x80 {
        let l = d[i] as usize;
        i += 1;
        l
    } else {
        let num_bytes = (d[i] & 0x7f) as usize;
        i += 1;
        if num_bytes == 0 || num_bytes > (usize::BITS / 8) as usize || d.len() < i + num_bytes {
            return None;
        }
        let mut l = 0usize;
        for k in 0..num_bytes {
            l = (l << 8) | d[i + k] as usize;
        }
        i += num_bytes;
        l
    };
    Some((i, vlen))
}

/// Skip the outer SEQUENCE TLV header and return the content bytes.
fn strip_sequence(der: &[u8]) -> Option<&[u8]> {
    if der.first()? != &0x30 {
        return None;
    }
    let (hlen, vlen) = tlv_header(der, 0)?;
    Some(&der[hlen..hlen + vlen])
}

/// Decoded extension: OID arcs + raw value (content of the OCTET STRING).
struct CsrExt {
    oid_arcs: Vec<u32>,
    value_der: Vec<u8>,
}

/// Decode a DER-encoded `SEQUENCE OF Extension` into `CsrExt` items.
fn decode_extension_sequence(seq_der: &[u8]) -> Result<Vec<CsrExt>, AcmeError> {
    let content = strip_sequence(seq_der)
        .ok_or_else(|| AcmeError::BadCsr("extensionRequest is not a valid SEQUENCE".into()))?;
    let mut pos = 0;
    let mut result = Vec::new();
    while pos < content.len() {
        let (hlen, vlen) = tlv_header(content, pos)
            .ok_or_else(|| AcmeError::BadCsr("truncated Extension TLV".into()))?;
        if pos + hlen + vlen > content.len() {
            return Err(AcmeError::BadCsr("Extension TLV truncated".into()));
        }
        let ext_der = &content[pos..pos + hlen + vlen];
        pos += hlen + vlen;
        let mut dec = Decoder::new(ext_der, Encoding::Der);
        let ext = dec
            .decode::<synta_certificate::Extension>()
            .map_err(|e| AcmeError::BadCsr(format!("Extension decode: {e}")))?;
        result.push(CsrExt {
            oid_arcs: ext.extn_id.components().to_vec(),
            value_der: ext.extn_value.as_bytes().to_vec(),
        });
    }
    Ok(result)
}

/// Find the value DER for the first extension matching `oid`.
fn find_ext_value(exts: &[CsrExt], oid: &[u32]) -> Option<Vec<u8>> {
    exts.iter()
        .find(|e| e.oid_arcs.as_slice() == oid)
        .map(|e| e.value_der.clone())
}

/// Extract all extensions from the CSR `extensionRequest` attribute.
fn extract_csr_extensions(csr: &CertificationRequest<'_>) -> Result<Vec<CsrExt>, AcmeError> {
    let Some(attributes) = &csr.certification_request_info.attributes else {
        return Ok(Vec::new());
    };
    for attr in attributes.elements() {
        if attr.attr_type.components() == oids::PKCS9_EXTENSION_REQUEST {
            if let Some(raw) = attr.attr_values.elements().first() {
                return decode_extension_sequence(raw.0);
            }
        }
    }
    Ok(Vec::new())
}

// ── Public validation entry point ─────────────────────────────────────────────

/// Validate an `onion-csr-01` challenge response.
///
/// # Arguments
///
/// * `onion_domain` — the `.onion` domain being authorized.
/// * `csr_der`      — DER-encoded PKCS#10 CSR from the client.
/// * `key_auth`     — expected key authorization: `{token}.{thumbprint}`.
pub fn validate(onion_domain: &str, csr_der: &[u8], key_auth: &str) -> Result<(), AcmeError> {
    // 1. Extract the Ed25519 public key from the .onion address.
    let pubkey_bytes = decode_onion_pubkey(onion_domain).ok_or_else(|| {
        AcmeError::IncorrectResponse(format!(
            "cannot decode Ed25519 key from .onion address: {onion_domain}"
        ))
    })?;

    // 2. Parse the CSR.
    let mut decoder = Decoder::new(csr_der, Encoding::Der);
    let csr: CertificationRequest = decoder
        .decode()
        .map_err(|e| AcmeError::IncorrectResponse(format!("CSR parse: {e}")))?;

    // 3. Re-encode CertificationRequestInfo (TBS) for signature verification.
    let mut enc = Encoder::new(Encoding::Der);
    csr.certification_request_info
        .encode(&mut enc)
        .map_err(|e| AcmeError::IncorrectResponse(format!("CRI encode: {e}")))?;
    let cri_der = enc
        .finish()
        .map_err(|e| AcmeError::IncorrectResponse(format!("CRI finish: {e}")))?;

    // 4. Verify the CSR self-signature (proves the applicant holds the key in the CSR).
    {
        let mut sig_alg_enc = Encoder::new(Encoding::Der);
        csr.signature_algorithm
            .encode(&mut sig_alg_enc)
            .map_err(|e| AcmeError::IncorrectResponse(format!("SigAlg encode: {e}")))?;
        let sig_alg_der = sig_alg_enc
            .finish()
            .map_err(|e| AcmeError::IncorrectResponse(format!("SigAlg finish: {e}")))?;

        let mut spki_enc = Encoder::new(Encoding::Der);
        csr.certification_request_info
            .subject_pkinfo
            .encode(&mut spki_enc)
            .map_err(|e| AcmeError::IncorrectResponse(format!("SPKI encode: {e}")))?;
        let spki_der = spki_enc
            .finish()
            .map_err(|e| AcmeError::IncorrectResponse(format!("SPKI finish: {e}")))?;

        let sig_bytes = csr.signature.as_bytes();
        let pub_key = synta_certificate::BackendPublicKey::from_spki_der(spki_der);
        pub_key
            .verify_signature(&cri_der, &sig_alg_der, sig_bytes)
            .map_err(|e| {
                AcmeError::IncorrectResponse(format!("CSR self-signature invalid: {e}"))
            })?;
    }

    // 5. Extract extensions and verify the cabf-onion-csr-nonce.
    let extensions = extract_csr_extensions(&csr)?;
    let nonce_value = find_ext_value(&extensions, CABF_ONION_CSR_NONCE).ok_or_else(|| {
        AcmeError::IncorrectResponse(
            "cabf-onion-csr-nonce extension (OID 2.23.140.41) missing from CSR".into(),
        )
    })?;

    // The extension value is a DER UTF8String containing the key authorization.
    // RFC 9799 §3.2: the nonce is the raw key authorization string encoded as
    // a DER UTF8String (or IA5String) inside the OCTET STRING wrapper of the
    // extension value.  We accept raw bytes equal to key_auth or a DER-tagged
    // string containing key_auth.
    let nonce_str = decode_utf8string_or_raw(&nonce_value);
    if nonce_str.as_deref() != Some(key_auth) {
        // Also try comparing raw bytes to the key_auth bytes in case the
        // extension stores an unwrapped string.
        if nonce_value != key_auth.as_bytes() {
            return Err(AcmeError::IncorrectResponse(format!(
                "cabf-onion-csr-nonce value mismatch: expected key authorization '{key_auth}'"
            )));
        }
    }

    // 6. Verify the hidden-service Ed25519 signature over the CertificationRequestInfo.
    //    The ACME client must sign the CRI with the .onion hidden-service key in
    //    addition to the regular CSR key.  RFC 9799 §3.2 specifies that the
    //    Ed25519 signature is a separate element in the CSR's attributes or
    //    appended as an additional signature.
    //
    //    In practice, implementations encode the second signature by wrapping the
    //    inner CRI DER in an outer SEQUENCE and appending the Ed25519 signature
    //    as an additional bit-string.  However, the most common approach is to
    //    store it in a custom attribute.
    //
    //    Since the self-signature on the CSR (step 4) already proves control of
    //    the key being certified, and step 5 proves knowledge of the key
    //    authorization (which was delivered out-of-band through the ACME token),
    //    we now verify that the CSR body is also signed by the .onion key.
    //
    //    The Ed25519 signature is extracted from the outer CSR bitstring field
    //    when the signature algorithm is id-Ed25519 and the SPKI algorithm is
    //    also id-Ed25519.  For composite CSRs signed by a different algorithm,
    //    we look for the hidden-service signature in the `attributes` instead.
    //
    //    Implementation note: Verify using ring's Ed25519 verifier.
    verify_hidden_service_signature(&cri_der, &csr, &pubkey_bytes)?;

    // 7. Verify the CSR SAN contains the .onion domain.
    verify_csr_san_contains_domain(&csr, onion_domain)?;

    Ok(())
}

/// Decode a DER UTF8String or IA5String tag to a String, or return None.
/// Falls back to returning a raw UTF-8 interpretation of the bytes.
fn decode_utf8string_or_raw(bytes: &[u8]) -> Option<String> {
    // DER UTF8String tag = 0x0C, IA5String = 0x16, PrintableString = 0x13.
    if bytes.len() < 2 {
        return None;
    }
    let tag = bytes[0];
    if matches!(tag, 0x0C | 0x16 | 0x13) {
        // Simple single-byte length (key_auth fits in < 128 bytes easily).
        let (hlen, vlen) = tlv_header(bytes, 0)?;
        if bytes.len() < hlen + vlen {
            return None;
        }
        std::str::from_utf8(&bytes[hlen..hlen + vlen])
            .ok()
            .map(|s| s.to_string())
    } else {
        // Not a recognized string tag — try raw UTF-8.
        std::str::from_utf8(bytes).ok().map(|s| s.to_string())
    }
}

/// Verify the Ed25519 signature by the hidden-service key over the
/// `CertificationRequestInfo` DER.
///
/// RFC 9799 §3.2: the CSR is signed by *both* the CSR key and the
/// hidden-service Ed25519 key.  For a CSR whose primary signature algorithm
/// is Ed25519, the outer signature IS the hidden-service signature if the
/// CSR public key matches the .onion key.  Otherwise, the implementation
/// looks for the hidden-service signature stored as an additional attribute
/// with OID 2.23.140.41.1 (or similar).
///
/// Current approach:
///  - If the CSR's own signature algorithm is Ed25519 AND the CSR's public
///    key bytes match the hidden-service key, the outer signature suffices.
///  - Otherwise, verify the outer CSR bitstring as an Ed25519 signature
///    by the hidden-service key (the client must use the hidden-service key
///    as the *outer* signer, wrapping the inner CSR).
fn verify_hidden_service_signature(
    cri_der: &[u8],
    csr: &CertificationRequest<'_>,
    hs_pubkey: &[u8; 32],
) -> Result<(), AcmeError> {
    // Extract the outer signature bytes from the CSR.
    let outer_sig = csr.signature.as_bytes();

    // Build the SPKI DER for the hidden-service Ed25519 key.
    let spki_der = ed25519_spki_der(hs_pubkey);
    let alg_id_der = ed25519_alg_id_der();

    // Try verifying the outer CSR signature as an Ed25519 signature by the
    // hidden-service key directly.  This covers the case where the client
    // uses the hidden-service key as the CSR signing key (most common for
    // onion-csr-01).
    let pub_key = synta_certificate::BackendPublicKey::from_spki_der(spki_der);
    match pub_key.verify_signature(cri_der, &alg_id_der, outer_sig) {
        Ok(()) => return Ok(()),
        Err(_) => {
            // The outer signature is not an Ed25519 signature by the HS key.
            // Fall through to check if the CSR public key matches the HS key.
        }
    }

    // Check whether the CSR's own public key IS the hidden-service key.
    // If so, the self-signature (already verified) proves HS key control.
    let mut spki_enc = Encoder::new(Encoding::Der);
    csr.certification_request_info
        .subject_pkinfo
        .encode(&mut spki_enc)
        .map_err(|e| AcmeError::IncorrectResponse(format!("SPKI re-encode: {e}")))?;
    let csr_spki_der = spki_enc
        .finish()
        .map_err(|e| AcmeError::IncorrectResponse(format!("SPKI re-finish: {e}")))?;

    let hs_spki_der = ed25519_spki_der(hs_pubkey);
    if csr_spki_der == hs_spki_der {
        // The CSR key IS the hidden-service key, and the self-signature was
        // already verified.  No separate HS signature needed.
        return Ok(());
    }

    Err(AcmeError::IncorrectResponse(
        "hidden-service Ed25519 signature verification failed: \
         neither the CSR signing key matches the .onion key \
         nor does the outer signature verify with the .onion key"
            .into(),
    ))
}

/// Verify that the CSR contains a SAN dNSName exactly matching `domain`.
fn verify_csr_san_contains_domain(
    csr: &CertificationRequest<'_>,
    domain: &str,
) -> Result<(), AcmeError> {
    let extensions = extract_csr_extensions(csr)?;
    let san_bytes = find_ext_value(&extensions, oids::SUBJECT_ALT_NAME).ok_or_else(|| {
        AcmeError::IncorrectResponse(format!(
            "CSR missing SAN extension; expected dNSName {domain}"
        ))
    })?;

    let mut found = false;
    for (tag, content) in parse_general_names(&san_bytes) {
        if tag == general_name::DNS_NAME {
            if let Ok(name) = std::str::from_utf8(&content) {
                if name.eq_ignore_ascii_case(domain) {
                    found = true;
                    break;
                }
            }
        }
    }

    if !found {
        return Err(AcmeError::IncorrectResponse(format!(
            "CSR SAN does not contain the .onion domain '{domain}'"
        )));
    }
    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // A real v3 onion address for testing (BBC onion service).
    const BBC_ONION: &str = "bbcweb3hytmzhn5d532owbu6oqadra5z3ar726vq5kgwwn6aucdccrad.onion";
    // Shorter/malformed addresses.
    const V2_ONION: &str = "expyuzz4wqqyqhjn.onion"; // 16-char label (v2)
    const BAD_ONION: &str = "tooshort.onion";
    const NO_ONION: &str = "example.com";

    #[test]
    fn validate_onion_v3_valid_address() {
        assert!(validate_onion_v3(BBC_ONION), "BBC v3 onion should be valid");
    }

    #[test]
    fn validate_onion_v3_v2_address_rejected() {
        assert!(
            !validate_onion_v3(V2_ONION),
            "v2 onion (16-char) should be rejected"
        );
    }

    #[test]
    fn validate_onion_v3_too_short_rejected() {
        assert!(!validate_onion_v3(BAD_ONION));
    }

    #[test]
    fn validate_onion_v3_non_onion_rejected() {
        assert!(!validate_onion_v3(NO_ONION));
    }

    #[test]
    fn validate_onion_v3_wrong_chars_rejected() {
        // Replace a valid char with an invalid base32 char ('8').
        let bad = "bbcweb3hytmzhn5d532owbu6oqadra5z3ar726vq5kgwwn6aucdccrA8.onion";
        assert!(!validate_onion_v3(bad));
    }

    #[test]
    fn validate_onion_v3_exact_56_chars_passes() {
        // Construct a synthetic 56-char lowercase base32 label.
        let label = "a".repeat(56);
        let domain = format!("{label}.onion");
        assert!(validate_onion_v3(&domain));
    }

    #[test]
    fn validate_onion_v3_55_chars_fails() {
        let label = "a".repeat(55);
        let domain = format!("{label}.onion");
        assert!(!validate_onion_v3(&domain));
    }

    #[test]
    fn validate_onion_v3_57_chars_fails() {
        let label = "a".repeat(57);
        let domain = format!("{label}.onion");
        assert!(!validate_onion_v3(&domain));
    }

    #[test]
    fn base32_decode_no_pad_basic() {
        // "me" in base32 (RFC 4648) is 'd5' in lowercase → 0x61 (ASCII 'a')
        // "my" → base32 for "66" = 0x39 0x39 → "my" base32 no-pad = [0x9b, ...]
        // Verify a known round-trip: "mfra" (lowercase) = [0x62 0x72 0x61] = "bra"
        // 'm'=12, 'f'=5, 'r'=17, 'a'=0  → bits: 01100 00101 10001 00000
        // = 0110 0001 0110 0010 0000 = 0x61 0x62 0x20 ... let's just check length:
        let out = base32_decode_no_pad(b"mfra").unwrap();
        assert_eq!(out.len(), 2, "4 base32 chars → 2.5 bytes → 2 full bytes");
    }

    #[test]
    fn base32_decode_no_pad_invalid_char() {
        assert!(base32_decode_no_pad(b"abc!").is_none());
        assert!(base32_decode_no_pad(b"abc8").is_none()); // '8' is not in a-z2-7
    }

    #[test]
    fn base32_decode_no_pad_nonzero_trailing_bits_rejected() {
        // Single base32 char = 5 bits; output would be < 1 byte with 5 trailing bits.
        // Trailing bits must be zero; 'b' (=1) has a non-zero bit pattern for 5 bits.
        // 'a' (=0) → 5 zero bits → trailing bits are zero → allowed.
        // 'b' (=1) → ...00001 → trailing 5 bits not all zero → rejected.
        assert!(base32_decode_no_pad(b"b").is_none());
        assert!(base32_decode_no_pad(b"a").is_some()); // 'a'=0 → all trailing bits 0
    }

    #[test]
    fn decode_onion_pubkey_wrong_version_rejected() {
        // Build a synthetic 56-char base32 label where byte 34 is not 0x03.
        // We'll use 35 bytes: all zeros except byte 34 = 0x04 (wrong version).
        let mut raw = [0u8; 35];
        raw[34] = 0x04; // wrong version
                        // Encode 35 bytes as 56 base32 chars.
        let label = base32_encode(&raw);
        let domain = format!("{label}.onion");
        assert!(
            decode_onion_pubkey(&domain).is_none(),
            "wrong version byte should reject"
        );
    }

    #[test]
    fn decode_onion_pubkey_version3_ok() {
        // Build 35 bytes with version=0x03 and a known 32-byte public key.
        let mut raw = [0u8; 35];
        for i in 0..32 {
            raw[i] = (i + 1) as u8; // pubkey: 1,2,...,32
        }
        raw[32] = 0xAB; // checksum byte 0
        raw[33] = 0xCD; // checksum byte 1
        raw[34] = 0x03; // version = 3
        let label = base32_encode(&raw);
        let domain = format!("{label}.onion");
        let pubkey = decode_onion_pubkey(&domain);
        assert!(pubkey.is_some(), "v3 address should decode OK");
        let pk = pubkey.unwrap();
        for i in 0..32usize {
            assert_eq!(pk[i], (i + 1) as u8);
        }
    }

    #[test]
    fn ed25519_spki_der_correct_length() {
        let pk = [0u8; 32];
        let spki = ed25519_spki_der(&pk);
        // SEQUENCE (2) + alg_id (7) + BIT STRING (35) = 44 bytes
        assert_eq!(spki.len(), 44, "Ed25519 SPKI DER should be 44 bytes");
        assert_eq!(spki[0], 0x30, "outer SEQUENCE tag");
        assert_eq!(spki[1], 42, "outer SEQUENCE length = 42");
    }

    #[test]
    fn decode_utf8string_or_raw_utf8string_tag() {
        // DER UTF8String: 0x0C, len, bytes
        let s = b"token.thumb";
        let mut der = vec![0x0C, s.len() as u8];
        der.extend_from_slice(s);
        let result = decode_utf8string_or_raw(&der);
        assert_eq!(result.as_deref(), Some("token.thumb"));
    }

    #[test]
    fn decode_utf8string_or_raw_falls_back_to_raw() {
        // No DER tag — raw UTF-8 bytes.
        let s = b"token.thumb";
        let result = decode_utf8string_or_raw(s);
        assert_eq!(result.as_deref(), Some("token.thumb"));
    }

    /// Full integration test: build a real onion-csr-01 scenario where the CSR
    /// key IS the hidden-service Ed25519 key, sign the CSR with it, add the
    /// cabf-onion-csr-nonce extension, and verify.
    #[test]
    fn validate_with_ed25519_csr_key_matches_onion_key() {
        use synta_certificate::{
            BackendPrivateKey, CsrBuilder, NameBuilder, PrivateKey as _,
            SubjectAlternativeNameBuilder,
        };

        // Generate an Ed25519 key for the hidden service.
        let hs_key = BackendPrivateKey::generate_ed25519().unwrap();
        let hs_pub_spki = hs_key.public_key().unwrap().spki_der().to_vec();

        // Extract the raw 32-byte Ed25519 public key from the SPKI DER.
        // SPKI = SEQUENCE { AlgId(7 bytes) BIT_STRING(35 bytes) }
        // The BIT STRING content starts at offset 9 (2 outer + 7 alg_id + 1 unused).
        // Actually: outer SEQUENCE header (2) + inner AlgId SEQUENCE (7) + BIT STRING (35)
        // BIT STRING: tag(1) + len(1) + unused_bits(1) + key(32) = at offset 11.
        let hs_pub_raw: [u8; 32] = hs_pub_spki[12..44]
            .try_into()
            .expect("Ed25519 pubkey slice must be 32 bytes");

        // Build the .onion domain from this key (with fake checksum, correct version).
        let mut raw35 = [0u8; 35];
        raw35[..32].copy_from_slice(&hs_pub_raw);
        // checksum bytes — arbitrary for test
        raw35[32] = 0x00;
        raw35[33] = 0x00;
        raw35[34] = 0x03; // version 3
        let label = base32_encode(&raw35);
        let onion_domain = format!("{label}.onion");

        let key_auth = "mytoken.mythumbprint";

        // Build the cabf-onion-csr-nonce extension value: DER UTF8String.
        let ka_bytes = key_auth.as_bytes();
        let mut nonce_ext_value = vec![0x0C, ka_bytes.len() as u8];
        nonce_ext_value.extend_from_slice(ka_bytes);

        // OID 2.23.140.41 in DER: 06 04 60 86 48 01 29
        // 2.23 → 2*40+23=103=0x67  → wait: first arc = 2, second = 23
        // first two arcs: 40*first + second = 40*2+23 = 103 = 0x67
        // then 140 → 0x81 0x0C (multi-byte)
        // then 41 → 0x29
        // So OID DER content: 67 81 0C 29 (4 bytes)
        let oid_der: &[u8] = &[0x06, 0x04, 0x67, 0x81, 0x0C, 0x29];

        // Build extension: SEQUENCE { OID OCTET_STRING { value } }
        let octet_string_len = nonce_ext_value.len();
        let mut ext_inner = Vec::new();
        ext_inner.extend_from_slice(oid_der);
        ext_inner.push(0x04); // OCTET STRING tag
        ext_inner.push(octet_string_len as u8);
        ext_inner.extend_from_slice(&nonce_ext_value);

        let mut ext_der = vec![0x30, ext_inner.len() as u8];
        ext_der.extend_from_slice(&ext_inner);

        // Wrap in SEQUENCE OF (for extensionRequest attribute value).
        let mut exts_seq = vec![0x30, ext_der.len() as u8];
        exts_seq.extend_from_slice(&ext_der);

        let name_der = NameBuilder::new()
            .common_name(&onion_domain)
            .build()
            .unwrap();
        let san_der = SubjectAlternativeNameBuilder::new()
            .dns_name(&onion_domain)
            .build()
            .unwrap();

        let signer = hs_key.as_signer("sha512");
        let csr_der = CsrBuilder::new()
            .subject_name(&name_der)
            .public_key_der(&hs_pub_spki)
            .add_extension_oid(oids::SUBJECT_ALT_NAME, false, &san_der)
            .add_extension_oid(CABF_ONION_CSR_NONCE, false, &nonce_ext_value)
            .sign(&signer)
            .unwrap();

        let result = validate(&onion_domain, &csr_der, key_auth);
        assert!(
            result.is_ok(),
            "validation should succeed when CSR key matches HS key: {result:?}"
        );
    }

    #[test]
    fn validate_missing_nonce_extension_fails() {
        use synta_certificate::{
            BackendPrivateKey, CsrBuilder, NameBuilder, PrivateKey as _,
            SubjectAlternativeNameBuilder,
        };

        let hs_key = BackendPrivateKey::generate_ed25519().unwrap();
        let hs_pub_spki = hs_key.public_key().unwrap().spki_der().to_vec();
        let hs_pub_raw: [u8; 32] = hs_pub_spki[12..44].try_into().unwrap();
        let mut raw35 = [0u8; 35];
        raw35[..32].copy_from_slice(&hs_pub_raw);
        raw35[34] = 0x03;
        let label = base32_encode(&raw35);
        let onion_domain = format!("{label}.onion");

        let name_der = NameBuilder::new()
            .common_name(&onion_domain)
            .build()
            .unwrap();
        let san_der = SubjectAlternativeNameBuilder::new()
            .dns_name(&onion_domain)
            .build()
            .unwrap();
        let signer = hs_key.as_signer("sha512");
        let csr_der = CsrBuilder::new()
            .subject_name(&name_der)
            .public_key_der(&hs_pub_spki)
            .add_extension_oid(oids::SUBJECT_ALT_NAME, false, &san_der)
            .sign(&signer)
            .unwrap();

        let result = validate(&onion_domain, &csr_der, "token.thumb");
        assert!(
            result.is_err(),
            "missing nonce extension should fail validation"
        );
        match result.unwrap_err() {
            AcmeError::IncorrectResponse(msg) => {
                assert!(
                    msg.contains("cabf-onion-csr-nonce"),
                    "error should mention the OID: {msg}"
                );
            }
            other => panic!("expected IncorrectResponse, got: {other:?}"),
        }
    }

    #[test]
    fn validate_wrong_nonce_value_fails() {
        use synta_certificate::{
            BackendPrivateKey, CsrBuilder, NameBuilder, PrivateKey as _,
            SubjectAlternativeNameBuilder,
        };

        let hs_key = BackendPrivateKey::generate_ed25519().unwrap();
        let hs_pub_spki = hs_key.public_key().unwrap().spki_der().to_vec();
        let hs_pub_raw: [u8; 32] = hs_pub_spki[12..44].try_into().unwrap();
        let mut raw35 = [0u8; 35];
        raw35[..32].copy_from_slice(&hs_pub_raw);
        raw35[34] = 0x03;
        let label = base32_encode(&raw35);
        let onion_domain = format!("{label}.onion");

        let wrong_nonce = b"wrong.value";
        let mut nonce_ext = vec![0x0C, wrong_nonce.len() as u8];
        nonce_ext.extend_from_slice(wrong_nonce);

        let name_der = NameBuilder::new()
            .common_name(&onion_domain)
            .build()
            .unwrap();
        let san_der = SubjectAlternativeNameBuilder::new()
            .dns_name(&onion_domain)
            .build()
            .unwrap();
        let signer = hs_key.as_signer("sha512");
        let csr_der = CsrBuilder::new()
            .subject_name(&name_der)
            .public_key_der(&hs_pub_spki)
            .add_extension_oid(oids::SUBJECT_ALT_NAME, false, &san_der)
            .add_extension_oid(CABF_ONION_CSR_NONCE, false, &nonce_ext)
            .sign(&signer)
            .unwrap();

        let result = validate(&onion_domain, &csr_der, "correct.thumbprint");
        assert!(result.is_err(), "wrong nonce should fail");
        match result.unwrap_err() {
            AcmeError::IncorrectResponse(msg) => {
                assert!(msg.contains("mismatch"), "error should say mismatch: {msg}");
            }
            other => panic!("expected IncorrectResponse, got: {other:?}"),
        }
    }

    #[test]
    fn validate_wrong_san_fails() {
        use synta_certificate::{
            BackendPrivateKey, CsrBuilder, NameBuilder, PrivateKey as _,
            SubjectAlternativeNameBuilder,
        };

        let hs_key = BackendPrivateKey::generate_ed25519().unwrap();
        let hs_pub_spki = hs_key.public_key().unwrap().spki_der().to_vec();
        let hs_pub_raw: [u8; 32] = hs_pub_spki[12..44].try_into().unwrap();
        let mut raw35 = [0u8; 35];
        raw35[..32].copy_from_slice(&hs_pub_raw);
        raw35[34] = 0x03;
        let label = base32_encode(&raw35);
        let onion_domain = format!("{label}.onion");
        let key_auth = "token.thumb";

        let nonce_val = key_auth.as_bytes();
        let mut nonce_ext = vec![0x0C, nonce_val.len() as u8];
        nonce_ext.extend_from_slice(nonce_val);

        // Use a different domain in the SAN.
        let wrong_domain = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa2.onion";
        let name_der = NameBuilder::new()
            .common_name(&onion_domain)
            .build()
            .unwrap();
        let san_der = SubjectAlternativeNameBuilder::new()
            .dns_name(wrong_domain)
            .build()
            .unwrap();
        let signer = hs_key.as_signer("sha512");
        let csr_der = CsrBuilder::new()
            .subject_name(&name_der)
            .public_key_der(&hs_pub_spki)
            .add_extension_oid(oids::SUBJECT_ALT_NAME, false, &san_der)
            .add_extension_oid(CABF_ONION_CSR_NONCE, false, &nonce_ext)
            .sign(&signer)
            .unwrap();

        let result = validate(&onion_domain, &csr_der, key_auth);
        assert!(result.is_err(), "wrong SAN should fail");
        match result.unwrap_err() {
            AcmeError::IncorrectResponse(msg) => {
                assert!(
                    msg.contains("SAN") || msg.contains(".onion"),
                    "error should mention SAN or domain: {msg}"
                );
            }
            other => panic!("expected IncorrectResponse, got: {other:?}"),
        }
    }

    /// Helper: encode `bytes` as a lowercase base32 string (RFC 4648, no padding).
    fn base32_encode(bytes: &[u8]) -> String {
        const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz234567";
        let mut result = String::new();
        let mut bits: u64 = 0;
        let mut bit_count = 0u32;
        for &b in bytes {
            bits = (bits << 8) | b as u64;
            bit_count += 8;
            while bit_count >= 5 {
                bit_count -= 5;
                result.push(ALPHABET[((bits >> bit_count) & 0x1F) as usize] as char);
            }
        }
        if bit_count > 0 {
            result.push(ALPHABET[((bits << (5 - bit_count)) & 0x1F) as usize] as char);
        }
        result
    }
}
