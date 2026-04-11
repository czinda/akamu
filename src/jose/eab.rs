//! External Account Binding (EAB) JWS verification — RFC 8555 §7.3.4.
//!
//! The EAB JWS uses an HMAC algorithm (HS256/HS384/HS512) keyed with a
//! pre-shared secret whose identifier is carried in the protected header `kid`.
//! Its payload MUST be the account public key (same JWK as in the outer JWS).

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::Deserialize;
use synta_certificate::{default_hmac_provider, HmacProvider};

use crate::error::AcmeError;
use crate::jose::jwk::JwkPublic;

/// Extract the `kid` from an EAB JWS protected header without full verification.
///
/// Call this first to get the kid for the DB lookup; then call
/// [`verify_eab_jws`] with the decoded key.
pub fn parse_eab_kid(eab: &serde_json::Value) -> Result<String, AcmeError> {
    #[derive(Deserialize)]
    struct EabJws {
        protected: String,
    }
    #[derive(Deserialize)]
    struct EabHeader {
        kid: String,
    }

    let jws: EabJws = serde_json::from_value(eab.clone())
        .map_err(|e| AcmeError::BadRequest(format!("EAB JWS parse error: {e}")))?;
    let header_bytes = URL_SAFE_NO_PAD
        .decode(&jws.protected)
        .map_err(|e| AcmeError::BadRequest(format!("EAB protected header base64: {e}")))?;
    let header: EabHeader = serde_json::from_slice(&header_bytes)
        .map_err(|e| AcmeError::BadRequest(format!("EAB protected header JSON: {e}")))?;
    Ok(header.kid)
}

/// Fully verify an EAB JWS (RFC 8555 §7.3.4).
///
/// # Arguments
/// - `eab`                — the `externalAccountBinding` JSON value
/// - `expected_url`       — new-account endpoint URL; must match EAB protected `url`
/// - `expected_kid`       — kid extracted earlier and resolved in the DB
/// - `account_thumbprint` — RFC 7638 thumbprint of the account public key (outer JWS)
/// - `hmac_key`           — raw HMAC key bytes decoded from `hmac_key_b64u`
pub fn verify_eab_jws(
    eab: &serde_json::Value,
    expected_url: &str,
    expected_kid: &str,
    account_thumbprint: &str,
    hmac_key: &[u8],
) -> Result<(), AcmeError> {
    #[derive(Deserialize)]
    struct EabJws {
        protected: String,
        payload: String,
        signature: String,
    }
    #[derive(Deserialize)]
    struct EabHeader {
        alg: String,
        kid: String,
        url: String,
    }

    let jws: EabJws = serde_json::from_value(eab.clone())
        .map_err(|e| AcmeError::BadRequest(format!("EAB JWS parse error: {e}")))?;

    // Decode and parse the protected header.
    let header_bytes = URL_SAFE_NO_PAD
        .decode(&jws.protected)
        .map_err(|e| AcmeError::BadRequest(format!("EAB protected header base64: {e}")))?;
    let header: EabHeader = serde_json::from_slice(&header_bytes)
        .map_err(|e| AcmeError::BadRequest(format!("EAB protected header JSON: {e}")))?;

    // Map algorithm to hash name for the HMAC provider.
    let hash_alg = match header.alg.as_str() {
        "HS256" => "sha256",
        "HS384" => "sha384",
        "HS512" => "sha512",
        other => {
            return Err(AcmeError::BadRequest(format!(
                "EAB: unsupported algorithm '{other}'; must be HS256, HS384, or HS512"
            )));
        }
    };

    // kid in the EAB must match the one we looked up.
    if header.kid != expected_kid {
        return Err(AcmeError::Unauthorized(format!(
            "EAB: kid mismatch: expected '{expected_kid}', got '{}'",
            header.kid
        )));
    }

    // URL must match the new-account endpoint.
    if header.url != expected_url {
        return Err(AcmeError::Unauthorized(format!(
            "EAB: url mismatch: expected '{expected_url}', got '{}'",
            header.url
        )));
    }

    // Payload MUST be the account public key (RFC 8555 §7.3.4).
    // Decode it, parse as JwkPublic, compute thumbprint, compare.
    let payload_bytes = URL_SAFE_NO_PAD
        .decode(&jws.payload)
        .map_err(|e| AcmeError::BadRequest(format!("EAB payload base64: {e}")))?;
    let payload_jwk: JwkPublic = serde_json::from_slice(&payload_bytes)
        .map_err(|e| AcmeError::BadRequest(format!("EAB payload JWK JSON: {e}")))?;
    let payload_thumbprint = payload_jwk.thumbprint()?;
    if payload_thumbprint != account_thumbprint {
        return Err(AcmeError::Unauthorized(
            "EAB payload does not match account public key".into(),
        ));
    }

    // Verify HMAC over "<protected>.<payload>" (ASCII bytes).
    // hmac_verify uses constant-time comparison via the OpenSSL backend.
    let signing_input = format!("{}.{}", jws.protected, jws.payload);
    let raw_sig = URL_SAFE_NO_PAD
        .decode(&jws.signature)
        .map_err(|e| AcmeError::BadRequest(format!("EAB signature base64: {e}")))?;

    default_hmac_provider()
        .hmac_verify(hash_alg, hmac_key, signing_input.as_bytes(), &raw_sig)
        .map_err(|_| AcmeError::Unauthorized("EAB: MAC verification failed".into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use synta_certificate::BackendPrivateKey;

    // ── helpers ────────────────────────────────────────────────────────────────

    /// Build a minimal P-256 JWK and return (JwkPublic, thumbprint, b64u_encoded_json).
    fn make_account_jwk() -> (JwkPublic, String, String) {
        let key = BackendPrivateKey::generate_ec("P-256").unwrap();
        let pub_key = key.public_key().unwrap();
        let (x_bytes, y_bytes) = pub_key.ec_affine_coordinates().unwrap().unwrap();
        let pad = |v: &[u8]| {
            let mut out = vec![0u8; 32];
            let start = 32usize.saturating_sub(v.len());
            out[start..].copy_from_slice(&v[v.len().saturating_sub(32)..]);
            URL_SAFE_NO_PAD.encode(&out)
        };
        let jwk = JwkPublic {
            kty: "EC".to_string(),
            crv: Some("P-256".to_string()),
            x: Some(pad(&x_bytes)),
            y: Some(pad(&y_bytes)),
            n: None,
            e: None,
        };
        let thumbprint = jwk.thumbprint().unwrap();
        // Canonical JWK JSON (matches what a well-behaved client would send)
        let jwk_json = serde_json::to_string(&serde_json::json!({
            "crv": "P-256",
            "kty": "EC",
            "x": jwk.x.as_deref().unwrap(),
            "y": jwk.y.as_deref().unwrap(),
        }))
        .unwrap();
        let jwk_b64u = URL_SAFE_NO_PAD.encode(jwk_json.as_bytes());
        (jwk, thumbprint, jwk_b64u)
    }

    /// Build a valid EAB JWS signed with the given HMAC key.
    fn make_eab_jws(
        kid: &str,
        url: &str,
        alg: &str,
        hmac_key: &[u8],
        payload_b64u: &str,
    ) -> serde_json::Value {
        let header_json = serde_json::to_string(&serde_json::json!({
            "alg": alg, "kid": kid, "url": url,
        }))
        .unwrap();
        let protected = URL_SAFE_NO_PAD.encode(header_json.as_bytes());
        let signing_input = format!("{protected}.{payload_b64u}");

        let hash_name = match alg {
            "HS256" => "sha256",
            "HS384" => "sha384",
            "HS512" => "sha512",
            _ => panic!("unsupported alg in test helper"),
        };
        let mac = default_hmac_provider()
            .hmac_compute(hash_name, hmac_key, signing_input.as_bytes())
            .unwrap();
        let signature = URL_SAFE_NO_PAD.encode(&mac);

        serde_json::json!({
            "protected": protected,
            "payload": payload_b64u,
            "signature": signature,
        })
    }

    // ── tests ──────────────────────────────────────────────────────────────────

    #[test]
    fn valid_hs256_eab_verifies() {
        let hmac_key = b"super-secret-hmac-key-32-bytes!!";
        let (_, thumbprint, jwk_b64u) = make_account_jwk();
        let url = "https://acme.test/acme/new-account";
        let kid = "kid-1";

        let eab = make_eab_jws(kid, url, "HS256", hmac_key, &jwk_b64u);
        verify_eab_jws(&eab, url, kid, &thumbprint, hmac_key).unwrap();
    }

    #[test]
    fn valid_hs384_eab_verifies() {
        let hmac_key = b"a-48-byte-key-for-hs384-testing-xxxxxxxxxxxxxxxxx";
        let (_, thumbprint, jwk_b64u) = make_account_jwk();
        let url = "https://acme.test/acme/new-account";
        let kid = "kid-2";

        let eab = make_eab_jws(kid, url, "HS384", hmac_key, &jwk_b64u);
        verify_eab_jws(&eab, url, kid, &thumbprint, hmac_key).unwrap();
    }

    #[test]
    fn valid_hs512_eab_verifies() {
        let hmac_key = b"a-64-byte-key-for-hs512-testing-xxxxxxxxxxxxxxxxxxxxxxxxxxxx!!";
        let (_, thumbprint, jwk_b64u) = make_account_jwk();
        let url = "https://acme.test/acme/new-account";
        let kid = "kid-3";

        let eab = make_eab_jws(kid, url, "HS512", hmac_key, &jwk_b64u);
        verify_eab_jws(&eab, url, kid, &thumbprint, hmac_key).unwrap();
    }

    #[test]
    fn wrong_hmac_key_fails() {
        let hmac_key = b"correct-key-32-bytes-exactly!!!!";
        let wrong_key = b"wrong---key-32-bytes-exactly!!!!";
        let (_, thumbprint, jwk_b64u) = make_account_jwk();
        let url = "https://acme.test/acme/new-account";
        let kid = "kid-4";

        let eab = make_eab_jws(kid, url, "HS256", hmac_key, &jwk_b64u);
        let result = verify_eab_jws(&eab, url, kid, &thumbprint, wrong_key);
        assert!(
            matches!(result, Err(AcmeError::Unauthorized(_))),
            "wrong HMAC key should be Unauthorized"
        );
    }

    #[test]
    fn url_mismatch_fails() {
        let hmac_key = b"some-32-byte-key-for-testing!!!!";
        let (_, thumbprint, jwk_b64u) = make_account_jwk();
        let url = "https://acme.test/acme/new-account";
        let wrong_url = "https://acme.test/acme/new-order";
        let kid = "kid-5";

        let eab = make_eab_jws(kid, wrong_url, "HS256", hmac_key, &jwk_b64u);
        let result = verify_eab_jws(&eab, url, kid, &thumbprint, hmac_key);
        assert!(
            matches!(result, Err(AcmeError::Unauthorized(_))),
            "URL mismatch should be Unauthorized"
        );
    }

    #[test]
    fn payload_mismatch_fails() {
        let hmac_key = b"some-32-byte-key-for-testing!!!!";
        let (_, thumbprint, _) = make_account_jwk();
        // Use a _different_ JWK as the payload
        let (_, _, other_jwk_b64u) = make_account_jwk();
        let url = "https://acme.test/acme/new-account";
        let kid = "kid-6";

        let eab = make_eab_jws(kid, url, "HS256", hmac_key, &other_jwk_b64u);
        let result = verify_eab_jws(&eab, url, kid, &thumbprint, hmac_key);
        // The HMAC itself will verify (we signed with correct key), but payload thumbprint mismatches.
        assert!(
            matches!(result, Err(AcmeError::Unauthorized(_))),
            "payload key mismatch should be Unauthorized"
        );
    }

    #[test]
    fn unsupported_algorithm_fails() {
        let (_, thumbprint, jwk_b64u) = make_account_jwk();
        let url = "https://acme.test/acme/new-account";
        // Build a JWS with RS256 in the protected header (but no real signature).
        let header_json = serde_json::to_string(&serde_json::json!({
            "alg": "RS256", "kid": "kid-7", "url": url,
        }))
        .unwrap();
        let protected = URL_SAFE_NO_PAD.encode(header_json.as_bytes());
        let eab = serde_json::json!({
            "protected": protected,
            "payload": jwk_b64u,
            "signature": URL_SAFE_NO_PAD.encode(b"bogus"),
        });
        let result = verify_eab_jws(&eab, url, "kid-7", &thumbprint, b"key");
        assert!(
            matches!(result, Err(AcmeError::BadRequest(_))),
            "unsupported algorithm should be BadRequest"
        );
    }

    #[test]
    fn kid_mismatch_fails() {
        let hmac_key = b"some-32-byte-key-for-testing!!!!";
        let (_, thumbprint, jwk_b64u) = make_account_jwk();
        let url = "https://acme.test/acme/new-account";

        // EAB protected header says kid-8, but we pass expected_kid = "kid-9".
        let eab = make_eab_jws("kid-8", url, "HS256", hmac_key, &jwk_b64u);
        let result = verify_eab_jws(&eab, url, "kid-9", &thumbprint, hmac_key);
        assert!(
            matches!(result, Err(AcmeError::Unauthorized(_))),
            "kid mismatch should be Unauthorized"
        );
    }

    #[test]
    fn parse_eab_kid_extracts_kid() {
        let header_json = serde_json::to_string(
            &serde_json::json!({"alg":"HS256","kid":"my-kid","url":"https://acme.test/"}),
        )
        .unwrap();
        let protected = URL_SAFE_NO_PAD.encode(header_json.as_bytes());
        let eab = serde_json::json!({"protected": protected, "payload": "", "signature": ""});
        assert_eq!(parse_eab_kid(&eab).unwrap(), "my-kid");
    }

    #[test]
    fn parse_eab_kid_invalid_base64_returns_error() {
        let eab = serde_json::json!({"protected": "!!!bad!!!", "payload": "", "signature": ""});
        assert!(matches!(parse_eab_kid(&eab), Err(AcmeError::BadRequest(_))));
    }
}
