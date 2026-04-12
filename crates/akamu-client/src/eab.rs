//! Client-side External Account Binding JWS creation (RFC 8555 §7.3.4).
//!
//! The server's `src/jose/eab.rs` *verifies* EAB JWSes; this module *creates*
//! them.  Both sides use `synta_certificate::default_hmac_provider()`.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use synta_certificate::{default_hmac_provider, HmacProvider};

use akamu_jose::JwkPublic;

use crate::error::ClientError;

/// Build the `externalAccountBinding` JWS object for a new-account request.
///
/// # Arguments
/// - `kid`         — EAB key identifier assigned by the CA
/// - `url`         — the new-account endpoint URL (must match what the server expects)
/// - `alg`         — `"HS256"`, `"HS384"`, or `"HS512"`
/// - `hmac_key`    — raw HMAC key bytes (caller decodes from base64url before calling)
/// - `account_jwk` — the public account JWK; serialized as the EAB payload
///
/// Returns the EAB JWS as a `serde_json::Value` ready for inclusion as
/// `"externalAccountBinding"` in the new-account request body.
pub fn create_eab_jws(
    kid: &str,
    url: &str,
    alg: &str,
    hmac_key: &[u8],
    account_jwk: &JwkPublic,
) -> Result<serde_json::Value, ClientError> {
    let hash_name = match alg {
        "HS256" => "sha256",
        "HS384" => "sha384",
        "HS512" => "sha512",
        other => {
            return Err(ClientError::Jose(
                akamu_jose::JoseError::UnsupportedAlgorithm(format!(
                    "EAB alg must be HS256/HS384/HS512, got '{other}'"
                )),
            ));
        }
    };

    // protected = base64url({"alg":"<alg>","kid":"<kid>","url":"<url>"})
    let header_json = serde_json::json!({ "alg": alg, "kid": kid, "url": url }).to_string();
    let protected = URL_SAFE_NO_PAD.encode(header_json.as_bytes());

    // payload = base64url(canonical JWK JSON)
    let jwk_json = serde_json::to_string(account_jwk)
        .map_err(|e| ClientError::Jose(akamu_jose::JoseError::Json(e)))?;
    let payload = URL_SAFE_NO_PAD.encode(jwk_json.as_bytes());

    // signature = HMAC_<hash>("<protected>.<payload>")
    let signing_input = format!("{protected}.{payload}");
    let mac = default_hmac_provider()
        .hmac_compute(hash_name, hmac_key, signing_input.as_bytes())
        .map_err(|e| ClientError::Crypto(format!("HMAC compute: {e}")))?;
    let signature = URL_SAFE_NO_PAD.encode(&mac);

    Ok(serde_json::json!({
        "protected": protected,
        "payload": payload,
        "signature": signature,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use synta_certificate::BackendPrivateKey;

    fn make_ec_jwk() -> JwkPublic {
        let key = BackendPrivateKey::generate_ec("P-256").unwrap();
        let pub_key = key.public_key().unwrap();
        JwkPublic::from_public_key(&pub_key).unwrap()
    }

    #[test]
    fn create_eab_hs256_roundtrip() {
        let hmac_key = b"super-secret-hmac-key-32-bytes!!";
        let jwk = make_ec_jwk();
        let eab = create_eab_jws(
            "kid-1",
            "https://acme.test/acme/new-account",
            "HS256",
            hmac_key,
            &jwk,
        )
        .unwrap();

        // Verify manually: decode protected, check fields.
        let protected_b64 = eab["protected"].as_str().unwrap();
        let header_bytes = URL_SAFE_NO_PAD.decode(protected_b64).unwrap();
        let header: serde_json::Value = serde_json::from_slice(&header_bytes).unwrap();
        assert_eq!(header["alg"], "HS256");
        assert_eq!(header["kid"], "kid-1");
        assert_eq!(header["url"], "https://acme.test/acme/new-account");

        // Verify HMAC by re-computing and comparing.
        let payload = eab["payload"].as_str().unwrap();
        let signing_input = format!("{protected_b64}.{payload}");
        let expected_mac = default_hmac_provider()
            .hmac_compute("sha256", hmac_key, signing_input.as_bytes())
            .unwrap();
        let sig_bytes = URL_SAFE_NO_PAD
            .decode(eab["signature"].as_str().unwrap())
            .unwrap();
        assert_eq!(sig_bytes, expected_mac);
    }

    #[test]
    fn create_eab_hs512_roundtrip() {
        let hmac_key = b"a-64-byte-key-for-hs512-testing-xxxxxxxxxxxxxxxxxxxxxxxxxxxx!!";
        let jwk = make_ec_jwk();
        let eab = create_eab_jws(
            "kid-2",
            "https://acme.test/acme/new-account",
            "HS512",
            hmac_key,
            &jwk,
        )
        .unwrap();

        let protected_b64 = eab["protected"].as_str().unwrap();
        let payload = eab["payload"].as_str().unwrap();
        let signing_input = format!("{protected_b64}.{payload}");
        let expected_mac = default_hmac_provider()
            .hmac_compute("sha512", hmac_key, signing_input.as_bytes())
            .unwrap();
        let sig_bytes = URL_SAFE_NO_PAD
            .decode(eab["signature"].as_str().unwrap())
            .unwrap();
        assert_eq!(sig_bytes, expected_mac);
    }

    #[test]
    fn unsupported_alg_returns_error() {
        let jwk = make_ec_jwk();
        let result = create_eab_jws("kid", "https://acme.test/", "RS256", b"key", &jwk);
        assert!(result.is_err());
    }

    #[test]
    fn payload_contains_account_jwk() {
        let hmac_key = b"some-key-for-testing-exactly!!!!";
        let jwk = make_ec_jwk();
        let eab = create_eab_jws(
            "kid",
            "https://acme.test/acme/new-account",
            "HS256",
            hmac_key,
            &jwk,
        )
        .unwrap();

        let payload_bytes = URL_SAFE_NO_PAD
            .decode(eab["payload"].as_str().unwrap())
            .unwrap();
        let payload_jwk: serde_json::Value = serde_json::from_slice(&payload_bytes).unwrap();
        // Should have kty field from our EC JWK.
        assert_eq!(payload_jwk["kty"], "EC");
    }
}
