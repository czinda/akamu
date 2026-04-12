//! Account key management and account representation.

use std::sync::Arc;

use akamu_jose::{JoseError, JwkPublic};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use synta_certificate::{BackendPrivateKey, DataHasher};

use crate::error::ClientError;

/// An ACME account key: holds the private key, the pre-computed public JWK,
/// its RFC 7638 thumbprint, and the JWS `alg` string.
pub struct AccountKey {
    priv_key: BackendPrivateKey,
    pub_jwk: JwkPublic,
    thumbprint: String,
    alg: &'static str,
}

impl AccountKey {
    /// Generate a new account key of the given type.
    ///
    /// `key_type` follows the same convention as the bench/CLI: `"ec:P-256"`,
    /// `"ec:P-384"`, `"ec:P-521"`, `"rsa:2048"`, `"rsa:3072"`, `"rsa:4096"`,
    /// `"ed25519"`, `"ed448"`, `"ml-dsa-44"`, `"ml-dsa-65"`, `"ml-dsa-87"`.
    pub fn generate(key_type: &str) -> Result<Self, ClientError> {
        let priv_key = generate_backend_key(key_type)?;
        Self::from_backend_key(priv_key)
    }

    /// Load an account key from a PEM-encoded private key file.
    pub fn from_pem(pem: &[u8]) -> Result<Self, ClientError> {
        let priv_key = BackendPrivateKey::from_pem(pem, None)
            .map_err(|e| ClientError::Crypto(format!("PEM load: {e}")))?;
        Self::from_backend_key(priv_key)
    }

    /// Serialize the private key to PEM (unencrypted).
    pub fn to_pem(&self) -> Result<Vec<u8>, ClientError> {
        self.priv_key
            .to_pem(None)
            .map_err(|e| ClientError::Crypto(format!("PEM export: {e}")))
    }

    /// The RFC 7638 JWK thumbprint of the public key.
    pub fn thumbprint(&self) -> &str {
        &self.thumbprint
    }

    /// The key-authorization value for a challenge token: `"{token}.{thumbprint}"`.
    pub fn key_authorization(&self, token: &str) -> String {
        format!("{token}.{}", self.thumbprint)
    }

    /// The public JWK (needed for the outer JWS `jwk` header and EAB payload).
    pub fn public_jwk(&self) -> &JwkPublic {
        &self.pub_jwk
    }

    /// The JWS `alg` string (e.g. `"ES256"`, `"EdDSA"`, `"ML-DSA-87"`).
    pub fn alg(&self) -> &'static str {
        self.alg
    }

    /// Access the underlying private key for signing.
    pub fn private_key(&self) -> &BackendPrivateKey {
        &self.priv_key
    }

    fn from_backend_key(priv_key: BackendPrivateKey) -> Result<Self, ClientError> {
        let pub_key = priv_key
            .public_key()
            .map_err(|e| ClientError::Crypto(format!("public key: {e}")))?;
        let pub_jwk = JwkPublic::from_public_key(&pub_key).map_err(ClientError::Jose)?;
        let thumbprint = pub_jwk
            .thumbprint()
            .map_err(|e: JoseError| ClientError::Jose(e))?;
        let alg = alg_for_key(&priv_key)?;
        Ok(AccountKey {
            priv_key,
            pub_jwk,
            thumbprint,
            alg,
        })
    }
}

/// A registered ACME account.
///
/// Returned by [`crate::client::AcmeClient::new_account`] and used for all
/// subsequent signed requests.
pub struct Account {
    /// The account URL (from the `Location` header of the 201 response).
    pub url: String,
    /// Account status: `"valid"`, `"deactivated"`, or `"revoked"`.
    pub status: String,
    /// Contact URIs registered for the account.
    pub contacts: Vec<String>,
    pub(crate) key: Arc<AccountKey>,
}

impl Account {
    pub fn new(url: String, status: String, contacts: Vec<String>, key: Arc<AccountKey>) -> Self {
        Account {
            url,
            status,
            contacts,
            key,
        }
    }

    pub fn thumbprint(&self) -> &str {
        self.key.thumbprint()
    }

    pub fn key_authorization(&self, token: &str) -> String {
        self.key.key_authorization(token)
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn generate_backend_key(key_type: &str) -> Result<BackendPrivateKey, ClientError> {
    let err =
        |e: &dyn std::fmt::Display| ClientError::Crypto(format!("generate '{key_type}': {e}"));
    match key_type {
        "ec:P-256" | "P-256" => BackendPrivateKey::generate_ec("P-256").map_err(|e| err(&e)),
        "ec:P-384" | "P-384" => BackendPrivateKey::generate_ec("P-384").map_err(|e| err(&e)),
        "ec:P-521" | "P-521" => BackendPrivateKey::generate_ec("P-521").map_err(|e| err(&e)),
        "rsa:2048" | "rsa2048" => BackendPrivateKey::generate_rsa(2048, 65537).map_err(|e| err(&e)),
        "rsa:3072" | "rsa3072" => BackendPrivateKey::generate_rsa(3072, 65537).map_err(|e| err(&e)),
        "rsa:4096" | "rsa4096" => BackendPrivateKey::generate_rsa(4096, 65537).map_err(|e| err(&e)),
        "ed25519" => BackendPrivateKey::generate_ed25519().map_err(|e| err(&e)),
        "ed448" => BackendPrivateKey::generate_ed448().map_err(|e| err(&e)),
        "ml-dsa-44" | "ML-DSA-44" => {
            BackendPrivateKey::generate_ml_dsa("ML-DSA-44").map_err(|e| err(&e))
        }
        "ml-dsa-65" | "ML-DSA-65" => {
            BackendPrivateKey::generate_ml_dsa("ML-DSA-65").map_err(|e| err(&e))
        }
        "ml-dsa-87" | "ML-DSA-87" => {
            BackendPrivateKey::generate_ml_dsa("ML-DSA-87").map_err(|e| err(&e))
        }
        other => Err(ClientError::Crypto(format!(
            "unknown key type '{other}'; use ec:P-256, rsa:2048, ed25519, ml-dsa-44, …"
        ))),
    }
}

/// Map a private key's type to the JWS `alg` string.
fn alg_for_key(key: &BackendPrivateKey) -> Result<&'static str, ClientError> {
    let pub_key = key
        .public_key()
        .map_err(|e| ClientError::Crypto(format!("public key for alg detection: {e}")))?;

    match pub_key.key_type() {
        "ec" => {
            let curve = pub_key.ec_curve_name().ok().flatten().unwrap_or("");
            match curve {
                "P-256" | "prime256v1" => Ok("ES256"),
                "P-384" | "secp384r1" => Ok("ES384"),
                "P-521" | "secp521r1" => Ok("ES512"),
                other => Err(ClientError::Crypto(format!("unknown EC curve '{other}'"))),
            }
        }
        "rsa" => Ok("PS256"),
        "ed25519" => Ok("EdDSA"),
        "ed448" => Ok("EdDSA"),
        _ => {
            // ML-DSA: inspect SPKI OID discriminant byte at offset 16.
            let spki = pub_key.spki_der();
            const PREFIX: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03];
            if spki.len() > 17 && spki[8..16] == *PREFIX {
                match spki[16] {
                    0x11 => Ok("ML-DSA-44"),
                    0x12 => Ok("ML-DSA-65"),
                    0x13 => Ok("ML-DSA-87"),
                    b => Err(ClientError::Crypto(format!(
                        "unknown ML-DSA OID discriminant 0x{b:02x}"
                    ))),
                }
            } else {
                Err(ClientError::Crypto(
                    "unsupported key type for ACME account".into(),
                ))
            }
        }
    }
}

/// Compute the RFC 7638 thumbprint for a JWK, returned as a base64url string.
///
/// Used in `AccountKey::from_backend_key` but also exposed for tests.
pub fn compute_thumbprint(jwk: &JwkPublic) -> Result<String, ClientError> {
    jwk.thumbprint().map_err(ClientError::Jose)
}

/// dns-01 / dns-persist-01 TXT record value: base64url(SHA-256(key_auth)).
pub fn dns_txt_value(key_auth: &str) -> Result<String, ClientError> {
    use synta_certificate::default_data_hasher;
    let digest = default_data_hasher()
        .hash_data("sha256", key_auth.as_bytes())
        .map_err(|e| ClientError::Crypto(format!("sha256: {e}")))?;
    Ok(URL_SAFE_NO_PAD.encode(&digest))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_p256_key_has_correct_alg() {
        let k = AccountKey::generate("ec:P-256").unwrap();
        assert_eq!(k.alg(), "ES256");
    }

    #[test]
    fn generate_ed25519_key_has_correct_alg() {
        let k = AccountKey::generate("ed25519").unwrap();
        assert_eq!(k.alg(), "EdDSA");
    }

    #[test]
    fn generate_ml_dsa_87_key_has_correct_alg() {
        let k = AccountKey::generate("ml-dsa-87").unwrap();
        assert_eq!(k.alg(), "ML-DSA-87");
    }

    #[test]
    fn key_authorization_format() {
        let k = AccountKey::generate("ec:P-256").unwrap();
        let ka = k.key_authorization("mytoken");
        assert!(ka.starts_with("mytoken."), "should start with token: {ka}");
        assert!(!k.thumbprint().is_empty());
    }

    #[test]
    fn pem_round_trip() {
        let k = AccountKey::generate("ec:P-256").unwrap();
        let pem = k.to_pem().unwrap();
        let k2 = AccountKey::from_pem(&pem).unwrap();
        assert_eq!(k.thumbprint(), k2.thumbprint());
        assert_eq!(k.alg(), k2.alg());
    }

    #[test]
    fn unknown_key_type_returns_error() {
        let result = AccountKey::generate("bogus:999");
        assert!(result.is_err());
    }
}
