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

    /// Build an account key from a raw private JWK JSON string (as stored in
    /// certbot's `accounts/…/private_key.json`).  Supports EC (`P-256`,
    /// `P-384`, `P-521`) and RSA keys.
    pub fn from_jwk_private(json: &str) -> Result<Self, ClientError> {
        let priv_key = jwk_private_to_backend_key(json)
            .map_err(|e| ClientError::Crypto(format!("JWK import: {e}")))?;
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
            // ML-DSA: OID arc 2.16.840.1.101.3.4.3.{17,18,19} = ML-DSA-{44,65,87}.
            // The 8-byte PREFIX is the DER encoding of 2.16.840.1.101.3.4.3;
            // the discriminant byte at offset 16 selects the variant.
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

/// Build a [`BackendPrivateKey`] from a raw private JWK JSON string.
///
/// Supports EC (`P-256`, `P-384`, `P-521`) and RSA keys.  The JWK fields are
/// expected in base64url-no-padding encoding, as produced by certbot.
///
/// Keys are constructed by encoding a PKCS#8 DER from the JWK components
/// and loading via [`BackendPrivateKey::from_der`].  This avoids the
/// `EVP_PKEY_fromdata` → `to_pkcs8_der` round-trip which panics on some
/// OpenSSL 3.x builds with "illegal zero content".
fn jwk_private_to_backend_key(json: &str) -> Result<BackendPrivateKey, String> {
    let v: serde_json::Value = serde_json::from_str(json).map_err(|e| format!("parse JWK: {e}"))?;
    let kty = v["kty"].as_str().unwrap_or("").to_uppercase();
    match kty.as_str() {
        "EC" => {
            let crv = v["crv"]
                .as_str()
                .ok_or_else(|| "EC JWK missing required 'crv' field".to_string())?;
            let d = jwk_b64u(&v, "d")?;
            let x = jwk_b64u(&v, "x")?;
            let y = jwk_b64u(&v, "y")?;
            let pkcs8 = ec_jwk_to_pkcs8(&d, &x, &y, crv)?;
            BackendPrivateKey::from_der(&pkcs8).map_err(|e| e.to_string())
        }
        "RSA" => {
            let n = jwk_b64u(&v, "n")?;
            let e = jwk_b64u(&v, "e")?;
            let d = jwk_b64u(&v, "d")?;
            let p = jwk_b64u(&v, "p")?;
            let q = jwk_b64u(&v, "q")?;
            let dp = jwk_b64u(&v, "dp")?;
            let dq = jwk_b64u(&v, "dq")?;
            let qi = jwk_b64u(&v, "qi")?;
            let components = synta_certificate::RsaPrivateComponents {
                n: &n,
                e: &e,
                d: &d,
                p: &p,
                q: &q,
                dp: &dp,
                dq: &dq,
                qi: &qi,
            };
            let pkcs8 = rsa_jwk_to_pkcs8(&components)?;
            BackendPrivateKey::from_der(&pkcs8).map_err(|e| e.to_string())
        }
        other => Err(format!("unsupported JWK kty: {other}")),
    }
}

/// Encode an RSA private key as unencrypted PKCS#8 DER.
fn rsa_jwk_to_pkcs8(c: &synta_certificate::RsaPrivateComponents<'_>) -> Result<Vec<u8>, String> {
    use synta::types::string::OctetStringRef;
    use synta::{Element, Encoder, Encoding, Integer, Null, ObjectIdentifier, Tag};

    let rsa_oid = ObjectIdentifier::new(synta_certificate::oids::RSA_ENCRYPTION)
        .map_err(|e| format!("RSA OID: {e}"))?;

    // RSAPrivateKey ::= SEQUENCE { version, n, e, d, p, q, dp, dq, qi }
    let mut inner = Encoder::new(Encoding::Der);
    inner
        .start_constructed_no_guard(Tag::universal_constructed(16))
        .map_err(|e| format!("RSA seq: {e}"))?;
    inner
        .encode(&Integer::from_i64(0))
        .map_err(|e| format!("RSA version: {e}"))?;
    for (label, bytes) in [
        ("n", c.n),
        ("e", c.e),
        ("d", c.d),
        ("p", c.p),
        ("q", c.q),
        ("dp", c.dp),
        ("dq", c.dq),
        ("qi", c.qi),
    ] {
        inner
            .encode(&Integer::from_unsigned_bytes(bytes))
            .map_err(|e| format!("RSA {label}: {e}"))?;
    }
    inner
        .end_constructed()
        .map_err(|e| format!("RSA end: {e}"))?;
    let rsa_der = inner.finish().map_err(|e| format!("RSA inner: {e}"))?;

    let pki = synta_certificate::pkcs8_types::OneAsymmetricKey {
        version: Integer::from_i64(0),
        private_key_algorithm: synta_certificate::AlgorithmIdentifier {
            algorithm: rsa_oid,
            parameters: Some(Element::Null(Null)),
        },
        private_key: OctetStringRef::new(&rsa_der),
        attributes: None,
        public_key: None,
    };
    pki.to_der()
        .map_err(|e| format!("PKCS#8 DER encoding failed: {e}"))
}

/// Encode an EC private key (from JWK big-endian unsigned components) as
/// unencrypted PKCS#8 DER (RFC 5915 ECPrivateKey wrapped in PKCS#8).
fn ec_jwk_to_pkcs8(d: &[u8], x: &[u8], y: &[u8], crv: &str) -> Result<Vec<u8>, String> {
    use synta::types::string::OctetStringRef;
    use synta::{
        BitString, Element, Encoder, Encoding, Integer, ObjectIdentifier, OctetString, Tag,
    };

    use synta_certificate::oids;

    let (curve_oid_components, expected_len): (&[u32], usize) = match crv {
        "P-256" => (oids::EC_CURVE_P256, 32),
        "P-384" => (oids::EC_CURVE_P384, 48),
        "P-521" => (oids::EC_CURVE_P521, 66),
        other => return Err(format!("unsupported EC curve: {other}")),
    };

    if d.len() != expected_len || x.len() != expected_len || y.len() != expected_len {
        return Err(format!(
            "EC {crv} coordinates must be {expected_len} bytes; got d={}, x={}, y={}",
            d.len(),
            x.len(),
            y.len()
        ));
    }

    let ec_oid = ObjectIdentifier::new(oids::EC_PUBLIC_KEY).map_err(|e| format!("EC OID: {e}"))?;
    let curve_oid =
        ObjectIdentifier::new(curve_oid_components).map_err(|e| format!("curve OID: {e}"))?;

    // ECPrivateKey ::= SEQUENCE { version, privateKey, [1] publicKey }
    let uncompressed_point: Vec<u8> = std::iter::once(0x04)
        .chain(x.iter().copied())
        .chain(y.iter().copied())
        .collect();

    let mut inner = Encoder::new(Encoding::Der);
    inner
        .start_constructed_no_guard(Tag::universal_constructed(16))
        .map_err(|e| format!("EC seq: {e}"))?;
    inner
        .encode(&Integer::from_i64(1))
        .map_err(|e| format!("EC version: {e}"))?;
    inner
        .encode(&OctetString::new(d.to_vec()))
        .map_err(|e| format!("EC d: {e}"))?;
    // [1] EXPLICIT BIT STRING (uncompressed point)
    inner
        .start_constructed_no_guard(Tag::context_specific_constructed(1))
        .map_err(|e| format!("EC [1]: {e}"))?;
    inner
        .encode(&BitString::new(uncompressed_point, 0).map_err(|e| format!("EC BitString: {e}"))?)
        .map_err(|e| format!("EC pubkey: {e}"))?;
    inner
        .end_constructed()
        .map_err(|e| format!("EC [1] end: {e}"))?;
    inner
        .end_constructed()
        .map_err(|e| format!("EC seq end: {e}"))?;
    let ec_der = inner.finish().map_err(|e| format!("EC inner: {e}"))?;

    let pki = synta_certificate::pkcs8_types::OneAsymmetricKey {
        version: Integer::from_i64(0),
        private_key_algorithm: synta_certificate::AlgorithmIdentifier {
            algorithm: ec_oid,
            parameters: Some(Element::ObjectIdentifier(curve_oid)),
        },
        private_key: OctetStringRef::new(&ec_der),
        attributes: None,
        public_key: None,
    };
    pki.to_der()
        .map_err(|e| format!("PKCS#8 DER encoding failed: {e}"))
}

fn jwk_b64u(v: &serde_json::Value, field: &str) -> Result<Vec<u8>, String> {
    let s = v[field]
        .as_str()
        .ok_or_else(|| format!("JWK missing field: {field}"))?;
    URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|e| format!("JWK field {field}: base64url decode: {e}"))
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
