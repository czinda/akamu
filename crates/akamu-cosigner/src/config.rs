use serde::Deserialize;
use std::path::Path;

use crate::error::CosignerError;

#[derive(Debug, Deserialize)]
pub struct Config {
    pub server: ServerConfig,
    #[serde(default)]
    pub tls: Option<TlsConfig>,
    pub signing_key: SigningKeyConfig,
    pub cosigner_id: CosignerIdConfig,
    #[serde(default)]
    pub acme_bootstrap: Option<AcmeBootstrapConfig>,
}

#[derive(Debug, Deserialize)]
pub struct ServerConfig {
    #[serde(default = "default_listen_addr")]
    pub listen_addr: String,
    pub base_url: String,
}

fn default_listen_addr() -> String {
    "0.0.0.0:8080".into()
}

/// TLS configuration for the HTTP server.
///
/// If absent, the server listens on plain HTTP.
#[derive(Debug, Deserialize, Clone)]
pub struct TlsConfig {
    pub cert_file: String,
    pub key_file: String,
}

/// Signing key used to produce `SubtreeSignature` responses.
///
/// This key is distinct from any TLS key.  It MUST be the key whose public
/// half is embedded in the cosigner-id certificate.
#[derive(Debug, Deserialize)]
pub struct SigningKeyConfig {
    pub key_file: String,
    /// Key type string, same format as akamu `[ca].key_type`:
    /// `"ec:P-256"`, `"ec:P-384"`, `"ed25519"`, `"rsa:2048"`, etc.
    #[serde(default = "default_key_type")]
    pub key_type: String,
    /// Hash algorithm for ECDSA/RSA signing; ignored for EdDSA and ML-DSA.
    #[serde(default = "default_hash_alg")]
    pub hash_alg: String,
}

fn default_key_type() -> String {
    "ec:P-256".into()
}

fn default_hash_alg() -> String {
    "sha256".into()
}

/// Cosigner identity certificate.
///
/// The issuer and serial from this certificate are embedded in every
/// `SubtreeSignature.cosigner` field so that relying parties can match
/// the signature back to a trusted cosigner.
///
/// If `cert_file` is absent at startup and `[acme_bootstrap]` is not
/// configured, a self-signed certificate is generated and written here.
#[derive(Debug, Deserialize)]
pub struct CosignerIdConfig {
    pub cert_file: String,
}

/// Optional ACME EAB bootstrap.
///
/// When present, akamu-cosigner uses `akamu-client` to obtain a certificate
/// from the configured ACME server on startup (if the cert file is absent or
/// expiring soon).  The issued certificate is stored at `cert_file` and
/// `key_file`; it is then used as the TLS server certificate and as the
/// cosigner-id source.
#[derive(Debug, Deserialize)]
pub struct AcmeBootstrapConfig {
    /// ACME server directory URL (e.g. `https://acme.example.com/directory`).
    pub server_url: String,
    /// Contact e-mail for the ACME account (`mailto:` prefix added automatically).
    #[serde(default)]
    pub account_email: Option<String>,
    /// EAB key identifier as provisioned by the CA.
    pub eab_kid: String,
    /// EAB HMAC key, base64url-encoded (no padding).
    pub eab_hmac: String,
    /// DNS name to certify (must be publicly resolvable for the chosen challenge).
    pub domain: String,
    /// ACME challenge type: `"http-01"`, `"dns-01"`, or `"tls-alpn-01"`.
    #[serde(default = "default_challenge_type")]
    pub challenge_type: String,
    /// Shell command called for dns-01 DNS provisioning.
    ///
    /// Invoked with `ACME_DOMAIN` and `ACME_TXT_VALUE` env vars set.
    /// Exit 0 = record provisioned.  If absent, the TXT value is logged and
    /// an operator must set it manually before akamu-cosigner can proceed.
    #[serde(default)]
    pub dns_hook: Option<String>,
    /// Where to write the issued certificate PEM chain.
    pub cert_file: String,
    /// Where to write the private key PEM for the issued certificate.
    pub key_file: String,
    /// Key type for the ACME CSR key (defaults to `"ec:P-256"`).
    #[serde(default = "default_key_type")]
    pub csr_key_type: String,
}

fn default_challenge_type() -> String {
    "http-01".into()
}

impl Config {
    pub fn from_file(path: &str) -> Result<Self, CosignerError> {
        let toml_str = std::fs::read_to_string(path)
            .map_err(|e| CosignerError::Config(format!("read config '{}': {e}", path)))?;
        toml::from_str(&toml_str)
            .map_err(|e| CosignerError::Config(format!("parse config '{}': {e}", path)))
    }

    /// Return the TLS config to use for the HTTP server.
    ///
    /// Priority: explicit `[tls]` section > cert produced by ACME bootstrap.
    pub fn effective_tls(&self) -> Option<TlsConfig> {
        if let Some(ref t) = self.tls {
            return Some(t.clone());
        }
        self.acme_bootstrap.as_ref().map(|b| TlsConfig {
            cert_file: b.cert_file.clone(),
            key_file: b.key_file.clone(),
        })
    }

    /// Path of the cosigner-id cert; falls back to ACME bootstrap cert.
    pub fn effective_cosigner_id_cert(&self) -> &str {
        if Path::new(&self.cosigner_id.cert_file).exists() {
            return &self.cosigner_id.cert_file;
        }
        if let Some(ref b) = self.acme_bootstrap {
            if Path::new(&b.cert_file).exists() {
                return &b.cert_file;
            }
        }
        &self.cosigner_id.cert_file
    }
}
