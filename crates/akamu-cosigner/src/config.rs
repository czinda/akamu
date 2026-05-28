use std::fmt;
use std::path::Path;

use serde::Deserialize;

use crate::error::CosignerError;

/// Role of a cosigner operator.
#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CosignerRole {
    Administrator,
    Auditor,
}

impl CosignerRole {
    pub fn as_str(self) -> &'static str {
        match self {
            CosignerRole::Administrator => "administrator",
            CosignerRole::Auditor => "auditor",
        }
    }
}

impl fmt::Display for CosignerRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Deserialize)]
pub struct Config {
    pub server: ServerConfig,
    #[serde(default)]
    pub tls: Option<TlsConfig>,
    pub signing_key: SigningKeyConfig,
    pub cosigner_id: CosignerIdConfig,
    #[serde(default)]
    pub acme_bootstrap: Option<AcmeBootstrapConfig>,
    #[serde(default)]
    pub admin: Option<AdminConfig>,
}

/// Admin interface configuration for akamu-cosigner.
#[derive(Debug, Deserialize, Clone)]
pub struct AdminConfig {
    pub listen_addr: String,
    /// Server TLS certificate for the admin listener.
    pub cert_file: String,
    /// Server TLS private key for the admin listener.
    pub key_file: String,
    /// CA certificate(s) trusted for operator client certificates.
    #[serde(default)]
    pub ca_certs: Vec<String>,
    /// Session TTL in seconds (default 3600).
    #[serde(default = "default_session_ttl")]
    pub session_ttl_secs: u64,
    /// Registered operators (at least one cert_fingerprint or gssapi_principal required).
    #[serde(default)]
    pub operators: Vec<OperatorConfig>,
}

/// Default admin session TTL in seconds (1 hour).
pub const DEFAULT_SESSION_TTL_SECS: u64 = 3600;

fn default_session_ttl() -> u64 {
    DEFAULT_SESSION_TTL_SECS
}

/// One operator entry from `[[admin.operators]]`.
#[derive(Debug, Deserialize, Clone)]
pub struct OperatorConfig {
    pub name: String,
    pub role: CosignerRole,
    /// SHA-256 hex fingerprint of the operator's client certificate DER leaf.
    #[serde(default)]
    pub cert_fingerprint: Option<String>,
    /// Kerberos principal, e.g. `alice@REALM`.
    #[serde(default)]
    pub gssapi_principal: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ServerConfig {
    /// Address to listen on.  Accepts `host:port` for TCP (e.g. `"0.0.0.0:8080"`)
    /// or `unix:/path/to/socket` / `/path/to/socket` for a Unix domain socket.
    /// The `AKAMU_COSIGNER_LISTEN` environment variable overrides this field.
    /// Unix domain sockets cannot be combined with `[tls]`.
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

/// Cosigner identity certificate and `TrustAnchorID`.
///
/// Per draft-ietf-plants-merkle-tree-certs-04 §4.1, `CosignerID` is an
/// `OBJECT IDENTIFIER` (`TrustAnchorID`) assigned to the cosigner.
/// `trust_anchor_id` (dotted-decimal) is embedded in every
/// `SubtreeSignature.cosigner` field so that relying parties can identify
/// the cosigner.
///
/// The X.509 certificate in `cert_file` is used by relying parties for
/// cryptographic signature verification; it is not used to derive the OID.
///
/// If `cert_file` is absent at startup and `[acme_bootstrap]` is not
/// configured, a self-signed certificate is generated and written here.
#[derive(Debug, Deserialize)]
pub struct CosignerIdConfig {
    pub cert_file: String,
    /// OID (dotted-decimal) that identifies this cosigner as a TrustAnchorID.
    /// Example: `"1.3.6.1.4.1.44363.47.10.1"`
    pub trust_anchor_id: String,
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
    /// ACME challenge type: `"http-01"`, `"dns-01"`, `"dns-persist-01"`, or `"tls-alpn-01"`.
    #[serde(default = "default_challenge_type")]
    pub challenge_type: String,
    /// Shell command called for dns-01 DNS provisioning.
    ///
    /// Invoked with `ACME_DOMAIN` and `ACME_TXT_VALUE` env vars set.
    /// Exit 0 = record provisioned.  If absent, the TXT value is logged and
    /// an operator must set it manually before akamu-cosigner can proceed.
    #[serde(default)]
    pub dns_hook: Option<String>,
    /// Shell command called for dns-persist-01 DNS provisioning.
    ///
    /// Invoked with `ACME_DOMAIN`, `ACME_TXT_NAME` (`_validation-persist.<domain>`),
    /// `ACME_TXT_VALUE` (`"<issuer>; accounturi=<uri>"`), `ACME_ACCOUNT_URI`, and
    /// `ACME_ISSUER_DOMAIN` env vars set.
    /// Exit 0 = record provisioned.
    #[serde(default)]
    pub dns_persist_hook: Option<String>,
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
        let cfg: Self = toml::from_str(&toml_str)
            .map_err(|e| CosignerError::Config(format!("parse config '{}': {e}", path)))?;
        let is_unix =
            cfg.server.listen_addr.starts_with("unix:") || cfg.server.listen_addr.starts_with('/');
        if cfg.effective_tls().is_some() && is_unix {
            return Err(CosignerError::Config(
                "TLS cannot be used with a Unix domain socket listener".to_owned(),
            ));
        }
        Ok(cfg)
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
            tracing::info!(
                path = %self.cosigner_id.cert_file,
                "using cosigner_id.cert_file as identity certificate"
            );
            return &self.cosigner_id.cert_file;
        }
        if let Some(ref b) = self.acme_bootstrap {
            if Path::new(&b.cert_file).exists() {
                tracing::info!(
                    path = %b.cert_file,
                    "cosigner_id.cert_file absent; falling back to ACME bootstrap cert"
                );
                return &b.cert_file;
            }
        }
        tracing::info!(
            path = %self.cosigner_id.cert_file,
            "cosigner_id.cert_file and ACME bootstrap cert both absent; \
             a self-signed certificate will be generated"
        );
        &self.cosigner_id.cert_file
    }
}
