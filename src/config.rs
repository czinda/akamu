use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct Config {
    /// Address to listen on, e.g. "0.0.0.0:8080"
    pub listen_addr: String,
    /// Public base URL of this ACME server, e.g. "https://acme.example.com"
    pub base_url: String,
    pub database: DatabaseConfig,
    pub ca: CaConfig,
    pub mtc: MtcConfig,
    #[serde(default)]
    pub server: ServerConfig,
    /// Server-side TLS. Absent or `enabled = false` → plain HTTP, no behavior change.
    #[serde(default)]
    pub tls: TlsConfig,
}

#[derive(Debug, Deserialize)]
pub struct DatabaseConfig {
    /// Path to the SQLite database file
    pub path: String,
}

#[derive(Debug, Deserialize)]
pub struct CaConfig {
    /// Path to the CA private key PEM file (generated on first run if absent)
    pub key_file: String,
    /// Path to the CA certificate PEM file (generated on first run if absent)
    pub cert_file: String,
    /// Key algorithm for auto-generated CA key: "ec:P-256", "ec:P-384", "ec:P-521",
    /// "rsa:2048", "rsa:3072", "rsa:4096", "ed25519"
    #[serde(default = "default_key_type")]
    pub key_type: String,
    /// Hash algorithm for signing: "sha256", "sha384", "sha512"
    #[serde(default = "default_hash_alg")]
    pub hash_alg: String,
    /// Default validity period for issued certificates (days)
    #[serde(default = "default_validity_days")]
    pub validity_days: u32,
    /// Optional CRL distribution point URL
    pub crl_url: Option<String>,
    /// Optional OCSP responder URL
    pub ocsp_url: Option<String>,
    /// CA distinguished name common name (used when auto-generating)
    #[serde(default = "default_ca_cn")]
    pub common_name: String,
    /// CA subject organization (used when auto-generating)
    #[serde(default = "default_ca_org")]
    pub organization: String,
    /// CA validity years (used when auto-generating)
    #[serde(default = "default_ca_validity_years")]
    pub ca_validity_years: u32,
}

#[derive(Debug, Deserialize)]
pub struct MtcConfig {
    /// Path to the MTC disk-backed log file
    pub log_path: String,
    /// Whether to append issued certificates to the MTC log
    #[serde(default)]
    pub enabled: bool,
}

#[derive(Debug, Deserialize, Default)]
pub struct ServerConfig {
    /// Terms of service URL included in the directory response
    pub terms_of_service_url: Option<String>,
    /// Website URL included in the directory response
    pub website_url: Option<String>,
    /// CAA identities (list of CA domain names for CAA record checking)
    #[serde(default)]
    pub caa_identities: Vec<String>,
    /// Whether external account binding is required
    #[serde(default)]
    pub external_account_required: bool,
    /// Order expiry in seconds (default: 1 day)
    #[serde(default = "default_order_expiry_secs")]
    pub order_expiry_secs: u64,
    /// Authorization expiry in seconds (default: 1 day)
    #[serde(default = "default_authz_expiry_secs")]
    pub authz_expiry_secs: u64,
    /// Maximum body size for JOSE+JSON requests (bytes)
    #[serde(default = "default_max_body_bytes")]
    pub max_body_bytes: usize,
}

/// Server-side TLS configuration.  Absent or `enabled = false` → plain HTTP (no change).
#[derive(Debug, Deserialize, Default)]
pub struct TlsConfig {
    /// Whether to listen with TLS.  Default: false (plain HTTP).
    #[serde(default)]
    pub enabled: bool,
    /// PEM file with the server certificate chain (leaf first).
    #[serde(default)]
    pub cert_file: String,
    /// PEM file with the server private key (PKCS#8 or SEC1, unencrypted).
    #[serde(default)]
    pub key_file: String,
    /// TLS protocol versions to accept. Default: ["TLSv1.2", "TLSv1.3"].
    #[serde(default = "default_tls_protocols")]
    pub protocols: Vec<String>,
    /// Hostname placed in CN and SAN of the auto-generated server certificate.
    /// Only used when cert_file/key_file are absent. Default: "localhost".
    #[serde(default = "default_tls_server_name")]
    pub server_name: String,
    /// Key algorithm for the auto-generated server certificate.
    /// Only used when cert_file/key_file are absent.
    /// Same syntax as ca.key_type: "ec:P-256", "ec:P-384", "ec:P-521",
    /// "rsa:2048", "rsa:3072", "rsa:4096", "ed25519". Default: "ec:P-256".
    #[serde(default = "default_tls_bootstrap_key_type")]
    pub bootstrap_key_type: String,
    /// Mutual TLS client certificate authentication (optional).
    pub client_auth: Option<ClientAuthConfig>,
}

/// Client certificate authentication (`[tls.client_auth]`).
#[derive(Debug, Deserialize, Clone)]
pub struct ClientAuthConfig {
    /// Reject connections that present no client certificate. Default: false.
    #[serde(default)]
    pub required: bool,
    /// PEM files containing trusted root CA certificates for client auth.
    pub ca_files: Vec<String>,
    /// Validation profile: "webpki" (CAB Forum, default) or "rfc5280".
    #[serde(default = "default_tls_profile")]
    pub profile: String,
    /// Allow ML-DSA / hybrid composite post-quantum algorithms. Default: false.
    #[serde(default)]
    pub allow_post_quantum: bool,
    /// Maximum chain depth (default 8).
    #[serde(default = "default_max_chain_depth")]
    pub max_chain_depth: u8,
    /// Minimum RSA modulus in bits (default 2048).
    #[serde(default = "default_minimum_rsa_modulus")]
    pub minimum_rsa_modulus: usize,
}

fn default_tls_protocols() -> Vec<String> {
    vec!["TLSv1.2".to_string(), "TLSv1.3".to_string()]
}
fn default_tls_server_name() -> String {
    "localhost".to_string()
}
fn default_tls_bootstrap_key_type() -> String {
    "ec:P-256".to_string()
}
fn default_tls_profile() -> String {
    "webpki".to_string()
}
fn default_max_chain_depth() -> u8 {
    8
}
fn default_minimum_rsa_modulus() -> usize {
    2048
}

fn default_key_type() -> String {
    "ec:P-256".to_string()
}

fn default_hash_alg() -> String {
    "sha256".to_string()
}

fn default_validity_days() -> u32 {
    90
}

fn default_ca_cn() -> String {
    "ACME Server CA".to_string()
}

fn default_ca_org() -> String {
    "ACME Server".to_string()
}

fn default_ca_validity_years() -> u32 {
    10
}

fn default_order_expiry_secs() -> u64 {
    86400
}

fn default_authz_expiry_secs() -> u64 {
    86400
}

fn default_max_body_bytes() -> usize {
    65536
}

impl Config {
    pub fn from_file(path: &str) -> Result<Self, String> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("cannot read config file '{}': {}", path, e))?;
        toml::from_str(&content).map_err(|e| format!("config parse error: {}", e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn minimal_toml() -> &'static str {
        r#"
listen_addr = "127.0.0.1:8080"
base_url = "https://acme.example.com"

[database]
path = "/tmp/test.db"

[ca]
key_file = "/tmp/ca.key"
cert_file = "/tmp/ca.crt"

[mtc]
log_path = "/tmp/mtc.log"
enabled = false
"#
    }

    #[test]
    fn parse_minimal_config() {
        let cfg: Config = toml::from_str(minimal_toml()).unwrap();
        assert_eq!(cfg.listen_addr, "127.0.0.1:8080");
        assert_eq!(cfg.base_url, "https://acme.example.com");
        assert_eq!(cfg.database.path, "/tmp/test.db");
        assert_eq!(cfg.ca.key_file, "/tmp/ca.key");
        assert_eq!(cfg.ca.cert_file, "/tmp/ca.crt");
        assert_eq!(cfg.mtc.log_path, "/tmp/mtc.log");
        assert!(!cfg.mtc.enabled);
    }

    #[test]
    fn config_ca_defaults_applied() {
        let cfg: Config = toml::from_str(minimal_toml()).unwrap();
        // CaConfig defaults
        assert_eq!(cfg.ca.key_type, "ec:P-256");
        assert_eq!(cfg.ca.hash_alg, "sha256");
        assert_eq!(cfg.ca.validity_days, 90);
        assert_eq!(cfg.ca.common_name, "ACME Server CA");
        assert_eq!(cfg.ca.organization, "ACME Server");
        assert_eq!(cfg.ca.ca_validity_years, 10);
        assert!(cfg.ca.crl_url.is_none());
        assert!(cfg.ca.ocsp_url.is_none());
    }

    #[test]
    fn config_server_defaults_applied_when_section_present() {
        // When [server] section is present, serde uses the `default = "fn"` defaults
        let toml_with_empty_server = format!("{}\n[server]\n", minimal_toml());
        let cfg: Config = toml::from_str(&toml_with_empty_server).unwrap();
        assert_eq!(cfg.server.order_expiry_secs, 86400);
        assert_eq!(cfg.server.authz_expiry_secs, 86400);
        assert_eq!(cfg.server.max_body_bytes, 65536);
        assert!(!cfg.server.external_account_required);
        assert!(cfg.server.caa_identities.is_empty());
        assert!(cfg.server.terms_of_service_url.is_none());
        assert!(cfg.server.website_url.is_none());
    }

    #[test]
    fn config_optional_fields() {
        let toml = r#"
listen_addr = "0.0.0.0:443"
base_url = "https://ca.example.org"

[database]
path = ":memory:"

[ca]
key_file = "/etc/ca.key"
cert_file = "/etc/ca.crt"
key_type = "rsa:4096"
hash_alg = "sha512"
validity_days = 365
crl_url = "http://crl.example.org/ca.crl"
ocsp_url = "http://ocsp.example.org"
common_name = "Test CA"
organization = "Test Org"
ca_validity_years = 5

[mtc]
log_path = "/var/mtc.log"
enabled = true

[server]
terms_of_service_url = "https://example.org/tos"
website_url = "https://example.org"
caa_identities = ["ca.example.org"]
external_account_required = true
order_expiry_secs = 3600
authz_expiry_secs = 7200
max_body_bytes = 131072
"#;
        let cfg: Config = toml::from_str(toml).unwrap();
        assert_eq!(cfg.ca.key_type, "rsa:4096");
        assert_eq!(cfg.ca.hash_alg, "sha512");
        assert_eq!(cfg.ca.validity_days, 365);
        assert_eq!(cfg.ca.crl_url.as_deref(), Some("http://crl.example.org/ca.crl"));
        assert_eq!(cfg.ca.ocsp_url.as_deref(), Some("http://ocsp.example.org"));
        assert_eq!(cfg.ca.ca_validity_years, 5);
        assert!(cfg.mtc.enabled);
        assert_eq!(cfg.server.terms_of_service_url.as_deref(), Some("https://example.org/tos"));
        assert_eq!(cfg.server.website_url.as_deref(), Some("https://example.org"));
        assert_eq!(cfg.server.caa_identities, vec!["ca.example.org"]);
        assert!(cfg.server.external_account_required);
        assert_eq!(cfg.server.order_expiry_secs, 3600);
        assert_eq!(cfg.server.authz_expiry_secs, 7200);
        assert_eq!(cfg.server.max_body_bytes, 131072);
    }

    #[test]
    fn from_file_missing_returns_error() {
        let result = Config::from_file("/nonexistent/path/config.toml");
        assert!(result.is_err());
        let msg = result.unwrap_err();
        assert!(msg.contains("cannot read config file"), "msg: {msg}");
    }

    #[test]
    fn from_file_invalid_toml_returns_error() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        writeln!(f, "this is not valid toml = = =").unwrap();
        let result = Config::from_file(f.path().to_str().unwrap());
        assert!(result.is_err());
        let msg = result.unwrap_err();
        assert!(msg.contains("config parse error"), "msg: {msg}");
    }

    #[test]
    fn from_file_valid_config() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        writeln!(f, "{}", minimal_toml()).unwrap();
        let cfg = Config::from_file(f.path().to_str().unwrap()).unwrap();
        assert_eq!(cfg.listen_addr, "127.0.0.1:8080");
    }
}
