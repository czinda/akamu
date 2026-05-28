use serde::Deserialize;

/// Server-side TLS configuration.  Absent or `enabled = false` → plain HTTP (no change).
#[derive(Debug, Deserialize, Default, Clone)]
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
