use serde::Deserialize;

/// Signing backend discriminator for a `[[ca]]` entry.
///
/// When absent from the config file (`signer` field omitted), the CA uses
/// local signing — the existing `key_file` + `cert_file` behaviour.
///
/// ```toml
/// # Local signing (default, signer section may be omitted entirely):
/// [[ca]]
/// key_file  = "/etc/akamu/ca.key"
/// cert_file = "/etc/akamu/ca.crt"
///
/// # Dogtag PKI delegation:
/// [[ca]]
/// cert_file = "/etc/akamu/dogtag-ca-chain.pem"
/// [ca.signer]
/// type         = "dogtag"
/// url          = "https://pki.example.com:8443"
/// ra_cert_file = "/etc/akamu/ra-agent.pem"
/// ra_key_file  = "/etc/akamu/ra-agent.key.pem"
/// profile_id   = "caServerCert"
/// ```
#[derive(Debug, Deserialize, Clone)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum SignerConfig {
    Local,
    Dogtag(DogtagSignerConfig),
}

/// Dogtag PKI CA REST API configuration for delegated signing.
///
/// When a `[[ca]]` entry uses `[ca.signer] type = "dogtag"`, Akamu acts as
/// an ACME Registration Authority: it validates ACME requests, performs
/// challenge verification, then submits the CSR to a Dogtag CA for signing
/// via the REST enrollment API.
#[derive(Debug, Deserialize, Clone)]
pub struct DogtagSignerConfig {
    /// Base URL of the Dogtag CA (e.g. `"https://pki.example.com:8443"`).
    /// The enrollment endpoint is `{url}/ca/rest/certrequests/`.
    pub url: String,
    /// PEM file containing the RA agent certificate for TLS client auth.
    pub ra_cert_file: String,
    /// PEM file containing the RA agent private key.
    pub ra_key_file: String,
    /// Optional passphrase file for an encrypted RA agent key.
    pub ra_key_password_file: Option<String>,
    /// Optional additional CA certificate PEM for TLS verification of the
    /// Dogtag server (when not in the system trust store).
    pub ca_cert_file: Option<String>,
    /// Default Dogtag enrollment profile ID.  Can be overridden per ACME
    /// profile via `dogtag_profile_id`.
    #[serde(default = "default_dogtag_profile")]
    pub profile_id: String,
    /// REST API call timeout in seconds.
    #[serde(default = "default_dogtag_timeout")]
    pub timeout_secs: u64,
}

fn default_dogtag_profile() -> String {
    "caServerCert".to_string()
}

fn default_dogtag_timeout() -> u64 {
    30
}

#[derive(Debug, Deserialize, Clone)]
pub struct CaConfig {
    /// Unique identifier for this CA (used as the URL prefix `/acme/{id}/...`).
    ///
    /// Required when using the `[[ca]]` array-of-tables format.  When using the
    /// legacy `[ca]` single-table format this field is absent from the config
    /// and the deserializer sets it to `"default"` automatically.
    ///
    /// Must match `^[a-z0-9][a-z0-9_-]*$` (lowercase letters, digits, underscore, hyphen;
    /// maximum 64 characters) and must not be a reserved ACME path segment
    /// (`"directory"`, `"new-nonce"`, `"new-account"`, …).
    #[serde(default)]
    pub id: String,
    /// Marks this CA as the one that serves the backward-compatible
    /// `/acme/directory` and `/ca/crl` endpoints.  Exactly one CA must be
    /// default; when there is only one `[[ca]]` entry it is implicitly default.
    #[serde(default)]
    pub is_default: bool,
    /// CAA domain identities specific to this CA.  Advertised in the ACME
    /// directory `meta.caaIdentities` field.  Falls back to
    /// `[server].caa_identities` when empty.
    #[serde(default)]
    pub caa_identities: Vec<String>,
    /// Path to the CA private key PEM file, or a PKCS#11 URI
    /// (`pkcs11:token=…;object=…;type=private`) for HSM-backed keys.
    ///
    /// PEM file keys are generated on first run if absent.  PKCS#11 keys must
    /// already exist in the token before the server starts.
    ///
    /// **OpenSSL backend**: the `pkcs11-provider` must be loaded via `openssl.cnf`
    /// or the `OPENSSL_CONF` environment variable before the server starts.
    ///
    /// **NSS backend**: the PKCS#11 module must be registered in the NSS secmod
    /// database.  The URI must include a non-empty `token=` attribute — the NSS
    /// path uses `PK11_ListPrivKeysInSlot`, which requires a slot handle obtained
    /// by `PK11_FindSlotByName` from the token label.
    pub key_file: Option<String>,
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
    /// Optional CRL distribution point URL.
    /// When set, issued certificates include a CRLDistributionPoints extension pointing
    /// here.  Set this to `{base_url}/ca/crl` to use the server's built-in CRL endpoint.
    pub crl_url: Option<String>,
    /// Optional OCSP responder URL.
    /// When set, issued certificates include an AuthorityInfoAccess/OCSP extension.
    /// Set this to `{base_url}/ca/ocsp` to use the server's built-in OCSP endpoint.
    pub ocsp_url: Option<String>,
    /// nextUpdate validity window for the built-in CRL endpoint (seconds).
    /// Default: 86400 (1 day).
    #[serde(default = "default_crl_next_update_secs")]
    pub crl_next_update_secs: u64,
    /// CA distinguished name common name (used when auto-generating)
    #[serde(default = "default_ca_cn")]
    pub common_name: String,
    /// CA subject organization (used when auto-generating)
    #[serde(default = "default_ca_org")]
    pub organization: String,
    /// CA validity years (used when auto-generating)
    #[serde(default = "default_ca_validity_years")]
    pub ca_validity_years: u32,
    /// When `true`, reject certificate issuance when the computed validity period
    /// exceeds 200 days (the current CA/B Forum BR §6.3.2 limit since 2026-03-15).
    /// Default `false` — private or enterprise PKI deployments may legitimately
    /// issue certificates with longer validity when not chaining to a public root.
    /// Public WebPKI CAs should set this to `true` to enforce the limit at
    /// issuance time rather than relying solely on the startup warning.
    #[serde(default)]
    pub enforce_validity_cap: bool,
    /// Require the CA private key PEM to be encrypted (FCS_STG_EXT.1).
    ///
    /// When `true`, the server refuses to load a plaintext (unencrypted) PEM
    /// private key from a file.  Only PKCS#8 encrypted PEM (`ENCRYPTED PRIVATE
    /// KEY`) or PKCS#11 URIs are accepted.  Set `key_password_file` to a file
    /// containing the decryption passphrase.
    #[serde(default)]
    pub require_encrypted_key: bool,
    /// Path to a file containing the passphrase for an encrypted PEM CA key.
    /// Required when `require_encrypted_key` is `true` and `key_file` is a
    /// filesystem path (not a PKCS#11 URI).  The file is read once at startup;
    /// trailing newlines are stripped.
    pub key_password_file: Option<String>,
    /// Per-CA MTC transparency log configuration.  When absent, this CA does
    /// not participate in an MTC log.  Falls back to the global `[mtc]` section
    /// when that exists and this field is `None`.
    pub mtc: Option<super::mtc::MtcConfig>,
    /// Signing backend.  When absent or `type = "local"`, the CA uses its own
    /// `key_file` for local signing (the default).  When `type = "dogtag"`,
    /// certificate signing is delegated to a Dogtag PKI CA via its REST API.
    #[serde(default)]
    pub signer: Option<SignerConfig>,
}

impl CaConfig {
    /// Returns `true` when this CA uses an external signing backend
    /// (i.e. the CA private key is not local).
    pub fn is_external_signer(&self) -> bool {
        matches!(self.signer, Some(SignerConfig::Dogtag(_)))
    }
}

pub(super) fn default_key_type() -> String {
    "ec:P-256".to_string()
}

pub(super) fn default_hash_alg() -> String {
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

fn default_crl_next_update_secs() -> u64 {
    86400
}
