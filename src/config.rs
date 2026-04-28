use std::collections::HashMap;

use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct Config {
    /// Address to listen on, e.g. "0.0.0.0:8080"
    pub listen_addr: String,
    /// Public base URL of this ACME server, e.g. `https://acme.example.com`
    pub base_url: String,
    pub database: DatabaseConfig,
    pub ca: CaConfig,
    pub mtc: MtcConfig,
    #[serde(default)]
    pub server: ServerConfig,
    /// Server-side TLS. Absent or `enabled = false` → plain HTTP, no behavior change.
    #[serde(default)]
    pub tls: TlsConfig,
    /// Certificate profile providers.  When absent, orders without a `profile`
    /// field fall back to CA defaults; the deprecated `server.profiles` map
    /// still governs directory advertisement in that case.
    #[serde(default)]
    pub profiles: ProfilesConfig,
    /// Admin API configuration.  Absent → admin endpoints return 404.
    #[serde(default)]
    pub admin: Option<AdminConfig>,
}

/// Admin API configuration.
///
/// When present, the server exposes admin endpoints under `/admin/`.
/// All requests must supply the configured bearer token in the
/// `Authorization: Bearer <token>` header.
///
/// ```toml
/// [admin]
/// bearer_token = "change-me"
/// ```
#[derive(Debug, Deserialize, Clone)]
pub struct AdminConfig {
    /// Secret token required in the `Authorization` header for all admin requests.
    pub bearer_token: String,
}

// ── Profile subsystem configuration ──────────────────────────────────────────

/// Top-level `[profiles]` configuration section.
///
/// Each key under `providers` is a provider name; the `type` field selects
/// the backend:
///
/// ```toml
/// # Refresh all profiles every 30 minutes
/// [profiles]
/// refresh_interval_secs = 1800
///
/// # Built-in profiles defined inline
/// [profiles.providers.local]
/// type = "builtin"
///
/// [profiles.providers.local.profiles.tlsserver]
/// description = "TLS server certificate"
/// validity_days = 90
/// key_usage  = ["digital_signature", "key_encipherment"]
/// eku        = ["server_auth"]
///
/// # Dogtag PKI profiles from the filesystem
/// [profiles.providers.dogtag_prod]
/// type        = "dogtag"
/// profile_dir = "/etc/pki/pki-tomcat/ca/profiles/ca"
/// profiles    = ["caServerCert", "caIPAserviceCert"]   # empty = all
///
/// # FreeIPA/IPAThinCA profiles via GSSAPI LDAP
/// [profiles.providers.ipa_prod]
/// type     = "ipa"
/// profiles = ["caIPAserviceCert", "IECUserRoles"]
///
/// [profiles.providers.ipa_prod.ldap]
/// uri          = "ldap://ipa.example.com:7389"
/// base_dn      = "o=ipaca"
/// gssapi       = true
/// keytab_file  = "/etc/akamu/akamu.keytab"
/// principal    = "akamu/akamu.example.com@EXAMPLE.COM"
/// ```
#[derive(Debug, Deserialize, Default, Clone)]
pub struct ProfilesConfig {
    /// How often the background task re-reads profiles from all providers.
    /// Profiles are cached in memory; this controls how long a stale cache
    /// can be served before a fresh load is attempted.  Default: 3600 (1 hour).
    /// Builtin (TOML) profiles never change between refreshes.
    #[serde(default = "default_profile_refresh_secs")]
    pub refresh_interval_secs: u64,
    /// Named providers.  When the same profile ID exists in multiple providers,
    /// the first one in HashMap iteration order wins.  Keep profile IDs unique
    /// across providers to avoid ambiguity.
    #[serde(default)]
    pub providers: HashMap<String, ProviderConfig>,
}

fn default_profile_refresh_secs() -> u64 {
    3600 // 1 hour
}

/// Per-provider configuration, discriminated by the `type` field.
#[derive(Debug, Deserialize, Clone)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum ProviderConfig {
    /// Profiles declared inline in `config.toml`; akamu's local CA signs.
    Builtin(BuiltinProviderConfig),
    /// Profiles read from Dogtag PKI `.cfg` files (filesystem or LDAP).
    ///
    /// LDAP layout: `cn=<id>,ou=certificateProfiles,ou=ca,<base_dn>`
    /// with object class `certProfile` and config in `certProfileConfig`.
    Dogtag(DogtagProviderConfig),
    /// Profiles read from a FreeIPA / IPAThinCA deployment.
    ///
    /// IPAThinCA stores profiles in the same Dogtag LDAP format at
    /// `ou=certificateProfiles,ou=ca,o=ipaca` on the IPA-embedded Dogtag
    /// LDAP instance (default port 7389).  LDAP access uses GSSAPI/Kerberos.
    Ipa(IpaProviderConfig),
}

// ── builtin ───────────────────────────────────────────────────────────────────

/// Configuration for the `builtin` provider.
#[derive(Debug, Deserialize, Default, Clone)]
pub struct BuiltinProviderConfig {
    /// Profile definitions keyed by profile identifier.
    #[serde(default)]
    pub profiles: HashMap<String, BuiltinProfileConfig>,
}

/// A single profile entry under a `builtin` provider.
#[derive(Debug, Deserialize, Clone)]
pub struct BuiltinProfileConfig {
    /// Human-readable label or URL; advertised in the ACME directory.
    pub description: String,
    /// Certificate validity in days.  `None` inherits from `[ca].validity_days`.
    pub validity_days: Option<u32>,
    /// Signing hash algorithm (`"sha256"`, `"sha384"`, `"sha512"`).
    /// `None` inherits from `[ca].hash_alg`.
    pub hash_alg: Option<String>,
    /// Key usage bit names.  Recognised values: `"digital_signature"`,
    /// `"non_repudiation"`, `"key_encipherment"`, `"data_encipherment"`,
    /// `"key_agreement"`, `"key_cert_sign"`, `"crl_sign"`,
    /// `"encipher_only"`, `"decipher_only"`.
    #[serde(default = "default_profile_key_usage")]
    pub key_usage: Vec<String>,
    /// Extended key usage entries.  Short names: `"server_auth"`,
    /// `"client_auth"`, `"code_signing"`, `"email_protection"`,
    /// `"time_stamping"`, `"ocsp_signing"`.  Dotted-decimal OID strings
    /// (e.g. `"1.3.6.1.5.5.7.3.1"`) are also accepted.
    #[serde(default = "default_profile_eku")]
    pub eku: Vec<String>,
    /// CRL distribution point URL.  `None` inherits from `[ca].crl_url`.
    /// Empty string `""` suppresses the CDP extension for this profile.
    pub crl_url: Option<String>,
    /// OCSP responder URL.  Same inheritance / suppression semantics as `crl_url`.
    pub ocsp_url: Option<String>,
    /// Restrict subscriber CSR key algorithms.  Empty = any key type accepted.
    /// Same format as `[ca].key_type`: `"ec:P-256"`, `"rsa:2048"`, etc.
    #[serde(default)]
    pub allowed_key_types: Vec<String>,
    /// Certificate policy OIDs to include in the CertificatePolicies extension.
    /// Empty = no CertificatePolicies extension.
    #[serde(default)]
    pub certificate_policies: Vec<PolicyEntry>,
    /// Certificate format to issue.  Accepted values: `"x509"` (default) and
    /// `"mtc"`.  When `"mtc"`, the server builds a Merkle Tree Certificate
    /// (StandaloneCertificate) and requires `[mtc]` to be enabled.
    #[serde(default)]
    pub issue_as: Option<String>,
    /// Regex patterns that order identifiers must satisfy for this profile to be
    /// used.  Each identifier is formatted as `"type:value"` (e.g.
    /// `"dns:example.com"`) before being tested against the patterns.
    /// Empty = no identifier restriction.
    #[serde(default)]
    pub allowed_identifiers: Vec<String>,
    /// Controls whether ALL identifiers must match a pattern (`"all"`, default)
    /// or whether ANY single match is sufficient (`"any"`).  Ignored when
    /// `allowed_identifiers` is empty.
    #[serde(default)]
    pub identifier_match: Option<String>,
    /// Path to an external authorization script.  Receives a JSON object on
    /// stdin (`{"account_id","profile","identifiers"}`).  Exit 0 = permit;
    /// non-zero = deny.  stdout (trimmed) is forwarded to the client as the
    /// denial reason.
    pub auth_hook: Option<String>,
    /// Seconds to wait for `auth_hook` before aborting with a denial.
    /// Default: 30.
    #[serde(default)]
    pub auth_hook_timeout_secs: Option<u64>,
}

/// A certificate policy OID with an optional CPS URI qualifier.
#[derive(Debug, Deserialize, Clone)]
pub struct PolicyEntry {
    /// Dotted-decimal OID string, e.g. `"2.23.140.1.2.1"` (BR DV-SSL).
    pub oid: String,
    /// Optional CPS URI pointer (`id-qt-cps`, OID 1.3.6.1.5.5.7.2.1).
    pub cps_uri: Option<String>,
}

fn default_profile_key_usage() -> Vec<String> {
    vec!["digital_signature".to_string()]
}

fn default_profile_eku() -> Vec<String> {
    vec!["server_auth".to_string()]
}

// ── dogtag ────────────────────────────────────────────────────────────────────

/// Configuration for the `dogtag` provider.
///
/// Reads Dogtag PKI certificate profile definitions.  When `ldap` is present
/// it takes priority over `profile_dir`; at least one must be configured.
///
/// Dogtag `.cfg` files are Java-properties files named `<profile_id>.cfg`.
/// The default filesystem location is `/etc/pki/<instance>/ca/profiles/ca/`.
#[derive(Debug, Deserialize, Clone)]
pub struct DogtagProviderConfig {
    /// Directory containing Dogtag `.cfg` profile files (filesystem source).
    pub profile_dir: Option<String>,
    /// LDAP connection for reading profiles from Dogtag's internal LDAP store.
    /// Profiles are searched at `ou=certificateProfiles,ou=ca,<ldap.base_dn>`.
    pub ldap: Option<LdapConfig>,
    /// Restrict loading to these profile IDs.  Empty = load all profiles found.
    #[serde(default)]
    pub profiles: Vec<String>,
}

// ── ipa ───────────────────────────────────────────────────────────────────────

/// Configuration for the `ipa` provider.
///
/// Reads certificate profile definitions from a FreeIPA / IPAThinCA deployment.
/// IPAThinCA stores profiles in Dogtag's LDAP format under
/// `ou=certificateProfiles,ou=ca,o=ipaca` on the IPA-embedded Dogtag LDAP
/// instance.  LDAP authentication is done via GSSAPI (Kerberos).
///
/// Filesystem fallback: profiles exported as `.cfg` files in `profile_dir`.
#[derive(Debug, Deserialize, Clone)]
pub struct IpaProviderConfig {
    /// Directory containing IPA/Dogtag `.cfg` profile files (filesystem fallback).
    pub profile_dir: Option<String>,
    /// LDAP connection to the IPA Dogtag LDAP instance.
    /// Typical URI: `ldap://ipa.example.com:7389`; `base_dn` = `o=ipaca`.
    /// Authentication is expected to be GSSAPI (`gssapi = true`).
    pub ldap: Option<LdapConfig>,
    /// Restrict loading to these profile IDs.  Empty = load all profiles found.
    #[serde(default)]
    pub profiles: Vec<String>,
}

// ── shared LDAP config ────────────────────────────────────────────────────────

/// LDAP connection parameters shared by the `dogtag` and `ipa` providers.
///
/// Two mutually exclusive authentication methods are supported:
///
/// **Simple bind** — set `bind_dn` and `bind_password_file`.
///
/// **GSSAPI / Kerberos** — set `gssapi = true`.  If `keytab_file` and
/// `principal` are set, a TGT is obtained from the keytab before connecting;
/// otherwise the current Kerberos credential cache (ccache) is used.  This
/// is the expected method for IPA LDAP access.
#[derive(Debug, Deserialize, Clone)]
pub struct LdapConfig {
    /// LDAP URI, e.g. `ldap://host:389`, `ldaps://host:636`,
    /// `ldap://ipa.example.com:7389`.
    pub uri: String,
    /// LDAP base DN under which profiles are searched.
    /// Dogtag: directory root suffix (e.g. `dc=example,dc=com`).
    /// IPA:    `o=ipaca`.
    pub base_dn: String,

    // ── Simple bind ────────────────────────────────────────────────────────
    /// Bind DN for simple authentication (mutually exclusive with `gssapi`).
    pub bind_dn: Option<String>,
    /// Path to a file containing the bind password (one line, no trailing newline
    /// required).  Required when `bind_dn` is set.
    pub bind_password_file: Option<String>,

    // ── GSSAPI / Kerberos ──────────────────────────────────────────────────
    /// Use SASL GSSAPI (Kerberos) authentication.  Default: `false`.
    /// Mutually exclusive with `bind_dn` / `bind_password_file`.
    #[serde(default)]
    pub gssapi: bool,
    /// Path to a Kerberos keytab file.  When set together with `principal`,
    /// a TGT is obtained from the keytab before connecting.  When absent,
    /// the current credential cache (ccache) is used.
    pub keytab_file: Option<String>,
    /// Kerberos principal for keytab-based authentication,
    /// e.g. `akamu/akamu.example.com@EXAMPLE.COM`.
    pub principal: Option<String>,

    // ── TLS ────────────────────────────────────────────────────────────────
    /// PEM file for LDAP server certificate verification.
    /// `None` = use the system trust store.
    pub tls_ca_cert_file: Option<String>,
    /// Upgrade a plain `ldap://` connection to TLS via STARTTLS before binding.
    /// Ignored for `ldaps://` URIs.
    #[serde(default)]
    pub starttls: bool,
}

#[derive(Debug, Deserialize)]
pub struct DatabaseConfig {
    /// Database URL.  SQLite: `sqlite://path/to/db` or `sqlite::memory:`.
    /// PostgreSQL: `postgres://user:pass@host/dbname`.
    /// MariaDB/MySQL: `mariadb://user:pass@host/dbname` or `mysql://…`.
    pub url: String,
    /// Maximum number of pooled connections.
    /// Defaults to 1 for SQLite (multiple connections cause SQLITE_BUSY_SNAPSHOT),
    /// 10 for PostgreSQL/MariaDB.
    pub max_connections: Option<u32>,
}

#[derive(Debug, Deserialize)]
pub struct CaConfig {
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

/// MTC signing key parameters for checkpoint production.
///
/// The signing key MUST be distinct from the X.509 CA key (§5.5 of
/// draft-ietf-plants-merkle-tree-certs).  When absent, checkpoint
/// production and standalone certificate construction are disabled.
///
/// ```toml
/// [mtc.signing_key]
/// key_file = "/var/lib/akamu/mtc-signing.key"
/// key_type = "ec:P-256"
/// hash_alg = "sha256"
/// ```
#[derive(Debug, Clone, Deserialize)]
pub struct MtcSigningKeyConfig {
    /// PEM file for the MTC signing key (generated on first run if absent).
    pub key_file: String,
    /// Key algorithm: same values as `[ca].key_type` ("ec:P-256", "ed25519", …).
    #[serde(default = "default_key_type")]
    pub key_type: String,
    /// Hash algorithm for signatures: "sha256", "sha384", "sha512".
    #[serde(default = "default_hash_alg")]
    pub hash_alg: String,
}

/// Configuration for a single external MTC cosigner.
///
/// Akāmu POSTs the DER-encoded `Checkpoint` to `url`; the cosigner is expected
/// to return a DER-encoded `SubtreeSignature`.  Partial failures are logged and
/// skipped — the standalone certificate is built with whatever signatures arrive.
#[derive(Debug, Clone, Deserialize)]
pub struct CosignerConfig {
    /// URL to POST the DER checkpoint to.
    pub url: String,
    /// Path to the cosigner's X.509 certificate PEM file.  When set, the
    /// signature in the returned `SubtreeSignature` is verified against the
    /// cosigner's public key before the signature is stored.
    pub cosigner_id_cert_pem: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct MtcConfig {
    /// Path to the MTC disk-backed log file.
    pub log_path: String,
    /// Whether to append issued certificates to the MTC log.
    #[serde(default)]
    pub enabled: bool,
    /// MTC signing key for checkpoint production.  Absent → checkpoints disabled.
    pub signing_key: Option<MtcSigningKeyConfig>,
    /// How often the checkpoint background task fires (seconds).  Default: 3600 (1 h).
    #[serde(default = "default_checkpoint_interval_secs")]
    pub checkpoint_interval_secs: u64,
    /// External cosigners.  Each entry is a `[[mtc.cosigners]]` table.
    #[serde(default)]
    pub cosigners: Vec<CosignerConfig>,
    /// How often to freeze a new landmark tree size (seconds).  Default: 86400 (1 day).
    #[serde(default = "default_landmark_interval_secs")]
    pub landmark_interval_secs: u64,
    /// Maximum number of active (non-expired) landmarks to retain.
    /// Once exceeded, the oldest landmark is available to relying parties for
    /// `ceil(max_cert_lifetime / landmark_interval) + 1` overlap.  Default: 100.
    #[serde(default = "default_max_active_landmarks")]
    pub max_active_landmarks: u32,
    /// Maximum number of checkpoints to retain in the database.
    /// Older checkpoints (and their cosignatures) are pruned after each new
    /// checkpoint is produced.  Default: 1000.
    #[serde(default = "default_checkpoint_retention_count")]
    pub checkpoint_retention_count: u32,
}

fn default_checkpoint_interval_secs() -> u64 {
    3600
}

fn default_landmark_interval_secs() -> u64 {
    86400
}

fn default_max_active_landmarks() -> u32 {
    100
}

fn default_checkpoint_retention_count() -> u32 {
    1000
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
    /// TCP port used when fetching http-01 challenge responses.
    /// RFC 8555 §8.3 requires port 80 in production.
    /// Override to a high port for testing or non-standard deployments.
    #[serde(default = "default_http_validation_port")]
    pub http_validation_port: u16,
    /// Issuer domain placed in the `issuer-domain-names` field of dns-persist-01
    /// challenges and matched against TXT records.  When absent the host portion
    /// of `base_url` is used.
    pub dns_persist_issuer_domain: Option<String>,
    /// Override the DNS resolver used for challenge validation (dns-01,
    /// dns-persist-01).  Format: `"ip:port"`, e.g. `"127.0.0.1:5353"`.
    /// When absent the system default resolver is used.
    /// Useful for testing and for split-horizon DNS deployments.
    pub dns_resolver_addr: Option<String>,
    /// Retry-After interval in seconds for `GET /acme/renewal-info` responses (RFC 9773 §4.3).
    #[serde(default = "default_ari_retry_after_secs")]
    pub ari_retry_after_secs: u64,
    /// Advertise RFC 9444 subdomain authorization support in the directory meta.
    #[serde(default)]
    pub allow_subdomain_auth: bool,
    /// Minimum STAR certificate lifetime in seconds (advertised in directory meta).
    pub star_min_lifetime_secs: Option<u64>,
    /// Maximum STAR order duration in seconds (advertised in directory meta).
    pub star_max_duration_secs: Option<u64>,
    /// Whether to advertise and allow unauthenticated GET of STAR certificates
    /// (RFC 8739 §3.1.3 `allow-certificate-get`).  Defaults to `true`.
    /// When `false`, the directory does not advertise the capability and
    /// unauthenticated GET requests are rejected even for orders that request it.
    #[serde(default = "default_star_allow_certificate_get")]
    pub star_allow_certificate_get: bool,
    /// Certificate profiles (draft-aaron-acme-profiles-01).
    /// Maps profile identifier → human-readable description or documentation URL.
    /// Advertised in directory meta. Clients may request a profile by name in newOrder.
    /// When empty, profile selection is not advertised and profile fields are ignored.
    #[serde(default)]
    pub profiles: HashMap<String, String>,
    /// External Account Binding pre-shared keys (RFC 8555 §7.3.4).
    /// Maps key identifier (kid) → base64url-encoded raw HMAC key bytes.
    /// Keys are seeded into the eab_keys DB table at startup using INSERT OR IGNORE,
    /// so runtime-provisioned or consumed keys are never overwritten.
    #[serde(default)]
    pub eab_keys: HashMap<String, String>,
    /// Whether this CA has Tor network connectivity (RFC 9799 §4).
    ///
    /// When `false` (the default), `http-01` and `tls-alpn-01` are NOT offered
    /// for `.onion` identifiers — only `onion-csr-01` is offered.
    /// Set to `true` only when the server can reach the Tor network and
    /// successfully perform outbound connections to `.onion` hidden services.
    #[serde(default)]
    pub tor_connectivity_enabled: bool,
    /// Enable DNSSEC validation for DNS-based challenge verification.
    ///
    /// Applies to dns-01, dns-persist-01, and CAA record lookups.
    /// Required by CA/B Forum BR §3.2.2.4 / §3.2.2.8.1 since 2026-03-15.
    /// Defaults to `true`.  Set to `false` only for testing or in deployments
    /// where the DNS infrastructure is not yet DNSSEC-signed (non-compliant).
    #[serde(default = "default_validate_dnssec")]
    pub validate_dnssec: bool,
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

fn default_http_validation_port() -> u16 {
    80
}

fn default_ari_retry_after_secs() -> u64 {
    21600 // 6 hours
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

fn default_validate_dnssec() -> bool {
    true
}

fn default_star_allow_certificate_get() -> bool {
    true
}

impl Config {
    pub fn from_file(path: &str) -> Result<Self, String> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("cannot read config file '{}': {}", path, e))?;
        toml::from_str(&content).map_err(|e| format!("config parse error: {}", e))
    }

    /// Returns the issuer domain used for dns-persist-01 TXT record validation.
    ///
    /// Uses `server.dns_persist_issuer_domain` when explicitly configured; otherwise
    /// extracts the host portion of `base_url` (stripping scheme and port).
    pub fn dns_persist_issuer_domain(&self) -> String {
        if let Some(ref d) = self.server.dns_persist_issuer_domain {
            return d.clone();
        }
        // Extract host from base_url: strip scheme, then take up to first '/' or ':'
        let without_scheme = self
            .base_url
            .strip_prefix("https://")
            .or_else(|| self.base_url.strip_prefix("http://"))
            .unwrap_or(&self.base_url);
        let host = without_scheme.split('/').next().unwrap_or(without_scheme);
        let host = host.split(':').next().unwrap_or(host);
        host.to_string()
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
url = "sqlite:///tmp/test.db"

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
        assert_eq!(cfg.database.url, "sqlite:///tmp/test.db");
        assert!(cfg.database.max_connections.is_none());
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
        assert!(cfg.server.dns_persist_issuer_domain.is_none());
        assert_eq!(cfg.server.ari_retry_after_secs, 21600);
    }

    #[test]
    fn dns_persist_issuer_domain_uses_explicit_field() {
        let toml = format!(
            "{}\n[server]\ndns_persist_issuer_domain = \"ca.example.org\"\n",
            minimal_toml()
        );
        let cfg: Config = toml::from_str(&toml).unwrap();
        assert_eq!(cfg.dns_persist_issuer_domain(), "ca.example.org");
    }

    #[test]
    fn dns_persist_issuer_domain_falls_back_to_base_url_https() {
        let cfg: Config = toml::from_str(minimal_toml()).unwrap();
        // base_url = "https://acme.example.com" → host = "acme.example.com"
        assert_eq!(cfg.dns_persist_issuer_domain(), "acme.example.com");
    }

    #[test]
    fn dns_persist_issuer_domain_strips_port_from_base_url() {
        let toml = r#"
listen_addr = "127.0.0.1:8080"
base_url = "https://acme.example.com:8443"
[database]
url = "sqlite::memory:"
[ca]
key_file = "/tmp/ca.key"
cert_file = "/tmp/ca.crt"
[mtc]
log_path = "/dev/null"
enabled = false
"#;
        let cfg: Config = toml::from_str(toml).unwrap();
        assert_eq!(cfg.dns_persist_issuer_domain(), "acme.example.com");
    }

    #[test]
    fn config_optional_fields() {
        let toml = r#"
listen_addr = "0.0.0.0:443"
base_url = "https://ca.example.org"

[database]
url = "sqlite::memory:"

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
        assert_eq!(
            cfg.ca.crl_url.as_deref(),
            Some("http://crl.example.org/ca.crl")
        );
        assert_eq!(cfg.ca.ocsp_url.as_deref(), Some("http://ocsp.example.org"));
        assert_eq!(cfg.ca.ca_validity_years, 5);
        assert!(cfg.mtc.enabled);
        assert_eq!(
            cfg.server.terms_of_service_url.as_deref(),
            Some("https://example.org/tos")
        );
        assert_eq!(
            cfg.server.website_url.as_deref(),
            Some("https://example.org")
        );
        assert_eq!(cfg.server.caa_identities, vec!["ca.example.org"]);
        assert!(cfg.server.external_account_required);
        assert_eq!(cfg.server.order_expiry_secs, 3600);
        assert_eq!(cfg.server.authz_expiry_secs, 7200);
        assert_eq!(cfg.server.max_body_bytes, 131072);
    }

    #[test]
    fn ari_retry_after_secs_explicit_and_default() {
        let toml_explicit = format!(
            "{}\n[server]\nari_retry_after_secs = 3600\n",
            minimal_toml()
        );
        let cfg: Config = toml::from_str(&toml_explicit).unwrap();
        assert_eq!(cfg.server.ari_retry_after_secs, 3600);

        // Default when [server] section is present but field is absent.
        // (When the section is completely absent, Rust's Default impl is used instead.)
        let toml_section_only = format!("{}\n[server]\n", minimal_toml());
        let cfg_default: Config = toml::from_str(&toml_section_only).unwrap();
        assert_eq!(cfg_default.server.ari_retry_after_secs, 21600);
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
