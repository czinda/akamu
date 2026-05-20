use std::collections::HashMap;

use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct Config {
    /// Address to listen on.  Accepts `host:port` for TCP (e.g. `"0.0.0.0:8080"`)
    /// or `unix:/path/to/socket` / `/path/to/socket` for a Unix domain socket.
    /// The `AKAMU_LISTEN` environment variable overrides this field.
    /// Unix domain sockets cannot be combined with `[tls]`.
    pub listen_addr: String,
    /// Public base URL of this ACME server, e.g. `https://acme.example.com`
    pub base_url: String,
    pub database: DatabaseConfig,
    #[serde(rename = "ca", deserialize_with = "deserialize_ca_array")]
    pub cas: Vec<CaConfig>,
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
    /// RFC 8823 S/MIME email-reply-00 challenge support.
    /// Absent or `enabled = false` → "email" identifier type is rejected.
    #[serde(default)]
    pub email_challenge: Option<EmailChallengeConfig>,
    /// Upstream CA configuration for the IdO→CA leg of RFC 9115.
    /// When absent, delegation orders are issued directly by Akamu's own CA.
    #[serde(default)]
    pub delegation_upstream: Option<DelegationUpstreamConfig>,
}

/// Admin API configuration (PP CA v2.1 FMT + FTA_SSL).
///
/// Admin interface configuration.  Admin endpoints (`/admin/*`) are served on
/// the same listener as the ACME API.  Operator authentication uses mTLS client
/// certificates (configure via `[tls.client_auth]` with `required = false`),
/// GSSAPI/Kerberos (`[admin.gssapi]`), or session tokens (EAB kid+HMAC login).
/// At least one of mTLS (`[tls.client_auth]`) or GSSAPI must be reachable.
///
/// ```toml
/// [admin]
/// session_ttl_secs = 3600
///
/// [admin.gssapi]
/// keytab_file  = "/etc/akamu/http.keytab"
/// service_name = "HTTP"
/// ```
#[derive(Debug, Deserialize, Clone)]
pub struct AdminConfig {
    /// GSSAPI/Kerberos authentication for operators.  When absent, only mTLS
    /// client certificates (via `[tls.client_auth]`) are accepted.
    pub gssapi: Option<AdminGssapiConfig>,
    /// Inactive session expiry (FTA_SSL.3/4/EXT.1).  Default: 3600 s (1 h).
    #[serde(default = "default_admin_session_ttl_secs")]
    pub session_ttl_secs: u64,
    /// Inactivity threshold before a session enters locked state
    /// (FTA_SSL_EXT.1).  Default: 900 s (15 min).
    ///
    /// After this much idle time, requests with the session token receive
    /// `423 Locked` instead of `401 Unauthorized`.  The session is not
    /// destroyed; the operator must re-authenticate to obtain a new token.
    /// Must be less than `session_ttl_secs`.
    #[serde(default = "default_admin_session_lock_secs")]
    pub session_lock_secs: u64,
    /// Maximum credential presentations (Bearer token, mTLS cert, or GSSAPI token)
    /// from a single source IP in a rolling 5-minute window before the source
    /// receives 429 responses.  Prevents audit-log floods that could trigger the
    /// FAU_STG.4 overflow halt or FAU_ARP.1 alarm.  Default: 20.
    #[serde(default = "default_admin_auth_rate_limit")]
    pub auth_rate_limit: u32,
    /// Maximum failed authentication attempts per operator before lockout
    /// (FIA_AFL.1).  Default: 5.
    #[serde(default = "default_max_failed_auth")]
    pub max_failed_auth: u32,
    /// Lockout duration in seconds after exceeding `max_failed_auth`
    /// (FIA_AFL.1).  Default: 1800 s (30 min).
    #[serde(default = "default_lockout_duration_secs")]
    pub lockout_duration_secs: u64,
    /// Maximum number of `audit_events` rows (FAU_STG.4).  Absent = unlimited.
    pub audit_max_rows: Option<i64>,
    /// Overflow policy when `audit_max_rows` is reached (FAU_STG.4).
    /// `"halt"` — refuse new requests.  `"drop_oldest"` — delete the oldest rows.
    /// Default: `"drop_oldest"`.
    #[serde(default = "default_audit_overflow")]
    pub audit_overflow: String,
    /// Number of `SecurityViolation` events in a rolling 5-minute window that
    /// triggers the FAU_ARP.1 alarm response.  Default: 10.
    #[serde(default = "default_audit_alarm_threshold")]
    pub audit_alarm_threshold: u32,
    /// Action taken when the FAU_ARP.1 threshold is exceeded.
    /// `"syslog"` — log CRIT.  `"halt"` — halt the server.  Default: `"syslog"`.
    #[serde(default = "default_audit_alarm_action")]
    pub audit_alarm_action: String,
    /// Key algorithm for the auto-generated bootstrap operator certificate.
    /// Same syntax as `ca.key_type`. Default: `"ec:P-256"`.
    #[serde(default = "default_admin_bootstrap_key_type")]
    pub bootstrap_key_type: String,
    /// PEM file for the bootstrap Administrator operator's client certificate.
    /// If set and the file is absent when the operators table is empty, a
    /// client certificate signed by the Akāmu CA is generated automatically
    /// and the operator is registered in the database.
    pub bootstrap_operator_cert_file: Option<String>,
    /// PEM file for the bootstrap Administrator operator's client private key.
    /// Must be set alongside `bootstrap_operator_cert_file`.
    pub bootstrap_operator_key_file: Option<String>,
    /// Name recorded in the database for the auto-provisioned bootstrap operator.
    /// Default: `"admin"`.
    #[serde(default = "default_admin_bootstrap_operator_name")]
    pub bootstrap_operator_name: String,
    /// Kerberos principal for the GSSAPI bootstrap Administrator operator
    /// (e.g. `"admin@REALM"`).  When set and the operators table is empty at
    /// startup, an Administrator row with this principal is inserted so that
    /// the first GSSAPI login succeeds without manual `akamuctl operator add`.
    /// Mutually exclusive with `bootstrap_operator_cert_file` / `bootstrap_operator_key_file`.
    pub bootstrap_operator_gssapi_principal: Option<String>,
}

fn default_admin_session_ttl_secs() -> u64 {
    3600
}
fn default_admin_session_lock_secs() -> u64 {
    900
}
fn default_admin_auth_rate_limit() -> u32 {
    20
}
fn default_max_failed_auth() -> u32 {
    5
}
fn default_lockout_duration_secs() -> u64 {
    1800
}
fn default_audit_overflow() -> String {
    "drop_oldest".to_owned()
}
fn default_audit_alarm_threshold() -> u32 {
    10
}
fn default_audit_alarm_action() -> String {
    "syslog".to_owned()
}
fn default_admin_bootstrap_key_type() -> String {
    "ec:P-256".to_owned()
}
fn default_admin_bootstrap_operator_name() -> String {
    "admin".to_owned()
}

impl AdminConfig {
    /// Validate the config and return a human-readable error if invalid.
    pub fn validate(&self) -> Result<(), String> {
        match self.audit_overflow.as_str() {
            "halt" | "drop_oldest" => {}
            other => {
                return Err(format!(
                    "[admin].audit_overflow must be \"halt\" or \"drop_oldest\", got \"{other}\""
                ))
            }
        }
        match self.audit_alarm_action.as_str() {
            "syslog" | "halt" => {}
            other => {
                return Err(format!(
                    "[admin].audit_alarm_action must be \"syslog\" or \"halt\", got \"{other}\""
                ))
            }
        }
        match (
            &self.bootstrap_operator_cert_file,
            &self.bootstrap_operator_key_file,
        ) {
            (Some(_), None) | (None, Some(_)) => {
                return Err(
                    "[admin] bootstrap_operator_cert_file and bootstrap_operator_key_file \
                     must be set together or not at all"
                        .into(),
                )
            }
            _ => {}
        }
        if self.bootstrap_operator_gssapi_principal.is_some()
            && self.bootstrap_operator_cert_file.is_some()
        {
            return Err("[admin] bootstrap_operator_gssapi_principal and \
                 bootstrap_operator_cert_file / bootstrap_operator_key_file \
                 are mutually exclusive; choose one bootstrap method"
                .into());
        }
        Ok(())
    }
}

/// GSSAPI/Kerberos configuration for the admin interface.
#[derive(Debug, Deserialize, Clone)]
pub struct AdminGssapiConfig {
    /// Path to the HTTP service keytab (e.g. `/etc/akamu/http.keytab`).
    pub keytab_file: String,
    /// Host-based service name.  MIT Kerberos appends `@<hostname>` automatically.
    /// Default: `"HTTP"`.
    #[serde(default = "default_gssapi_service")]
    pub service_name: String,
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
    /// When `true`, the requesting account must have this profile's name in its
    /// `profile_grants` attribute.  Grants are set via the admin API or copied
    /// from the EAB key at account-creation time.
    #[serde(default)]
    pub require_account_grant: bool,
    /// Restrict this profile to specific CA IDs.  When empty (the default) the
    /// profile is available to all CAs.  Use CA IDs from the `[[ca]]` entries.
    ///
    /// Example: `ca_ids = ["rsa", "ec"]` makes the profile available only
    /// through the RSA and EC CAs.
    #[serde(default)]
    pub ca_ids: Vec<String>,
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
    // ── Server address(es) ─────────────────────────────────────────────────
    /// Single LDAP URI (`ldap://host:389`, `ldaps://host:636`).
    /// Kept for backward compatibility; prefer `uris` for explicit lists.
    /// Mutually exclusive with `srv_domain`; combined with `uris` if both are set.
    #[serde(default)]
    pub uri: Option<String>,
    /// List of LDAP URIs tried in order for failover.
    /// `ldap_initialize` receives all of them as a space-separated string and
    /// tries each in turn.  Mutually exclusive with `srv_domain`.
    #[serde(default)]
    pub uris: Vec<String>,
    /// Discover LDAP servers via DNS SRV records (`_ldap._tcp.{srv_domain}`).
    /// Resolved records are sorted by RFC 2782 priority/weight and appended
    /// after any explicitly listed `uris`.
    pub srv_domain: Option<String>,

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

    /// URI scheme used when constructing URIs from SRV-discovered servers.
    /// Allowed values: `"ldap"` (default) or `"ldaps"`.  Use `"ldaps"` when
    /// SRV records point at LDAP-over-TLS servers (port 636).
    #[serde(default = "default_srv_scheme")]
    pub srv_scheme: String,

    // ── Timeouts ───────────────────────────────────────────────────────────
    /// Timeout in seconds for TCP connect and LDAP operations.
    /// 0 means no finite timeout (OS default).  Default: 10.
    #[serde(default = "default_ldap_timeout_secs")]
    pub timeout_secs: u64,
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
    /// Require TLS for database connections (FPT_ITT.1).
    ///
    /// When `true`, the server refuses to start unless the database URL contains
    /// an SSL/TLS mode parameter that enforces encryption:
    /// - PostgreSQL: `sslmode=require`, `sslmode=verify-ca`, or `sslmode=verify-full`
    /// - MariaDB/MySQL: `ssl-mode=REQUIRED`, `ssl-mode=VERIFY_CA`, or `ssl-mode=VERIFY_IDENTITY`
    /// - SQLite: ignored (local file, no network transport)
    #[serde(default)]
    pub require_tls: bool,
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
    /// Hash algorithm used for Merkle tree leaf hashing.  Default: `"sha256"`.
    /// Valid values: `sha256`, `sha384`, `sha512`, `sha3-256`, `sha3-384`, `sha3-512`.
    ///
    /// WARNING: changing this for an existing log requires deleting the log file
    /// and recreating it; the algorithm is stored in the log's file header.
    #[serde(default = "default_hash_alg")]
    pub hash_alg: String,
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

#[derive(Debug, Deserialize)]
pub struct ServerConfig {
    /// Account scoping for multi-CA deployments.
    ///
    /// `"server"` (default) — one account registration is valid for all CAs;
    /// all CA directories advertise the shared `/acme/new-account` endpoint.
    ///
    /// `"ca"` — accounts are isolated per CA; each CA directory advertises its
    /// own `/acme/{ca_id}/new-account` endpoint and JWS validation enforces
    /// that the account's CA matches the request's CA.
    #[serde(default = "default_account_scope")]
    pub account_scope: String,
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
    /// Allow http-01 redirect targets that resolve to private or loopback IP
    /// addresses (RFC-1918, link-local 169.254/16, loopback 127/8, etc.).
    ///
    /// **Default: `false`** — private-IP redirects are blocked to prevent
    /// SSRF attacks against cloud metadata endpoints (e.g. 169.254.169.254).
    ///
    /// Set to `true` only in isolated test environments where the challenge
    /// responder intentionally runs on a private address.
    #[serde(default)]
    pub http_validation_allow_private_ips: bool,
    /// Issuer domain(s) placed in the `issuer-domain-names` field of
    /// dns-persist-01 challenges and matched against TXT records.  Accepts a
    /// single string or an array of strings.  When empty, the host portion of
    /// `base_url` is used as the sole issuer domain.
    ///
    /// ```toml
    /// dns_persist_issuer_domains = "acme.example.com"
    /// # or
    /// dns_persist_issuer_domains = ["acme.example.com", "acme.example.org"]
    /// ```
    #[serde(default, deserialize_with = "deserialize_string_or_vec")]
    pub dns_persist_issuer_domains: Vec<String>,
    /// Override the DNS resolver used for challenge validation (dns-01,
    /// dns-persist-01, and CAA).  Format: `"ip:port"`, e.g. `"127.0.0.1:5353"`.
    /// When absent the system default resolver is used.
    /// Useful for testing and for split-horizon DNS deployments.
    pub dns_resolver_addr: Option<String>,
    /// Override the DNS resolver used exclusively for dns-persist-01 validation.
    /// Falls back to `dns_resolver_addr` when absent.
    /// Useful when TXT records for persistent challenges are served by a different
    /// resolver than the one used for dns-01 and CAA lookups.
    pub dns_persist01_resolver_addr: Option<String>,
    /// TLS server name (SNI hostname) for DNS-over-TLS (DoT, RFC 7858).
    /// When set, all DNS challenge queries use DoT on port 853.
    /// `dns_resolver_addr` must point to the DoT server (e.g. `"1.1.1.1:853"`).
    /// Example: `dns_dot_server_name = "cloudflare-dns.com"`.
    pub dns_dot_server_name: Option<String>,
    /// Retry-After interval in seconds for `GET /acme/renewal-info` responses (RFC 9773 §4.3).
    #[serde(default = "default_ari_retry_after_secs")]
    pub ari_retry_after_secs: u64,
    /// URL included in `GET /acme/renewal-info` responses as `explanationURL` (RFC 9773 §4.1).
    /// When absent, the field is omitted from the response.  Use this to point clients at a
    /// human-readable page explaining why early renewal is being suggested (e.g. an incident
    /// notice or CA policy update).
    pub ari_explanation_url: Option<String>,
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
    /// RFC 9115 §2.3.4: advertise delegation support in directory meta.
    #[serde(default)]
    pub delegation_enabled: bool,
    /// RFC 9115 §2.3.5: advertise and allow unauthenticated cert GET for
    /// non-STAR delegation orders.
    #[serde(default)]
    pub allow_certificate_get: bool,
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
    /// CIDR blocks whose connecting IP is trusted to supply `X-Remote-User`.
    ///
    /// When a request arrives from one of these addresses the server reads the
    /// `X-Remote-User` header value as the authenticated principal name (set by
    /// a reverse proxy that terminated SPNEGO/Kerberos authentication).
    ///
    /// Example: `trusted_proxies = ["127.0.0.1/32", "::1/128", "10.0.0.0/8"]`
    ///
    /// Requests from other source IPs never have `X-Remote-User` honoured,
    /// regardless of what the header contains.
    #[serde(default)]
    pub trusted_proxies: Vec<ipnet::IpNet>,
    /// Standalone GSSAPI/SPNEGO configuration.
    ///
    /// When set, Akamu handles `Authorization: Negotiate` directly without a
    /// reverse proxy.  The server acquires credentials from `keytab_file` at
    /// startup and validates each SPNEGO token with `gss_accept_sec_context`.
    ///
    /// Example:
    /// ```toml
    /// [server.gssapi]
    /// keytab_file  = "/etc/akamu/http.keytab"
    /// service_name = "HTTP"   # MIT Kerberos appends @<hostname> automatically
    /// ```
    pub gssapi: Option<GssapiConfig>,
    /// Base64url-encoded master secret for HKDF-based EAB key derivation.
    /// Must decode to ≥ 32 bytes.  When absent, `/acme/eab` returns only the
    /// principal name (backward-compatible stub behaviour).
    ///
    /// Generate with: `openssl rand -base64 32 | tr '+/' '-_' | tr -d '='`
    pub eab_master_secret: Option<String>,
    /// Management web UI configuration.
    ///
    /// When present, the server serves the built PatternFly web UI at `/ui/*`
    /// on the same listener as the ACME and admin APIs.
    ///
    /// ```toml
    /// [server.webui]
    /// static_dir = "/usr/share/akamu/webui"
    /// ```
    pub webui: Option<WebUiConfig>,
}

/// Web UI configuration (`[server.webui]`).
///
/// The web UI is served at `/ui/*` on the main ACME/admin listener.
/// Admin API calls from the browser go to `/admin/*` directly — no proxy.
#[derive(Debug, Deserialize, Clone)]
pub struct WebUiConfig {
    /// Directory containing the built `webui/dist/` output to serve.
    /// When absent the server falls back to the binary-embedded UI (if
    /// compiled with the `embed-webui` feature).
    pub static_dir: Option<String>,
}

/// Upstream CA configuration for the IdO→CA leg of RFC 9115 delegation.
///
/// ```toml
/// [delegation_upstream]
/// directory_url      = "https://acme.ca.example/acme/directory"
/// account_key_file   = "/etc/akamu/upstream-account.key"
/// contacts           = ["mailto:admin@ido.example"]
/// challenge_solver   = "dns-01"
/// poll_interval_secs = 10
/// ```
#[derive(Debug, Deserialize, Clone)]
pub struct DelegationUpstreamConfig {
    /// Directory URL of the upstream ACME CA.
    pub directory_url: String,
    /// PEM file containing the ACME account private key for the IdO's CA account.
    pub account_key_file: String,
    /// Contact URIs (e.g. `"mailto:admin@example.com"`) used when registering the
    /// account if it does not yet exist on the upstream CA.
    #[serde(default)]
    pub contacts: Vec<String>,
    /// Challenge solver to use for the upstream CA: `"dns-01"`, `"http-01"`, or
    /// `"tls-alpn-01"`.
    pub challenge_solver: String,
    /// Path to an executable that provisions a DNS-01 TXT record.
    ///
    /// Called with environment variables `CERTBOT_DOMAIN` (the bare domain,
    /// without `_acme-challenge.` prefix) and `CERTBOT_VALIDATION` (the
    /// base64url SHA-256 value to publish).  Required when `challenge_solver =
    /// "dns-01"`.
    #[serde(default)]
    pub challenge_deploy_script: Option<String>,
    /// Path to an executable that removes the DNS-01 TXT record after validation.
    ///
    /// Called with `CERTBOT_DOMAIN` and `CERTBOT_AUTH_OUTPUT` (same domain).
    /// Optional; cleanup is skipped when absent.
    #[serde(default)]
    pub challenge_cleanup_script: Option<String>,
    /// Seconds between upstream order status checks. Default: 10.
    #[serde(default = "default_upstream_poll_secs")]
    pub poll_interval_secs: u64,
}

fn default_upstream_poll_secs() -> u64 {
    10
}

/// Standalone GSSAPI/SPNEGO configuration for Akamu acting as its own KDC client.
#[derive(Debug, Deserialize)]
pub struct GssapiConfig {
    /// Path to the HTTP service keytab (e.g. `/etc/akamu/http.keytab`).
    pub keytab_file: String,
    /// Host-based service name to acquire credentials for.
    /// MIT Kerberos appends `@<local-hostname>` when no realm is specified.
    /// Default: `"HTTP"`.
    #[serde(default = "default_gssapi_service")]
    pub service_name: String,
}

fn default_gssapi_service() -> String {
    "HTTP".into()
}

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

fn default_crl_next_update_secs() -> u64 {
    86400
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

fn default_ldap_timeout_secs() -> u64 {
    10
}

fn default_srv_scheme() -> String {
    "ldap".to_owned()
}

fn default_account_scope() -> String {
    "server".to_owned()
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            // Explicitly "server" so that code checking account_scope works
            // correctly whether [server] is absent (Rust Default path) or
            // account_scope is absent within a present [server] section (serde
            // default_account_scope() path).  All other fields keep their Rust
            // defaults (false/0/""/vec![]/None) so that integration-test
            // fixtures using `..ServerConfig::default()` are not disrupted.
            account_scope: default_account_scope(),
            terms_of_service_url: None,
            website_url: None,
            caa_identities: vec![],
            external_account_required: false,
            order_expiry_secs: 0,
            authz_expiry_secs: 0,
            max_body_bytes: 0,
            http_validation_port: 0,
            http_validation_allow_private_ips: false,
            dns_persist_issuer_domains: vec![],
            dns_resolver_addr: None,
            dns_persist01_resolver_addr: None,
            dns_dot_server_name: None,
            ari_retry_after_secs: 0,
            ari_explanation_url: None,
            allow_subdomain_auth: false,
            star_min_lifetime_secs: None,
            star_max_duration_secs: None,
            star_allow_certificate_get: false,
            delegation_enabled: false,
            allow_certificate_get: false,
            profiles: std::collections::HashMap::new(),
            eab_keys: std::collections::HashMap::new(),
            tor_connectivity_enabled: false,
            validate_dnssec: false,
            trusted_proxies: vec![],
            gssapi: None,
            eab_master_secret: None,
            webui: None,
        }
    }
}

fn is_valid_ca_id(id: &str) -> bool {
    // max 64 chars: matches MariaDB VARCHAR(64) column for ca_id
    // lowercase-only so reserved-segment checks are unambiguous and Axum
    // route matching stays consistent (paths are case-sensitive).
    if id.is_empty() || id.len() > 64 {
        return false;
    }
    let mut chars = id.chars();
    match chars.next() {
        None => return false,
        Some(c) => {
            if !c.is_ascii_lowercase() && !c.is_ascii_digit() {
                return false;
            }
        }
    }
    chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-')
}

/// Deserialize either a `[ca]` single-table (backward compat) or a
/// `[[ca]]` array-of-tables into `Vec<CaConfig>`.
///
/// When the TOML source uses the old `[ca]` form the resulting single entry
/// gets `id = "default"` and `is_default = true` injected automatically so
/// the rest of the codebase can treat multi-CA and single-CA configs uniformly.
fn deserialize_ca_array<'de, D>(deserializer: D) -> Result<Vec<CaConfig>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::{MapAccess, SeqAccess, Visitor};
    use std::fmt;

    struct CaArrayVisitor;

    impl<'de> Visitor<'de> for CaArrayVisitor {
        type Value = Vec<CaConfig>;

        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("a [ca] table or [[ca]] array of tables")
        }

        fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Vec<CaConfig>, A::Error> {
            let mut cas = Vec::new();
            while let Some(ca) = seq.next_element::<CaConfig>()? {
                cas.push(ca);
            }
            Ok(cas)
        }

        fn visit_map<M: MapAccess<'de>>(self, map: M) -> Result<Vec<CaConfig>, M::Error> {
            let mut ca = CaConfig::deserialize(serde::de::value::MapAccessDeserializer::new(map))?;
            if ca.id.is_empty() {
                ca.id = "default".to_owned();
            }
            ca.is_default = true;
            Ok(vec![ca])
        }
    }

    deserializer.deserialize_any(CaArrayVisitor)
}

/// ACME path segments that are not valid CA identifiers.
///
/// CA IDs must not collide with these because both the legacy `/acme/{segment}`
/// and the per-CA `/acme/{ca_id}/{segment}` routes share the same URL tree.
/// This list is used in [`Config::validate`] and exported so the router can
/// enforce the same constraint without duplicating it.
pub const RESERVED_CA_IDS: &[&str] = &[
    // NOTE: "default" is intentionally excluded from this list because the legacy
    // single-[ca] compatibility mode auto-assigns id = "default" to the sole CA.
    // The constraint for "default" is enforced separately below: it may only be
    // used as the CA ID when is_default = true (so migration sentinel rows point
    // to the correct CA).
    "directory",
    "new-nonce",
    "new-account",
    "new-order",
    "new-authz",
    "revoke-cert",
    "key-change",
    "renewal-info",
    "cert",
    "order",
    "authz",
    "chall",
    "eab",
    "mtc",
    "account",
];

/// RFC 8823 S/MIME email-reply-00 challenge configuration.
///
/// When present and `enabled = true`, the server accepts `"email"` identifiers in
/// new-order requests and offers the `"email-reply-00"` challenge.
///
/// ```toml
/// [email_challenge]
/// enabled             = true
/// from_address        = "acme-validation@example.com"
/// send_script         = "/etc/akamu/send-email.sh"
/// # Generate with: openssl rand -hex 32
/// webhook_hmac_secret = "<replace-with-strong-secret>"
/// ```
///
/// The `send_script` is invoked for each challenge with these environment variables:
///
/// | Variable              | Value                                          |
/// |-----------------------|------------------------------------------------|
/// | `ACME_TO`             | Recipient email address (the identifier value) |
/// | `ACME_FROM`           | Server's From: address (`from_address`)        |
/// | `ACME_SUBJECT`        | `ACME: <base64url(token-part1)>` per RFC 8823  |
/// | `ACME_MESSAGE_ID`     | `<uuid@from-domain>` generated by the server   |
/// | `ACME_AUTO_SUBMITTED` | `auto-generated; type=acme`                    |
///
/// Exit code 0 = success; non-zero = challenge fails (client may retry).
///
/// Inbound client reply emails are received via the webhook endpoint at
/// `POST /acme/email-webhook`.  Callers authenticate with the header
/// `X-Akamu-Signature: sha256=<hex(HMAC-SHA256(body, webhook_hmac_secret))>`.
/// The secret must be at least 32 characters (256 bits) of random data.
#[derive(Deserialize, Clone)]
pub struct EmailChallengeConfig {
    /// Offer the email-reply-00 challenge type. Default: false.
    #[serde(default)]
    pub enabled: bool,
    /// `From:` address placed in challenge emails sent by `send_script`.
    #[serde(default)]
    pub from_address: String,
    /// Absolute path to the executable that sends the challenge email.
    #[serde(default)]
    pub send_script: String,
    /// Timeout in seconds for `send_script` execution (default 30).
    #[serde(default = "default_send_script_timeout_secs")]
    pub send_script_timeout_secs: u64,
    /// Shared secret (≥ 32 chars) for `POST /acme/email-webhook` HMAC authentication.
    #[serde(default)]
    pub webhook_hmac_secret: String,
}

fn default_send_script_timeout_secs() -> u64 {
    30
}

impl std::fmt::Debug for EmailChallengeConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EmailChallengeConfig")
            .field("enabled", &self.enabled)
            .field("from_address", &self.from_address)
            .field("send_script", &self.send_script)
            .field("webhook_hmac_secret", &"[REDACTED]")
            .finish()
    }
}

impl Config {
    pub fn from_file(path: &str) -> Result<Self, String> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("cannot read config file '{}': {}", path, e))?;
        let config: Self =
            toml::from_str(&content).map_err(|e| format!("config parse error: {}", e))?;
        config.validate()?;
        Ok(config)
    }

    /// Validate semantic constraints on the config that cannot be expressed with
    /// serde alone.  Called automatically by [`Self::from_file`].  Unit tests that
    /// construct configs via `toml::from_str` directly may call this manually.
    pub fn validate(&self) -> Result<(), String> {
        if self.cas.is_empty() {
            return Err("at least one [ca] or [[ca]] entry is required".into());
        }

        for ca in &self.cas {
            if ca.id.is_empty() {
                return Err("each [[ca]] entry must have a non-empty `id` field".into());
            }
            if !is_valid_ca_id(&ca.id) {
                return Err(format!(
                    "CA id {:?} must match ^[a-z0-9][a-z0-9_-]*$",
                    ca.id
                ));
            }
            if RESERVED_CA_IDS.contains(&ca.id.as_str()) {
                return Err(format!(
                    "CA id {:?} is a reserved ACME path segment and cannot be used",
                    ca.id
                ));
            }
            // "default" is the migration backfill sentinel; only the default CA may use it.
            // The legacy [ca] format auto-injects id="default" with is_default=true, which is correct.
            if ca.id == "default" && !ca.is_default {
                return Err(
                    "CA id \"default\" is the migration sentinel and may only be used on the \
                     default CA (is_default = true)"
                        .into(),
                );
            }
        }

        let mut seen = std::collections::HashSet::new();
        for ca in &self.cas {
            if !seen.insert(ca.id.as_str()) {
                return Err(format!("duplicate CA id {:?}", ca.id));
            }
        }

        if self.cas.len() > 1 {
            let default_count = self.cas.iter().filter(|c| c.is_default).count();
            if default_count == 0 {
                return Err(
                    "with multiple [[ca]] entries, exactly one must have `is_default = true`"
                        .into(),
                );
            }
            if default_count > 1 {
                return Err("at most one [[ca]] entry may have `is_default = true`".into());
            }
        }

        match self.server.account_scope.as_str() {
            "server" | "ca" => {}
            other => {
                return Err(format!(
                    "[server].account_scope must be \"server\" or \"ca\", got {:?}",
                    other
                ));
            }
        }

        // Validate that ca_ids in builtin profiles reference configured CAs.
        let known_ca_ids: std::collections::HashSet<&str> =
            self.cas.iter().map(|c| c.id.as_str()).collect();
        for (provider_name, provider) in &self.profiles.providers {
            if let ProviderConfig::Builtin(builtin) = provider {
                for (profile_name, profile) in &builtin.profiles {
                    for ca_id in &profile.ca_ids {
                        if !known_ca_ids.contains(ca_id.as_str()) {
                            return Err(format!(
                                "profile {profile_name:?} in provider {provider_name:?}: \
                                 ca_ids references unknown CA id {ca_id:?}"
                            ));
                        }
                    }
                }
            }
        }

        if let Some(du) = &self.delegation_upstream {
            const VALID_SOLVERS: &[&str] = &["dns-01", "http-01", "tls-alpn-01"];
            if du.directory_url.is_empty() {
                return Err("[delegation_upstream].directory_url must not be empty".into());
            }
            if !du.directory_url.starts_with("https://") {
                return Err(format!(
                    "[delegation_upstream].directory_url {:?} must use https://",
                    du.directory_url
                ));
            }
            if du.account_key_file.is_empty() {
                return Err("[delegation_upstream].account_key_file must not be empty".into());
            }
            if !std::path::Path::new(&du.account_key_file).is_absolute() {
                return Err(format!(
                    "[delegation_upstream].account_key_file {:?} must be an absolute path",
                    du.account_key_file
                ));
            }
            if !VALID_SOLVERS.contains(&du.challenge_solver.as_str()) {
                return Err(format!(
                    "[delegation_upstream].challenge_solver {:?} must be one of: {}",
                    du.challenge_solver,
                    VALID_SOLVERS.join(", ")
                ));
            }
            if du.poll_interval_secs == 0 {
                return Err("[delegation_upstream].poll_interval_secs must be at least 1".into());
            }
            if du.challenge_solver == "dns-01" && du.challenge_deploy_script.is_none() {
                return Err("[delegation_upstream].challenge_deploy_script is required \
                     when challenge_solver = \"dns-01\""
                    .into());
            }
            if let Some(ref script) = du.challenge_deploy_script {
                if !std::path::Path::new(script).is_absolute() {
                    return Err(format!(
                        "[delegation_upstream].challenge_deploy_script {script:?} must be an absolute path"
                    ));
                }
            }
            if let Some(ref script) = du.challenge_cleanup_script {
                if !std::path::Path::new(script).is_absolute() {
                    return Err(format!(
                        "[delegation_upstream].challenge_cleanup_script {script:?} must be an absolute path"
                    ));
                }
            }
        }

        if let Some(wu) = &self.server.webui {
            if let Some(ref dir) = wu.static_dir {
                if !std::path::Path::new(dir).is_absolute() {
                    return Err(format!(
                        "[server.webui].static_dir {dir:?} must be an absolute path"
                    ));
                }
            }
        }

        if let Some(ec) = &self.email_challenge {
            // Format/security checks run unconditionally whenever the section is present,
            // so a misconfigured disabled section is still caught at startup.
            if !ec.from_address.is_empty()
                && ec
                    .from_address
                    .split_once('@')
                    .is_none_or(|(l, d)| l.is_empty() || !d.contains('.'))
            {
                return Err(format!(
                    "[email_challenge].from_address {:?} is not a valid email address \
                     (expected local-part@domain.tld)",
                    ec.from_address
                ));
            }
            if !ec.send_script.is_empty() && !std::path::Path::new(&ec.send_script).is_absolute() {
                return Err(format!(
                    "[email_challenge].send_script {:?} must be an absolute path",
                    ec.send_script
                ));
            }
            if !ec.webhook_hmac_secret.is_empty() && ec.webhook_hmac_secret.len() < 32 {
                return Err(
                    "[email_challenge].webhook_hmac_secret must be at least 32 characters \
                     (generate with: openssl rand -hex 32)"
                        .into(),
                );
            }
            if ec.enabled {
                if ec.from_address.is_empty() {
                    return Err(
                        "[email_challenge].from_address must not be empty when enabled".into(),
                    );
                }
                if ec.send_script.is_empty() {
                    return Err(
                        "[email_challenge].send_script must not be empty when enabled".into(),
                    );
                }
                if ec.webhook_hmac_secret.is_empty() {
                    return Err(
                        "[email_challenge].webhook_hmac_secret must not be empty when enabled"
                            .into(),
                    );
                }
                if ec.send_script_timeout_secs == 0 {
                    return Err(
                        "[email_challenge].send_script_timeout_secs must be at least 1".into(),
                    );
                }
            }
        }

        if let Err(e) = self
            .mtc
            .hash_alg
            .parse::<synta_mtc::crypto::HashAlgorithm>()
        {
            return Err(format!("[mtc].hash_alg: {e}"));
        }

        let is_unix = self.listen_addr.starts_with("unix:") || self.listen_addr.starts_with('/');
        if self.tls.enabled && is_unix {
            return Err("TLS cannot be used with a Unix domain socket listener".to_owned());
        }

        Ok(())
    }

    /// Returns the default CA config: the one with `is_default = true`, or the
    /// only CA when there is exactly one `[[ca]]` entry.
    ///
    /// # Panics
    ///
    /// Panics if `cas` is empty or no CA is marked default in a multi-CA
    /// config.  [`Self::validate`] prevents both situations when loading from a file.
    pub fn default_ca(&self) -> &CaConfig {
        if self.cas.len() == 1 {
            return &self.cas[0];
        }
        self.cas
            .iter()
            .find(|c| c.is_default)
            .expect("validate() ensures exactly one default CA when multiple CAs are configured")
    }

    /// Returns the list of issuer domains used for dns-persist-01 TXT record
    /// validation and the `issuer-domain-names` challenge field.
    ///
    /// Uses `server.dns_persist_issuer_domains` when explicitly configured;
    /// otherwise falls back to the host portion of `base_url`.
    pub fn dns_persist_issuer_domains(&self) -> Vec<String> {
        if !self.server.dns_persist_issuer_domains.is_empty() {
            return self.server.dns_persist_issuer_domains.clone();
        }
        // Extract host from base_url: strip scheme, then take up to first '/' or ':'
        let without_scheme = self
            .base_url
            .strip_prefix("https://")
            .or_else(|| self.base_url.strip_prefix("http://"))
            .unwrap_or(&self.base_url);
        let host = without_scheme.split('/').next().unwrap_or(without_scheme);
        let host = host.split(':').next().unwrap_or(host);
        vec![host.to_string()]
    }
}

/// Serde deserialiser that accepts either a bare string or an array of strings.
///
/// Used for `dns_persist_issuer_domains` so that operators can write either:
/// ```toml
/// dns_persist_issuer_domains = "acme.example.com"
/// dns_persist_issuer_domains = ["acme.example.com", "acme.example.org"]
/// ```
fn deserialize_string_or_vec<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::{self, Visitor};
    use std::fmt;

    struct StringOrVec;

    impl<'de> Visitor<'de> for StringOrVec {
        type Value = Vec<String>;

        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("a string or array of strings")
        }

        fn visit_str<E: de::Error>(self, v: &str) -> Result<Vec<String>, E> {
            Ok(vec![v.to_owned()])
        }

        fn visit_seq<A: de::SeqAccess<'de>>(self, mut seq: A) -> Result<Vec<String>, A::Error> {
            let mut out = Vec::new();
            while let Some(s) = seq.next_element::<String>()? {
                out.push(s);
            }
            Ok(out)
        }
    }

    deserializer.deserialize_any(StringOrVec)
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
        let ca = cfg.default_ca();
        assert_eq!(ca.key_file, "/tmp/ca.key");
        assert_eq!(ca.cert_file, "/tmp/ca.crt");
        assert_eq!(cfg.mtc.log_path, "/tmp/mtc.log");
        assert!(!cfg.mtc.enabled);
    }

    #[test]
    fn legacy_ca_table_gets_default_id_and_is_default() {
        let cfg: Config = toml::from_str(minimal_toml()).unwrap();
        assert_eq!(cfg.cas.len(), 1);
        assert_eq!(cfg.cas[0].id, "default");
        assert!(cfg.cas[0].is_default);
    }

    #[test]
    fn config_ca_defaults_applied() {
        let cfg: Config = toml::from_str(minimal_toml()).unwrap();
        let ca = cfg.default_ca();
        assert_eq!(ca.key_type, "ec:P-256");
        assert_eq!(ca.hash_alg, "sha256");
        assert_eq!(ca.validity_days, 90);
        assert_eq!(ca.common_name, "ACME Server CA");
        assert_eq!(ca.organization, "ACME Server");
        assert_eq!(ca.ca_validity_years, 10);
        assert!(ca.crl_url.is_none());
        assert!(ca.ocsp_url.is_none());
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
        assert!(cfg.server.dns_persist_issuer_domains.is_empty());
        assert_eq!(cfg.server.ari_retry_after_secs, 21600);
    }

    #[test]
    fn dns_persist_issuer_domains_uses_explicit_string() {
        let toml = format!(
            "{}\n[server]\ndns_persist_issuer_domains = \"ca.example.org\"\n",
            minimal_toml()
        );
        let cfg: Config = toml::from_str(&toml).unwrap();
        assert_eq!(cfg.dns_persist_issuer_domains(), vec!["ca.example.org"]);
    }

    #[test]
    fn dns_persist_issuer_domains_accepts_array() {
        let toml = format!(
            "{}\n[server]\ndns_persist_issuer_domains = [\"ca.example.org\", \"ca2.example.org\"]\n",
            minimal_toml()
        );
        let cfg: Config = toml::from_str(&toml).unwrap();
        assert_eq!(
            cfg.dns_persist_issuer_domains(),
            vec!["ca.example.org", "ca2.example.org"]
        );
    }

    #[test]
    fn dns_persist_issuer_domains_falls_back_to_base_url_https() {
        let cfg: Config = toml::from_str(minimal_toml()).unwrap();
        // base_url = "https://acme.example.com" → host = "acme.example.com"
        assert_eq!(cfg.dns_persist_issuer_domains(), vec!["acme.example.com"]);
    }

    #[test]
    fn dns_persist_issuer_domains_strips_port_from_base_url() {
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
        assert_eq!(cfg.dns_persist_issuer_domains(), vec!["acme.example.com"]);
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
        let ca = cfg.default_ca();
        assert_eq!(ca.key_type, "rsa:4096");
        assert_eq!(ca.hash_alg, "sha512");
        assert_eq!(ca.validity_days, 365);
        assert_eq!(ca.crl_url.as_deref(), Some("http://crl.example.org/ca.crl"));
        assert_eq!(ca.ocsp_url.as_deref(), Some("http://ocsp.example.org"));
        assert_eq!(ca.ca_validity_years, 5);
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

    #[test]
    fn trusted_proxies_absent_defaults_to_empty() {
        let cfg: Config = toml::from_str(minimal_toml()).unwrap();
        assert!(cfg.server.trusted_proxies.is_empty());
    }

    #[test]
    fn trusted_proxies_parses_cidr_list() {
        let toml = format!(
            "{}\n[server]\ntrusted_proxies = [\"127.0.0.1/32\", \"::1/128\", \"10.0.0.0/8\"]\n",
            minimal_toml()
        );
        let cfg: Config = toml::from_str(&toml).unwrap();
        assert_eq!(cfg.server.trusted_proxies.len(), 3);
        let strs: Vec<String> = cfg
            .server
            .trusted_proxies
            .iter()
            .map(|n| n.to_string())
            .collect();
        assert!(strs.contains(&"127.0.0.1/32".to_owned()));
        assert!(strs.contains(&"::1/128".to_owned()));
        assert!(strs.contains(&"10.0.0.0/8".to_owned()));
    }

    #[test]
    fn trusted_proxies_invalid_cidr_returns_error() {
        let toml = format!(
            "{}\n[server]\ntrusted_proxies = [\"not-a-cidr\"]\n",
            minimal_toml()
        );
        assert!(toml::from_str::<Config>(&toml).is_err());
    }

    #[test]
    fn gssapi_absent_is_none() {
        let cfg: Config = toml::from_str(minimal_toml()).unwrap();
        assert!(cfg.server.gssapi.is_none());
    }

    #[test]
    fn gssapi_section_parses_explicit_values() {
        let toml = format!(
            "{}\n[server.gssapi]\nkeytab_file = \"/etc/akamu/http.keytab\"\nservice_name = \"HTTP@host.example.com\"\n",
            minimal_toml()
        );
        let cfg: Config = toml::from_str(&toml).unwrap();
        let gcfg = cfg.server.gssapi.expect("gssapi should be Some");
        assert_eq!(gcfg.keytab_file, "/etc/akamu/http.keytab");
        assert_eq!(gcfg.service_name, "HTTP@host.example.com");
    }

    #[test]
    fn eab_master_secret_absent_is_none() {
        let cfg: Config = toml::from_str(minimal_toml()).unwrap();
        assert!(cfg.server.eab_master_secret.is_none());
    }

    #[test]
    fn eab_master_secret_present_parses() {
        let toml = format!(
            "{}\n[server]\neab_master_secret = \"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"\n",
            minimal_toml()
        );
        let cfg: Config = toml::from_str(&toml).unwrap();
        assert!(cfg.server.eab_master_secret.is_some());
    }

    #[test]
    fn gssapi_service_name_defaults_to_http() {
        let toml = format!(
            "{}\n[server.gssapi]\nkeytab_file = \"/etc/akamu/http.keytab\"\n",
            minimal_toml()
        );
        let cfg: Config = toml::from_str(&toml).unwrap();
        let gcfg = cfg.server.gssapi.expect("gssapi should be Some");
        assert_eq!(gcfg.service_name, "HTTP");
    }

    // ── AdminConfig tests ──────────────────────────────────────────────────────

    fn admin_toml_base() -> String {
        format!(
            r#"{}
[admin]
"#,
            minimal_toml()
        )
    }

    #[test]
    fn admin_config_defaults_parse() {
        let cfg: Config = toml::from_str(&admin_toml_base()).unwrap();
        let admin = cfg.admin.expect("admin should be Some");
        assert!(admin.gssapi.is_none());
        assert_eq!(admin.session_ttl_secs, 3600);
        assert_eq!(admin.audit_overflow, "drop_oldest");
        assert_eq!(admin.audit_alarm_threshold, 10);
        assert_eq!(admin.audit_alarm_action, "syslog");
        assert!(admin.audit_max_rows.is_none());
    }

    #[test]
    fn admin_config_validate_ok_with_gssapi() {
        let toml = format!(
            r#"{}
[admin]

[admin.gssapi]
keytab_file  = "/etc/akamu/http.keytab"
service_name = "HTTP"
"#,
            minimal_toml()
        );
        let cfg: Config = toml::from_str(&toml).unwrap();
        assert!(cfg.admin.unwrap().validate().is_ok());
    }

    #[test]
    fn admin_config_validate_ok_minimal() {
        let cfg: Config = toml::from_str(&admin_toml_base()).unwrap();
        assert!(cfg.admin.unwrap().validate().is_ok());
    }

    #[test]
    fn admin_config_validate_bad_overflow() {
        let toml = format!(
            r#"{}
[admin]
audit_overflow = "delete"
"#,
            minimal_toml()
        );
        let cfg: Config = toml::from_str(&toml).unwrap();
        let err = cfg.admin.unwrap().validate().unwrap_err();
        assert!(err.contains("audit_overflow"), "msg: {err}");
    }

    #[test]
    fn admin_config_audit_policy_drop_oldest() {
        let cfg: Config = toml::from_str(&admin_toml_base()).unwrap();
        let policy = crate::audit::AuditPolicy::from_admin_config(&cfg.admin.unwrap());
        assert!(policy.max_rows.is_none());
        assert_eq!(policy.overflow, crate::audit::OverflowPolicy::DropOldest);
        assert_eq!(policy.alarm_threshold, 10);
        assert_eq!(policy.alarm_action, crate::audit::AlarmAction::Syslog);
    }

    #[test]
    fn admin_config_audit_policy_halt() {
        let toml = format!(
            r#"{}
[admin]
audit_max_rows        = 500000
audit_overflow        = "halt"
audit_alarm_threshold = 5
audit_alarm_action    = "halt"
"#,
            minimal_toml()
        );
        let cfg: Config = toml::from_str(&toml).unwrap();
        let policy = crate::audit::AuditPolicy::from_admin_config(&cfg.admin.unwrap());
        assert_eq!(policy.max_rows, Some(500_000));
        assert_eq!(policy.overflow, crate::audit::OverflowPolicy::Halt);
        assert_eq!(policy.alarm_threshold, 5);
        assert_eq!(policy.alarm_action, crate::audit::AlarmAction::Halt);
    }

    // ── Multi-CA config tests ──────────────────────────────────────────────────

    #[test]
    fn multi_ca_array_parses() {
        let toml = r#"
listen_addr = "127.0.0.1:8080"
base_url = "https://acme.example.com"

[database]
url = "sqlite::memory:"

[[ca]]
id = "rsa"
is_default = true
key_file = "/etc/akamu/rsa.key"
cert_file = "/etc/akamu/rsa.crt"

[[ca]]
id = "ec"
key_file = "/etc/akamu/ec.key"
cert_file = "/etc/akamu/ec.crt"

[mtc]
log_path = "/dev/null"
enabled = false
"#;
        let cfg: Config = toml::from_str(toml).unwrap();
        // Validate must also pass (tests the full parse→validate pipeline).
        cfg.validate().unwrap();
        assert_eq!(cfg.cas.len(), 2);
        assert_eq!(cfg.cas[0].id, "rsa");
        assert!(cfg.cas[0].is_default);
        assert_eq!(cfg.cas[1].id, "ec");
        assert!(!cfg.cas[1].is_default);
        assert_eq!(cfg.default_ca().id, "rsa");
    }

    #[test]
    fn default_ca_returns_non_first_default() {
        // Verify that default_ca() uses Iterator::find on is_default, not cas[0].
        let toml = r#"
listen_addr = "127.0.0.1:8080"
base_url = "https://acme.example.com"
[database]
url = "sqlite::memory:"
[[ca]]
id = "ec"
key_file = "/etc/akamu/ec.key"
cert_file = "/etc/akamu/ec.crt"
[[ca]]
id = "rsa"
is_default = true
key_file = "/etc/akamu/rsa.key"
cert_file = "/etc/akamu/rsa.crt"
[mtc]
log_path = "/dev/null"
enabled = false
"#;
        let cfg: Config = toml::from_str(toml).unwrap();
        cfg.validate().unwrap();
        assert_eq!(cfg.default_ca().id, "rsa");
    }

    #[test]
    fn multi_ca_validate_rejects_reserved_id_case_insensitive() {
        // "Directory" (mixed case) must be rejected — CA IDs are lowercase-only
        // so mixed-case collisions with reserved path segments cannot happen.
        let toml = r#"
listen_addr = "127.0.0.1:8080"
base_url = "https://acme.example.com"
[database]
url = "sqlite::memory:"
[[ca]]
id = "Directory"
is_default = true
key_file = "/etc/akamu/ca.key"
cert_file = "/etc/akamu/ca.crt"
[mtc]
log_path = "/dev/null"
enabled = false
"#;
        let cfg: Config = toml::from_str(toml).unwrap();
        let err = cfg.validate().unwrap_err();
        // Mixed-case IDs are now rejected at the format check (lowercase-only)
        // before the reserved-segment check is reached.
        assert!(
            err.contains("reserved") || err.contains("must match"),
            "err: {err}"
        );
    }

    #[test]
    fn multi_ca_validate_requires_default() {
        let toml = r#"
listen_addr = "127.0.0.1:8080"
base_url = "https://acme.example.com"
[database]
url = "sqlite::memory:"
[[ca]]
id = "rsa"
key_file = "/etc/akamu/rsa.key"
cert_file = "/etc/akamu/rsa.crt"
[[ca]]
id = "ec"
key_file = "/etc/akamu/ec.key"
cert_file = "/etc/akamu/ec.crt"
[mtc]
log_path = "/dev/null"
enabled = false
"#;
        let cfg: Config = toml::from_str(toml).unwrap();
        let err = cfg.validate().unwrap_err();
        assert!(err.contains("is_default"), "err: {err}");
    }

    #[test]
    fn multi_ca_validate_rejects_duplicate_id() {
        let toml = r#"
listen_addr = "127.0.0.1:8080"
base_url = "https://acme.example.com"
[database]
url = "sqlite::memory:"
[[ca]]
id = "rsa"
is_default = true
key_file = "/etc/akamu/rsa.key"
cert_file = "/etc/akamu/rsa.crt"
[[ca]]
id = "rsa"
key_file = "/etc/akamu/rsa2.key"
cert_file = "/etc/akamu/rsa2.crt"
[mtc]
log_path = "/dev/null"
enabled = false
"#;
        let cfg: Config = toml::from_str(toml).unwrap();
        let err = cfg.validate().unwrap_err();
        assert!(err.contains("duplicate"), "err: {err}");
    }

    #[test]
    fn multi_ca_validate_rejects_reserved_id() {
        let toml = r#"
listen_addr = "127.0.0.1:8080"
base_url = "https://acme.example.com"
[database]
url = "sqlite::memory:"
[[ca]]
id = "directory"
is_default = true
key_file = "/etc/akamu/ca.key"
cert_file = "/etc/akamu/ca.crt"
[mtc]
log_path = "/dev/null"
enabled = false
"#;
        let cfg: Config = toml::from_str(toml).unwrap();
        let err = cfg.validate().unwrap_err();
        assert!(err.contains("reserved"), "err: {err}");
    }

    #[test]
    fn multi_ca_validate_rejects_invalid_id_chars() {
        let toml = r#"
listen_addr = "127.0.0.1:8080"
base_url = "https://acme.example.com"
[database]
url = "sqlite::memory:"
[[ca]]
id = "bad id!"
is_default = true
key_file = "/etc/akamu/ca.key"
cert_file = "/etc/akamu/ca.crt"
[mtc]
log_path = "/dev/null"
enabled = false
"#;
        let cfg: Config = toml::from_str(toml).unwrap();
        let err = cfg.validate().unwrap_err();
        assert!(err.contains("must match"), "err: {err}");
    }

    #[test]
    fn multi_ca_validate_rejects_two_defaults() {
        let toml = r#"
listen_addr = "127.0.0.1:8080"
base_url = "https://acme.example.com"
[database]
url = "sqlite::memory:"
[[ca]]
id = "rsa"
is_default = true
key_file = "/etc/akamu/rsa.key"
cert_file = "/etc/akamu/rsa.crt"
[[ca]]
id = "ec"
is_default = true
key_file = "/etc/akamu/ec.key"
cert_file = "/etc/akamu/ec.crt"
[mtc]
log_path = "/dev/null"
enabled = false
"#;
        let cfg: Config = toml::from_str(toml).unwrap();
        let err = cfg.validate().unwrap_err();
        assert!(err.contains("at most one"), "err: {err}");
    }

    #[test]
    fn account_scope_default_is_server() {
        // When [server] is absent entirely, ServerConfig::Default gives "server".
        let cfg: Config = toml::from_str(minimal_toml()).unwrap();
        assert_eq!(cfg.server.account_scope, "server");

        // When [server] is present but account_scope is absent, serde's
        // default_account_scope() function also gives "server".
        let toml_with_server = format!("{}\n[server]\n", minimal_toml());
        let cfg2: Config = toml::from_str(&toml_with_server).unwrap();
        assert_eq!(cfg2.server.account_scope, "server");
    }

    #[test]
    fn account_scope_ca_parses() {
        let toml = format!("{}\n[server]\naccount_scope = \"ca\"\n", minimal_toml());
        let cfg: Config = toml::from_str(&toml).unwrap();
        assert_eq!(cfg.server.account_scope, "ca");
    }

    #[test]
    fn account_scope_invalid_fails_validate() {
        let toml = format!(
            "{}\n[server]\naccount_scope = \"invalid\"\n",
            minimal_toml()
        );
        let cfg: Config = toml::from_str(&toml).unwrap();
        let err = cfg.validate().unwrap_err();
        assert!(err.contains("account_scope"), "err: {err}");
    }

    #[test]
    fn builtin_profile_ca_ids_parses() {
        let toml = r#"
listen_addr = "127.0.0.1:8080"
base_url = "https://acme.example.com"
[database]
url = "sqlite::memory:"
[ca]
key_file = "/tmp/ca.key"
cert_file = "/tmp/ca.crt"
[mtc]
log_path = "/dev/null"
enabled = false
[profiles.providers.local]
type = "builtin"
[profiles.providers.local.profiles.tlsserver]
description = "TLS server"
ca_ids = ["rsa", "ec"]
"#;
        let cfg: Config = toml::from_str(toml).unwrap();
        let builtin = match cfg.profiles.providers.get("local").expect("local provider") {
            ProviderConfig::Builtin(b) => b,
            _ => panic!("expected builtin"),
        };
        let profile = builtin.profiles.get("tlsserver").expect("tlsserver");
        assert_eq!(profile.ca_ids, vec!["rsa", "ec"]);
    }

    #[test]
    fn multi_ca_caa_identities_per_ca() {
        let toml = r#"
listen_addr = "127.0.0.1:8080"
base_url = "https://acme.example.com"
[database]
url = "sqlite::memory:"
[[ca]]
id = "rsa"
is_default = true
key_file = "/etc/akamu/rsa.key"
cert_file = "/etc/akamu/rsa.crt"
caa_identities = ["rsa.example.com"]
[[ca]]
id = "ec"
key_file = "/etc/akamu/ec.key"
cert_file = "/etc/akamu/ec.crt"
[mtc]
log_path = "/dev/null"
enabled = false
"#;
        let cfg: Config = toml::from_str(toml).unwrap();
        assert_eq!(cfg.cas[0].caa_identities, vec!["rsa.example.com"]);
        assert!(cfg.cas[1].caa_identities.is_empty());
    }

    fn minimal_toml_with_mtc(hash_alg: &str) -> String {
        format!(
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
hash_alg = "{hash_alg}"
"#
        )
    }

    #[test]
    fn mtc_hash_alg_invalid_fails_validate() {
        let cfg: Config = toml::from_str(&minimal_toml_with_mtc("md5")).unwrap();
        let err = cfg.validate().unwrap_err();
        assert!(err.contains("hash_alg"), "err: {err}");
        assert!(err.contains("md5"), "err: {err}");
    }

    #[test]
    fn mtc_hash_alg_valid_passes_validate() {
        for alg in [
            "sha256", "sha384", "sha512", "sha3-256", "sha3-384", "sha3-512",
        ] {
            let cfg: Config = toml::from_str(&minimal_toml_with_mtc(alg)).unwrap();
            cfg.validate()
                .unwrap_or_else(|e| panic!("hash_alg={alg} rejected: {e}"));
        }
    }
}
