use std::collections::HashMap;

use serde::Deserialize;

use super::ldap::LdapConfig;

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
    /// KPN SAN templates expanded against the order's DNS SANs at issuance.
    /// Syntax: `"HTTP/{dns}@REALM"` → NT-SRV-HST(3); `"{dns}@REALM"` →
    /// NT-PRINCIPAL(1).  Static templates (no `{dns}`) are injected once.
    #[serde(default)]
    pub kpn_san_templates: Vec<String>,
    /// MS-UPN SAN template (OID 1.3.6.1.4.1.311.20.2.3).  `{dns}` is replaced
    /// with the first DNS SAN from the CSR, or use a literal UPN for a static value.
    #[serde(default)]
    pub ms_upn_san_template: Option<String>,
    /// When `true`, inject the account's stored Kerberos principal
    /// (copied from the EAB `bound_principal` at registration) as a
    /// KRB5PrincipalName OtherName SAN.
    #[serde(default)]
    pub inject_account_kpn: bool,
    /// HTTPS or Unix-socket URLs of JWKS endpoints trusted for `kid`-signed
    /// authority tokens (RFC 9447 tkauth-01).  Only meaningful when `[tkauth]`
    /// is enabled.  When empty, `kid`-signed tokens are rejected for this profile.
    /// Unix-socket form: `"http+unix://%2Frun%2Fekishib%2Fekishib.sock/jwks"`.
    #[serde(default)]
    pub trust_jwks_urls: Vec<String>,
    /// Dogtag enrollment profile ID override.  When set, overrides the default
    /// `profile_id` in the `[ca.signer]` Dogtag configuration for orders that
    /// use this ACME profile.  Ignored for local-signing CAs.
    #[serde(default)]
    pub dogtag_profile_id: Option<String>,
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
