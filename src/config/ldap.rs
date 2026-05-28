use serde::Deserialize;

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

fn default_ldap_timeout_secs() -> u64 {
    10
}

fn default_srv_scheme() -> String {
    "ldap".to_owned()
}
