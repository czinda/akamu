use serde::Deserialize;

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
    /// Mutually exclusive with `bootstrap_operator_pkcs12_file`.
    pub bootstrap_operator_cert_file: Option<String>,
    /// PEM file for the bootstrap Administrator operator's client private key.
    /// Must be set alongside `bootstrap_operator_cert_file`.
    /// Mutually exclusive with `bootstrap_operator_pkcs12_file`.
    pub bootstrap_operator_key_file: Option<String>,
    /// PKCS#12 / PFX file for the bootstrap Administrator operator's client
    /// certificate and private key.  When set and the file is absent and the
    /// operators table is empty, a client certificate and key are generated,
    /// bundled into a PKCS#12 file, and the operator is registered.
    /// Mutually exclusive with `bootstrap_operator_cert_file` /
    /// `bootstrap_operator_key_file`.
    pub bootstrap_operator_pkcs12_file: Option<String>,
    /// Password for the PKCS#12 bundle written by `bootstrap_operator_pkcs12_file`.
    /// Default: `""` (empty password — the key is still encrypted with PBES2/AES-256-CBC;
    /// leave the password field blank or press Enter when tools prompt for it).
    #[serde(default)]
    pub bootstrap_operator_pkcs12_password: String,
    /// Name recorded in the database for the auto-provisioned bootstrap operator.
    /// Default: `"admin"`.
    #[serde(default = "default_admin_bootstrap_operator_name")]
    pub bootstrap_operator_name: String,
    /// Kerberos principal for the GSSAPI bootstrap Administrator operator
    /// (e.g. `"admin@REALM"`).  When set and no cert bootstrap is configured,
    /// an Administrator row with this principal is inserted at startup (if the
    /// operators table is empty) so that the first GSSAPI login succeeds without
    /// a manual `akamuctl operator add`.
    ///
    /// When set alongside `bootstrap_operator_pkcs12_file` or
    /// `bootstrap_operator_cert_file` / `bootstrap_operator_key_file`, the
    /// principal is stored on the same bootstrapped operator row so that the
    /// operator can authenticate via either mTLS or GSSAPI.
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
        if self.bootstrap_operator_pkcs12_file.is_some()
            && self.bootstrap_operator_cert_file.is_some()
        {
            return Err(
                "[admin] bootstrap_operator_pkcs12_file is mutually exclusive with \
                 bootstrap_operator_cert_file / bootstrap_operator_key_file; \
                 choose one bootstrap output format"
                    .into(),
            );
        }
        Ok(())
    }
}

/// GSSAPI/Kerberos configuration for the admin interface.
#[derive(Debug, Deserialize, Clone)]
pub struct AdminGssapiConfig {
    /// Path to the HTTP service keytab (e.g. `/etc/akamu/http.keytab`).
    /// Required when `gssproxy = false` (the default).  Omit when `gssproxy = true`.
    #[serde(default)]
    pub keytab_file: Option<String>,
    /// When `true`, GSSAPI credential acquisition is delegated to gssproxy.
    /// The process must have a matching entry in `/etc/gssproxy/conf.d/`.
    /// `GSS_USE_PROXY=yes` is set in the environment before the first GSSAPI call.
    /// Default: `false`.
    #[serde(default)]
    pub gssproxy: bool,
    /// Host-based service name.  MIT Kerberos appends `@<hostname>` automatically.
    /// Default: `"HTTP"`.
    #[serde(default = "default_gssapi_service")]
    pub service_name: String,
}

pub(super) fn default_gssapi_service() -> String {
    "HTTP".into()
}
