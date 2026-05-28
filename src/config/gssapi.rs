use serde::Deserialize;

use super::admin::default_gssapi_service;

/// Standalone GSSAPI/SPNEGO configuration for Akamu acting as its own KDC client.
#[derive(Debug, Deserialize)]
pub struct GssapiConfig {
    /// Path to the HTTP service keytab (e.g. `/etc/akamu/http.keytab`).
    /// Required when `gssproxy = false` (the default).  Omit when `gssproxy = true`.
    #[serde(default)]
    pub keytab_file: Option<String>,
    /// When `true`, GSSAPI credential acquisition is delegated to gssproxy.
    /// The process must have a matching entry in `/etc/gssproxy/conf.d/`.
    /// No direct keytab access is needed.  `GSS_USE_PROXY=yes` is set in the
    /// environment before the first GSSAPI call.  Default: `false`.
    #[serde(default)]
    pub gssproxy: bool,
    /// Host-based service name to acquire credentials for.
    /// MIT Kerberos appends `@<local-hostname>` when no realm is specified.
    /// Default: `"HTTP"`.
    #[serde(default = "default_gssapi_service")]
    pub service_name: String,
}
