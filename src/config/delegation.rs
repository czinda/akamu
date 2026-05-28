use serde::Deserialize;

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
