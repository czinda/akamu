//! ACME protocol types (RFC 8555).

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// An ACME identifier (e.g. `{"type": "dns", "value": "example.com"}`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Identifier {
    pub r#type: String,
    pub value: String,
}

impl Identifier {
    pub fn dns(value: impl Into<String>) -> Self {
        Identifier {
            r#type: "dns".into(),
            value: value.into(),
        }
    }

    pub fn ip(addr: impl Into<String>) -> Self {
        Identifier {
            r#type: "ip".into(),
            value: addr.into(),
        }
    }

    pub fn onion(addr: impl Into<String>) -> Self {
        Identifier {
            r#type: "onion".into(),
            value: addr.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifier_dns() {
        let id = Identifier::dns("example.com");
        assert_eq!(id.r#type, "dns");
        assert_eq!(id.value, "example.com");
    }

    #[test]
    fn identifier_ip() {
        let id = Identifier::ip("192.0.2.1");
        assert_eq!(id.r#type, "ip");
        assert_eq!(id.value, "192.0.2.1");
    }

    #[test]
    fn identifier_ip_v6() {
        let id = Identifier::ip("2001:db8::1");
        assert_eq!(id.r#type, "ip");
        assert_eq!(id.value, "2001:db8::1");
    }

    #[test]
    fn identifier_onion() {
        let id = Identifier::onion("example.onion");
        assert_eq!(id.r#type, "onion");
        assert_eq!(id.value, "example.onion");
    }
}

/// ACME order object (RFC 8555 §7.1.3).
#[derive(Debug, Clone, Deserialize)]
pub struct Order {
    pub status: String,
    pub url: String,
    pub finalize: String,
    pub authorizations: Vec<String>,
    #[serde(default)]
    pub certificate: Option<String>,
    #[serde(default)]
    pub identifiers: Vec<Identifier>,
    /// Profile echoed back by the server (draft-ietf-acme-profiles-01).
    #[serde(default)]
    pub profile: Option<String>,
    /// RFC 9115 §2.3.2: delegation URL echoed by the server.
    #[serde(default)]
    pub delegation: Option<String>,
}

/// ACME authorization object (RFC 8555 §7.1.4).
#[derive(Debug, Clone, Deserialize)]
pub struct Authorization {
    pub status: String,
    pub identifier: Identifier,
    pub challenges: Vec<Challenge>,
}

impl Authorization {
    pub fn find_challenge(&self, r#type: &str) -> Option<&Challenge> {
        self.challenges.iter().find(|c| c.r#type == r#type)
    }
}

/// ACME challenge object (RFC 8555 §7.1.5).
#[derive(Debug, Clone, Deserialize)]
pub struct Challenge {
    pub r#type: String,
    pub url: String,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub token: Option<String>,
    /// Issuer domain names sent by the server for `dns-persist-01` challenges.
    #[serde(default, rename = "issuer-domain-names")]
    pub issuer_domain_names: Option<Vec<String>>,
    /// Token type for `tkauth-01` challenges (RFC 9447).
    #[serde(default, rename = "tkauth-type")]
    pub tkauth_type: Option<String>,
    /// Token Authority URL hint for `tkauth-01` challenges (RFC 9447).
    #[serde(default, rename = "token-authority")]
    pub token_authority: Option<String>,
    /// Error object returned when challenge validation fails (RFC 8555 §7.1.5).
    #[serde(default)]
    pub error: Option<serde_json::Value>,
}

/// Renewal information from the ACME server (RFC 9773).
#[derive(Debug, Clone)]
pub struct RenewalInfo {
    /// Start of the suggested renewal window (RFC 3339 timestamp string).
    pub window_start: String,
    /// End of the suggested renewal window (RFC 3339 timestamp string).
    pub window_end: String,
    /// Value of the `Retry-After` response header, in seconds (if present).
    pub retry_after_secs: Option<u64>,
}

/// Parameters for a STAR (Short-Term, Automatically Renewed) order (RFC 8739 §3.1).
///
/// At minimum, `end_date` and `lifetime_secs` must be provided.
pub struct StarOrderParams<'a> {
    /// Identifiers to certify (same as a normal order).
    pub identifiers: &'a [Identifier],
    /// The latest acceptable `notAfter` of the last automatically renewed certificate
    /// (RFC 8739 §3.1, RFC 3339 string).  The server MUST NOT issue certificates
    /// whose `notAfter` exceeds this value.
    pub end_date: &'a str,
    /// Validity period of each certificate, in seconds.
    pub lifetime_secs: u64,
    /// Earliest `notBefore` of the first certificate (RFC 3339 string). Defaults to
    /// when the order becomes ready when absent.
    pub start_date: Option<&'a str>,
    /// Pre-date each certificate's `notBefore` by this many seconds for clock-skew
    /// tolerance (RFC 8739 §3.1.1). Default: 0.
    pub lifetime_adjust_secs: u64,
    /// When `true`, the rolling `star-certificate` URL may be fetched with an
    /// unauthenticated GET (RFC 8739 §3.1.3).
    pub allow_certificate_get: bool,
}

/// A STAR order response.  Returned by `AcmeClient::star_order()` after finalization.
#[derive(Debug, Clone)]
pub struct StarOrder {
    /// URL of the order object.
    pub url: String,
    /// Status of the order (`"pending"`, `"ready"`, `"valid"`, `"canceled"`).
    pub status: String,
    /// Finalize URL (for submitting the CSR).
    pub finalize: String,
    /// Authorization URLs.
    pub authorizations: Vec<String>,
    /// Rolling certificate URL (present when status is `"valid"`).
    pub star_certificate: Option<String>,
}

/// Options for account registration; passed to `AcmeClient::new_account()`.
pub struct AccountOptions<'a> {
    /// Contact URIs (e.g. `"mailto:admin@example.com"`).
    pub contacts: &'a [&'a str],
    /// Whether the client agrees to the server's terms of service.
    pub agree_tos: bool,
    /// External Account Binding options; required when the server mandates EAB.
    pub eab: Option<EabOptions<'a>>,
}

/// External Account Binding credentials (RFC 8555 §7.3.4).
pub struct EabOptions<'a> {
    /// EAB key identifier as provided by the CA.
    pub kid: &'a str,
    /// Raw HMAC key bytes (caller must base64url-decode from config/flag first).
    pub hmac_key: &'a [u8],
    /// HMAC algorithm: `"HS256"` (default), `"HS384"`, or `"HS512"`.
    pub alg: &'a str,
}

/// Persistent renewal configuration written as a TOML sidecar alongside the
/// certificate chain (e.g. `<cert>.renewal.toml`).
///
/// Every field that has a sensible default is annotated with `#[serde(default
/// = "...")]` so that existing configs with fewer fields remain forward-compatible.
#[derive(Clone, Serialize, Deserialize)]
pub struct RenewalConfig {
    /// ACME directory URL (base URL or full per-CA directory URL).
    pub server: String,
    /// CA identifier for akamu multi-CA servers.
    ///
    /// When set, the directory URL is derived as `{server}/acme/{ca}/directory`.
    /// Ignored when `server` already ends in `/directory`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ca: Option<String>,
    /// Identifiers (domains or IPs) to certify.
    pub domains: Vec<Identifier>,
    /// Path to the account private key PEM.
    pub account_key: PathBuf,
    /// ACME account URL (kid).  When present, the existing account is used
    /// instead of attempting registration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account_url: Option<String>,
    /// Key type for the account key (`"ec:P-256"`, `"rsa:2048"`, etc.).
    #[serde(default = "defaults::key_type")]
    pub account_key_type: String,
    /// Where the certificate chain is written.
    pub cert_path: PathBuf,
    /// Where the certificate private key is written.
    pub cert_key_path: PathBuf,
    /// Key type for the certificate key.
    #[serde(default = "defaults::key_type")]
    pub cert_key_type: String,
    /// ACME challenge type (`"http-01"`, `"dns-01"`, `"dns-persist-01"`,
    /// `"tls-alpn-01"`).
    #[serde(default = "defaults::challenge_type")]
    pub challenge_type: String,
    /// HTTP port for `http-01` challenges.
    #[serde(default = "defaults::http_port")]
    pub http_port: u16,
    /// TLS port for `tls-alpn-01` challenges.
    #[serde(default = "defaults::tls_port")]
    pub tls_port: u16,
    /// Path to the onion service private key (tor-only orders).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub onion_key: Option<PathBuf>,
    /// Poll timeout in seconds when waiting for challenge validation.
    #[serde(default = "defaults::poll_timeout")]
    pub poll_timeout: u64,
    /// Contact URIs registered with the account (e.g. `"mailto:admin@example.com"`).
    #[serde(default)]
    pub contacts: Vec<String>,
    /// EAB key identifier.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub eab_kid: Option<String>,
    /// EAB HMAC key (base64url).  Not serialized — operator must re-supply on renewal.
    #[serde(default, skip_serializing)]
    pub eab_key: Option<String>,
    /// EAB HMAC algorithm.
    #[serde(default = "defaults::eab_alg")]
    pub eab_alg: String,
    /// Path to a Kerberos keytab for GSSAPI-authenticated EAB fetch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gssapi_keytab: Option<PathBuf>,
    /// Hook script for DNS TXT record management.  Invoked as
    /// `<dns_hook> add|remove` with values passed via environment variables.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns_hook: Option<String>,
    /// Certificate profile identifier (draft-aaron-acme-profiles-01).
    /// When set, the value is sent as `"profile"` in the newOrder payload.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
    /// Token Authority URL for `tkauth-01` challenges (RFC 9447).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tkauth_url: Option<String>,
    /// Path to a Kerberos keytab for SPNEGO authentication to the Token Authority.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tkauth_keytab: Option<PathBuf>,
    /// Base64url-encoded JWTClaimConstraints blob for `tkauth-01` orders.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwtcc: Option<String>,
}

impl std::fmt::Debug for RenewalConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RenewalConfig")
            .field("server", &self.server)
            .field("ca", &self.ca)
            .field("domains", &self.domains)
            .field("account_key", &self.account_key)
            .field("account_url", &self.account_url)
            .field("account_key_type", &self.account_key_type)
            .field("cert_path", &self.cert_path)
            .field("cert_key_path", &self.cert_key_path)
            .field("cert_key_type", &self.cert_key_type)
            .field("challenge_type", &self.challenge_type)
            .field("http_port", &self.http_port)
            .field("tls_port", &self.tls_port)
            .field("onion_key", &self.onion_key)
            .field("poll_timeout", &self.poll_timeout)
            .field("contacts", &self.contacts)
            .field("eab_kid", &self.eab_kid)
            .field("eab_key", &self.eab_key.as_ref().map(|_| "[REDACTED]"))
            .field("eab_alg", &self.eab_alg)
            .field("gssapi_keytab", &self.gssapi_keytab)
            .field("dns_hook", &self.dns_hook)
            .field("profile", &self.profile)
            .field("tkauth_url", &self.tkauth_url)
            .field("tkauth_keytab", &self.tkauth_keytab)
            .field("jwtcc", &self.jwtcc)
            .finish()
    }
}

mod defaults {
    pub fn key_type() -> String {
        "ec:P-256".into()
    }
    pub fn challenge_type() -> String {
        "http-01".into()
    }
    pub fn http_port() -> u16 {
        80
    }
    pub fn tls_port() -> u16 {
        443
    }
    pub fn poll_timeout() -> u64 {
        120
    }
    pub fn eab_alg() -> String {
        "HS256".into()
    }
}
