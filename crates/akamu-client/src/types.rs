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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RenewalConfig {
    /// ACME directory URL.
    pub server: String,
    /// Identifiers (domains or IPs) to certify.
    pub domains: Vec<Identifier>,
    /// Path to the account private key PEM.
    pub account_key: PathBuf,
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
    pub onion_key: Option<PathBuf>,
    /// Poll timeout in seconds when waiting for challenge validation.
    #[serde(default = "defaults::poll_timeout")]
    pub poll_timeout: u64,
    /// Contact URIs registered with the account (e.g. `"mailto:admin@example.com"`).
    #[serde(default)]
    pub contacts: Vec<String>,
    /// EAB key identifier.
    pub eab_kid: Option<String>,
    /// EAB HMAC key (base64url).
    pub eab_key: Option<String>,
    /// EAB HMAC algorithm.
    #[serde(default = "defaults::eab_alg")]
    pub eab_alg: String,
    /// Path to a Kerberos keytab for GSSAPI-authenticated EAB fetch.
    #[serde(default)]
    pub gssapi_keytab: Option<PathBuf>,
    /// Hook script for DNS TXT record management.  Invoked as
    /// `<dns_hook> add|remove` with values passed via environment variables.
    pub dns_hook: Option<String>,
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
