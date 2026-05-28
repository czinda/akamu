use std::collections::HashMap;

use serde::Deserialize;

use super::gssapi::GssapiConfig;
use super::webui::WebUiConfig;

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
    /// Certificate profiles (draft-ietf-acme-profiles-01).
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

pub(super) fn default_account_scope() -> String {
    "server".to_owned()
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
