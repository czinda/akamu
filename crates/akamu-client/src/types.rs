//! ACME protocol types (RFC 8555).

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
