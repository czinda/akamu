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
