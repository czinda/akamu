//! Population spec: TOML-deserialisable description of what to generate.

use std::collections::HashMap;

use serde::Deserialize;

// ── Top-level ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize)]
pub struct SeedSpec {
    #[serde(default)]
    pub global: GlobalConfig,

    /// CA configurations.  At least one must have `is_default = true`.
    #[serde(default)]
    pub ca: Vec<CaSpec>,

    /// Cross-sign pairs — each causes the issuer CA to sign the subject CA's cert.
    #[serde(default)]
    pub cross_sign: Vec<CrossSignSpec>,

    /// Profile definitions added to the in-process server at startup.
    #[serde(default)]
    pub profile: Vec<ProfileSpec>,

    /// Issuance scenarios — each runs a batch of accounts and certs.
    #[serde(default)]
    pub scenario: Vec<ScenarioSpec>,
}

impl SeedSpec {
    /// Load from a TOML file.
    pub fn load(path: &str) -> Result<Self, String> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("cannot read spec file '{path}': {e}"))?;
        let spec: SeedSpec =
            toml::from_str(&text).map_err(|e| format!("spec parse error in '{path}': {e}"))?;
        spec.validate()?;
        Ok(spec)
    }

    /// Built-in default spec: 2 CAs, mutual cross-signs, 3 profiles, 2 scenarios.
    pub fn built_in() -> Self {
        let spec: SeedSpec = toml::from_str(DEFAULT_SPEC).expect("built-in spec is valid TOML");
        spec.validate().expect("built-in spec passes validation");
        spec
    }

    /// Validate cross-references and consistency constraints.
    pub fn validate(&self) -> Result<(), String> {
        // Must have at least one CA.
        if self.ca.is_empty() {
            return Err("spec validation: at least one [[ca]] entry is required".into());
        }

        // Exactly one CA must be the default.
        let default_count = self.ca.iter().filter(|c| c.is_default).count();
        if default_count != 1 {
            return Err(format!(
                "spec validation: exactly one [[ca]] must have is_default = true (found {default_count})"
            ));
        }

        // CA IDs must be unique.
        let mut ca_ids = std::collections::HashSet::new();
        for c in &self.ca {
            if !ca_ids.insert(c.id.as_str()) {
                return Err(format!("spec validation: duplicate CA id '{}'", c.id));
            }
        }

        // Cross-sign references must resolve.
        for cs in &self.cross_sign {
            if !ca_ids.contains(cs.issuer.as_str()) {
                return Err(format!(
                    "cross_sign: issuer '{}' is not a known CA id",
                    cs.issuer
                ));
            }
            if !ca_ids.contains(cs.subject.as_str()) {
                return Err(format!(
                    "cross_sign: subject '{}' is not a known CA id",
                    cs.subject
                ));
            }
            if cs.issuer == cs.subject {
                return Err(format!(
                    "cross_sign: issuer and subject must differ (got '{}')",
                    cs.issuer
                ));
            }
            if cs.validity_years == 0 || cs.validity_years > 50 {
                return Err("cross_sign: validity_years must be 1–50".into());
            }
        }

        // Profile ids must be unique.
        let mut seen_profiles = std::collections::HashSet::new();
        for p in &self.profile {
            if !seen_profiles.insert(p.id.as_str()) {
                return Err(format!("duplicate profile id '{}'", p.id));
            }
            for ca_id in &p.ca_ids {
                if !ca_ids.contains(ca_id.as_str()) {
                    return Err(format!(
                        "profile '{}': ca_ids references unknown CA '{ca_id}'",
                        p.id
                    ));
                }
            }
        }
        let profile_ids: std::collections::HashSet<&str> =
            self.profile.iter().map(|p| p.id.as_str()).collect();

        // Scenario references must resolve.
        for s in &self.scenario {
            if !ca_ids.contains(s.ca_id.as_str()) {
                return Err(format!(
                    "scenario '{}': ca_id '{}' is not a known CA id",
                    s.name, s.ca_id
                ));
            }
            if let Some(ref pid) = s.profile_id {
                if !profile_ids.contains(pid.as_str()) {
                    return Err(format!(
                        "scenario '{}': profile_id '{}' is not a known profile id",
                        s.name, pid
                    ));
                }
            }
            let deact = s.accounts.deactivated;
            if deact > s.num_accounts {
                return Err(format!(
                    "scenario '{}': accounts.deactivated ({deact}) > num_accounts ({})",
                    s.name, s.num_accounts
                ));
            }
        }

        Ok(())
    }

    /// Return the CA spec marked `is_default`, or `None` when the spec is empty.
    pub fn default_ca(&self) -> Option<&CaSpec> {
        self.ca.iter().find(|c| c.is_default)
    }
}

// ── Global ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize)]
pub struct GlobalConfig {
    /// RNG seed — same seed with the same spec → identical output database.
    #[serde(default = "default_seed")]
    pub seed: u64,

    /// Output SQLite file path.
    #[serde(default = "default_output")]
    pub output: String,
}

fn default_seed() -> u64 {
    42
}
fn default_output() -> String {
    "test-data.sqlite3".to_string()
}

impl Default for GlobalConfig {
    fn default() -> Self {
        GlobalConfig {
            seed: default_seed(),
            output: default_output(),
        }
    }
}

// ── CA ────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize)]
pub struct CaSpec {
    /// Unique CA identifier (used in profile `ca_ids` and cross-sign references).
    pub id: String,
    /// Exactly one CA must be the default.
    #[serde(default)]
    pub is_default: bool,
    /// CA private-key / signing key type.  Same syntax as the main server config.
    #[serde(default = "default_key_type")]
    pub key_type: String,
    /// Default validity for end-entity certs issued by this CA.
    #[serde(default = "default_validity_days")]
    pub validity_days: u32,
    #[serde(default = "default_hash_alg")]
    pub hash_alg: String,
    #[serde(default = "default_common_name")]
    pub common_name: String,
    #[serde(default = "default_organization")]
    pub organization: String,
    #[serde(default = "default_ca_validity_years")]
    pub ca_validity_years: u32,
}

fn default_key_type() -> String {
    "ec:P-256".to_string()
}
fn default_validity_days() -> u32 {
    90
}
fn default_hash_alg() -> String {
    "sha256".to_string()
}
fn default_common_name() -> String {
    "Akamu Seedgen CA".to_string()
}
fn default_organization() -> String {
    "Akamu Seedgen".to_string()
}
fn default_ca_validity_years() -> u32 {
    10
}

// ── Cross-sign ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize)]
pub struct CrossSignSpec {
    /// CA id of the signing CA.
    pub issuer: String,
    /// CA id of the CA whose cert is being signed.
    pub subject: String,
    /// Validity of the resulting cross-certificate in years.
    #[serde(default = "default_cross_validity_years")]
    pub validity_years: u32,
}

fn default_cross_validity_years() -> u32 {
    5
}

// ── Profile ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize)]
pub struct ProfileSpec {
    pub id: String,
    #[serde(default)]
    pub description: String,
    /// EKU short names: `server_auth`, `client_auth`, `code_signing`, etc.
    #[serde(default)]
    pub eku: Vec<String>,
    /// Key usage short names: `digital_signature`, `key_encipherment`, etc.
    #[serde(default)]
    pub key_usage: Vec<String>,
    /// Certificate validity days.  `None` inherits from the CA.
    pub validity_days: Option<u32>,
    /// Allowed subscriber CSR key types.  Empty = any.
    #[serde(default)]
    pub allowed_key_types: Vec<String>,
    /// When true the subscribing account must have this profile in its grants.
    #[serde(default)]
    pub require_account_grant: bool,
    /// Restrict this profile to specific CA ids.  Empty = all CAs.
    #[serde(default)]
    pub ca_ids: Vec<String>,
    /// Regex patterns that identifiers must satisfy.
    #[serde(default)]
    pub allowed_identifiers: Vec<String>,
}

// ── Scenario ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize)]
pub struct ScenarioSpec {
    /// Human-readable name for logging.
    pub name: String,
    /// CA id to issue certs under.
    pub ca_id: String,
    /// Profile id to use.  `None` → no profile header (CA defaults apply).
    pub profile_id: Option<String>,
    /// Number of ACME accounts to register.
    #[serde(default = "default_num_accounts")]
    pub num_accounts: usize,
    /// Certificate/order counts for this scenario.
    #[serde(default)]
    pub certs: CertCountSpec,
    /// Account post-processing.
    #[serde(default)]
    pub accounts: AccountStateSpec,
}

fn default_num_accounts() -> usize {
    5
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct CertCountSpec {
    /// Certs left in `valid` status.
    #[serde(default)]
    pub valid: usize,
    /// Certs revoked with various RFC 5280 reason codes.
    #[serde(default)]
    pub revoked: usize,
    /// Certs whose `not_after` is backdated to ≥1 year ago.
    #[serde(default)]
    pub expired: usize,
    /// Certs whose `not_after` is within the next 30 days.
    #[serde(default)]
    pub near_expiry: usize,
    /// Number of ARI replacement chains.  Each chain is 3 certs A→B→C.
    #[serde(default)]
    pub ari_chains: usize,
    /// STAR orders left active.
    #[serde(default)]
    pub star_active: usize,
    /// STAR orders that are canceled.
    #[serde(default)]
    pub star_canceled: usize,
    /// Orders left in `processing` state (simulated delegation).
    #[serde(default)]
    pub delegation: usize,
    /// Orders left in `pending` state (never finalized).
    #[serde(default)]
    pub pending_orders: usize,
    /// Orders set to `invalid` (expired/abandoned).
    #[serde(default)]
    pub invalid_orders: usize,
    /// Leaf cert key-type weights: `{"ec:P-256" = 6, "rsa:2048" = 1}`.
    /// When empty defaults to `{"ec:P-256" = 1}`.
    #[serde(default)]
    pub key_types: HashMap<String, u32>,
}

impl CertCountSpec {
    /// Total certs that need the full ACME issuance flow.
    pub fn issuance_total(&self) -> usize {
        // ARI chains: 3 certs each
        self.valid
            + self.revoked
            + self.expired
            + self.near_expiry
            + self.ari_chains * 3
            + self.star_active
            + self.star_canceled
    }

    /// Total orders (some without certs).
    pub fn order_total(&self) -> usize {
        self.issuance_total() + self.delegation + self.pending_orders + self.invalid_orders
    }

    /// Effective key-type distribution with fallback.
    pub fn effective_key_types(&self) -> HashMap<String, u32> {
        if self.key_types.is_empty() {
            [("ec:P-256".to_string(), 1u32)].into()
        } else {
            self.key_types.clone()
        }
    }
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct AccountStateSpec {
    /// How many of the `num_accounts` accounts to deactivate after cert generation.
    #[serde(default)]
    pub deactivated: usize,
}

// ── Built-in default spec ─────────────────────────────────────────────────────

const DEFAULT_SPEC: &str = r#"
[global]
seed   = 42
output = "test-data.sqlite3"

[[ca]]
id            = "primary"
key_type      = "ec:P-256"
is_default    = true
validity_days = 90
hash_alg      = "sha256"
common_name   = "Akamu Primary CA"
organization  = "Akamu Test"

[[ca]]
id            = "legacy"
key_type      = "rsa:2048"
is_default    = false
validity_days = 365
hash_alg      = "sha256"
common_name   = "Akamu Legacy CA"
organization  = "Akamu Test"

[[cross_sign]]
issuer         = "primary"
subject        = "legacy"
validity_years = 5

[[cross_sign]]
issuer         = "legacy"
subject        = "primary"
validity_years = 5

[[profile]]
id          = "tls-server"
description = "Standard TLS server certificate"
eku         = ["server_auth"]
key_usage   = ["digital_signature"]
validity_days = 90

[[profile]]
id                   = "client-auth"
description          = "Client authentication certificate"
eku                  = ["client_auth"]
key_usage            = ["digital_signature"]
validity_days        = 365
allowed_key_types    = ["ec:P-256", "ec:P-384", "ed25519"]
require_account_grant = false
ca_ids               = ["primary"]

[[profile]]
id          = "code-signing"
description = "Code signing certificate"
eku         = ["code_signing"]
key_usage   = ["digital_signature"]
validity_days = 730

[[scenario]]
name         = "web-servers"
ca_id        = "primary"
profile_id   = "tls-server"
num_accounts = 8

[scenario.certs]
valid          = 30
revoked        = 15
expired        = 12
near_expiry    = 8
ari_chains     = 3
star_active    = 2
star_canceled  = 2
delegation     = 2
pending_orders = 3
invalid_orders = 3

[scenario.certs.key_types]
"ec:P-256" = 5
"ec:P-384" = 2
"rsa:2048" = 1
"ed25519"  = 1

[scenario.accounts]
deactivated = 2

[[scenario]]
name         = "legacy-rsa"
ca_id        = "legacy"
profile_id   = "tls-server"
num_accounts = 4

[scenario.certs]
valid   = 15
revoked = 8
expired = 8

[scenario.certs.key_types]
"rsa:2048" = 4
"rsa:4096" = 1
"ec:P-256" = 1

[scenario.accounts]
deactivated = 1

[[scenario]]
name         = "client-certs"
ca_id        = "primary"
profile_id   = "client-auth"
num_accounts = 3

[scenario.certs]
valid   = 10
revoked = 5
expired = 5

[scenario.certs.key_types]
"ec:P-256" = 3
"ed25519"  = 2
"#;
