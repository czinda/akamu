use std::collections::HashMap;

use serde::Deserialize;

/// Top-level `[linter]` configuration section.
///
/// Defines named linter profiles that can be referenced from certificate profiles
/// or from a per-CA `default_linter` field.  Two profiles — `"webpki"` and
/// `"rfc5280"` — are always available as built-ins even when this section is absent.
#[derive(Debug, Deserialize, Default)]
pub struct LinterConfig {
    /// Named linter profiles.  Each entry is referenced by its map key.
    #[serde(default)]
    pub profiles: HashMap<String, LinterProfileConfig>,
}

/// Configuration for a single named linter profile.
///
/// All fields are optional; omitting a field inherits the value from the chosen base.
#[derive(Debug, Deserialize)]
pub struct LinterProfileConfig {
    /// Base profile to start from: `"webpki"` (default) or `"rfc5280"`.
    ///
    /// - `"webpki"`: CA/B Forum Baseline Requirements profile.  SAN required,
    ///   name constraints absent on EE, `cA=FALSE` enforced.
    /// - `"rfc5280"`: plain RFC 5280 profile.  SAN optional, name constraints
    ///   may be present on EE, `cA=TRUE` allowed.
    pub base: Option<String>,

    /// Subject Alternative Name extension handling.
    ///
    /// `"required"` (default for `webpki`), `"optional"` (default for `rfc5280`),
    /// or `"absent"`.
    pub san: Option<String>,

    /// Name Constraints extension handling.
    ///
    /// `"required"`, `"optional"` (default for `rfc5280`), or `"absent"` (default
    /// for `webpki`).
    pub name_constraints: Option<String>,

    /// Algorithm allowlist tier.
    ///
    /// - `"webpki"`: classical algorithms only (RSA, EC, Ed25519, Ed448).
    /// - `"webpki_pq"` (default): classical + ML-DSA + composite ML-DSA.
    /// - `"pq_only"`: ML-DSA-44/65/87 and ML-KEM-512/768/1024 only.
    pub algorithms: Option<String>,

    /// Minimum RSA public key modulus size in bits.  Default: 2048.
    pub minimum_rsa_bits: Option<u32>,
}
