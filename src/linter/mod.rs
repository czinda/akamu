//! Pre-issuance linter profile registry.
//!
//! Resolves named linter profiles from configuration and exposes them as
//! [`ResolvedLinterProfile`] values that `ca::issue` converts into a
//! `PolicyDefinition` at cert-sign time.

use std::collections::HashMap;

use synta_x509_verification::policy::{
    AlgorithmId, ValidationProfile, POSTQUANTUM_PERMITTED_SIGNATURE_ALGORITHMS,
    POSTQUANTUM_PERMITTED_SPKI_ALGORITHMS, WEBPKI_PERMITTED_SIGNATURE_ALGORITHMS,
    WEBPKI_PERMITTED_SIGNATURE_ALGORITHMS_WITH_PQ, WEBPKI_PERMITTED_SPKI_ALGORITHMS,
    WEBPKI_PERMITTED_SPKI_ALGORITHMS_WITH_PQ,
};

use crate::config::LinterConfig;
use crate::error::AcmeError;

// ── Built-in profiles ─────────────────────────────────────────────────────────

/// `san` / `name_constraints` presence policy for extension overrides.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExtPresence {
    Required,
    Optional,
    Absent,
}

/// Fully resolved linter profile — all fields are concrete, no `Option` wrappers.
///
/// All fields are `Copy`; the struct is safe to pass into `spawn_blocking` closures.
#[derive(Clone, Copy, Debug)]
pub struct ResolvedLinterProfile {
    /// Base validation profile (`WebPki` or `Rfc5280`).
    pub base: ValidationProfile,
    /// How the SAN extension must appear in the EE certificate.
    pub san: ExtPresence,
    /// How the Name Constraints extension must appear in the EE certificate.
    pub name_constraints: ExtPresence,
    /// Minimum RSA modulus size in bits.
    pub minimum_rsa_bits: usize,
    /// Permitted SPKI algorithm OIDs.
    pub spki_algs: &'static [AlgorithmId],
    /// Permitted signature algorithm OIDs.
    pub sig_algs: &'static [AlgorithmId],
    /// Whether to extend algorithm lists with composite ML-DSA OIDs at lint time.
    pub include_composite_algs: bool,
}

/// Built-in "webpki" profile (CA/B Forum BR).
///
/// SAN required; name constraints absent on EE; classical + ML-DSA + composite
/// algorithm lists; RSA ≥ 2048 bits.
pub const WEBPKI_PROFILE: ResolvedLinterProfile = ResolvedLinterProfile {
    base: ValidationProfile::WebPki,
    san: ExtPresence::Required,
    name_constraints: ExtPresence::Absent,
    minimum_rsa_bits: 2048,
    spki_algs: WEBPKI_PERMITTED_SPKI_ALGORITHMS_WITH_PQ,
    sig_algs: WEBPKI_PERMITTED_SIGNATURE_ALGORITHMS_WITH_PQ,
    include_composite_algs: true,
};

/// Built-in "rfc5280" profile.
///
/// SAN optional; name constraints optional with agnostic criticality; same
/// algorithm lists as `webpki_pq`; RSA ≥ 2048 bits.
pub const RFC5280_PROFILE: ResolvedLinterProfile = ResolvedLinterProfile {
    base: ValidationProfile::Rfc5280,
    san: ExtPresence::Optional,
    name_constraints: ExtPresence::Optional,
    minimum_rsa_bits: 2048,
    spki_algs: WEBPKI_PERMITTED_SPKI_ALGORITHMS_WITH_PQ,
    sig_algs: WEBPKI_PERMITTED_SIGNATURE_ALGORITHMS_WITH_PQ,
    include_composite_algs: true,
};

// ── Registry ──────────────────────────────────────────────────────────────────

/// Registry of named linter profiles.
///
/// Always contains the `"webpki"` and `"rfc5280"` built-ins.  User-defined
/// profiles from `[linter.profiles.*]` are added on top.
#[derive(Debug)]
pub struct LinterRegistry {
    profiles: HashMap<String, ResolvedLinterProfile>,
}

impl LinterRegistry {
    /// Build the registry from a `[linter]` config section.
    ///
    /// The built-ins `"webpki"` and `"rfc5280"` are always registered; user
    /// entries override them only if they explicitly re-declare those names.
    pub fn new(cfg: &LinterConfig) -> Result<Self, AcmeError> {
        let mut profiles = HashMap::new();
        profiles.insert("webpki".to_string(), WEBPKI_PROFILE);
        profiles.insert("rfc5280".to_string(), RFC5280_PROFILE);

        for (name, pcfg) in &cfg.profiles {
            let base_name = pcfg.base.as_deref().unwrap_or("webpki");
            let base = match base_name {
                "webpki" => WEBPKI_PROFILE,
                "rfc5280" => RFC5280_PROFILE,
                other => {
                    return Err(AcmeError::Config(format!(
                        "linter profile '{name}': unknown base '{other}'; \
                         expected 'webpki' or 'rfc5280'"
                    )));
                }
            };

            let san = match pcfg.san.as_deref() {
                Some("optional") | Some("maybe") => ExtPresence::Optional,
                Some("absent") | Some("none") => ExtPresence::Absent,
                Some("required") => ExtPresence::Required,
                None => base.san,
                Some(other) => {
                    return Err(AcmeError::Config(format!(
                        "linter profile '{name}': unknown san value '{other}'; \
                         expected 'required', 'optional', or 'absent'"
                    )));
                }
            };

            let name_constraints = match pcfg.name_constraints.as_deref() {
                Some("optional") | Some("maybe") => ExtPresence::Optional,
                Some("absent") | Some("none") => ExtPresence::Absent,
                Some("required") => ExtPresence::Required,
                None => base.name_constraints,
                Some(other) => {
                    return Err(AcmeError::Config(format!(
                        "linter profile '{name}': unknown name_constraints value '{other}'; \
                         expected 'required', 'optional', or 'absent'"
                    )));
                }
            };

            let (spki_algs, sig_algs, include_composite_algs) = match pcfg.algorithms.as_deref() {
                Some("webpki") => (
                    WEBPKI_PERMITTED_SPKI_ALGORITHMS,
                    WEBPKI_PERMITTED_SIGNATURE_ALGORITHMS,
                    false,
                ),
                Some("pq_only") | Some("pq") => (
                    POSTQUANTUM_PERMITTED_SPKI_ALGORITHMS,
                    POSTQUANTUM_PERMITTED_SIGNATURE_ALGORITHMS,
                    false,
                ),
                None | Some("webpki_pq") | Some("webpki+pq") => {
                    (base.spki_algs, base.sig_algs, base.include_composite_algs)
                }
                Some(other) => {
                    return Err(AcmeError::Config(format!(
                        "linter profile '{name}': unknown algorithms value '{other}'; \
                         expected 'webpki', 'webpki_pq', or 'pq_only'"
                    )));
                }
            };

            let minimum_rsa_bits = pcfg
                .minimum_rsa_bits
                .map(|b| b as usize)
                .unwrap_or(base.minimum_rsa_bits);

            let base_profile = base.base;

            profiles.insert(
                name.clone(),
                ResolvedLinterProfile {
                    base: base_profile,
                    san,
                    name_constraints,
                    minimum_rsa_bits,
                    spki_algs,
                    sig_algs,
                    include_composite_algs,
                },
            );
        }

        Ok(Self { profiles })
    }

    /// Look up a profile by name.
    ///
    /// Returns an error for unknown profile names so misconfigurations are
    /// caught early rather than silently degraded to the default.
    pub fn resolve(&self, name: &str) -> Result<&ResolvedLinterProfile, AcmeError> {
        self.profiles.get(name).ok_or_else(|| {
            AcmeError::Config(format!(
                "unknown linter profile '{name}'; \
                 available: {}",
                self.profiles.keys().cloned().collect::<Vec<_>>().join(", ")
            ))
        })
    }
}
