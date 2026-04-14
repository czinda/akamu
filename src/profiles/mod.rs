//! Certificate profile subsystem.
//!
//! A *profile* governs which extensions, key usage bits, validity period, and
//! signing algorithm are applied when issuing a certificate.  Profiles are
//! loaded from one or more configured *providers* and cached in memory.
//! akamu's own CA always does the signing.
//!
//! # Provider types
//!
//! | `type`    | Source                                               |
//! |-----------|------------------------------------------------------|
//! | `builtin` | Inline TOML declaration in `config.toml`             |
//! | `dogtag`  | Dogtag PKI `.cfg` files — filesystem or LDAP         |
//! | `ipa`     | FreeIPA/IPAThinCA — filesystem or LDAP (GSSAPI auth) |
//!
//! All providers produce [`CertificateParameters`] consumed by
//! [`crate::ca::issue::issue_with_params`].
//!
//! # Caching and refresh
//!
//! Profiles are cached in memory after the initial load so that no external
//! system is queried at certificate issuance time.  A background tokio task
//! (started by [`ProfileRegistry::spawn_refresh_task`]) periodically reloads
//! all providers and updates the cache.  The refresh interval is controlled by
//! `profiles.refresh_interval_secs` in `config.toml` (default: 3600 s).
//!
//! # Adding a provider type
//!
//! 1. Add a variant to [`crate::config::ProviderConfig`].
//! 2. Implement a `load_<type>` function in a new submodule.
//! 3. Call it from [`load_all_providers`].

pub mod builtin;
pub mod cfg;
pub mod dogtag;
pub mod ipa;

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::Instant;

use crate::config::ProfilesConfig;
use crate::state::CaState;

/// Simplified CA defaults used during profile parameter resolution.
///
/// Copied from `CaState` at registry construction time.  Stored inside
/// `ProfileRegistry` so the refresh task does not need access to the full
/// `CaState`.
#[derive(Clone, Debug)]
pub struct CaDefaults {
    pub validity_days: u32,
    pub hash_alg: String,
    pub crl_url: Option<String>,
    pub ocsp_url: Option<String>,
}

impl CaDefaults {
    pub fn from_ca(ca: &CaState) -> Self {
        Self {
            validity_days: ca.validity_days,
            hash_alg: ca.hash_alg.clone(),
            crl_url: ca.crl_url.clone(),
            ocsp_url: ca.ocsp_url.clone(),
        }
    }
}

/// Parameters that govern how a certificate is issued for a given profile.
///
/// All fields are concrete at this point — inheritance from `CaDefaults` /
/// `CaState` has already been applied by the loading function.
#[derive(Debug, Clone)]
pub struct CertificateParameters {
    /// Validity period in days.
    pub validity_days: u32,
    /// Signing hash algorithm: `"sha256"`, `"sha384"`, or `"sha512"`.
    pub hash_alg: String,
    /// Key usage bitmask.  Bit positions correspond to `KEY_USAGE_*` constants
    /// from `synta_certificate` (e.g. `1u16 << KEY_USAGE_DIGITAL_SIGNATURE`).
    /// Zero means the KeyUsage extension is omitted.
    pub key_usage_bits: u16,
    /// Extended key usage entries.  Short names (`"server_auth"`,
    /// `"client_auth"`, `"code_signing"`, `"email_protection"`,
    /// `"time_stamping"`, `"ocsp_signing"`) and raw dotted-decimal OID
    /// strings are both accepted.
    pub extended_key_usages: Vec<String>,
    /// CRL distribution point URL.  `None` → no CDP extension.
    pub crl_url: Option<String>,
    /// OCSP responder URL.  `None` → no AIA extension.
    pub ocsp_url: Option<String>,
    /// Allowed subscriber CSR key types.  Empty = any key type accepted.
    /// Format: `"ec:P-256"`, `"rsa:2048"`, etc.
    pub allowed_key_types: Vec<String>,
    /// Certificate policy `(OID, CPS URI)` pairs.
    /// Empty = no CertificatePolicies extension.
    pub certificate_policies: Vec<(String, Option<String>)>,
}

impl CertificateParameters {
    /// Build `CertificateParameters` from CA defaults.
    ///
    /// Used when an order carries no `profile` field and no `"default"` profile
    /// is configured.  Reproduces the pre-profile issuance behaviour:
    /// `digitalSignature` KeyUsage, `serverAuth` EKU, CA validity and URLs.
    pub fn from_ca(ca: &CaState) -> Self {
        use synta_certificate::KEY_USAGE_DIGITAL_SIGNATURE;
        Self {
            validity_days: ca.validity_days,
            hash_alg: ca.hash_alg.clone(),
            key_usage_bits: 1u16 << KEY_USAGE_DIGITAL_SIGNATURE,
            extended_key_usages: vec!["server_auth".to_string()],
            crl_url: ca.crl_url.clone(),
            ocsp_url: ca.ocsp_url.clone(),
            allowed_key_types: vec![],
            certificate_policies: vec![],
        }
    }
}

// ── Profile cache ─────────────────────────────────────────────────────────────

/// Snapshot of loaded profiles at a point in time.
struct ProfileCache {
    /// `profile_id` → `(description, parameters)`.
    profiles: HashMap<String, (String, CertificateParameters)>,
    /// When this snapshot was populated (for staleness logging).
    loaded_at: Instant,
}

// ── ProfileRegistry ───────────────────────────────────────────────────────────

/// Runtime registry of cached certificate profiles.
///
/// Thread-safe; the internal cache is updated atomically under a write lock
/// by the background refresh task while readers hold a read lock only for
/// the duration of a lookup.
pub struct ProfileRegistry {
    /// Read-optimised in-memory cache, replaced wholesale on each refresh.
    cache: RwLock<ProfileCache>,
    /// Cloned provider configurations used by the refresh task.
    providers_cfg: ProfilesConfig,
    /// CA defaults for inheriting validity/hash/URLs during loading.
    ca_defaults: CaDefaults,
}

impl ProfileRegistry {
    /// Build the registry and perform the initial profile load.
    pub async fn new(cfg: &ProfilesConfig, ca: &CaState) -> Result<Arc<Self>, String> {
        let ca_defaults = CaDefaults::from_ca(ca);
        let profiles = load_all_providers(cfg, &ca_defaults).await?;

        let registry = Arc::new(Self {
            cache: RwLock::new(ProfileCache {
                profiles,
                loaded_at: Instant::now(),
            }),
            providers_cfg: cfg.clone(),
            ca_defaults,
        });

        Ok(registry)
    }

    /// Empty registry — no providers configured.
    ///
    /// All orders without a `profile` field fall back to `CaState` defaults.
    pub fn empty(ca: &CaState) -> Arc<Self> {
        Arc::new(Self {
            cache: RwLock::new(ProfileCache {
                profiles: HashMap::new(),
                loaded_at: Instant::now(),
            }),
            providers_cfg: ProfilesConfig::default(),
            ca_defaults: CaDefaults::from_ca(ca),
        })
    }

    /// Spawn a background tokio task that refreshes the profile cache
    /// at `refresh_interval_secs` intervals.
    ///
    /// Call once after the registry is constructed.  The task runs for the
    /// lifetime of the `Arc<ProfileRegistry>` — it holds a weak reference so
    /// that server shutdown (dropping the `Arc`) terminates the loop cleanly.
    pub fn spawn_refresh_task(self: &Arc<Self>) {
        let interval_secs = self.providers_cfg.refresh_interval_secs;
        if interval_secs == 0 || self.providers_cfg.providers.is_empty() {
            return;
        }

        let weak = Arc::downgrade(self);
        tokio::spawn(async move {
            let interval = tokio::time::Duration::from_secs(interval_secs);
            loop {
                tokio::time::sleep(interval).await;
                match weak.upgrade() {
                    None => break, // registry dropped — server is shutting down
                    Some(registry) => {
                        if let Err(e) = registry.refresh().await {
                            tracing::warn!("profile cache refresh failed: {e}");
                        }
                    }
                }
            }
        });
    }

    /// Re-read all providers and atomically replace the cache.
    pub async fn refresh(&self) -> Result<(), String> {
        let profiles = load_all_providers(&self.providers_cfg, &self.ca_defaults).await?;
        let count = profiles.len();
        {
            let mut cache = self.cache.write().unwrap();
            cache.profiles = profiles;
            cache.loaded_at = Instant::now();
        }
        tracing::info!("profile cache refreshed: {} profile(s) loaded", count);
        Ok(())
    }

    /// Resolve a profile name to its certificate parameters.
    ///
    /// Returns a cloned `CertificateParameters` so the read lock is not held
    /// across async issuance code.  Returns `None` when the profile is not
    /// loaded in any provider.
    pub fn resolve(&self, profile_name: &str) -> Option<CertificateParameters> {
        self.cache
            .read()
            .unwrap()
            .profiles
            .get(profile_name)
            .map(|(_, p)| p.clone())
    }

    /// Return all `profile_id → description` pairs from the cache.
    ///
    /// Used to populate the ACME directory `meta.profiles` field
    /// (draft-aaron-acme-profiles-01).
    pub fn all_profiles(&self) -> HashMap<String, String> {
        self.cache
            .read()
            .unwrap()
            .profiles
            .iter()
            .map(|(id, (desc, _))| (id.clone(), desc.clone()))
            .collect()
    }

    /// Return `true` when no profiles are currently cached.
    pub fn is_empty(&self) -> bool {
        self.cache.read().unwrap().profiles.is_empty()
    }
}

// ── Internal loader ───────────────────────────────────────────────────────────

/// Load all providers and merge their profiles into a single map.
///
/// When the same profile ID appears in multiple providers, the first one in
/// HashMap iteration order wins.
async fn load_all_providers(
    cfg: &ProfilesConfig,
    ca: &CaDefaults,
) -> Result<HashMap<String, (String, CertificateParameters)>, String> {
    let mut merged: HashMap<String, (String, CertificateParameters)> = HashMap::new();

    for (provider_name, provider_cfg) in &cfg.providers {
        let loaded = match provider_cfg {
            crate::config::ProviderConfig::Builtin(bcfg) => builtin::load_builtin(bcfg, ca),
            crate::config::ProviderConfig::Dogtag(dcfg) => {
                dogtag::load_dogtag(provider_name, dcfg, ca).await?
            }
            crate::config::ProviderConfig::Ipa(icfg) => {
                ipa::load_ipa(provider_name, icfg, ca).await?
            }
        };

        let count = loaded.len();
        // Earlier providers take precedence — do not overwrite.
        for (id, entry) in loaded {
            merged.entry(id).or_insert(entry);
        }
        tracing::info!(
            "profiles: provider '{}' contributed {} profile(s)",
            provider_name,
            count,
        );
    }

    Ok(merged)
}
