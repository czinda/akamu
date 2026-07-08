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
//! 3. Call it from `load_all_providers`.

pub mod auth;
pub mod builtin;
pub mod cfg;
pub mod dogtag;
pub mod ipa;
pub mod ldap_resolve;
pub mod ldap_session;

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::Instant;

use crate::config::{ProfilesConfig, ProviderConfig};
use crate::state::CaState;

/// Simplified CA defaults used during profile parameter resolution.
///
/// Copied from `CaState` at registry construction time.  Stored inside
/// `ProfileRegistry` so the refresh task does not need access to the full
/// `CaState`.
#[derive(Clone, Debug)]
pub struct CaDefaults {
    /// Default validity period in days, copied from `[ca].validity_days`.
    pub validity_days: u32,
    /// Signing hash algorithm string, copied from `[ca].hash_alg`
    /// (e.g. `"sha256"`, `"sha384"`, `"sha512"`).
    pub hash_alg: String,
    /// CRL distribution point URL, copied from `[ca].crl_url`.  `None` means
    /// the CA has no CRL URL; profiles that do not override this value will
    /// emit no CRLDistributionPoints extension.
    pub crl_url: Option<String>,
    /// OCSP responder URL, copied from `[ca].ocsp_url`.  `None` means the CA
    /// has no OCSP URL; profiles that do not override this value will emit no
    /// AuthorityInfoAccess extension.
    pub ocsp_url: Option<String>,
}

impl CaDefaults {
    /// Snapshot the CA-level defaults from `CaState` for use during profile loading.
    ///
    /// Called once when [`ProfileRegistry::new`] is constructed so that the
    /// background refresh task does not need to retain a reference to `CaState`.
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
    /// CRL distribution point URL.  `None` means no CRLDistributionPoints
    /// extension is included in the issued certificate.  This is a fully
    /// resolved value — the three-state inheritance semantics from
    /// `BuiltinProfileConfig` (`None` = inherit, `""` = suppress,
    /// `Some(url)` = override) have already been applied by the provider
    /// loading function before this struct is populated.
    pub crl_url: Option<String>,
    /// OCSP responder URL.  `None` means no AuthorityInfoAccess extension is
    /// included in the issued certificate.  Fully resolved, same as `crl_url`.
    pub ocsp_url: Option<String>,
    /// Allowed subscriber CSR key types.  Empty = any key type accepted.
    /// Format: `"ec:P-256"`, `"rsa:2048"`, etc.
    pub allowed_key_types: Vec<String>,
    /// Certificate policy `(OID, CPS URI)` pairs for the CertificatePolicies
    /// extension.  Empty = no CertificatePolicies extension is included.
    /// The inner `Option<String>` is `None` when no `id-qt-cps` qualifier
    /// (OID 1.3.6.1.5.5.7.2.1) is needed for that policy OID.
    pub certificate_policies: Vec<(String, Option<String>)>,
    /// When `true`, the ACME server issues an MTC `StandaloneCertificate`
    /// instead of a full X.509 PEM chain.  Requires `[mtc]` to be enabled in
    /// the server configuration; the finalization handler enforces this at
    /// request time and returns `InvalidProfile` if MTC is not active.
    pub issue_as_mtc: bool,
    /// Regex patterns that order identifiers must satisfy.  Each identifier is
    /// formatted as `"type:value"` (e.g. `"dns:example.com"`) before matching.
    /// Empty = no identifier restriction.
    pub allowed_identifier_patterns: Vec<String>,
    /// When `true`, ALL order identifiers must match at least one pattern in
    /// `allowed_identifier_patterns`.  When `false`, at least one identifier
    /// matching any pattern is sufficient.  Ignored when
    /// `allowed_identifier_patterns` is empty.
    pub identifier_match_all: bool,
    /// Path to an external authorization script.  `None` = no hook.
    /// Receives `{"account_id","profile","identifiers"}` on stdin; exit 0 = allow.
    pub auth_hook: Option<String>,
    /// Seconds before the auth hook subprocess is considered timed out.
    pub auth_hook_timeout_secs: u64,
    /// When `true`, the requesting account must have this profile listed in its
    /// `profile_grants` attribute (managed via the admin API or EAB metadata).
    pub require_account_grant: bool,
    /// CA IDs that this profile is restricted to.  Empty = available for all CAs.
    /// Populated from `BuiltinProfileConfig.ca_ids`; Dogtag/IPA profiles always
    /// use `vec![]` (no per-CA restriction).
    pub ca_ids: Vec<String>,
    /// KPN SAN templates expanded against the CSR's DNS SANs at issuance time.
    /// Each entry follows the syntax `"SERVICE/{dns}@REALM"` (NT-SRV-HST) or
    /// `"{dns}@REALM"` (NT-PRINCIPAL).  Templates without `{dns}` are static
    /// and injected exactly once.  See `ca::krb5_san::expand_kpn_template`.
    pub kpn_san_templates: Vec<String>,
    /// MS-UPN SAN template expanded against the first CSR DNS SAN.  Produces
    /// an OtherName SAN with OID 1.3.6.1.4.1.311.20.2.3 (UTF-8 UPN value).
    /// Use `{dns}` as a placeholder for the first DNS SAN, or a literal value
    /// for a static UPN that is always injected.
    pub ms_upn_san_template: Option<String>,
    /// When `true`, look up the account's stored Kerberos principal
    /// (`accounts.kerberos_principal`) and inject it as a KRB5PrincipalName
    /// OtherName SAN.  The principal is stored at account registration when the
    /// account is created via a GSSAPI-authenticated EAB key.
    pub inject_account_kpn: bool,
    /// JWKS endpoint URLs trusted for `kid`-signed authority tokens (RFC 9447).
    ///
    /// Empty = this profile does not accept `kid`-keyed authority tokens.
    /// Populated from `BuiltinProfileConfig.trust_jwks_urls`; non-builtin
    /// providers always carry an empty list.
    pub trust_jwks_urls: Vec<String>,
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
            issue_as_mtc: false,
            allowed_identifier_patterns: vec![],
            identifier_match_all: true,
            auth_hook: None,
            auth_hook_timeout_secs: 30,
            require_account_grant: false,
            ca_ids: vec![],
            kpn_san_templates: vec![],
            ms_upn_san_template: None,
            inject_account_kpn: false,
            trust_jwks_urls: vec![],
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
    /// DNS resolver address for SRV-based LDAP discovery.  `None` when no
    /// provider uses `srv_domain`.
    dns_resolver: Option<std::net::SocketAddr>,
}

impl ProfileRegistry {
    /// Build the registry and perform the initial profile load.
    ///
    /// Iterates all configured providers and loads their profiles.  Providers
    /// may perform filesystem or network I/O.  Returns `Err` if any provider
    /// returns a fatal error (for example, when the `dogtag` or `ipa` LDAP
    /// backend is configured but LDAP loading is not yet implemented).
    /// A provider that finds zero matching profiles is not an error.
    pub async fn new(cfg: &ProfilesConfig, ca: &CaState) -> Result<Arc<Self>, String> {
        let ca_defaults = CaDefaults::from_ca(ca);
        let dns_resolver = if needs_dns_resolver(cfg) {
            Some(crate::dns::system_resolver_addr())
        } else {
            None
        };
        let profiles = load_all_providers(cfg, &ca_defaults, dns_resolver).await?;

        let registry = Arc::new(Self {
            cache: RwLock::new(ProfileCache {
                profiles,
                loaded_at: Instant::now(),
            }),
            providers_cfg: cfg.clone(),
            ca_defaults,
            dns_resolver,
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
            dns_resolver: None,
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
        let profiles =
            load_all_providers(&self.providers_cfg, &self.ca_defaults, self.dns_resolver).await?;
        let count = profiles.len();
        {
            let mut cache = self.cache.write().unwrap_or_else(|e| e.into_inner());
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
            .unwrap_or_else(|e| e.into_inner())
            .profiles
            .get(profile_name)
            .map(|(_, p)| p.clone())
    }

    /// Return all `profile_id → description` pairs from the cache.
    ///
    /// Used to populate the ACME directory `meta.profiles` field
    /// (draft-ietf-acme-profiles-01).
    pub fn all_profiles(&self) -> HashMap<String, String> {
        self.cache
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .profiles
            .iter()
            .map(|(id, (desc, _))| (id.clone(), desc.clone()))
            .collect()
    }

    /// Return `profile_id → description` pairs available for a specific CA.
    ///
    /// A profile is available for `ca_id` when its `ca_ids` list is empty
    /// (unrestricted) or explicitly contains `ca_id`.
    pub fn profiles_for_ca(&self, ca_id: &str) -> HashMap<String, String> {
        self.cache
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .profiles
            .iter()
            .filter(|(_, (_, p))| p.ca_ids.is_empty() || p.ca_ids.iter().any(|id| id == ca_id))
            .map(|(id, (desc, _))| (id.clone(), desc.clone()))
            .collect()
    }

    /// Resolve a profile for a specific CA, respecting `ca_ids` restriction.
    ///
    /// Returns `None` when the profile does not exist or its `ca_ids` list
    /// does not include `ca_id`.
    pub fn resolve_for_ca(&self, profile_name: &str, ca_id: &str) -> Option<CertificateParameters> {
        self.cache
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .profiles
            .get(profile_name)
            .filter(|(_, p)| p.ca_ids.is_empty() || p.ca_ids.iter().any(|id| id == ca_id))
            .map(|(_, p)| p.clone())
    }

    /// Return `true` when no profiles are currently cached.
    pub fn is_empty(&self) -> bool {
        self.cache
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .profiles
            .is_empty()
    }

    /// Add a profile to the runtime cache (FPT_NPE_EXT.1).
    ///
    /// Returns `false` when a profile with the same `id` already exists.
    pub fn add_profile(
        &self,
        id: String,
        description: String,
        params: CertificateParameters,
    ) -> bool {
        let mut cache = self.cache.write().unwrap_or_else(|e| e.into_inner());
        if cache.profiles.contains_key(&id) {
            return false;
        }
        cache.profiles.insert(id, (description, params));
        true
    }

    /// Remove a profile from the runtime cache (FPT_NPE_EXT.1).
    ///
    /// Returns `true` when the profile existed and was removed.
    pub fn remove_profile(&self, id: &str) -> bool {
        self.cache
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .profiles
            .remove(id)
            .is_some()
    }

    /// Replace an existing profile in the runtime cache (FPT_NPE_EXT.1).
    ///
    /// Returns `true` when the profile existed and was updated.
    pub fn update_profile(
        &self,
        id: &str,
        description: String,
        params: CertificateParameters,
    ) -> bool {
        let mut cache = self.cache.write().unwrap_or_else(|e| e.into_inner());
        if let Some(entry) = cache.profiles.get_mut(id) {
            *entry = (description, params);
            true
        } else {
            false
        }
    }
}

// ── Internal loader ───────────────────────────────────────────────────────────

/// Load all providers and merge their profiles into a single map.
///
/// Providers are iterated in `HashMap` iteration order, which is not
/// deterministic across runs.  When the same profile ID appears in multiple
/// providers, the first provider encountered during this iteration wins and
/// later providers cannot overwrite it.  Keep profile IDs unique across
/// providers to avoid ambiguity, or treat one provider as the authoritative
/// source for each profile ID.
///
/// Returns `Err` if any provider returns a fatal loading error.
async fn load_all_providers(
    cfg: &ProfilesConfig,
    ca: &CaDefaults,
    resolver: Option<std::net::SocketAddr>,
) -> Result<HashMap<String, (String, CertificateParameters)>, String> {
    let mut merged: HashMap<String, (String, CertificateParameters)> = HashMap::new();

    for (provider_name, provider_cfg) in &cfg.providers {
        let loaded = match provider_cfg {
            ProviderConfig::Builtin(bcfg) => builtin::load_builtin(bcfg, ca),
            ProviderConfig::Dogtag(dcfg) => {
                dogtag::load_dogtag(provider_name, dcfg, ca, resolver).await?
            }
            ProviderConfig::Ipa(icfg) => ipa::load_ipa(provider_name, icfg, ca, resolver).await?,
        };

        let count = loaded.len();
        for (id, entry) in loaded {
            use std::collections::hash_map::Entry;
            match merged.entry(id.clone()) {
                Entry::Vacant(e) => {
                    e.insert(entry);
                }
                Entry::Occupied(_) => {
                    tracing::warn!(
                        "profiles: profile '{}' from provider '{}' skipped — \
                         already loaded by an earlier provider; \
                         keep profile IDs unique across providers to avoid ambiguity",
                        id,
                        provider_name,
                    );
                }
            }
        }
        tracing::info!(
            "profiles: provider '{}' contributed {} profile(s)",
            provider_name,
            count,
        );
    }

    Ok(merged)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::{CaState, MtcState};

    fn make_ca() -> CaState {
        CaState {
            id: "default".into(),
            key_type: "ec:P-256".into(),
            signing: crate::state::SigningBackend::Local {
                key: Box::new(synta_certificate::BackendPrivateKey::generate_ec("P-256").unwrap()),
            },
            cert_der: vec![],
            hash_alg: "sha256".into(),
            validity_days: 90,
            crl_url: None,
            ocsp_url: None,
            aki_bytes: vec![],
            enforce_validity_cap: false,
            crl_next_update_secs: 86400,
            caa_identities: vec![],
            mtc: Arc::new(MtcState::disabled()),
        }
    }

    fn empty_params(ca_ids: Vec<String>) -> CertificateParameters {
        use synta_certificate::KEY_USAGE_DIGITAL_SIGNATURE;
        CertificateParameters {
            validity_days: 90,
            hash_alg: "sha256".into(),
            key_usage_bits: 1u16 << KEY_USAGE_DIGITAL_SIGNATURE,
            extended_key_usages: vec!["server_auth".into()],
            crl_url: None,
            ocsp_url: None,
            allowed_key_types: vec![],
            certificate_policies: vec![],
            issue_as_mtc: false,
            allowed_identifier_patterns: vec![],
            identifier_match_all: true,
            auth_hook: None,
            auth_hook_timeout_secs: 30,
            require_account_grant: false,
            ca_ids,
            kpn_san_templates: vec![],
            ms_upn_san_template: None,
            inject_account_kpn: false,
            trust_jwks_urls: vec![],
        }
    }

    fn make_registry(
        profiles: HashMap<String, (String, CertificateParameters)>,
    ) -> Arc<ProfileRegistry> {
        let ca = make_ca();
        let reg = Arc::new(ProfileRegistry {
            cache: RwLock::new(ProfileCache {
                profiles,
                loaded_at: Instant::now(),
            }),
            providers_cfg: ProfilesConfig::default(),
            ca_defaults: CaDefaults::from_ca(&ca),
            dns_resolver: None,
        });
        reg
    }

    #[test]
    fn profiles_for_ca_unrestricted_appears_for_any_ca() {
        let mut profiles = HashMap::new();
        profiles.insert("global".into(), ("Global".into(), empty_params(vec![])));
        let reg = make_registry(profiles);

        let for_rsa = reg.profiles_for_ca("rsa");
        assert!(for_rsa.contains_key("global"));

        let for_ec = reg.profiles_for_ca("ec");
        assert!(for_ec.contains_key("global"));
    }

    #[test]
    fn profiles_for_ca_restricted_only_appears_for_matching_ca() {
        let mut profiles = HashMap::new();
        profiles.insert(
            "rsa-only".into(),
            ("RSA only".into(), empty_params(vec!["rsa".into()])),
        );
        let reg = make_registry(profiles);

        let for_rsa = reg.profiles_for_ca("rsa");
        assert!(for_rsa.contains_key("rsa-only"));

        let for_ec = reg.profiles_for_ca("ec");
        assert!(!for_ec.contains_key("rsa-only"));
    }

    #[test]
    fn resolve_for_ca_restricted_returns_none_for_wrong_ca() {
        let mut profiles = HashMap::new();
        profiles.insert(
            "ec-only".into(),
            ("EC only".into(), empty_params(vec!["ec".into()])),
        );
        let reg = make_registry(profiles);

        assert!(reg.resolve_for_ca("ec-only", "ec").is_some());
        assert!(reg.resolve_for_ca("ec-only", "rsa").is_none());
        assert!(reg.resolve_for_ca("ec-only", "default").is_none());
    }

    #[test]
    fn resolve_for_ca_unrestricted_resolves_for_any_ca() {
        let mut profiles = HashMap::new();
        profiles.insert("any".into(), ("Any CA".into(), empty_params(vec![])));
        let reg = make_registry(profiles);

        assert!(reg.resolve_for_ca("any", "rsa").is_some());
        assert!(reg.resolve_for_ca("any", "ec").is_some());
        assert!(reg.resolve_for_ca("any", "default").is_some());
    }

    #[test]
    fn resolve_for_ca_missing_profile_returns_none() {
        let reg = make_registry(HashMap::new());
        assert!(reg.resolve_for_ca("nonexistent", "default").is_none());
    }
}

/// Return `true` when at least one provider uses SRV-based LDAP discovery.
fn needs_dns_resolver(cfg: &ProfilesConfig) -> bool {
    cfg.providers.values().any(|p| match p {
        ProviderConfig::Dogtag(d) => d
            .ldap
            .as_ref()
            .map(|l| l.srv_domain.is_some())
            .unwrap_or(false),
        ProviderConfig::Ipa(i) => i
            .ldap
            .as_ref()
            .map(|l| l.srv_domain.is_some())
            .unwrap_or(false),
        ProviderConfig::Builtin(_) => false,
    })
}
