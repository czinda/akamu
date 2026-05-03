//! FreeIPA / IPAThinCA profile provider.
//!
//! Reads certificate profile definitions from a FreeIPA deployment.
//! IPAThinCA stores profiles in the same Dogtag Java-properties `.cfg` format
//! under Dogtag's internal LDAP database (`o=ipaca`).
//!
//! # LDAP source
//!
//! Profiles are stored at:
//! ```text
//! ou=certificateProfiles,ou=ca,o=ipaca
//! ```
//! on the IPA-embedded Dogtag LDAP instance (default port 7389).
//!
//! Object class: `certProfile`
//! Config attribute: `certProfileConfig` (OCTET STRING, raw `.cfg` bytes)
//!
//! Authentication uses SASL GSSAPI (Kerberos).  Set `gssapi = true` in the
//! `[profiles.providers.<name>.ldap]` section.  Provide `keytab_file` and
//! `principal` to obtain a TGT before connecting, or rely on the current
//! Kerberos credential cache when running in a Kerberos-enabled environment.
//!
//! # Filesystem fallback
//!
//! IPAThinCA profile `.cfg` files can be exported to a directory on disk.
//! Point `profile_dir` at the export location to use the filesystem source
//! instead of (or while waiting for) LDAP support.

use std::collections::HashMap;

use crate::config::IpaProviderConfig;
use crate::profiles::{CaDefaults, CertificateParameters};

/// Load profiles from an IPA / IPAThinCA provider.
///
/// LDAP takes priority when configured; falls back to the filesystem.
/// At least one of `ldap` or `profile_dir` must be set.
pub async fn load_ipa(
    provider_name: &str,
    icfg: &IpaProviderConfig,
    ca: &CaDefaults,
    resolver: Option<std::net::SocketAddr>,
) -> Result<HashMap<String, (String, CertificateParameters)>, String> {
    if let Some(ldap_cfg) = &icfg.ldap {
        return load_from_ldap(provider_name, ldap_cfg, &icfg.profiles, ca, resolver).await;
    }
    if let Some(dir) = &icfg.profile_dir {
        // The IPA provider uses the same `.cfg` format as Dogtag; reuse the
        // filesystem loader from the `dogtag` module.
        return crate::profiles::dogtag::load_from_filesystem(
            provider_name,
            dir,
            &icfg.profiles,
            ca,
        );
    }
    Err(format!(
        "profiles provider '{provider_name}' (ipa): \
         neither 'profile_dir' nor 'ldap' is configured"
    ))
}

// ── LDAP loader ───────────────────────────────────────────────────────────────

async fn load_from_ldap(
    provider_name: &str,
    ldap_cfg: &crate::config::LdapConfig,
    filter: &[String],
    ca: &CaDefaults,
    resolver: Option<std::net::SocketAddr>,
) -> Result<HashMap<String, (String, CertificateParameters)>, String> {
    crate::profiles::ldap_session::load_profiles_from_ldap(
        provider_name,
        "ipa",
        ldap_cfg,
        filter,
        ca,
        resolver,
    )
    .await
}
