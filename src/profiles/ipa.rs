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
) -> Result<HashMap<String, (String, CertificateParameters)>, String> {
    if let Some(ldap_cfg) = &icfg.ldap {
        return load_from_ldap(provider_name, ldap_cfg, &icfg.profiles, ca).await;
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

/// Load profiles from the IPA Dogtag LDAP store via GSSAPI.
///
/// LDAP layout:
/// - Container: `ou=certificateProfiles,ou=ca,<base_dn>` (typically `o=ipaca`)
/// - Object class: `certProfile`
/// - Config attribute: `certProfileConfig` (raw `.cfg` bytes)
///
/// Search performed:
/// ```text
/// base:   ou=certificateProfiles,ou=ca,<base_dn>
/// scope:  one
/// filter: (objectClass=certProfile)
/// attrs:  cn, certProfileConfig
/// ```
///
/// Authentication: SASL GSSAPI.  If `keytab_file` and `principal` are set in
/// [`LdapConfig`][crate::config::LdapConfig], a TGT is obtained from the
/// keytab before connecting; otherwise the current ccache is used.
///
/// # Not yet implemented
///
/// GSSAPI LDAP requires an async LDAP client (e.g. `ldap3`) compiled with
/// SASL/GSSAPI support and linked against `libsasl2` + `libgssapi_krb5`.
/// The dependency has not been added yet; use `profile_dir` as a filesystem
/// fallback in the meantime.
async fn load_from_ldap(
    provider_name: &str,
    ldap_cfg: &crate::config::LdapConfig,
    _filter: &[String],
    _ca: &CaDefaults,
) -> Result<HashMap<String, (String, CertificateParameters)>, String> {
    let container_dn = format!(
        "ou=certificateProfiles,ou=ca,{}",
        ldap_cfg.base_dn
    );
    let auth_method = if ldap_cfg.gssapi {
        "SASL GSSAPI (Kerberos)"
    } else {
        "simple bind"
    };
    Err(format!(
        "profiles provider '{provider_name}' (ipa): \
         LDAP profile loading is not yet implemented \
         (would connect to '{}' with {auth_method}, \
         search '{container_dn}', filter '(objectClass=certProfile)', \
         attr 'certProfileConfig'); \
         configure 'profile_dir' as a filesystem fallback",
        ldap_cfg.uri
    ))
}
