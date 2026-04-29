//! Dogtag PKI profile provider.
//!
//! Reads Dogtag certificate profile definitions from the filesystem or from
//! Dogtag's LDAP store.  The actual certificate signing is always done by
//! akamu's own CA; this provider only supplies the issuance parameters.
//!
//! # Filesystem source
//!
//! Each profile is a `.cfg` file in `profile_dir` named `<profile_id>.cfg`.
//! The default location on a Dogtag installation is:
//! `/etc/pki/<instance>/ca/profiles/ca/`
//!
//! # LDAP source
//!
//! Profiles are searched at:
//! ```text
//! ou=certificateProfiles,ou=ca,<ldap.base_dn>
//! ```
//! Object class: `certProfile`
//! Config attribute: `certProfileConfig` (OCTET STRING, raw `.cfg` content)
//!
//! Authentication supports simple bind (`bind_dn` + `bind_password_file`)
//! and GSSAPI/Kerberos (`gssapi = true`).

use std::collections::HashMap;
use std::path::Path;

use hickory_resolver::TokioAsyncResolver;

use crate::config::DogtagProviderConfig;
use crate::profiles::{cfg, CaDefaults, CertificateParameters};

/// Load profiles from a Dogtag provider.
///
/// LDAP takes priority when configured; falls back to filesystem.
/// At least one of `ldap` or `profile_dir` must be set.
pub async fn load_dogtag(
    provider_name: &str,
    dcfg: &DogtagProviderConfig,
    ca: &CaDefaults,
    resolver: Option<&TokioAsyncResolver>,
) -> Result<HashMap<String, (String, CertificateParameters)>, String> {
    if let Some(ldap_cfg) = &dcfg.ldap {
        return load_from_ldap(provider_name, ldap_cfg, &dcfg.profiles, ca, resolver).await;
    }
    if let Some(dir) = &dcfg.profile_dir {
        return load_from_filesystem(provider_name, dir, &dcfg.profiles, ca);
    }
    Err(format!(
        "profiles provider '{provider_name}' (dogtag): \
         neither 'profile_dir' nor 'ldap' is configured"
    ))
}

// ── Filesystem loader ─────────────────────────────────────────────────────────

/// Load Dogtag certificate profiles from a directory of `.cfg` files.
///
/// Each file named `<profile_id>.cfg` in `profile_dir` is read and parsed by
/// [`crate::profiles::cfg::parse_and_translate`].  When `filter` is non-empty,
/// only profile IDs listed in `filter` are loaded; an empty `filter` loads all
/// `.cfg` files found.  Files that cannot be read or that fail to parse are
/// logged at `WARN` level and skipped — they do not cause the entire load to
/// fail.
///
/// This function is `pub(crate)` so that the `ipa` provider can reuse it for
/// its filesystem fallback path, because IPA profile `.cfg` files use the same
/// Dogtag Java-properties format.
pub(crate) fn load_from_filesystem(
    provider_name: &str,
    profile_dir: &str,
    filter: &[String],
    ca: &CaDefaults,
) -> Result<HashMap<String, (String, CertificateParameters)>, String> {
    let dir = Path::new(profile_dir);
    if !dir.is_dir() {
        return Err(format!(
            "profiles provider '{provider_name}': \
             profile_dir '{profile_dir}' does not exist or is not a directory"
        ));
    }

    let mut out = HashMap::new();

    let entries = std::fs::read_dir(dir).map_err(|e| {
        format!(
            "profiles provider '{provider_name}': \
             cannot read profile_dir '{profile_dir}': {e}"
        )
    })?;

    for entry in entries {
        let entry = entry.map_err(|e| {
            format!("profiles provider '{provider_name}': directory entry error: {e}")
        })?;
        let path = entry.path();

        // Only process `.cfg` files.
        if path.extension().and_then(|e| e.to_str()) != Some("cfg") {
            continue;
        }

        let profile_id = match path.file_stem().and_then(|s| s.to_str()) {
            Some(s) => s.to_string(),
            None => continue,
        };

        // Apply the profile filter if one is configured.
        if !filter.is_empty() && !filter.iter().any(|f| f == &profile_id) {
            continue;
        }

        let content = match std::fs::read_to_string(&path) {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(
                    "profiles provider '{}': cannot read '{}': {}; skipped",
                    provider_name,
                    path.display(),
                    e
                );
                continue;
            }
        };

        match cfg::parse_and_translate(&content, &profile_id, ca) {
            Ok((desc, params)) => {
                out.insert(profile_id, (desc, params));
            }
            Err(e) => {
                tracing::warn!(
                    "profiles provider '{}': skipping '{}': {}",
                    provider_name,
                    profile_id,
                    e
                );
            }
        }
    }

    Ok(out)
}

// ── LDAP loader ───────────────────────────────────────────────────────────────

async fn load_from_ldap(
    provider_name: &str,
    ldap_cfg: &crate::config::LdapConfig,
    filter: &[String],
    ca: &CaDefaults,
    resolver: Option<&TokioAsyncResolver>,
) -> Result<HashMap<String, (String, CertificateParameters)>, String> {
    crate::profiles::ldap_session::load_profiles_from_ldap(
        provider_name,
        "dogtag",
        ldap_cfg,
        filter,
        ca,
        resolver,
    )
    .await
}
