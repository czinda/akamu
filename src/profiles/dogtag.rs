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
) -> Result<HashMap<String, (String, CertificateParameters)>, String> {
    if let Some(ldap_cfg) = &dcfg.ldap {
        return load_from_ldap(provider_name, ldap_cfg, &dcfg.profiles, ca).await;
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

/// Load profiles from Dogtag's LDAP store.
///
/// Performs a one-level LDAP search:
///
/// ```text
/// base:   ou=certificateProfiles,ou=ca,<base_dn>
/// scope:  one
/// filter: (objectClass=certProfile)
/// attrs:  cn, certProfileConfig
/// ```
///
/// Authentication supports simple bind (`bind_dn` + `bind_password_file`)
/// and GSSAPI/Kerberos (`gssapi = true`).
async fn load_from_ldap(
    provider_name: &str,
    ldap_cfg: &crate::config::LdapConfig,
    filter: &[String],
    ca: &CaDefaults,
) -> Result<HashMap<String, (String, CertificateParameters)>, String> {
    use akamu_ldap::{AsyncLdapConnection, Auth, Scope};

    let auth = if ldap_cfg.gssapi {
        Auth::Gssapi
    } else {
        let bind_dn = ldap_cfg.bind_dn.as_deref().ok_or_else(|| {
            format!(
                "profiles provider '{provider_name}' (dogtag): \
                 'bind_dn' is required for simple bind LDAP authentication"
            )
        })?;
        let pw_file = ldap_cfg.bind_password_file.as_deref().ok_or_else(|| {
            format!(
                "profiles provider '{provider_name}' (dogtag): \
                 'bind_password_file' is required when 'bind_dn' is set"
            )
        })?;
        let bind_password = std::fs::read_to_string(pw_file).map_err(|e| {
            format!(
                "profiles provider '{provider_name}': \
                 read bind_password_file '{pw_file}': {e}"
            )
        })?;
        let bind_password = bind_password
            .trim_end_matches('\n')
            .trim_end_matches('\r')
            .to_owned();
        Auth::Simple {
            bind_dn: bind_dn.to_owned(),
            password: bind_password,
        }
    };

    let uri_str = crate::profiles::ldap_resolve::resolve_ldap_uris(ldap_cfg, provider_name).await?;
    let tls_ca = ldap_cfg.tls_ca_cert_file.as_deref();
    let conn = AsyncLdapConnection::connect(&uri_str, tls_ca, ldap_cfg.starttls)
        .await
        .map_err(|e| {
            format!(
                "profiles provider '{provider_name}': \
                 LDAP connect to '{uri_str}': {e}"
            )
        })?;
    conn.bind(auth).await.map_err(|e| {
        format!("profiles provider '{provider_name}': LDAP bind: {e}")
    })?;

    let base = format!("ou=certificateProfiles,ou=ca,{}", ldap_cfg.base_dn);
    let entries = conn
        .search(
            &base,
            Scope::OneLevel,
            "(objectClass=certProfile)",
            vec!["cn".into(), "certProfileConfig".into()],
        )
        .await
        .map_err(|e| {
            format!(
                "profiles provider '{provider_name}': \
                 LDAP search '{base}': {e}"
            )
        })?;

    let mut out = HashMap::new();
    for entry in entries {
        // akamu-ldap lowercases all attribute names.
        let profile_id = match entry.attrs.get("cn").and_then(|v| v.first()) {
            Some(id) => id.clone(),
            None => {
                tracing::warn!(
                    "profiles provider '{}': LDAP entry missing 'cn'; skipped",
                    provider_name
                );
                continue;
            }
        };

        if !filter.is_empty() && !filter.iter().any(|f| f == &profile_id) {
            continue;
        }

        // certProfileConfig is stored as OCTET STRING (binary) in Dogtag LDAP.
        let cfg_content = if let Some(bytes) =
            entry.bin_attrs.get("certprofileconfig").and_then(|v| v.first())
        {
            match std::str::from_utf8(bytes) {
                Ok(s) => s.to_string(),
                Err(_) => {
                    tracing::warn!(
                        "profiles provider '{}': certProfileConfig for '{}' \
                         is not valid UTF-8; skipped",
                        provider_name,
                        profile_id
                    );
                    continue;
                }
            }
        } else if let Some(s) = entry.attrs.get("certprofileconfig").and_then(|v| v.first()) {
            s.clone()
        } else {
            tracing::warn!(
                "profiles provider '{}': LDAP entry '{}' missing 'certProfileConfig'; skipped",
                provider_name,
                profile_id
            );
            continue;
        };

        match cfg::parse_and_translate(&cfg_content, &profile_id, ca) {
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
