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
use crate::profiles::{cfg, CaDefaults, CertificateParameters};

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

/// Load profiles from the IPA-embedded Dogtag LDAP store.
///
/// Performs a one-level LDAP search:
///
/// ```text
/// base:   ou=certificateProfiles,ou=ca,<base_dn>   (typically o=ipaca)
/// scope:  one
/// filter: (objectClass=certProfile)
/// attrs:  cn, certProfileConfig
/// ```
///
/// Simple bind is supported when `gssapi = false` (requires `bind_dn` and
/// `bind_password_file`).  GSSAPI/Kerberos authentication (`gssapi = true`)
/// uses the Kerberos TGT from the current credential cache.
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
                "profiles provider '{provider_name}' (ipa): \
                 'bind_dn' is required for simple bind LDAP authentication"
            )
        })?;
        let pw_file = ldap_cfg.bind_password_file.as_deref().ok_or_else(|| {
            format!(
                "profiles provider '{provider_name}' (ipa): \
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
    let conn = AsyncLdapConnection::connect(&uri_str, tls_ca, ldap_cfg.starttls, ldap_cfg.timeout_secs)
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
