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
    resolver: Option<std::net::SocketAddr>,
) -> Result<HashMap<String, (String, CertificateParameters)>, String> {
    if let Some(ldap_cfg) = &dcfg.ldap {
        return load_from_ldap(provider_name, ldap_cfg, &dcfg.profiles, ca, resolver).await;
    }
    if let Some(dir) = &dcfg.profile_dir {
        // Directory scan + per-file reads are blocking I/O; run them on the
        // blocking pool instead of the async profile-load task.
        let provider_name = provider_name.to_string();
        let dir = dir.clone();
        let filter = dcfg.profiles.clone();
        let ca = ca.clone();
        return tokio::task::spawn_blocking(move || {
            load_from_filesystem(&provider_name, &dir, &filter, &ca)
        })
        .await
        .map_err(|e| format!("profile_dir load task panicked: {e}"))?;
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
    resolver: Option<std::net::SocketAddr>,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::DogtagProviderConfig;

    fn default_ca() -> CaDefaults {
        CaDefaults {
            validity_days: 90,
            hash_alg: "sha256".to_string(),
            crl_url: None,
            ocsp_url: None,
        }
    }

    const SAMPLE_CFG: &str = r#"
name=Server Cert
policyset.list=serverCertSet
policyset.serverCertSet.list=1
policyset.serverCertSet.1.default.class_id=validityDefaultImpl
policyset.serverCertSet.1.default.params.range=180
policyset.serverCertSet.1.default.params.rangeUnit=day
"#;

    /// Regression test for the directory scan + file reads running on
    /// tokio's blocking pool (`spawn_blocking`) instead of directly on the
    /// async task: the loaded profile must still come back correctly through
    /// the `JoinHandle`.
    #[tokio::test]
    async fn load_dogtag_filesystem_reads_cfg_files_via_blocking_pool() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("caServerCert.cfg"), SAMPLE_CFG).unwrap();
        // Non-.cfg files must be ignored.
        std::fs::write(dir.path().join("README"), "not a profile").unwrap();

        let dcfg = DogtagProviderConfig {
            profile_dir: Some(dir.path().to_string_lossy().to_string()),
            ldap: None,
            profiles: vec![],
        };

        let result = load_dogtag("dogtag-test", &dcfg, &default_ca(), None)
            .await
            .unwrap();
        assert_eq!(result.len(), 1);
        let (desc, _params) = result.get("caServerCert").unwrap();
        assert_eq!(desc, "Server Cert");
    }

    #[tokio::test]
    async fn load_dogtag_filesystem_missing_dir_returns_err() {
        let dcfg = DogtagProviderConfig {
            profile_dir: Some("/nonexistent/path/for/akamu/tests".to_string()),
            ldap: None,
            profiles: vec![],
        };
        let result = load_dogtag("dogtag-test", &dcfg, &default_ca(), None).await;
        assert!(result.is_err());
    }
}
