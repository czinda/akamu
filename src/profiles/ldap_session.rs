//! Shared LDAP session helper for profile loading.
//!
//! Both the Dogtag and IPA providers perform the same connect→bind→search→parse
//! loop.  This module contains the shared implementation so the two callers
//! don't carry identical copies of ~130 lines.

use std::collections::HashMap;

use akamu_ldap::{AsyncLdapConnection, Auth, Scope};

use crate::config::LdapConfig;
use crate::profiles::{cfg, CaDefaults, CertificateParameters};

/// Connect to the LDAP directory, search `ou=certificateProfiles,ou=ca,<base_dn>`,
/// and parse every returned entry into a [`CertificateParameters`].
///
/// `kind` is a short backend label (e.g. `"dogtag"` or `"ipa"`) used in
/// error messages to identify which provider configuration is at fault.
///
/// `resolver` is the shared DNS resolver from `ProfileRegistry`; forwarded to
/// SRV discovery so no new resolver is allocated per refresh cycle.
pub(crate) async fn load_profiles_from_ldap(
    provider_name: &str,
    kind: &str,
    ldap_cfg: &LdapConfig,
    filter: &[String],
    ca: &CaDefaults,
    resolver: Option<std::net::SocketAddr>,
) -> Result<HashMap<String, (String, CertificateParameters)>, String> {
    let auth = if ldap_cfg.gssapi {
        Auth::Gssapi
    } else {
        let bind_dn = ldap_cfg.bind_dn.as_deref().ok_or_else(|| {
            format!(
                "profiles provider '{provider_name}' ({kind}): \
                 'bind_dn' is required for simple bind LDAP authentication"
            )
        })?;
        let pw_file = ldap_cfg.bind_password_file.as_deref().ok_or_else(|| {
            format!(
                "profiles provider '{provider_name}' ({kind}): \
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

    let uri_str =
        crate::profiles::ldap_resolve::resolve_ldap_uris(ldap_cfg, provider_name, resolver).await?;
    let tls_ca = ldap_cfg.tls_ca_cert_file.as_deref();
    let conn =
        AsyncLdapConnection::connect(&uri_str, tls_ca, ldap_cfg.starttls, ldap_cfg.timeout_secs)
            .await
            .map_err(|e| {
                format!(
                    "profiles provider '{provider_name}': \
                     LDAP connect to '{uri_str}': {e}"
                )
            })?;
    conn.bind(auth)
        .await
        .map_err(|e| format!("profiles provider '{provider_name}': LDAP bind: {e}"))?;

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
        let profile_id = match entry.attrs.get("cn").and_then(|v| v.first()) {
            Some(id) => id.clone(),
            None => {
                tracing::warn!(
                    provider = %provider_name,
                    dn = %entry.dn,
                    "profiles provider: LDAP entry missing 'cn'; skipped"
                );
                continue;
            }
        };

        if !filter.is_empty() && !filter.iter().any(|f| f == &profile_id) {
            continue;
        }

        // certProfileConfig may be stored as OCTET STRING (binary) in some LDAP schemas.
        let cfg_content = if let Some(bytes) = entry
            .bin_attrs
            .get("certprofileconfig")
            .and_then(|v| v.first())
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
