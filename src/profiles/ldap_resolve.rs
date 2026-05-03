//! Resolve the set of LDAP server URIs to try for a given [`LdapConfig`].
//!
//! Two sources are merged:
//!
//! 1. **Explicit** — `uri` / `uris` fields in the config, used as-is.
//! 2. **SRV discovery** — when `srv_domain` is set, `_ldap._tcp.{srv_domain}`
//!    SRV records are queried and sorted per RFC 2782 (ascending priority,
//!    descending weight within each priority group).
//!
//! The resulting ordered list is joined with spaces and passed to
//! `ldap_initialize`, which tries each URI in turn for failover.

use std::net::SocketAddr;
use std::str::FromStr;

use hickory_client::proto::rr::{Name, RData, RecordType};

use crate::config::LdapConfig;

/// Return an ordered, space-joined URI string suitable for `ldap_initialize`.
///
/// Explicit URIs (`uri` / `uris`) are listed first; SRV-discovered servers are
/// appended after them.  Returns an error if no servers can be determined.
///
/// `resolver` is the shared DNS resolver from `ProfileRegistry`; when `None`
/// (e.g. during unit tests or when called outside the registry), a one-shot
/// resolver is created for the duration of this call.
pub async fn resolve_ldap_uris(
    cfg: &LdapConfig,
    provider_name: &str,
    resolver: Option<SocketAddr>,
) -> Result<String, String> {
    let mut uris: Vec<String> = Vec::new();

    // Explicit single URI (backward-compatible field).
    if let Some(u) = &cfg.uri {
        uris.push(u.clone());
    }
    // Explicit list.
    uris.extend(cfg.uris.iter().cloned());

    // SRV-based discovery appended after explicit servers.
    // Failure to resolve SRV is non-fatal when explicit URIs are available;
    // the operator may have configured fallback URIs precisely for this case.
    if let Some(domain) = &cfg.srv_domain {
        match resolve_srv(domain, &cfg.srv_scheme, provider_name, resolver).await {
            Ok(discovered) => uris.extend(discovered),
            Err(e) if !uris.is_empty() => {
                tracing::warn!("{e}; continuing with explicitly configured URIs");
            }
            Err(e) => return Err(e),
        }
    }

    if uris.is_empty() {
        return Err(format!(
            "profiles provider '{provider_name}': no LDAP servers configured; \
             set 'uri', 'uris', or 'srv_domain'"
        ));
    }

    Ok(uris.join(" "))
}

/// Resolve `_ldap._tcp.{domain}` SRV records and return URIs with `scheme`
/// ordered by priority (ascending) then weight (descending).  RFC 2782
/// requires weighted-random selection within a priority group; this
/// implementation uses a deterministic sort instead, which is simpler and
/// sufficient for typical LDAP topologies where servers within a priority
/// group are equivalent.
///
/// A lookup that returns zero SRV records is not treated as an error.
async fn resolve_srv(
    domain: &str,
    scheme: &str,
    provider_name: &str,
    resolver: Option<SocketAddr>,
) -> Result<Vec<String>, String> {
    let addr = resolver.unwrap_or_else(crate::dns::system_resolver_addr);

    let srv_name = format!("_ldap._tcp.{domain}.");
    let fqdn = Name::from_str(&srv_name).map_err(|e| {
        format!(
            "profiles provider '{provider_name}': \
             invalid SRV name '{srv_name}': {e}"
        )
    })?;
    let resp = crate::dns::dns_query(addr, false, fqdn, RecordType::SRV)
        .await
        .map_err(|e| {
            format!(
                "profiles provider '{provider_name}': \
                 SRV lookup '{srv_name}': {e}"
            )
        })?;

    // Collect (priority, weight, uri) tuples.
    let mut records: Vec<(u16, u16, String)> = resp
        .answers()
        .iter()
        .filter_map(|answer| {
            if let Some(RData::SRV(srv)) = answer.data() {
                let host = srv.target().to_utf8();
                let host = host.trim_end_matches('.');
                let uri = format!("{scheme}://{host}:{}", srv.port());
                Some((srv.priority(), srv.weight(), uri))
            } else {
                None
            }
        })
        .collect();

    // Ascending priority; within the same priority, descending weight (higher
    // weight = more preferred = listed earlier so ldap_initialize tries it first).
    records.sort_by(|a, b| a.0.cmp(&b.0).then(b.1.cmp(&a.1)));

    Ok(records.into_iter().map(|(_, _, uri)| uri).collect())
}
