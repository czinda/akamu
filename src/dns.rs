//! Thin DNS query helper built on hickory-resolver.
//!
//! Each call to [`dns_query`] creates a single-shot [`TokioAsyncResolver`]
//! pointing at the configured nameserver, performs one query, and returns
//! the result.  No connection pooling is done; the resolver is cheap to
//! construct and its background task exits as soon as the query completes.
//!
//! When `dot_server_name` is `Some`, queries are sent over DNS-over-TLS
//! (DoT, RFC 7858) using system OpenSSL via the `native-tls` crate.
//! The TLS certificate is verified against the system root CA store.

use std::net::SocketAddr;

use hickory_resolver::config::{NameServerConfig, Protocol, ResolverConfig, ResolverOpts};
use hickory_resolver::error::ResolveErrorKind;
use hickory_resolver::lookup::Lookup;
use hickory_resolver::proto::op::ResponseCode;
use hickory_resolver::proto::rr::{Name, RecordType};
use hickory_resolver::TokioAsyncResolver;

use crate::error::AcmeError;

/// Return the first nameserver address from `/etc/resolv.conf`, or the
/// systemd-resolved stub listener (`127.0.0.53:53`) as a fallback.
pub fn system_resolver_addr() -> SocketAddr {
    if let Ok(contents) = std::fs::read_to_string("/etc/resolv.conf") {
        for line in contents.lines() {
            let line = line.trim();
            if let Some(rest) = line.strip_prefix("nameserver") {
                if let Ok(ip) = rest.trim().parse::<std::net::IpAddr>() {
                    return SocketAddr::new(ip, 53);
                }
            }
        }
    }
    "127.0.0.53:53".parse().expect("hardcoded addr is valid")
}

/// Send a single DNS query and return the result.
///
/// Returns:
/// - `Ok(Some(lookup))` — records found (NOERROR with answers).
/// - `Ok(None)` — no records (NXDOMAIN or NOERROR with empty answer section);
///   callers that walk up the DNS tree treat this as "no constraint at this label".
/// - `Err(AcmeError::Dns(...))` — DNS failure (SERVFAIL, REFUSED, network
///   error, DNSSEC validation failure); callers must treat this as a hard error.
///
/// When `dot_server_name` is `Some(hostname)`, queries use DNS-over-TLS
/// (port 853) with `hostname` as the TLS SNI and certificate CN to verify.
/// `server_addr` must point at port 853 when using DoT.
///
/// When `validate_dnssec` is `true`, DNSSEC signatures are validated against
/// the built-in ICANN root trust anchor.
pub async fn dns_query(
    server_addr: SocketAddr,
    validate_dnssec: bool,
    dot_server_name: Option<&str>,
    name: Name,
    record_type: RecordType,
) -> Result<Option<Lookup>, AcmeError> {
    let resolver = build_resolver(server_addr, validate_dnssec, dot_server_name)?;

    match resolver.lookup(name.clone(), record_type).await {
        Ok(lookup) => Ok(Some(lookup)),
        Err(e) => match e.kind() {
            ResolveErrorKind::NoRecordsFound { response_code, .. } => {
                match response_code {
                    // Benign: domain or record type does not exist — tell the
                    // caller "no records" so it can decide (e.g. walk up the tree).
                    ResponseCode::NXDomain | ResponseCode::NoError => Ok(None),
                    // Hard failure: SERVFAIL, REFUSED, malformed response, etc.
                    rcode => Err(AcmeError::Dns(format!(
                        "DNS {rcode} querying {record_type} for {name}: {e}"
                    ))),
                }
            }
            _ => Err(AcmeError::Dns(format!(
                "DNS error querying {record_type} for {name}: {e}"
            ))),
        },
    }
}

fn build_resolver(
    server_addr: SocketAddr,
    validate_dnssec: bool,
    dot_server_name: Option<&str>,
) -> Result<TokioAsyncResolver, AcmeError> {
    let protocol = if dot_server_name.is_some() {
        Protocol::Tls
    } else {
        Protocol::Udp
    };
    let mut ns = NameServerConfig::new(server_addr, protocol);
    ns.tls_dns_name = dot_server_name.map(str::to_owned);

    let mut config = ResolverConfig::new();
    config.add_name_server(ns);

    let mut opts = ResolverOpts::default();
    opts.validate = validate_dnssec;

    Ok(TokioAsyncResolver::tokio(config, opts))
}
