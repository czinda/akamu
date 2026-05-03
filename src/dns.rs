//! Thin DNS query helper built on hickory-client.
//!
//! `hickory-resolver` 0.25 (available in Fedora) has an incompatible API with
//! the 0.24 we require, so we use `hickory-client` 0.24 directly.  Each call
//! to [`dns_query`] opens a new UDP socket, sends one query, and closes the
//! socket — matching the per-request socket model used by hickory-resolver's
//! UDP transport internally.

use std::net::SocketAddr;

use hickory_client::client::{AsyncClient, AsyncDnssecClient, ClientHandle};
use hickory_client::op::DnsResponse;
use hickory_client::proto::rr::{DNSClass, Name, RecordType};
use hickory_client::proto::udp::UdpClientStream;
use tokio::net::UdpSocket;

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

/// Send a single DNS query over UDP and return the full DNS response.
///
/// When `validate_dnssec` is `true`, [`AsyncDnssecClient`] is used, which
/// validates DNSSEC signatures locally against the built-in root trust anchor.
/// When `false`, a plain [`AsyncClient`] is used.
///
/// A new UDP socket is created per call (matches hickory's internal model for
/// cache-poisoning resistance).
pub async fn dns_query(
    server_addr: SocketAddr,
    validate_dnssec: bool,
    name: Name,
    record_type: RecordType,
) -> Result<DnsResponse, AcmeError> {
    let stream = UdpClientStream::<UdpSocket>::new(server_addr);

    if validate_dnssec {
        let (mut client, bg) = AsyncDnssecClient::connect(stream)
            .await
            .map_err(|e| AcmeError::Dns(format!("DNS connect to {server_addr}: {e}")))?;
        tokio::spawn(bg);
        client
            .query(name, DNSClass::IN, record_type)
            .await
            .map_err(|e| AcmeError::Dns(format!("DNS query to {server_addr}: {e}")))
    } else {
        let (mut client, bg) = AsyncClient::connect(stream)
            .await
            .map_err(|e| AcmeError::Dns(format!("DNS connect to {server_addr}: {e}")))?;
        tokio::spawn(bg);
        client
            .query(name, DNSClass::IN, record_type)
            .await
            .map_err(|e| AcmeError::Dns(format!("DNS query to {server_addr}: {e}")))
    }
}
