//! Thin DNS query helper built on hickory-client.
//!
//! `hickory-resolver` 0.25 (available in Fedora) has an incompatible API with
//! the 0.24 we require, so we use `hickory-client` 0.24 directly.  Each call
//! to [`dns_query`] opens a new socket, sends one query, and closes it.
//!
//! When `dot_server_name` is `Some`, queries are sent over DNS-over-TLS
//! (DoT, RFC 7858) using the system OpenSSL via the `native-tls` crate.
//! The TLS certificate is verified against the system root CA store.

use std::net::SocketAddr;

use hickory_client::client::{AsyncClient, AsyncDnssecClient, ClientHandle};
use hickory_client::op::DnsResponse;
use hickory_client::proto::iocompat::AsyncIoTokioAsStd;
use hickory_client::proto::native_tls::TlsClientStreamBuilder;
use hickory_client::proto::rr::{DNSClass, Name, RecordType};
use hickory_client::proto::udp::UdpClientStream;
use hickory_client::proto::DnssecDnsHandle;
use tokio::net::{TcpStream, UdpSocket};

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

/// Send a single DNS query and return the full DNS response.
///
/// When `dot_server_name` is `Some(hostname)`, the query is sent over
/// DNS-over-TLS (DoT, RFC 7858) to `server_addr` using `hostname` for
/// TLS SNI and certificate verification.  When `None`, plain UDP is used.
///
/// When `validate_dnssec` is `true`, DNSSEC signatures are validated
/// against the built-in ICANN root trust anchor regardless of transport.
pub async fn dns_query(
    server_addr: SocketAddr,
    validate_dnssec: bool,
    dot_server_name: Option<&str>,
    name: Name,
    record_type: RecordType,
) -> Result<DnsResponse, AcmeError> {
    if let Some(sni) = dot_server_name {
        dot_query(server_addr, sni, validate_dnssec, name, record_type).await
    } else {
        udp_query(server_addr, validate_dnssec, name, record_type).await
    }
}

async fn udp_query(
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

async fn dot_query(
    server_addr: SocketAddr,
    sni: &str,
    validate_dnssec: bool,
    name: Name,
    record_type: RecordType,
) -> Result<DnsResponse, AcmeError> {
    let builder = TlsClientStreamBuilder::<AsyncIoTokioAsStd<TcpStream>>::new();
    let (stream_future, sender) = builder.build(server_addr, sni.to_owned());
    let (plain_client, bg) = AsyncClient::new(stream_future, sender, None)
        .await
        .map_err(|e| AcmeError::Dns(format!("DoT connect to {server_addr}: {e}")))?;
    tokio::spawn(bg);

    if validate_dnssec {
        let mut client = DnssecDnsHandle::new(plain_client);
        client
            .query(name, DNSClass::IN, record_type)
            .await
            .map_err(|e| AcmeError::Dns(format!("DoT query to {server_addr}: {e}")))
    } else {
        let mut client = plain_client;
        client
            .query(name, DNSClass::IN, record_type)
            .await
            .map_err(|e| AcmeError::Dns(format!("DoT query to {server_addr}: {e}")))
    }
}
