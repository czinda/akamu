/// Build `HTTP@<hostname>` from a server URL for use as a GSSAPI SPN.
///
/// If the host portion of the URL is an IP address or a loopback name
/// ("localhost", "localhost.localdomain", "ip6-localhost", etc.):
/// - Loopback addresses / names are replaced with the machine's own FQDN.
/// - Other IPs are resolved to a hostname via reverse PTR lookup.
///
/// If reverse DNS fails, the raw IP is used and a warning is printed.
pub(crate) async fn derive_spn(url: &str) -> String {
    if url.starts_with("http+unix://") {
        // Unix socket: the admin server is on this machine.
        let host = system_fqdn()
            .await
            .unwrap_or_else(|| "localhost".to_owned());
        return format!("HTTP@{host}");
    }
    let host = url
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .split('/')
        .next()
        .unwrap_or(url)
        .split(':') // strip port
        .next()
        .unwrap_or(url);
    format!("HTTP@{}", resolve_host_for_spn(host).await)
}

/// Resolve a URL host component to a hostname suitable for a Kerberos SPN.
async fn resolve_host_for_spn(host: &str) -> String {
    use std::net::IpAddr;

    // Loopback hostnames — replace with the machine's own FQDN.
    let is_loopback_name = matches!(
        host,
        "localhost" | "localhost.localdomain" | "ip6-localhost" | "ip6-loopback"
    );
    if is_loopback_name {
        return system_fqdn().await.unwrap_or_else(|| host.to_owned());
    }

    // If the host is an IP address, perform loopback check or reverse PTR lookup.
    if let Ok(ip) = host.parse::<IpAddr>() {
        if ip.is_loopback() {
            return system_fqdn().await.unwrap_or_else(|| host.to_owned());
        }
        return ptr_lookup(ip).await.unwrap_or_else(|| {
            eprintln!("warning: reverse DNS for {ip} failed; SPN will use the IP address");
            host.to_owned()
        });
    }

    // Already a proper DNS hostname.
    host.to_owned()
}

/// Return the machine's fully-qualified hostname via `gethostname(2)`.
///
/// If the result contains no dot (a bare short name), performs a forward
/// lookup and then a reverse PTR lookup via hickory-resolver to obtain the FQDN.
async fn system_fqdn() -> Option<String> {
    use std::ffi::CStr;
    let mut buf = [0u8; 256];
    let ret = unsafe { libc::gethostname(buf.as_mut_ptr().cast(), buf.len()) };
    if ret != 0 {
        return None;
    }
    let name = CStr::from_bytes_until_nul(&buf)
        .ok()?
        .to_str()
        .ok()?
        .to_owned();
    if name.contains('.') {
        return Some(name);
    }
    // Short hostname — forward lookup then PTR to get the FQDN.
    let resolver = build_resolver();
    let lookup = resolver.lookup_ip(name.as_str()).await.ok()?;
    for ip in lookup {
        if let Some(fqdn) = ptr_lookup_with(ip, &resolver).await {
            if fqdn.contains('.') {
                return Some(fqdn);
            }
        }
    }
    Some(name)
}

/// Reverse-resolve an IP address to a hostname via a DNS PTR query.
async fn ptr_lookup(ip: std::net::IpAddr) -> Option<String> {
    ptr_lookup_with(ip, &build_resolver()).await
}

async fn ptr_lookup_with(
    ip: std::net::IpAddr,
    resolver: &hickory_resolver::TokioAsyncResolver,
) -> Option<String> {
    let lookup = resolver.reverse_lookup(ip).await.ok()?;
    let name = lookup.into_iter().next()?;
    let s = name.to_utf8();
    let s = s.trim_end_matches('.');
    if s.is_empty() || s == ip.to_string() {
        None
    } else {
        Some(s.to_owned())
    }
}

/// Build a hickory resolver pointed at the system nameserver.
fn build_resolver() -> hickory_resolver::TokioAsyncResolver {
    use hickory_resolver::config::{NameServerConfig, Protocol, ResolverConfig, ResolverOpts};
    let mut ns = NameServerConfig::new(system_resolver_addr(), Protocol::Udp);
    ns.tls_dns_name = None;
    let mut config = ResolverConfig::new();
    config.add_name_server(ns);
    hickory_resolver::TokioAsyncResolver::tokio(config, ResolverOpts::default())
}

/// Return the first nameserver from `/etc/resolv.conf`, or the
/// systemd-resolved stub (`127.0.0.53:53`) as a fallback.
fn system_resolver_addr() -> std::net::SocketAddr {
    if let Ok(contents) = std::fs::read_to_string("/etc/resolv.conf") {
        for line in contents.lines() {
            let line = line.trim();
            if let Some(rest) = line.strip_prefix("nameserver") {
                if let Ok(ip) = rest.trim().parse::<std::net::IpAddr>() {
                    return std::net::SocketAddr::new(ip, 53);
                }
            }
        }
    }
    "127.0.0.53:53".parse().expect("hardcoded addr is valid")
}
