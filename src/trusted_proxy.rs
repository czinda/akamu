use std::fmt;
use std::net::IpAddr;

use serde::de::{self, Deserializer};
use serde::Deserialize;

/// A single trusted-proxy entry: either a CIDR network or the special
/// `"local addresses"` literal that expands to all local interface IPs.
#[derive(Debug, Clone)]
pub enum TrustedProxy {
    Cidr(ipnet::IpNet),
    LocalAddresses,
}

impl fmt::Display for TrustedProxy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TrustedProxy::Cidr(net) => net.fmt(f),
            TrustedProxy::LocalAddresses => f.write_str("local addresses"),
        }
    }
}

impl<'de> Deserialize<'de> for TrustedProxy {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        if s == "local addresses" {
            return Ok(TrustedProxy::LocalAddresses);
        }
        s.parse::<ipnet::IpNet>()
            .map(TrustedProxy::Cidr)
            .map_err(de::Error::custom)
    }
}

/// A list of trusted-proxy entries with a `contains` method that handles
/// both CIDR matching and local-address expansion.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(transparent)]
pub struct TrustedProxies(Vec<TrustedProxy>);

impl TrustedProxies {
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Check whether `ip` matches any entry in the list.
    ///
    /// IPv4-mapped IPv6 addresses (`::ffff:a.b.c.d`) are normalized to plain
    /// IPv4 so they match IPv4 CIDR entries.
    pub fn contains(&self, ip: &IpAddr) -> bool {
        let ip = normalize_ip(*ip);
        self.0.iter().any(|entry| match entry {
            TrustedProxy::Cidr(net) => net.contains(&ip),
            TrustedProxy::LocalAddresses => ip.is_loopback() || local_addrs_cache::contains(ip),
        })
    }

    pub fn iter(&self) -> std::slice::Iter<'_, TrustedProxy> {
        self.0.iter()
    }
}

/// Normalize IPv4-mapped IPv6 addresses (`::ffff:a.b.c.d`) to plain IPv4.
fn normalize_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(v6)),
        v4 => v4,
    }
}

mod local_addrs_cache {
    use std::collections::HashSet;
    use std::net::IpAddr;
    use std::sync::RwLock;
    use std::time::{Duration, Instant};

    static CACHE: RwLock<Option<(HashSet<IpAddr>, Instant)>> = RwLock::new(None);
    const TTL: Duration = Duration::from_secs(30);

    pub fn contains(addr: IpAddr) -> bool {
        {
            let guard = CACHE.read().unwrap_or_else(|e| {
                tracing::warn!("local_addrs_cache RwLock poisoned (read); recovering");
                e.into_inner()
            });
            if let Some((set, ts)) = &*guard {
                if ts.elapsed() < TTL {
                    return set.contains(&addr);
                }
            }
        }
        let mut guard = CACHE.write().unwrap_or_else(|e| {
            tracing::warn!("local_addrs_cache RwLock poisoned (write); recovering");
            e.into_inner()
        });
        if let Some((set, ts)) = &*guard {
            if ts.elapsed() < TTL {
                return set.contains(&addr);
            }
        }
        if let Some(addrs) = enumerate_local_addrs() {
            let found = addrs.contains(&addr);
            *guard = Some((addrs, Instant::now()));
            found
        } else {
            tracing::debug!(
                %addr,
                "getifaddrs unavailable; denying non-loopback local address check"
            );
            false
        }
    }

    #[cfg(unix)]
    fn enumerate_local_addrs() -> Option<HashSet<IpAddr>> {
        struct IfAddrsGuard(*mut libc::ifaddrs);
        impl Drop for IfAddrsGuard {
            fn drop(&mut self) {
                if !self.0.is_null() {
                    // SAFETY: pointer was returned by a successful getifaddrs call.
                    unsafe { libc::freeifaddrs(self.0) };
                }
            }
        }

        let mut ifaddrs: *mut libc::ifaddrs = std::ptr::null_mut();
        // SAFETY: `&mut ifaddrs` is a valid pointer-to-pointer that getifaddrs
        // will populate.
        if unsafe { libc::getifaddrs(&mut ifaddrs) } != 0 {
            let err = std::io::Error::last_os_error();
            tracing::warn!(error = %err, "getifaddrs failed; local address check will deny non-loopback");
            return None;
        }
        let _guard = IfAddrsGuard(ifaddrs);

        let mut result = HashSet::new();
        let mut cur = ifaddrs;
        while !cur.is_null() {
            // SAFETY: cur is a valid, non-null ifaddrs node from getifaddrs.
            let ifa = unsafe { &*cur };
            if !ifa.ifa_addr.is_null() {
                // SAFETY: ifa_addr is non-null and points to a valid sockaddr.
                let sa = unsafe { &*ifa.ifa_addr };
                if sa.sa_family == libc::AF_INET as libc::sa_family_t {
                    // SAFETY: sa_family == AF_INET guarantees ifa_addr points to
                    // a sockaddr_in with correct size and alignment (POSIX).
                    let sin = unsafe { &*(ifa.ifa_addr as *const libc::sockaddr_in) };
                    result.insert(IpAddr::V4(std::net::Ipv4Addr::from(u32::from_be(
                        sin.sin_addr.s_addr,
                    ))));
                } else if sa.sa_family == libc::AF_INET6 as libc::sa_family_t {
                    // SAFETY: sa_family == AF_INET6 guarantees ifa_addr points to
                    // a sockaddr_in6 with correct size and alignment (POSIX).
                    let sin6 = unsafe { &*(ifa.ifa_addr as *const libc::sockaddr_in6) };
                    result.insert(IpAddr::V6(std::net::Ipv6Addr::from(sin6.sin6_addr.s6_addr)));
                }
            }
            cur = ifa.ifa_next;
        }
        Some(result)
    }

    #[cfg(not(unix))]
    fn enumerate_local_addrs() -> Option<HashSet<IpAddr>> {
        tracing::warn!(
            "\"local addresses\" is not supported on non-Unix platforms; \
             only loopback addresses will be trusted"
        );
        Some(HashSet::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn normalize_ipv4_passthrough() {
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(normalize_ip(ip), ip);
    }

    #[test]
    fn normalize_ipv6_mapped_to_v4() {
        let mapped = IpAddr::V6(Ipv4Addr::LOCALHOST.to_ipv6_mapped());
        assert_eq!(normalize_ip(mapped), IpAddr::V4(Ipv4Addr::LOCALHOST));
    }

    #[test]
    fn normalize_native_v6_unchanged() {
        let ip = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
        assert_eq!(normalize_ip(ip), ip);
    }

    #[test]
    fn contains_cidr_match() {
        let tp = TrustedProxies(vec![TrustedProxy::Cidr("10.0.0.0/8".parse().unwrap())]);
        assert!(tp.contains(&IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3))));
    }

    #[test]
    fn contains_cidr_no_match() {
        let tp = TrustedProxies(vec![TrustedProxy::Cidr("10.0.0.0/8".parse().unwrap())]);
        assert!(!tp.contains(&IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
    }

    #[test]
    fn contains_local_addresses_loopback() {
        let tp = TrustedProxies(vec![TrustedProxy::LocalAddresses]);
        assert!(tp.contains(&IpAddr::V4(Ipv4Addr::LOCALHOST)));
        assert!(tp.contains(&IpAddr::V6(Ipv6Addr::LOCALHOST)));
    }

    #[test]
    fn contains_empty() {
        let tp = TrustedProxies::default();
        assert!(!tp.contains(&IpAddr::V4(Ipv4Addr::LOCALHOST)));
    }

    #[test]
    fn display_cidr() {
        let entry = TrustedProxy::Cidr("10.0.0.0/8".parse().unwrap());
        assert_eq!(entry.to_string(), "10.0.0.0/8");
    }

    #[test]
    fn display_local_addresses() {
        assert_eq!(TrustedProxy::LocalAddresses.to_string(), "local addresses");
    }

    #[test]
    fn deserialize_cidr() {
        let tp: TrustedProxy = serde_json::from_str("\"127.0.0.1/32\"").unwrap();
        assert!(matches!(tp, TrustedProxy::Cidr(_)));
    }

    #[test]
    fn deserialize_local_addresses() {
        let tp: TrustedProxy = serde_json::from_str("\"local addresses\"").unwrap();
        assert!(matches!(tp, TrustedProxy::LocalAddresses));
    }

    #[test]
    fn deserialize_invalid() {
        assert!(serde_json::from_str::<TrustedProxy>("\"not-a-cidr\"").is_err());
    }

    #[test]
    fn deserialize_proxies_mixed() {
        let tp: TrustedProxies =
            serde_json::from_str("[\"local addresses\", \"10.0.0.0/8\"]").unwrap();
        assert_eq!(tp.len(), 2);
        assert!(matches!(tp.0[0], TrustedProxy::LocalAddresses));
        assert!(matches!(tp.0[1], TrustedProxy::Cidr(_)));
    }
}
