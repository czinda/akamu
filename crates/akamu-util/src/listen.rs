//! Listener target types and helpers shared between the akamu ACME server and
//! the akamu-cosigner daemon.

/// Marker inserted into request extensions for Unix-socket connections.
///
/// When present, the `RemoteUser` extractor skips the CIDR check in
/// `trusted_proxies` — UDS connections are inherently local and trusted.
#[derive(Clone)]
pub struct UdsConnection;

/// Listener target: either a TCP socket address or a Unix domain socket path.
#[derive(Debug, Clone)]
pub enum ListenTarget {
    /// TCP/IP socket address.
    Tcp(std::net::SocketAddr),
    /// Filesystem path for a Unix domain socket.
    Unix(String),
}

/// Error returned when parsing a listen address fails.
#[derive(Debug)]
pub struct ListenTargetParseError {
    input: String,
    reason: String,
}

impl std::fmt::Display for ListenTargetParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "invalid listen address '{}': {}",
            self.input, self.reason
        )
    }
}

impl std::error::Error for ListenTargetParseError {}

impl std::str::FromStr for ListenTarget {
    type Err = ListenTargetParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Some(path) = s.strip_prefix("unix:") {
            return Ok(ListenTarget::Unix(path.to_owned()));
        }
        if s.starts_with('/') {
            return Ok(ListenTarget::Unix(s.to_owned()));
        }
        s.parse::<std::net::SocketAddr>()
            .map(ListenTarget::Tcp)
            .map_err(|e| ListenTargetParseError {
                input: s.to_owned(),
                reason: e.to_string(),
            })
    }
}

/// Parse `listen_addr` into a `ListenTarget`.
///
/// `env_var` is checked first; if set, it overrides `listen_addr` from config.
/// Accepted formats:
/// - `"host:port"` → TCP
/// - `"unix:/path/to/socket"` or `"/path/to/socket"` → Unix domain socket
///
/// Returns an error if the environment variable contains non-UTF-8 bytes or if
/// the address string cannot be parsed.
pub fn parse_listen_target(listen_addr: &str, env_var: &str) -> Result<ListenTarget, String> {
    let raw = match std::env::var(env_var) {
        Ok(v) => v,
        Err(std::env::VarError::NotPresent) => listen_addr.to_owned(),
        Err(std::env::VarError::NotUnicode(os)) => {
            return Err(format!(
                "environment variable {} contains non-UTF-8 bytes: {:?}",
                env_var, os
            ));
        }
    };
    raw.parse::<ListenTarget>().map_err(|e| e.to_string())
}

/// Remove a stale Unix domain socket file left by a previous run.
///
/// Validates that the existing file (if any) is actually a Unix socket before
/// removing it, to avoid silently deleting unrelated files when the path is
/// misconfigured.  No-op when the path does not exist.
pub async fn remove_stale_socket(path: &str) -> Result<(), String> {
    use std::os::unix::fs::FileTypeExt as _;

    match tokio::fs::metadata(path).await {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(format!("stat '{}': {e}", path)),
        Ok(meta) => {
            if !meta.file_type().is_socket() {
                return Err(format!(
                    "path '{}' exists but is not a Unix socket; refusing to remove",
                    path
                ));
            }
            tracing::info!(path = %path, "removing stale Unix socket from previous run");
        }
    }
    match tokio::fs::remove_file(path).await {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(format!("remove stale socket '{}': {e}", path)),
    }
}

/// Axum middleware that tags incoming requests with a [`UdsConnection`] extension.
///
/// Apply this layer on every Unix-domain-socket listener so that downstream
/// extractors (e.g. `RemoteUser`) can distinguish UDS connections from TCP ones.
pub async fn uds_marker_layer(
    mut req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    req.extensions_mut().insert(UdsConnection);
    next.run(req).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_tcp_address() {
        let t = "127.0.0.1:8080".parse::<ListenTarget>().unwrap();
        assert!(matches!(t, ListenTarget::Tcp(addr) if addr.port() == 8080));
    }

    #[test]
    fn parse_unix_prefix() {
        let t = "unix:/run/akamu/akamu.sock"
            .parse::<ListenTarget>()
            .unwrap();
        assert!(matches!(t, ListenTarget::Unix(ref p) if p == "/run/akamu/akamu.sock"));
    }

    #[test]
    fn parse_unix_bare_path() {
        let t = "/run/akamu/akamu.sock".parse::<ListenTarget>().unwrap();
        assert!(matches!(t, ListenTarget::Unix(ref p) if p == "/run/akamu/akamu.sock"));
    }

    #[test]
    fn parse_invalid_returns_error() {
        let result = "not-a-valid-address".parse::<ListenTarget>();
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("not-a-valid-address"), "got: {msg}");
    }

    #[test]
    fn parse_listen_target_uses_config_when_env_absent() {
        std::env::remove_var("_AKAMU_UTIL_TEST_LISTEN_ABSENT");
        let t = parse_listen_target("127.0.0.1:9000", "_AKAMU_UTIL_TEST_LISTEN_ABSENT").unwrap();
        assert!(matches!(t, ListenTarget::Tcp(addr) if addr.port() == 9000));
    }

    #[test]
    fn parse_listen_target_env_overrides_config() {
        std::env::set_var("_AKAMU_UTIL_TEST_LISTEN_OVERRIDE", "/run/test.sock");
        let t = parse_listen_target("127.0.0.1:9000", "_AKAMU_UTIL_TEST_LISTEN_OVERRIDE").unwrap();
        std::env::remove_var("_AKAMU_UTIL_TEST_LISTEN_OVERRIDE");
        assert!(matches!(t, ListenTarget::Unix(ref p) if p == "/run/test.sock"));
    }

    #[test]
    fn parse_listen_target_non_unicode_env_is_error() {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt as _;

        let key = "_AKAMU_UTIL_TEST_LISTEN_NONUTF8";
        std::env::set_var(key, OsStr::from_bytes(b"\xff\xfe"));
        let result = parse_listen_target("127.0.0.1:9000", key);
        std::env::remove_var(key);
        assert!(result.is_err());
        let msg = result.unwrap_err();
        assert!(msg.contains("non-UTF-8"), "got: {msg}");
    }
}
