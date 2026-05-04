//! akamuctl configuration file and session cache.

/// Annotated example configuration printed by `akamuctl config generate`.
pub const EXAMPLE_CONFIG: &str = r#"# akamuctl configuration file.
# Default location: ~/.config/akamu/akamuctl.toml
#
# Generate this file:
#   akamuctl config generate > ~/.config/akamu/akamuctl.toml

# ── Server admin API ──────────────────────────────────────────────────────────
[server]
# Base URL of the akamu admin API listener.
# Corresponds to [admin].listen_addr in the akamu server configuration.
url = "https://akamu.example.com:9443"

# CA certificate used to verify the admin TLS endpoint.
# Omit to rely on the system trust store.
# ca_cert = "/etc/akamu/certs/ca.cert.pem"

# mTLS client certificate and private key.
# Required when the admin API is configured for certificate authentication.
# cert_file = "/home/alice/.config/akamu/operator.cert.pem"
# key_file  = "/home/alice/.config/akamu/operator.key.pem"

# GSSAPI/Kerberos authentication (alternative to mTLS).
# Used by 'akamuctl login --gssapi'. Requires a valid Kerberos TGT in the
# default ccache (run 'kinit' first).
# Overrides the automatic HTTP@<hostname> SPN derivation from the server URL.
# Omit to let the SPN be derived automatically.
# gssapi_service = "HTTP@akamu.example.com"

# ── Cosigner admin API ────────────────────────────────────────────────────────
# Required only for 'akamuctl cosigner' commands.
# [cosigner]
# url     = "https://cosigner.example.com:9444"
# ca_cert = "/etc/akamu/certs/ca.cert.pem"
# cert_file = "/home/alice/.config/akamu/cosigner-operator.cert.pem"
# key_file  = "/home/alice/.config/akamu/cosigner-operator.key.pem"
# gssapi_service = "HTTP@cosigner.example.com"
"#;

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// Top-level akamuctl configuration, deserialized from `akamuctl.toml`.
#[derive(Debug, Default, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub server: ServerConfig,
    #[serde(default)]
    pub cosigner: Option<CosignerConfig>,
}

/// Connection parameters for the akamu server admin API.
#[derive(Debug, Default, Deserialize)]
pub struct ServerConfig {
    pub url: Option<String>,
    pub ca_cert: Option<String>,
    pub cert_file: Option<String>,
    pub key_file: Option<String>,
    /// GSSAPI service principal name for Negotiate login (e.g. `HTTP@akamu.example.com`).
    /// When set, `akamuctl login` uses the ambient Kerberos ccache instead of mTLS.
    pub gssapi_service: Option<String>,
}

/// Connection parameters for the akamu-cosigner admin API.
#[derive(Debug, Default, Deserialize)]
pub struct CosignerConfig {
    pub url: Option<String>,
    pub ca_cert: Option<String>,
    pub cert_file: Option<String>,
    pub key_file: Option<String>,
    /// GSSAPI service principal name for Negotiate login to the cosigner admin API.
    pub gssapi_service: Option<String>,
}

impl Config {
    pub fn from_file(path: &std::path::Path) -> Result<Self, String> {
        let s = std::fs::read_to_string(path)
            .map_err(|e| format!("read config '{}': {e}", path.display()))?;
        toml::from_str(&s).map_err(|e| format!("parse config '{}': {e}", path.display()))
    }

    /// Return the default path to the session cache file.
    pub fn default_path() -> PathBuf {
        dirs_home()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".config/akamu/akamuctl.toml")
    }
}

fn dirs_home() -> Option<PathBuf> {
    std::env::var_os("HOME").map(PathBuf::from)
}

// ── Session cache ─────────────────────────────────────────────────────────────

/// On-disk session token cache stored at `~/.config/akamu/session.json`.
///
/// Avoids re-authenticating on every command when a valid session exists.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct SessionCache {
    /// Cached session for the akamu server admin API.
    pub server: Option<SessionEntry>,
    /// Cached session for the akamu-cosigner admin API.
    pub cosigner: Option<SessionEntry>,
}

/// A single cached session entry (server or cosigner).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionEntry {
    /// Admin API base URL this token was issued for.
    pub url: String,
    /// Bearer session token returned by `POST /admin/session`.
    pub token: String,
    /// RFC 3339 expiry timestamp from the session response.
    pub expires_at: String,
}

impl SessionCache {
    pub fn default_path() -> PathBuf {
        dirs_home()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".config/akamu/session.json")
    }

    /// Load the session cache from disk; returns an empty cache on any I/O or parse error.
    pub fn load() -> Self {
        let path = Self::default_path();
        let Ok(s) = std::fs::read_to_string(&path) else {
            return Self::default();
        };
        serde_json::from_str(&s).unwrap_or_default()
    }

    /// Persist the session cache to disk at mode 0600 (user-readable only).
    pub fn save(&self) -> Result<(), String> {
        use std::io::Write as _;
        use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _};
        let path = Self::default_path();
        if let Some(parent) = path.parent() {
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(parent)
                .map_err(|e| format!("mkdir: {e}"))?;
        }
        let s = serde_json::to_string_pretty(self).map_err(|e| format!("serialize: {e}"))?;
        std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&path)
            .and_then(|mut f| f.write_all(s.as_bytes()))
            .map_err(|e| format!("write session: {e}"))
    }

    /// Return the cached token for `url` if it's not expired (30 s margin).
    pub fn get_valid_token(&self, url: &str, is_cosigner: bool) -> Option<String> {
        let entry = if is_cosigner {
            self.cosigner.as_ref()?
        } else {
            self.server.as_ref()?
        };
        if entry.url != url {
            return None;
        }
        if is_expired(&entry.expires_at, 30) {
            return None;
        }
        Some(entry.token.clone())
    }
}

fn is_expired(expires_at: &str, margin_secs: i64) -> bool {
    // Parse RFC 3339 manually (no chrono dependency).
    // Format: YYYY-MM-DDTHH:MM:SSZ
    let parse = |s: &str| -> Option<i64> {
        let b = s.as_bytes();
        if b.len() < 20 {
            return None;
        }
        let year: i32 = std::str::from_utf8(&b[0..4]).ok()?.parse().ok()?;
        let month: i32 = std::str::from_utf8(&b[5..7]).ok()?.parse().ok()?;
        let day: i32 = std::str::from_utf8(&b[8..10]).ok()?.parse().ok()?;
        let hour: i64 = std::str::from_utf8(&b[11..13]).ok()?.parse().ok()?;
        let min: i64 = std::str::from_utf8(&b[14..16]).ok()?.parse().ok()?;
        let sec: i64 = std::str::from_utf8(&b[17..19]).ok()?.parse().ok()?;
        // Correct Gregorian leap-year check (century years divisible by 400 are leap).
        let is_leap = |y: i32| y % 4 == 0 && (y % 100 != 0 || y % 400 == 0);
        let days_per_month = [
            31,
            if is_leap(year) { 29 } else { 28 },
            31,
            30,
            31,
            30,
            31,
            31,
            30,
            31,
            30,
            31,
        ];
        // Days elapsed since 1970-01-01.
        let mut days: i64 = 0;
        for y in 1970..year {
            days += if is_leap(y) { 366 } else { 365 };
        }
        for d in &days_per_month[..(month - 1) as usize] {
            days += *d as i64;
        }
        days += (day - 1) as i64;
        Some(days * 86400 + hour * 3600 + min * 60 + sec)
    };
    let expires_unix = parse(expires_at).unwrap_or(0);
    let now_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    expires_unix - now_unix < margin_secs
}
