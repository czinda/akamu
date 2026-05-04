//! akamuctl configuration file and session cache.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

#[derive(Debug, Default, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub server: ServerConfig,
    #[serde(default)]
    pub cosigner: Option<CosignerConfig>,
    #[serde(default)]
    pub output: OutputConfig,
}

#[derive(Debug, Default, Deserialize)]
pub struct ServerConfig {
    pub url: Option<String>,
    pub ca_cert: Option<String>,
    pub cert_file: Option<String>,
    pub key_file: Option<String>,
    pub keytab: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
pub struct CosignerConfig {
    pub url: Option<String>,
    pub ca_cert: Option<String>,
    pub cert_file: Option<String>,
    pub key_file: Option<String>,
    pub keytab: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
pub struct OutputConfig {
    #[serde(default = "default_format")]
    pub format: String,
}

fn default_format() -> String {
    "table".into()
}

impl Config {
    pub fn from_file(path: &std::path::Path) -> Result<Self, String> {
        let s = std::fs::read_to_string(path)
            .map_err(|e| format!("read config '{}': {e}", path.display()))?;
        toml::from_str(&s).map_err(|e| format!("parse config '{}': {e}", path.display()))
    }

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

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct SessionCache {
    pub server: Option<SessionEntry>,
    pub cosigner: Option<SessionEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionEntry {
    pub url: String,
    pub token: String,
    pub expires_at: String,
}

impl SessionCache {
    pub fn default_path() -> PathBuf {
        dirs_home()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".config/akamu/session.json")
    }

    pub fn load() -> Self {
        let path = Self::default_path();
        let Ok(s) = std::fs::read_to_string(&path) else {
            return Self::default();
        };
        serde_json::from_str(&s).unwrap_or_default()
    }

    pub fn save(&self) -> Result<(), String> {
        let path = Self::default_path();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| format!("mkdir: {e}"))?;
        }
        let s = serde_json::to_string_pretty(self).map_err(|e| format!("serialize: {e}"))?;
        std::fs::write(&path, s).map_err(|e| format!("write session: {e}"))
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
        let year: i64 = std::str::from_utf8(&b[0..4]).ok()?.parse().ok()?;
        let month: i64 = std::str::from_utf8(&b[5..7]).ok()?.parse().ok()?;
        let day: i64 = std::str::from_utf8(&b[8..10]).ok()?.parse().ok()?;
        let hour: i64 = std::str::from_utf8(&b[11..13]).ok()?.parse().ok()?;
        let min: i64 = std::str::from_utf8(&b[14..16]).ok()?.parse().ok()?;
        let sec: i64 = std::str::from_utf8(&b[17..19]).ok()?.parse().ok()?;
        // Simple day-of-year → Unix seconds approximation (good enough for TTL checks).
        let days_from_epoch = (year - 1970) * 365 + (year - 1969) / 4
            + [0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334]
                [(month as usize).saturating_sub(1)]
            + day
            - 1;
        Some(days_from_epoch * 86400 + hour * 3600 + min * 60 + sec)
    };
    let expires_unix = parse(expires_at).unwrap_or(0);
    let now_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    expires_unix - now_unix < margin_secs
}
