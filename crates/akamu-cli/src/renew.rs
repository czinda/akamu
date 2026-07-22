use std::{fs, path::Path};

use akamu_client::{AcmeClient, RenewalConfig};

use crate::args::{CommonCertArgs, EabFlags, RenewArgs};
use crate::helpers::resolve_directory_url;

// ── parse_rfc3339_utc ────────────────────────────────────────────────────────

/// Parse an RFC 3339 UTC timestamp string to Unix seconds.
/// Accepts "Z", "+00:00", or "-00:00" as the UTC offset indicator.
fn parse_rfc3339_utc(s: &str) -> Option<u64> {
    // Strip UTC offset suffix, then drop optional sub-second fraction.
    let s = if let Some(stripped) = s
        .strip_suffix("+00:00")
        .or_else(|| s.strip_suffix("-00:00"))
    {
        stripped
    } else {
        s.trim_end_matches('Z')
    };
    let s = s.split('.').next()?; // drop sub-seconds
                                  // "YYYY-MM-DDTHH:MM:SS" = 19 chars
    if s.len() != 19 {
        return None;
    }
    let year: i64 = s[0..4].parse().ok()?;
    let month: i64 = s[5..7].parse().ok()?;
    let day: i64 = s[8..10].parse().ok()?;
    let hour: i64 = s[11..13].parse().ok()?;
    let min: i64 = s[14..16].parse().ok()?;
    let sec: i64 = s[17..19].parse().ok()?;
    if !(1970..=9999).contains(&year)
        || !(1..=12).contains(&month)
        || day < 1
        || hour > 23
        || min > 59
        || sec > 60
    {
        return None;
    }
    let is_leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
    let max_day: i64 = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap => 29,
        2 => 28,
        _ => return None,
    };
    if day > max_day {
        return None;
    }
    // Days since Unix epoch (1970-01-01). Gregorian formula (signed arithmetic).
    let y = if month <= 2 { year - 1 } else { year };
    let m = if month <= 2 { month + 9 } else { month - 3 };
    let days: i64 = 365 * y + y / 4 - y / 100 + y / 400 + (153 * m + 2) / 5 + day - 1 - 719468;
    let secs = days
        .checked_mul(86400)?
        .checked_add(hour * 3600 + min * 60 + sec)?;
    u64::try_from(secs).ok()
}

// ── check_ari_window ─────────────────────────────────────────────────────────

/// Check ARI renewal window (RFC 9773).
///
/// Returns `Ok(true)` if renewal should proceed (window open or past),
/// `Ok(false)` if the window hasn't opened yet,
/// or `Err(...)` if the certificate file cannot be read.
/// When the ARI endpoint is unavailable, logs a warning and returns `Ok(true)`.
/// Skips the check when `cert_path` does not exist.
async fn check_ari_window(dir_url: &str, cert_path: &Path) -> Result<bool, String> {
    if !cert_path.exists() {
        return Ok(true);
    }
    let client = AcmeClient::new(dir_url).await.map_err(|e| e.to_string())?;
    let cert_bytes =
        fs::read(cert_path).map_err(|e| format!("read {}: {e}", cert_path.display()))?;
    match client.get_renewal_info(&cert_bytes).await {
        Ok(info) => {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let start = parse_rfc3339_utc(&info.window_start).unwrap_or_else(|| {
                eprintln!(
                    "Warning: cannot parse ARI window_start '{}'; treating as epoch",
                    info.window_start
                );
                0
            });
            let end = parse_rfc3339_utc(&info.window_end).unwrap_or_else(|| {
                eprintln!(
                    "Warning: cannot parse ARI window_end '{}'; treating as max",
                    info.window_end
                );
                u64::MAX
            });
            if now < start {
                println!(
                    "Renewal not yet suggested (window opens {}). Use --force to override.",
                    info.window_start
                );
                return Ok(false);
            }
            if now > end {
                eprintln!(
                    "Warning: past the ARI renewal window end ({}); renewing anyway.",
                    info.window_end
                );
            }
            println!(
                "ARI: renewal suggested (window {} – {})",
                info.window_start, info.window_end
            );
            Ok(true)
        }
        Err(e) => {
            eprintln!("ARI unavailable ({}); proceeding with renewal.", e);
            Ok(true)
        }
    }
}

// ── renew ─────────────────────────────────────────────────────────────────────

pub(crate) async fn cmd_renew(args: RenewArgs) -> Result<(), String> {
    // When --renewal-config is provided, load all settings from the TOML file
    // and delegate to cmd_issue directly.
    if let Some(ref config_path) = args.renewal_config {
        let toml_str = fs::read_to_string(config_path)
            .map_err(|e| format!("read {}: {e}", config_path.display()))?;
        let cfg: RenewalConfig = toml::from_str(&toml_str)
            .map_err(|e| format!("parse {}: {e}", config_path.display()))?;

        let cfg_dir_url = resolve_directory_url(&cfg.server, cfg.ca.as_deref());

        // Check ARI if --cert or cert_path from config exists and --force is not set.
        if !args.force {
            let cert_path = args.cert.as_deref().unwrap_or(&cfg.cert_path);
            if !check_ari_window(&cfg_dir_url, cert_path).await? {
                return Ok(());
            }
        }

        let eab = EabFlags {
            eab_kid: cfg.eab_kid,
            eab_key: cfg.eab_key,
            eab_alg: cfg.eab_alg,
            gssapi_keytab: cfg.gssapi_keytab,
        };
        let account_url = cfg.account_url.clone();
        let common = CommonCertArgs {
            server: cfg.server,
            ca: cfg.ca,
            domains: cfg.domains.into_iter().map(|id| id.value).collect(),
            key_type: cfg.account_key_type,
            account_key: Some(cfg.account_key),
            cert_key_type: cfg.cert_key_type,
            challenge_type: cfg.challenge_type,
            http_port: cfg.http_port,
            tls_port: cfg.tls_port,
            onion_key: cfg.onion_key,
            poll_timeout: cfg.poll_timeout,
            out: Some(cfg.cert_path),
            cert_key: Some(cfg.cert_key_path),
            dns_hook: cfg.dns_hook,
            profile: cfg.profile,
            tkauth_url: cfg.tkauth_url,
            tkauth_keytab: cfg.tkauth_keytab,
            jwtcc: cfg.jwtcc,
            server_ca: args.common.server_ca.clone(),
            eab,
        };
        return crate::issue::cmd_issue(common, None, account_url.as_deref()).await;
    }

    let dir_url = resolve_directory_url(&args.common.server, args.common.ca.as_deref());
    if !args.force {
        if let Some(ref cert_path) = args.cert {
            if !check_ari_window(&dir_url, cert_path).await? {
                return Ok(());
            }
        }
    }

    crate::issue::cmd_issue(args.common, None, None).await
}

#[cfg(test)]
mod tests {
    use super::parse_rfc3339_utc;

    #[test]
    fn rfc3339_utc_basic() {
        // 1970-01-01T00:00:00Z = 0
        assert_eq!(parse_rfc3339_utc("1970-01-01T00:00:00Z"), Some(0));
    }

    #[test]
    fn rfc3339_utc_known_timestamp() {
        // 2024-01-01T00:00:00Z = 1704067200
        assert_eq!(parse_rfc3339_utc("2024-01-01T00:00:00Z"), Some(1704067200));
    }

    #[test]
    fn rfc3339_utc_rejects_feb31() {
        assert_eq!(parse_rfc3339_utc("2025-02-31T00:00:00Z"), None);
    }

    #[test]
    fn rfc3339_utc_rejects_apr31() {
        assert_eq!(parse_rfc3339_utc("2025-04-31T00:00:00Z"), None);
    }

    #[test]
    fn rfc3339_utc_accepts_feb29_leap() {
        assert!(parse_rfc3339_utc("2024-02-29T00:00:00Z").is_some());
    }

    #[test]
    fn rfc3339_utc_rejects_feb29_non_leap() {
        assert_eq!(parse_rfc3339_utc("2025-02-29T00:00:00Z"), None);
    }

    #[test]
    fn rfc3339_utc_rejects_year_before_1970() {
        assert_eq!(parse_rfc3339_utc("1969-12-31T23:59:59Z"), None);
    }

    #[test]
    fn rfc3339_utc_rejects_year_after_9999() {
        assert_eq!(parse_rfc3339_utc("10000-01-01T00:00:00Z"), None);
    }

    #[test]
    fn rfc3339_utc_rejects_hour25() {
        assert_eq!(parse_rfc3339_utc("2025-01-01T25:00:00Z"), None);
    }

    #[test]
    fn rfc3339_utc_rejects_min60() {
        assert_eq!(parse_rfc3339_utc("2025-01-01T00:60:00Z"), None);
    }

    #[test]
    fn rfc3339_utc_subsecond_ignored() {
        let base = parse_rfc3339_utc("2024-06-15T12:30:45Z");
        let frac = parse_rfc3339_utc("2024-06-15T12:30:45.123456Z");
        assert_eq!(base, frac);
    }

    #[test]
    fn rfc3339_utc_accepts_plus_zero_offset() {
        let z = parse_rfc3339_utc("2024-01-01T00:00:00Z");
        let plus = parse_rfc3339_utc("2024-01-01T00:00:00+00:00");
        let minus = parse_rfc3339_utc("2024-01-01T00:00:00-00:00");
        assert!(z.is_some());
        assert_eq!(z, plus);
        assert_eq!(z, minus);
    }

    #[test]
    fn rfc3339_utc_accepts_subsecond_plus_offset() {
        let z = parse_rfc3339_utc("2024-06-15T12:30:45Z");
        let plus = parse_rfc3339_utc("2024-06-15T12:30:45.5+00:00");
        assert_eq!(z, plus);
    }

    #[test]
    fn rfc3339_utc_rejects_nonzero_offset() {
        assert_eq!(parse_rfc3339_utc("2024-01-01T00:00:00+05:30"), None);
        assert_eq!(parse_rfc3339_utc("2024-01-01T00:00:00-08:00"), None);
    }
}
