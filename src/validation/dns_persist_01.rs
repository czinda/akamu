//! dns-persist-01 challenge validation.
//!
//! Queries TXT records for `_validation-persist.<domain>` and checks that at
//! least one record satisfies all of:
//!
//!  1. First `;`-separated token equals the CA's issuer domain (case-insensitive,
//!     trailing dot stripped).
//!  2. `accounturi=<uri>` key matches the requesting account's full URI.
//!  3. For wildcard orders, `policy=wildcard` is present.
//!  4. If `persistUntil=<timestamp>` is present, the timestamp is >= now.
//!
//! TXT record format (per the Let's Encrypt dns-persist-01 specification):
//! ```text
//! _validation-persist.<domain>. IN TXT
//!   "<issuer-domain>; accounturi=<uri>[; policy=wildcard][; persistUntil=<ISO8601Z>]"
//! ```

use hickory_resolver::config::{NameServerConfig, Protocol, ResolverConfig, ResolverOpts};
use hickory_resolver::TokioAsyncResolver;

use crate::error::AcmeError;

/// Validate a dns-persist-01 challenge.
///
/// * `domain`        — identifier value; any leading `*.` wildcard is stripped
///   before forming the DNS query.
/// * `account_uri`   — full ACME account URI (stored in the key_auth DB column).
/// * `issuer_domain` — CA's configured issuer domain (from `Config::dns_persist_issuer_domain`).
/// * `resolver_addr` — optional DNS resolver override (used in tests and split-horizon
///   deployments); `None` uses the system default resolver.
pub async fn validate(
    domain: &str,
    account_uri: &str,
    issuer_domain: &str,
    resolver_addr: Option<std::net::SocketAddr>,
) -> Result<(), AcmeError> {
    let resolver = match resolver_addr {
        Some(addr) => {
            let mut config = ResolverConfig::new();
            config.add_name_server(NameServerConfig::new(addr, Protocol::Udp));
            TokioAsyncResolver::tokio(config, ResolverOpts::default())
        }
        None => TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default()),
    };
    validate_with_resolver(domain, account_uri, issuer_domain, resolver).await
}

async fn validate_with_resolver(
    domain: &str,
    account_uri: &str,
    issuer_domain: &str,
    resolver: TokioAsyncResolver,
) -> Result<(), AcmeError> {
    let base_domain = domain.strip_prefix("*.").unwrap_or(domain);
    let is_wildcard = domain.starts_with("*.");
    let query_name = format!("_validation-persist.{base_domain}");

    let now = unix_now();

    tracing::debug!(
        domain,
        query_name,
        issuer_domain,
        account_uri,
        is_wildcard,
        "dns-persist-01: querying TXT records"
    );

    let lookup = resolver
        .txt_lookup(&query_name)
        .await
        .map_err(|e| AcmeError::Dns(format!("TXT lookup for '{query_name}': {e}")))?;

    let records: Vec<String> = lookup
        .iter()
        .map(|r| {
            r.iter()
                .map(|s| String::from_utf8_lossy(s).into_owned())
                .collect()
        })
        .collect();

    tracing::debug!(
        query_name,
        count = records.len(),
        "dns-persist-01: TXT records received"
    );

    for value in &records {
        let value = value.trim();
        let matched = matches_record(value, issuer_domain, account_uri, is_wildcard, now);
        tracing::debug!(
            record = value,
            matched,
            "dns-persist-01: evaluating TXT record"
        );
        if matched {
            tracing::info!(
                domain,
                query_name,
                "dns-persist-01: TXT record validated successfully"
            );
            return Ok(());
        }
    }

    Err(AcmeError::IncorrectResponse(format!(
        "dns-persist-01: no TXT record at '{query_name}' matches \
         issuer='{issuer_domain}' accounturi='{account_uri}'"
    )))
}

/// Check whether a single TXT record value satisfies the dns-persist-01 requirements.
///
/// Returns `true` only when all of the following hold:
/// - First token (before `;`) equals `expected_issuer` (case-insensitive, no trailing dot).
/// - `accounturi=<expected_account_uri>` is present among the key=value tokens.
/// - If `require_wildcard_policy` is true, `policy=wildcard` is present.
/// - If `persistUntil=<ts>` is present, `<ts>` parses and is >= `now`.
pub(crate) fn matches_record(
    raw: &str,
    expected_issuer: &str,
    expected_account_uri: &str,
    require_wildcard_policy: bool,
    now: i64,
) -> bool {
    let mut parts = raw.split(';');

    // First token: issuer domain.
    let issuer_token = match parts.next() {
        Some(t) => t.trim().trim_end_matches('.').to_lowercase(),
        None => return false,
    };
    let norm_expected = expected_issuer.trim().trim_end_matches('.').to_lowercase();
    if issuer_token != norm_expected {
        return false;
    }

    let mut found_account_uri = false;
    let mut found_wildcard_policy = false;
    let mut persist_until_ok = true;

    for part in parts {
        let part = part.trim();
        if let Some(uri) = part.strip_prefix("accounturi=") {
            if uri.trim() == expected_account_uri {
                found_account_uri = true;
            }
        } else if part == "policy=wildcard" {
            found_wildcard_policy = true;
        } else if let Some(ts) = part.strip_prefix("persistUntil=") {
            match parse_persist_until(ts.trim()) {
                Some(expiry) if expiry >= now => { /* still valid */ }
                _ => persist_until_ok = false,
            }
        }
        // Unknown key=value tokens are silently ignored.
    }

    if !found_account_uri {
        return false;
    }
    if require_wildcard_policy && !found_wildcard_policy {
        return false;
    }
    if !persist_until_ok {
        return false;
    }

    true
}

/// Parse an ISO 8601 UTC timestamp of the form `YYYY-MM-DDTHH:MM:SSZ` to a
/// Unix timestamp (seconds since 1970-01-01T00:00:00Z).
///
/// Returns `None` if the format is not recognised or the field values are out
/// of range.  No external date/time crate is required; the algorithm is the
/// standard proleptic Gregorian count of days from the Unix epoch.
fn parse_persist_until(s: &str) -> Option<i64> {
    // Strip mandatory UTC suffix.
    let s = s.strip_suffix('Z').or_else(|| s.strip_suffix('z'))?;
    // Require exactly "YYYY-MM-DDTHH:MM:SS" — 19 characters.
    if s.len() != 19 {
        return None;
    }
    // Validate separators.
    if &s[4..5] != "-"
        || &s[7..8] != "-"
        || &s[10..11] != "T"
        || &s[13..14] != ":"
        || &s[16..17] != ":"
    {
        return None;
    }
    let year: i64 = s[0..4].parse().ok()?;
    let month: i64 = s[5..7].parse().ok()?;
    let day: i64 = s[8..10].parse().ok()?;
    let hour: i64 = s[11..13].parse().ok()?;
    let minute: i64 = s[14..16].parse().ok()?;
    let second: i64 = s[17..19].parse().ok()?;

    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour > 23
        || minute > 59
        || second > 60
    // 60 for leap seconds
    {
        return None;
    }

    // Count leap years before year `y` (exclusive): y/4 - y/100 + y/400
    // for y >= 1; the formula counts years from year 1, so subtract from 1970.
    fn leap_years_before(y: i64) -> i64 {
        let y = y - 1;
        y / 4 - y / 100 + y / 400
    }

    let days_to_year = (year - 1970) * 365 + leap_years_before(year) - leap_years_before(1970);

    let is_leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
    let days_in_months: [i64; 13] = [0, 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    let mut days_to_month = 0i64;
    for m in 1..month {
        days_to_month += days_in_months[m as usize];
        if m == 2 && is_leap {
            days_to_month += 1;
        }
    }

    let total_days = days_to_year + days_to_month + day - 1;
    Some(total_days * 86400 + hour * 3600 + minute * 60 + second)
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_resolver::config::{NameServerConfig, Protocol};
    use tokio::net::UdpSocket;

    // ── parse_persist_until ───────────────────────────────────────────────────

    #[test]
    fn parse_epoch_returns_zero() {
        assert_eq!(parse_persist_until("1970-01-01T00:00:00Z"), Some(0));
    }

    #[test]
    fn parse_known_timestamp() {
        // 2024-01-01T00:00:00Z = 1704067200
        assert_eq!(
            parse_persist_until("2024-01-01T00:00:00Z"),
            Some(1_704_067_200)
        );
    }

    #[test]
    fn parse_leap_year_feb_29() {
        // 2024 is a leap year; 2024-02-29 is valid.
        let ts = parse_persist_until("2024-02-29T00:00:00Z");
        assert!(ts.is_some(), "2024-02-29 should be valid in leap year 2024");
    }

    #[test]
    fn parse_rejects_bad_separator() {
        assert!(parse_persist_until("2024/01/01T00:00:00Z").is_none());
        assert!(parse_persist_until("2024-01-01 00:00:00Z").is_none());
    }

    #[test]
    fn parse_rejects_missing_z() {
        assert!(parse_persist_until("2024-01-01T00:00:00").is_none());
        assert!(parse_persist_until("2024-01-01T00:00:00+00:00").is_none());
    }

    #[test]
    fn parse_rejects_out_of_range() {
        assert!(parse_persist_until("2024-13-01T00:00:00Z").is_none()); // month 13
        assert!(parse_persist_until("2024-01-32T00:00:00Z").is_none()); // day 32
        assert!(parse_persist_until("2024-01-01T25:00:00Z").is_none()); // hour 25
    }

    #[test]
    fn parse_lowercase_z() {
        assert_eq!(parse_persist_until("1970-01-01T00:00:00z"), Some(0));
    }

    // ── matches_record ────────────────────────────────────────────────────────

    const NOW: i64 = 1_700_000_000; // 2023-11-14

    #[test]
    fn matches_basic_record() {
        assert!(matches_record(
            "acme.example.com; accounturi=https://acme.example.com/acme/account/1",
            "acme.example.com",
            "https://acme.example.com/acme/account/1",
            false,
            NOW,
        ));
    }

    #[test]
    fn matches_case_insensitive_issuer() {
        assert!(matches_record(
            "ACME.EXAMPLE.COM; accounturi=https://acme.example.com/acme/account/1",
            "acme.example.com",
            "https://acme.example.com/acme/account/1",
            false,
            NOW,
        ));
    }

    #[test]
    fn matches_trailing_dot_stripped() {
        assert!(matches_record(
            "acme.example.com.; accounturi=https://acme.example.com/acme/account/1",
            "acme.example.com",
            "https://acme.example.com/acme/account/1",
            false,
            NOW,
        ));
    }

    #[test]
    fn rejects_wrong_issuer() {
        assert!(!matches_record(
            "evil.example.com; accounturi=https://acme.example.com/acme/account/1",
            "acme.example.com",
            "https://acme.example.com/acme/account/1",
            false,
            NOW,
        ));
    }

    #[test]
    fn rejects_wrong_account_uri() {
        assert!(!matches_record(
            "acme.example.com; accounturi=https://acme.example.com/acme/account/99",
            "acme.example.com",
            "https://acme.example.com/acme/account/1",
            false,
            NOW,
        ));
    }

    #[test]
    fn rejects_missing_account_uri() {
        assert!(!matches_record(
            "acme.example.com; policy=wildcard",
            "acme.example.com",
            "https://acme.example.com/acme/account/1",
            false,
            NOW,
        ));
    }

    #[test]
    fn matches_with_wildcard_policy() {
        assert!(matches_record(
            "acme.example.com; accounturi=https://acme.example.com/acme/account/1; policy=wildcard",
            "acme.example.com",
            "https://acme.example.com/acme/account/1",
            true, // require wildcard policy
            NOW,
        ));
    }

    #[test]
    fn rejects_missing_wildcard_policy_when_required() {
        assert!(!matches_record(
            "acme.example.com; accounturi=https://acme.example.com/acme/account/1",
            "acme.example.com",
            "https://acme.example.com/acme/account/1",
            true, // require wildcard policy
            NOW,
        ));
    }

    #[test]
    fn accepts_non_wildcard_order_without_policy() {
        assert!(matches_record(
            "acme.example.com; accounturi=https://acme.example.com/acme/account/1",
            "acme.example.com",
            "https://acme.example.com/acme/account/1",
            false, // wildcard policy not required
            NOW,
        ));
    }

    #[test]
    fn matches_with_future_persist_until() {
        // persistUntil well in the future
        assert!(matches_record(
            "acme.example.com; accounturi=https://acme.example.com/acme/account/1; persistUntil=2099-01-01T00:00:00Z",
            "acme.example.com",
            "https://acme.example.com/acme/account/1",
            false,
            NOW,
        ));
    }

    #[test]
    fn rejects_expired_persist_until() {
        // persistUntil in the past
        assert!(!matches_record(
            "acme.example.com; accounturi=https://acme.example.com/acme/account/1; persistUntil=2020-01-01T00:00:00Z",
            "acme.example.com",
            "https://acme.example.com/acme/account/1",
            false,
            NOW,
        ));
    }

    #[test]
    fn rejects_unparseable_persist_until() {
        assert!(!matches_record(
            "acme.example.com; accounturi=https://acme.example.com/acme/account/1; persistUntil=not-a-date",
            "acme.example.com",
            "https://acme.example.com/acme/account/1",
            false,
            NOW,
        ));
    }

    #[test]
    fn ignores_unknown_key_value_tokens() {
        assert!(matches_record(
            "acme.example.com; accounturi=https://acme.example.com/acme/account/1; unknownField=xyz",
            "acme.example.com",
            "https://acme.example.com/acme/account/1",
            false,
            NOW,
        ));
    }

    #[test]
    fn matches_record_with_all_fields() {
        assert!(matches_record(
            "acme.example.com; accounturi=https://acme.example.com/acme/account/1; policy=wildcard; persistUntil=2099-12-31T23:59:59Z",
            "acme.example.com",
            "https://acme.example.com/acme/account/1",
            true,
            NOW,
        ));
    }

    // ── DNS server harness (reused from dns01 tests) ──────────────────────────

    fn build_txt_dns_response(query: &[u8], txt_value: &str) -> Vec<u8> {
        let mut pos = 12usize;
        while pos < query.len() {
            let label_len = query[pos] as usize;
            pos += 1;
            if label_len == 0 {
                break;
            }
            pos += label_len;
        }
        pos += 4; // skip QTYPE + QCLASS
        let question_end = pos;

        let txt_bytes = txt_value.as_bytes();
        let rdlength = (txt_bytes.len() + 1) as u16;

        let mut resp = Vec::with_capacity(question_end + 16 + txt_bytes.len());
        resp.extend_from_slice(&query[..2]);
        resp.extend_from_slice(&[0x81, 0x80]);
        resp.extend_from_slice(&[0x00, 0x01]);
        resp.extend_from_slice(&[0x00, 0x01]);
        resp.extend_from_slice(&[0x00, 0x00]);
        resp.extend_from_slice(&[0x00, 0x00]);
        resp.extend_from_slice(&query[12..question_end]);
        resp.extend_from_slice(&[0xC0, 0x0C]);
        resp.extend_from_slice(&[0x00, 0x10]);
        resp.extend_from_slice(&[0x00, 0x01]);
        resp.extend_from_slice(&[0x00, 0x00, 0x00, 0x3C]);
        resp.extend_from_slice(&rdlength.to_be_bytes());
        resp.push(txt_bytes.len() as u8);
        resp.extend_from_slice(txt_bytes);
        resp
    }

    async fn start_txt_dns_server(txt_value: String) -> u16 {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = socket.local_addr().unwrap().port();
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            if let Ok((n, addr)) = socket.recv_from(&mut buf).await {
                let query = &buf[..n];
                let response = build_txt_dns_response(query, &txt_value);
                let _ = socket.send_to(&response, addr).await;
            }
        });
        port
    }

    fn local_resolver(port: u16) -> (hickory_resolver::config::ResolverConfig, ResolverOpts) {
        let mut config = hickory_resolver::config::ResolverConfig::new();
        let ns = NameServerConfig::new(format!("127.0.0.1:{port}").parse().unwrap(), Protocol::Udp);
        config.add_name_server(ns);
        (config, ResolverOpts::default())
    }

    // ── validate_with_resolver integration tests ──────────────────────────────

    #[tokio::test]
    async fn validate_matching_record_returns_ok() {
        let issuer = "acme.example.com";
        let account_uri = "https://acme.example.com/acme/account/42";
        let txt = format!("{issuer}; accounturi={account_uri}");
        let port = start_txt_dns_server(txt).await;
        let (config, opts) = local_resolver(port);
        let resolver = TokioAsyncResolver::tokio(config, opts);

        let result = validate_with_resolver("example.test", account_uri, issuer, resolver).await;
        assert!(
            result.is_ok(),
            "expected Ok for matching record: {result:?}"
        );
    }

    #[tokio::test]
    async fn validate_wrong_issuer_returns_error() {
        let account_uri = "https://acme.example.com/acme/account/42";
        let txt = format!("evil.example.com; accounturi={account_uri}");
        let port = start_txt_dns_server(txt).await;
        let (config, opts) = local_resolver(port);
        let resolver = TokioAsyncResolver::tokio(config, opts);

        let result =
            validate_with_resolver("example.test", account_uri, "acme.example.com", resolver).await;
        assert!(
            matches!(result, Err(AcmeError::IncorrectResponse(_))),
            "expected IncorrectResponse: {result:?}"
        );
    }

    #[tokio::test]
    async fn validate_wildcard_domain_strips_prefix() {
        // "*.example.test" should query "_validation-persist.example.test"
        let issuer = "acme.example.com";
        let account_uri = "https://acme.example.com/acme/account/1";
        let txt = format!("{issuer}; accounturi={account_uri}; policy=wildcard");
        let port = start_txt_dns_server(txt).await;
        let (config, opts) = local_resolver(port);
        let resolver = TokioAsyncResolver::tokio(config, opts);

        let result = validate_with_resolver("*.example.test", account_uri, issuer, resolver).await;
        assert!(
            result.is_ok(),
            "wildcard validation should succeed: {result:?}"
        );
    }

    #[tokio::test]
    async fn validate_wildcard_requires_policy() {
        // Wildcard order but record missing policy=wildcard → fail
        let issuer = "acme.example.com";
        let account_uri = "https://acme.example.com/acme/account/1";
        let txt = format!("{issuer}; accounturi={account_uri}");
        let port = start_txt_dns_server(txt).await;
        let (config, opts) = local_resolver(port);
        let resolver = TokioAsyncResolver::tokio(config, opts);

        let result = validate_with_resolver("*.example.test", account_uri, issuer, resolver).await;
        assert!(
            matches!(result, Err(AcmeError::IncorrectResponse(_))),
            "expected IncorrectResponse for missing wildcard policy: {result:?}"
        );
    }

    #[tokio::test]
    async fn validate_nonexistent_domain_returns_dns_error() {
        let result = validate(
            "nonexistent.acme-test-invalid.invalid",
            "uri",
            "issuer",
            None,
        )
        .await;
        assert!(result.is_err());
    }
}
