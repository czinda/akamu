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
//! TXT record format (per draft-ietf-acme-dns-persist):
//! ```text
//! _validation-persist.<domain>. IN TXT
//!   "<issuer-domain>; accounturi=<uri>[; policy=wildcard][; persistUntil=<unix-ts>]"
//! ```

use std::str::FromStr;

use hickory_resolver::proto::rr::{Name, RData, RecordType};

use crate::error::AcmeError;
use crate::util::unix_now;

/// Validate a dns-persist-01 challenge.
///
/// * `domain`          — identifier value; any leading `*.` wildcard is stripped
///   before forming the DNS query.
/// * `account_uri`     — full ACME account URI (stored in the key_auth DB column).
/// * `issuer_domains`  — one or more CA issuer domains; a TXT record is accepted
///   if its first token matches **any** of them.
/// * `resolver_addr`   — optional DNS resolver override (used in tests and
///   split-horizon deployments); `None` uses the system default resolver.
/// * `dot_server_name` — optional DoT SNI hostname; when set, queries use TLS.
pub async fn validate(
    domain: &str,
    account_uri: &str,
    issuer_domains: &[&str],
    resolver_addr: Option<std::net::SocketAddr>,
    validate_dnssec: bool,
    dot_server_name: Option<&str>,
) -> Result<(), AcmeError> {
    // dns-persist-01 is only valid for DNS identifiers, not IP addresses.
    if domain.parse::<std::net::IpAddr>().is_ok() {
        return Err(AcmeError::IncorrectResponse(
            "dns-persist-01 cannot validate IP address identifiers".into(),
        ));
    }
    let addr = resolver_addr.unwrap_or_else(crate::dns::system_resolver_addr);
    validate_with_resolver(
        domain,
        account_uri,
        issuer_domains,
        addr,
        validate_dnssec,
        dot_server_name,
    )
    .await
}

async fn validate_with_resolver(
    domain: &str,
    account_uri: &str,
    issuer_domains: &[&str],
    resolver_addr: std::net::SocketAddr,
    validate_dnssec: bool,
    dot_server_name: Option<&str>,
) -> Result<(), AcmeError> {
    let base_domain = domain.strip_prefix("*.").unwrap_or(domain);
    let is_wildcard = domain.starts_with("*.");
    let query_name = format!("_validation-persist.{base_domain}.");

    let now = unix_now();

    tracing::debug!(
        domain,
        query_name,
        ?issuer_domains,
        account_uri,
        is_wildcard,
        "dns-persist-01: querying TXT records"
    );

    let fqdn = Name::from_str(&query_name)
        .map_err(|e| AcmeError::Dns(format!("invalid DNS name '{query_name}': {e}")))?;
    let lookup = crate::dns::dns_query(
        resolver_addr,
        validate_dnssec,
        dot_server_name,
        fqdn,
        RecordType::TXT,
    )
    .await?;

    let records: Vec<String> = lookup
        .as_ref()
        .map(|l| {
            l.iter()
                .filter_map(|rdata| {
                    if let RData::TXT(txt) = rdata {
                        Some(
                            txt.iter()
                                .map(|s| String::from_utf8_lossy(s).into_owned())
                                .collect(),
                        )
                    } else {
                        None
                    }
                })
                .collect()
        })
        .unwrap_or_default();

    tracing::debug!(
        query_name,
        count = records.len(),
        "dns-persist-01: TXT records received"
    );

    for value in &records {
        let value = value.trim();
        let matched = matches_record(value, issuer_domains, account_uri, is_wildcard, now);
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
         issuer={issuer_domains:?} accounturi='{account_uri}'"
    )))
}

/// Check whether a single TXT record value satisfies the dns-persist-01 requirements.
///
/// Returns `true` only when all of the following hold:
/// - First token (before `;`) equals **any** entry in `expected_issuers`
///   (case-insensitive, trailing dot stripped).
/// - `accounturi=<expected_account_uri>` is present among the key=value tokens.
/// - If `require_wildcard_policy` is true, `policy=wildcard` is present.
/// - If `persistUntil=<ts>` is present, `<ts>` is a valid base-10 integer and is >= `now`.
pub(crate) fn matches_record(
    raw: &str,
    expected_issuers: &[&str],
    expected_account_uri: &str,
    require_wildcard_policy: bool,
    now: i64,
) -> bool {
    let mut parts = raw.split(';');

    // First token: issuer domain — must match one of the configured issuers.
    let issuer_token = match parts.next() {
        Some(t) => t.trim().trim_end_matches('.').to_lowercase(),
        None => return false,
    };
    if !expected_issuers
        .iter()
        .any(|e| e.trim().trim_end_matches('.').to_lowercase() == issuer_token)
    {
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
        } else if let Some(val) = part.strip_prefix("policy=") {
            if val.trim().eq_ignore_ascii_case("wildcard") {
                found_wildcard_policy = true;
            }
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

/// Parse a `persistUntil` value as a base-10 UNIX timestamp
/// (draft-ietf-acme-dns-persist Section 4.1 item 5).
fn parse_persist_until(s: &str) -> Option<i64> {
    s.parse::<i64>().ok()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::UdpSocket;

    // ── parse_persist_until ───────────────────────────────────────────────────

    #[test]
    fn parse_epoch_returns_zero() {
        assert_eq!(parse_persist_until("0"), Some(0));
    }

    #[test]
    fn parse_known_timestamp() {
        assert_eq!(parse_persist_until("1704067200"), Some(1_704_067_200));
    }

    #[test]
    fn parse_negative_timestamp() {
        assert_eq!(parse_persist_until("-1"), Some(-1));
    }

    #[test]
    fn parse_rejects_non_integer() {
        assert!(parse_persist_until("not-a-number").is_none());
        assert!(parse_persist_until("2024-01-01T00:00:00Z").is_none());
        assert!(parse_persist_until("123.456").is_none());
        assert!(parse_persist_until("").is_none());
    }

    // ── matches_record ────────────────────────────────────────────────────────

    const NOW: i64 = 1_700_000_000; // 2023-11-14

    #[test]
    fn matches_basic_record() {
        assert!(matches_record(
            "acme.example.com; accounturi=https://acme.example.com/acme/account/1",
            &["acme.example.com"],
            "https://acme.example.com/acme/account/1",
            false,
            NOW,
        ));
    }

    #[test]
    fn matches_case_insensitive_issuer() {
        assert!(matches_record(
            "ACME.EXAMPLE.COM; accounturi=https://acme.example.com/acme/account/1",
            &["acme.example.com"],
            "https://acme.example.com/acme/account/1",
            false,
            NOW,
        ));
    }

    #[test]
    fn matches_trailing_dot_stripped() {
        assert!(matches_record(
            "acme.example.com.; accounturi=https://acme.example.com/acme/account/1",
            &["acme.example.com"],
            "https://acme.example.com/acme/account/1",
            false,
            NOW,
        ));
    }

    #[test]
    fn rejects_wrong_issuer() {
        assert!(!matches_record(
            "evil.example.com; accounturi=https://acme.example.com/acme/account/1",
            &["acme.example.com"],
            "https://acme.example.com/acme/account/1",
            false,
            NOW,
        ));
    }

    #[test]
    fn rejects_wrong_account_uri() {
        assert!(!matches_record(
            "acme.example.com; accounturi=https://acme.example.com/acme/account/99",
            &["acme.example.com"],
            "https://acme.example.com/acme/account/1",
            false,
            NOW,
        ));
    }

    #[test]
    fn rejects_missing_account_uri() {
        assert!(!matches_record(
            "acme.example.com; policy=wildcard",
            &["acme.example.com"],
            "https://acme.example.com/acme/account/1",
            false,
            NOW,
        ));
    }

    #[test]
    fn matches_with_wildcard_policy() {
        assert!(matches_record(
            "acme.example.com; accounturi=https://acme.example.com/acme/account/1; policy=wildcard",
            &["acme.example.com"],
            "https://acme.example.com/acme/account/1",
            true, // require wildcard policy
            NOW,
        ));
    }

    #[test]
    fn rejects_missing_wildcard_policy_when_required() {
        assert!(!matches_record(
            "acme.example.com; accounturi=https://acme.example.com/acme/account/1",
            &["acme.example.com"],
            "https://acme.example.com/acme/account/1",
            true, // require wildcard policy
            NOW,
        ));
    }

    #[test]
    fn matches_wildcard_policy_uppercase() {
        assert!(matches_record(
            "acme.example.com; accounturi=https://acme.example.com/acme/account/1; policy=WILDCARD",
            &["acme.example.com"],
            "https://acme.example.com/acme/account/1",
            true,
            NOW,
        ));
    }

    #[test]
    fn matches_wildcard_policy_mixed_case() {
        assert!(matches_record(
            "acme.example.com; accounturi=https://acme.example.com/acme/account/1; policy=Wildcard",
            &["acme.example.com"],
            "https://acme.example.com/acme/account/1",
            true,
            NOW,
        ));
    }

    #[test]
    fn accepts_non_wildcard_order_without_policy() {
        assert!(matches_record(
            "acme.example.com; accounturi=https://acme.example.com/acme/account/1",
            &["acme.example.com"],
            "https://acme.example.com/acme/account/1",
            false, // wildcard policy not required
            NOW,
        ));
    }

    #[test]
    fn matches_with_future_persist_until() {
        // persistUntil=4102444800 (2099-12-31)
        assert!(matches_record(
            "acme.example.com; accounturi=https://acme.example.com/acme/account/1; persistUntil=4102444800",
            &["acme.example.com"],
            "https://acme.example.com/acme/account/1",
            false,
            NOW,
        ));
    }

    #[test]
    fn rejects_expired_persist_until() {
        // persistUntil=1577836800 (2020-01-01)
        assert!(!matches_record(
            "acme.example.com; accounturi=https://acme.example.com/acme/account/1; persistUntil=1577836800",
            &["acme.example.com"],
            "https://acme.example.com/acme/account/1",
            false,
            NOW,
        ));
    }

    #[test]
    fn rejects_unparseable_persist_until() {
        assert!(!matches_record(
            "acme.example.com; accounturi=https://acme.example.com/acme/account/1; persistUntil=not-a-number",
            &["acme.example.com"],
            "https://acme.example.com/acme/account/1",
            false,
            NOW,
        ));
    }

    #[test]
    fn rejects_iso8601_persist_until() {
        assert!(!matches_record(
            "acme.example.com; accounturi=https://acme.example.com/acme/account/1; persistUntil=2099-01-01T00:00:00Z",
            &["acme.example.com"],
            "https://acme.example.com/acme/account/1",
            false,
            NOW,
        ));
    }

    #[test]
    fn ignores_unknown_key_value_tokens() {
        assert!(matches_record(
            "acme.example.com; accounturi=https://acme.example.com/acme/account/1; unknownField=xyz",
            &["acme.example.com"],
            "https://acme.example.com/acme/account/1",
            false,
            NOW,
        ));
    }

    #[test]
    fn matches_record_with_all_fields() {
        // persistUntil=4102444799 (2099-12-31T23:59:59Z)
        assert!(matches_record(
            "acme.example.com; accounturi=https://acme.example.com/acme/account/1; policy=wildcard; persistUntil=4102444799",
            &["acme.example.com"],
            "https://acme.example.com/acme/account/1",
            true,
            NOW,
        ));
    }

    #[test]
    fn matches_second_issuer_in_list() {
        assert!(matches_record(
            "acme2.example.org; accounturi=https://acme.example.com/acme/account/1",
            &["acme.example.com", "acme2.example.org"],
            "https://acme.example.com/acme/account/1",
            false,
            NOW,
        ));
    }

    #[test]
    fn rejects_issuer_not_in_list() {
        assert!(!matches_record(
            "evil.example.com; accounturi=https://acme.example.com/acme/account/1",
            &["acme.example.com", "acme2.example.org"],
            "https://acme.example.com/acme/account/1",
            false,
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

    fn local_resolver(port: u16) -> std::net::SocketAddr {
        format!("127.0.0.1:{port}").parse().unwrap()
    }

    // ── validate_with_resolver integration tests ──────────────────────────────

    #[tokio::test]
    async fn validate_matching_record_returns_ok() {
        let issuer = "acme.example.com";
        let account_uri = "https://acme.example.com/acme/account/42";
        let txt = format!("{issuer}; accounturi={account_uri}");
        let port = start_txt_dns_server(txt).await;
        let resolver_addr = local_resolver(port);

        let result = validate_with_resolver(
            "example.test",
            account_uri,
            &[issuer],
            resolver_addr,
            false,
            None,
        )
        .await;
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
        let resolver_addr = local_resolver(port);

        let result = validate_with_resolver(
            "example.test",
            account_uri,
            &["acme.example.com"],
            resolver_addr,
            false,
            None,
        )
        .await;
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
        let resolver_addr = local_resolver(port);

        let result = validate_with_resolver(
            "*.example.test",
            account_uri,
            &[issuer],
            resolver_addr,
            false,
            None,
        )
        .await;
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
        let resolver_addr = local_resolver(port);

        let result = validate_with_resolver(
            "*.example.test",
            account_uri,
            &[issuer],
            resolver_addr,
            false,
            None,
        )
        .await;
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
            &["issuer"],
            None,
            false,
            None,
        )
        .await;
        assert!(result.is_err());
    }
}
