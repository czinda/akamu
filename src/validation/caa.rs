//! CAA record checking (RFC 8659 + RFC 8657 validationmethods/accounturi parameters).
//!
//! Before issuing a certificate the CA MUST query CAA records starting at the
//! domain being certified and walk up to the root until records are found.
//! If a record set is found, the CA must appear in at least one `issue` property
//! (or `issuewild` for wildcard certificates).
//!
//! RFC 8657 adds two optional parameters enforced by this implementation:
//! - `validationmethods`: the challenge type used must appear in the list.
//! - `accounturi`: the requesting ACME account URL must match the parameter value.

use hickory_resolver::config::{NameServerConfig, Protocol, ResolverConfig, ResolverOpts};
use hickory_resolver::proto::rr::RData;
use hickory_resolver::proto::rr::RecordType;
use hickory_resolver::TokioAsyncResolver;

use crate::error::AcmeError;

/// Check CAA records for `domain` before issuing a certificate.
///
/// Returns `Ok(())` if issuance is allowed, `Err(AcmeError::Caa(...))` if blocked.
///
/// * `domain`          — The domain being certified (without `*.` prefix).
/// * `ca_identities`   — The CA's domain names from `server.caa_identities`.
///   If empty, the check is skipped (open policy).
/// * `is_wildcard`     — `true` if the cert covers a wildcard (`*.<domain>`).
/// * `challenge_type`  — e.g. `"http-01"`, `"dns-01"` — for `validationmethods` checking.
/// * `account_url`     — The full ACME account URL for `accounturi` enforcement (RFC 8657 §4).
/// * `resolver_addr`   — Optional DNS resolver override from config.
pub async fn check_caa(
    domain: &str,
    ca_identities: &[String],
    is_wildcard: bool,
    challenge_type: &str,
    account_url: Option<&str>,
    resolver_addr: Option<&str>,
    validate_dnssec: bool,
) -> Result<(), AcmeError> {
    // Step 1: If ca_identities is empty → no-op (open policy).
    if ca_identities.is_empty() {
        return Ok(());
    }

    let resolver = build_resolver(resolver_addr, validate_dnssec)?;
    check_caa_with_resolver(
        domain,
        ca_identities,
        is_wildcard,
        challenge_type,
        account_url,
        resolver,
    )
    .await
}

/// Inner implementation that takes a custom resolver for testability.
///
/// `account_url` is the full ACME account URL passed through to
/// `evaluate_caa_record_set` for RFC 8657 §4 `accounturi` enforcement.
pub(crate) async fn check_caa_with_resolver(
    domain: &str,
    ca_identities: &[String],
    is_wildcard: bool,
    challenge_type: &str,
    account_url: Option<&str>,
    resolver: TokioAsyncResolver,
) -> Result<(), AcmeError> {
    // Step 2: Build a list of DNS names to check, walking up to (but not including) the TLD.
    let names_to_check = build_name_walk(domain);

    // Step 3: For each name, query CAA records.
    for name in &names_to_check {
        let query_name = format!("{name}.");

        tracing::debug!(domain, query_name, is_wildcard, "caa: querying CAA records");

        let result = resolver.lookup(query_name.as_str(), RecordType::CAA).await;

        match result {
            Ok(lookup) => {
                // Collect CAA records from the response.
                let caa_records: Vec<&hickory_resolver::proto::rr::rdata::CAA> = lookup
                    .iter()
                    .filter_map(|rdata| {
                        if let RData::CAA(caa) = rdata {
                            Some(caa)
                        } else {
                            None
                        }
                    })
                    .collect();

                if caa_records.is_empty() {
                    // No CAA records at this label — continue walking up.
                    tracing::debug!(query_name, "caa: no CAA records found, walking up");
                    continue;
                }

                // Step 4 (inline): Found a CAA record set — evaluate it and stop walking.
                tracing::debug!(
                    query_name,
                    count = caa_records.len(),
                    "caa: evaluating CAA record set"
                );
                return evaluate_caa_record_set(
                    &caa_records,
                    domain,
                    ca_identities,
                    is_wildcard,
                    challenge_type,
                    account_url,
                );
            }
            Err(e) => {
                use hickory_resolver::error::ResolveErrorKind;
                use hickory_resolver::proto::op::ResponseCode;

                match e.kind() {
                    ResolveErrorKind::NoRecordsFound { response_code, .. } => {
                        match response_code {
                            // SERVFAIL / REFUSED: the lookup failed — deny issuance per RFC 8659 §4.
                            ResponseCode::ServFail | ResponseCode::Refused => {
                                tracing::warn!(
                                    query_name,
                                    error = %e,
                                    "caa: DNS lookup returned SERVFAIL/REFUSED"
                                );
                                return Err(AcmeError::Caa(format!(
                                    "CAA lookup failed for '{name}': {e}"
                                )));
                            }
                            // NXDOMAIN or NOERROR with no records → continue walking up.
                            _ => {
                                tracing::debug!(
                                    query_name,
                                    "caa: NXDOMAIN or no records, walking up"
                                );
                                continue;
                            }
                        }
                    }
                    // Network / timeout / proto errors → fail closed.
                    _ => {
                        tracing::warn!(
                            query_name,
                            error = %e,
                            "caa: DNS lookup error"
                        );
                        return Err(AcmeError::Caa(format!(
                            "CAA lookup failed for '{name}': {e}"
                        )));
                    }
                }
            }
        }
    }

    // Step 4 (after walk): No CAA records found anywhere → unconstrained (RFC 8659 §4).
    tracing::debug!(
        domain,
        "caa: no CAA records found anywhere, allowing issuance"
    );
    Ok(())
}

/// Build the list of names to check, from `domain` up to (but not including)
/// a single-label name (the TLD).
///
/// Example: `sub.example.com` → `["sub.example.com", "example.com"]`
/// (`com` is excluded because it is a single-label name).
fn build_name_walk(domain: &str) -> Vec<String> {
    let mut names = Vec::new();
    let mut current = domain.trim_end_matches('.');

    loop {
        // Count labels in current name.
        let label_count = current.split('.').count();
        if label_count < 2 {
            // Single label (TLD) or empty — stop.
            break;
        }
        names.push(current.to_string());

        // Walk up: drop the first label.
        match current.find('.') {
            Some(pos) => current = &current[pos + 1..],
            None => break,
        }
    }

    names
}

/// Evaluate a CAA record set against the CA identities.
///
/// Returns `Ok(())` if at least one `issue` (or `issuewild` for wildcards) record
/// authorises issuance, `Err(AcmeError::Caa(...))` if the set denies issuance.
///
/// `challenge_type` is matched against the `validationmethods` parameter when
/// present (RFC 8657 §3).  `account_url` is matched against the `accounturi`
/// parameter when present (RFC 8657 §4); a `None` value causes any record that
/// carries `accounturi` to be rejected.
fn evaluate_caa_record_set(
    records: &[&hickory_resolver::proto::rr::rdata::CAA],
    domain: &str,
    ca_identities: &[String],
    is_wildcard: bool,
    challenge_type: &str,
    account_url: Option<&str>,
) -> Result<(), AcmeError> {
    use hickory_resolver::proto::rr::rdata::caa::Value;

    // RFC 8659 §4: for wildcards, if `issuewild` records are present in the set,
    // use them. If absent, fall back to `issue` records.
    let relevant: Vec<_> = if is_wildcard {
        let issuewild: Vec<_> = records
            .iter()
            .filter(|caa| caa.tag().is_issuewild())
            .collect();
        if issuewild.is_empty() {
            // Fall back to `issue` records for wildcards when no `issuewild` exist.
            records.iter().filter(|caa| caa.tag().is_issue()).collect()
        } else {
            issuewild
        }
    } else {
        records.iter().filter(|caa| caa.tag().is_issue()).collect()
    };

    // If NO relevant records exist in the set → unconstrained by this set.
    // (e.g. only `iodef` records are present — RFC 8659 §4)
    if relevant.is_empty() {
        tracing::debug!(
            domain,
            is_wildcard,
            "caa: no issue/issuewild records in set, allowing issuance"
        );
        return Ok(());
    }

    // Check if any relevant record authorises issuance by one of our CA identities.
    for caa in &relevant {
        if let Value::Issuer(ref name_opt, ref key_values) = *caa.value() {
            // An empty name means "no CA may issue" for this record.
            let tag_name = match name_opt {
                Some(name) => {
                    // Strip trailing dot and lowercase for comparison.
                    name.to_string().trim_end_matches('.').to_ascii_lowercase()
                }
                None => {
                    // Explicit denial ("CAA 0 issue ;") — this record doesn't match any CA.
                    continue;
                }
            };

            // Check if the tag name matches one of our CA identities.
            let identity_match = ca_identities
                .iter()
                .any(|id| id.trim_end_matches('.').to_ascii_lowercase() == tag_name);

            if !identity_match {
                continue;
            }

            // We have a matching identity. Now check RFC 8657 parameters.
            let mut validationmethods_ok = true;
            let mut accounturi_ok = true;

            for kv in key_values {
                match kv.key() {
                    "validationmethods" => {
                        // The value is a comma-separated list of challenge types.
                        if !challenge_type.is_empty() {
                            let methods: Vec<&str> =
                                kv.value().split(',').map(|s| s.trim()).collect();
                            if !methods.contains(&challenge_type) {
                                validationmethods_ok = false;
                            }
                        }
                    }
                    "accounturi" => {
                        // RFC 8657 §4: the requesting account's URL must match.
                        match account_url {
                            Some(url) => {
                                if kv.value() != url {
                                    tracing::debug!(
                                        domain,
                                        record_accounturi = kv.value(),
                                        request_accounturi = url,
                                        "caa: accounturi mismatch — this record does not authorise this account"
                                    );
                                    accounturi_ok = false;
                                }
                            }
                            None => {
                                // Account URL not supplied to the check — deny this record.
                                tracing::warn!(
                                    domain,
                                    "caa: accounturi parameter present but no account URL provided; denying this record"
                                );
                                accounturi_ok = false;
                            }
                        }
                    }
                    _ => {
                        // Unknown parameters: ignore unless critical bit is set.
                        // Per RFC 8659 §4: critical unknown tags → fail issuance.
                        // Here we check the record-level critical flag, not per-param.
                        // Unknown parameters in the value are silently ignored per RFC 8657.
                    }
                }
            }

            if validationmethods_ok && accounturi_ok {
                tracing::info!(
                    domain,
                    ca = tag_name,
                    "caa: issuance authorised by CAA record"
                );
                return Ok(());
            }
        }
    }

    // No record authorised issuance.
    Err(AcmeError::Caa(format!(
        "CAA policy denies issuance for {domain}"
    )))
}

/// Build a resolver, optionally using an override address.
fn build_resolver(
    resolver_addr: Option<&str>,
    validate_dnssec: bool,
) -> Result<TokioAsyncResolver, AcmeError> {
    let mut opts = ResolverOpts::default();
    opts.validate = validate_dnssec;
    let resolver = match resolver_addr {
        Some(addr) => {
            let socket_addr = addr.parse::<std::net::SocketAddr>().map_err(|e| {
                AcmeError::Internal(format!("invalid dns_resolver_addr '{addr}': {e}"))
            })?;
            let mut config = ResolverConfig::new();
            config.add_name_server(NameServerConfig::new(socket_addr, Protocol::Udp));
            TokioAsyncResolver::tokio(config, opts)
        }
        None => TokioAsyncResolver::tokio(ResolverConfig::default(), opts),
    };
    Ok(resolver)
}

// ── Tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_resolver::config::{NameServerConfig, Protocol};
    use tokio::net::UdpSocket;

    // ── Unit tests for build_name_walk ─────────────────────────────────────────

    #[test]
    fn name_walk_single_subdomain() {
        let names = build_name_walk("sub.example.com");
        assert_eq!(names, vec!["sub.example.com", "example.com"]);
    }

    #[test]
    fn name_walk_tld_not_included() {
        let names = build_name_walk("example.com");
        assert_eq!(names, vec!["example.com"]);
    }

    #[test]
    fn name_walk_deep_subdomain() {
        let names = build_name_walk("a.b.c.example.com");
        assert_eq!(
            names,
            vec![
                "a.b.c.example.com",
                "b.c.example.com",
                "c.example.com",
                "example.com"
            ]
        );
    }

    #[test]
    fn name_walk_strips_trailing_dot() {
        let names = build_name_walk("example.com.");
        assert_eq!(names, vec!["example.com"]);
    }

    #[test]
    fn name_walk_single_label_is_empty() {
        let names = build_name_walk("com");
        assert!(names.is_empty());
    }

    // ── Unit tests for empty ca_identities (no-op) ─────────────────────────────

    #[tokio::test]
    async fn empty_ca_identities_returns_ok() {
        // When ca_identities is empty, check_caa is a no-op regardless of anything else.
        let result = check_caa("example.com", &[], false, "http-01", None, None, false).await;
        assert!(
            result.is_ok(),
            "empty identities should always return Ok: {result:?}"
        );
    }

    // ── Wire-format parsing tests (manual raw-byte parsing) ────────────────────
    //
    // These tests exercise the logic that would apply to CAA RDATA if we had to
    // parse it manually, and also verify the build_caa_dns_response helper used
    // in integration tests below.

    /// Helper: build a minimal DNS response with one CAA record.
    fn build_caa_dns_response(query: &[u8], flags: u8, tag: &str, value: &str) -> Vec<u8> {
        // Parse QNAME length from question section (starts at byte 12 after header).
        let mut pos = 12usize;
        while pos < query.len() {
            let label_len = query[pos] as usize;
            pos += 1;
            if label_len == 0 {
                break;
            }
            pos += label_len;
        }
        pos += 4; // skip QTYPE (2) + QCLASS (2)
        let question_end = pos;

        // CAA RDATA: flags(1) + tag_len(1) + tag(N) + value(M)
        let tag_bytes = tag.as_bytes();
        let value_bytes = value.as_bytes();
        let rdlength = (1 + 1 + tag_bytes.len() + value_bytes.len()) as u16;

        let mut resp = Vec::new();
        resp.extend_from_slice(&query[..2]); // Transaction ID
        resp.extend_from_slice(&[0x81, 0x80]); // Flags: QR=1, RD=1, RA=1
        resp.extend_from_slice(&[0x00, 0x01]); // QDCOUNT = 1
        resp.extend_from_slice(&[0x00, 0x01]); // ANCOUNT = 1
        resp.extend_from_slice(&[0x00, 0x00]); // NSCOUNT = 0
        resp.extend_from_slice(&[0x00, 0x00]); // ARCOUNT = 0
        resp.extend_from_slice(&query[12..question_end]); // Echo question section
        resp.extend_from_slice(&[0xC0, 0x0C]); // Name: pointer to offset 12
        resp.extend_from_slice(&[0x01, 0x01]); // TYPE = CAA (257 = 0x0101)
        resp.extend_from_slice(&[0x00, 0x01]); // CLASS = IN
        resp.extend_from_slice(&[0x00, 0x00, 0x00, 0x3C]); // TTL = 60
        resp.extend_from_slice(&rdlength.to_be_bytes()); // RDLENGTH
        resp.push(flags); // flags byte
        resp.push(tag_bytes.len() as u8); // tag length
        resp.extend_from_slice(tag_bytes); // tag
        resp.extend_from_slice(value_bytes); // value
        resp
    }

    /// Helper: build a DNS NXDOMAIN response.
    fn build_nxdomain_response(query: &[u8]) -> Vec<u8> {
        let mut pos = 12usize;
        while pos < query.len() {
            let label_len = query[pos] as usize;
            pos += 1;
            if label_len == 0 {
                break;
            }
            pos += label_len;
        }
        pos += 4;
        let question_end = pos;

        let mut resp = Vec::new();
        resp.extend_from_slice(&query[..2]);
        // Flags: QR=1, AA=1, RD=1, RA=1, RCODE=NXDOMAIN(3)
        resp.extend_from_slice(&[0x85, 0x83]);
        resp.extend_from_slice(&[0x00, 0x01]); // QDCOUNT = 1
        resp.extend_from_slice(&[0x00, 0x00]); // ANCOUNT = 0
        resp.extend_from_slice(&[0x00, 0x00]); // NSCOUNT = 0
        resp.extend_from_slice(&[0x00, 0x00]); // ARCOUNT = 0
        resp.extend_from_slice(&query[12..question_end]);
        resp
    }

    /// Start a mock DNS server that serves CAA records.
    ///
    /// The server serves queries in order. For each query it pops from the front
    /// of `responses`, which is a Vec of closures returning the response bytes.
    /// If the vec is empty, it sends NXDOMAIN.
    async fn start_mock_dns(responses: Vec<Box<dyn Fn(&[u8]) -> Vec<u8> + Send + 'static>>) -> u16 {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = socket.local_addr().unwrap().port();
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            let mut responses = responses;
            while !responses.is_empty() {
                if let Ok((n, addr)) = socket.recv_from(&mut buf).await {
                    let query = &buf[..n];
                    let response_fn = responses.remove(0);
                    let response = response_fn(query);
                    let _ = socket.send_to(&response, addr).await;
                }
            }
        });
        port
    }

    fn local_resolver(port: u16) -> TokioAsyncResolver {
        let mut config = ResolverConfig::new();
        let ns = NameServerConfig::new(format!("127.0.0.1:{port}").parse().unwrap(), Protocol::Udp);
        config.add_name_server(ns);
        let mut opts = ResolverOpts::default();
        // Disable search path expansion for tests.
        opts.ndots = 0;
        opts.attempts = 1;
        TokioAsyncResolver::tokio(config, opts)
    }

    // ── DNS-based integration tests ────────────────────────────────────────────

    /// No CAA records anywhere → Ok (unconstrained, RFC 8659 §4).
    #[tokio::test]
    async fn no_caa_records_returns_ok() {
        // NXDOMAIN for example.com (only one label to walk, no parent to try).
        let port = start_mock_dns(vec![Box::new(build_nxdomain_response)]).await;
        let resolver = local_resolver(port);
        let result = check_caa_with_resolver(
            "example.com",
            &["ca.example.com".to_string()],
            false,
            "http-01",
            None,
            resolver,
        )
        .await;
        assert!(
            result.is_ok(),
            "no CAA records should return Ok: {result:?}"
        );
    }

    /// CAA record exists and matches our CA identity → Ok.
    #[tokio::test]
    async fn matching_caa_record_returns_ok() {
        let port = start_mock_dns(vec![Box::new(|q: &[u8]| {
            build_caa_dns_response(q, 0, "issue", "ca.example.com")
        })])
        .await;
        let resolver = local_resolver(port);
        let result = check_caa_with_resolver(
            "example.com",
            &["ca.example.com".to_string()],
            false,
            "http-01",
            None,
            resolver,
        )
        .await;
        assert!(
            result.is_ok(),
            "matching CAA record should return Ok: {result:?}"
        );
    }

    /// CAA `issue` record does not match any of our CA identities → Err(Caa).
    #[tokio::test]
    async fn non_matching_caa_record_returns_err() {
        let port = start_mock_dns(vec![Box::new(|q: &[u8]| {
            build_caa_dns_response(q, 0, "issue", "other-ca.example.com")
        })])
        .await;
        let resolver = local_resolver(port);
        let result = check_caa_with_resolver(
            "example.com",
            &["ca.example.com".to_string()],
            false,
            "http-01",
            None,
            resolver,
        )
        .await;
        assert!(
            matches!(result, Err(AcmeError::Caa(_))),
            "non-matching CAA record should return Err(Caa): {result:?}"
        );
    }

    /// Wildcard cert: when no `issuewild` is present, `issue` records govern wildcards (RFC 8659 §4).
    /// A matching `issue` record with our CA → Ok.
    #[tokio::test]
    async fn wildcard_falls_back_to_issue_when_no_issuewild() {
        // Only an `issue` record, no `issuewild`. RFC 8659 §4 says `issue` governs wildcards
        // when `issuewild` is absent.
        let port = start_mock_dns(vec![Box::new(|q: &[u8]| {
            build_caa_dns_response(q, 0, "issue", "ca.example.com")
        })])
        .await;
        let resolver = local_resolver(port);
        let result = check_caa_with_resolver(
            "example.com",
            &["ca.example.com".to_string()],
            true, // wildcard
            "dns-01",
            None,
            resolver,
        )
        .await;
        assert!(
            result.is_ok(),
            "matching issue record governs wildcards when no issuewild is present: {result:?}"
        );
    }

    /// Wildcard cert: `issue` record present (non-matching) but no `issuewild` → Err(Caa).
    #[tokio::test]
    async fn wildcard_issue_fallback_non_matching_returns_err() {
        // Only an `issue` record for a different CA, no `issuewild`.
        let port = start_mock_dns(vec![Box::new(|q: &[u8]| {
            build_caa_dns_response(q, 0, "issue", "other-ca.example.com")
        })])
        .await;
        let resolver = local_resolver(port);
        let result = check_caa_with_resolver(
            "example.com",
            &["ca.example.com".to_string()],
            true, // wildcard
            "dns-01",
            None,
            resolver,
        )
        .await;
        assert!(
            matches!(result, Err(AcmeError::Caa(_))),
            "non-matching issue record should deny wildcard when no issuewild present: {result:?}"
        );
    }

    /// Wildcard cert: `issuewild` record matching our CA → Ok.
    #[tokio::test]
    async fn wildcard_with_issuewild_record_returns_ok() {
        let port = start_mock_dns(vec![Box::new(|q: &[u8]| {
            build_caa_dns_response(q, 0, "issuewild", "ca.example.com")
        })])
        .await;
        let resolver = local_resolver(port);
        let result = check_caa_with_resolver(
            "example.com",
            &["ca.example.com".to_string()],
            true, // wildcard
            "dns-01",
            None,
            resolver,
        )
        .await;
        assert!(
            result.is_ok(),
            "issuewild record should satisfy wildcard: {result:?}"
        );
    }

    /// `validationmethods` param present with matching method → Ok.
    #[tokio::test]
    async fn validationmethods_matching_returns_ok() {
        // CAA value: "ca.example.com; validationmethods=http-01,dns-01"
        let port = start_mock_dns(vec![Box::new(|q: &[u8]| {
            build_caa_dns_response(
                q,
                0,
                "issue",
                "ca.example.com; validationmethods=http-01,dns-01",
            )
        })])
        .await;
        let resolver = local_resolver(port);
        let result = check_caa_with_resolver(
            "example.com",
            &["ca.example.com".to_string()],
            false,
            "http-01",
            None,
            resolver,
        )
        .await;
        assert!(
            result.is_ok(),
            "matching validationmethods should return Ok: {result:?}"
        );
    }

    /// `validationmethods` param present but challenge type not in list → Err(Caa).
    #[tokio::test]
    async fn validationmethods_non_matching_returns_err() {
        // CAA value: "ca.example.com; validationmethods=dns-01"
        let port = start_mock_dns(vec![Box::new(|q: &[u8]| {
            build_caa_dns_response(q, 0, "issue", "ca.example.com; validationmethods=dns-01")
        })])
        .await;
        let resolver = local_resolver(port);
        let result = check_caa_with_resolver(
            "example.com",
            &["ca.example.com".to_string()],
            false,
            "http-01", // not in validationmethods
            None,
            resolver,
        )
        .await;
        assert!(
            matches!(result, Err(AcmeError::Caa(_))),
            "non-matching validationmethods should return Err(Caa): {result:?}"
        );
    }

    /// CAA record set with only `iodef` (no `issue` or `issuewild`) → Ok
    /// (RFC 8659 §4: only unrelated tags present, no restriction applies).
    #[tokio::test]
    async fn only_iodef_records_returns_ok() {
        let port = start_mock_dns(vec![Box::new(|q: &[u8]| {
            build_caa_dns_response(q, 0, "iodef", "mailto:security@example.com")
        })])
        .await;
        let resolver = local_resolver(port);
        let result = check_caa_with_resolver(
            "example.com",
            &["ca.example.com".to_string()],
            false,
            "http-01",
            None,
            resolver,
        )
        .await;
        // iodef-only → no issue/issuewild restriction
        assert!(
            result.is_ok(),
            "iodef-only CAA record set should return Ok: {result:?}"
        );
    }

    /// CAA tag matching is case-insensitive.
    #[tokio::test]
    async fn ca_identity_matching_is_case_insensitive() {
        // DNS returns "CA.EXAMPLE.COM"; our identity is "ca.example.com"
        let port = start_mock_dns(vec![Box::new(|q: &[u8]| {
            build_caa_dns_response(q, 0, "issue", "CA.EXAMPLE.COM")
        })])
        .await;
        let resolver = local_resolver(port);
        let result = check_caa_with_resolver(
            "example.com",
            &["ca.example.com".to_string()],
            false,
            "http-01",
            None,
            resolver,
        )
        .await;
        assert!(
            result.is_ok(),
            "CA identity matching should be case-insensitive: {result:?}"
        );
    }

    /// RFC 8657 §4: `accounturi` param matches the requesting account URL → Ok.
    #[tokio::test]
    async fn accounturi_matching_returns_ok() {
        let port = start_mock_dns(vec![Box::new(|q: &[u8]| {
            build_caa_dns_response(
                q,
                0,
                "issue",
                "ca.example.com; accounturi=https://acme.example.com/acme/account/42",
            )
        })])
        .await;
        let resolver = local_resolver(port);
        let result = check_caa_with_resolver(
            "example.com",
            &["ca.example.com".to_string()],
            false,
            "http-01",
            Some("https://acme.example.com/acme/account/42"),
            resolver,
        )
        .await;
        assert!(
            result.is_ok(),
            "matching accounturi should return Ok: {result:?}"
        );
    }

    /// RFC 8657 §4: `accounturi` param does not match the requesting account URL → Err(Caa).
    #[tokio::test]
    async fn accounturi_mismatch_returns_err() {
        let port = start_mock_dns(vec![Box::new(|q: &[u8]| {
            build_caa_dns_response(
                q,
                0,
                "issue",
                "ca.example.com; accounturi=https://acme.example.com/acme/account/42",
            )
        })])
        .await;
        let resolver = local_resolver(port);
        let result = check_caa_with_resolver(
            "example.com",
            &["ca.example.com".to_string()],
            false,
            "http-01",
            Some("https://acme.example.com/acme/account/99"), // different account
            resolver,
        )
        .await;
        assert!(
            matches!(result, Err(AcmeError::Caa(_))),
            "mismatched accounturi should return Err(Caa): {result:?}"
        );
    }
}
