//! dns-01 challenge validation (RFC 8555 §8.4).
//!
//! Queries TXT records for `_acme-challenge.{domain}` and checks that at least
//! one value equals `BASE64URL(SHA-256(keyAuthorization))`.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use hickory_resolver::TokioAsyncResolver;
use synta_certificate::{default_data_hasher, DataHasher};

use crate::error::AcmeError;

/// Validate a dns-01 challenge.
///
/// * `domain`   — the identifier value; any leading `*.` wildcard is stripped
///   before querying.
/// * `key_auth` — `{token}.{jwk_thumbprint}`.
pub async fn validate(domain: &str, key_auth: &str) -> Result<(), AcmeError> {
    let resolver = TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());
    validate_with_resolver(domain, key_auth, resolver).await
}

/// Inner implementation that takes a custom resolver for testability.
async fn validate_with_resolver(
    domain: &str,
    key_auth: &str,
    resolver: TokioAsyncResolver,
) -> Result<(), AcmeError> {
    // RFC 8555 §8.4: for wildcard orders the identifier has the `*.` prefix
    // stripped when forming the DNS query.
    let base_domain = domain.strip_prefix("*.").unwrap_or(domain);
    let query_name = format!("_acme-challenge.{}", base_domain);

    // Compute expected TXT value: base64url(SHA-256(keyAuthorization)).
    let digest = default_data_hasher()
        .hash_data("sha256", key_auth.as_bytes())
        .map_err(|e| AcmeError::Crypto(format!("SHA-256 digest: {e}")))?;
    let expected = URL_SAFE_NO_PAD.encode(&digest);

    let lookup = resolver
        .txt_lookup(&query_name)
        .await
        .map_err(|e| AcmeError::Dns(format!("TXT lookup for '{query_name}': {e}")))?;

    for record in lookup.iter() {
        // TXT records may be split across multiple character-strings; join them.
        let value: String = record
            .iter()
            .map(|s| String::from_utf8_lossy(s).into_owned())
            .collect();
        if value.trim() == expected {
            return Ok(());
        }
    }

    Err(AcmeError::IncorrectResponse(format!(
        "dns-01: no TXT record at '{query_name}' matches the expected value"
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_resolver::config::{NameServerConfig, Protocol};
    use tokio::net::UdpSocket;

    /// Constructs a minimal DNS TXT response packet by echoing the question section
    /// back and appending a single TXT answer record with `txt_value`.
    fn build_txt_dns_response(query: &[u8], txt_value: &str) -> Vec<u8> {
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

        let txt_bytes = txt_value.as_bytes();
        let rdlength = (txt_bytes.len() + 1) as u16; // +1 for the length-prefix octet

        let mut resp = Vec::with_capacity(question_end + 16 + txt_bytes.len());
        resp.extend_from_slice(&query[..2]); // Transaction ID (echo)
        resp.extend_from_slice(&[0x81, 0x80]); // Flags: QR=1, RD=1, RA=1
        resp.extend_from_slice(&[0x00, 0x01]); // QDCOUNT = 1
        resp.extend_from_slice(&[0x00, 0x01]); // ANCOUNT = 1
        resp.extend_from_slice(&[0x00, 0x00]); // NSCOUNT = 0
        resp.extend_from_slice(&[0x00, 0x00]); // ARCOUNT = 0
        resp.extend_from_slice(&query[12..question_end]); // Echo question section
        resp.extend_from_slice(&[0xC0, 0x0C]); // Name: pointer to offset 12
        resp.extend_from_slice(&[0x00, 0x10]); // TYPE = TXT (16)
        resp.extend_from_slice(&[0x00, 0x01]); // CLASS = IN
        resp.extend_from_slice(&[0x00, 0x00, 0x00, 0x3C]); // TTL = 60
        resp.extend_from_slice(&rdlength.to_be_bytes()); // RDLENGTH
        resp.push(txt_bytes.len() as u8); // TXT string length prefix
        resp.extend_from_slice(txt_bytes); // TXT string data
        resp
    }

    /// Start a local UDP "DNS" server that responds to exactly one query with the
    /// given TXT value, then returns the port it bound to.
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

    /// Build a resolver config pointing at a local UDP nameserver on `port`.
    fn local_resolver(port: u16) -> (ResolverConfig, ResolverOpts) {
        let mut config = ResolverConfig::new();
        let ns = NameServerConfig::new(format!("127.0.0.1:{port}").parse().unwrap(), Protocol::Udp);
        config.add_name_server(ns);
        (config, ResolverOpts::default())
    }

    /// Covers dns01.rs lines 36-43: TXT record found and value matches → Ok(()).
    #[tokio::test]
    async fn validate_matching_txt_returns_ok() {
        let key_auth = "test-token.test-thumbprint";
        let digest = default_data_hasher()
            .hash_data("sha256", key_auth.as_bytes())
            .expect("SHA-256 digest");
        let expected = URL_SAFE_NO_PAD.encode(&digest);

        let port = start_txt_dns_server(expected).await;
        let (config, opts) = local_resolver(port);
        let resolver = TokioAsyncResolver::tokio(config, opts);

        let result = validate_with_resolver("example.test", key_auth, resolver).await;
        assert!(
            result.is_ok(),
            "expected Ok for matching TXT record: {result:?}"
        );
    }

    /// Covers dns01.rs lines 36-44, 47-49: TXT record found but value wrong → IncorrectResponse.
    #[tokio::test]
    async fn validate_wrong_txt_returns_incorrect_response() {
        let port = start_txt_dns_server("wrong-value-that-does-not-match".to_string()).await;
        let (config, opts) = local_resolver(port);
        let resolver = TokioAsyncResolver::tokio(config, opts);

        let result = validate_with_resolver("example.test", "token.thumbprint", resolver).await;
        assert!(
            matches!(result, Err(AcmeError::IncorrectResponse(_))),
            "expected IncorrectResponse for wrong TXT value: {result:?}"
        );
    }

    #[tokio::test]
    async fn validate_fails_for_nonexistent_domain() {
        // This domain is guaranteed not to exist; the DNS lookup will fail.
        let result = validate(
            "invalid.localhost.acme-test-nonexistent.invalid",
            "token.thumbprint",
        )
        .await;
        // Should return a Dns error or IncorrectResponse
        assert!(result.is_err(), "expected error for non-existent domain");
    }

    #[tokio::test]
    async fn validate_strips_wildcard_prefix() {
        // Wildcard domain "*.example.invalid" should query "_acme-challenge.example.invalid",
        // not "_acme-challenge.*.example.invalid". The DNS lookup will fail (domain doesn't exist),
        // but the error message should reference the stripped domain.
        let result = validate("*.acme-test-nonexistent.invalid", "token.thumbprint").await;
        assert!(result.is_err());
        // The error must reference "acme-test-nonexistent.invalid" (stripped domain)
        let msg = result.unwrap_err().to_string();
        assert!(
            !msg.contains("*."),
            "wildcard prefix should be stripped: {msg}"
        );
    }
}
