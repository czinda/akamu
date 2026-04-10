//! dns-01 challenge validation (RFC 8555 §8.4).
//!
//! Queries TXT records for `_acme-challenge.{domain}` and checks that at least
//! one value equals `BASE64URL(SHA-256(keyAuthorization))`.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use hickory_resolver::TokioAsyncResolver;
use sha2::{Digest, Sha256};

use crate::error::AcmeError;

/// Validate a dns-01 challenge.
///
/// * `domain`   — the identifier value; any leading `*.` wildcard is stripped
///                before querying.
/// * `key_auth` — `{token}.{jwk_thumbprint}`.
pub async fn validate(domain: &str, key_auth: &str) -> Result<(), AcmeError> {
    // RFC 8555 §8.4: for wildcard orders the identifier has the `*.` prefix
    // stripped when forming the DNS query.
    let base_domain = domain.strip_prefix("*.").unwrap_or(domain);
    let query_name = format!("_acme-challenge.{}", base_domain);

    // Compute expected TXT value: base64url(SHA-256(keyAuthorization)).
    let digest = Sha256::digest(key_auth.as_bytes());
    let expected = URL_SAFE_NO_PAD.encode(digest);

    let resolver = TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());

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
