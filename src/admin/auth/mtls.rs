//! mTLS and proxy-forwarded client certificate admin authentication.
//!
//! Reads the `PeerClientCert` request extension (injected by the admin TLS
//! accept loop) for direct mTLS, or parses a proxy-forwarded header (XFCC or
//! raw PEM) when `[admin.proxy_auth]` is configured, computes SHA-256 of the
//! DER bytes, and looks up the fingerprint in the `operators` table.

use axum::http::request::Parts;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

use crate::config::{AdminProxyAuthConfig, ProxyHeaderFormat};

/// DER-encoded leaf client certificate injected into request extensions by the
/// admin TLS accept loop.  Absent when the admin listener has no client-cert
/// requirement or the client presented no certificate.
#[derive(Clone)]
pub struct PeerClientCert(pub Vec<u8>);

/// Extract the `Cert=` value from an Envoy XFCC header.
///
/// XFCC format: elements separated by `,`, key-value pairs within each
/// element separated by `;`, key and value joined by `=`.  Values may be
/// double-quoted (and quoted values may contain commas/semicolons).
/// We take the **last** element (nearest proxy).
fn parse_xfcc_cert(header_value: &str) -> Option<String> {
    let elements = split_xfcc_elements(header_value);
    let last_element = elements.last()?;
    for pair in split_xfcc_pairs(last_element) {
        let pair = pair.trim();
        if let Some((key, value)) = pair.split_once('=') {
            if key.trim().eq_ignore_ascii_case("Cert") {
                let v = value.trim();
                let v = v
                    .strip_prefix('"')
                    .and_then(|s| s.strip_suffix('"'))
                    .unwrap_or(v);
                return Some(v.to_owned());
            }
        }
    }
    None
}

/// Split XFCC header into elements on `,`, respecting double-quoted values.
fn split_xfcc_elements(s: &str) -> Vec<String> {
    split_respecting_quotes(s, ',')
}

/// Split a single XFCC element into key-value pairs on `;`, respecting quotes.
fn split_xfcc_pairs(s: &str) -> Vec<String> {
    split_respecting_quotes(s, ';')
}

fn split_respecting_quotes(s: &str, delimiter: char) -> Vec<String> {
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    for ch in s.chars() {
        if ch == '"' {
            in_quotes = !in_quotes;
            current.push(ch);
        } else if ch == delimiter && !in_quotes {
            parts.push(std::mem::take(&mut current));
        } else {
            current.push(ch);
        }
    }
    parts.push(current);
    parts
}

/// Maximum size of a proxy-forwarded certificate header (64 KiB).
const MAX_PROXY_CERT_HEADER_LEN: usize = 64 * 1024;

/// Try to extract a DER-encoded client certificate from a proxy-forwarded
/// header.  Returns `Ok(None)` when no cert is available (peer untrusted or
/// header absent).  Returns `Err(400)` when the header is present but
/// malformed.
#[allow(clippy::result_large_err)]
pub(super) fn extract_proxy_cert(
    parts: &Parts,
    proxy_cfg: &AdminProxyAuthConfig,
) -> Result<Option<Vec<u8>>, Response> {
    let peer_addr = match parts
        .extensions
        .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
    {
        Some(ci) => ci.0,
        None => {
            tracing::warn!("proxy cert auth: ConnectInfo absent from request extensions");
            return Ok(None);
        }
    };

    if !proxy_cfg.trusted_proxies.contains(&peer_addr.ip()) {
        return Ok(None);
    }

    let fmt = proxy_cfg.header_format;
    let header_name = fmt.header_name();

    let hdr = match parts.headers.get(header_name) {
        Some(v) => v,
        None => return Ok(None),
    };
    let hdr_str = hdr.to_str().map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            format!("{header_name} header is not valid UTF-8"),
        )
            .into_response()
    })?;
    if hdr_str.len() > MAX_PROXY_CERT_HEADER_LEN {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("{header_name} header exceeds size limit"),
        )
            .into_response());
    }

    let pem_value = if fmt == ProxyHeaderFormat::Xfcc {
        match parse_xfcc_cert(hdr_str) {
            Some(v) => std::borrow::Cow::Owned(v),
            None => return Ok(None),
        }
    } else {
        std::borrow::Cow::Borrowed(hdr_str)
    };

    let decoded = percent_encoding::percent_decode_str(&pem_value)
        .decode_utf8()
        .map_err(|_| {
            (
                StatusCode::BAD_REQUEST,
                format!("{header_name}: URL-decoded value is not valid UTF-8"),
            )
                .into_response()
        })?;
    let der = synta_certificate::pem_to_der(decoded.as_bytes())
        .into_iter()
        .next()
        .ok_or_else(|| {
            (
                StatusCode::BAD_REQUEST,
                format!("{header_name}: no PEM certificate found"),
            )
                .into_response()
        })?;
    Ok(Some(der))
}

/// Cheap check: does a proxy cert header exist and is the peer trusted?
/// Used for rate-limiting without full parsing.
pub(super) fn has_proxy_cert_header(parts: &Parts, config: &crate::config::Config) -> bool {
    let proxy_cfg = match config.admin.as_ref().and_then(|a| a.proxy_auth.as_ref()) {
        Some(p) => p,
        None => return false,
    };
    let peer_addr = match parts
        .extensions
        .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
    {
        Some(ci) => ci.0,
        None => return false,
    };
    if !proxy_cfg.trusted_proxies.contains(&peer_addr.ip()) {
        return false;
    }
    parts
        .headers
        .contains_key(proxy_cfg.header_format.header_name())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_xfcc_cert_basic() {
        let hdr = "Cert=ABCD";
        assert_eq!(parse_xfcc_cert(hdr), Some("ABCD".to_string()));
    }

    #[test]
    fn parse_xfcc_cert_quoted() {
        let hdr = r#"Cert="ABCD""#;
        assert_eq!(parse_xfcc_cert(hdr), Some("ABCD".to_string()));
    }

    #[test]
    fn parse_xfcc_cert_multi_element_takes_last() {
        let hdr = "Cert=FIRST,Cert=SECOND";
        assert_eq!(parse_xfcc_cert(hdr), Some("SECOND".to_string()));
    }

    #[test]
    fn parse_xfcc_cert_with_other_fields() {
        let hdr = "By=spiffe://foo;Hash=abc123;Cert=MYCERT;Subject=\"CN=test\"";
        assert_eq!(parse_xfcc_cert(hdr), Some("MYCERT".to_string()));
    }

    #[test]
    fn parse_xfcc_cert_missing_cert_key() {
        let hdr = "By=spiffe://foo;Hash=abc123";
        assert_eq!(parse_xfcc_cert(hdr), None);
    }

    #[test]
    fn parse_xfcc_cert_empty() {
        assert_eq!(parse_xfcc_cert(""), None);
    }

    #[test]
    fn parse_xfcc_cert_quoted_comma_in_subject() {
        let hdr = r#"Subject="O=Corp, Inc.";Cert=MYCERT"#;
        assert_eq!(parse_xfcc_cert(hdr), Some("MYCERT".to_string()));
    }

    #[test]
    fn parse_xfcc_cert_case_insensitive() {
        let hdr = "cert=ABCD";
        assert_eq!(parse_xfcc_cert(hdr), Some("ABCD".to_string()));
    }

    #[test]
    fn parse_xfcc_cert_quoted_semicolon_in_value() {
        let hdr = r#"Subject="CN=a;b";Cert=MYCERT"#;
        assert_eq!(parse_xfcc_cert(hdr), Some("MYCERT".to_string()));
    }
}
