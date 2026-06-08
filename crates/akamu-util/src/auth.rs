//! Authentication primitives shared between the akamu ACME server and
//! the akamu-cosigner daemon.
//!
//! These are intentionally thin; the full admin authentication logic (session
//! management, DB lookups, GSSAPI, EAB) lives in `akamu::admin::auth` which
//! depends on the full akamu library.  Only the parts needed by the cosigner
//! are placed here.

// ── PeerClientCert extension ──────────────────────────────────────────────────

/// DER-encoded leaf client certificate injected into request extensions by the
/// TLS accept loop.  Absent when the listener has no client-cert requirement or
/// the client presented no certificate.
#[derive(Clone)]
pub struct PeerClientCert(pub Vec<u8>);

// ── Session token generation ──────────────────────────────────────────────────

/// Generate a cryptographically random 32-byte hex-encoded session token.
pub fn generate_token() -> Result<String, String> {
    let mut bytes = [0u8; 32];
    native_ossl::rand::Rand::fill(&mut bytes).map_err(|e| format!("getrandom: {e}"))?;
    Ok(native_ossl::util::hex_encode(bytes))
}

// ── Session store helpers ─────────────────────────────────────────────────────

/// Constant-time lookup of `token` among the keys of `map`.
///
/// Uses `subtle::ConstantTimeEq` to prevent timing side-channels.  Residual:
/// `find()` short-circuits on the first match, leaking the map position.
/// HashMap iteration order is randomised by the std hasher; this residual is
/// accepted.
pub fn find_session_token<V>(
    map: &std::collections::HashMap<String, V>,
    token: &str,
) -> Option<String> {
    use subtle::ConstantTimeEq as _;
    let token_bytes = token.as_bytes();
    map.keys()
        .find(|k| {
            let kb = k.as_bytes();
            kb.len() == token_bytes.len() && kb.ct_eq(token_bytes).into()
        })
        .cloned()
}
