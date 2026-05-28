//! Shared cryptographic utility functions.

/// Compute the SHA-256 fingerprint of `data` and return it as a lowercase hex string.
pub fn sha256_hex(data: &[u8]) -> Result<String, String> {
    let alg = native_ossl::digest::DigestAlg::fetch(c"SHA2-256", None)
        .map_err(|e| format!("SHA2-256 fetch: {e}"))?;
    let mut ctx = alg
        .new_context()
        .map_err(|e| format!("digest context: {e}"))?;
    ctx.update(data)
        .map_err(|e| format!("digest update: {e}"))?;
    let mut out = [0u8; 32];
    ctx.finish(&mut out)
        .map_err(|e| format!("digest finish: {e}"))?;
    Ok(native_ossl::util::hex_encode(out))
}
