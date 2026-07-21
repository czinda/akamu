//! Shared utility functions.

/// Read a password from a file path, or from stdin when `path` is `"-"`.
///
/// Returns a [`SecretBuffer`] so the password is zeroed on drop.
/// Trailing `\n` and `\r` are stripped so that files created with
/// `echo "secret" > pw.txt` work without surprises.
///
/// If `context` is non-empty it is prepended to error messages
/// (e.g. `"profiles provider 'ldap1': read password file …"`).
pub fn read_password_from_file(
    path: &std::path::Path,
    context: &str,
) -> Result<crate::SecretBuffer, String> {
    let prefix = if context.is_empty() {
        String::new()
    } else {
        format!("{context}: ")
    };
    let raw = if path == std::path::Path::new("-") {
        use std::io::BufRead;
        let mut line = String::new();
        std::io::stdin()
            .lock()
            .read_line(&mut line)
            .map_err(|e| format!("{prefix}read password from stdin: {e}"))?;
        line
    } else {
        let meta = std::fs::metadata(path)
            .map_err(|e| format!("{prefix}read password file '{}': {e}", path.display()))?;
        if meta.len() > 4096 {
            return Err(format!(
                "{prefix}password file '{}' is too large ({} bytes, max 4096)",
                path.display(),
                meta.len()
            ));
        }
        std::fs::read_to_string(path)
            .map_err(|e| format!("{prefix}read password file '{}': {e}", path.display()))?
    };
    let trimmed = raw.trim_end_matches('\n').trim_end_matches('\r');
    let secret = crate::SecretBuffer::from_bytes(trimmed.as_bytes());
    // `raw` is dropped here — but it's a plain String so the memory is
    // only freed, not zeroed.  The *returned* SecretBuffer is the one
    // that matters: it holds the canonical copy and zeroes on drop.
    Ok(secret)
}

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
