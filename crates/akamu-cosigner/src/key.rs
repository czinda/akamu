use std::path::Path;
use synta_certificate::BackendPrivateKey;

use crate::config::SigningKeyConfig;
use crate::error::CosignerError;

/// Write `data` to `path` with mode 0o600 (owner-read/write only).
///
/// Uses `OpenOptions` on Unix to set the mode atomically on creation,
/// preventing a window where the file is world-readable.
pub(crate) fn write_private_file(path: &str, data: &[u8]) -> Result<(), CosignerError> {
    #[cfg(unix)]
    {
        use std::io::Write as _;
        use std::os::unix::fs::OpenOptionsExt as _;
        std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?
            .write_all(data)?;
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, data)?;
    }
    Ok(())
}

/// Load the signing key from `cfg.key_file`, or generate and persist it if absent.
///
/// Mirrors `load_or_generate_mtc_key` in akamu `src/main.rs`, reusing
/// `akamu::ca::init::generate_backend_key` for key generation.
pub fn load_or_generate(cfg: &SigningKeyConfig) -> Result<BackendPrivateKey, CosignerError> {
    if Path::new(&cfg.key_file).exists() {
        let pem = std::fs::read(&cfg.key_file)?;
        BackendPrivateKey::from_pem(&pem, None)
            .map_err(|e| CosignerError::Crypto(format!("load signing key '{}': {e}", cfg.key_file)))
    } else {
        tracing::info!(
            "generating new cosigner signing key ({}) → {}",
            cfg.key_type,
            cfg.key_file
        );
        let key = akamu::ca::init::generate_backend_key(&cfg.key_type)?;
        let pem = key
            .to_pem(None)
            .map_err(|e| CosignerError::Crypto(format!("signing key to PEM: {e}")))?;
        write_private_file(&cfg.key_file, &pem)?;
        Ok(key)
    }
}

/// Derive the DER-encoded `AlgorithmIdentifier` for signing with `key` using `hash_alg`.
///
/// Returns the DER bytes that can be decoded into `AlgorithmIdentifier<'_>` per request.
/// Stored in `AppState.sig_alg_der` to avoid re-deriving on every request.
pub fn sig_alg_der(key: &BackendPrivateKey, hash_alg: &str) -> Result<Vec<u8>, CosignerError> {
    let pub_key = key
        .public_key()
        .map_err(|e| CosignerError::Crypto(format!("public key from signing key: {e}")))?;
    let spki_der = pub_key.spki_der().to_vec();

    // Decode the SPKI to get the key OID.
    let mut dec = synta::Decoder::new(&spki_der, synta::Encoding::Der);
    let spki: synta_certificate::SubjectPublicKeyInfo = dec
        .decode()
        .map_err(|e| CosignerError::Asn1(format!("decode SPKI: {e}")))?;

    synta_certificate::signing_algorithm_der(&spki.algorithm.algorithm, hash_alg).ok_or_else(|| {
        CosignerError::Crypto(format!(
            "unsupported key/hash combination for signing: hash_alg='{hash_alg}'"
        ))
    })
}
