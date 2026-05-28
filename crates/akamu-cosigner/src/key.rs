use std::path::Path;
use synta_certificate::BackendPrivateKey;

use crate::config::SigningKeyConfig;
use crate::error::CosignerError;

/// Generate a `BackendPrivateKey` from a key-type string.
///
/// Inlined from `akamu::ca::init::generate_backend_key` to avoid the full
/// `akamu` library dependency in the cosigner binary.
fn generate_backend_key(key_type: &str) -> Result<BackendPrivateKey, CosignerError> {
    let cry =
        |e: &dyn std::fmt::Display| CosignerError::Crypto(format!("generate {key_type}: {e}"));
    match key_type {
        "ec:P-256" | "P-256" => BackendPrivateKey::generate_ec("P-256").map_err(|e| cry(&e)),
        "ec:P-384" | "P-384" => BackendPrivateKey::generate_ec("P-384").map_err(|e| cry(&e)),
        "ec:P-521" | "P-521" => BackendPrivateKey::generate_ec("P-521").map_err(|e| cry(&e)),
        "rsa:2048" | "rsa2048" => BackendPrivateKey::generate_rsa(2048, 65537).map_err(|e| cry(&e)),
        "rsa:3072" | "rsa3072" => BackendPrivateKey::generate_rsa(3072, 65537).map_err(|e| cry(&e)),
        "rsa:4096" | "rsa4096" => BackendPrivateKey::generate_rsa(4096, 65537).map_err(|e| cry(&e)),
        "ed25519" => BackendPrivateKey::generate_ed25519().map_err(|e| cry(&e)),
        "ed448" => BackendPrivateKey::generate_ed448().map_err(|e| cry(&e)),
        "ml-dsa-44" | "ML-DSA-44" => {
            BackendPrivateKey::generate_ml_dsa("ML-DSA-44").map_err(|e| cry(&e))
        }
        "ml-dsa-65" | "ML-DSA-65" => {
            BackendPrivateKey::generate_ml_dsa("ML-DSA-65").map_err(|e| cry(&e))
        }
        "ml-dsa-87" | "ML-DSA-87" => {
            BackendPrivateKey::generate_ml_dsa("ML-DSA-87").map_err(|e| cry(&e))
        }
        other => {
            let upper = other.to_ascii_uppercase();
            let candidate = upper.strip_prefix("COMPOSITE-").unwrap_or(&upper);
            for sub_arc in 37u32..=54 {
                if let Some(spec) = synta_certificate::crypto::composite_spec(sub_arc) {
                    let label_upper = spec.label.to_ascii_uppercase();
                    let label_short = label_upper.strip_prefix("COMPSIG-").unwrap_or(&label_upper);
                    if candidate == label_upper || candidate == label_short {
                        return BackendPrivateKey::generate_composite_ml_dsa(sub_arc)
                            .map_err(|e| cry(&e));
                    }
                }
            }
            Err(CosignerError::Crypto(format!(
                "unknown key type '{other}'; use 'ec:P-256', 'rsa:2048', 'ed25519', \
                 'ml-dsa-44', or composite form"
            )))
        }
    }
}

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
        let key = generate_backend_key(&cfg.key_type)?;
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
