//! Merkle Tree Certificate transparency log integration.
//!
//! Wraps `synta_mtc::storage::DiskBackedLog` for use in an async context.
//! The log itself uses synchronous file I/O; CPU-bound encoding work is
//! offloaded to `tokio::task::spawn_blocking` and the sub-millisecond disk
//! append runs under a `tokio::sync::Mutex` guard.

use std::sync::Arc;

use synta::traits::Encode;
use synta::{Decoder, Encoder, Encoding};
use synta_certificate::Certificate;
use synta_mtc::{
    crypto::{hash_leaf, HashAlgorithm},
    integration::tbs_certificate_to_log_entry,
    storage::DiskBackedLog,
};
use tokio::sync::Mutex;

use crate::error::AcmeError;

/// Shared handle to the disk-backed MTC log.
pub type SharedLog = Arc<Mutex<DiskBackedLog>>;

/// Open an existing MTC log file, or create a new one if none exists.
///
/// Uses a try-create-first strategy to eliminate the TOCTOU race that a
/// `exists()` → `open/create` sequence would introduce: we attempt to create
/// the log, and if that fails (because the file already exists), we open it.
///
/// Note: concurrent calls on the **same path** from different processes are
/// still not supported — the caller is responsible for ensuring mutual
/// exclusion at that level (e.g. via a file lock or single-process guarantee).
pub fn open_or_create(path: &str, algorithm: HashAlgorithm) -> Result<DiskBackedLog, AcmeError> {
    match DiskBackedLog::create(path, algorithm) {
        Ok(log) => Ok(log),
        Err(_) => {
            // Creation failed — assume the file already exists and open it.
            DiskBackedLog::open(path).map_err(|e| AcmeError::Mtc(format!("open MTC log: {e}")))
        }
    }
}

/// Append an issued certificate to the MTC transparency log.
///
/// The `TBSCertificate` is converted to a `TBSCertificateLogEntry`, encoded to
/// DER, hashed with domain separation (`hash_leaf`), and appended to the log.
///
/// Returns the zero-based leaf index assigned to this entry.
pub async fn append_cert_to_log(
    log: &SharedLog,
    cert_der: Vec<u8>,
    algorithm: HashAlgorithm,
) -> Result<u64, AcmeError> {
    // DER parsing and encoding is CPU-only — run in a blocking thread.
    let leaf_hash = tokio::task::spawn_blocking(move || -> Result<Vec<u8>, AcmeError> {
        // Parse the issued certificate.
        let mut dec = Decoder::new(&cert_der, Encoding::Der);
        let cert: Certificate = dec
            .decode()
            .map_err(|e| AcmeError::Mtc(format!("parse cert for MTC: {e}")))?;

        // Build the log entry from the TBS certificate.
        let log_entry = tbs_certificate_to_log_entry(&cert.tbs_certificate, algorithm)
            .map_err(|e| AcmeError::Mtc(format!("build log entry: {e}")))?;

        // DER-encode the log entry.
        let mut enc = Encoder::new(Encoding::Der);
        log_entry
            .encode(&mut enc)
            .map_err(|e| AcmeError::Mtc(format!("encode log entry: {e}")))?;
        let entry_der = enc
            .finish()
            .map_err(|e| AcmeError::Mtc(format!("finish log entry: {e}")))?;

        // Compute the leaf hash (with Merkle tree domain separation).
        Ok(hash_leaf(algorithm, &entry_der))
    })
    .await
    .map_err(|e| AcmeError::Mtc(format!("spawn_blocking panicked: {e}")))??;

    // Append the hash to the log file (one write syscall).
    let mut guard = log.lock().await;
    guard
        .append_leaf(&leaf_hash)
        .map_err(|e| AcmeError::Mtc(format!("append_leaf: {e}")))
}

/// Return the current number of leaves in the log.
pub async fn tree_size(log: &SharedLog) -> Result<u64, AcmeError> {
    let guard = log.lock().await;
    guard
        .tree_size()
        .map_err(|e| AcmeError::Mtc(format!("tree_size: {e}")))
}

/// Compute the current Merkle root of the log.
///
/// Returns the root hash as a byte vector (length depends on the algorithm).
pub async fn compute_root(log: &SharedLog) -> Result<Vec<u8>, AcmeError> {
    let mut guard = log.lock().await;
    guard
        .compute_root()
        .map_err(|e| AcmeError::Mtc(format!("compute_root: {e}")))
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use synta_mtc::crypto::HashAlgorithm;
    use tempfile::TempDir;
    use tokio::sync::Mutex;

    use super::{append_cert_to_log, open_or_create, tree_size};

    /// A minimal valid DER-encoded certificate.
    ///
    /// Generated offline with `openssl req -x509 -nodes -newkey ec ... -days 1`
    /// and extracted as DER bytes.  The exact content doesn't matter; we only
    /// need something that synta_certificate::Certificate can parse.
    fn test_cert_der() -> Vec<u8> {
        // Build a small in-memory cert using our own CA machinery.
        use crate::ca::init::unix_to_generalized_time;
        use synta_certificate::BackendPrivateKey;
        use synta_certificate::{
            default_key_id_hasher, encode_basic_constraints, encode_subject_key_identifier,
            parse_time, CertificateBuilder, KeyIdMethod, NameBuilder, PrivateKey as _,
        };

        let key = BackendPrivateKey::generate_ec("P-256").unwrap();
        let spki = key.public_key().unwrap().spki_der().to_vec();
        let name_der = NameBuilder::new().common_name("MTC Test").build().unwrap();
        let now = unix_to_generalized_time(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64,
        );
        let exp = unix_to_generalized_time(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64
                + 86400,
        );
        let hasher = default_key_id_hasher();
        let bc = encode_basic_constraints(false, None).unwrap();
        let ski = encode_subject_key_identifier(&spki, KeyIdMethod::Rfc5280Sha1, &hasher).unwrap();
        let signer = key.as_signer("sha256");
        CertificateBuilder::new()
            .issuer_name(&name_der)
            .subject_name(&name_der)
            .public_key_der(&spki)
            .serial_number(synta::Integer::from_i64(42))
            .not_valid_before(parse_time(&now).unwrap())
            .not_valid_after(parse_time(&exp).unwrap())
            .add_extension_oid(synta_certificate::oids::BASIC_CONSTRAINTS, false, &bc)
            .add_extension_oid(synta_certificate::oids::SUBJECT_KEY_IDENTIFIER, false, &ski)
            .sign(&signer)
            .unwrap()
    }

    #[tokio::test]
    async fn append_and_tree_size() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.log").to_string_lossy().into_owned();
        let algorithm = HashAlgorithm::Sha256;

        let log = open_or_create(&path, algorithm).unwrap();
        let shared = Arc::new(Mutex::new(log));

        assert_eq!(tree_size(&shared).await.unwrap(), 0);

        let cert_der = test_cert_der();
        let idx = append_cert_to_log(&shared, cert_der.clone(), algorithm)
            .await
            .unwrap();
        assert_eq!(idx, 0);
        assert_eq!(tree_size(&shared).await.unwrap(), 1);

        // Append a second leaf.
        let idx2 = append_cert_to_log(&shared, cert_der, algorithm)
            .await
            .unwrap();
        assert_eq!(idx2, 1);
        assert_eq!(tree_size(&shared).await.unwrap(), 2);
    }

    #[tokio::test]
    async fn open_existing_log_reopens_correctly() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("reopen.log").to_string_lossy().into_owned();
        let algorithm = HashAlgorithm::Sha256;

        // Create and populate a log.
        {
            let log = open_or_create(&path, algorithm).unwrap();
            let shared = Arc::new(Mutex::new(log));
            let cert_der = test_cert_der();
            append_cert_to_log(&shared, cert_der, algorithm)
                .await
                .unwrap();
        }

        // Re-open the existing file (covers the `DiskBackedLog::open` branch).
        let log = open_or_create(&path, algorithm).unwrap();
        let shared = Arc::new(Mutex::new(log));
        assert_eq!(tree_size(&shared).await.unwrap(), 1);
    }

    #[tokio::test]
    async fn compute_root_returns_hash() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("root.log").to_string_lossy().into_owned();
        let algorithm = HashAlgorithm::Sha256;

        let log = open_or_create(&path, algorithm).unwrap();
        let shared = Arc::new(Mutex::new(log));

        // Append a leaf so the tree is non-empty.
        let cert_der = test_cert_der();
        append_cert_to_log(&shared, cert_der, algorithm)
            .await
            .unwrap();

        let root = super::compute_root(&shared).await.unwrap();
        assert!(!root.is_empty(), "root hash should be non-empty");
        // SHA-256 root is 32 bytes.
        assert_eq!(root.len(), 32);
    }
}
