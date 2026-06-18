//! Merkle Tree Certificate transparency log integration.
//!
//! Wraps `synta_mtc::storage::DiskBackedLog` for use in an async context.
//! The log itself uses synchronous file I/O; CPU-bound encoding work is
//! offloaded to `tokio::task::spawn_blocking` and the sub-millisecond disk
//! append runs under a `tokio::sync::Mutex` guard.

use std::fs;
use std::os::unix::io::AsRawFd;
use std::sync::Arc;

use synta::types::string::OctetString;
use synta::{Decoder, Encoding};
use synta_certificate::Certificate;
use synta_mtc::{
    builder::IssuanceLogBuilder,
    crypto::{hash_log_entry, HashAlgorithm},
    integration::{hash_subject_public_key, parse_extensions, parse_raw_name},
    storage::DiskBackedLog,
    types::MerkleTreeCertEntry,
    types::TBSCertificateLogEntry,
};
use tokio::sync::Mutex;

use crate::error::AcmeError;

/// `DiskBackedLog` wrapped with an in-memory root-hash cache.
///
/// `compute_root` is O(N) disk reads.  The cache stores the most recently
/// computed `(tree_size, root_hash)` pair so that HTTP reads of the current
/// checkpoint can skip the O(N) traversal when the tree hasn't grown since the
/// last checkpoint-production run.
///
/// Cache coherence rules:
/// - Warmed by `compute_root()` and `tree_size_and_root()`.
/// - Invalidated by `append_leaf()` (any write to the log).
pub struct CachedLog {
    log: DiskBackedLog,
    root_cache: Option<(u64, Vec<u8>)>,
}

impl CachedLog {
    pub fn new(log: DiskBackedLog) -> Self {
        Self {
            log,
            root_cache: None,
        }
    }

    pub fn tree_size(&mut self) -> Result<u64, AcmeError> {
        self.log
            .tree_size()
            .map_err(|e| AcmeError::Mtc(format!("tree_size: {e}")))
    }

    /// Compute the Merkle root and warm the cache.
    pub fn compute_root(&mut self) -> Result<Vec<u8>, AcmeError> {
        let root = self
            .log
            .compute_root()
            .map_err(|e| AcmeError::Mtc(format!("compute_root: {e}")))?;
        // Best-effort: if tree_size fails here we still return the root.
        if let Ok(size) = self.log.tree_size() {
            self.root_cache = Some((size, root.clone()));
        }
        Ok(root)
    }

    /// Return `(tree_size, root_hash)`, using the cache when the tree hasn't grown.
    pub fn tree_size_and_root(&mut self) -> Result<(u64, Vec<u8>), AcmeError> {
        let size = self.tree_size()?;
        if let Some((cached_size, ref root)) = self.root_cache {
            if cached_size == size {
                return Ok((size, root.clone()));
            }
        }
        let root = self
            .log
            .compute_root()
            .map_err(|e| AcmeError::Mtc(format!("compute_root: {e}")))?;
        self.root_cache = Some((size, root.clone()));
        Ok((size, root))
    }

    /// Append a leaf hash; invalidates the root cache.
    pub fn append_leaf(&mut self, hash: &[u8]) -> Result<u64, AcmeError> {
        let idx = self
            .log
            .append_leaf(hash)
            .map_err(|e| AcmeError::Mtc(format!("append_leaf: {e}")))?;
        self.root_cache = None;
        Ok(idx)
    }

    pub fn generate_proof(&mut self, leaf_index: u64) -> Result<Vec<Vec<u8>>, AcmeError> {
        self.log
            .generate_proof(leaf_index)
            .map_err(|e| AcmeError::Mtc(format!("generate_proof: {e}")))
    }

    /// Read a contiguous range of leaf hashes; returns `Ok(vec![])` when
    /// `start` is at or beyond the current tree size.
    pub fn read_hash_range(&mut self, start: u64, count: usize) -> Result<Vec<Vec<u8>>, AcmeError> {
        let size = self.tree_size()?;
        if start >= size {
            return Ok(vec![]);
        }
        self.log
            .read_hash_range(start, count)
            .map_err(|e| AcmeError::Mtc(format!("read_hash_range: {e}")))
    }

    pub fn read_all_hashes(&mut self) -> Result<Vec<Vec<u8>>, AcmeError> {
        self.log
            .read_all_hashes()
            .map_err(|e| AcmeError::Mtc(format!("read_all_hashes: {e}")))
    }

    /// The hash algorithm recorded in this log file's header.
    pub fn algorithm(&self) -> HashAlgorithm {
        self.log.algorithm()
    }
}

/// Shared handle to the disk-backed MTC log.
pub type SharedLog = Arc<Mutex<CachedLog>>;

/// Open an existing MTC log file, or create a new one if none exists.
///
/// Uses a try-create-first strategy to eliminate the TOCTOU race that a
/// `exists()` → `open/create` sequence would introduce: we attempt to create
/// the log, and if that fails (because the file already exists), we open it.
///
/// Note: concurrent calls on the **same path** from different processes are
/// still not supported — the caller is responsible for ensuring mutual
/// exclusion at that level (e.g. via a file lock or single-process guarantee).
pub fn open_or_create(path: &str, algorithm: HashAlgorithm) -> Result<CachedLog, AcmeError> {
    match DiskBackedLog::create(path, algorithm) {
        Ok(mut log) => {
            // §5.3 of draft-ietf-plants-merkle-tree-certs: entry zero of every
            // issuance log MUST be of type null_entry.  Seed it immediately so
            // that the first real certificate receives index ≥ 1 and never gets
            // a zero serial number in the MTC proof.
            let null_hash = IssuanceLogBuilder::new()
                .hash_algorithm(algorithm)
                .compute_leaf_hashes()
                .map_err(|e| AcmeError::Mtc(format!("compute null_entry hash: {e}")))?
                .into_iter()
                .next()
                .ok_or_else(|| AcmeError::Mtc("IssuanceLogBuilder yielded no hashes".into()))?;
            log.append_leaf(&null_hash)
                .map_err(|e| AcmeError::Mtc(format!("seed null_entry at index 0: {e}")))?;
            Ok(CachedLog::new(log))
        }
        Err(create_err) => {
            tracing::debug!(
                path,
                "MTC log create failed, attempting to open existing: {create_err}"
            );
            DiskBackedLog::open(path)
                .map(CachedLog::new)
                .map_err(|e| AcmeError::Mtc(format!("open MTC log: {e}")))
        }
    }
}

/// Acquire an exclusive advisory lock on `{path}.lock`.
///
/// Opens (or creates) the sidecar lock file and calls `flock(LOCK_EX|LOCK_NB)`.
/// The returned `File` must be stored for the lifetime of the process; the
/// kernel releases the lock automatically when the `File` is dropped or the
/// process exits.
///
/// Returns `Err` immediately if another process already holds the lock so the
/// caller gets a clear error rather than silent log corruption.
pub fn acquire_log_lock(path: &str) -> Result<fs::File, AcmeError> {
    let lock_path = format!("{path}.lock");
    let file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .open(&lock_path)
        .map_err(|e| AcmeError::Mtc(format!("open MTC lock file '{lock_path}': {e}")))?;
    // SAFETY: `file` was just opened successfully, so `as_raw_fd()` returns a valid
    // file descriptor. `flock` is a POSIX system call; flags are compile-time constants.
    let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if rc != 0 {
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::EWOULDBLOCK) {
            return Err(AcmeError::Mtc(format!(
                "MTC log '{path}' is locked by another process; \
                 ensure only one Akāmu instance accesses this log file \
                 (lock file: '{lock_path}')"
            )));
        }
        return Err(AcmeError::Mtc(format!(
            "flock on MTC lock file '{lock_path}': {err}"
        )));
    }
    Ok(file)
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
    logid_issuer_dn_der: Vec<u8>,
    algorithm: HashAlgorithm,
) -> Result<u64, AcmeError> {
    // DER parsing and encoding is CPU-only — run in a blocking thread.
    let leaf_hash = tokio::task::spawn_blocking(move || -> Result<Vec<u8>, AcmeError> {
        // Parse the issued certificate.
        let mut dec = Decoder::new(&cert_der, Encoding::Der);
        let cert: Certificate = dec
            .decode()
            .map_err(|e| AcmeError::Mtc(format!("parse cert for MTC: {e}")))?;

        let tbs = &cert.tbs_certificate;

        // Build the log entry using the LogID issuer DN rather than the original
        // CA DN.  The standalone cert's TBS (produced by MtcX509CertificateBuilder)
        // has the LogID as issuer, so the leaf hash must match what a verifier
        // computes from that TBS.
        let issuer = parse_raw_name(&logid_issuer_dn_der)
            .map_err(|e| AcmeError::Mtc(format!("parse LogID issuer DN: {e}")))?;
        let subject = parse_raw_name(tbs.subject.as_bytes())
            .map_err(|e| AcmeError::Mtc(format!("parse subject DN: {e}")))?;
        let pk_hash = hash_subject_public_key(tbs, algorithm)
            .map_err(|e| AcmeError::Mtc(format!("hash subject public key: {e}")))?;
        let extensions = tbs
            .extensions
            .map(|raw| parse_extensions(raw.as_bytes()))
            .transpose()
            .map_err(|e| AcmeError::Mtc(format!("parse extensions: {e}")))?;

        let log_entry = TBSCertificateLogEntry {
            version: tbs.version.clone(),
            issuer,
            validity: tbs.validity.clone(),
            subject,
            subject_public_key_algorithm: tbs.subject_public_key_info.algorithm.clone(),
            subject_public_key_info_hash: OctetString::from(pk_hash),
            issuer_unique_id: tbs.issuer_unique_id.as_ref().map(|b| b.to_owned()),
            subject_unique_id: tbs.subject_unique_id.as_ref().map(|b| b.to_owned()),
            extensions,
        };

        // Hash via TLS wire encoding (spec §4.2); direction bits are implicit.
        let entry = MerkleTreeCertEntry::TbsCertEntry(log_entry);
        hash_log_entry(algorithm, &entry, &[])
            .map_err(|e| AcmeError::Mtc(format!("hash_log_entry: {e}")))
    })
    .await
    .map_err(|e| AcmeError::Mtc(format!("spawn_blocking panicked: {e}")))??;

    // Append the hash; CachedLog::append_leaf also invalidates the root cache.
    let mut guard = log.lock().await;
    guard.append_leaf(&leaf_hash)
}

/// Compute a Merkle inclusion proof for the leaf at `leaf_index`.
///
/// Returns the ordered sibling hashes along the path from the leaf to the root.
/// Direction is implicit from the leaf index per spec §4.3.2.
/// Leaf index 0 is the null_entry; real certificates begin at index 1.
pub async fn generate_proof(log: &SharedLog, leaf_index: u64) -> Result<Vec<Vec<u8>>, AcmeError> {
    let log_clone = Arc::clone(log);
    tokio::task::spawn_blocking(move || log_clone.blocking_lock().generate_proof(leaf_index))
        .await
        .map_err(|e| AcmeError::Mtc(format!("spawn_blocking panicked: {e}")))?
}

/// Compute a Merkle inclusion proof and the current tree size atomically.
///
/// Both values are read under the same `blocking_lock` guard so the `proof`,
/// `leafIndex`, and `treeSize` fields in an HTTP response are always consistent
/// with each other.
pub async fn proof_and_tree_size(
    log: &SharedLog,
    leaf_index: u64,
) -> Result<(Vec<Vec<u8>>, u64), AcmeError> {
    let log_clone = Arc::clone(log);
    tokio::task::spawn_blocking(move || {
        let mut guard = log_clone.blocking_lock();
        let proof = guard.generate_proof(leaf_index)?;
        let size = guard.tree_size()?;
        Ok::<_, AcmeError>((proof, size))
    })
    .await
    .map_err(|e| AcmeError::Mtc(format!("spawn_blocking panicked: {e}")))?
}

/// Return the current number of leaves in the log.
///
/// `DiskBackedLog::tree_size` calls `fstat`, a blocking syscall.  Holding the
/// async `Mutex` guard while calling it would block a Tokio runtime thread;
/// this helper moves the call onto a blocking thread via `spawn_blocking`.
/// Prefer this over open-coding `log.lock().await; guard.tree_size()` to
/// keep the async executor thread available for other tasks.
pub async fn tree_size(log: &SharedLog) -> Result<u64, AcmeError> {
    let log_clone = Arc::clone(log);
    tokio::task::spawn_blocking(move || log_clone.blocking_lock().tree_size())
        .await
        .map_err(|e| AcmeError::Mtc(format!("spawn_blocking panicked: {e}")))?
}

/// Compute the current Merkle root of the log.
///
/// Returns the root hash as a byte vector (length depends on the algorithm).
pub async fn compute_root(log: &SharedLog) -> Result<Vec<u8>, AcmeError> {
    let log_clone = Arc::clone(log);
    tokio::task::spawn_blocking(move || log_clone.blocking_lock().compute_root())
        .await
        .map_err(|e| AcmeError::Mtc(format!("spawn_blocking panicked: {e}")))?
}

/// Return the current tree size and Merkle root atomically.
///
/// Both values are read under the same `blocking_lock` guard, ensuring the
/// `treeSize` and `rootHash` in HTTP responses are always consistent.
/// Return `(tree_size, root_hash)`, using the in-memory cache when the tree
/// hasn't grown since the last `compute_root` or checkpoint-production run.
pub async fn tree_size_and_root(log: &SharedLog) -> Result<(u64, Vec<u8>), AcmeError> {
    let log_clone = Arc::clone(log);
    tokio::task::spawn_blocking(move || log_clone.blocking_lock().tree_size_and_root())
        .await
        .map_err(|e| AcmeError::Mtc(format!("spawn_blocking panicked: {e}")))?
}

/// Read a contiguous range of leaf hashes from the log.
///
/// Returns at most `count` hashes starting at `start`; returns fewer when
/// the range reaches the end of the log.  Returns an empty vec when `start`
/// is at or beyond the current tree size (the tile is past the log head).
pub async fn read_hash_range(
    log: &SharedLog,
    start: u64,
    count: usize,
) -> Result<Vec<Vec<u8>>, AcmeError> {
    let log_clone = Arc::clone(log);
    tokio::task::spawn_blocking(move || log_clone.blocking_lock().read_hash_range(start, count))
        .await
        .map_err(|e| AcmeError::Mtc(format!("spawn_blocking panicked: {e}")))?
}

/// Compute the Merkle root for a prefix of the log (the first `size` leaves).
pub async fn compute_root_at_size(
    log: &SharedLog,
    algorithm: HashAlgorithm,
    size: u64,
) -> Result<Vec<u8>, AcmeError> {
    let log_clone = Arc::clone(log);
    tokio::task::spawn_blocking(move || {
        let mut guard = log_clone.blocking_lock();
        let hashes = guard.read_hash_range(0, size as usize)?;
        if hashes.is_empty() {
            return Err(AcmeError::Mtc("cannot compute root of empty tree".into()));
        }
        synta_mtc::crypto::hash::compute_root(algorithm, hashes)
            .map_err(|e| AcmeError::Mtc(format!("compute_root_at_size: {e}")))
    })
    .await
    .map_err(|e| AcmeError::Mtc(format!("spawn_blocking panicked: {e}")))?
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use synta_mtc::crypto::HashAlgorithm;
    use tempfile::TempDir;
    use tokio::sync::Mutex;

    use super::{append_cert_to_log, open_or_create, tree_size};

    fn test_logid_issuer_dn_der() -> Vec<u8> {
        use synta_certificate::BackendPrivateKey;
        let key = BackendPrivateKey::generate_ec("P-256").unwrap();
        let spki = key.public_key().unwrap().spki_der().to_vec();
        crate::mtc::standalone::build_logid_issuer_dn_der(&spki, HashAlgorithm::Sha256).unwrap()
    }

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
        let ski = encode_subject_key_identifier(&spki, KeyIdMethod::Rfc7093Method1Sha256, &hasher)
            .unwrap();
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
        let logid_dn = test_logid_issuer_dn_der();

        // A fresh log already has the null_entry at index 0 (§5.3).
        assert_eq!(tree_size(&shared).await.unwrap(), 1);

        let cert_der = test_cert_der();
        let idx = append_cert_to_log(&shared, cert_der.clone(), logid_dn.clone(), algorithm)
            .await
            .unwrap();
        assert_eq!(idx, 1);
        assert_eq!(tree_size(&shared).await.unwrap(), 2);

        // Append a second leaf.
        let idx2 = append_cert_to_log(&shared, cert_der, logid_dn, algorithm)
            .await
            .unwrap();
        assert_eq!(idx2, 2);
        assert_eq!(tree_size(&shared).await.unwrap(), 3);
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
            let logid_dn = test_logid_issuer_dn_der();
            append_cert_to_log(&shared, cert_der, logid_dn, algorithm)
                .await
                .unwrap();
        }

        // Re-open the existing file (covers the `DiskBackedLog::open` branch).
        // null_entry (index 0) + one cert (index 1) = 2 leaves.
        let log = open_or_create(&path, algorithm).unwrap();
        let shared = Arc::new(Mutex::new(log));
        assert_eq!(tree_size(&shared).await.unwrap(), 2);
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
        let logid_dn = test_logid_issuer_dn_der();
        append_cert_to_log(&shared, cert_der, logid_dn, algorithm)
            .await
            .unwrap();

        let root = super::compute_root(&shared).await.unwrap();
        assert!(!root.is_empty(), "root hash should be non-empty");
        // SHA-256 root is 32 bytes.
        assert_eq!(root.len(), 32);
    }
}
