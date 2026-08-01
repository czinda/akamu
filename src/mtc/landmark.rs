//! Landmark management (§6.3.1 of draft-ietf-plants-merkle-tree-certs).
//!
//! A landmark is a frozen tree-size snapshot that relying parties can use to
//! anchor inclusion proofs over time.  Landmarks are allocated periodically (by
//! default daily) and a `LandmarkCertificate` is built for each one.  The
//! landmark cert embeds a TBSCertificate from any leaf at an index less than
//! the landmark's tree size, together with an inclusion proof against the full
//! set of leaves at that tree size.

use std::sync::Arc;

use synta::{Decoder, Encoding};
use synta_certificate::{BackendPrivateKey, CertificateSigner as _, PrivateKey as _};
use synta_mtc::builder::cert::LandmarkCertificateBuilder;
use synta_mtc::crypto::HashAlgorithm;
use synta_mtc::types::LandmarkID;

use crate::db::{self, Db, DbKind};
use crate::error::AcmeError;
use crate::mtc::log::SharedLog;
use crate::state::AppState;

/// Attempt to allocate a new landmark and build its `LandmarkCertificate`.
///
/// Returns `Ok(())` immediately (no-op) in any of three cases:
/// 1. The log is empty (`tree_size == 0`).
/// 2. The latest stored landmark already covers the current tree size.
/// 3. No representative certificate exists for this tree size yet — inserting
///    a landmark row with `cert_der = NULL` would leave it permanently
///    uncertified because there is no retry path for NULL rows.
///
/// When all three guards pass, the landmark row is inserted and its certificate
/// built inside a write transaction so that `sequence_no` assignment is
/// serialised even under concurrent access.
pub struct LandmarkAllocationParams<'a> {
    pub log: &'a SharedLog,
    pub signing_key: &'a BackendPrivateKey,
    pub signing_hash_alg: &'a str,
    pub log_algorithm: HashAlgorithm,
    pub db: &'a Db,
    pub db_kind: DbKind,
    pub ca_id: &'a str,
    pub keep_count: u32,
}

pub async fn maybe_allocate_landmark(
    params: &LandmarkAllocationParams<'_>,
) -> Result<(), AcmeError> {
    let tree_size = crate::mtc::log::tree_size(params.log).await?;

    if tree_size == 0 {
        return Ok(());
    }

    // Fast path: skip without acquiring a write transaction if we already have
    // a landmark for this tree size.
    if let Some(latest) = db::landmarks::get_latest(params.db, params.ca_id).await? {
        if latest.tree_size as u64 >= tree_size {
            tracing::debug!(tree_size, "landmark up to date; skipping");
            return Ok(());
        }
    }

    // Fetch a representative certificate before writing the landmark row.
    // If no cert exists yet, skip: inserting a landmark row with cert_der = NULL
    // would leave it permanently uncertified (nothing retries NULL rows).
    let Some(cert_row) =
        db::certs::get_representative_for_landmark(params.db, tree_size as i64).await?
    else {
        tracing::debug!(
            tree_size,
            "no certificates to use as landmark representative; skipping cert build"
        );
        return Ok(());
    };

    let now_unix = crate::util::unix_now();

    // Atomically insert the landmark row inside a write transaction so that
    // sequence_no assignment is serialised even under concurrent access.
    let landmark = {
        let mut tx = db::begin_write(params.db, params.db_kind).await?;
        if !db::landmarks::insert(&mut *tx, params.ca_id, tree_size as i64, now_unix).await? {
            // Another writer inserted a landmark for this tree_size first.
            return Ok(());
        }
        let Some(lm) = db::landmarks::get_latest(&mut *tx, params.ca_id).await? else {
            return Ok(());
        };
        tx.commit()
            .await
            .map_err(|e| AcmeError::Database(format!("commit landmark tx: {e}")))?;
        lm
    };

    let key = params.signing_key.clone();
    let hash_alg_str = params.signing_hash_alg.to_string();
    let log_clone = Arc::clone(params.log);
    let log_algorithm = params.log_algorithm;
    let leaf_index = cert_row
        .mtc_log_index
        .ok_or_else(|| AcmeError::Mtc("representative cert has no mtc_log_index".into()))?
        as u64;

    // Build the LandmarkCertificate in a blocking thread (disk I/O + crypto).
    //
    // NOTE: reads `tree_size` leaf hashes into memory (32 bytes each), which is
    // O(tree_size).  For a log with 10 million leaves that is ~320 MB.
    // Operators should plan memory capacity accordingly, or reduce
    // `landmark_interval_secs` to produce more frequent (smaller) snapshots.
    let landmark_cert_der = tokio::task::spawn_blocking(move || -> Result<Vec<u8>, AcmeError> {
        let spki_der = key
            .public_key()
            .map_err(|e| AcmeError::Crypto(format!("MTC signing key public: {e}")))?
            .spki_der()
            .to_vec();

        // Read exactly `tree_size` leaf hashes.  LandmarkCertificateBuilder
        // requires the full tree to generate the inclusion proof internally.
        let tree_leaves = {
            let mut guard = log_clone.blocking_lock();
            guard.read_hash_range(0, tree_size as usize)?
        };

        build_landmark_cert_der(LandmarkCertParams {
            cert_der: &cert_row.der,
            leaf_index,
            tree_leaves,
            spki_der: &spki_der,
            tree_size,
            log_algorithm,
            signing_key: &key,
            hash_alg_str: &hash_alg_str,
        })
    })
    .await
    .map_err(|e| AcmeError::Mtc(format!("landmark blocking task panicked: {e}")))??;

    db::landmarks::set_cert_der(params.db, landmark.id, &landmark_cert_der).await?;
    tracing::info!(
        sequence_no = landmark.sequence_no,
        tree_size,
        "MTC landmark allocated and cert built"
    );

    // Prune oldest landmarks to stay within the configured retention window.
    if let Err(e) = db::landmarks::prune_oldest(params.db, params.ca_id, params.keep_count).await {
        tracing::warn!("prune old MTC landmarks: {e}");
    }

    Ok(())
}

struct LandmarkCertParams<'a> {
    cert_der: &'a [u8],
    leaf_index: u64,
    tree_leaves: Vec<Vec<u8>>,
    spki_der: &'a [u8],
    tree_size: u64,
    log_algorithm: HashAlgorithm,
    signing_key: &'a BackendPrivateKey,
    hash_alg_str: &'a str,
}

fn build_landmark_cert_der(
    LandmarkCertParams {
        cert_der,
        leaf_index,
        tree_leaves,
        spki_der,
        tree_size,
        log_algorithm,
        signing_key,
        hash_alg_str,
    }: LandmarkCertParams<'_>,
) -> Result<Vec<u8>, AcmeError> {
    use synta::traits::Encode;
    use synta::types::constructed::Element;
    use synta::types::primitive::Null;
    use synta::types::string::BitString;
    use synta::{Encoder, Integer};
    use synta_certificate::{AlgorithmIdentifier, Certificate, SubjectPublicKeyInfo};

    // Parse the representative certificate's TBSCertificate.
    let cert: Certificate<'_> = Decoder::new(cert_der, Encoding::Der)
        .decode()
        .map_err(|e| AcmeError::Mtc(format!("decode cert for landmark: {e}")))?;
    let tbs = cert.tbs_certificate;

    // DER-encode TBSCertificate for signing.
    let mut enc = Encoder::new(Encoding::Der);
    tbs.encode(&mut enc)
        .map_err(|e| AcmeError::Mtc(format!("encode TBSCertificate for landmark: {e}")))?;
    let tbs_bytes = enc
        .finish()
        .map_err(|e| AcmeError::Mtc(format!("finish TBSCertificate DER: {e}")))?;

    // Sign and get AlgorithmIdentifier DER.
    let signer = signing_key.as_signer(hash_alg_str);
    let sig_bytes = signer
        .sign_tbs(&tbs_bytes)
        .map_err(|e| AcmeError::Mtc(format!("sign landmark TBS: {e}")))?;
    let sig_alg_der = signer
        .signature_algorithm_der()
        .map_err(|e| AcmeError::Mtc(format!("signature_algorithm_der for landmark: {e}")))?;
    let sig_alg = Decoder::new(&sig_alg_der, Encoding::Der)
        .decode()
        .map_err(|e| AcmeError::Mtc(format!("decode AlgorithmIdentifier for landmark: {e}")))?;

    // Build LogID for LandmarkID.
    let spki: SubjectPublicKeyInfo<'_> = Decoder::new(spki_der, Encoding::Der)
        .decode()
        .map_err(|e| AcmeError::Mtc(format!("decode SPKI for landmark: {e}")))?;
    let hash_oid = crate::mtc::hash_algorithm_to_oid(log_algorithm)?;
    let log_id = synta_mtc::types::LogID {
        hash_algorithm: AlgorithmIdentifier {
            algorithm: hash_oid,
            parameters: Some(Element::Null(Null)),
        },
        public_key: spki,
    };

    let landmark_id = LandmarkID {
        log_id,
        tree_size: Integer::from(tree_size),
    };

    let cert = LandmarkCertificateBuilder::new()
        .tbs_certificate(tbs)
        .log_entry_index(leaf_index)
        .tree_leaves(tree_leaves)
        .hash_algorithm(log_algorithm)
        .landmark_id(landmark_id)
        .signature_algorithm(sig_alg)
        .signature(
            BitString::new(sig_bytes, 0)
                .map_err(|e| AcmeError::Mtc(format!("build BitString for landmark: {e}")))?,
        )
        .build()
        .map_err(|e| AcmeError::Mtc(format!("build LandmarkCertificate: {e}")))?;

    cert.to_der()
        .map_err(|e| AcmeError::Mtc(format!("DER-encode LandmarkCertificate: {e}")))
}

/// Spawn a periodic landmark allocation task.
///
/// Fires every `config.mtc.landmark_interval_secs` seconds.  No-op when the
/// MTC signing key is not configured.
///
/// The returned `JoinHandle` should be retained by the caller; dropping it
/// detaches the task silently, making panics undetectable.
pub fn spawn_landmark_task(state: Arc<AppState>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
        interval.tick().await; // skip immediate first tick
        loop {
            interval.tick().await;
            let now = crate::util::unix_now();
            let ttl = state
                .config
                .gossip
                .as_ref()
                .map(|g| g.ownership_ttl_secs as i64)
                .unwrap_or(150);
            for (ca_id, ca) in state.cas.iter() {
                let mtc = &ca.mtc;
                let (Some(log), Some(signing_key)) = (mtc.log.as_ref(), mtc.signing_key.as_ref())
                else {
                    continue;
                };
                // See the identical gate in mtc::checkpoint::spawn_checkpoint_task:
                // only the elected writer's log has this CA's full leaf set, and
                // this tick also renews (or, if vacant, acquires) that election.
                let is_writer = {
                    let mut crdt = state.crdt.write().await;
                    crdt.claim_mtc_writer(ca_id, &state.node_id, now, ttl)
                };
                if !is_writer {
                    continue;
                }
                if now - mtc.last_landmark_at() < mtc.landmark_interval_secs as i64 {
                    continue;
                }
                let params = LandmarkAllocationParams {
                    log,
                    signing_key,
                    signing_hash_alg: &mtc.signing_hash_alg,
                    log_algorithm: mtc.algorithm,
                    db: &state.db,
                    db_kind: state.db_kind,
                    ca_id,
                    keep_count: mtc.max_active_landmarks,
                };
                if let Err(e) = maybe_allocate_landmark(&params).await {
                    tracing::error!(ca_id, "MTC landmark allocation failed: {e}");
                }
                mtc.touch_landmark();
            }
        }
    })
}
