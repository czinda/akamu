//! Periodic MTC checkpoint production and standalone certificate construction.
//!
//! A checkpoint captures the current Merkle root and tree size, signed by the
//! dedicated MTC signing key (distinct from the X.509 CA key as required by
//! §5.5 of draft-ietf-plants-merkle-tree-certs).  Checkpoints are stored in
//! the `mtc_checkpoints` table.  After each checkpoint, Merkle inclusion proofs
//! are generated for all newly covered certificates and used to build
//! `StandaloneCertificate` DER blobs (§6.1), stored in `certificates.mtc_standalone_der`.

use std::sync::Arc;

use synta_certificate::{BackendPrivateKey, CertificateSigner as _, PrivateKey as _};
use synta_mtc::crypto::HashAlgorithm;

use crate::db::{self, Db};
use crate::error::AcmeError;
use crate::mtc::log::SharedLog;
use crate::state::AppState;

/// Produce and persist a checkpoint for the current log state, then build
/// `StandaloneCertificate` DER for every certificate newly covered by the checkpoint.
///
/// No-op when the log is empty or when the latest stored checkpoint already
/// covers the current tree size.
pub async fn produce_checkpoint(
    log: &SharedLog,
    signing_key: &BackendPrivateKey,
    signing_hash_alg: &str,
    log_algorithm: HashAlgorithm,
    db: &Db,
) -> Result<(), AcmeError> {
    // Get current tree size (O(1) file stat — very fast, OK in async context).
    let tree_size = {
        let guard = log.lock().await;
        guard
            .tree_size()
            .map_err(|e| AcmeError::Mtc(format!("tree_size: {e}")))?
    };

    if tree_size == 0 {
        return Ok(());
    }

    // Skip when the latest checkpoint already covers this tree size.
    if let Some(latest) = db::checkpoints::get_latest(db).await? {
        if latest.tree_size as u64 >= tree_size {
            tracing::debug!(tree_size, "MTC checkpoint up to date; skipping");
            return Ok(());
        }
    }

    let now_unix = unix_now_secs();

    // Fetch certs covered by this checkpoint that still need a standalone DER.
    // This must happen before spawn_blocking so we can do async DB I/O.
    let pending_certs = db::certs::get_pending_standalone(db, tree_size as i64).await?;

    // Clone the key so it can be moved into spawn_blocking.
    // BackendPrivateKey is Clone + Send (OpenSSL Pkey<Private> is ref-counted).
    let key = signing_key.clone();
    let hash_alg_str = signing_hash_alg.to_string();
    let log_clone = Arc::clone(log);

    let (root_bytes, signature, standalone_defs) = tokio::task::spawn_blocking(
        move || -> Result<(Vec<u8>, Vec<u8>, Vec<(String, Vec<u8>)>), AcmeError> {
            // Obtain the signing key's SubjectPublicKeyInfo DER.
            let spki_der = key
                .public_key()
                .map_err(|e| AcmeError::Crypto(format!("MTC signing key public: {e}")))?
                .spki_der()
                .to_vec();

            // Lock the log ONCE for both compute_root and generate_proof so that
            // all proofs are consistent with the same tree_size used for the root.
            let (root_bytes, cert_proofs) = {
                let mut guard = log_clone.blocking_lock();
                let root = guard
                    .compute_root()
                    .map_err(|e| AcmeError::Mtc(format!("compute_root: {e}")))?;
                let mut proofs: Vec<(String, Vec<u8>, u64, Vec<(bool, Vec<u8>)>)> = Vec::new();
                for cert in &pending_certs {
                    match guard.generate_proof(cert.mtc_log_index as u64) {
                        Ok(proof) => proofs.push((
                            cert.id.clone(),
                            cert.der.clone(),
                            cert.mtc_log_index as u64,
                            proof,
                        )),
                        Err(e) => tracing::warn!(
                            cert_id = %cert.id,
                            "generate_proof for standalone cert: {e}"
                        ),
                    }
                }
                (root, proofs)
            };
            // Log mutex released here.

            // Build the DER-encoded Checkpoint structure.
            let checkpoint_der =
                build_checkpoint_der(&spki_der, tree_size, root_bytes.clone(), now_unix, log_algorithm)?;

            // Sign the DER-encoded checkpoint.
            let signer = key.as_signer(&hash_alg_str);
            let signature = signer
                .sign_tbs(&checkpoint_der)
                .map_err(|e| AcmeError::Mtc(format!("sign checkpoint: {e}")))?;

            // Build standalone certificate DERs (signing key reused; no log access needed).
            let mut standalone_defs: Vec<(String, Vec<u8>)> = Vec::new();
            for (cert_id, cert_der, leaf_idx, proof) in cert_proofs {
                match crate::mtc::standalone::build_standalone_der(
                    &cert_der,
                    leaf_idx,
                    proof,
                    tree_size,
                    &key,
                    &hash_alg_str,
                    log_algorithm,
                ) {
                    Ok(der) => standalone_defs.push((cert_id, der)),
                    Err(e) => tracing::warn!(cert_id = %cert_id, "build standalone cert: {e}"),
                }
            }

            Ok::<_, AcmeError>((root_bytes, signature, standalone_defs))
        },
    )
    .await
    .map_err(|e| AcmeError::Mtc(format!("checkpoint blocking task panicked: {e}")))??;

    let root_hex: String = root_bytes.iter().map(|b| format!("{b:02x}")).collect();
    db::checkpoints::upsert(db, tree_size as i64, &root_hex, &signature, now_unix as i64).await?;
    tracing::info!(tree_size, root_hex, "MTC checkpoint produced");

    // Persist standalone DERs built during this checkpoint cycle.
    for (cert_id, der) in standalone_defs {
        if let Err(e) = db::certs::set_mtc_standalone_der(db, &cert_id, &der).await {
            tracing::warn!(cert_id = %cert_id, "store standalone DER: {e}");
        } else {
            tracing::debug!(cert_id = %cert_id, "MTC standalone certificate stored");
        }
    }

    Ok(())
}

/// Construct and DER-encode a `synta_mtc::types::Checkpoint` from raw components.
fn build_checkpoint_der(
    spki_der: &[u8],
    tree_size: u64,
    root_bytes: Vec<u8>,
    now_unix: u64,
    log_algorithm: HashAlgorithm,
) -> Result<Vec<u8>, AcmeError> {
    use synta::traits::Encode;
    use synta::types::constructed::Element;
    use synta::types::primitive::Null;
    use synta::types::string::OctetString;
    use synta::{Decoder, Encoder, Encoding, Integer, ObjectIdentifier};
    use synta_certificate::{AlgorithmIdentifier, SubjectPublicKeyInfo};
    use synta_mtc::types::{Checkpoint, LogID};

    // Decode the MTC signing key's SPKI from DER.
    let mut dec = Decoder::new(spki_der, Encoding::Der);
    let spki: SubjectPublicKeyInfo = dec
        .decode()
        .map_err(|e| AcmeError::Mtc(format!("decode MTC signing key SPKI: {e}")))?;

    // OID for the log entry hash algorithm (SHA-256/384/512).
    let hash_oid = match log_algorithm {
        HashAlgorithm::Sha256 => ObjectIdentifier::new(&[2u32, 16, 840, 1, 101, 3, 4, 2, 1]),
        HashAlgorithm::Sha384 => ObjectIdentifier::new(&[2u32, 16, 840, 1, 101, 3, 4, 2, 2]),
        HashAlgorithm::Sha512 => ObjectIdentifier::new(&[2u32, 16, 840, 1, 101, 3, 4, 2, 3]),
    }
    .map_err(|e| AcmeError::Mtc(format!("hash algorithm OID: {e}")))?;

    let log_id = LogID {
        hash_algorithm: AlgorithmIdentifier {
            algorithm: hash_oid,
            parameters: Some(Element::Null(Null)),
        },
        public_key: spki,
    };

    let timestamp = synta::GeneralizedTime::from_unix(now_unix as i64)
        .ok_or_else(|| AcmeError::Mtc("checkpoint timestamp out of GeneralizedTime range".into()))?;

    let checkpoint = Checkpoint {
        log_id,
        tree_size: Integer::from(tree_size),
        tree_minimum_index: None,
        root_value: OctetString::from(root_bytes),
        timestamp,
    };

    let mut enc = Encoder::new(Encoding::Der);
    checkpoint
        .encode(&mut enc)
        .map_err(|e| AcmeError::Mtc(format!("encode Checkpoint: {e}")))?;
    enc.finish()
        .map_err(|e| AcmeError::Mtc(format!("finish Checkpoint DER: {e}")))
}

/// Spawn the periodic checkpoint background task.
///
/// The task fires every `config.mtc.checkpoint_interval_secs` seconds.
/// It is a no-op when the signing key is not configured or when the log is
/// not enabled, so callers may call it unconditionally.
pub fn spawn_checkpoint_task(state: Arc<AppState>) {
    let interval_secs = state.config.mtc.checkpoint_interval_secs;
    tokio::spawn(async move {
        let mut interval =
            tokio::time::interval(std::time::Duration::from_secs(interval_secs));
        interval.tick().await; // skip the immediate first tick
        loop {
            interval.tick().await;
            let mtc = &state.mtc;
            let (Some(log), Some(signing_key)) = (mtc.log.as_ref(), mtc.signing_key.as_ref())
            else {
                // MTC or signing key not configured; nothing to do.
                return;
            };
            if let Err(e) = produce_checkpoint(
                log,
                signing_key,
                &mtc.signing_hash_alg,
                mtc.algorithm,
                &state.db,
            )
            .await
            {
                tracing::warn!("MTC checkpoint failed: {e}");
            }
        }
    });
}

fn unix_now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
