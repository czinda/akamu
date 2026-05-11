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
use crate::mtc::cosign::CosignerClient;
use crate::mtc::log::SharedLog;
use crate::state::AppState;

/// Produce and persist a checkpoint for the current log state.
///
/// After the checkpoint is stored:
/// 1. Cosignatures are gathered from each configured external cosigner.
/// 2. A `StandaloneCertificate` is built for every certificate newly covered
///    by the checkpoint, with any received cosignatures embedded.
///
/// No-op when the log is empty or when the latest stored checkpoint already
/// covers the current tree size.
pub async fn produce_checkpoint(
    log: &SharedLog,
    signing_key: &BackendPrivateKey,
    signing_hash_alg: &str,
    log_algorithm: HashAlgorithm,
    db: &Db,
    cosigners: &[CosignerClient],
) -> Result<(), AcmeError> {
    let tree_size = crate::mtc::log::tree_size(log).await?;

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

    let now_unix = crate::util::unix_now();

    // Fetch certs covered by this checkpoint that still need a standalone DER.
    // Must happen before spawn_blocking so we can do async DB I/O.
    let pending_certs = db::certs::get_pending_standalone(db, tree_size as i64).await?;

    // Clone the key so it can be moved into spawn_blocking.
    // BackendPrivateKey is Clone + Send (OpenSSL Pkey<Private> is ref-counted).
    let key = signing_key.clone();
    let hash_alg_str = signing_hash_alg.to_string();
    let log_clone = Arc::clone(log);

    // Per-certificate proof data collected inside the blocking closure.
    struct CertProofEntry {
        cert_id: String,
        cert_der: Vec<u8>,
        leaf_index: u64,
        proof: Vec<Vec<u8>>,
    }

    // ── Phase 1 (blocking): compute root, generate proofs, build + sign checkpoint ──
    type Phase1Result = Result<(u64, Vec<u8>, Vec<u8>, Vec<u8>, Vec<CertProofEntry>), AcmeError>;
    let (actual_tree_size, root_bytes, checkpoint_der, signature, cert_proofs) =
        tokio::task::spawn_blocking(move || -> Phase1Result {
            // Obtain the signing key's SubjectPublicKeyInfo DER.
            let spki_der = key
                .public_key()
                .map_err(|e| AcmeError::Crypto(format!("MTC signing key public: {e}")))?
                .spki_der()
                .to_vec();

            // Lock the log ONCE for tree_size, compute_root, and generate_proof so
            // that the checkpoint covers the exact tree state at the root computation.
            // Reading tree_size outside this guard (as an early-exit hint) is fine;
            // the value here is the authoritative size embedded in the checkpoint DER.
            let (actual_tree_size, root_bytes, cert_proofs) = {
                let mut guard = log_clone.blocking_lock();
                let actual_tree_size = guard.tree_size()?;
                // compute_root also warms the CachedLog root cache.
                let root = guard.compute_root()?;
                let mut proofs: Vec<CertProofEntry> = Vec::new();
                for cert in &pending_certs {
                    match guard.generate_proof(cert.mtc_log_index as u64) {
                        Ok(proof) => proofs.push(CertProofEntry {
                            cert_id: cert.id.clone(),
                            cert_der: cert.der.clone(),
                            leaf_index: cert.mtc_log_index as u64,
                            proof,
                        }),
                        Err(e) => tracing::error!(
                            cert_id = %cert.id,
                            "generate_proof for standalone cert: {e}"
                        ),
                    }
                }
                (actual_tree_size, root, proofs)
            };
            // Log mutex released here.

            // Build and sign the DER-encoded Checkpoint structure.
            let checkpoint_der = build_checkpoint_der(
                &spki_der,
                actual_tree_size,
                &root_bytes,
                now_unix,
                log_algorithm,
            )?;
            let signer = key.as_signer(&hash_alg_str);
            let signature = signer
                .sign_tbs(&checkpoint_der)
                .map_err(|e| AcmeError::Mtc(format!("sign checkpoint: {e}")))?;

            Ok::<_, AcmeError>((
                actual_tree_size,
                root_bytes,
                checkpoint_der,
                signature,
                cert_proofs,
            ))
        })
        .await
        .map_err(|e| AcmeError::Mtc(format!("checkpoint blocking task panicked: {e}")))??;

    // Store checkpoint and resolve its DB row ID for cosignature FK.
    let root_hex: String = root_bytes.iter().map(|b| format!("{b:02x}")).collect();
    db::checkpoints::upsert(db, actual_tree_size as i64, &root_hex, &signature, now_unix).await?;
    tracing::info!(actual_tree_size, root_hex, "MTC checkpoint produced");
    // Query by tree_size (UNIQUE) — safe against concurrent checkpoint inserts.
    let checkpoint_id = db::checkpoints::get_by_tree_size(db, actual_tree_size as i64)
        .await?
        .map(|r| r.id);

    // ── Async: gather cosignatures from external cosigners ────────────────────
    let cosig_results = if cosigners.is_empty() {
        Vec::new()
    } else {
        crate::mtc::cosign::gather_cosignatures(&checkpoint_der, cosigners).await
    };
    let cosig_ders: Vec<Vec<u8>> = cosig_results.iter().map(|(_, d)| d.clone()).collect();

    // Compute SPKI DER once for LogID construction inside build_standalone_der.
    let spki_der: Vec<u8> = signing_key
        .public_key()
        .map_err(|e| AcmeError::Crypto(format!("MTC signing key public for standalone: {e}")))?
        .spki_der()
        .to_vec();

    // ── Phase 2 (blocking): build standalone DERs with proofs + cosignatures ──
    let standalone_defs: Vec<(String, Vec<u8>)> = tokio::task::spawn_blocking(move || {
        let mut out = Vec::new();
        for entry in cert_proofs {
            match crate::mtc::standalone::build_standalone_der(
                crate::mtc::standalone::StandaloneParams {
                    cert_der: &entry.cert_der,
                    leaf_index: entry.leaf_index,
                    proof: entry.proof,
                    tree_size: actual_tree_size,
                    spki_der: &spki_der,
                    log_algorithm,
                    cosignature_ders: &cosig_ders,
                },
            ) {
                Ok(der) => out.push((entry.cert_id, der)),
                Err(e) => tracing::warn!(cert_id = %entry.cert_id, "build standalone cert: {e}"),
            }
        }
        out
    })
    .await
    .map_err(|e| AcmeError::Mtc(format!("standalone blocking task panicked: {e}")))?;

    // Persist standalone DERs.
    for (cert_id, der) in standalone_defs {
        if let Err(e) = db::certs::set_mtc_standalone_der(db, &cert_id, &der).await {
            tracing::error!(cert_id = %cert_id, "store standalone DER: {e}");
        } else {
            tracing::debug!(cert_id = %cert_id, "MTC standalone certificate stored");
        }
    }

    // Persist cosignatures.
    if let Some(chk_id) = checkpoint_id {
        for (url, der) in cosig_results {
            if let Err(e) = db::cosignatures::upsert(db, chk_id, &url, &der, now_unix).await {
                tracing::warn!(url = %url, "store cosignature: {e}");
            }
        }
    } else if !cosig_results.is_empty() {
        tracing::error!(
            count = cosig_results.len(),
            "checkpoint row not found after upsert; cosignatures will not be stored"
        );
    }

    Ok(())
}

/// Construct and DER-encode a `synta_mtc::types::Checkpoint` from raw components.
fn build_checkpoint_der(
    spki_der: &[u8],
    tree_size: u64,
    root_bytes: &[u8],
    now_unix: i64,
    log_algorithm: HashAlgorithm,
) -> Result<Vec<u8>, AcmeError> {
    use synta::traits::Encode;
    use synta::types::string::OctetString;
    use synta::{Encoder, Encoding, Integer};
    use synta_mtc::types::Checkpoint;

    let log_id = crate::mtc::standalone::build_log_id(spki_der, log_algorithm)?;

    let timestamp = synta::GeneralizedTime::from_unix(now_unix).ok_or_else(|| {
        AcmeError::Mtc("checkpoint timestamp out of GeneralizedTime range".into())
    })?;

    let checkpoint = Checkpoint {
        log_id,
        tree_size: Integer::from(tree_size),
        tree_minimum_index: None,
        root_value: OctetString::from(root_bytes.to_vec()),
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
///
/// The returned `JoinHandle` should be retained by the caller; dropping it
/// detaches the task silently, making panics undetectable.
pub fn spawn_checkpoint_task(state: Arc<AppState>) -> tokio::task::JoinHandle<()> {
    let interval_secs = state.config.mtc.checkpoint_interval_secs;
    let retention_count = state.config.mtc.checkpoint_retention_count;
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(interval_secs));
        interval.tick().await; // skip the immediate first tick
        loop {
            interval.tick().await;
            let mtc = &state.mtc;
            let (Some(log), Some(signing_key)) = (mtc.log.as_ref(), mtc.signing_key.as_ref())
            else {
                continue;
            };
            if let Err(e) = produce_checkpoint(
                log,
                signing_key,
                &mtc.signing_hash_alg,
                mtc.algorithm,
                &state.db,
                &mtc.cosigner_clients,
            )
            .await
            {
                tracing::error!("MTC checkpoint failed: {e}");
                continue;
            }
            // Prune old checkpoints; CASCADE deletes their cosignatures automatically.
            if let Err(e) = db::checkpoints::prune_oldest(&state.db, retention_count).await {
                tracing::warn!("prune old MTC checkpoints: {e}");
            }
        }
    })
}
