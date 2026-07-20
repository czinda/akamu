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

/// Parameters for [`produce_checkpoint`].
pub struct CheckpointParams<'a> {
    pub log: &'a SharedLog,
    pub signing_key: &'a BackendPrivateKey,
    pub signing_hash_alg: &'a str,
    pub log_algorithm: HashAlgorithm,
    pub db: &'a Db,
    pub ca_id: &'a str,
    pub cosigners: &'a [CosignerClient],
    pub log_number: u16,
    pub tree_minimum_index: Option<u64>,
    pub trust_anchor_id_der: Option<&'a [u8]>,
    /// C2SP tlog origin for cosigned_message (e.g. `oid/1.3.6.1.4.1.32473.2.0.1`).
    pub log_origin: Option<&'a str>,
}

/// Produce and persist a checkpoint for the current log state.
///
/// After the checkpoint is stored:
/// 1. Cosignatures are gathered from each configured external cosigner.
/// 2. A `StandaloneCertificate` is built for every certificate newly covered
///    by the checkpoint, with any received cosignatures embedded.
///
/// No-op when the log is empty or when the latest stored checkpoint already
/// covers the current tree size.
pub async fn produce_checkpoint(params: CheckpointParams<'_>) -> Result<(), AcmeError> {
    let CheckpointParams {
        log,
        signing_key,
        signing_hash_alg,
        log_algorithm,
        db,
        ca_id,
        cosigners,
        log_number,
        tree_minimum_index,
        trust_anchor_id_der,
        log_origin,
    } = params;
    let tree_size = crate::mtc::log::tree_size(log).await?;

    if tree_size == 0 {
        return Ok(());
    }

    // Capture previous checkpoint tree size for subtree-relative proofs,
    // and skip when the latest checkpoint already covers this tree size.
    let prev_tree_size = match db::checkpoints::get_latest(db, ca_id).await? {
        Some(latest) => {
            if latest.tree_size as u64 >= tree_size {
                tracing::debug!(tree_size, "MTC checkpoint up to date; skipping");
                return Ok(());
            }
            latest.tree_size as u64
        }
        None => 0,
    };

    let now_unix = crate::util::unix_now();

    // Fetch certs covered by this checkpoint that still need a standalone DER.
    // Must happen before spawn_blocking so we can do async DB I/O.
    let pending_certs = db::certs::get_pending_standalone(db, tree_size as i64).await?;
    if pending_certs.len() == 500 {
        tracing::warn!(
            ca_id,
            "checkpoint: batch limit reached (500); remaining certs deferred to next cycle"
        );
    }

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
        subtree_start: u64,
    }

    // Subtree info produced by Phase 1: which range [start, end) the proofs cover,
    // and the Merkle root of that subtree's leaf hashes.
    struct SubtreeInfo {
        start: u64,
        root: Vec<u8>,
    }

    // ── Phase 1 (blocking): compute root, generate proofs, build + sign checkpoint ──
    type Phase1Result = Result<
        (
            u64,
            Vec<u8>,
            Vec<u8>,
            Vec<u8>,
            Vec<CertProofEntry>,
            SubtreeInfo,
        ),
        AcmeError,
    >;
    let (actual_tree_size, root_bytes, checkpoint_der, signature, cert_proofs, subtree_info) =
        tokio::task::spawn_blocking(move || -> Phase1Result {
            let spki_der = key
                .public_key()
                .map_err(|e| AcmeError::Crypto(format!("MTC signing key public: {e}")))?
                .spki_der()
                .to_vec();

            // Lock the log ONCE for tree_size, compute_root, and generate_proof so
            // that the checkpoint covers the exact tree state at the root computation.
            let (actual_tree_size, root_bytes, cert_proofs, subtree_info) = {
                let mut guard = log_clone.blocking_lock();
                let actual_tree_size = guard.tree_size()?;
                let root = guard.compute_root()?;

                // Decide whether subtree-relative proofs are feasible for this batch.
                // Requirements: (1) a prior checkpoint exists, (2) all pending certs
                // are in the new range, (3) subtree alignment per §4.3.1.
                let subtree_size = actual_tree_size.saturating_sub(prev_tree_size);
                let use_subtree = prev_tree_size > 0
                    && subtree_size > 0
                    && prev_tree_size
                        % subtree_size.checked_next_power_of_two().unwrap_or(u64::MAX)
                        == 0
                    && pending_certs
                        .iter()
                        .all(|c| (c.mtc_log_index as u64) >= prev_tree_size);

                tracing::debug!(
                    use_subtree,
                    prev_tree_size,
                    actual_tree_size,
                    subtree_size,
                    "subtree proof decision"
                );

                let mut proofs: Vec<CertProofEntry> = Vec::new();
                let mut skipped = 0u32;

                let result = if use_subtree {
                    let subtree_hashes =
                        guard.read_hash_range(prev_tree_size, subtree_size as usize)?;
                    let subtree_root =
                        synta_mtc::crypto::generate_subtree_hash(log_algorithm, &subtree_hashes)
                            .map_err(|e| AcmeError::Mtc(format!("subtree root: {e}")))?;

                    for cert in &pending_certs {
                        let leaf_index = cert.mtc_log_index as u64;
                        let relative_index = leaf_index - prev_tree_size;
                        match synta_mtc::crypto::generate_inclusion_proof(
                            log_algorithm,
                            relative_index,
                            &subtree_hashes,
                        ) {
                            Ok(proof) => proofs.push(CertProofEntry {
                                cert_id: cert.id.clone(),
                                cert_der: cert.der.clone(),
                                leaf_index,
                                proof,
                                subtree_start: prev_tree_size,
                            }),
                            Err(e) => {
                                tracing::error!(
                                    cert_id = %cert.id,
                                    "generate subtree proof: {e}"
                                );
                                skipped += 1;
                            }
                        }
                    }

                    let info = SubtreeInfo {
                        start: prev_tree_size,
                        root: subtree_root,
                    };
                    (actual_tree_size, root, proofs, info)
                } else {
                    for cert in &pending_certs {
                        let leaf_index = cert.mtc_log_index as u64;
                        match guard.generate_proof(leaf_index) {
                            Ok(proof) => proofs.push(CertProofEntry {
                                cert_id: cert.id.clone(),
                                cert_der: cert.der.clone(),
                                leaf_index,
                                proof,
                                subtree_start: 0,
                            }),
                            Err(e) => {
                                tracing::error!(
                                    cert_id = %cert.id,
                                    "generate full-tree proof: {e}"
                                );
                                skipped += 1;
                            }
                        }
                    }

                    let info = SubtreeInfo {
                        start: 0,
                        root: root.clone(),
                    };
                    (actual_tree_size, root, proofs, info)
                };

                if skipped > 0 {
                    tracing::warn!(
                        skipped,
                        total = pending_certs.len(),
                        "proof generation: {skipped}/{} certs skipped; will retry next checkpoint",
                        pending_certs.len()
                    );
                }

                result
            };
            // Log mutex released here.

            let checkpoint_der = build_checkpoint_der(
                &spki_der,
                actual_tree_size,
                &root_bytes,
                now_unix,
                log_algorithm,
                tree_minimum_index,
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
                subtree_info,
            ))
        })
        .await
        .map_err(|e| AcmeError::Mtc(format!("checkpoint blocking task panicked: {e}")))??;

    // Store checkpoint and resolve its DB row ID for cosignature FK.
    let root_hex: String = root_bytes.iter().map(|b| format!("{b:02x}")).collect();
    db::checkpoints::upsert(
        db,
        ca_id,
        actual_tree_size as i64,
        &root_hex,
        &signature,
        now_unix,
    )
    .await?;
    tracing::info!(actual_tree_size, root_hex, "MTC checkpoint produced");
    // Query by tree_size (UNIQUE) — safe against concurrent checkpoint inserts.
    let checkpoint_id = db::checkpoints::get_by_tree_size(db, ca_id, actual_tree_size as i64)
        .await?
        .map(|r| r.id);

    // ── CA self-cosignature (§5.4) ──────────────────────────────────────────────
    let mut cosig_ders: Vec<(String, Vec<u8>)> = Vec::new();
    if let (Some(ta_der), Some(origin)) = (trust_anchor_id_der, log_origin) {
        let self_cosig_der = crate::mtc::cosign::build_ca_self_cosignature(
            &crate::mtc::cosign::SelfCosignatureParams {
                signing_key,
                signing_hash_alg,
                trust_anchor_id_der: ta_der,
                checkpoint_der: &checkpoint_der,
                subtree_start: subtree_info.start,
                subtree_end: actual_tree_size,
                subtree_root_bytes: &subtree_info.root,
                log_origin: origin,
            },
        )?;
        tracing::debug!("CA self-cosignature produced");
        cosig_ders.push(("self".to_string(), self_cosig_der));
    }

    // ── Async: gather cosignatures from external cosigners ────────────────────
    if !cosigners.is_empty() && log_origin.is_none() {
        tracing::warn!(
            ca_id,
            cosigner_count = cosigners.len(),
            "cosigners configured but log_origin is not set; skipping cosignature gathering"
        );
    }
    if let (false, Some(origin)) = (cosigners.is_empty(), log_origin) {
        let external =
            crate::mtc::cosign::gather_cosignatures(&checkpoint_der, cosigners, origin).await;
        cosig_ders.extend(external);
    }
    // Persist cosignatures before Phase 2 so cosig_ders can be moved (not
    // cloned) into the spawn_blocking closure.
    if let Some(chk_id) = checkpoint_id {
        for (url, der) in &cosig_ders {
            if let Err(e) = db::cosignatures::upsert(db, ca_id, chk_id, url, der, now_unix).await {
                tracing::warn!(url = %url, "store cosignature: {e}");
            }
        }
    } else if !cosig_ders.is_empty() {
        tracing::error!(
            ca_id,
            tree_size = actual_tree_size,
            count = cosig_ders.len(),
            "checkpoint row not found after upsert; cosignatures will not be stored"
        );
    }

    // Compute SPKI DER once for LogID construction inside build_standalone_der.
    let spki_der: Vec<u8> = signing_key
        .public_key()
        .map_err(|e| AcmeError::Crypto(format!("MTC signing key public for standalone: {e}")))?
        .spki_der()
        .to_vec();

    // ── Phase 2 (blocking): build standalone DERs with proofs + cosignatures ──
    let cert_proofs_total = cert_proofs.len();
    let standalone_defs: Vec<(String, Vec<u8>)> = tokio::task::spawn_blocking(move || {
        let mut out = Vec::new();
        let mut skipped = 0u32;
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
                    log_number,
                    subtree_start: entry.subtree_start,
                },
            ) {
                Ok(der) => out.push((entry.cert_id, der)),
                Err(e) => {
                    tracing::error!(cert_id = %entry.cert_id, "build standalone cert: {e}");
                    skipped += 1;
                }
            }
        }
        if skipped > 0 {
            tracing::warn!(
                skipped,
                total = cert_proofs_total,
                "standalone DER: {skipped}/{cert_proofs_total} certs skipped; will retry next checkpoint",
            );
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

    Ok(())
}

/// Construct and DER-encode a `synta_mtc::types::Checkpoint` from raw components.
fn build_checkpoint_der(
    spki_der: &[u8],
    tree_size: u64,
    root_bytes: &[u8],
    now_unix: i64,
    log_algorithm: HashAlgorithm,
    tree_minimum_index: Option<u64>,
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
        tree_minimum_index: tree_minimum_index.map(Integer::from),
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
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
        interval.tick().await; // skip the immediate first tick
        loop {
            interval.tick().await;
            let now = crate::util::unix_now();
            for (ca_id, ca) in state.cas.iter() {
                let mtc = &ca.mtc;
                let (Some(log), Some(signing_key)) = (mtc.log.as_ref(), mtc.signing_key.as_ref())
                else {
                    continue;
                };
                if now - mtc.last_checkpoint_at() < mtc.checkpoint_interval_secs as i64 {
                    continue;
                }
                let origin = mtc.tlog_origin();
                if let Err(e) = produce_checkpoint(CheckpointParams {
                    log,
                    signing_key,
                    signing_hash_alg: &mtc.signing_hash_alg,
                    log_algorithm: mtc.algorithm,
                    db: &state.db,
                    ca_id,
                    cosigners: &mtc.cosigner_clients,
                    log_number: mtc.log_number,
                    tree_minimum_index: mtc.tree_minimum_index,
                    trust_anchor_id_der: mtc.trust_anchor_id_der.as_deref(),
                    log_origin: origin,
                })
                .await
                {
                    tracing::error!(ca_id, "MTC checkpoint failed: {e}");
                    continue;
                }
                mtc.touch_checkpoint();
                if let Err(e) =
                    db::checkpoints::prune_oldest(&state.db, ca_id, mtc.checkpoint_retention_count)
                        .await
                {
                    tracing::warn!(ca_id, "prune old MTC checkpoints: {e}");
                }
            }
        }
    })
}
