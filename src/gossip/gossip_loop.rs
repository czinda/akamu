//! Background gossip loop — spawned once from `main` after `AppState` is built.
//!
//! Each round: for every configured peer whose CRDT generation differs from the
//! last successful exchange, build a (delta or full) `GossipEnvelope`, seal it,
//! POST it, then merge the peer's signed response.  Hourly: purge old tombstones.
//!
//! Round structure (four sequential phases):
//!   A — build envelopes under one shared CRDT read-lock
//!   B — sign each envelope (no lock)
//!   C — spawn one JoinHandle per peer for the HTTP round-trip (parallel)
//!   D — process results sequentially: merge → snapshot → persist → update maps

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use tokio::task::JoinHandle;

use akamu_crdt::{Merge, CRDT_GENERATION};

use crate::gossip::crypto::{random_nonce, sign_and_seal, verify_and_open, SealRecipient};
use crate::gossip::envelope::GossipEnvelope;
use crate::state::AppState;
use crate::util::{unix_now, unix_to_rfc3339};

struct PreparedPeer {
    url: String,
    peer_node_id: String,
    kem_key: Vec<u8>,
    signing_key: Vec<u8>,
    envelope_bytes: Vec<u8>,
    is_first_contact: bool,
}

struct PeerTask {
    url: String,
    signing_key: Vec<u8>,
    is_first_contact: bool,
    handle: JoinHandle<Result<Vec<u8>, ()>>,
}

/// Entry point: called once from `main`.  Returns immediately when gossip is not configured.
pub async fn run(state: Arc<AppState>) {
    let gossip_cfg = match state.config.gossip.as_ref() {
        Some(g) if !g.peers.is_empty() => g,
        _ => {
            tracing::info!("gossip: no peers configured — loop disabled");
            return;
        }
    };

    let interval = Duration::from_secs(gossip_cfg.interval_secs.max(1));
    let tombstone_ttl_secs = gossip_cfg.tombstone_ttl_secs;
    // After a write notification, wait this long before running gossip so that
    // bursts of concurrent writes (e.g. all hooks from one issuance) are batched
    // into a single round rather than spawning N rounds in quick succession.
    let write_debounce = Duration::from_millis(10);

    // Tracks which http:// peers have already received a plaintext-HTTP warning (H-9).
    let mut http_warned: HashSet<String> = HashSet::new();

    tracing::info!(
        peers = ?gossip_cfg.peers,
        interval_secs = interval.as_secs(),
        "gossip: loop started"
    );

    // `peer_last_gen`: our CRDT_GENERATION after the last successful push to this peer.
    let mut peer_last_gen: HashMap<String, u64> = HashMap::new();
    // `peer_response_gen`: peer's reported generation; sent as `request_delta_since`.
    let mut peer_response_gen: HashMap<String, u64> = HashMap::new();
    // `peer_miss_count`: consecutive rounds a peer had no pinned keys; suppresses log spam.
    let mut peer_miss_count: HashMap<String, u32> = HashMap::new();

    // Time-based hourly GC — independent of how often notify-triggered rounds fire.
    let gc_interval = Duration::from_secs(3600);
    let mut last_gc = std::time::Instant::now();
    // Slow periodic DB persist: the DB is a restart-recovery cache, not hot path.
    // Persisting on every gossip receive would starve ACME requests on a shared pool.
    let persist_interval = Duration::from_secs(30);
    let mut last_persist = std::time::Instant::now();

    loop {
        // Wake on whichever fires first: the scheduled interval, or a CRDT write
        // notification from crdt_hooks.  On a write notification we add a short
        // debounce so that a burst of writes (all hooks from one issuance) is
        // batched into a single gossip round.
        tokio::select! {
            _ = tokio::time::sleep(interval) => {},
            _ = state.write_notify.notified() => {
                tokio::time::sleep(write_debounce).await;
            },
        }

        let now = unix_now();

        // Slow periodic DB persist — the DB is a restart-recovery cache, not hot path.
        // Doing this on a 30-second timer rather than after every peer merge avoids
        // contending with ACME requests on a shared pool.
        if last_persist.elapsed() >= persist_interval {
            last_persist = std::time::Instant::now();
            let snap = {
                let crdt = state.crdt.read().await;
                crdt.clone()
            };
            if let Err(e) = akamu_crdt::db::persist_crdt_cluster(&state.crdt_db, &snap).await {
                tracing::warn!(error = %e, "gossip: periodic CRDT cluster persist failed");
            }
            if let Err(e) = akamu_crdt::db::persist_crdt_acme(&state.db, &snap).await {
                tracing::warn!(error = %e, "gossip: periodic ACME persist failed");
            }
        }

        // Hourly: purge old tombstones.  Apply the purge in-place under a write lock
        // rather than persisting a snapshot first.  A snapshot approach has a data-loss
        // window: entries written after the snapshot read but before the in-memory purge
        // apply are absent from the persisted snapshot, so a crash at that point loses
        // them permanently from the DB.  The post-purge DB state is written on the next
        // periodic persist.
        if last_gc.elapsed() >= gc_interval {
            last_gc = std::time::Instant::now();
            let cutoff = now - tombstone_ttl_secs as i64;
            let audit_cutoff_str = unix_to_rfc3339(cutoff);
            {
                let mut crdt = state.crdt.write().await;
                crdt.purge_old_tombstones(cutoff);
                crdt.audit_events
                    .retain(|e| e.occurred_at.as_str() >= audit_cutoff_str.as_str());
            }
            tracing::info!(
                cutoff_secs = cutoff,
                "gossip: tombstone GC applied in-memory — DB will sync on next periodic persist"
            );
        }

        // Build peer list from config + CRDT-discovered peers (deduplicated).
        let all_peers: Vec<String> = {
            let crdt = state.crdt.read().await;
            let crdt_peers: Vec<String> = crdt
                .cluster_nodes
                .live_values()
                .filter(|(id, _)| id.as_str() != state.node_id.as_str())
                .map(|(_, e)| e.gossip_url.clone())
                .filter(|url| !url.is_empty())
                .collect();
            let mut seen = HashSet::new();
            state
                .config
                .gossip
                .as_ref()
                .map(|g| g.peers.as_slice())
                .unwrap_or(&[])
                .iter()
                .chain(crdt_peers.iter())
                .filter(|u| seen.insert((*u).clone()))
                .cloned()
                .collect()
        };

        // Warn once per http:// peer (H-9: plaintext transport).
        for peer_url in &all_peers {
            if peer_url.starts_with("http://") && http_warned.insert(peer_url.clone()) {
                tracing::warn!(
                    peer = %peer_url,
                    "gossip: peer URL uses plaintext HTTP — gossip traffic will not be encrypted in transit"
                );
            }
        }

        // Prune stale per-peer maps; HashSet gives O(1) lookup (L-5).
        let peer_set: HashSet<&str> = all_peers.iter().map(|s| s.as_str()).collect();
        peer_last_gen.retain(|k, _| peer_set.contains(k.as_str()));
        peer_response_gen.retain(|k, _| peer_set.contains(k.as_str()));
        peer_miss_count.retain(|k, _| peer_set.contains(k.as_str()));

        // H-10: Acquire ordering so we see all preceding CRDT writes.
        let current_gen = CRDT_GENERATION.load(std::sync::atomic::Ordering::Acquire);

        // ── Phase A: Build envelopes (sequential, one CRDT read-lock for all peers) ──────
        let mut prepared_peers: Vec<PreparedPeer> = Vec::new();
        {
            let crdt = state.crdt.read().await;
            for peer_url in &all_peers {
                let is_first_contact = !peer_last_gen.contains_key(peer_url.as_str());

                if peer_last_gen.get(peer_url.as_str()).copied() == Some(current_gen) {
                    tracing::debug!(peer = %peer_url, gen = current_gen, "gossip: unchanged, skipping");
                    continue;
                }

                // Find peer in cluster_nodes by URL; extract keys up-front (no references escape).
                // Reject if either key is absent — no TOFU (H-7).
                let found: Option<(String, Vec<u8>, Vec<u8>)> = crdt
                    .cluster_nodes
                    .live_values()
                    .find(|(id, e)| {
                        id.as_str() != state.node_id.as_str() && urls_match(peer_url, &e.gossip_url)
                    })
                    .map(|(id, e)| {
                        (
                            id.clone(),
                            e.kem_public_key_der.clone(),
                            e.gossip_signing_pub_key_der.clone(),
                        )
                    });

                let (peer_node_id, kem_key, signing_key) = match found {
                    None => {
                        let count = peer_miss_count.entry(peer_url.clone()).or_insert(0);
                        *count += 1;
                        if *count <= 3 {
                            tracing::warn!(
                                peer = %peer_url,
                                "gossip: peer not in cluster_nodes — use POST /admin/gossip/register to enroll"
                            );
                        } else {
                            tracing::debug!(
                                peer = %peer_url,
                                rounds = *count,
                                "gossip: peer not in cluster_nodes (suppressed)"
                            );
                        }
                        continue;
                    }
                    Some(t) => t,
                };

                if kem_key.is_empty() || signing_key.is_empty() {
                    let count = peer_miss_count.entry(peer_url.clone()).or_insert(0);
                    *count += 1;
                    if *count <= 3 {
                        tracing::warn!(
                            peer = %peer_url,
                            node_id = %peer_node_id,
                            "gossip: peer missing KEM or signing key — use POST /admin/gossip/register to enroll"
                        );
                    } else {
                        tracing::debug!(
                            peer = %peer_url,
                            node_id = %peer_node_id,
                            rounds = *count,
                            "gossip: peer missing keys (suppressed)"
                        );
                    }
                    continue;
                }
                peer_miss_count.remove(peer_url.as_str());

                let (payload_crdt, is_delta) = match peer_last_gen.get(peer_url.as_str()).copied() {
                    Some(since) => (crdt.delta_since(since), true),
                    None => (crdt.clone(), false),
                };

                let crdt_bytes = match GossipEnvelope::encode_crdt(&payload_crdt) {
                    Ok(b) => b,
                    Err(e) => {
                        tracing::error!(peer = %peer_url, error = %e, "gossip: CBOR encode CRDT failed");
                        continue;
                    }
                };

                let nonce = match random_nonce() {
                    Ok(n) => n,
                    Err(e) => {
                        tracing::error!(peer = %peer_url, error = %e, "gossip: nonce generation failed");
                        continue;
                    }
                };

                let envelope = GossipEnvelope {
                    crdt: crdt_bytes,
                    issued_at: unix_now(),
                    is_delta,
                    my_gen: current_gen,
                    request_delta_since: peer_response_gen.get(peer_url.as_str()).copied(),
                    nonce,
                };

                let envelope_bytes = match envelope.encode() {
                    Ok(b) => b,
                    Err(e) => {
                        tracing::error!(peer = %peer_url, error = %e, "gossip: CBOR encode envelope failed");
                        continue;
                    }
                };

                prepared_peers.push(PreparedPeer {
                    url: peer_url.clone(),
                    peer_node_id,
                    kem_key,
                    signing_key,
                    envelope_bytes,
                    is_first_contact,
                });
            }
        } // CRDT read lock released here.

        // ── Phase B: Sign each envelope (sequential, no lock) ───────────────────────────
        let mut peer_tasks: Vec<PeerTask> = Vec::new();
        for pp in prepared_peers {
            let signed_body = match sign_and_seal(
                &pp.envelope_bytes,
                &[SealRecipient {
                    hint: &pp.peer_node_id,
                    spki_der: &pp.kem_key,
                }],
                &state.node_gossip_signing_priv,
                &state.node_gossip_signing_cert,
            ) {
                Ok(b) => b,
                Err(e) => {
                    tracing::error!(peer = %pp.url, error = %e, "gossip: sign_and_seal failed");
                    continue;
                }
            };

            // ── Phase C: Spawn parallel HTTP round-trip (M-2: one JoinHandle per peer) ──
            let gossip_client = state.gossip_client.clone();
            let node_id = Arc::clone(&state.node_id);
            let post_url = format!("{}/gossip/sync", pp.url.trim_end_matches('/'));
            let display_url = pp.url.clone();

            let handle: JoinHandle<Result<Vec<u8>, ()>> = tokio::spawn(async move {
                tracing::debug!(peer = %display_url, bytes = signed_body.len(), "gossip: pushing");
                let resp = gossip_client
                    .post(&post_url)
                    .header("content-type", "application/pkcs7-mime")
                    .header("x-akamu-node-id", node_id.as_str())
                    .body(signed_body)
                    .send()
                    .await;
                match resp {
                    Err(e) => {
                        tracing::warn!(peer = %display_url, error = %e, "gossip: request failed");
                        Err(())
                    }
                    Ok(r) if !r.status().is_success() => {
                        tracing::warn!(
                            peer = %display_url,
                            status = %r.status(),
                            "gossip: peer returned error"
                        );
                        Err(())
                    }
                    Ok(r) => match r.bytes().await {
                        Ok(b) => Ok(b.to_vec()),
                        Err(e) => {
                            tracing::warn!(
                                peer = %display_url,
                                error = %e,
                                "gossip: read response body failed"
                            );
                            Err(())
                        }
                    },
                }
            });

            peer_tasks.push(PeerTask {
                url: pp.url,
                signing_key: pp.signing_key,
                is_first_contact: pp.is_first_contact,
                handle,
            });
        }

        // ── Phase D: Process results sequentially (merge → persist → map update) ────────
        for pt in peer_tasks {
            let http_result = match pt.handle.await {
                Ok(r) => r,
                Err(e) => {
                    tracing::error!(peer = %pt.url, "gossip: task panicked: {e}");
                    peer_last_gen.remove(pt.url.as_str());
                    peer_response_gen.remove(pt.url.as_str());
                    continue;
                }
            };

            let response_bytes = match http_result {
                Ok(b) => b,
                Err(()) => {
                    peer_last_gen.remove(pt.url.as_str());
                    peer_response_gen.remove(pt.url.as_str());
                    continue;
                }
            };

            // Verify and decrypt using pinned signing key — no TOFU.
            let plaintext = match verify_and_open(
                &response_bytes,
                &state.node_kem_priv,
                &pt.signing_key,
            ) {
                Ok(p) => p,
                Err(e) => {
                    tracing::warn!(peer = %pt.url, error = %e, "gossip: verify_and_open response failed");
                    peer_last_gen.remove(pt.url.as_str());
                    peer_response_gen.remove(pt.url.as_str());
                    continue;
                }
            };

            let peer_envelope = match GossipEnvelope::decode(&plaintext) {
                Ok(e) => e,
                Err(e) => {
                    tracing::warn!(peer = %pt.url, error = %e, "gossip: CBOR decode peer envelope failed");
                    peer_last_gen.remove(pt.url.as_str());
                    peer_response_gen.remove(pt.url.as_str());
                    continue;
                }
            };

            // Validate response timestamp — reject future-dated or stale responses.
            let resp_max_age = state
                .config
                .gossip
                .as_ref()
                .map(|g| g.gossip_envelope_max_age_secs as i64)
                .unwrap_or(300);
            let resp_clock_skew = state
                .config
                .gossip
                .as_ref()
                .map(|g| g.clock_skew_tolerance_secs as i64)
                .unwrap_or(30);
            if peer_envelope.issued_at > now + resp_clock_skew {
                tracing::warn!(
                    peer = %pt.url,
                    issued_at = peer_envelope.issued_at,
                    "gossip: rejecting future-dated response envelope"
                );
                peer_last_gen.remove(pt.url.as_str());
                peer_response_gen.remove(pt.url.as_str());
                continue;
            }
            if peer_envelope.issued_at < now - resp_max_age {
                tracing::warn!(
                    peer = %pt.url,
                    issued_at = peer_envelope.issued_at,
                    "gossip: rejecting stale response envelope"
                );
                peer_last_gen.remove(pt.url.as_str());
                peer_response_gen.remove(pt.url.as_str());
                continue;
            }

            let peer_crdt = match peer_envelope.decode_crdt() {
                Ok(c) => c,
                Err(e) => {
                    tracing::warn!(peer = %pt.url, error = %e, "gossip: CBOR decode peer CRDT failed");
                    peer_last_gen.remove(pt.url.as_str());
                    peer_response_gen.remove(pt.url.as_str());
                    continue;
                }
            };

            // Merge under write lock, then clone under read lock.  Holding the write
            // lock for the clone blocks all concurrent ACME read-lock holders for the
            // full clone duration; splitting the operations eliminates that stall.
            {
                let mut crdt = state.crdt.write().await;
                Merge::merge(&mut *crdt, peer_crdt);
            }
            let crdt_snapshot = {
                let crdt = state.crdt.read().await;
                crdt.clone()
            };

            // DB persist is intentionally omitted from the per-merge hot path.
            // The periodic persist (every 30 s, see above) keeps the DB in sync
            // without contending with ACME requests on a shared pool.

            // H-10: Acquire ordering so we see the generation bump from the merge above.
            let post_merge_gen = CRDT_GENERATION.load(std::sync::atomic::Ordering::Acquire);
            peer_last_gen.insert(pt.url.clone(), post_merge_gen);
            if peer_envelope.my_gen > 0 {
                peer_response_gen.insert(pt.url.clone(), peer_envelope.my_gen);
            }

            tracing::debug!(peer = %pt.url, delta = peer_envelope.is_delta, "gossip: merge complete");

            if pt.is_first_contact {
                let counts = crdt_snapshot.entry_counts();
                tracing::info!(
                    peer = %pt.url,
                    accounts = counts.accounts,
                    orders = counts.orders,
                    certificates = counts.certificates,
                    authorizations = counts.authorizations,
                    cluster_nodes = counts.cluster_nodes,
                    "gossip: first-contact merge complete"
                );
            }
        }
    }
}

/// Returns true when `peer_url` and `crdt_url` refer to the same origin.
///
/// Normalises by stripping trailing slashes before comparing.
fn urls_match(peer_url: &str, crdt_url: &str) -> bool {
    peer_url.trim_end_matches('/') == crdt_url.trim_end_matches('/')
}
