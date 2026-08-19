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

use akamu_crdt::{AkaCrdt, Merge, CRDT_GENERATION};

use crate::gossip::crypto::{random_nonce, sign_and_seal, verify_and_open, SealRecipient};
use crate::gossip::envelope::GossipEnvelope;
use crate::state::AppState;
use crate::util::unix_now;

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

struct ValidatedPeer {
    url: String,
    peer_my_gen: u64,
    is_first_contact: bool,
    is_delta: bool,
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
    // Sliding-window debounce: after the first write notification, extend the
    // wait on each additional notification that arrives within the slide window,
    // up to a hard cap.  This coalesces all ~8 writes from one ACME issuance
    // into a single gossip round instead of firing N rounds in quick succession.
    let write_debounce_slide = Duration::from_millis(20);
    let write_debounce_max = Duration::from_millis(150);
    // Minimum wall-clock gap between write-notify-triggered rounds.  Under high
    // concurrency the debounce window fills immediately, capping gossip at ~7 Hz.
    // At 10 nodes that means 63 simultaneous inbound gossip handlers per second,
    // each performing a full CRDT clone for its response — enough to saturate the
    // runtime.  This floor limits write-notify gossip to ~2 Hz regardless of load.
    let write_notify_min_interval = Duration::from_millis(500);
    // Stagger first gossip round by a node-id-derived jitter so that nodes started
    // together (e.g. in a benchmark or simultaneous deploy) do not all gossip at the
    // same instant.  Synchronized gossip storms cause N-1 gossip_sync write-lock
    // requests to queue simultaneously on every receiving node, creating a write-lock
    // convoy that delays ACME request handlers for the duration of N-1 merges.
    // The jitter spreads those storms across the full min_interval window.
    let startup_jitter = {
        let hash = state
            .node_id
            .bytes()
            .fold(0u64, |acc, b| acc.wrapping_mul(31).wrapping_add(b as u64));
        Duration::from_millis(hash % write_notify_min_interval.as_millis() as u64)
    };
    let mut last_notify_round = std::time::Instant::now()
        .checked_sub(startup_jitter)
        .unwrap_or_else(std::time::Instant::now);

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
    let mut persist_fail_streak: u32 = 0;

    loop {
        // Wake on whichever fires first: the scheduled interval, or a CRDT write
        // notification from crdt_hooks.  On a write notification we add a short
        // debounce so that a burst of writes (all hooks from one issuance) is
        // batched into a single gossip round.
        tokio::select! {
            _ = tokio::time::sleep(interval) => {},
            _ = state.write_notify.notified() => {
                let hard_cap = tokio::time::Instant::now() + write_debounce_max;
                loop {
                    let window_end = (tokio::time::Instant::now() + write_debounce_slide).min(hard_cap);
                    match tokio::time::timeout_at(window_end, state.write_notify.notified()).await {
                        Ok(_) if tokio::time::Instant::now() < hard_cap => {}
                        _ => break,
                    }
                }
                // Rate-limit write-notify rounds: if the previous round fired recently,
                // sleep out the remainder so gossip runs at most once per min_interval.
                let elapsed = last_notify_round.elapsed();
                if elapsed < write_notify_min_interval {
                    tokio::time::sleep(write_notify_min_interval - elapsed).await;
                }
                last_notify_round = std::time::Instant::now();
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
            let mut failed = false;
            if let Err(e) = akamu_crdt::db::persist_crdt_cluster(&state.crdt_db, &snap).await {
                tracing::warn!(error = %e, "gossip: periodic CRDT cluster persist failed");
                failed = true;
            }
            if let Err(e) = akamu_crdt::db::persist_crdt_acme(&state.db, &snap).await {
                tracing::warn!(error = %e, "gossip: periodic ACME persist failed");
                failed = true;
            }
            if failed {
                persist_fail_streak += 1;
                if persist_fail_streak >= 3 {
                    tracing::error!(
                        consecutive_failures = persist_fail_streak,
                        "gossip: DB persist has failed {persist_fail_streak} consecutive times — \
                         in-memory state may be lost on restart"
                    );
                }
            } else {
                persist_fail_streak = 0;
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
            {
                let mut crdt = state.crdt.write().await;
                crdt.purge_old_tombstones(cutoff);
            }
            tracing::info!(
                cutoff_secs = cutoff,
                "gossip: tombstone GC applied in-memory — DB will sync on next periodic persist"
            );
        }

        // Retry policy rebuild if a previous round failed.
        if state
            .policy_rebuild_needed
            .swap(false, std::sync::atomic::Ordering::AcqRel)
        {
            tracing::info!("retrying deferred policy rebuild from previous gossip round");
            crate::policy::rebuild_or_defer(&state, "deferred policy rebuild still failing").await;
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

        // Fan-out limiting: contact at most `fan_out` peers per round to bound the
        // O(N²) simultaneous-handler load on receiving nodes.  A rotating window
        // (indexed by current_gen) cycles through all peers so each is reached within
        // ceil(N / fan_out) rounds.  fan_out = 0 means all peers (default).
        let fan_out_buf: Vec<String>;
        let gossip_peers: &[String] =
            if gossip_cfg.fan_out == 0 || all_peers.len() <= gossip_cfg.fan_out {
                &all_peers
            } else {
                let n = all_peers.len();
                let k = gossip_cfg.fan_out;
                let start = (current_gen as usize) % n;
                fan_out_buf = (0..k).map(|i| all_peers[(start + i) % n].clone()).collect();
                &fan_out_buf
            };

        // ── Phase A: Build envelopes (sequential, one CRDT read-lock for all peers) ──────
        let mut prepared_peers: Vec<PreparedPeer> = Vec::new();
        {
            let crdt = state.crdt.read().await;
            for peer_url in gossip_peers {
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

        // ── Phase D: Validate + decode (no lock), batch-merge under one write-lock ─────────
        //
        // Pass 1: await handles and decrypt/decode all responses without holding any lock.
        // Pass 2: merge all valid CRDTs under a single write-lock acquisition (N→1 per round).
        // Pass 3: update per-peer maps and emit first-contact log if needed.
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

        let mut peer_crdts: Vec<AkaCrdt> = Vec::new();
        let mut validated: Vec<ValidatedPeer> = Vec::new();

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

            let mut peer_crdt = match peer_envelope.decode_crdt() {
                Ok(c) => c,
                Err(e) => {
                    tracing::warn!(peer = %pt.url, error = %e, "gossip: CBOR decode peer CRDT failed");
                    peer_last_gen.remove(pt.url.as_str());
                    peer_response_gen.remove(pt.url.as_str());
                    continue;
                }
            };
            // Bound per-entry timestamps to the same forward tolerance
            // already applied to the envelope's own issued_at above, so a
            // compromised or clock-skewed peer cannot assert a far-future
            // added_at/tombstone_at to always win merge tiebreaks going
            // forward — see the identical clamp in gossip::handlers::gossip_sync.
            peer_crdt.clamp_timestamps(now + resp_clock_skew);

            peer_crdts.push(peer_crdt);
            validated.push(ValidatedPeer {
                url: pt.url,
                peer_my_gen: peer_envelope.my_gen,
                is_first_contact: pt.is_first_contact,
                is_delta: peer_envelope.is_delta,
            });
        }

        // Pre-merge all peer CRDTs into a scratch accumulator (no lock held).
        // Then merge the accumulator into the live CRDT under a single brief write-lock.
        // This reduces both the number of write-lock acquisitions (N→1) and the
        // lock-hold duration (proportional to one merge instead of N merges).
        let policy_changed = if !peer_crdts.is_empty() {
            let policy_gen_before = {
                let crdt = state.crdt.read().await;
                crdt.policy_rules.max_local_gen()
            };
            let mut combined = AkaCrdt::default();
            for peer_crdt in peer_crdts {
                Merge::merge(&mut combined, peer_crdt);
            }
            {
                let mut crdt = state.crdt.write().await;
                Merge::merge(&mut *crdt, combined);
            }
            let policy_gen_after = {
                let crdt = state.crdt.read().await;
                crdt.policy_rules.max_local_gen()
            };
            policy_gen_after > policy_gen_before
        } else {
            false
        };

        if policy_changed {
            tracing::info!(
                "policy_rules changed via gossip, persisting and rebuilding issuance policy"
            );
            let snap = {
                let crdt = state.crdt.read().await;
                crdt.clone()
            };
            if let Err(e) = akamu_crdt::db::persist_crdt_acme(&state.db, &snap).await {
                tracing::error!(error = %e, "gossip: policy-triggered ACME persist failed — skipping rebuild (DB state is stale)");
            } else {
                crate::policy::rebuild_or_defer(
                    &state,
                    "failed to rebuild policy after gossip merge",
                )
                .await;
            }
        }

        // H-10: Acquire ordering so we see all generation bumps from the merges above.
        let post_merge_gen = CRDT_GENERATION.load(std::sync::atomic::Ordering::Acquire);

        let has_first_contact = validated.iter().any(|v| v.is_first_contact);
        let crdt_snapshot = if has_first_contact {
            let crdt = state.crdt.read().await;
            Some(crdt.clone())
        } else {
            None
        };

        for v in validated {
            peer_last_gen.insert(v.url.clone(), post_merge_gen);
            if v.peer_my_gen > 0 {
                peer_response_gen.insert(v.url.clone(), v.peer_my_gen);
            }
            tracing::debug!(peer = %v.url, delta = v.is_delta, "gossip: merge complete");
            if v.is_first_contact {
                let counts = crdt_snapshot.as_ref().unwrap().entry_counts();
                tracing::info!(
                    peer = %v.url,
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
