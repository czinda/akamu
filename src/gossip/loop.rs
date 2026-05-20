//! Background gossip loop — spawned once from `main` after `AppState` is built.
//!
//! Each round: for every configured peer whose CRDT generation differs from the
//! last successful exchange, build a (delta or full) `GossipEnvelope`, seal it,
//! POST it, then merge the peer's signed response.  Hourly: purge old tombstones.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use akamu_crdt::{Merge, CRDT_GENERATION};

use crate::gossip::crypto::{sign_and_seal, verify_and_open, SealRecipient};
use crate::gossip::envelope::GossipEnvelope;
use crate::state::AppState;
use crate::util::unix_now;

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
    let rounds_per_hour = (3600u64 / interval.as_secs().max(1)).max(1);

    tracing::info!(
        peers = ?gossip_cfg.peers,
        interval_secs = interval.as_secs(),
        "gossip: loop started"
    );

    // Per-peer tracking maps (local; not in AppState — only the loop needs them).
    // `peer_last_gen`: our CRDT_GENERATION after the last successful push to this peer.
    let mut peer_last_gen: HashMap<String, u64> = HashMap::new();
    // `peer_response_gen`: peer's reported CRDT_GENERATION from their last response.
    //   Sent back as `request_delta_since` so the peer replies with only new entries.
    let mut peer_response_gen: HashMap<String, u64> = HashMap::new();
    // `peer_kem_skip_count`: consecutive rounds a peer's KEM key was missing.
    let mut peer_kem_skip_count: HashMap<String, u32> = HashMap::new();

    let mut round: u64 = 0;

    loop {
        tokio::time::sleep(interval).await;
        round += 1;

        let now = unix_now();

        // Hourly: purge old tombstones in memory and in the DB.
        if round.is_multiple_of(rounds_per_hour) {
            let cutoff = now - tombstone_ttl_secs as i64;
            {
                let mut crdt = state.crdt.write().await;
                crdt.purge_old_tombstones(cutoff);
            }
            if let Err(e) = akamu_crdt::db::persist_crdt(&state.db, &*state.crdt.read().await).await
            {
                tracing::error!(err = %e, "gossip: persist after tombstone purge failed");
            }
        }

        // Build the peer list from config.  CRDT-discovered peers (from cluster_nodes)
        // are merged in so newly bootstrapped nodes are reached automatically.
        let all_peers: Vec<String> = {
            let crdt = state.crdt.read().await;
            let crdt_peers: Vec<String> = crdt
                .cluster_nodes
                .live_values()
                .filter(|(id, _)| id.as_str() != state.node_id.as_str())
                .map(|(_, e)| e.gossip_url.clone())
                .filter(|url| !url.is_empty())
                .collect();
            let mut seen = std::collections::BTreeSet::new();
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

        // Prune stale generation entries for peers no longer in the list.
        peer_last_gen.retain(|k, _| all_peers.contains(k));
        peer_response_gen.retain(|k, _| all_peers.contains(k));
        peer_kem_skip_count.retain(|k, _| all_peers.contains(k));

        for peer in &all_peers {
            // Look up this peer's node entry by gossip_url match.
            let (peer_node_id, kem_key): (String, Vec<u8>) = {
                let crdt = state.crdt.read().await;
                let found: Option<(String, Vec<u8>)> = crdt
                    .cluster_nodes
                    .live_values()
                    .find(|(id, e)| {
                        id.as_str() != state.node_id.as_str()
                            && !e.kem_public_key_der.is_empty()
                            && urls_match(peer, &e.gossip_url)
                    })
                    .map(|(id, e)| (id.clone(), e.kem_public_key_der.clone()));
                found.unwrap_or_default()
            };

            if kem_key.is_empty() {
                let count = peer_kem_skip_count.entry(peer.clone()).or_insert(0);
                *count += 1;
                if *count <= 3 {
                    tracing::warn!(peer = %peer, consecutive = *count, "gossip: no KEM key for peer, skipping");
                } else {
                    tracing::debug!(peer = %peer, consecutive = *count, "gossip: no KEM key for peer (suppressed)");
                }
                continue;
            }
            peer_kem_skip_count.remove(peer.as_str());

            let is_first_contact = !peer_last_gen.contains_key(peer.as_str());
            let current_gen = CRDT_GENERATION.load(std::sync::atomic::Ordering::Relaxed);
            if peer_last_gen.get(peer.as_str()).copied() == Some(current_gen) {
                tracing::debug!(peer = %peer, gen = current_gen, "gossip: unchanged, skipping");
                continue;
            }

            // Build envelope: delta if we have a prior sync point, full state otherwise.
            let envelope_bytes = {
                let crdt = state.crdt.read().await;
                let (payload_crdt, is_delta) = match peer_last_gen.get(peer.as_str()).copied() {
                    Some(since) => (crdt.delta_since(since), true),
                    None => (crdt.clone(), false),
                };
                let crdt_bytes = match GossipEnvelope::encode_crdt(&payload_crdt) {
                    Ok(b) => b,
                    Err(e) => {
                        tracing::error!(peer = %peer, err = %e, "gossip: CBOR encode CRDT failed");
                        continue;
                    }
                };
                let envelope = GossipEnvelope {
                    crdt: crdt_bytes,
                    issued_at: unix_now(),
                    is_delta,
                    my_gen: current_gen,
                    request_delta_since: peer_response_gen.get(peer.as_str()).copied(),
                };
                match envelope.encode() {
                    Ok(b) => b,
                    Err(e) => {
                        tracing::error!(peer = %peer, err = %e, "gossip: CBOR encode envelope failed");
                        continue;
                    }
                }
            };

            let send_body = match sign_and_seal(
                &envelope_bytes,
                &[SealRecipient {
                    hint: &peer_node_id,
                    spki_der: &kem_key,
                }],
                &state.node_gossip_signing_priv,
                &state.node_gossip_signing_cert,
            ) {
                Ok(b) => b,
                Err(e) => {
                    tracing::error!(peer = %peer, err = %e, "gossip: sign_and_seal failed");
                    continue;
                }
            };

            let url = format!("{}/admin/gossip/sync", peer.trim_end_matches('/'));
            tracing::debug!(peer = %peer, bytes = send_body.len(), "gossip: pushing");

            let resp = state
                .gossip_client
                .post(&url)
                .header("content-type", "application/pkcs7-mime")
                .header("x-akamu-node-id", state.node_id.as_str())
                .body(send_body)
                .send()
                .await;

            match resp {
                Err(e) => {
                    tracing::warn!(peer = %peer, err = %e, "gossip: request failed");
                    peer_last_gen.remove(peer.as_str());
                    peer_response_gen.remove(peer.as_str());
                }
                Ok(r) if !r.status().is_success() => {
                    tracing::warn!(peer = %peer, status = %r.status(), "gossip: peer returned error");
                    peer_last_gen.remove(peer.as_str());
                    peer_response_gen.remove(peer.as_str());
                }
                Ok(r) => {
                    let peer_bytes = match r.bytes().await {
                        Ok(b) => b,
                        Err(e) => {
                            tracing::warn!(peer = %peer, err = %e, "gossip: read response body failed");
                            peer_last_gen.remove(peer.as_str());
                            peer_response_gen.remove(peer.as_str());
                            continue;
                        }
                    };

                    // Verify response with TOFU when we have no signing key yet.
                    let peer_signing_pub: Option<Vec<u8>> = {
                        let crdt = state.crdt.read().await;
                        crdt.cluster_nodes
                            .get(&peer_node_id)
                            .filter(|e| !e.gossip_signing_pub_key_der.is_empty())
                            .map(|e| e.gossip_signing_pub_key_der.clone())
                    };

                    let plaintext = match verify_and_open(
                        &peer_bytes,
                        &state.node_kem_priv,
                        peer_signing_pub.as_deref(),
                    ) {
                        Ok(p) => p,
                        Err(e) => {
                            tracing::warn!(peer = %peer, err = %e, "gossip: verify_and_open response failed");
                            continue;
                        }
                    };

                    let peer_envelope = match GossipEnvelope::decode(&plaintext) {
                        Ok(e) => e,
                        Err(e) => {
                            tracing::warn!(peer = %peer, err = %e, "gossip: CBOR decode peer envelope failed");
                            continue;
                        }
                    };

                    let peer_crdt = match peer_envelope.decode_crdt() {
                        Ok(c) => c,
                        Err(e) => {
                            tracing::warn!(peer = %peer, err = %e, "gossip: CBOR decode peer CRDT failed");
                            continue;
                        }
                    };

                    {
                        let mut crdt = state.crdt.write().await;
                        Merge::merge(&mut *crdt, peer_crdt);
                    }

                    if let Err(e) =
                        akamu_crdt::db::persist_crdt(&state.db, &*state.crdt.read().await).await
                    {
                        tracing::error!(peer = %peer, err = %e, "gossip: persist after merge failed");
                    }

                    let post_merge_gen = CRDT_GENERATION.load(std::sync::atomic::Ordering::Relaxed);
                    peer_last_gen.insert(peer.clone(), post_merge_gen);
                    if peer_envelope.my_gen > 0 {
                        peer_response_gen.insert(peer.clone(), peer_envelope.my_gen);
                    }

                    tracing::debug!(peer = %peer, delta = peer_envelope.is_delta, "gossip: merge complete");

                    if is_first_contact {
                        let counts = state.crdt.read().await.entry_counts();
                        tracing::info!(
                            peer = %peer,
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
    }
}

/// Returns true when `peer_url` and `crdt_url` refer to the same origin.
///
/// Normalises by stripping trailing slashes before comparing so that
/// `"http://node2:8081"` matches `"http://node2:8081/"`.
fn urls_match(peer_url: &str, crdt_url: &str) -> bool {
    peer_url.trim_end_matches('/') == crdt_url.trim_end_matches('/')
}
