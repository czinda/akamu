use serde::{Deserialize, Serialize};

use crate::{
    grow_set::GrowSet,
    lww_map::LwwMap,
    lww_register::LwwRegister,
    merge::Merge,
    or_map::OrMap,
    types::{
        AccountEntry, AkaNodeEntry, AuditEventEntry, AuthzEntry, CertEntry, ChallengeEntry,
        DelegationEntry, EabKeyEntry, MtcCheckpointEntry, MtcCosigEntry, MtcWriter, OperatorEntry,
        OrderEntry, OrderOwner,
    },
};

// LwwMap key type for cosignatures: (checkpoint_id, cosigner_url)
type CosigKey = (String, String);

/// Counts of live entries per field — for observability / gossip status endpoint.
#[derive(Debug, Clone, Default)]
pub struct AkaCrdtCounts {
    pub cluster_nodes: usize,
    pub accounts: usize,
    pub orders: usize,
    pub authorizations: usize,
    pub challenges: usize,
    pub certificates: usize,
    pub eab_keys: usize,
    pub operators: usize,
    pub delegations: usize,
    pub mtc_checkpoints: usize,
    pub mtc_cosignatures: usize,
    pub audit_events: usize,
}

/// Top-level CRDT for Akamu cluster state.
///
/// All ACME protocol state, admin state, and MTC state lives here. Nonces,
/// CA private keys, and admin sessions are NOT replicated.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AkaCrdt {
    pub cluster_nodes: OrMap<String, AkaNodeEntry>,
    pub accounts: OrMap<String, AccountEntry>,
    pub orders: OrMap<String, OrderEntry>,
    pub authorizations: OrMap<String, AuthzEntry>,
    pub challenges: LwwMap<String, ChallengeEntry>,
    pub certificates: OrMap<String, CertEntry>,
    pub eab_keys: LwwMap<String, EabKeyEntry>,
    pub operators: OrMap<String, OperatorEntry>,
    pub delegations: OrMap<String, DelegationEntry>,
    pub mtc_checkpoints: LwwMap<u64, MtcCheckpointEntry>,
    pub mtc_cosignatures: LwwMap<CosigKey, MtcCosigEntry>,
    pub audit_events: GrowSet<AuditEventEntry>,
    /// Gossip-consensus ownership: order_id → owning node + claim timestamp.
    /// Access via `claim_order` / `is_order_owner`; not directly writable externally.
    pub(crate) order_owners: LwwMap<String, OrderOwner>,
    /// Gossip-consensus election: single elected MTC log writer.
    /// Access via `claim_mtc_writer` / `is_mtc_writer`; not directly writable externally.
    pub(crate) mtc_writer: LwwRegister<MtcWriter>,
}

impl AkaCrdt {
    /// Returns a sparse CRDT containing only entries written after `gen`.
    pub fn delta_since(&self, gen: u64) -> Self {
        Self {
            cluster_nodes: self.cluster_nodes.delta_since(gen),
            accounts: self.accounts.delta_since(gen),
            orders: self.orders.delta_since(gen),
            authorizations: self.authorizations.delta_since(gen),
            challenges: self.challenges.delta_since(gen),
            certificates: self.certificates.delta_since(gen),
            eab_keys: self.eab_keys.delta_since(gen),
            operators: self.operators.delta_since(gen),
            delegations: self.delegations.delta_since(gen),
            mtc_checkpoints: self.mtc_checkpoints.delta_since(gen),
            mtc_cosignatures: self.mtc_cosignatures.delta_since(gen),
            audit_events: self.audit_events.delta_since(gen),
            order_owners: self.order_owners.delta_since(gen),
            mtc_writer: self.mtc_writer.delta_since(gen).unwrap_or_default(),
        }
    }

    /// Returns entries written in the half-open range `(since, until]`.
    pub fn delta_range(&self, since: u64, until: u64) -> Self {
        Self {
            cluster_nodes: self.cluster_nodes.delta_range(since, until),
            accounts: self.accounts.delta_range(since, until),
            orders: self.orders.delta_range(since, until),
            authorizations: self.authorizations.delta_range(since, until),
            challenges: self.challenges.delta_range(since, until),
            certificates: self.certificates.delta_range(since, until),
            eab_keys: self.eab_keys.delta_range(since, until),
            operators: self.operators.delta_range(since, until),
            delegations: self.delegations.delta_range(since, until),
            mtc_checkpoints: self.mtc_checkpoints.delta_range(since, until),
            mtc_cosignatures: self.mtc_cosignatures.delta_range(since, until),
            audit_events: self.audit_events.delta_range(since, until),
            order_owners: self.order_owners.delta_range(since, until),
            mtc_writer: self.mtc_writer.delta_range(since, until).unwrap_or_default(),
        }
    }

    /// Permanently remove tombstones older than `cutoff` (unix seconds).
    pub fn purge_old_tombstones(&mut self, cutoff: i64) {
        self.cluster_nodes.purge_old_tombstones(cutoff);
        self.accounts.purge_old_tombstones(cutoff);
        self.orders.purge_old_tombstones(cutoff);
        self.authorizations.purge_old_tombstones(cutoff);
        self.challenges.purge_old_tombstones(cutoff);
        self.certificates.purge_old_tombstones(cutoff);
        self.eab_keys.purge_old_tombstones(cutoff);
        self.operators.purge_old_tombstones(cutoff);
        self.delegations.purge_old_tombstones(cutoff);
        self.mtc_checkpoints.purge_old_tombstones(cutoff);
        self.mtc_cosignatures.purge_old_tombstones(cutoff);
        self.order_owners.purge_old_tombstones(cutoff);
    }

    /// Returns the highest `local_gen` across all CRDT sub-collections.
    /// Used at startup to seed `CRDT_GENERATION` after `load_from_db`.
    pub fn max_local_gen(&self) -> u64 {
        let mut max = 0u64;
        max = max.max(self.cluster_nodes.max_local_gen());
        max = max.max(self.accounts.max_local_gen());
        max = max.max(self.orders.max_local_gen());
        max = max.max(self.authorizations.max_local_gen());
        max = max.max(self.challenges.max_local_gen());
        max = max.max(self.certificates.max_local_gen());
        max = max.max(self.eab_keys.max_local_gen());
        max = max.max(self.operators.max_local_gen());
        max = max.max(self.delegations.max_local_gen());
        max = max.max(self.mtc_checkpoints.max_local_gen());
        max = max.max(self.mtc_cosignatures.max_local_gen());
        max = max.max(self.audit_events.max_local_gen());
        max = max.max(self.order_owners.max_local_gen());
        max = max.max(self.mtc_writer.local_gen());
        max
    }

    /// Count of live (non-tombstoned) entries per field.
    pub fn entry_counts(&self) -> AkaCrdtCounts {
        AkaCrdtCounts {
            cluster_nodes: self.cluster_nodes.count_live(),
            accounts: self.accounts.count_live(),
            orders: self.orders.count_live(),
            authorizations: self.authorizations.count_live(),
            challenges: self.challenges.count_live(),
            certificates: self.certificates.count_live(),
            eab_keys: self.eab_keys.count_live(),
            operators: self.operators.count_live(),
            delegations: self.delegations.count_live(),
            mtc_checkpoints: self.mtc_checkpoints.count_live(),
            mtc_cosignatures: self.mtc_cosignatures.count_live(),
            audit_events: self.audit_events.len(),
        }
    }

    // ── Gossip-consensus ownership helpers ────────────────────────────────────

    /// Attempt to claim ownership of an order for `node_id`.
    ///
    /// Returns `true` if this node is now the owner (either it just claimed, or
    /// it already held live ownership). Returns `false` if another node holds
    /// live ownership that has not yet lapsed.
    pub fn claim_order(&mut self, order_id: &str, node_id: &str, now: i64, ttl: i64) -> bool {
        if let Some(owner) = self.order_owners.get(order_id) {
            if owner.node_id != node_id && owner.claimed_at.saturating_add(ttl) >= now {
                return false; // another live owner holds the slot
            }
        }
        self.order_owners.set(
            order_id.to_owned(),
            OrderOwner {
                node_id: node_id.to_owned(),
                claimed_at: now,
            },
            now,
            node_id,
        );
        true
    }

    /// Returns `true` if `node_id` holds live (non-lapsed) ownership of `order_id`.
    pub fn is_order_owner(&self, order_id: &str, node_id: &str, now: i64, ttl: i64) -> bool {
        self.order_owners
            .get(order_id)
            .map(|o| o.node_id == node_id && o.claimed_at.saturating_add(ttl) >= now)
            .unwrap_or(false)
    }

    /// Attempt to claim MTC log writer election for `node_id`.
    ///
    /// Returns `true` if this node is now the elected writer.
    pub fn claim_mtc_writer(&mut self, node_id: &str, now: i64, ttl: i64) -> bool {
        if let Some(writer) = self.mtc_writer.get() {
            if writer.node_id != node_id && writer.claimed_at.saturating_add(ttl) >= now {
                return false; // incumbent writer holds the election
            }
        }
        self.mtc_writer.set(
            MtcWriter {
                node_id: node_id.to_owned(),
                claimed_at: now,
            },
            now,
            node_id,
        );
        true
    }

    /// Returns `true` if `node_id` is the elected MTC writer and has not lapsed.
    pub fn is_mtc_writer(&self, node_id: &str, now: i64, ttl: i64) -> bool {
        self.mtc_writer
            .get()
            .map(|w| w.node_id == node_id && w.claimed_at.saturating_add(ttl) >= now)
            .unwrap_or(false)
    }
}

impl Merge for AkaCrdt {
    fn merge(&mut self, other: Self) {
        self.cluster_nodes.merge(other.cluster_nodes);
        self.accounts.merge(other.accounts);
        self.orders.merge(other.orders);
        self.authorizations.merge(other.authorizations);
        self.challenges.merge(other.challenges);
        self.certificates.merge(other.certificates);
        self.eab_keys.merge(other.eab_keys);
        self.operators.merge(other.operators);
        self.delegations.merge(other.delegations);
        self.mtc_checkpoints.merge(other.mtc_checkpoints);
        self.mtc_cosignatures.merge(other.mtc_cosignatures);
        self.audit_events.merge(other.audit_events);
        self.order_owners.merge(other.order_owners);
        self.mtc_writer.merge(other.mtc_writer);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::*;

    fn sample_crdt() -> AkaCrdt {
        let mut c = AkaCrdt::default();
        let now = 1_700_000_000i64;

        c.cluster_nodes.upsert(
            "node-1".to_owned(),
            AkaNodeEntry {
                node_id: "node-1".to_owned(),
                gossip_url: "https://node1/".to_owned(),
                ..Default::default()
            },
            now,
        );
        c.accounts.upsert(
            "acct-1".to_owned(),
            AccountEntry {
                account_id: "acct-1".to_owned(),
                status: "valid".to_owned(),
                ..Default::default()
            },
            now,
        );
        c.orders.upsert(
            "ord-1".to_owned(),
            OrderEntry {
                order_id: "ord-1".to_owned(),
                status: "pending".to_owned(),
                ..Default::default()
            },
            now,
        );
        c.authorizations.upsert(
            "authz-1".to_owned(),
            AuthzEntry {
                authz_id: "authz-1".to_owned(),
                status: "pending".to_owned(),
                ..Default::default()
            },
            now,
        );
        c.challenges.set(
            "chall-1".to_owned(),
            ChallengeEntry {
                challenge_id: "chall-1".to_owned(),
                status: "pending".to_owned(),
                ..Default::default()
            },
            now,
            "node-1",
        );
        c.certificates.upsert(
            "cert-1".to_owned(),
            CertEntry {
                cert_id: "cert-1".to_owned(),
                status: "valid".to_owned(),
                ..Default::default()
            },
            now,
        );
        c.eab_keys.set(
            "kid-1".to_owned(),
            EabKeyEntry {
                kid: "kid-1".to_owned(),
                ..Default::default()
            },
            now,
            "node-1",
        );
        c.operators.upsert(
            "op-1".to_owned(),
            OperatorEntry {
                operator_id: 1,
                name: "admin".to_owned(),
                role: "admin".to_owned(),
                ..Default::default()
            },
            now,
        );
        c.delegations.upsert(
            "del-1".to_owned(),
            DelegationEntry {
                delegation_id: "del-1".to_owned(),
                ..Default::default()
            },
            now,
        );
        c.mtc_checkpoints.set(
            1u64,
            MtcCheckpointEntry {
                tree_size: 1,
                root_hex: "abc".to_owned(),
                ..Default::default()
            },
            now,
            "node-1",
        );
        c.mtc_cosignatures.set(
            ("cp-1".to_owned(), "https://cosign/".to_owned()),
            MtcCosigEntry {
                checkpoint_id: "cp-1".to_owned(),
                cosigner_url: "https://cosign/".to_owned(),
                signature: vec![0, 1, 2],
                signed_at: now,
            },
            now,
            "node-1",
        );
        c.audit_events.insert(AuditEventEntry {
            event_id: "evt-1".to_owned(),
            occurred_at: "2024-01-01T00:00:00Z".to_owned(),
            event_type: "account.created".to_owned(),
            outcome: "success".to_owned(),
            node_id: "node-1".to_owned(),
            subject: None,
            principal: None,
            detail: None,
        });
        c
    }

    #[test]
    fn cbor_round_trip() {
        let crdt = sample_crdt();

        let mut buf = Vec::new();
        ciborium::ser::into_writer(&crdt, &mut buf).expect("encode failed");
        let decoded: AkaCrdt = ciborium::de::from_reader(buf.as_slice()).expect("decode failed");

        assert!(decoded.accounts.get("acct-1").is_some());
        assert!(decoded.orders.get("ord-1").is_some());
        assert!(decoded.certificates.get("cert-1").is_some());
        assert_eq!(decoded.mtc_cosignatures.count_live(), 1);
        assert_eq!(decoded.audit_events.len(), 1);
    }

    #[test]
    fn delta_since_zero_returns_full_state() {
        let crdt = sample_crdt();
        let delta = crdt.delta_since(0);

        assert!(delta.accounts.get("acct-1").is_some());
        assert!(delta.orders.get("ord-1").is_some());
        assert!(delta.cluster_nodes.get("node-1").is_some());
    }

    #[test]
    fn merge_is_convergent() {
        let mut a = sample_crdt();

        let mut b = AkaCrdt::default();
        b.accounts.upsert(
            "acct-b".to_owned(),
            AccountEntry {
                account_id: "acct-b".to_owned(),
                status: "valid".to_owned(),
                ..Default::default()
            },
            1_700_000_001,
        );

        let a_clone = a.clone();
        let b_clone = b.clone();
        a.merge(b_clone);
        b.merge(a_clone);

        assert!(a.accounts.get("acct-1").is_some());
        assert!(a.accounts.get("acct-b").is_some());
        assert!(b.accounts.get("acct-1").is_some());
        assert!(b.accounts.get("acct-b").is_some());
    }

    #[test]
    fn order_ownership_claim_and_lapse() {
        let mut crdt = AkaCrdt::default();
        let ttl = 150i64;
        let now = 1_700_000_000i64;

        assert!(crdt.claim_order("ord-1", "node-a", now, ttl));
        assert!(crdt.is_order_owner("ord-1", "node-a", now, ttl));
        assert!(!crdt.claim_order("ord-1", "node-b", now + 10, ttl));

        let lapsed_at = now + ttl + 1;
        assert!(crdt.claim_order("ord-1", "node-b", lapsed_at, ttl));
        assert!(crdt.is_order_owner("ord-1", "node-b", lapsed_at, ttl));
        assert!(!crdt.is_order_owner("ord-1", "node-a", lapsed_at, ttl));
    }

    #[test]
    fn mtc_writer_election_and_lapse() {
        let mut crdt = AkaCrdt::default();
        let ttl = 150i64;
        let now = 1_700_000_000i64;

        assert!(crdt.claim_mtc_writer("node-a", now, ttl));
        assert!(crdt.is_mtc_writer("node-a", now, ttl));
        assert!(!crdt.claim_mtc_writer("node-b", now + 10, ttl));

        let lapsed_at = now + ttl + 1;
        assert!(crdt.claim_mtc_writer("node-b", lapsed_at, ttl));
        assert!(crdt.is_mtc_writer("node-b", lapsed_at, ttl));
    }

    #[test]
    fn eab_hmac_key_not_gossiped() {
        // EabKeyEntry.hmac_key_b64u carries the HMAC secret and must be excluded
        // from CBOR serialization so it is never transmitted in gossip messages.
        let mut crdt = AkaCrdt::default();
        crdt.eab_keys.set(
            "kid-1".to_owned(),
            EabKeyEntry {
                kid: "kid-1".to_owned(),
                hmac_key_b64u: "super-secret-hmac-key".to_owned(),
                created: 1_700_000_000,
                used_at: None,
                profile_grants: None,
            },
            1_700_000_000,
            "node-1",
        );

        let mut buf = Vec::new();
        ciborium::ser::into_writer(&crdt, &mut buf).expect("encode failed");

        // The HMAC key must not appear anywhere in the CBOR bytes.
        assert!(
            !buf.windows("super-secret-hmac-key".len())
                .any(|w| w == b"super-secret-hmac-key"),
            "HMAC key leaked into CBOR gossip payload"
        );

        // The key ID must still be present (used_at and other metadata are gossiped).
        let decoded: AkaCrdt = ciborium::de::from_reader(buf.as_slice()).expect("decode failed");
        let entry = decoded.eab_keys.get("kid-1").expect("eab key missing after round-trip");
        assert_eq!(entry.kid, "kid-1");
        assert!(
            entry.hmac_key_b64u.is_empty(),
            "hmac_key_b64u should be empty string after CBOR round-trip (serde skip)"
        );
    }
}
