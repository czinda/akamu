use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::merge::Merge;

/// Observed-Remove Map. Supports soft deletes via tombstones.
/// Merge = union of live entries; tombstones always win over live.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(
    serialize = "K: Serialize + Eq + std::hash::Hash, V: Serialize",
    deserialize = "K: Deserialize<'de> + Eq + std::hash::Hash, V: Deserialize<'de>"
))]
pub struct OrMap<K, V> {
    #[serde(rename = "e")]
    entries: HashMap<K, OrMapEntry<V>>,
}

impl<K, V> Default for OrMap<K, V> {
    fn default() -> Self {
        Self {
            entries: HashMap::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrMapEntry<V> {
    #[serde(rename = "v")]
    pub(crate) value: V,
    #[serde(rename = "at")]
    pub(crate) added_at: i64,
    #[serde(rename = "ts")]
    pub(crate) tombstone: bool,
    #[serde(rename = "ta", skip_serializing_if = "Option::is_none", default)]
    pub(crate) tombstone_at: Option<i64>,
    /// Local-only write generation. Never serialised; defaults to 0 after reload.
    #[serde(skip, default)]
    pub(crate) local_gen: u64,
}

impl<K: Eq + std::hash::Hash + Clone, V: Clone> OrMap<K, V> {
    pub fn all_entries(&self) -> impl Iterator<Item = (&K, &OrMapEntry<V>)> {
        self.entries.iter()
    }

    pub fn insert(&mut self, key: K, value: V, timestamp: i64) {
        self.entries.entry(key).or_insert_with(|| {
            let gen = crate::generation::next_gen();
            OrMapEntry {
                value,
                added_at: timestamp,
                tombstone: false,
                tombstone_at: None,
                local_gen: gen,
            }
        });
    }

    /// Tombstone an entry. Returns the `local_gen` of the resulting tombstone.
    ///
    /// Inserts a tombstone even when the key is absent: if a remove arrives
    /// before its matching insert (out-of-order gossip delivery), the tombstone
    /// must be recorded so the subsequent insert does not resurrect the entry.
    pub fn remove(&mut self, key: &K, timestamp: i64) -> u64
    where
        V: Default,
    {
        let e = self
            .entries
            .entry(key.clone())
            .or_insert_with(|| OrMapEntry {
                value: V::default(),
                added_at: timestamp,
                tombstone: false,
                tombstone_at: None,
                local_gen: 0,
            });
        // Also update tombstone_at when the entry is already tombstoned but
        // tombstone_at is None (can happen when loaded from DB without a
        // tombstone timestamp). Without a tombstone_at, purge_old_tombstones
        // would incorrectly GC the entry immediately.
        if !e.tombstone || e.tombstone_at.is_none() {
            e.tombstone = true;
            e.tombstone_at = Some(timestamp);
            e.local_gen = crate::generation::next_gen();
        }
        e.local_gen
    }

    pub fn get<Q>(&self, key: &Q) -> Option<&V>
    where
        K: std::borrow::Borrow<Q>,
        Q: Eq + std::hash::Hash + ?Sized,
    {
        self.entries
            .get(key)
            .filter(|e| !e.tombstone)
            .map(|e| &e.value)
    }

    /// Insert or replace an entry, clearing any existing tombstone.
    ///
    /// If the entry was previously tombstoned (soft-deleted), calling `upsert`
    /// resurrects it. Only call `upsert` after a `remove` when the business
    /// logic explicitly permits resurrection (e.g., re-activating an account).
    ///
    /// Returns the `local_gen` assigned to this entry.
    pub fn upsert(&mut self, key: K, value: V, timestamp: i64) -> u64 {
        let gen = crate::generation::next_gen();
        self.entries.insert(
            key,
            OrMapEntry {
                value,
                added_at: timestamp,
                tombstone: false,
                tombstone_at: None,
                local_gen: gen,
            },
        );
        gen
    }

    /// Insert an entry directly from a DB row, preserving the stored `local_gen`.
    /// Used only by `db::load_from_db`; does not advance `CRDT_GENERATION`.
    #[cfg(feature = "db")]
    pub(crate) fn load_entry(
        &mut self,
        key: K,
        value: V,
        added_at: i64,
        tombstone: bool,
        tombstone_at: Option<i64>,
        local_gen: u64,
    ) {
        self.entries.insert(
            key,
            OrMapEntry {
                value,
                added_at,
                tombstone,
                tombstone_at,
                local_gen,
            },
        );
    }

    pub fn live_values(&self) -> impl Iterator<Item = (&K, &V)> {
        self.entries
            .iter()
            .filter(|(_, e)| !e.tombstone)
            .map(|(k, e)| (k, &e.value))
    }

    pub fn tombstoned_values(&self) -> impl Iterator<Item = (&K, &V)> {
        self.entries
            .iter()
            .filter(|(_, e)| e.tombstone)
            .map(|(k, e)| (k, &e.value))
    }

    pub fn count_live(&self) -> usize {
        self.entries.values().filter(|e| !e.tombstone).count()
    }

    /// Remove (not tombstone) live entries for which `f` returns false.
    /// Tombstoned entries are always kept so removal propagates on merge.
    pub fn retain<F>(&mut self, mut f: F)
    where
        F: FnMut(&K, &V) -> bool,
    {
        self.entries.retain(|k, e| e.tombstone || f(k, &e.value));
    }

    /// Returns a map containing only entries whose `local_gen` exceeds `gen`.
    pub fn delta_since(&self, gen: u64) -> Self
    where
        K: Clone,
        V: Clone,
    {
        Self {
            entries: self
                .entries
                .iter()
                .filter(|(_, e)| e.local_gen > gen)
                .map(|(k, e)| (k.clone(), e.clone()))
                .collect(),
        }
    }

    /// Returns a map containing only entries written in `(since, until]`.
    pub fn delta_range(&self, since: u64, until: u64) -> Self
    where
        K: Clone,
        V: Clone,
    {
        Self {
            entries: self
                .entries
                .iter()
                .filter(|(_, e)| e.local_gen > since && e.local_gen <= until)
                .map(|(k, e)| (k.clone(), e.clone()))
                .collect(),
        }
    }

    /// Permanently remove tombstones older than `cutoff` (unix seconds).
    /// Only call after the tombstone has had time to propagate to all peers.
    pub fn purge_old_tombstones(&mut self, cutoff: i64) {
        self.entries
            .retain(|_, e| !e.tombstone || e.tombstone_at.is_some_and(|t| t >= cutoff));
    }

    /// Returns the highest `local_gen` across all entries in this map.
    pub fn max_local_gen(&self) -> u64 {
        self.entries
            .values()
            .map(|e| e.local_gen)
            .max()
            .unwrap_or(0)
    }
}

impl<K: Eq + std::hash::Hash + Clone, V: Clone> Merge for OrMap<K, V> {
    fn merge(&mut self, other: Self) {
        for (k, mut other_entry) in other.entries {
            match self.entries.get_mut(&k) {
                None => {
                    other_entry.local_gen = crate::generation::next_gen();
                    self.entries.insert(k, other_entry);
                }
                Some(self_entry) => {
                    if other_entry.tombstone && !self_entry.tombstone {
                        // Tombstone always wins over live.
                        self_entry.tombstone = true;
                        self_entry.tombstone_at = other_entry.tombstone_at;
                        self_entry.local_gen = crate::generation::next_gen();
                    } else if !other_entry.tombstone
                        && !self_entry.tombstone
                        && other_entry.added_at > self_entry.added_at
                    {
                        // LWW for live entries: later write timestamp wins.
                        other_entry.local_gen = crate::generation::next_gen();
                        *self_entry = other_entry;
                    }
                    // self is tombstone, other is live → tombstone wins (no change).
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insert_is_idempotent() {
        let mut m: OrMap<String, u32> = OrMap::default();
        m.insert("k".to_owned(), 1, 100);
        m.insert("k".to_owned(), 2, 200); // second insert on same key is a no-op
        assert_eq!(m.get("k"), Some(&1));
    }

    #[test]
    fn tombstone_wins_on_merge() {
        let mut a: OrMap<String, u32> = OrMap::default();
        a.insert("k".to_owned(), 42, 100);

        let mut b: OrMap<String, u32> = OrMap::default();
        b.insert("k".to_owned(), 42, 100);
        b.remove(&"k".to_owned(), 200);

        a.merge(b);
        assert_eq!(a.get("k"), None); // tombstone won
        assert!(a.entries["k"].tombstone);
    }

    #[test]
    fn merge_live_lww_by_added_at() {
        // Node A has an older version; node B has a newer one.  After merge the
        // newer value must win — live-vs-live conflict resolves by added_at LWW.
        let mut a: OrMap<String, u32> = OrMap::default();
        a.upsert("k".to_owned(), 1, 100);

        let mut b: OrMap<String, u32> = OrMap::default();
        b.upsert("k".to_owned(), 2, 200);

        a.merge(b);
        assert_eq!(a.get("k"), Some(&2)); // newer wins

        // Older timestamp must NOT overwrite a newer in-place entry.
        let mut c: OrMap<String, u32> = OrMap::default();
        c.upsert("k".to_owned(), 99, 50); // older than current value in a

        a.merge(c);
        assert_eq!(a.get("k"), Some(&2)); // still 2
    }

    #[test]
    fn tombstone_blocks_subsequent_live_insert() {
        // A tombstone delivered before a matching insert must prevent resurrection.
        let mut m: OrMap<String, u32> = OrMap::default();
        m.remove(&"k".to_owned(), 100);
        assert!(m.entries["k"].tombstone);

        // Later insert at a lower timestamp must not resurrect.
        m.insert("k".to_owned(), 42, 50);
        assert_eq!(m.get("k"), None);
    }

    #[test]
    fn delta_range_excludes_outside_window() {
        let mut m: OrMap<String, u32> = OrMap::default();
        m.insert("a".to_owned(), 1, 100);
        let gen_a = m.entries["a"].local_gen;
        m.insert("b".to_owned(), 2, 200);
        let gen_b = m.entries["b"].local_gen;

        // delta_range for window (gen_a, gen_b] should include only "b"
        let delta = m.delta_range(gen_a, gen_b);
        assert!(delta.get("b").is_some());
        assert!(delta.get("a").is_none());
    }
}
