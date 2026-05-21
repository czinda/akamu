use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::lww_register::LwwRegister;
use crate::merge::Merge;

/// LWW-Map: each key has an independent LWW value.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(
    serialize = "K: Serialize + Eq + std::hash::Hash, V: Serialize",
    deserialize = "K: Deserialize<'de> + Eq + std::hash::Hash, V: Deserialize<'de>"
))]
pub struct LwwMap<K, V> {
    #[serde(rename = "e")]
    entries: HashMap<K, LwwRegister<V>>,
}

impl<K, V> Default for LwwMap<K, V> {
    fn default() -> Self {
        Self {
            entries: HashMap::default(),
        }
    }
}

impl<K: Eq + std::hash::Hash + Clone, V: Clone> LwwMap<K, V> {
    pub fn all_entries(&self) -> impl Iterator<Item = (&K, &LwwRegister<V>)> {
        self.entries.iter()
    }

    /// Set a value. Returns the `local_gen` of the register after the write
    /// (unchanged if the new timestamp did not win the LWW race).
    pub fn set(&mut self, key: K, value: V, timestamp: i64, node_id: &str) -> u64 {
        let reg = self.entries.entry(key).or_default();
        reg.set(value, timestamp, node_id);
        reg.local_gen()
    }

    pub fn get<Q>(&self, key: &Q) -> Option<&V>
    where
        K: std::borrow::Borrow<Q>,
        Q: Eq + std::hash::Hash + ?Sized,
    {
        self.entries.get(key).and_then(|r| r.get())
    }

    /// Record a deletion tombstone for the given key.
    /// Returns the `local_gen` of the register after the write.
    pub fn remove(&mut self, key: K, timestamp: i64, node_id: &str) -> u64 {
        let reg = self.entries.entry(key).or_default();
        reg.remove(timestamp, node_id);
        reg.local_gen()
    }

    /// Returns `true` if any register (live or tombstoned) exists for this key.
    pub fn contains_key<Q>(&self, key: &Q) -> bool
    where
        K: std::borrow::Borrow<Q>,
        Q: Eq + std::hash::Hash + ?Sized,
    {
        self.entries.contains_key(key)
    }

    pub fn retain<F: FnMut(&V) -> bool>(&mut self, mut f: F) {
        // Tombstones must always be kept so remove-wins semantics propagate on merge.
        self.entries
            .retain(|_, reg| reg.is_tombstone() || reg.get().map(&mut f).unwrap_or(false));
    }

    pub fn count_live(&self) -> usize {
        self.entries.values().filter(|r| r.get().is_some()).count()
    }

    /// Returns a map containing only registers whose `local_gen` exceeds `gen`.
    pub fn delta_since(&self, gen: u64) -> Self
    where
        K: Clone,
        V: Clone,
    {
        Self {
            entries: self
                .entries
                .iter()
                .filter(|(_, r)| r.delta_since(gen).is_some())
                .map(|(k, r)| (k.clone(), r.clone()))
                .collect(),
        }
    }

    /// Returns a map containing only registers written in `(since, until]`.
    pub fn delta_range(&self, since: u64, until: u64) -> Self
    where
        K: Clone,
        V: Clone,
    {
        Self {
            entries: self
                .entries
                .iter()
                .filter_map(|(k, r)| r.delta_range(since, until).map(|dr| (k.clone(), dr)))
                .collect(),
        }
    }

    /// Returns the highest `local_gen` across all registers in this map.
    pub fn max_local_gen(&self) -> u64 {
        self.entries
            .values()
            .map(|r| r.local_gen())
            .max()
            .unwrap_or(0)
    }

    /// Insert a register directly from a DB row, preserving the stored `local_gen`.
    /// Used only by `db::load_from_db`; does not advance `CRDT_GENERATION`.
    #[cfg(feature = "db")]
    pub(crate) fn load_entry(&mut self, key: K, register: LwwRegister<V>) {
        self.entries.insert(key, register);
    }

    /// Remove tombstoned entries whose deletion timestamp is older than `cutoff`.
    pub fn purge_old_tombstones(&mut self, cutoff: i64) {
        self.entries
            .retain(|_, reg| !reg.is_tombstone() || reg.timestamp() >= cutoff);
    }
}

impl<K: Eq + std::hash::Hash + Clone, V: Clone> Merge for LwwMap<K, V> {
    fn merge(&mut self, other: Self) {
        for (k, other_reg) in other.entries {
            self.entries.entry(k).or_default().merge(other_reg);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn concurrent_set_converges() {
        let mut a: LwwMap<String, u32> = LwwMap::default();
        let mut b: LwwMap<String, u32> = LwwMap::default();

        a.set("k".to_owned(), 1, 100, "node-a");
        b.set("k".to_owned(), 2, 200, "node-b");

        // Both nodes merge each other: both should converge on value 2 (higher ts).
        let a_clone = a.clone();
        let b_clone = b.clone();
        a.merge(b_clone);
        b.merge(a_clone);

        assert_eq!(a.get("k"), Some(&2));
        assert_eq!(b.get("k"), Some(&2));
    }

    #[test]
    fn delta_since_includes_all_inserted_keys() {
        let mut m: LwwMap<String, u32> = LwwMap::default();
        m.set("a".to_owned(), 1, 100, "node-a");
        m.set("b".to_owned(), 2, 200, "node-b");

        // delta_since(0) should include both keys.
        let delta = m.delta_since(0);
        assert!(delta.get("a").is_some());
        assert!(delta.get("b").is_some());
    }
}
