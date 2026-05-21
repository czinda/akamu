use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::merge::Merge;

/// Grow-only set with per-entry generation tracking.
///
/// Merge = union. No tombstones; use age-based archival externally.
///
/// Each entry records the local generation at which it was inserted, enabling
/// `delta_since` to return only newly added entries rather than the full set.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(
    serialize = "T: Serialize + Eq + std::hash::Hash",
    deserialize = "T: Deserialize<'de> + Eq + std::hash::Hash"
))]
pub struct GrowSet<T: Eq + std::hash::Hash> {
    /// Maps each entry to the local generation at which it was first inserted.
    #[serde(rename = "e")]
    entries: HashMap<T, u64>,
}

impl<T: Eq + std::hash::Hash> Default for GrowSet<T> {
    fn default() -> Self {
        Self {
            entries: HashMap::default(),
        }
    }
}

impl<T: Eq + std::hash::Hash + Clone> GrowSet<T> {
    /// Insert a value.  Does nothing if the value is already present.
    pub fn insert(&mut self, value: T) {
        self.entries
            .entry(value)
            .or_insert_with(crate::generation::next_gen);
    }

    pub fn contains(&self, value: &T) -> bool {
        self.entries.contains_key(value)
    }

    pub fn iter(&self) -> impl Iterator<Item = &T> {
        self.entries.keys()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Remove entries for which `keep` returns `false`.
    /// Use for age-based archival; there are no tombstones in a GrowSet.
    pub fn retain<F: FnMut(&T) -> bool>(&mut self, mut keep: F) {
        self.entries.retain(|k, _| keep(k));
    }

    /// Returns the highest `local_gen` across all entries in this set.
    pub fn max_local_gen(&self) -> u64 {
        self.entries.values().copied().max().unwrap_or(0)
    }

    /// Returns a GrowSet containing only entries inserted after `gen`.
    pub fn delta_since(&self, gen: u64) -> Self {
        Self {
            entries: self
                .entries
                .iter()
                .filter(|(_, &entry_gen)| entry_gen > gen)
                .map(|(k, &v)| (k.clone(), v))
                .collect(),
        }
    }

    /// Returns a GrowSet containing only entries inserted in `(since, until]`.
    pub fn delta_range(&self, since: u64, until: u64) -> Self {
        Self {
            entries: self
                .entries
                .iter()
                .filter(|(_, &entry_gen)| entry_gen > since && entry_gen <= until)
                .map(|(k, &v)| (k.clone(), v))
                .collect(),
        }
    }
}

impl<T: Eq + std::hash::Hash + Clone> Merge for GrowSet<T> {
    fn merge(&mut self, other: Self) {
        for (value, _remote_gen) in other.entries {
            // Assign a local generation to newly received entries so that
            // delta_since works correctly on this node after the merge.
            // Existing entries keep their local gen (first-insert wins).
            self.entries
                .entry(value)
                .or_insert_with(crate::generation::next_gen);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insert_is_idempotent() {
        let mut s: GrowSet<u32> = GrowSet::default();
        s.insert(1);
        let gen_after_first = *s.entries.get(&1).unwrap();
        s.insert(1); // duplicate — should not change local_gen
        assert_eq!(*s.entries.get(&1).unwrap(), gen_after_first);
        assert_eq!(s.len(), 1);
    }

    #[test]
    fn merge_union_correctness() {
        let mut a: GrowSet<u32> = GrowSet::default();
        let mut b: GrowSet<u32> = GrowSet::default();
        a.insert(1);
        a.insert(2);
        b.insert(2);
        b.insert(3);

        a.merge(b);
        assert!(a.contains(&1));
        assert!(a.contains(&2));
        assert!(a.contains(&3));
        assert_eq!(a.len(), 3);
    }

    #[test]
    fn delta_since_returns_only_new_entries() {
        let mut s: GrowSet<u32> = GrowSet::default();
        s.insert(1);
        let gen_after_1 = *s.entries.get(&1).unwrap();
        s.insert(2);

        let delta = s.delta_since(gen_after_1);
        assert!(!delta.contains(&1));
        assert!(delta.contains(&2));
    }
}
