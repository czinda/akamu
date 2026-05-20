use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use crate::merge::Merge;

impl<T: Eq + std::hash::Hash> Default for GrowSet<T> {
    fn default() -> Self {
        Self {
            entries: HashSet::default(),
            local_gen: 0,
        }
    }
}

/// Grow-only set. Merge = union. No tombstones; use age-based archival externally.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrowSet<T: Eq + std::hash::Hash> {
    #[serde(rename = "e")]
    entries: HashSet<T>,
    #[serde(skip, default)]
    local_gen: u64,
}

impl<T: Eq + std::hash::Hash + Clone> GrowSet<T> {
    pub fn insert(&mut self, value: T) {
        if self.entries.insert(value) {
            self.local_gen = crate::generation::next_gen();
        }
    }

    pub fn contains(&self, value: &T) -> bool {
        self.entries.contains(value)
    }

    pub fn iter(&self) -> impl Iterator<Item = &T> {
        self.entries.iter()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Set `local_gen` directly (used by `db::load_from_db` to restore persisted gen).
    pub(crate) fn set_local_gen(&mut self, gen: u64) {
        self.local_gen = gen;
    }

    /// Insert a value directly from a DB row without advancing `CRDT_GENERATION`.
    pub(crate) fn load_entry(&mut self, value: T) {
        self.entries.insert(value);
    }

    /// Returns `Some(clone of self)` if written after `gen`, else `None`.
    pub fn delta_since(&self, gen: u64) -> Option<Self> {
        if self.local_gen > gen {
            Some(self.clone())
        } else {
            None
        }
    }
}

impl<T: Eq + std::hash::Hash + Clone> Merge for GrowSet<T> {
    fn merge(&mut self, other: Self) {
        let before = self.entries.len();
        self.entries.extend(other.entries);
        if self.entries.len() != before {
            self.local_gen = crate::generation::next_gen();
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
        let gen_after_first = s.local_gen;
        s.insert(1); // duplicate — should not change local_gen
        assert_eq!(s.local_gen, gen_after_first);
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
}
