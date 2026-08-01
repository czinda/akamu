use serde::{Deserialize, Serialize};

use crate::merge::Merge;

/// Last-Write-Wins Register. The value with the highest timestamp wins.
/// On ties, the lexicographically greater node_id wins.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LwwRegister<T> {
    #[serde(rename = "v")]
    value: Option<T>,
    #[serde(rename = "t")]
    timestamp: i64,
    #[serde(rename = "n")]
    node_id: String,
    /// Local-only write generation. Never serialised; defaults to 0 after reload.
    #[serde(skip, default)]
    local_gen: u64,
}

impl<T> Default for LwwRegister<T> {
    fn default() -> Self {
        Self {
            value: None,
            timestamp: 0,
            node_id: String::new(),
            local_gen: 0,
        }
    }
}

impl<T: Clone> LwwRegister<T> {
    /// Construct directly from a DB row, preserving the stored `local_gen`.
    /// Used only by `db::load_from_db`; does not advance `CRDT_GENERATION`.
    #[cfg(feature = "db")]
    pub(crate) fn load(
        value: Option<T>,
        timestamp: i64,
        node_id: impl Into<String>,
        local_gen: u64,
    ) -> Self {
        Self {
            value,
            timestamp,
            node_id: node_id.into(),
            local_gen,
        }
    }

    pub fn set(&mut self, value: T, timestamp: i64, node_id: &str) {
        if timestamp > self.timestamp
            || (timestamp == self.timestamp && node_id > self.node_id.as_str())
        {
            self.value = Some(value);
            self.timestamp = timestamp;
            node_id.clone_into(&mut self.node_id);
            self.local_gen = crate::generation::next_gen();
        }
    }

    pub const fn get(&self) -> Option<&T> {
        self.value.as_ref()
    }

    pub const fn timestamp(&self) -> i64 {
        self.timestamp
    }

    pub fn node_id_str(&self) -> &str {
        &self.node_id
    }

    /// Mark this register as deleted. Wins only if timestamp is strictly higher
    /// (or equal with a lexicographically greater node_id).
    pub fn remove(&mut self, timestamp: i64, node_id: &str) {
        if timestamp > self.timestamp
            || (timestamp == self.timestamp && node_id > self.node_id.as_str())
        {
            self.value = None;
            self.timestamp = timestamp;
            node_id.clone_into(&mut self.node_id);
            self.local_gen = crate::generation::next_gen();
        }
    }

    /// Returns `true` if this register holds a deletion tombstone
    /// (explicitly removed, not merely default-unset).
    pub const fn is_tombstone(&self) -> bool {
        self.value.is_none() && self.timestamp > 0
    }

    pub const fn local_gen(&self) -> u64 {
        self.local_gen
    }

    /// Alias for `local_gen()`, matching `OrMap`/`LwwMap`'s method name so
    /// callers generic over "any CRDT field" (see `crdt.rs`'s field macro)
    /// don't need a special case for single-value registers.
    pub const fn max_local_gen(&self) -> u64 {
        self.local_gen()
    }

    /// Returns `Some(self)` if this register was written after `gen`, else `None`.
    pub fn delta_since(&self, gen: u64) -> Option<Self> {
        if self.local_gen > gen {
            Some(self.clone())
        } else {
            None
        }
    }

    /// Returns `Some(self)` if written in `(since, until]`, else `None`.
    pub fn delta_range(&self, since: u64, until: u64) -> Option<Self> {
        if self.local_gen > since && self.local_gen <= until {
            Some(self.clone())
        } else {
            None
        }
    }
}

impl<T: Clone> Merge for LwwRegister<T> {
    fn merge(&mut self, other: Self) {
        // Skip default-initialised registers (value=None, timestamp=0).
        if other.value.is_none() && other.timestamp == 0 {
            return;
        }
        if let Some(v) = other.value {
            self.set(v, other.timestamp, &other.node_id);
        } else {
            self.remove(other.timestamp, &other.node_id);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_wins_on_higher_timestamp() {
        let mut reg: LwwRegister<u32> = LwwRegister::default();
        reg.set(1, 100, "node-a");
        reg.set(2, 200, "node-b");
        assert_eq!(reg.get(), Some(&2));
        assert_eq!(reg.timestamp(), 200);
    }

    #[test]
    fn tombstone_wins_on_equal_timestamp_with_greater_node_id() {
        let mut reg: LwwRegister<u32> = LwwRegister::default();
        reg.set(42, 100, "node-a");
        // node-z > node-a, so remove at same timestamp wins
        reg.remove(100, "node-z");
        assert_eq!(reg.get(), None);
        assert!(reg.is_tombstone());
    }

    #[test]
    fn delta_since_returns_none_when_not_changed() {
        let mut reg: LwwRegister<u32> = LwwRegister::default();
        reg.set(1, 100, "node-a");
        let gen = reg.local_gen;
        // No mutation since gen; delta should be None.
        assert!(reg.delta_since(gen).is_none());
        // Mutate and delta should be Some.
        reg.set(2, 200, "node-a");
        assert!(reg.delta_since(gen).is_some());
    }
}
