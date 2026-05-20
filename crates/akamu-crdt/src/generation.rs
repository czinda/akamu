use std::sync::atomic::{AtomicU64, Ordering};

pub static CRDT_GENERATION: AtomicU64 = AtomicU64::new(0);

pub fn next_gen() -> u64 {
    CRDT_GENERATION.fetch_add(1, Ordering::Relaxed) + 1
}
