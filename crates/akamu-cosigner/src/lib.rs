//! akamu-cosigner library — shared types and handlers used by the daemon binary
//! and integration tests alike.

pub mod admin;
pub mod config;
pub mod error;
pub mod key;
pub mod routes;
pub mod state;
pub mod util;

// Private to the library; only the binary's `main.rs` uses these via `crate::`.
pub mod acme;
