//! Lightweight shared utilities for the akamu ecosystem.
//!
//! This crate provides a minimal-dependency subset of utilities that are needed
//! by both `akamu` (the main ACME server) and `akamu-cosigner` (the MTC cosigner
//! daemon).  It exists to break the `akamu-cosigner → akamu` full-library
//! dependency, which previously pulled in sqlx, DB migrations, gossip, CRDT, etc.
//! just to use a handful of utility functions.
//!
//! ## Modules
//!
//! - [`listen`] — `ListenTarget`, `parse_listen_target`, `remove_stale_socket`,
//!   `uds_marker_layer`, `UdsConnection`
//! - [`tls`] — `load_server_cert_chain`, `load_server_private_key`
//! - [`auth`] — `PeerClientCert`, `generate_token`, `find_session_token`
//! - [`util`] — `sha256_hex`, `read_password_from_file`

pub mod auth;
pub mod listen;
mod secret_buffer;
pub mod tls;
pub mod util;

pub use secret_buffer::SecretBuffer;
