//! akamuctl subcommand implementations.
//!
//! Each submodule maps to one top-level subcommand group.  All submodule
//! functions accept an [`AdminClient`](`crate::client::AdminClient`) and
//! delegate directly to the admin HTTP API.

pub mod account;
pub mod audit;
pub mod cert;
pub mod config_cmd;
pub mod cosigner;
pub mod eab;
pub mod operator;
pub mod server;
pub mod session;
