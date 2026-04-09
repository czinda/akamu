//! Shared application state threaded through axum handlers via `Arc<AppState>`.

use std::sync::Arc;

use synta_mtc::crypto::HashAlgorithm;
use synta_certificate::BackendPrivateKey;
use tokio_rusqlite::Connection;

use crate::config::Config;
use crate::mtc::log::SharedLog;

/// Top-level application state cloned into every axum handler.
#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub db: Arc<Connection>,
    pub ca: Arc<CaState>,
    pub mtc: Arc<MtcState>,
}

/// CA key material and issuance policy.
pub struct CaState {
    /// CA private key (used for signing certificates and CRLs).
    pub key: BackendPrivateKey,
    /// DER-encoded CA certificate.
    pub cert_der: Vec<u8>,
    /// Hash algorithm string, e.g. `"sha256"`.
    pub hash_alg: String,
    /// Default validity period for issued end-entity certificates.
    pub validity_days: u32,
    /// Optional CRL distribution point URL.
    pub crl_url: Option<String>,
    /// Optional OCSP responder URL.
    pub ocsp_url: Option<String>,
}

/// MTC transparency log state.
pub struct MtcState {
    /// Shared, mutex-guarded disk-backed log.  `None` when MTC is disabled.
    pub log: Option<SharedLog>,
    /// Hash algorithm used for log leaf hashing.
    pub algorithm: HashAlgorithm,
}

impl MtcState {
    /// Return `true` when the MTC log is enabled and ready.
    pub fn is_enabled(&self) -> bool {
        self.log.is_some()
    }
}
