use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Instant;

use synta_certificate::BackendPrivateKey;

use crate::config::OperatorConfig;

/// Shared application state threaded through all Axum handlers.
pub struct AppState {
    /// The cosigner signing key (distinct from TLS key).
    pub signing_key: BackendPrivateKey,
    /// Hash algorithm name passed to `signing_key.as_signer()`.
    pub hash_alg: String,
    /// DER-encoded `AlgorithmIdentifier` for the signing algorithm.
    ///
    /// Decoded once per request (cheap) to avoid lifetime fights
    /// when embedding into `SubtreeSignature<'_>`.
    pub sig_alg_der: Vec<u8>,
    /// DER-encoded `AlgorithmIdentifier` for the cosigner's hash algorithm.
    ///
    /// Extracted from the cosigner-id cert's `tbs_certificate.signature` field.
    /// Decoded per request to build `CosignerID.hash_algorithm`.
    pub cosigner_hash_alg_der: Vec<u8>,
    /// DER-encoded `SubjectPublicKeyInfo` of the cosigner's signing key.
    ///
    /// Decoded per request to build `CosignerID.public_key`.
    pub cosigner_spki_der: Vec<u8>,
    /// Token store for ACME http-01 challenges.
    ///
    /// Populated during ACME bootstrap; read by `GET /.well-known/acme-challenge/:token`.
    pub challenge_tokens: Arc<RwLock<HashMap<String, String>>>,
    /// Registered operators (from `[[admin.operators]]` in config).
    pub admin_operators: Vec<OperatorConfig>,
    /// In-memory admin session store (token → session).
    pub admin_sessions: Arc<Mutex<HashMap<String, CosignerSession>>>,
    /// Admin session TTL in seconds.
    pub admin_session_ttl_secs: u64,
    /// Timestamp of server startup (for uptime reporting).
    pub startup_time: Instant,
    /// Counter for checkpoints signed (for GET /admin/stats).
    pub checkpoints_signed: Arc<std::sync::atomic::AtomicU64>,
    /// Unix timestamp of last checkpoint signature.
    pub last_checkpoint_at: Arc<Mutex<Option<i64>>>,
}

pub struct CosignerSession {
    pub name: String,
    pub role: String,
    pub created_at: Instant,
    pub last_active_at: Instant,
}
