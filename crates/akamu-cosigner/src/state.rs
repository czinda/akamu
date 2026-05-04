use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Instant;

use synta_certificate::BackendPrivateKey;

use crate::config::{CosignerRole, OperatorConfig};

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
    pub admin_sessions: Arc<tokio::sync::Mutex<HashMap<String, CosignerSession>>>,
    /// Admin session TTL in seconds.
    pub admin_session_ttl_secs: u64,
    /// Timestamp of server startup (for uptime reporting).
    pub startup_time: Instant,
    /// Signing statistics: (checkpoints_signed, last_checkpoint_at_unix).
    ///
    /// Held under a single lock so the counter and timestamp are always
    /// consistent with each other (no window where count incremented but
    /// timestamp not yet updated).
    pub signing_stats: Arc<Mutex<(u64, Option<i64>)>>,
}

pub struct CosignerSession {
    pub name: zeroize::Zeroizing<String>,
    pub role: CosignerRole,
    /// Position of the operator in `AppState::admin_operators` (0-based, cast to i64).
    pub operator_id: i64,
    pub created_at: Instant,
    pub last_active_at: Instant,
}
