use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Instant;

use synta::ObjectIdentifier;
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
    /// Parsed `TrustAnchorID` OID for this cosigner.
    ///
    /// Per draft-ietf-plants-merkle-tree-certs-04 §4.1, `CosignerID` is a
    /// `TrustAnchorID ::= OBJECT IDENTIFIER`.  Cloned per request to build
    /// `SubtreeSignature.cosigner`.  `ObjectIdentifier` is `Clone` so no DER
    /// round-trip is needed on the hot signing path.
    pub cosigner_oid: ObjectIdentifier,
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
    ///
    /// `std::sync::Mutex` is intentional: the critical section is two assignments
    /// with no `.await` points, so blocking the executor thread for a microsecond
    /// is acceptable.  Do NOT hold this lock across an `.await`.
    pub signing_stats: Arc<Mutex<(u64, Option<i64>)>>,
}

/// An active admin session in the cosigner session store.
///
/// Stores operator identity and timing data for TTL enforcement and for
/// audit event attribution.
pub struct CosignerSession {
    /// Operator name, zeroed on drop via `OPENSSL_cleanse` (FDP_RIP.1).
    pub name: akamu_util::SecretBuffer,
    /// Role governing which admin endpoints this session may access.
    pub role: CosignerRole,
    /// Position of the operator in `AppState::admin_operators` (0-based, cast to i64).
    pub operator_id: i64,
    /// When this session token was issued.
    pub created_at: Instant,
    /// Updated on every authenticated request; TTL is measured from this.
    pub last_active_at: Instant,
}
