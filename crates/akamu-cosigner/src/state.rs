use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use synta_certificate::BackendPrivateKey;
use synta_mtc::types::CosignerID;

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
    /// `CosignerID` extracted from the cosigner-id certificate at startup.
    pub cosigner_id: CosignerID,
    /// Token store for ACME http-01 challenges.
    ///
    /// Populated during ACME bootstrap; read by `GET /.well-known/acme-challenge/:token`.
    pub challenge_tokens: Arc<RwLock<HashMap<String, String>>>,
}
