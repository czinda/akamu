//! Session token generation, storage, and lookup for admin authentication.
//!
//! Session tokens are 32 random bytes, hex-encoded (64 chars), stored in
//! `AppState::admin_sessions` with an `Instant` timestamp. TTL is
//! `[admin].session_ttl_secs` (default 1 h). Expired sessions are swept on
//! every lookup.

use std::time::{Duration, Instant};

use crate::state::{AdminAuthMethod, AdminSession, AppState, OperatorRole};

/// Generate a cryptographically random 32-byte hex-encoded session token.
pub fn generate_token() -> Result<String, String> {
    let mut bytes = [0u8; 32];
    native_ossl::rand::Rand::fill(&mut bytes).map_err(|e| format!("getrandom: {e}"))?;
    Ok(native_ossl::util::hex_encode(bytes))
}

/// Constant-time lookup of `token` among the keys of `map`.
///
/// Uses `subtle::ConstantTimeEq` to prevent timing side-channels. Residual:
/// `find()` short-circuits on the first match, leaking the map position.
/// HashMap iteration order is randomised by the std hasher; this residual is
/// accepted.
pub fn find_session_token<V>(
    map: &std::collections::HashMap<String, V>,
    token: &str,
) -> Option<String> {
    use subtle::ConstantTimeEq as _;
    let token_bytes = token.as_bytes();
    map.keys()
        .find(|k| {
            let kb = k.as_bytes();
            kb.len() == token_bytes.len() && kb.ct_eq(token_bytes).into()
        })
        .cloned()
}

/// Create a new session for `operator_id` and return the token.
pub async fn create_session(
    state: &AppState,
    operator_id: i64,
    name: String,
    role: OperatorRole,
    ca_id: String,
    auth_method: AdminAuthMethod,
) -> Result<String, crate::error::AcmeError> {
    let token = generate_token().map_err(crate::error::AcmeError::Internal)?;
    let session = AdminSession {
        operator_id,
        name: akamu_util::SecretBuffer::from_string(name),
        role,
        ca_id,
        created_at: Instant::now(),
        last_active_at: Instant::now(),
        auth_method,
    };
    let store = state.admin_sessions.as_ref().ok_or_else(|| {
        crate::error::AcmeError::Internal("admin sessions store not initialised".into())
    })?;
    let mut map = store.lock().await;
    // Sweep expired entries while we hold the lock.
    let ttl = Duration::from_secs(
        state
            .config
            .admin
            .as_ref()
            .map(|a| a.session_ttl_secs)
            .unwrap_or(3600),
    );
    map.retain(|_, s| s.last_active_at.elapsed() < ttl);
    // Evict oldest session if cap reached (prevents unbounded growth under
    // adversarial mTLS or GSSAPI authentication floods).
    const SESSION_CAP: usize = 1000;
    if map.len() >= SESSION_CAP {
        if let Some(oldest_key) = map
            .iter()
            .min_by_key(|(_, s)| s.last_active_at)
            .map(|(k, _)| k.clone())
        {
            map.remove(&oldest_key);
        }
    }
    map.insert(token.clone(), session);
    Ok(token)
}

/// Result of a session token lookup.
pub(super) enum SessionLookup {
    /// Session is valid and active; contains operator details.
    Active(i64, String, OperatorRole, String, AdminAuthMethod),
    /// Session exists but is locked due to inactivity (FTA_SSL_EXT.1).
    Locked,
    /// Token is absent, expired, or invalid.
    NotFound,
}

/// Look up a session by token.  Sweeps expired entries; updates `last_active_at`
/// on a hit.  Returns [`SessionLookup::Locked`] when the session is idle longer
/// than `session_lock_secs` but has not yet reached `session_ttl_secs`.
pub(super) async fn lookup_session(state: &AppState, token: &str) -> SessionLookup {
    let store = match state.admin_sessions.as_ref() {
        Some(s) => s,
        None => return SessionLookup::NotFound,
    };
    let admin = state.config.admin.as_ref();
    let ttl = Duration::from_secs(admin.map(|a| a.session_ttl_secs).unwrap_or(3600));
    let lock_secs = admin.map(|a| a.session_lock_secs).unwrap_or(900);
    let lock_threshold = Duration::from_secs(lock_secs);

    let mut map = store.lock().await;
    map.retain(|_, s| s.last_active_at.elapsed() < ttl);
    let key = match find_session_token(&map, token) {
        Some(k) => k,
        None => return SessionLookup::NotFound,
    };
    let session = match map.get_mut(&key) {
        Some(s) => s,
        None => return SessionLookup::NotFound,
    };

    if session.last_active_at.elapsed() >= lock_threshold {
        return SessionLookup::Locked;
    }

    session.last_active_at = Instant::now();
    SessionLookup::Active(
        session.operator_id,
        session.name.to_string_lossy(),
        session.role,
        session.ca_id.clone(),
        session.auth_method,
    )
}

/// Remove a session token from the store.  No-op if the token is unknown.
pub async fn invalidate_session(state: &AppState, token: &str) {
    if let Some(ref store) = state.admin_sessions {
        store.lock().await.remove(token);
    }
}
