//! GET /acme/eab — derive and return EAB credentials for the authenticated principal.
//!
//! # Authentication
//!
//! The caller must authenticate via one of:
//!
//! - **Proxy mode** — a trusted reverse proxy (configured in `[server].trusted_proxies`)
//!   sets `X-Remote-User` to the authenticated Kerberos principal after completing
//!   SPNEGO on behalf of the client.
//! - **Standalone GSSAPI** — the client presents `Authorization: Negotiate <base64>`
//!   directly; akamu validates the SPNEGO/Kerberos token using the keytab configured in
//!   `[server.gssapi]`.
//!
//! # Key Derivation (HKDF-SHA-256, RFC 5869)
//!
//! When `[server].eab_master_secret` is configured, the server derives deterministic EAB
//! credentials from `(master_secret, principal)` using HKDF-SHA-256 (RFC 5869,
//! extract-and-expand):
//!
//! ```text
//! kid      = base64url( HKDF-SHA256(IKM=master_secret, info="akamu-eab-v1-kid:<principal>", L=16) )
//! hmac_key = base64url( HKDF-SHA256(IKM=master_secret, info="akamu-eab-v1-key:<principal>", L=32) )
//! ```
//!
//! The same `(master_secret, principal)` pair always produces the same `(kid, hmac_key)`.
//! Credentials are stored in the `eab_keys` table on first request and returned on
//! subsequent requests; once the `kid` has been consumed by an account registration,
//! re-fetching returns HTTP 409.
//!
//! # EAB JWS Construction (RFC 8555 §7.3.4)
//!
//! The client uses the returned `kid` and `hmac_key` to construct an External Account
//! Binding JWS and includes it in the `externalAccountBinding` field of `newAccount`:
//!
//! ```text
//! protected = base64url({ "alg": "HS256", "kid": "<kid>", "url": "<newAccount URL>" })
//! payload   = base64url(<account public key JWK>)
//! signature = base64url( HMAC-SHA256(key=hmac_key, data="<protected>.<payload>") )
//! ```
//!
//! The server verifies the EAB JWS in `crate::jose::eab::verify_eab_jws` using the
//! stored `hmac_key_b64u` from the `eab_keys` table, then marks the `kid` as used
//! atomically within the `newAccount` transaction.
//!
//! # Response
//!
//! **With `eab_master_secret` configured** — `200 OK`:
//! ```json
//! { "principal": "host/client.example.com@REALM", "kid": "…", "hmac_key": "…", "alg": "HS256" }
//! ```
//!
//! **Without `eab_master_secret`** (stub / backward-compat) — `200 OK`:
//! ```json
//! { "principal": "host/client.example.com@REALM" }
//! ```
//!
//! **Key already consumed** — `409 Conflict`.

use std::sync::Arc;

use axum::extract::State;
use axum::response::IntoResponse;
use axum::Json;

use crate::db;
use crate::eab_derivation::derive_eab_credentials;
use crate::error::AcmeError;
use crate::extract::RemoteUser;
use crate::state::AppState;
use crate::util::unix_now;

pub async fn get_eab_identity(
    State(state): State<Arc<AppState>>,
    RemoteUser(principal): RemoteUser,
) -> impl IntoResponse {
    let Some(ref master) = state.eab_master_secret else {
        return Json(serde_json::json!({ "principal": principal })).into_response();
    };

    let (kid, hmac_key) = match derive_eab_credentials(master, &principal) {
        Ok(pair) => pair,
        Err(e) => return e.into_response(),
    };

    // Store if not present, binding the GSSAPI principal for web UI EAB login.
    if let Err(e) = db::eab::insert_if_absent(
        &state.db,
        &kid,
        &hmac_key,
        unix_now(),
        Some(&principal),
        "sha256",
    )
    .await
    {
        return e.into_response();
    }

    // Check if already consumed by a prior account registration.
    match db::eab::get_by_kid(&state.db, &kid).await {
        Err(e) => e.into_response(),
        Ok(None) => AcmeError::Internal("EAB key vanished after insert".into()).into_response(),
        Ok(Some(row)) if row.used_at.is_some() => AcmeError::Conflict(format!(
            "EAB credentials for '{principal}' have already been consumed; \
             contact your CA administrator to reset them"
        ))
        .into_response(),
        Ok(Some(_)) => Json(serde_json::json!({
            "principal": principal,
            "kid":       kid,
            "hmac_key":  hmac_key,
            "alg":       "HS256",
        }))
        .into_response(),
    }
}
