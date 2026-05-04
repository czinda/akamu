//! Axum route assembly and shared request-handling utilities.

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::Request;
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, head, post};
use axum::{Json, Router};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use tower_http::trace::TraceLayer;

use crate::db;
use crate::error::AcmeError;
use crate::jose::jws::{JwsFlattened, JwsKeyRef, JwsProtectedHeader};
use crate::state::{AppState, CachedAccount};

pub mod account;
pub mod admin;
pub mod authz;
pub mod certificate;
pub mod challenge;
pub mod crl;
pub mod directory;
pub mod eab_identity;
pub mod finalize;
pub mod key_change;
pub mod mtc;
pub mod nonce;
pub mod ocsp;
pub mod order;
pub mod renewal_info;
pub mod revoke;
pub mod star_cert;

/// Middleware: reject ACME requests when the audit store is full and the
/// overflow policy is `halt` (FAU_STG.4).  Admin routes bypass this check
/// so operators can query status and resolve the condition.
async fn halt_check(
    axum::extract::State(state): axum::extract::State<Arc<AppState>>,
    req: Request,
    next: Next,
) -> Response {
    use std::sync::atomic::Ordering;
    if state.audit.should_halt.load(Ordering::Acquire) {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            [("Retry-After", "300")],
            "audit storage full — server halted per FAU_STG.4 policy",
        )
            .into_response();
    }
    next.run(req).await
}

/// Build the main axum router with all ACME endpoints.
pub fn build_router(state: Arc<AppState>) -> Router {
    // max_body_bytes = 0 means "use the 2 MiB default".
    // Never disable the limit entirely — that would allow unbounded request bodies.
    let max_body = state.config.server.max_body_bytes;

    // ACME routes: subject to FAU_STG.4 halt_check middleware.
    let acme_router = Router::new()
        // Directory
        .route("/acme/directory", get(directory::get_directory))
        // Nonces
        .route("/acme/new-nonce", head(nonce::new_nonce_head))
        .route("/acme/new-nonce", get(nonce::new_nonce_get))
        // Accounts
        .route("/acme/new-account", post(account::new_account))
        .route("/acme/account/{id}", post(account::update_account))
        // Orders
        .route("/acme/new-order", post(order::new_order))
        .route("/acme/order/{id}", post(order::get_order))
        .route("/acme/order/{id}/finalize", post(finalize::finalize_order))
        // Authorizations
        .route("/acme/new-authz", post(authz::new_authz))
        .route("/acme/authz/{id}", post(authz::get_authz))
        // Challenges
        .route(
            "/acme/chall/{authz_id}/{type}",
            post(challenge::respond_challenge),
        )
        // Certificates
        .route(
            "/acme/cert/{id}",
            get(certificate::download_cert).post(certificate::download_cert_post),
        )
        // STAR rolling certificate URL (RFC 8739 §3.3)
        .route(
            "/acme/cert/star/{order_id}",
            get(star_cert::star_cert_get).post(star_cert::star_cert_post),
        )
        // Revocation
        .route("/acme/revoke-cert", post(revoke::revoke_cert))
        // Key change
        .route("/acme/key-change", post(key_change::key_change))
        // Renewal Info (RFC 9773 ARI)
        .route(
            "/acme/renewal-info/{cert_id}",
            get(renewal_info::get_renewal_info),
        )
        // MTC log state (read-only; 404 when MTC is disabled)
        .route("/acme/mtc/tree-size", get(mtc::get_tree_size))
        .route("/acme/mtc/root", get(mtc::get_root))
        .route(
            "/acme/mtc/inclusion-proof/{cert_id}",
            get(mtc::get_inclusion_proof),
        )
        .route(
            "/acme/mtc/cert/{cert_id}/standalone",
            get(mtc::get_standalone),
        )
        .route("/acme/mtc/landmarks", get(mtc::get_landmarks))
        .route(
            "/acme/mtc/landmarks/{seq}/cert",
            get(mtc::get_landmark_cert),
        )
        // C2SP tlog-tiles API
        .route("/acme/mtc/tlog/checkpoint", get(mtc::get_tlog_checkpoint))
        .route("/acme/mtc/tlog/cosignature", get(mtc::get_tlog_cosignature))
        .route("/acme/mtc/tlog/tile/{*path}", get(mtc::get_tlog_tile))
        // EAB identity — returns authenticated principal (proxy header or GSSAPI)
        .route("/acme/eab", get(eab_identity::get_eab_identity))
        .layer(axum::middleware::from_fn_with_state(
            Arc::clone(&state),
            halt_check,
        ));

    // Non-ACME routes: CRL/OCSP (public, read-only).  Admin routes are served
    // on the dedicated admin listener via `build_admin_router`; they are not
    // registered here so the main ACME listener never handles /admin/* paths.
    let other_router = Router::new()
        // CRL (RFC 5280) — public, no auth required
        .route("/ca/crl", get(crl::get_crl))
        // OCSP (RFC 6960) — public, no auth required
        .route("/ca/ocsp", post(ocsp::post_ocsp))
        .route("/ca/ocsp/{request}", get(ocsp::get_ocsp));

    Router::new()
        .merge(acme_router)
        .merge(other_router)
        .layer(axum::extract::DefaultBodyLimit::max(if max_body > 0 {
            max_body
        } else {
            2 * 1024 * 1024
        }))
        .layer(TraceLayer::new_for_http().on_request(()).on_eos(()))
        .with_state(state)
}

/// Build the admin-only axum router served on the dedicated admin listener.
///
/// Admin routes intentionally bypass `halt_check` so operators can query status
/// and resolve audit-overflow conditions even when the ACME listener is halted.
/// Full operator authentication (mTLS cert + session token + GSSAPI) is enforced
/// by the `OperatorContext` extractor in `crate::admin::auth`.
pub fn build_admin_router(state: Arc<AppState>) -> Router {
    let max_body = state.config.server.max_body_bytes;

    Router::new()
        .route(
            "/admin/session",
            post(crate::admin::auth::post_session).delete(crate::admin::auth::delete_session),
        )
        .route(
            "/admin/operators",
            axum::routing::get(admin::get_operators).post(admin::post_operators),
        )
        .route(
            "/admin/account/{id}/profile-grants",
            axum::routing::get(admin::get_account_profile_grants)
                .put(admin::put_account_profile_grants)
                .delete(admin::delete_account_profile_grants),
        )
        .route(
            "/admin/eab",
            axum::routing::get(admin::get_eab).post(admin::post_eab),
        )
        .route(
            "/admin/eab/{kid}",
            axum::routing::get(admin::get_eab_key).delete(admin::delete_eab),
        )
        .route("/admin/audit", axum::routing::get(admin::get_audit))
        .route("/admin/certs", axum::routing::get(admin::get_certs))
        .route("/admin/certs/{id}", axum::routing::get(admin::get_cert))
        .route(
            "/admin/certs/{id}/download",
            axum::routing::get(admin::get_cert_download),
        )
        .route(
            "/admin/profiles",
            axum::routing::get(admin::get_profiles).post(admin::post_profiles),
        )
        .route(
            "/admin/profiles/{id}",
            axum::routing::put(admin::put_profile).delete(admin::delete_profile),
        )
        .route("/admin/accounts", axum::routing::get(admin::get_accounts))
        .route(
            "/admin/account/{id}",
            axum::routing::get(admin::get_account),
        )
        .route(
            "/admin/account/{id}/deactivate",
            post(admin::post_account_deactivate),
        )
        .route(
            "/admin/operators/{id}",
            axum::routing::get(admin::get_operator)
                .put(admin::put_operator)
                .patch(admin::patch_operator),
        )
        .route(
            "/admin/operators/{id}/unlock",
            post(admin::unlock_operator),
        )
        .route("/admin/orders", axum::routing::get(admin::get_orders))
        .route("/admin/orders/{id}", axum::routing::get(admin::get_order))
        .route("/admin/config", axum::routing::get(admin::get_config))
        .route("/admin/crl/force", post(admin::post_crl_force))
        .route("/admin/revoke", post(admin::post_revoke))
        .route("/admin/stats", axum::routing::get(admin::get_stats))
        .layer(axum::extract::DefaultBodyLimit::max(if max_body > 0 {
            max_body
        } else {
            2 * 1024 * 1024
        }))
        .layer(TraceLayer::new_for_http().on_request(()).on_eos(()))
        .with_state(state)
}

// ── Shared request helpers ────────────────────────────────────────────────────

/// Result of JWS parsing and verification.
pub(crate) struct JwsContext {
    pub header: JwsProtectedHeader,
    /// Decoded payload bytes (empty for POST-as-GET).
    pub payload: Vec<u8>,
    /// SPKI DER of the key used to sign the request.
    pub spki_der: Vec<u8>,
    /// Account ID from `kid`, or `None` for new-account with `jwk`.
    pub account_id: Option<String>,
    /// JWK thumbprint for the signing account (`None` for `jwk`-based requests).
    pub jwk_thumbprint: Option<String>,
    /// Fresh nonce to include in the response Replay-Nonce header.
    /// Generated and stored atomically with the consumed incoming nonce.
    pub next_nonce: String,
}

/// Parse, verify nonce, and verify signature for an ACME POST request.
///
/// `expected_url` must be the full URL the client should have signed, e.g.
/// `"https://acme.example.com/acme/new-account"`.
pub(crate) async fn parse_jws(
    state: &AppState,
    body: Bytes,
    expected_url: &str,
) -> Result<JwsContext, AcmeError> {
    // Parse the JWS flattened JSON body.
    let jws: JwsFlattened = serde_json::from_slice(&body)
        .map_err(|e| AcmeError::BadRequest(format!("JWS parse: {e}")))?;

    let header = jws.decode_header()?;

    // Verify the URL claim.
    if header.url != expected_url {
        return Err(AcmeError::Unauthorized(format!(
            "JWS url mismatch: got '{}', expected '{}'",
            header.url, expected_url
        )));
    }

    // Generate the response nonce and consume the incoming nonce atomically.
    // Uses the in-memory NonceBucket to avoid 4 DB round-trips per JWS call
    // (BEGIN IMMEDIATE + DELETE + INSERT + COMMIT).
    let mut nonce_bytes = [0u8; 16];
    getrandom::getrandom(&mut nonce_bytes)
        .map_err(|e| AcmeError::Internal(format!("nonce rng: {e}")))?;
    let next_nonce = URL_SAFE_NO_PAD.encode(nonce_bytes);
    if !state.nonces.consume_and_insert(&header.nonce, &next_nonce) {
        return Err(AcmeError::BadNonce);
    }

    // Resolve the signing key and account ID.
    let (spki_der, account_id, jwk_thumbprint) = match &header.key_ref {
        JwsKeyRef::Jwk { jwk } => {
            let spki = jwk.to_spki_der()?;
            (spki, None, None)
        }
        JwsKeyRef::Kid { kid } => {
            let id = crate::jose::kid::account_id_from_kid(&state.config.base_url, kid)?;
            // Try the in-memory account cache first to avoid a DB round-trip.
            let cached = state
                .spki_cache
                .read()
                .unwrap_or_else(|e| e.into_inner())
                .get(&id)
                .cloned();
            let cached_account = if let Some(acc) = cached {
                if acc.status != "valid" {
                    return Err(AcmeError::Unauthorized(format!(
                        "account status is '{}'",
                        acc.status
                    )));
                }
                acc
            } else {
                let account = db::accounts::get_by_id(&state.db, &id)
                    .await?
                    .ok_or_else(|| AcmeError::Unauthorized("account not found".into()))?;
                if account.status != "valid" {
                    return Err(AcmeError::Unauthorized(format!(
                        "account status is '{}'",
                        account.status
                    )));
                }
                let entry = CachedAccount {
                    spki_der: account.public_key,
                    jwk_thumbprint: account.jwk_thumbprint,
                    status: account.status,
                };
                state
                    .spki_cache
                    .write()
                    .unwrap_or_else(|e| e.into_inner())
                    .insert(id.clone(), entry.clone());
                entry
            };
            let thumb = cached_account.jwk_thumbprint.clone();
            (cached_account.spki_der, Some(id), Some(thumb))
        }
    };

    // Verify the JWS signature; emit AuthJwsOk or AuthJwsFail audit event.
    if let Err(e) = jws.verify(&spki_der) {
        let principal = account_id
            .as_deref()
            .map(|id| format!("acme:{id}"))
            .unwrap_or_else(|| "acme:unknown".to_string());
        state
            .record_audit(
                crate::audit::AuditEvent::failure(crate::audit::AuditEventType::AuthJwsFail)
                    .with_principal(&principal),
            )
            .await;
        return Err(e.into());
    }
    state
        .record_audit(
            crate::audit::AuditEvent::success(crate::audit::AuditEventType::AuthJwsOk)
                .with_principal(account_id.as_deref().unwrap_or("new-account")),
        )
        .await;

    let payload = jws.decode_payload()?;
    Ok(JwsContext {
        header,
        payload,
        spki_der,
        account_id,
        jwk_thumbprint,
        next_nonce,
    })
}

// ── Response helpers ──────────────────────────────────────────────────────────

/// Generate a fresh anti-replay nonce, store it in the in-memory bucket, and return it.
pub(crate) fn new_nonce(state: &AppState) -> Result<String, AcmeError> {
    let mut bytes = [0u8; 16];
    getrandom::getrandom(&mut bytes).map_err(|e| AcmeError::Internal(format!("nonce rng: {e}")))?;
    let nonce = URL_SAFE_NO_PAD.encode(bytes);
    state.nonces.insert(&nonce);
    Ok(nonce)
}

/// Build standard ACME response headers using a pre-generated nonce.
///
/// The nonce was already consumed and the new one inserted atomically in
/// `parse_jws` via `state.nonces.consume_and_insert`, so no DB call is needed here.
pub(crate) fn acme_headers(state: &AppState, nonce: &str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        HeaderName::from_static("replay-nonce"),
        HeaderValue::from_str(nonce).unwrap(),
    );
    // Use the precomputed Link header value — avoids format!() + from_str() per response.
    headers.insert(axum::http::header::LINK, (*state.link_header).clone());
    headers
}

/// Wrap a JSON response with ACME headers.
///
/// `body` can be any type implementing `Serialize` — both `serde_json::Value`
/// and typed response structs (e.g. `OrderJson`) are accepted.
///
/// `nonce` must be a fresh nonce already inserted into the DB (use `ctx.next_nonce`
/// from `parse_jws`, or call `new_nonce` for endpoints that do not use `parse_jws`).
pub(crate) fn json_response<T: serde::Serialize>(
    state: &AppState,
    status: StatusCode,
    body: T,
    nonce: &str,
) -> Result<Response, AcmeError> {
    let headers = acme_headers(state, nonce);
    let mut resp = (status, Json(body)).into_response();
    resp.headers_mut().extend(headers);
    resp.headers_mut().insert(
        axum::http::header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    Ok(resp)
}

/// Parse the payload as JSON, return an error if the payload is empty
/// (POST-as-GET is not allowed here).
pub(crate) fn require_payload<T: serde::de::DeserializeOwned>(
    payload: &[u8],
    ctx: &str,
) -> Result<T, AcmeError> {
    if payload.is_empty() {
        return Err(AcmeError::BadRequest(format!(
            "{ctx}: payload is required (not POST-as-GET)"
        )));
    }
    serde_json::from_slice(payload).map_err(|e| AcmeError::BadRequest(format!("{ctx} JSON: {e}")))
}

pub(crate) use crate::util::unix_now;

/// Format a Unix timestamp as an RFC 3339 string (`YYYY-MM-DDTHH:MM:SSZ`).
///
/// Uses `synta::GeneralizedTime::from_unix` for the Gregorian decomposition.
pub(crate) fn fmt_time(unix: i64) -> String {
    let gt = synta::GeneralizedTime::from_unix(unix)
        .unwrap_or_else(|| synta::GeneralizedTime::from_unix(0).unwrap());
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        gt.year, gt.month, gt.day, gt.hour, gt.minute, gt.second
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fmt_time_known_epoch() {
        // Unix epoch = 1970-01-01T00:00:00Z
        assert_eq!(fmt_time(0), "1970-01-01T00:00:00Z");
    }

    #[test]
    fn fmt_time_known_date() {
        // 2024-01-01 00:00:00 UTC = 1704067200
        assert_eq!(fmt_time(1_704_067_200), "2024-01-01T00:00:00Z");
    }

    #[test]
    fn unix_now_is_positive() {
        let t = unix_now();
        assert!(t > 0, "unix_now() should return a positive Unix timestamp");
    }

    #[test]
    fn require_payload_empty_returns_error() {
        let result: Result<serde_json::Value, _> = require_payload(b"", "test-ctx");
        assert!(result.is_err());
        match result.unwrap_err() {
            AcmeError::BadRequest(msg) => {
                assert!(msg.contains("test-ctx"));
                assert!(msg.contains("required"));
            }
            other => panic!("expected BadRequest, got {other:?}"),
        }
    }

    #[test]
    fn require_payload_invalid_json_returns_error() {
        let result: Result<serde_json::Value, _> = require_payload(b"not json", "test-ctx");
        assert!(result.is_err());
        match result.unwrap_err() {
            AcmeError::BadRequest(msg) => assert!(msg.contains("test-ctx")),
            other => panic!("expected BadRequest, got {other:?}"),
        }
    }

    #[test]
    fn require_payload_valid_json() {
        let result: Result<serde_json::Value, _> =
            require_payload(b"{\"key\":\"value\"}", "test-ctx");
        assert!(result.is_ok());
    }
}
