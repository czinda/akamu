//! EAB-based admin web UI login (`POST /admin/session/eab`).

use std::sync::Arc;

use axum::http::StatusCode;
use axum::response::IntoResponse;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use serde_json::json;
use synta_certificate::HmacProvider as _;

use crate::audit::{AuditEvent, AuditEventType};
use crate::db;
use crate::state::{AdminAuthMethod, AppState, OperatorRole};

use super::check_lockout;
use super::session::create_session;

/// `POST /admin/session/eab`
///
/// Authenticate using an EAB kid + HMAC-SHA256 signature (web UI secondary login).
///
/// Request body:
/// ```json
/// {"kid": "…", "timestamp": 1234567890, "signature": "<base64url(HMAC-SHA256(kid.timestamp))>"}
/// ```
///
/// The message authenticated is `kid + "." + timestamp_as_decimal_string`.
/// Replay window: ±60 seconds; duplicate `(kid, timestamp)` pairs within that
/// window are rejected by an in-memory nonce cache.  The EAB key must have been
/// provisioned via the admin API (so that `created_by_operator_id` is known);
/// config-file keys are rejected with 403.
pub async fn post_session_eab(
    axum::extract::State(state): axum::extract::State<Arc<AppState>>,
    req: axum::extract::Request,
) -> axum::response::Response {
    use axum::extract::FromRequest as _;
    use synta_certificate::default_hmac_provider;

    if state.config.admin.is_none() {
        return StatusCode::NOT_FOUND.into_response();
    }

    let peer_ip = req
        .extensions()
        .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
        .map(|c| c.0.ip());

    let axum::extract::Json(payload) =
        match axum::extract::Json::<serde_json::Value>::from_request(req, &state).await {
            Ok(j) => j,
            Err(e) => {
                return (
                    StatusCode::BAD_REQUEST,
                    axum::Json(json!({"status": 400, "detail": e.to_string()})),
                )
                    .into_response()
            }
        };

    // ── Per-IP rate limiting (FIA_AFL.1 / FAU_ARP.1 self-DoS guard) ──────────
    if let (Some(ip_addr), Some(limiter)) = (peer_ip, state.admin_auth_limiter.as_ref()) {
        let rate_limit = state
            .config
            .admin
            .as_ref()
            .map(|a| a.auth_rate_limit)
            .unwrap_or(20);
        if let Err(attempts) = super::check_rate_limit(limiter, ip_addr, rate_limit).await {
            tracing::warn!(
                ip = %ip_addr,
                attempts,
                limit = rate_limit,
                "EAB session auth rate limit exceeded"
            );
            state
                .record_audit(
                    AuditEvent::failure(AuditEventType::AdminLogin)
                        .with_detail("{\"method\":\"eab\",\"reason\":\"rate limit exceeded\"}"),
                )
                .await;
            return (
                StatusCode::TOO_MANY_REQUESTS,
                axum::Json(json!({"status": 429, "detail": "authentication rate limit exceeded; try again later"})),
            )
                .into_response();
        }
    }

    let kid = match payload.get("kid").and_then(|v| v.as_str()) {
        Some(k) if !k.is_empty() => k.to_owned(),
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                axum::Json(json!({"status": 400, "detail": "kid is required"})),
            )
                .into_response();
        }
    };
    let timestamp = match payload.get("timestamp").and_then(|v| v.as_i64()) {
        Some(t) => t,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                axum::Json(json!({"status": 400, "detail": "timestamp (integer) is required"})),
            )
                .into_response();
        }
    };
    let signature_b64 = match payload.get("signature").and_then(|v| v.as_str()) {
        Some(s) if !s.is_empty() => s.to_owned(),
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                axum::Json(json!({"status": 400, "detail": "signature is required"})),
            )
                .into_response();
        }
    };

    // Replay window: ±60 seconds.
    let now = crate::util::unix_now();
    if (now - timestamp).abs() > 60 {
        return (
            StatusCode::UNAUTHORIZED,
            axum::Json(json!({
                "status": 401,
                "detail": "timestamp must be within 60 seconds of server time"
            })),
        )
            .into_response();
    }

    // Anti-replay: atomically check-and-reserve the (kid, timestamp) slot.
    // Inserting the sentinel inside the lock prevents a TOCTOU race where two
    // concurrent requests both pass the contains_key check before either commits.
    // On HMAC failure the slot is released so the client can retry; on all other
    // failures the slot remains reserved (those paths are not retryable anyway).
    const EAB_NONCE_CAP: usize = 10_000;
    let nonce_key = format!("{kid}.{timestamp}");
    if let Some(ref nonce_store) = state.eab_session_nonces {
        let mut store = nonce_store.lock().await;
        store.retain(|_, ts| (now - *ts).abs() <= 120);
        if store.contains_key(&nonce_key) {
            return (
                StatusCode::UNAUTHORIZED,
                axum::Json(json!({"status": 401, "detail": "replay detected"})),
            )
                .into_response();
        }
        if store.len() >= EAB_NONCE_CAP {
            let mut pairs: Vec<(String, i64)> = store.drain().collect();
            pairs.sort_unstable_by_key(|p| std::cmp::Reverse(p.1)); // newest first
            pairs.truncate(EAB_NONCE_CAP / 2);
            *store = pairs.into_iter().collect();
        }
        store.insert(nonce_key.clone(), now);
    }

    // Look up the EAB key.
    let eab_row = match db::eab::get_by_kid(&state.db, &kid).await {
        Ok(Some(r)) => r,
        Ok(None) => {
            state
                .record_audit(
                    AuditEvent::failure(AuditEventType::AdminLogin)
                        .with_detail("{\"method\":\"eab\",\"reason\":\"kid not found\"}"),
                )
                .await;
            return (
                StatusCode::UNAUTHORIZED,
                axum::Json(json!({"status": 401, "detail": "authentication failed"})),
            )
                .into_response();
        }
        Err(e) => {
            tracing::error!(error = %e, "post_session_eab: EAB key lookup failed");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    // Resolve operator before HMAC verify so failures can be counted toward lockout.
    enum OperatorSource {
        ById(i64),
        ByPrincipal(String),
    }
    let op_source = match (
        eab_row.created_by_operator_id,
        eab_row.bound_principal.clone(),
    ) {
        (Some(id), _) => OperatorSource::ById(id),
        (None, Some(principal)) => OperatorSource::ByPrincipal(principal),
        (None, None) => {
            state
                .record_audit(
                    AuditEvent::failure(AuditEventType::AdminLogin)
                        .with_detail("{\"method\":\"eab\",\"reason\":\"no operator owner\"}"),
                )
                .await;
            return (
                StatusCode::FORBIDDEN,
                "EAB key has no operator association and cannot be used for web UI login",
            )
                .into_response();
        }
    };

    // Look up the owning operator before HMAC verify so failures count toward lockout.
    let op = match op_source {
        OperatorSource::ById(id) => match db::operators::get_by_id(&state.db, id).await {
            Ok(Some(op)) => op,
            Ok(None) => {
                tracing::warn!(kid = %kid, operator_id = id, "EAB key owner operator not found");
                return (StatusCode::FORBIDDEN, "EAB key owner operator not found").into_response();
            }
            Err(e) => {
                tracing::error!(error = %e, "post_session_eab: operator lookup by id failed");
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
        },
        OperatorSource::ByPrincipal(ref principal) => {
            match db::operators::get_by_principal(&state.db, principal).await {
                Ok(Some(op)) => op,
                Ok(None) => {
                    tracing::warn!(
                        kid = %kid,
                        principal = %principal,
                        "EAB key bound principal has no matching operator"
                    );
                    return (
                        StatusCode::FORBIDDEN,
                        "EAB key principal is not registered as an operator",
                    )
                        .into_response();
                }
                Err(e) => {
                    tracing::error!(
                        error = %e,
                        "post_session_eab: operator lookup by principal failed"
                    );
                    return StatusCode::INTERNAL_SERVER_ERROR.into_response();
                }
            }
        }
    };

    // Check account status before HMAC computation so a locked-out operator cannot
    // probe HMAC key validity by observing response-code differences (timing oracle).
    if op.active == 0 {
        return (StatusCode::FORBIDDEN, "operator account is not active").into_response();
    }
    if let Err(resp) = check_lockout(&op) {
        return resp;
    }

    // Decode the HMAC key and the provided signature.
    let hmac_key = match URL_SAFE_NO_PAD.decode(&eab_row.hmac_key_b64u) {
        Ok(k) => k,
        Err(_) => {
            tracing::error!(kid = %kid, "EAB key: base64url decode failed");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };
    let sig_bytes = match URL_SAFE_NO_PAD
        .decode(&signature_b64)
        .or_else(|_| base64::engine::general_purpose::STANDARD.decode(&signature_b64))
    {
        Ok(b) => b,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                axum::Json(json!({"status": 400, "detail": "signature is not valid base64url"})),
            )
                .into_response();
        }
    };

    // The web UI EAB login always computes HMAC-SHA256 regardless of the key's
    // configured algorithm; reject non-sha256 keys early with a clear 400 rather
    // than letting the HMAC verify silently fail.
    let hash_alg = eab_row.alg.as_str();
    if hash_alg != "sha256" {
        if !matches!(hash_alg, "sha384" | "sha512") {
            tracing::error!(kid = %kid, alg = %hash_alg, "EAB key has unrecognised algorithm");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
        return (
            StatusCode::BAD_REQUEST,
            axum::Json(json!({"status": 400, "detail": "EAB web UI login only supports sha256 keys; this key uses a different algorithm"})),
        )
            .into_response();
    }

    // Message: "kid.timestamp"
    let message = format!("{kid}.{timestamp}");
    if default_hmac_provider()
        .hmac_verify(hash_alg, &hmac_key, message.as_bytes(), &sig_bytes)
        .is_err()
    {
        let admin_cfg = state.config.admin.as_ref();
        let max_attempts = admin_cfg.map(|a| a.max_failed_auth).unwrap_or(5);
        let lock_secs = admin_cfg.map(|a| a.lockout_duration_secs).unwrap_or(900) as i64;
        let lock_until = crate::util::unix_to_rfc3339(crate::util::unix_now() + lock_secs);
        if let Err(e) =
            db::operators::increment_failed(&state.db, op.id, max_attempts, &lock_until).await
        {
            tracing::warn!(error = %e, operator_id = op.id, "failed to record failed EAB attempt");
        }
        // Release the reserved nonce slot so the client can retry with a correct signature.
        if let Some(ref nonce_store) = state.eab_session_nonces {
            nonce_store.lock().await.remove(&nonce_key);
        }
        state
            .record_audit(
                AuditEvent::failure(AuditEventType::AdminLogin)
                    .with_detail("{\"method\":\"eab\",\"reason\":\"hmac verify failed\"}"),
            )
            .await;
        return (
            StatusCode::UNAUTHORIZED,
            axum::Json(json!({"status": 401, "detail": "authentication failed"})),
        )
            .into_response();
    }

    let role = match op.role.parse::<OperatorRole>() {
        Ok(r) => r,
        Err(_) => {
            tracing::error!(role = %op.role, "EAB operator has unknown role");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    let token = match create_session(
        &state,
        op.id,
        op.name.clone(),
        role,
        op.ca_id.clone(),
        AdminAuthMethod::Eab,
    )
    .await
    {
        Ok(t) => t,
        Err(e) => {
            tracing::error!(error = %e, "EAB session creation failed");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    let ts_str = crate::util::rfc3339_now();
    if let Err(e) = db::operators::reset_failed(&state.db, op.id).await {
        tracing::warn!(error = %e, operator_id = op.id, "failed to reset failed_attempts after EAB login");
    }
    if let Err(e) = db::operators::update_last_seen(&state.db, op.id, &ts_str).await {
        tracing::warn!(error = %e, operator_id = op.id, "failed to update last_seen_at");
    }
    let session_prefix = token.get(..8).unwrap_or(&token);
    state
        .record_audit(
            AuditEvent::success(AuditEventType::AdminLogin)
                .with_principal(&op.name)
                .with_detail(
                    serde_json::json!({
                        "method": "eab",
                        "kid": kid,
                        "session_prefix": session_prefix,
                    })
                    .to_string(),
                ),
        )
        .await;

    let admin = state.config.admin.as_ref();
    let ttl_secs = admin.map(|a| a.session_ttl_secs).unwrap_or(3600);
    let expires_unix = crate::util::unix_now() + ttl_secs as i64;
    let expires_at = crate::util::unix_to_rfc3339(expires_unix);

    let cookie =
        format!("session={token}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age={ttl_secs}");
    let mut resp = (
        StatusCode::OK,
        axum::Json(json!({
            "session_token": token,
            "role": role.as_str(),
            "operator": op.name,
            "expires_at": expires_at,
        })),
    )
        .into_response();
    if let Ok(hv) = axum::http::HeaderValue::from_str(&cookie) {
        resp.headers_mut().insert("Set-Cookie", hv);
    }
    resp
}
