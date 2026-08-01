//! GSSAPI/SPNEGO (Kerberos) admin authentication.
//!
//! Validates the SPNEGO token via `gss_accept_sec_context`, extracts the
//! Kerberos principal, looks up `operators.gssapi_principal`, and issues a
//! session token.

use std::sync::Arc;

use axum::http::request::Parts;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;

use crate::audit::{AuditEvent, AuditEventType};
use crate::db;
use crate::state::{AdminAuthMethod, AppState, OperatorRole};

use super::session::create_session;
use super::{check_lockout, OperatorContext};

/// Optional GSSAPI out-token (base64-encoded) to be returned in a
/// `WWW-Authenticate: Negotiate <token>` response header.
#[derive(Clone)]
pub struct GssapiOutToken(pub String);

pub(super) async fn authenticate_gssapi(
    app: &Arc<AppState>,
    negotiate_token: &str,
    parts: &mut Parts,
) -> Result<OperatorContext, Response> {
    // Reject oversized tokens before allocating for the base64 decode.
    // 128 KiB decoded ≈ 175 KiB base64-encoded (4/3 ratio + padding).
    const MAX_NEGOTIATE_DECODED: usize = 128 * 1024;
    const MAX_NEGOTIATE_ENCODED: usize = MAX_NEGOTIATE_DECODED * 4 / 3 + 4;
    if negotiate_token.len() > MAX_NEGOTIATE_ENCODED {
        return Err((
            StatusCode::BAD_REQUEST,
            "Negotiate token exceeds size limit",
        )
            .into_response());
    }

    // Decode the base64 SPNEGO token.
    let token_bytes = URL_SAFE_NO_PAD
        .decode(negotiate_token)
        .or_else(|_| base64::engine::general_purpose::STANDARD.decode(negotiate_token))
        .map_err(|_| {
            (StatusCode::BAD_REQUEST, "invalid base64 in Negotiate token").into_response()
        })?;

    // Use the admin-specific GSSAPI credential if configured, otherwise fall
    // back to the server-wide credential (`app.gss_cred`).
    let gss_cred = app
        .admin_gss_cred
        .as_ref()
        .or(app.gss_cred.as_ref())
        .ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                "GSSAPI not configured for admin interface",
            )
                .into_response()
        })?;

    // Channel binding: read from request extensions (injected by TLS accept loop).
    let channel_bindings = parts
        .extensions
        .get::<crate::tls::channel_binding::TlsServerEndpointBinding>()
        .map(|b| b.0.clone());

    // Use spawn_blocking so the synchronous GSSAPI FFI call does not block the
    // tokio executor thread.  block_in_place would panic on the single-thread
    // runtime used by #[tokio::test].
    let cred = Arc::clone(gss_cred);
    let token_bytes_owned = token_bytes.to_vec();
    let channel_bindings_owned = channel_bindings.map(|b| b.to_vec());
    let result = tokio::task::spawn_blocking(move || {
        akamu_gssapi::accept_token(&cred, &token_bytes_owned, channel_bindings_owned.as_deref())
    })
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "GSSAPI spawn_blocking panicked");
        StatusCode::INTERNAL_SERVER_ERROR.into_response()
    })?;

    let (out_token, principal) = match result {
        Ok(akamu_gssapi::AcceptStep::Complete {
            out_token,
            principal,
        }) => (out_token, principal),
        Ok(akamu_gssapi::AcceptStep::Continue { out_token, ctx: _ }) => {
            // Mechanism needs another round-trip.  Return 401 with the continuation
            // token; the client will re-send and a fresh context will be started.
            let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&out_token);
            let mut resp = (StatusCode::UNAUTHORIZED, "").into_response();
            let negotiate = format!("Negotiate {b64}");
            match axum::http::HeaderValue::from_str(&negotiate) {
                Ok(hv) => {
                    resp.headers_mut()
                        .insert(axum::http::header::WWW_AUTHENTICATE, hv);
                }
                Err(e) => {
                    tracing::error!(error = %e, "failed to build GSSAPI continuation WWW-Authenticate header");
                }
            }
            return Err(resp);
        }
        Err(e) => {
            tracing::warn!(error = %e, "admin GSSAPI authentication failed");
            app.record_audit(
                AuditEvent::failure(AuditEventType::AdminLogin)
                    .with_detail("{\"method\":\"gssapi\",\"reason\":\"token rejected\"}"),
            )
            .await;
            return Err((StatusCode::FORBIDDEN, "GSSAPI authentication failed").into_response());
        }
    };

    // Look up the principal in the operators table.
    match db::operators::get_by_principal(&app.db, &principal).await {
        Ok(Some(op)) => {
            check_lockout(&op)?;
            let role = op.role.parse::<OperatorRole>().map_err(|_| {
                tracing::error!(role = %op.role, "operator has unknown role");
                StatusCode::INTERNAL_SERVER_ERROR.into_response()
            })?;
            // Successful auth — reset failure counter (FIA_AFL.1).
            if let Err(e) = db::operators::reset_failed(&app.db, op.id).await {
                tracing::warn!(error = %e, operator_id = op.id, "failed to reset auth failure counter");
            }
            let token = create_session(
                app,
                op.id,
                op.name.clone(),
                role,
                op.ca_id.clone(),
                AdminAuthMethod::Gssapi,
            )
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "session creation failed");
                StatusCode::INTERNAL_SERVER_ERROR.into_response()
            })?;
            let ts_str = crate::util::rfc3339_now();
            if let Err(e) = db::operators::update_last_seen(&app.db, op.id, &ts_str).await {
                tracing::warn!(error = %e, operator_id = op.id, "failed to update last_seen_at");
            }
            let session_prefix = token.get(..8).unwrap_or(&token);
            app.record_audit(
                AuditEvent::success(AuditEventType::AdminLogin)
                    .with_principal(&op.name)
                    .with_detail(
                        serde_json::json!({"method":"gssapi","session_prefix":session_prefix})
                            .to_string(),
                    ),
            )
            .await;
            if !out_token.is_empty() {
                let encoded = base64::engine::general_purpose::STANDARD.encode(&out_token);
                parts.extensions.insert(GssapiOutToken(encoded));
            }
            Ok(OperatorContext {
                operator_id: op.id,
                name: op.name,
                role,
                ca_id: op.ca_id,
                auth_method: AdminAuthMethod::Gssapi,
                session_token: Some(token),
            })
        }
        Ok(None) => {
            tracing::warn!(principal = %principal, "GSSAPI principal not registered as operator");
            app.record_audit(
                AuditEvent::failure(AuditEventType::AdminLogin)
                    .with_principal(&principal)
                    .with_detail("{\"method\":\"gssapi\",\"reason\":\"principal not registered\"}"),
            )
            .await;
            Err((
                StatusCode::FORBIDDEN,
                "Kerberos principal is not a registered operator",
            )
                .into_response())
        }
        Err(e) => {
            tracing::error!(error = %e, "operator DB lookup failed");
            Err(StatusCode::INTERNAL_SERVER_ERROR.into_response())
        }
    }
}
