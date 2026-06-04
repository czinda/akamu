//! Admin statistics and configuration handlers.

use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;

use crate::admin::auth::OperatorContext;
use crate::db;
use crate::require_role;
use crate::state::AppState;

/// `GET /admin/stats`
///
/// Returns live server statistics.  Requires: any role.
pub async fn get_stats(operator: OperatorContext, State(state): State<Arc<AppState>>) -> Response {
    require_role!(
        operator,
        state,
        Administrator | CaOperations | CaRa | Auditor
    );

    let uptime_secs = state.startup_time.elapsed().as_secs();

    let ca_scope = operator.ca_scope();

    let counts = match db::stats::summary(&state.db, ca_scope).await {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error = %e, "stats DB query failed");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    let server_version = env!("CARGO_PKG_VERSION");

    (
        StatusCode::OK,
        Json(json!({
            "server_version": server_version,
            "uptime_secs": uptime_secs,
            "ca_scope": ca_scope,
            "accounts": {
                "total": counts.account_total,
                "active": counts.account_active,
            },
            "certs": {
                "total": counts.cert_total,
                "active": counts.cert_active,
                "revoked": counts.cert_revoked,
            },
            "eab_keys": {
                "total": counts.eab_total,
                "used": counts.eab_used,
                "bound": counts.eab_bound,
                "free": counts.eab_total - counts.eab_used - counts.eab_bound,
            },
            "audit_events": {
                "since_startup": state.audit.event_count.load(std::sync::atomic::Ordering::Relaxed),
            },
        })),
    )
        .into_response()
}

/// `GET /admin/config`
///
/// Show redacted server configuration.
/// Requires: `administrator`.
pub async fn get_config(operator: OperatorContext, State(state): State<Arc<AppState>>) -> Response {
    require_role!(operator, state, Administrator);

    let cfg = &state.config;
    let cas: Vec<_> = state
        .cas
        .values()
        .map(|ca| {
            json!({
                "id": ca.id,
                "is_default": ca.id == state.default_ca_id.as_str(),
                "crl_url": ca.crl_url,
                "ocsp_url": ca.ocsp_url,
            })
        })
        .collect();
    (
        StatusCode::OK,
        Json(json!({
            "base_url": cfg.base_url,
            "db_url": "***",
            "mtc_enabled": state.cas.values().any(|ca| ca.mtc.is_enabled()),
            "caa_identities": cfg.server.caa_identities,
            "validate_dnssec": cfg.server.validate_dnssec,
            "cas": cas,
        })),
    )
        .into_response()
}
