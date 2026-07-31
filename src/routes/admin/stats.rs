//! Admin statistics and configuration handlers.

use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;

use crate::admin::auth::OperatorContext;
use crate::db;
use crate::mtc::log;
use crate::state::AppState;

use super::error::AdminApiError;

/// `GET /admin/stats`
///
/// Returns live server statistics.  Requires: any role.
pub async fn get_stats(
    operator: OperatorContext,
    State(state): State<Arc<AppState>>,
) -> Result<Response, AdminApiError> {
    let uptime_secs = state.startup_time.elapsed().as_secs();

    let ca_scope = operator.ca_scope();

    let counts = db::stats::summary(&state.db, ca_scope).await?;

    let server_version = env!("CARGO_PKG_VERSION");

    let mut mtc_cas = Vec::new();
    for ca in state.cas.values() {
        if let Some(scope) = ca_scope {
            if ca.id != scope {
                continue;
            }
        }
        let tree_size = match ca.mtc.log.as_ref() {
            Some(shared_log) => match log::tree_size(shared_log).await {
                Ok(s) => Some(s),
                Err(e) => {
                    tracing::warn!(ca_id = %ca.id, "stats: tree_size query failed: {e}");
                    None
                }
            },
            None => None,
        };
        let landmark_count = match db::landmarks::count(&state.db_ro, &ca.id).await {
            Ok(c) => Some(c),
            Err(e) => {
                tracing::warn!(ca_id = %ca.id, "stats: landmark count query failed: {e}");
                None
            }
        };
        mtc_cas.push(json!({
            "ca_id": ca.id,
            "enabled": ca.mtc.is_enabled(),
            "tree_size": tree_size,
            "landmarks": landmark_count,
            "last_checkpoint_at": ca.mtc.last_checkpoint_at(),
            "last_landmark_at": ca.mtc.last_landmark_at(),
            "cosigner_count": ca.mtc.cosigner_clients.len(),
        }));
    }

    Ok((
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
                "since_startup": state.audit.event_count.load(std::sync::atomic::Ordering::Acquire),
                "journal_connected": state.journal.is_connected(),
            },
            "mtc": mtc_cas,
        })),
    )
        .into_response())
}

/// `GET /admin/config`
///
/// Show redacted server configuration.
/// Requires: `administrator`.
pub async fn get_config(
    _operator: OperatorContext,
    State(state): State<Arc<AppState>>,
) -> Response {
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
