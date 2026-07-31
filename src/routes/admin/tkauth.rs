//! Admin tkauth JTI cache management handler.

use std::sync::Arc;

use axum::extract::State;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;

use crate::admin::auth::OperatorContext;
use crate::db;
use crate::state::AppState;

use super::super::unix_now;
use super::error::AdminApiError;

/// `POST /admin/tkauth/prune-jti?dry_run=true`
///
/// Delete expired entries from the tkauth JTI replay-prevention cache.
/// With `?dry_run=true`, returns the count without deleting.
/// Requires: `administrator` or `ca_operations`.
pub async fn post_tkauth_prune_jti(
    _operator: OperatorContext,
    State(state): State<Arc<AppState>>,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> Result<Response, AdminApiError> {
    if !state.config.tkauth.as_ref().is_some_and(|t| t.enabled) {
        return Err(AdminApiError::BadRequest("tkauth is not enabled".into()));
    }

    let dry_run = params
        .get("dry_run")
        .is_some_and(|v| v == "true" || v == "1");
    let now = unix_now();

    if dry_run {
        let n = db::tkauth::count_expired(&state.db_ro, now).await?;
        Ok(Json(json!({"would_delete": n, "dry_run": true})).into_response())
    } else {
        let n = db::tkauth::purge_expired(&state.db, now).await?;
        tracing::info!(deleted = n, "tkauth JTI cache pruned via admin API");
        Ok(Json(json!({"deleted": n})).into_response())
    }
}
