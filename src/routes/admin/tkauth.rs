//! Admin tkauth JTI cache management handler.

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

use super::super::unix_now;

/// `POST /admin/tkauth/prune-jti?dry_run=true`
///
/// Delete expired entries from the tkauth JTI replay-prevention cache.
/// With `?dry_run=true`, returns the count without deleting.
/// Requires: `administrator` or `ca_operations`.
pub async fn post_tkauth_prune_jti(
    operator: OperatorContext,
    State(state): State<Arc<AppState>>,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> Response {
    require_role!(operator, state, Administrator | CaOperations);

    if !state.config.tkauth.as_ref().is_some_and(|t| t.enabled) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"status": 400, "detail": "tkauth is not enabled"})),
        )
            .into_response();
    }

    let dry_run = params
        .get("dry_run")
        .is_some_and(|v| v == "true" || v == "1");
    let now = unix_now();

    if dry_run {
        match db::tkauth::count_expired(&state.db_ro, now).await {
            Ok(n) => Json(json!({"would_delete": n, "dry_run": true})).into_response(),
            Err(e) => {
                tracing::error!(error = %e, "tkauth prune-jti dry-run: db error");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"status": 500, "detail": "database error"})),
                )
                    .into_response()
            }
        }
    } else {
        match db::tkauth::purge_expired(&state.db, now).await {
            Ok(n) => {
                tracing::info!(deleted = n, "tkauth JTI cache pruned via admin API");
                Json(json!({"deleted": n})).into_response()
            }
            Err(e) => {
                tracing::error!(error = %e, "tkauth prune-jti: db error");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"status": 500, "detail": "database error"})),
                )
                    .into_response()
            }
        }
    }
}
