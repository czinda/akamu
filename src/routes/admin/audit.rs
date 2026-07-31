//! Admin audit log query handler.

use std::sync::atomic::Ordering;
use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;

use crate::admin::auth::OperatorContext;
use crate::audit::{query_journal, AuditQuery};
use crate::state::AppState;

use super::error::AdminApiError;

/// `GET /admin/audit`
///
/// Query the audit event log with optional filters.
///
/// Query params: `type`, `subject`, `from`, `until`, `outcome`, `limit` (≤1000), `offset`.
/// Requires: `administrator` or `auditor`, unscoped (server-wide) only.
///
/// Audit events are not tagged with a `ca_id` (the journal/JSONL storage
/// backends have no per-CA concept), so results cannot be filtered to a
/// single CA the way `/admin/stats` or `/admin/certs` are. Rather than give a
/// CA-scoped operator the server-wide audit trail (accounts, certs,
/// operators, and delegations across every tenant CA), this endpoint is
/// restricted to unscoped operators until the audit pipeline carries a
/// `ca_id` end to end.
pub async fn get_audit(
    operator: OperatorContext,
    State(state): State<Arc<AppState>>,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> Result<Response, AdminApiError> {
    if operator.ca_scope().is_some() {
        return Err(AdminApiError::Forbidden(
            "audit log access requires an unscoped (server-wide) operator".into(),
        ));
    }

    let limit: u32 = params
        .get("limit")
        .and_then(|v| v.parse().ok())
        .unwrap_or(100)
        .clamp(1, 1000);
    let offset: u32 = params
        .get("offset")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);

    let q = AuditQuery {
        event_type: params.get("type").cloned(),
        subject: params.get("subject").cloned(),
        from: params.get("from").cloned(),
        until: params.get("until").cloned(),
        outcome: params.get("outcome").cloned(),
        limit,
        offset,
    };

    match query_journal(&state.journal, &q).await {
        Ok(rows) => {
            let events: Vec<_> = rows
                .into_iter()
                .map(|r| {
                    json!({
                        "occurred_at": r.occurred_at,
                        "event_type": r.event_type,
                        "subject": r.subject,
                        "principal": r.principal,
                        "outcome": r.outcome,
                        "detail": r.detail,
                    })
                })
                .collect();
            let total = state.audit.event_count.load(Ordering::Acquire);
            Ok((
                StatusCode::OK,
                Json(json!({
                    "events": events,
                    "total_since_startup": total,
                    "limit": limit,
                    "offset": offset,
                })),
            )
                .into_response())
        }
        Err(e) => {
            let msg = e.to_string();
            if msg.contains("invalid") && msg.contains("timestamp") {
                tracing::warn!(error = %e, "get_audit: invalid timestamp parameter");
                Err(AdminApiError::BadRequest(msg))
            } else {
                Err(AdminApiError::Internal(format!("journal query error: {e}")))
            }
        }
    }
}
