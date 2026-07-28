//! Admin policy rule management handlers.

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use serde_json::json;

use crate::admin::auth::OperatorContext;
use crate::audit::{AuditEvent, AuditEventType};
use crate::crdt_hooks;
use crate::db;
use crate::error::AcmeError;
use crate::policy::rebuild_issuance_policy;
use crate::require_role;
use crate::state::AppState;

use super::super::unix_now;

/// `GET /admin/policy/rules?scope=issuance`
pub async fn get_policy_rules(
    operator: OperatorContext,
    State(state): State<Arc<AppState>>,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> Response {
    require_role!(operator, state, Administrator | CaOperations | Auditor);

    let scope = params
        .get("scope")
        .map(String::as_str)
        .unwrap_or("issuance");
    let rows = match db::policy_rules::list_by_scope(&state.db_ro, scope).await {
        Ok(r) => r,
        Err(e) => return e.into_response(),
    };
    let items: Vec<serde_json::Value> = rows
        .iter()
        .map(|r| {
            json!({
                "id": r.id,
                "scope": r.scope,
                "name": r.name,
                "rule_json": r.rule_json,
                "enabled": r.enabled != 0,
                "created_at": r.created_at,
                "updated_at": r.updated_at,
                "created_by": r.created_by,
            })
        })
        .collect();
    axum::Json(json!(items)).into_response()
}

/// `POST /admin/policy/rules`
pub async fn post_policy_rule(
    operator: OperatorContext,
    State(state): State<Arc<AppState>>,
    axum::Json(payload): axum::Json<CreatePolicyRulePayload>,
) -> Response {
    require_role!(operator, state, Administrator);

    if let Some(scope_ca) = operator.ca_scope() {
        if !ca_scope_visible_json(&payload.rule, scope_ca) {
            return AcmeError::Unauthorized(
                "CA-scoped operator cannot create rules outside assigned CA".into(),
            )
            .into_response();
        }
    }

    let scope = payload.scope.as_deref().unwrap_or("issuance");
    if payload.name.is_empty() {
        return AcmeError::BadRequest("name must not be empty".into()).into_response();
    }

    match db::policy_rules::get_by_scope_and_name(&state.db_ro, scope, &payload.name).await {
        Ok(Some(_)) => {
            return AcmeError::Conflict(format!(
                "rule '{}' already exists in scope '{scope}'",
                payload.name
            ))
            .into_response();
        }
        Err(e) => return e.into_response(),
        Ok(None) => {}
    }

    let mut rule_value = payload.rule.clone();
    if let Some(obj) = rule_value.as_object_mut() {
        obj.insert(
            "name".to_string(),
            serde_json::Value::String(payload.name.clone()),
        );
    }

    let _cfg = match validate_rule_json(&rule_value) {
        Ok(c) => c,
        Err(e) => return e.into_response(),
    };

    let enabled = payload.enabled.unwrap_or(true);
    let now = crate::util::rfc3339_now();
    let id = uuid::Uuid::new_v4().to_string();

    let rule_json = match serde_json::to_string(&rule_value) {
        Ok(s) => s,
        Err(e) => return AcmeError::Internal(format!("serialize rule: {e}")).into_response(),
    };

    let row = db::policy_rules::PolicyRuleRow {
        id: id.clone(),
        scope: scope.to_string(),
        name: payload.name.clone(),
        rule_json,
        enabled: enabled as i64,
        created_at: now.clone(),
        updated_at: now.clone(),
        created_by: Some(operator.name.clone()),
    };
    if let Err(e) = db::policy_rules::insert(&state.db, &row).await {
        return e.into_response();
    }

    let unix = unix_now();
    crdt_hooks::on_policy_rule_upsert(
        &state,
        crdt_hooks::PolicyRuleUpsertParams {
            id: &row.id,
            scope: &row.scope,
            name: &row.name,
            rule_json: &row.rule_json,
            enabled,
            created_at: &row.created_at,
            updated_at: &row.updated_at,
            created_by: Some(&operator.name),
        },
        unix,
    )
    .await;

    state
        .record_audit(
            AuditEvent::success(AuditEventType::AdminAction)
                .with_principal(&operator.name)
                .with_detail(
                    json!({"action": "policy_rule.create", "id": id, "name": payload.name, "scope": scope})
                        .to_string(),
                ),
        )
        .await;

    if let Err(e) = rebuild_issuance_policy(&state).await {
        tracing::error!("failed to rebuild policy after creating rule {id}: {e}");
        state
            .policy_rebuild_needed
            .store(true, std::sync::atomic::Ordering::Release);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            axum::Json(json!({
                "status": 500,
                "detail": "rule saved but policy engine rebuild failed; rule will take effect on next server restart",
                "id": id,
            })),
        )
            .into_response();
    }

    (
        StatusCode::CREATED,
        axum::Json(json!({"id": id, "name": payload.name})),
    )
        .into_response()
}

/// `DELETE /admin/policy/rules/{id}`
pub async fn delete_policy_rule(
    operator: OperatorContext,
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Response {
    require_role!(operator, state, Administrator);

    if let Some(scope_ca) = operator.ca_scope() {
        match db::policy_rules::get_by_id(&state.db_ro, &id).await {
            Ok(Some(r)) if !ca_scope_visible(&r.rule_json, scope_ca) => {
                return AcmeError::NotFound.into_response();
            }
            Ok(None) => return AcmeError::NotFound.into_response(),
            Err(e) => return e.into_response(),
            _ => {}
        }
    }

    match db::policy_rules::delete(&state.db, &id).await {
        Ok(false) => return AcmeError::NotFound.into_response(),
        Err(e) => return e.into_response(),
        Ok(true) => {}
    }

    crdt_hooks::on_policy_rule_remove(&state, &id, unix_now()).await;

    state
        .record_audit(
            AuditEvent::success(AuditEventType::AdminAction)
                .with_principal(&operator.name)
                .with_detail(json!({"action": "policy_rule.delete", "id": id}).to_string()),
        )
        .await;

    if let Err(e) = rebuild_issuance_policy(&state).await {
        tracing::error!("failed to rebuild policy after deleting rule {id}: {e}");
        state
            .policy_rebuild_needed
            .store(true, std::sync::atomic::Ordering::Release);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            axum::Json(json!({
                "status": 500,
                "detail": "rule deleted but policy engine rebuild failed; deletion will take effect on next server restart",
            })),
        )
            .into_response();
    }

    StatusCode::NO_CONTENT.into_response()
}

fn rule_row_to_json(r: &db::policy_rules::PolicyRuleRow) -> serde_json::Value {
    json!({
        "id": r.id,
        "scope": r.scope,
        "name": r.name,
        "rule_json": r.rule_json,
        "enabled": r.enabled != 0,
        "created_at": r.created_at,
        "updated_at": r.updated_at,
        "created_by": r.created_by,
    })
}
