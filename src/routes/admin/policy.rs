//! Admin policy rule management handlers.

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use serde_json::json;

use crate::admin::auth::OperatorContext;
use crate::audit::{AuditEvent, AuditEventType};
use crate::crdt_hooks;
use crate::db;
use crate::policy::rebuild_or_defer;
use crate::require_role;
use crate::state::AppState;

use super::super::unix_now;

#[derive(Deserialize)]
pub struct CreatePolicyRulePayload {
    pub scope: Option<String>,
    pub name: String,
    pub rule: serde_json::Value,
    pub enabled: Option<bool>,
}

/// Payload for `PUT /admin/policy/rules/{id}`.  Scope is immutable after
/// creation and intentionally excluded — delete and recreate to change scope.
/// The `rule` field is required (full replacement); `name` and `enabled` are
/// optional and default to the existing values when omitted.
#[derive(Deserialize)]
pub struct UpdatePolicyRulePayload {
    pub name: Option<String>,
    pub rule: serde_json::Value,
    pub enabled: Option<bool>,
}

/// Known valid scope values.
///
/// Adding a new scope (e.g. "revocation") requires updates in:
/// `AppState`, `AppStateBuilder`, `main.rs` init, `src/policy.rs` rebuild,
/// gossip loop detection, and integration tests.  Consider refactoring to a
/// `HashMap<String, Arc<IssuancePolicyEngine>>` before adding a second scope.
const KNOWN_SCOPES: &[&str] = &["issuance"];

const MAX_NAME_LEN: usize = 255;
const MAX_RULE_JSON_BYTES: usize = 65_536;

/// Read-visibility check: a CA-scoped operator can **see** a rule if it
/// mentions their CA or if the rule is global (no `ca` field).  Global
/// rules return `true` so scoped operators can see (but not mutate) them.
///
/// Design note: CA-scoped operators see the full configuration of global
/// rules, including identifier patterns for other CAs.  This is intentional
/// — global rules affect their CA and they need visibility for debugging.
/// Mutation of global rules is correctly restricted to server-wide operators.
fn ca_scope_visible(rule_json: &str, rule_id: &str, scope_ca: &str) -> bool {
    match serde_json::from_str::<akamu_policy::config::PolicyRuleConfig>(rule_json) {
        Ok(cfg) => match cfg.ca {
            Some(cas) => cas.iter().any(|c| c == scope_ca),
            None => true,
        },
        Err(e) => {
            tracing::warn!(rule_id, scope_ca, error = %e, "corrupt policy rule JSON in CA-scope filter");
            false
        }
    }
}

/// Write-authorization check: a CA-scoped operator can only **modify or
/// delete** a rule that *exclusively* targets their CA.  Global rules
/// (no `ca` field) and multi-CA rules are read-only for scoped operators
/// — only server-wide operators may mutate them.  Uses `all()` so a
/// scoped operator cannot narrow or delete a rule that also protects
/// other CAs outside their scope.
fn ca_scope_mutable(rule_json: &str, rule_id: &str, scope_ca: &str) -> bool {
    match serde_json::from_str::<akamu_policy::config::PolicyRuleConfig>(rule_json) {
        Ok(cfg) => match cfg.ca {
            Some(cas) => !cas.is_empty() && cas.iter().all(|c| c == scope_ca),
            None => false,
        },
        Err(e) => {
            tracing::warn!(rule_id, scope_ca, error = %e, "corrupt policy rule JSON in CA-scope mutable check");
            false
        }
    }
}

/// Payload-validation check: a CA-scoped operator can only **create** rules
/// that target exclusively their CA.  Uses `all()` so a scoped operator
/// cannot create rules targeting CAs outside their scope.
fn ca_scope_creatable(rule: &serde_json::Value, scope_ca: &str) -> bool {
    match rule.get("ca") {
        Some(serde_json::Value::Array(cas)) => {
            !cas.is_empty()
                && cas
                    .iter()
                    .all(|c| c.as_str().is_some_and(|s| s == scope_ca))
        }
        None => false,
        Some(_) => false,
    }
}

fn validate_rule_json(
    rule: &serde_json::Value,
) -> Result<akamu_policy::config::PolicyRuleConfig, Box<Response>> {
    if !rule.is_object() {
        return Err(Box::new(
            axum::Json(json!({"status": 400, "detail": "rule must be a JSON object"}))
                .into_response(),
        ));
    }
    let cfg: akamu_policy::config::PolicyRuleConfig = serde_json::from_value(rule.clone())
        .map_err(|e| {
            Box::new(
                axum::Json(json!({"status": 400, "detail": format!("invalid rule: {e}")}))
                    .into_response(),
            )
        })?;
    cfg.to_abac_rule().map_err(|e| {
        Box::new(
            axum::Json(json!({"status": 400, "detail": format!("invalid rule: {e}")}))
                .into_response(),
        )
    })?;
    Ok(cfg)
}

/// `GET /admin/policy/scopes`
pub async fn get_policy_scopes(
    operator: OperatorContext,
    State(state): State<Arc<AppState>>,
) -> Response {
    require_role!(operator, state, Administrator | CaOperations | Auditor);

    match db::policy_rules::list_scopes(&state.db_ro).await {
        Ok(scopes) => axum::Json(json!(scopes)).into_response(),
        Err(e) => e.into_response(),
    }
}

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
    let all_rows = match db::policy_rules::list_by_scope(&state.db_ro, scope).await {
        Ok(r) => r,
        Err(e) => return e.into_response(),
    };
    let ca_scope = operator.ca_scope().map(|s| s.to_string());
    let rows: Vec<_> = if let Some(ref scope_ca) = ca_scope {
        all_rows
            .into_iter()
            .filter(|r| ca_scope_visible(&r.rule_json, &r.id, scope_ca))
            .collect()
    } else {
        all_rows
    };
    let items: Vec<serde_json::Value> = rows.iter().map(rule_row_to_json).collect();
    axum::Json(json!(items)).into_response()
}

/// `POST /admin/policy/rules`
pub async fn post_policy_rule(
    operator: OperatorContext,
    State(state): State<Arc<AppState>>,
    body: Bytes,
) -> Response {
    require_role!(operator, state, Administrator | CaOperations);

    let payload: CreatePolicyRulePayload = match serde_json::from_slice(&body) {
        Ok(p) => p,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                axum::Json(json!({"status": 400, "detail": format!("invalid JSON: {e}")})),
            )
                .into_response()
        }
    };

    if let Some(scope_ca) = operator.ca_scope() {
        if !ca_scope_creatable(&payload.rule, scope_ca) {
            return (
                StatusCode::FORBIDDEN,
                axum::Json(
                    json!({"status": 403, "detail": "CA-scoped operator cannot create rules outside assigned CA"}),
                ),
            )
                .into_response();
        }
    }

    let scope = payload.scope.as_deref().unwrap_or("issuance");
    if !KNOWN_SCOPES.contains(&scope) {
        return (
            StatusCode::BAD_REQUEST,
            axum::Json(json!({"status": 400, "detail": format!("unknown scope '{scope}'")})),
        )
            .into_response();
    }
    if payload.name.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            axum::Json(json!({"status": 400, "detail": "name must not be empty"})),
        )
            .into_response();
    }
    if payload.name.len() > MAX_NAME_LEN {
        return (
            StatusCode::BAD_REQUEST,
            axum::Json(
                json!({"status": 400, "detail": format!("name exceeds {MAX_NAME_LEN} characters")}),
            ),
        )
            .into_response();
    }
    if body.len() > MAX_RULE_JSON_BYTES {
        return (
            StatusCode::BAD_REQUEST,
            axum::Json(json!({"status": 400, "detail": format!("request body exceeds {MAX_RULE_JSON_BYTES} bytes")})),
        )
            .into_response();
    }

    match db::policy_rules::get_by_scope_and_name(&state.db, scope, &payload.name).await {
        Ok(Some(_)) => {
            return (
                StatusCode::CONFLICT,
                axum::Json(json!({
                    "status": 409,
                    "detail": format!("rule '{}' already exists in scope '{scope}'", payload.name)
                })),
            )
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

    let cfg = match validate_rule_json(&rule_value) {
        Ok(c) => c,
        Err(resp) => return *resp,
    };

    let enabled = payload.enabled.unwrap_or(true);
    let now = crate::util::rfc3339_now();
    let id = uuid::Uuid::new_v4().to_string();

    let rule_json = match serde_json::to_string(&cfg) {
        Ok(s) => s,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                axum::Json(json!({"status": 500, "detail": format!("serialize rule: {e}")})),
            )
                .into_response()
        }
    };

    let row = db::policy_rules::PolicyRuleRow {
        id: id.clone(),
        scope: scope.to_string(),
        name: payload.name.clone(),
        rule_json,
        enabled: i64::from(enabled),
        created_at: now.clone(),
        updated_at: now.clone(),
        created_by: Some(operator.name.clone()),
    };
    if let Err(e) = db::policy_rules::insert(&state.db, &row).await {
        let msg = e.to_string();
        if db::is_unique_constraint_violation(&msg) {
            return (
                StatusCode::CONFLICT,
                axum::Json(json!({"status": 409, "detail": format!("rule '{}' already exists in scope '{scope}'", payload.name)})),
            )
                .into_response();
        }
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

    let rebuilt =
        rebuild_or_defer(&state, &format!("policy rebuild after creating rule {id}")).await;

    let body = json!({"id": id, "name": payload.name});
    let mut resp = (StatusCode::CREATED, axum::Json(body)).into_response();
    if !rebuilt {
        resp.headers_mut().insert(
            "warning",
            HeaderValue::from_static(
                "299 akamu \"rule saved but policy engine rebuild failed; change takes effect after retry\"",
            ),
        );
    }
    resp
}

/// `GET /admin/policy/rules/{id}`
pub async fn get_policy_rule(
    operator: OperatorContext,
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Response {
    require_role!(operator, state, Administrator | CaOperations | Auditor);

    let row = match db::policy_rules::get_by_id(&state.db_ro, &id).await {
        Ok(Some(r)) => r,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                axum::Json(json!({"status": 404, "detail": "not found"})),
            )
                .into_response()
        }
        Err(e) => return e.into_response(),
    };

    if let Some(scope_ca) = operator.ca_scope() {
        if !ca_scope_visible(&row.rule_json, &row.id, scope_ca) {
            return (
                StatusCode::NOT_FOUND,
                axum::Json(json!({"status": 404, "detail": "not found"})),
            )
                .into_response();
        }
    }

    axum::Json(rule_row_to_json(&row)).into_response()
}

/// `PUT /admin/policy/rules/{id}`
pub async fn put_policy_rule(
    operator: OperatorContext,
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    body: Bytes,
) -> Response {
    require_role!(operator, state, Administrator | CaOperations);

    let payload: UpdatePolicyRulePayload = match serde_json::from_slice(&body) {
        Ok(p) => p,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                axum::Json(json!({"status": 400, "detail": format!("invalid JSON: {e}")})),
            )
                .into_response()
        }
    };

    let existing = match db::policy_rules::get_by_id(&state.db, &id).await {
        Ok(Some(r)) => r,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                axum::Json(json!({"status": 404, "detail": "not found"})),
            )
                .into_response()
        }
        Err(e) => return e.into_response(),
    };

    if let Some(scope_ca) = operator.ca_scope() {
        if !ca_scope_mutable(&existing.rule_json, &existing.id, scope_ca) {
            return (
                StatusCode::NOT_FOUND,
                axum::Json(json!({"status": 404, "detail": "not found"})),
            )
                .into_response();
        }
        if !ca_scope_creatable(&payload.rule, scope_ca) {
            return (
                StatusCode::FORBIDDEN,
                axum::Json(
                    json!({"status": 403, "detail": "CA-scoped operator cannot move rule outside assigned CA"}),
                ),
            )
                .into_response();
        }
    }

    if let Some(ref n) = payload.name {
        if n.is_empty() {
            return (
                StatusCode::BAD_REQUEST,
                axum::Json(json!({"status": 400, "detail": "name must not be empty"})),
            )
                .into_response();
        }
        if n.len() > MAX_NAME_LEN {
            return (
                StatusCode::BAD_REQUEST,
                axum::Json(json!({"status": 400, "detail": format!("name exceeds {MAX_NAME_LEN} characters")})),
            )
                .into_response();
        }
    }
    if body.len() > MAX_RULE_JSON_BYTES {
        return (
            StatusCode::BAD_REQUEST,
            axum::Json(json!({"status": 400, "detail": format!("request body exceeds {MAX_RULE_JSON_BYTES} bytes")})),
        )
            .into_response();
    }

    let name = payload.name.as_deref().unwrap_or(&existing.name);
    if name != existing.name {
        match db::policy_rules::get_by_scope_and_name(&state.db, &existing.scope, name).await {
            Ok(Some(_)) => {
                return (
                    StatusCode::CONFLICT,
                    axum::Json(json!({
                        "status": 409,
                        "detail": format!("rule '{name}' already exists in scope '{}'", existing.scope)
                    })),
                )
                    .into_response();
            }
            Err(e) => return e.into_response(),
            Ok(None) => {}
        }
    }

    let mut rule_value = payload.rule.clone();
    if let Some(obj) = rule_value.as_object_mut() {
        obj.insert(
            "name".to_string(),
            serde_json::Value::String(name.to_string()),
        );
    }

    let cfg = match validate_rule_json(&rule_value) {
        Ok(c) => c,
        Err(resp) => return *resp,
    };

    let enabled = payload.enabled.unwrap_or(existing.enabled != 0);
    let now = crate::util::rfc3339_now();
    let rule_json = match serde_json::to_string(&cfg) {
        Ok(s) => s,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                axum::Json(json!({"status": 500, "detail": format!("serialize rule: {e}")})),
            )
                .into_response()
        }
    };

    match db::policy_rules::update(&state.db, &id, name, &rule_json, i64::from(enabled), &now).await
    {
        Ok(false) => {
            return (
                StatusCode::NOT_FOUND,
                axum::Json(json!({"status": 404, "detail": "not found"})),
            )
                .into_response()
        }
        Err(e) => {
            let msg = e.to_string();
            if db::is_unique_constraint_violation(&msg) {
                return (
                    StatusCode::CONFLICT,
                    axum::Json(json!({"status": 409, "detail": format!("rule '{name}' already exists in scope '{}'", existing.scope)})),
                )
                    .into_response();
            }
            return e.into_response();
        }
        Ok(true) => {}
    }

    let unix = unix_now();
    crdt_hooks::on_policy_rule_upsert(
        &state,
        crdt_hooks::PolicyRuleUpsertParams {
            id: &id,
            scope: &existing.scope,
            name,
            rule_json: &rule_json,
            enabled,
            created_at: &existing.created_at,
            updated_at: &now,
            created_by: existing.created_by.as_deref(),
        },
        unix,
    )
    .await;

    state
        .record_audit(
            AuditEvent::success(AuditEventType::AdminAction)
                .with_principal(&operator.name)
                .with_detail(
                    json!({"action": "policy_rule.update", "id": id, "name": name}).to_string(),
                ),
        )
        .await;

    let rebuilt =
        rebuild_or_defer(&state, &format!("policy rebuild after updating rule {id}")).await;

    no_content_with_rebuild_warning(rebuilt)
}

/// `DELETE /admin/policy/rules/{id}`
pub async fn delete_policy_rule(
    operator: OperatorContext,
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Response {
    require_role!(operator, state, Administrator | CaOperations);

    // Note: there is a narrow TOCTOU window between the CA-scope check and
    // the soft-delete below.  Exploiting it requires concurrent CA-scoped
    // Administrator or CaOperations operations within single-digit milliseconds.
    // A concurrent PUT could also move the rule's CA scope between the GET and
    // DELETE, allowing a scoped operator to delete a rule that was moved outside
    // their scope.  The practical risk is very low and gossip convergence would
    // surface any inconsistency.
    if let Some(scope_ca) = operator.ca_scope() {
        match db::policy_rules::get_by_id(&state.db, &id).await {
            Ok(Some(r)) if !ca_scope_mutable(&r.rule_json, &r.id, scope_ca) => {
                return (
                    StatusCode::NOT_FOUND,
                    axum::Json(json!({"status": 404, "detail": "not found"})),
                )
                    .into_response();
            }
            Ok(None) => {
                return (
                    StatusCode::NOT_FOUND,
                    axum::Json(json!({"status": 404, "detail": "not found"})),
                )
                    .into_response()
            }
            Err(e) => return e.into_response(),
            _ => {}
        }
    }

    let unix = unix_now();
    match db::policy_rules::delete(&state.db, &id, unix).await {
        Ok(false) => {
            return (
                StatusCode::NOT_FOUND,
                axum::Json(json!({"status": 404, "detail": "not found"})),
            )
                .into_response()
        }
        Err(e) => return e.into_response(),
        Ok(true) => {}
    }

    crdt_hooks::on_policy_rule_remove(&state, &id, unix).await;

    state
        .record_audit(
            AuditEvent::success(AuditEventType::AdminAction)
                .with_principal(&operator.name)
                .with_detail(json!({"action": "policy_rule.delete", "id": id}).to_string()),
        )
        .await;

    let rebuilt =
        rebuild_or_defer(&state, &format!("policy rebuild after deleting rule {id}")).await;

    no_content_with_rebuild_warning(rebuilt)
}

fn no_content_with_rebuild_warning(rebuilt: bool) -> Response {
    if rebuilt {
        return StatusCode::NO_CONTENT.into_response();
    }
    let mut resp = StatusCode::NO_CONTENT.into_response();
    resp.headers_mut().insert(
        "warning",
        HeaderValue::from_static(
            "299 akamu \"rule saved but policy engine rebuild failed; change takes effect after retry\"",
        ),
    );
    resp
}

fn rule_row_to_json(r: &db::policy_rules::PolicyRuleRow) -> serde_json::Value {
    let (rule, corrupt) = match serde_json::from_str::<serde_json::Value>(&r.rule_json) {
        Ok(v) => (v, false),
        Err(e) => {
            tracing::warn!(rule_id = %r.id, error = %e, "corrupt rule_json in policy rule");
            (json!({"_error": format!("corrupt rule JSON: {e}")}), true)
        }
    };
    let mut obj = json!({
        "id": r.id,
        "scope": r.scope,
        "name": r.name,
        "rule_json": rule,
        "enabled": r.enabled != 0,
        "created_at": r.created_at,
        "updated_at": r.updated_at,
        "created_by": r.created_by,
    });
    if corrupt {
        obj["corrupt"] = json!(true);
    }
    obj
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_scopes_matches_app_state() {
        assert!(
            KNOWN_SCOPES.contains(&"issuance"),
            "KNOWN_SCOPES must contain 'issuance' to match AppState::issuance_policy"
        );
        assert_eq!(
            KNOWN_SCOPES.len(),
            1,
            "KNOWN_SCOPES has {} entries but AppState only has issuance_policy — add a HashMap<String, Arc<IssuancePolicyEngine>> before adding more scopes",
            KNOWN_SCOPES.len()
        );
    }
}
