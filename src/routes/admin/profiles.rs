//! Admin certificate profile management handlers.

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;
use serde_json::json;

use crate::admin::auth::OperatorContext;
use crate::audit::{AuditEvent, AuditEventType};
use crate::require_role;
use crate::state::AppState;

/// JSON payload for `POST /admin/profiles` and `PUT /admin/profiles/{id}`.
#[derive(Deserialize)]
struct ProfilePayload {
    #[serde(default)]
    description: String,
    #[serde(default = "default_profile_validity_days")]
    validity_days: u32,
    #[serde(default = "default_profile_hash_alg")]
    hash_alg: String,
    #[serde(default)]
    key_usage_bits: u16,
    #[serde(default)]
    extended_key_usages: Vec<String>,
    #[serde(default)]
    crl_url: Option<String>,
    #[serde(default)]
    ocsp_url: Option<String>,
    #[serde(default)]
    allowed_key_types: Vec<String>,
    #[serde(default)]
    certificate_policies: Vec<(String, Option<String>)>,
    #[serde(default)]
    issue_as_mtc: bool,
    #[serde(default)]
    allowed_identifier_patterns: Vec<String>,
    #[serde(default = "default_true")]
    identifier_match_all: bool,
    #[serde(default)]
    auth_hook: Option<String>,
    #[serde(default = "default_auth_hook_timeout")]
    auth_hook_timeout_secs: u64,
    #[serde(default)]
    require_account_grant: bool,
    #[serde(default)]
    ca_ids: Vec<String>,
    #[serde(default)]
    kpn_san_templates: Vec<String>,
    #[serde(default)]
    ms_upn_san_template: Option<String>,
    #[serde(default)]
    inject_account_kpn: bool,
}

fn default_profile_validity_days() -> u32 {
    90
}
fn default_profile_hash_alg() -> String {
    "sha256".to_string()
}
fn default_true() -> bool {
    true
}
fn default_auth_hook_timeout() -> u64 {
    30
}

impl ProfilePayload {
    fn into_params(self) -> crate::profiles::CertificateParameters {
        crate::profiles::CertificateParameters {
            validity_days: self.validity_days,
            hash_alg: self.hash_alg,
            key_usage_bits: self.key_usage_bits,
            extended_key_usages: self.extended_key_usages,
            crl_url: self.crl_url,
            ocsp_url: self.ocsp_url,
            allowed_key_types: self.allowed_key_types,
            certificate_policies: self.certificate_policies,
            issue_as_mtc: self.issue_as_mtc,
            allowed_identifier_patterns: self.allowed_identifier_patterns,
            identifier_match_all: self.identifier_match_all,
            auth_hook: self.auth_hook,
            auth_hook_timeout_secs: self.auth_hook_timeout_secs,
            require_account_grant: self.require_account_grant,
            ca_ids: self.ca_ids,
            kpn_san_templates: self.kpn_san_templates,
            ms_upn_san_template: self.ms_upn_san_template,
            inject_account_kpn: self.inject_account_kpn,
            trust_jwks_urls: vec![],
            dogtag_profile_id: None,
        }
    }
}

/// JSON payload for `POST /admin/profiles` (creation includes the profile ID).
#[derive(Deserialize)]
struct ProfileCreatePayload {
    id: String,
    #[serde(flatten)]
    inner: ProfilePayload,
}

/// `GET /admin/profiles`
///
/// List all loaded certificate profiles with their parameters.
/// Requires: any role.
pub async fn get_profiles(
    operator: OperatorContext,
    State(state): State<Arc<AppState>>,
) -> Response {
    require_role!(
        operator,
        state,
        Administrator | CaOperations | CaRa | Auditor
    );

    let profiles = state.profiles.all_profiles();
    let mut list: Vec<serde_json::Value> = profiles
        .iter()
        .map(|(id, description)| {
            let mut entry = json!({
                "id": id,
                "description": description,
            });
            if let Some(params) = state.profiles.resolve(id) {
                entry["validity_days"] = json!(params.validity_days);
                entry["hash_alg"] = json!(params.hash_alg);
                entry["extended_key_usages"] = json!(params.extended_key_usages);
                entry["issue_as_mtc"] = json!(params.issue_as_mtc);
            }
            entry
        })
        .collect();
    list.sort_by(|a, b| a["id"].as_str().cmp(&b["id"].as_str()));

    (StatusCode::OK, Json(json!({"profiles": list}))).into_response()
}

/// `POST /admin/profiles`
///
/// Add a new certificate profile to the runtime cache (FPT_NPE_EXT.1).
/// Requires: `administrator`.
pub async fn post_profiles(
    operator: OperatorContext,
    State(state): State<Arc<AppState>>,
    body: Bytes,
) -> Response {
    require_role!(operator, state, Administrator);

    let payload: ProfileCreatePayload = match serde_json::from_slice(&body) {
        Ok(p) => p,
        Err(e) => return (StatusCode::BAD_REQUEST, format!("JSON: {e}")).into_response(),
    };

    if payload.id.is_empty() {
        return (StatusCode::BAD_REQUEST, "id is required").into_response();
    }

    let id = payload.id.clone();
    let desc = payload.inner.description.clone();
    if state
        .profiles
        .add_profile(id.clone(), desc.clone(), payload.inner.into_params())
    {
        state
            .record_audit(
                AuditEvent::success(AuditEventType::AdminAction)
                    .with_principal(&operator.name)
                    .with_detail(json!({"action": "profile.create", "id": id}).to_string()),
            )
            .await;
        (
            StatusCode::CREATED,
            Json(json!({"id": id, "description": desc})),
        )
            .into_response()
    } else {
        (
            StatusCode::CONFLICT,
            Json(json!({"status": 409, "detail": "profile already exists"})),
        )
            .into_response()
    }
}

/// `PUT /admin/profiles/{id}`
///
/// Replace an existing certificate profile in the runtime cache (FPT_NPE_EXT.1).
/// Requires: `administrator`.
pub async fn put_profile(
    operator: OperatorContext,
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    body: Bytes,
) -> Response {
    require_role!(operator, state, Administrator);

    let payload: ProfilePayload = match serde_json::from_slice(&body) {
        Ok(p) => p,
        Err(e) => return (StatusCode::BAD_REQUEST, format!("JSON: {e}")).into_response(),
    };

    let desc = payload.description.clone();
    if state
        .profiles
        .update_profile(&id, desc, payload.into_params())
    {
        state
            .record_audit(
                AuditEvent::success(AuditEventType::AdminAction)
                    .with_principal(&operator.name)
                    .with_detail(json!({"action": "profile.update", "id": id}).to_string()),
            )
            .await;
        StatusCode::NO_CONTENT.into_response()
    } else {
        (
            StatusCode::NOT_FOUND,
            Json(json!({"status": 404, "detail": "profile not found"})),
        )
            .into_response()
    }
}

/// `GET /admin/profiles/{id}`
///
/// Return a single certificate profile by ID.
/// Requires: any role.
pub async fn get_profile(
    operator: OperatorContext,
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Response {
    require_role!(
        operator,
        state,
        Administrator | CaOperations | CaRa | Auditor
    );

    let descriptions = state.profiles.all_profiles();
    match (descriptions.get(&id), state.profiles.resolve(&id)) {
        (Some(description), Some(params)) => (
            StatusCode::OK,
            Json(json!({
                "id": id,
                "description": description,
                "validity_days": params.validity_days,
                "hash_alg": params.hash_alg,
                "key_usage_bits": params.key_usage_bits,
                "extended_key_usages": params.extended_key_usages,
                "crl_url": params.crl_url,
                "ocsp_url": params.ocsp_url,
                "allowed_key_types": params.allowed_key_types,
                "certificate_policies": params.certificate_policies,
                "issue_as_mtc": params.issue_as_mtc,
                "allowed_identifier_patterns": params.allowed_identifier_patterns,
                "identifier_match_all": params.identifier_match_all,
                "auth_hook": params.auth_hook,
                "auth_hook_timeout_secs": params.auth_hook_timeout_secs,
                "require_account_grant": params.require_account_grant,
                "ca_ids": params.ca_ids,
            })),
        )
            .into_response(),
        _ => (
            StatusCode::NOT_FOUND,
            Json(json!({"status": 404, "detail": "profile not found"})),
        )
            .into_response(),
    }
}

/// `DELETE /admin/profiles/{id}`
///
/// Remove a certificate profile from the runtime cache (FPT_NPE_EXT.1).
/// Requires: `administrator`.
pub async fn delete_profile(
    operator: OperatorContext,
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Response {
    require_role!(operator, state, Administrator);

    if state.profiles.remove_profile(&id) {
        state
            .record_audit(
                AuditEvent::success(AuditEventType::AdminAction)
                    .with_principal(&operator.name)
                    .with_detail(json!({"action": "profile.delete", "id": id}).to_string()),
            )
            .await;
        StatusCode::NO_CONTENT.into_response()
    } else {
        (
            StatusCode::NOT_FOUND,
            Json(json!({"status": 404, "detail": "profile not found"})),
        )
            .into_response()
    }
}
