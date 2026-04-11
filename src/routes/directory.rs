//! GET /acme/directory — RFC 8555 §7.1.1

use std::sync::Arc;

use axum::extract::State;
use axum::response::IntoResponse;
use axum::Json;
use serde_json::json;

use crate::state::AppState;

pub async fn get_directory(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let base = &state.config.base_url;
    let mut meta = json!({});
    if let Some(tos) = &state.config.server.terms_of_service_url {
        meta["termsOfService"] = json!(tos);
    }
    if let Some(website) = &state.config.server.website_url {
        meta["website"] = json!(website);
    }
    if !state.config.server.caa_identities.is_empty() {
        meta["caaIdentities"] = json!(state.config.server.caa_identities);
    }
    if state.config.server.external_account_required {
        meta["externalAccountRequired"] = json!(true);
    }
    if state.config.server.allow_subdomain_auth {
        meta["subdomainAuthAllowed"] = json!(true);
    }
    if let Some(min_lifetime) = state.config.server.star_min_lifetime_secs {
        let mut auto_renewal = json!({
            "min-lifetime": min_lifetime,
            "allow-certificate-get": true,
        });
        if let Some(max_dur) = state.config.server.star_max_duration_secs {
            auto_renewal["max-duration"] = json!(max_dur);
        }
        meta["auto-renewal"] = auto_renewal;
    }

    let dir = json!({
        "newNonce":    format!("{base}/acme/new-nonce"),
        "newAccount":  format!("{base}/acme/new-account"),
        "newOrder":    format!("{base}/acme/new-order"),
        "newAuthz":    format!("{base}/acme/new-authz"),
        "revokeCert":  format!("{base}/acme/revoke-cert"),
        "keyChange":   format!("{base}/acme/key-change"),
        "renewalInfo": format!("{base}/acme/renewal-info"),
        "meta": meta,
    });
    Json(dir)
}
