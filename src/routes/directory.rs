//! GET /acme/directory and GET /acme/{ca_id}/directory — RFC 8555 §7.1.1

use std::sync::Arc;

use axum::extract::State;
use axum::response::IntoResponse;
use axum::Json;
use serde_json::json;

use crate::state::AppState;

use super::{acme_prefix, CaId};

pub async fn get_directory(State(state): State<Arc<AppState>>, ca_id: CaId) -> impl IntoResponse {
    let base = &state.config.base_url;
    let pfx = acme_prefix(base, &ca_id.0, &state.default_ca_id);
    let ca = state
        .get_ca(&ca_id.0)
        .expect("CaId extractor guarantees CA exists");

    let mut meta = json!({});
    if let Some(tos) = &state.config.server.terms_of_service_url {
        meta["termsOfService"] = json!(tos);
    }
    if let Some(website) = &state.config.server.website_url {
        meta["website"] = json!(website);
    }
    // CAA identities: CA-level first, fall back to server-level.
    let caa = if !ca.caa_identities.is_empty() {
        &ca.caa_identities
    } else {
        &state.config.server.caa_identities
    };
    if !caa.is_empty() {
        meta["caaIdentities"] = json!(caa);
    }
    if state.config.server.external_account_required {
        meta["externalAccountRequired"] = json!(true);
    }
    if state.config.server.allow_subdomain_auth {
        meta["subdomainAuthAllowed"] = json!(true);
    }
    if state.config.server.in_band_onion_caa {
        meta["inBandOnionCAARequired"] = json!(true);
    }
    if let Some(min_lifetime) = state.config.server.star_min_lifetime_secs {
        let mut auto_renewal = json!({
            "min-lifetime": min_lifetime,
            "allow-certificate-get": state.config.server.star_allow_certificate_get,
        });
        if let Some(max_dur) = state.config.server.star_max_duration_secs {
            auto_renewal["max-duration"] = json!(max_dur);
        }
        meta["auto-renewal"] = auto_renewal;
    }
    if state.config.server.delegation_enabled {
        meta["delegation-enabled"] = json!(true);
    }
    if state.config.server.allow_certificate_get {
        meta["allow-certificate-get"] = json!(true);
    }
    let loaded_profiles = state.profiles.profiles_for_ca(&ca_id.0);
    if !loaded_profiles.is_empty() {
        meta["profiles"] = json!(loaded_profiles);
    }

    // Account-level endpoints (newAccount, keyChange) use the canonical
    // prefix when accounts are server-wide (default).  Per-CA directories
    // still return per-CA URLs for order/authz/revoke endpoints.
    let acct_pfx = if state.config.server.account_scope == "ca" {
        pfx.clone()
    } else {
        format!("{base}/acme")
    };

    let dir = json!({
        "newNonce":    format!("{pfx}/new-nonce"),
        "newAccount":  format!("{acct_pfx}/new-account"),
        "newOrder":    format!("{pfx}/new-order"),
        "newAuthz":    format!("{pfx}/new-authz"),
        "revokeCert":  format!("{pfx}/revoke-cert"),
        "keyChange":   format!("{acct_pfx}/key-change"),
        "renewalInfo": format!("{pfx}/renewal-info"),
        "meta": meta,
    });
    Json(dir)
}
