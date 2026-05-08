//! POST-as-GET endpoints for RFC 9115 delegation objects.
//!
//! `POST /acme/delegations/{account_id}` — list delegations for an account.
//! `POST /acme/delegation/{id}`          — fetch a single delegation object.

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::response::Response;
use serde_json::json;

use crate::db;
use crate::error::AcmeError;
use crate::state::AppState;

use super::{acme_prefix, json_response, parse_jws, CaId};

/// `POST /acme/delegations/{account_id}` — RFC 9115 §2.3.1.2
///
/// Returns the list of delegation URLs for the requesting account.
/// The authenticated account must match `account_id`.
pub async fn list_delegations(
    State(state): State<Arc<AppState>>,
    ca_id: CaId,
    Path(account_id): Path<String>,
    body: Bytes,
) -> Result<Response, AcmeError> {
    if !state.config.server.delegation_enabled {
        return Err(AcmeError::NotFound);
    }

    let pfx = acme_prefix(&state.config.base_url, &ca_id.0, &state.default_ca_id);
    let url = format!("{pfx}/delegations/{account_id}");
    let ctx = parse_jws(&state, body, &url).await?;

    let requesting_id = ctx
        .account_id
        .ok_or(AcmeError::Unauthorized("kid required".into()))?;
    if requesting_id != account_id {
        return Err(AcmeError::Unauthorized(
            "account does not match path".into(),
        ));
    }

    let rows = db::delegations::list_for_account(&state.db_ro, &account_id).await?;
    let urls: Vec<String> = rows
        .iter()
        .map(|r| format!("{pfx}/delegation/{}", r.id))
        .collect();

    json_response(
        &state,
        &ca_id.0,
        axum::http::StatusCode::OK,
        json!({ "delegations": urls }),
        &ctx.next_nonce,
    )
}

/// `POST /acme/delegation/{id}` — RFC 9115 §2.3.1.3
///
/// Returns the delegation object: CSR template and optional CNAME map.
/// The authenticated account must own the delegation.
pub async fn get_delegation(
    State(state): State<Arc<AppState>>,
    ca_id: CaId,
    Path(id): Path<String>,
    body: Bytes,
) -> Result<Response, AcmeError> {
    if !state.config.server.delegation_enabled {
        return Err(AcmeError::NotFound);
    }

    let pfx = acme_prefix(&state.config.base_url, &ca_id.0, &state.default_ca_id);
    let url = format!("{pfx}/delegation/{id}");
    let ctx = parse_jws(&state, body, &url).await?;

    let account_id = ctx
        .account_id
        .ok_or(AcmeError::Unauthorized("kid required".into()))?;

    let row = db::delegations::get_by_id(&state.db_ro, &id)
        .await?
        .ok_or(AcmeError::UnknownDelegation)?;

    if row.account_id != account_id {
        return Err(AcmeError::UnknownDelegation);
    }

    let template: serde_json::Value = serde_json::from_str(&row.csr_template).map_err(|e| {
        AcmeError::Internal(format!("corrupt csr_template in delegation {id}: {e}"))
    })?;

    let mut obj = json!({ "csr-template": template });
    if let Some(cmap) = &row.cname_map {
        let cmap_val: serde_json::Value = serde_json::from_str(cmap).map_err(|e| {
            AcmeError::Internal(format!("corrupt cname_map in delegation {id}: {e}"))
        })?;
        obj["cname-map"] = cmap_val;
    }

    json_response(
        &state,
        &ca_id.0,
        axum::http::StatusCode::OK,
        obj,
        &ctx.next_nonce,
    )
}
