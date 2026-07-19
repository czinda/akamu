//! Certificate download — RFC 8555 §7.4.2
//!
//! GET  /acme/cert/{id}  — unauthenticated (for simple HTTP clients)
//! POST /acme/cert/{id}  — POST-as-GET (RFC 8555 §6.3); required by ACME clients
//!                         that send all requests as authenticated POSTs.

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;

use crate::db;
use crate::error::AcmeError;
use crate::state::AppState;

use super::{acme_headers, acme_prefix, parse_jws, CaId};

const PROPERTIES_CT: &str = "application/pem-certificate-chain-with-properties";

/// Serve the certificate chain as PEM (unauthenticated GET).
pub async fn download_cert(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(params): Path<std::collections::HashMap<String, String>>,
) -> Result<Response, AcmeError> {
    let id = params.get("id").ok_or(AcmeError::NotFound)?;
    let cert = db::certs::get_by_id(&state.db_ro, id)
        .await?
        .ok_or(AcmeError::NotFound)?;
    let (standalone_der, link_alternate, trust_anchor_id) = if cert.mtc_log_index.is_some() {
        let pfx = acme_prefix(&state.config.base_url, &cert.ca_id, &state.default_ca_id);
        let ta_id = state
            .get_ca(&cert.ca_id)
            .and_then(|ca| ca.mtc.trust_anchor_id_der.clone());
        (
            db::certs::get_mtc_standalone_der(&state.db_ro, id).await?,
            Some(format!("{pfx}/mtc/cert/{id}/landmark")),
            ta_id,
        )
    } else {
        (None, None, None)
    };
    let wants_properties = accepts_properties(&headers);
    Ok(cert_pem_response(
        cert,
        standalone_der,
        link_alternate,
        wants_properties.then_some(trust_anchor_id).flatten(),
    ))
}

/// POST-as-GET handler for certificate download (RFC 8555 §6.3 + §7.4.2).
///
/// The JWS must have an empty payload (`""`).  The account that owns the order
/// linked to this certificate must match the `kid` in the JWS header — or any
/// authenticated account may download (some servers allow this; we require the
/// account to match the order for consistency with the rest of the API).
pub async fn download_cert_post(
    State(state): State<Arc<AppState>>,
    ca_id: CaId,
    headers: HeaderMap,
    Path(params): Path<std::collections::HashMap<String, String>>,
    body: Bytes,
) -> Result<Response, AcmeError> {
    let id = params.get("id").cloned().ok_or(AcmeError::NotFound)?;
    let pfx = acme_prefix(&state.config.base_url, &ca_id.0, &state.default_ca_id);
    let url = format!("{pfx}/cert/{id}");
    let ctx = parse_jws(&state, body, &url).await?;

    // POST-as-GET must have an empty payload.
    if !ctx.payload.is_empty() {
        return Err(AcmeError::BadRequest(
            "certificate download: payload must be empty (POST-as-GET)".into(),
        ));
    }

    // Verify the requesting account owns the order linked to this certificate.
    let account_id = ctx
        .account_id
        .ok_or_else(|| AcmeError::Unauthorized("kid required".into()))?;

    let cert = db::certs::get_by_id(&state.db_ro, &id)
        .await?
        .ok_or(AcmeError::NotFound)?;

    // RFC 9115 §2.3.5: when the order's allow_cert_get flag is set, any
    // authenticated account may download the certificate (not just the owner).
    // Use the write pool to avoid replication-lag races where a newly-created
    // delegation order's allow_cert_get hasn't propagated to the read replica.
    let allow_cert_get = db::orders::get_by_id(&state.db, &cert.order_id)
        .await?
        .is_some_and(|o| o.allow_cert_get != 0);

    if !allow_cert_get && cert.account_id != account_id {
        return Err(AcmeError::Unauthorized(
            "certificate belongs to a different account".into(),
        ));
    }

    let (standalone_der, link_alternate, trust_anchor_id) = if cert.mtc_log_index.is_some() {
        let ta_id = state
            .get_ca(&cert.ca_id)
            .and_then(|ca| ca.mtc.trust_anchor_id_der.clone());
        (
            db::certs::get_mtc_standalone_der(&state.db_ro, &id).await?,
            Some(format!("{pfx}/mtc/cert/{id}/landmark")),
            ta_id,
        )
    } else {
        (None, None, None)
    };
    let wants_properties = accepts_properties(&headers);
    let mut resp = cert_pem_response(
        cert,
        standalone_der,
        link_alternate,
        wants_properties.then_some(trust_anchor_id).flatten(),
    );
    resp.headers_mut()
        .extend(acme_headers(&state, &ca_id.0, &ctx.next_nonce));
    Ok(resp)
}

fn cert_pem_response(
    cert: crate::db::schema::CertificateRow,
    standalone_der: Option<Vec<u8>>,
    link_alternate: Option<String>,
    trust_anchor_id_der: Option<Vec<u8>>,
) -> Response {
    // §9: when the client accepts properties and we have a trust anchor ID,
    // serve the PEM with TrustAnchorIdentifier property.
    let mtc_der = standalone_der.or_else(|| {
        cert.pem
            .starts_with("-----BEGIN STANDALONE MTC CERTIFICATE-----")
            .then(|| cert.der.clone())
    });

    if let Some(der) = mtc_der {
        if let Some(ta_der) = trust_anchor_id_der {
            let pem = synta_certificate::der_to_pem("STANDALONE MTC CERTIFICATE", &der);
            let ta_b64 = STANDARD.encode(&ta_der);
            let body = format!(
                "{}\nTrustAnchorIdentifier = {ta_b64}\n",
                String::from_utf8_lossy(&pem),
            );
            let mut resp = (StatusCode::OK, body.into_bytes()).into_response();
            resp.headers_mut().insert(
                axum::http::header::CONTENT_TYPE,
                HeaderValue::from_static(PROPERTIES_CT),
            );
            add_link_header(&mut resp, &link_alternate);
            return resp;
        }

        let mut resp = (StatusCode::OK, der).into_response();
        resp.headers_mut().insert(
            axum::http::header::CONTENT_TYPE,
            HeaderValue::from_static("application/pkix-cert"),
        );
        add_link_header(&mut resp, &link_alternate);
        return resp;
    }

    let mut resp = (StatusCode::OK, cert.pem.into_bytes()).into_response();
    resp.headers_mut().insert(
        axum::http::header::CONTENT_TYPE,
        HeaderValue::from_static("application/pem-certificate-chain"),
    );
    resp
}

fn accepts_properties(headers: &HeaderMap) -> bool {
    headers
        .get(axum::http::header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|accept| accept.contains(PROPERTIES_CT))
}

fn add_link_header(resp: &mut Response, link_alternate: &Option<String>) {
    if let Some(url) = link_alternate {
        match HeaderValue::from_str(&format!("<{url}>; rel=\"alternate\"")) {
            Ok(val) => {
                resp.headers_mut().insert(axum::http::header::LINK, val);
            }
            Err(e) => tracing::warn!(url = %url, "could not set Link header: {e}"),
        }
    }
}
