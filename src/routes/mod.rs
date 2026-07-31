//! Axum route assembly and shared request-handling utilities.

mod embedded_ui;

use std::collections::HashMap;
use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{FromRef, FromRequestParts, Path, Request};
use axum::http::request::Parts;
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, head, post};
use axum::{Json, Router};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use tower_http::services::{ServeDir, ServeFile};
use tower_http::trace::TraceLayer;

use crate::db;
use crate::error::AcmeError;
use crate::jose::jws::{JwsFlattened, JwsKeyRef, JwsProtectedHeader};
use crate::state::{AppState, CachedAccount};

// ── CaId extractor ────────────────────────────────────────────────────────────

/// Carries the CA identifier for the current request.
///
/// Extracted from the `:ca_id` URL path parameter when present.
/// Falls back to the server's `default_ca_id` on legacy routes that have no
/// `:ca_id` segment.  Returns 404 when `:ca_id` is present but unknown.
#[derive(Debug, Clone)]
pub struct CaId(pub String);

impl<S> FromRequestParts<S> for CaId
where
    S: Send + Sync,
    Arc<AppState>: FromRef<S>,
{
    type Rejection = AcmeError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let app = Arc::<AppState>::from_ref(state);

        // Fast path: if the matched route template has no `{ca_id}` segment this
        // is a legacy route — return the default CA without allocating anything.
        if !parts
            .extensions
            .get::<axum::extract::MatchedPath>()
            .is_some_and(|mp| mp.as_str().contains("{ca_id}"))
        {
            return Ok(CaId((*app.default_ca_id).clone()));
        }

        // Per-CA route: extract `{ca_id}` from the path parameters.
        if let Ok(Path(params)) =
            Path::<HashMap<String, String>>::from_request_parts(parts, state).await
        {
            if let Some(id) = params.get("ca_id") {
                return if app.cas.contains_key(id.as_str()) {
                    Ok(CaId(id.clone()))
                } else {
                    Err(AcmeError::NotFound)
                };
            }
        }
        Ok(CaId((*app.default_ca_id).clone()))
    }
}

pub mod account;
pub mod admin;
pub mod authz;
pub mod certificate;
pub mod challenge;
pub mod crl;
pub mod delegation;
pub mod directory;
pub mod eab_identity;
pub mod email_webhook;
pub mod finalize;
pub mod key_change;
pub mod mtc;
pub mod nonce;
pub mod ocsp;
pub mod order;
pub mod renewal_info;
pub mod revoke;
pub mod star_cert;

/// Challenge entry used in both authorization and challenge response bodies.
///
/// Shared between `authz::build_authz_json` and `challenge::challenge_response`
/// to prevent field-set drift when new challenge types are added.
#[derive(serde::Serialize)]
pub(crate) struct ChallengeJson<'a> {
    pub r#type: &'a str,
    pub url: String,
    pub status: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub accounturi: Option<String>,
    #[serde(
        rename = "issuer-domain-names",
        skip_serializing_if = "Option::is_none"
    )]
    pub issuer_domain_names: Option<&'a [String]>,
    #[serde(rename = "authKey", skip_serializing_if = "Option::is_none")]
    pub auth_key: Option<String>,
    /// RFC 9799 §3.2: server-generated nonce for onion-csr-01 challenges.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
    #[serde(rename = "tkauth-type", skip_serializing_if = "Option::is_none")]
    pub tkauth_type: Option<&'a str>,
    #[serde(rename = "token-authority", skip_serializing_if = "Option::is_none")]
    pub token_authority: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub validated: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<Box<serde_json::value::RawValue>>,
}

/// Construct the ACME account URI for dns-persist-01 `accounturi` fields.
///
/// Uses `acme_pfx` (from [`acme_prefix`]) so the URI respects the
/// `account_scope` setting (`/acme/account/…` vs `/acme/{ca}/account/…`).
pub(crate) fn account_uri(acme_pfx: &str, account_id: &str) -> String {
    format!("{acme_pfx}/account/{account_id}")
}

/// Middleware: reject ACME requests when the audit store is full and the
/// overflow policy is `halt` (FAU_STG.4).  Admin routes bypass this check
/// so operators can query status and resolve the condition.
async fn halt_check(
    axum::extract::State(state): axum::extract::State<Arc<AppState>>,
    req: Request,
    next: Next,
) -> Response {
    use std::sync::atomic::Ordering;
    if state.audit.should_halt.load(Ordering::Acquire) {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            [("Retry-After", "300")],
            "audit storage full — server halted per FAU_STG.4 policy",
        )
            .into_response();
    }
    next.run(req).await
}

/// Register a route on both `/acme/{path}` (legacy) and `/acme/{ca_id}/{path}` (per-CA).
///
/// Axum resolves static segments before dynamic ones, so `/acme/directory`
/// is unambiguous vs `/acme/{ca_id}/directory`.  Config validation ensures
/// no CA ID matches a reserved ACME path segment.
fn dual_acme_route(
    router: Router<Arc<AppState>>,
    path: &str,
    handler: axum::routing::MethodRouter<Arc<AppState>>,
) -> Router<Arc<AppState>> {
    router
        .route(&format!("/acme/{path}"), handler.clone())
        .route(&format!("/acme/{{ca_id}}/{path}"), handler)
}

/// ACME protocol routes (both legacy and per-CA), with FAU_STG.4 halt_check.
fn build_acme_router(state: &Arc<AppState>) -> Router<Arc<AppState>> {
    let mut r = Router::new();
    // Directory
    r = dual_acme_route(r, "directory", get(directory::get_directory));
    // Nonces
    r = dual_acme_route(r, "new-nonce", head(nonce::new_nonce_head));
    r = dual_acme_route(r, "new-nonce", get(nonce::new_nonce_get));
    // Accounts
    r = dual_acme_route(r, "new-account", post(account::new_account));
    r = dual_acme_route(r, "account/{id}", post(account::update_account));
    // Orders
    r = dual_acme_route(r, "new-order", post(order::new_order));
    r = dual_acme_route(r, "order/{id}", post(order::get_order));
    r = dual_acme_route(r, "order/{id}/finalize", post(finalize::finalize_order));
    // Delegations (RFC 9115)
    r = dual_acme_route(
        r,
        "delegations/{account_id}",
        post(delegation::list_delegations),
    );
    r = dual_acme_route(r, "delegation/{id}", post(delegation::get_delegation));
    // Authorizations
    r = dual_acme_route(r, "new-authz", post(authz::new_authz));
    r = dual_acme_route(r, "authz/{id}", post(authz::get_authz));
    // Challenges
    r = dual_acme_route(
        r,
        "chall/{authz_id}/{type}",
        post(challenge::respond_challenge),
    );
    // Certificates
    r = dual_acme_route(
        r,
        "cert/{id}",
        get(certificate::download_cert).post(certificate::download_cert_post),
    );
    // STAR rolling certificate URL (RFC 8739 §3.3)
    r = dual_acme_route(
        r,
        "cert/star/{order_id}",
        get(star_cert::star_cert_get).post(star_cert::star_cert_post),
    );
    // Revocation
    r = dual_acme_route(r, "revoke-cert", post(revoke::revoke_cert));
    // Key change
    r = dual_acme_route(r, "key-change", post(key_change::key_change));
    // Renewal Info (RFC 9773 ARI)
    r = dual_acme_route(
        r,
        "renewal-info/{cert_id}",
        get(renewal_info::get_renewal_info),
    );
    // MTC log state (read-only; 404 when MTC is disabled)
    r = dual_acme_route(r, "mtc/tree-size", get(mtc::get_tree_size));
    r = dual_acme_route(r, "mtc/root", get(mtc::get_root));
    r = dual_acme_route(
        r,
        "mtc/inclusion-proof/{cert_id}",
        get(mtc::get_inclusion_proof),
    );
    r = dual_acme_route(r, "mtc/cert/{cert_id}/standalone", get(mtc::get_standalone));
    r = dual_acme_route(
        r,
        "mtc/cert/{cert_id}/landmark",
        get(mtc::get_landmark_for_cert),
    );
    r = dual_acme_route(r, "mtc/landmarks", get(mtc::get_landmarks));
    r = dual_acme_route(r, "mtc/landmark-list", get(mtc::get_landmark_list));
    r = dual_acme_route(r, "mtc/landmarks/{seq}/cert", get(mtc::get_landmark_cert));
    // C2SP tlog-tiles API
    r = dual_acme_route(r, "mtc/checkpoint", get(mtc::get_tlog_checkpoint));
    r = dual_acme_route(r, "mtc/cosignature", get(mtc::get_tlog_cosignature));
    r = dual_acme_route(r, "mtc/discovery", get(mtc::get_discovery));
    r = dual_acme_route(r, "mtc/tile/{*path}", get(mtc::get_tlog_tile));
    // Consistency proof for monitors
    r = dual_acme_route(r, "mtc/consistency-proof", get(mtc::get_consistency_proof));
    // Subtree root hash
    r = dual_acme_route(r, "mtc/subtree-root", get(mtc::get_subtree_root));
    // Revoked ranges
    r = dual_acme_route(r, "mtc/revoked-ranges", get(mtc::get_revoked_ranges));
    // EAB identity — legacy-only (no per-CA counterpart)
    r = r.route("/acme/eab", get(eab_identity::get_eab_identity));

    r.layer(axum::middleware::from_fn_with_state(
        Arc::clone(state),
        halt_check,
    ))
}

/// Non-ACME public routes: CRL/OCSP/cross-certs, email webhook, gossip sync.
fn build_other_router() -> Router<Arc<AppState>> {
    Router::new()
        // RFC 8823 email-reply-00 webhook — HMAC-authenticated, not JWS-authenticated.
        // Body is capped at 64 KiB; legitimate payloads are a few KiB.
        // halt_check exemption is documented in src/routes/email_webhook.rs.
        .route(
            "/acme/email-webhook",
            post(email_webhook::handle_webhook)
                .layer(axum::extract::DefaultBodyLimit::max(64 * 1024)),
        )
        // Legacy CRL/OCSP/cross-certs — alias to default CA
        .route("/ca/crl", get(crl::get_crl))
        .route("/ca/ocsp", post(ocsp::post_ocsp))
        .route("/ca/ocsp/{request}", get(ocsp::get_ocsp))
        .route("/ca/cross-certs", get(crl::get_cross_certs))
        // Per-CA CRL/OCSP/cross-certs
        .route("/ca/{ca_id}/crl", get(crl::get_crl))
        .route("/ca/{ca_id}/ocsp", post(ocsp::post_ocsp))
        .route("/ca/{ca_id}/ocsp/{request}", get(ocsp::get_ocsp))
        .route("/ca/{ca_id}/cross-certs", get(crl::get_cross_certs))
        // Inter-node gossip sync (C-3): on the public listener; authentication is
        // provided by the CMS SignedData wrapper (ECDSA P-256 with pinned peer cert).
        .route("/gossip/sync", post(crate::gossip::handlers::gossip_sync))
}

/// Admin API routes (bypass halt_check; auth enforced per-handler via OperatorContext).
fn build_admin_router() -> Router<Arc<AppState>> {
    Router::new()
        .route(
            "/admin/session",
            post(crate::admin::auth::post_session).delete(crate::admin::auth::delete_session),
        )
        .route(
            "/admin/session/eab",
            post(crate::admin::auth::post_session_eab),
        )
        .route(
            "/admin/operators",
            axum::routing::get(admin::get_operators).post(admin::post_operators),
        )
        .route(
            "/admin/account/{id}/profile-grants",
            axum::routing::get(admin::get_account_profile_grants)
                .put(admin::put_account_profile_grants)
                .delete(admin::delete_account_profile_grants),
        )
        .route(
            "/admin/eab",
            axum::routing::get(admin::get_eab).post(admin::post_eab),
        )
        .route(
            "/admin/eab/{kid}",
            axum::routing::get(admin::get_eab_key).delete(admin::delete_eab),
        )
        .route("/admin/audit", axum::routing::get(admin::get_audit))
        .route("/admin/certs", axum::routing::get(admin::get_certs))
        .route("/admin/certs/{id}", axum::routing::get(admin::get_cert))
        .route(
            "/admin/certs/{id}/download",
            axum::routing::get(admin::get_cert_download),
        )
        .route(
            "/admin/profiles",
            axum::routing::get(admin::get_profiles).post(admin::post_profiles),
        )
        .route(
            "/admin/profiles/{id}",
            axum::routing::get(admin::get_profile)
                .put(admin::put_profile)
                .delete(admin::delete_profile),
        )
        .route("/admin/accounts", axum::routing::get(admin::get_accounts))
        .route(
            "/admin/account/{id}",
            axum::routing::get(admin::get_account),
        )
        .route(
            "/admin/account/{id}/deactivate",
            post(admin::post_account_deactivate),
        )
        .route(
            "/admin/operators/{id}",
            axum::routing::get(admin::get_operator)
                .put(admin::put_operator)
                .patch(admin::patch_operator),
        )
        .route("/admin/operators/{id}/unlock", post(admin::unlock_operator))
        .route("/admin/orders", axum::routing::get(admin::get_orders))
        .route("/admin/orders/{id}", axum::routing::get(admin::get_order))
        .route(
            "/admin/delegations",
            axum::routing::get(admin::get_delegations).post(admin::post_delegations),
        )
        .route(
            "/admin/delegations/{id}",
            axum::routing::get(admin::get_delegation_admin)
                .put(admin::put_delegation)
                .delete(admin::delete_delegation),
        )
        .route(
            "/admin/policy/scopes",
            axum::routing::get(admin::get_policy_scopes),
        )
        .route(
            "/admin/policy/rules",
            axum::routing::get(admin::get_policy_rules).post(admin::post_policy_rule),
        )
        .route(
            "/admin/policy/rules/{id}",
            axum::routing::get(admin::get_policy_rule)
                .put(admin::put_policy_rule)
                .delete(admin::delete_policy_rule),
        )
        .route("/admin/config", axum::routing::get(admin::get_config))
        .route("/admin/crl/force", post(admin::post_crl_force))
        .route(
            "/admin/tkauth/prune-jti",
            post(admin::post_tkauth_prune_jti),
        )
        .route("/admin/revoke", post(admin::post_revoke))
        .route("/admin/stats", axum::routing::get(admin::get_stats))
        .route("/admin/cas", axum::routing::get(admin::get_cas))
        .route("/admin/cas/{id}", axum::routing::get(admin::get_ca))
        .route(
            "/admin/cas/{id}/cert",
            axum::routing::get(admin::get_ca_cert),
        )
        .route("/admin/ca/{id}/crl/force", post(admin::post_ca_crl_force))
        .route("/admin/ca/{id}/cross-sign", post(admin::post_ca_cross_sign))
        .route(
            "/admin/cross-certs",
            axum::routing::get(admin::get_cross_certs),
        )
        .route(
            "/admin/cross-certs/{id}",
            axum::routing::get(admin::get_cross_cert),
        )
        // ── MTC transparency log ──────────────────────────────────────────
        .route(
            "/admin/mtc/tree-size",
            axum::routing::get(admin::get_mtc_tree_size),
        )
        .route("/admin/mtc/root", axum::routing::get(admin::get_mtc_root))
        .route(
            "/admin/mtc/landmarks",
            axum::routing::get(admin::get_mtc_landmarks),
        )
        .route(
            "/admin/mtc/landmark-list",
            axum::routing::get(admin::get_mtc_landmark_list),
        )
        .route(
            "/admin/mtc/inclusion-proof/{cert_id}",
            axum::routing::get(admin::get_mtc_inclusion_proof),
        )
        .route(
            "/admin/mtc/standalone/{cert_id}",
            axum::routing::get(admin::get_mtc_standalone),
        )
        .route(
            "/admin/mtc/landmarks/{seq}/cert",
            axum::routing::get(admin::get_mtc_landmark_cert),
        )
        .route(
            "/admin/mtc/landmarks/{seq}/cert-details",
            axum::routing::get(admin::get_mtc_landmark_cert_details),
        )
        .route(
            "/admin/mtc/consistency-proof",
            axum::routing::get(admin::get_mtc_consistency_proof),
        )
        .route(
            "/admin/mtc/subtree-root",
            axum::routing::get(admin::get_mtc_subtree_root),
        )
        .route(
            "/admin/mtc/revoked-ranges",
            axum::routing::get(admin::get_mtc_revoked_ranges),
        )
        .route(
            "/admin/mtc/checkpoint",
            axum::routing::get(admin::get_mtc_checkpoint),
        )
        .route(
            "/admin/mtc/cosignature",
            axum::routing::get(admin::get_mtc_cosignature),
        )
        .route(
            "/admin/ca/{id}/mtc/force-checkpoint",
            post(admin::post_mtc_force_checkpoint),
        )
        .route(
            "/admin/ca/{id}/mtc/force-landmark",
            post(admin::post_mtc_force_landmark),
        )
        .route(
            "/admin/ca/{id}/mtc/log-list-entry",
            axum::routing::get(admin::get_mtc_log_list_entry),
        )
        .route(
            "/admin/gossip/status",
            axum::routing::get(crate::gossip::handlers::gossip_status),
        )
        // Peer enrollment (H-8): operator must pre-pin a peer's keys before gossip
        // can proceed.  Authentication via OperatorContext (admin session).
        .route(
            "/admin/gossip/register",
            post(crate::gossip::handlers::gossip_register),
        )
}

/// Build the unified axum router: ACME, admin API, and optional web UI.
///
/// When `static_dir` is `Some`, serves the PatternFly SPA from `/ui/*` and
/// redirects `GET /` to `/ui/`.  Admin routes intentionally bypass `halt_check`
/// so operators can query status even when the ACME listener is halted.
pub fn build_router(
    state: Arc<AppState>,
    static_dir: Option<&std::path::Path>,
    webui_enabled: bool,
) -> Router {
    let max_body = state.config.server.max_body_bytes;

    let mut router = Router::new()
        .merge(build_acme_router(&state))
        .merge(build_other_router())
        .merge(build_admin_router());

    let mut has_ui = false;

    if let Some(dir) = static_dir {
        let index = ServeFile::new(dir.join("index.html"));
        let serve = ServeDir::new(dir)
            .append_index_html_on_directories(true)
            .fallback(index);
        let serve_with_headers = tower::ServiceBuilder::new()
            .layer(axum::middleware::from_fn(ui_security_headers))
            .service(serve);
        router = router.nest_service("/ui", serve_with_headers);
        has_ui = true;
    } else if webui_enabled {
        #[cfg(feature = "embed-webui")]
        {
            let ui =
                embedded_ui::webui_router().layer(axum::middleware::from_fn(ui_security_headers));
            router = router.nest("/ui", ui);
            has_ui = true;
        }
        #[cfg(not(feature = "embed-webui"))]
        {
            tracing::error!(
                "[server.webui] is configured without static_dir but the binary was \
                 not compiled with the embed-webui feature"
            );
        }
    }

    if has_ui {
        router = router.route("/", get(|| async { Redirect::permanent("/ui/") }));
    }

    router
        .layer(axum::extract::DefaultBodyLimit::max(if max_body > 0 {
            max_body
        } else {
            2 * 1024 * 1024
        }))
        .layer(TraceLayer::new_for_http().on_request(()).on_eos(()))
        .with_state(state)
}

// ── WebUI security headers ────────────────────────────────────────────────────

/// Middleware that adds security headers to every `/ui/*` response.
async fn ui_security_headers(req: Request, next: Next) -> Response {
    let is_hashed_asset = req.uri().path().starts_with("/assets/");
    let mut resp = next.run(req).await;
    let headers = resp.headers_mut();
    headers.insert(
        HeaderName::from_static("content-security-policy"),
        HeaderValue::from_static(
            // script-src has no 'unsafe-inline': the built webui only loads
            // external module scripts. style-src still needs it because React's
            // `style={{...}}` prop (used throughout webui/src) compiles to
            // inline `style="..."` attributes, which CSP has no nonce/hash
            // mechanism for short of a broader refactor away from inline styles.
            "default-src 'self'; \
             script-src 'self'; \
             style-src 'self' 'unsafe-inline'; \
             img-src 'self' data:; \
             font-src 'self'; \
             connect-src 'self'; \
             frame-ancestors 'none'",
        ),
    );
    headers.insert(
        HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        HeaderName::from_static("x-frame-options"),
        HeaderValue::from_static("DENY"),
    );
    headers.insert(
        HeaderName::from_static("referrer-policy"),
        HeaderValue::from_static("strict-origin-when-cross-origin"),
    );
    if is_hashed_asset {
        headers.insert(
            hyper::header::CACHE_CONTROL,
            HeaderValue::from_static("public, max-age=31536000, immutable"),
        );
    } else {
        headers.insert(
            hyper::header::CACHE_CONTROL,
            HeaderValue::from_static("no-cache"),
        );
    }
    resp
}

// ── Shared request helpers ────────────────────────────────────────────────────

/// Result of JWS parsing and verification.
pub(crate) struct JwsContext {
    pub header: JwsProtectedHeader,
    /// Decoded payload bytes (empty for POST-as-GET).
    pub payload: Vec<u8>,
    /// SPKI DER of the key used to sign the request.
    pub spki_der: Vec<u8>,
    /// Account ID from `kid`, or `None` for new-account with `jwk`.
    pub account_id: Option<String>,
    /// JWK thumbprint for the signing account (`None` for `jwk`-based requests).
    pub jwk_thumbprint: Option<String>,
    /// Fresh nonce to include in the response Replay-Nonce header.
    /// Generated and stored atomically with the consumed incoming nonce.
    pub next_nonce: String,
}

/// Parse, verify nonce, and verify signature for an ACME POST request.
///
/// `expected_url` must be the full URL the client should have signed, e.g.
/// `"https://acme.example.com/acme/new-account"`.
pub(crate) async fn parse_jws(
    state: &AppState,
    body: Bytes,
    expected_url: &str,
) -> Result<JwsContext, AcmeError> {
    // Parse the JWS flattened JSON body.
    let jws: JwsFlattened = serde_json::from_slice(&body)
        .map_err(|e| AcmeError::BadRequest(format!("JWS parse: {e}")))?;

    let header = jws.decode_header()?;

    // Verify the URL claim.
    if header.url != expected_url {
        return Err(AcmeError::Unauthorized(format!(
            "JWS url mismatch: got '{}', expected '{}'",
            header.url, expected_url
        )));
    }

    // Generate the response nonce and consume the incoming nonce atomically.
    // Uses the in-memory NonceBucket to avoid 4 DB round-trips per JWS call
    // (BEGIN IMMEDIATE + DELETE + INSERT + COMMIT).
    let next_nonce = gen_nonce(&state.nonces.node_prefix)?;
    // Reject nonces not issued by this node (wrong prefix) or unknown (replay).
    // In both cases, insert next_nonce so the client can retry on this node.
    let ok = state.nonces.has_local_prefix(&header.nonce)
        && state.nonces.consume_and_insert(&header.nonce, &next_nonce);
    if !ok {
        state.nonces.insert(next_nonce.clone());
        return Err(AcmeError::BadNonce(next_nonce));
    }

    // Resolve the signing key and account ID.
    let (spki_der, account_id, jwk_thumbprint) = match &header.key_ref {
        JwsKeyRef::Jwk { jwk } => {
            let spki = jwk.to_spki_der()?;
            (spki, None, None)
        }
        JwsKeyRef::Kid { kid } => {
            let id = crate::jose::kid::account_id_from_kid(&state.config.base_url, kid)?;
            // Try the in-memory account cache first to avoid a DB round-trip.
            let cached = state
                .spki_cache
                .read()
                .unwrap_or_else(|e| e.into_inner())
                .get(&id)
                .cloned();
            let cached_account = if let Some(acc) = cached {
                if acc.status != "valid" {
                    return Err(AcmeError::Unauthorized(format!(
                        "account status is '{}'",
                        acc.status
                    )));
                }
                acc
            } else {
                let account = db::accounts::get_by_id(&state.db_ro, &id)
                    .await?
                    .ok_or_else(|| AcmeError::Unauthorized("account not found".into()))?;
                if account.status != "valid" {
                    return Err(AcmeError::Unauthorized(format!(
                        "account status is '{}'",
                        account.status
                    )));
                }
                let entry = CachedAccount {
                    spki_der: account.public_key,
                    jwk_thumbprint: account.jwk_thumbprint,
                    status: account.status,
                };
                state
                    .spki_cache
                    .write()
                    .unwrap_or_else(|e| e.into_inner())
                    .insert(id.clone(), entry.clone());
                entry
            };
            let thumb = cached_account.jwk_thumbprint.clone();
            (cached_account.spki_der, Some(id), Some(thumb))
        }
    };

    // Verify the JWS signature; emit AuthJwsOk or AuthJwsFail audit event.
    if let Err(e) = jws.verify(&spki_der) {
        let principal = account_id
            .as_deref()
            .map(|id| format!("acme:{id}"))
            .unwrap_or_else(|| "acme:unknown".to_string());
        state
            .record_audit(
                crate::audit::AuditEvent::failure(crate::audit::AuditEventType::AuthJwsFail)
                    .with_principal(&principal),
            )
            .await;
        return Err(e.into());
    }
    state
        .record_audit(
            crate::audit::AuditEvent::success(crate::audit::AuditEventType::AuthJwsOk)
                .with_principal(account_id.as_deref().unwrap_or("new-account")),
        )
        .await;

    let payload = jws.decode_payload()?;
    Ok(JwsContext {
        header,
        payload,
        spki_der,
        account_id,
        jwk_thumbprint,
        next_nonce,
    })
}

// ── Response helpers ──────────────────────────────────────────────────────────

/// Return the ACME URL prefix for a given CA.
///
/// - Default CA: `{base_url}/acme` (legacy form; backward compatible)
/// - Non-default CA: `{base_url}/acme/{ca_id}` (per-CA form)
///
/// Use this to construct per-operation ACME URLs that are embedded in
/// directory responses, JWS `url` header checks, and `Location` headers.
pub(crate) fn acme_prefix(base_url: &str, ca_id: &str, default_ca_id: &str) -> String {
    if ca_id == default_ca_id {
        format!("{base_url}/acme")
    } else {
        format!("{base_url}/acme/{ca_id}")
    }
}

/// Generate a fresh anti-replay nonce, store it in the in-memory bucket, and return it.
pub(crate) fn new_nonce(state: &AppState) -> Result<String, AcmeError> {
    let nonce = gen_nonce(&state.nonces.node_prefix)?;
    state.nonces.insert(nonce.clone());
    Ok(nonce)
}

/// Generate a random nonce, optionally prefixed with `"{prefix}."`.
///
/// When `prefix` is empty (single-node mode) the returned nonce is plain base64url.
fn gen_nonce(prefix: &str) -> Result<String, AcmeError> {
    let mut bytes = [0u8; 16];
    native_ossl::rand::Rand::fill(&mut bytes)
        .map_err(|e| AcmeError::Internal(format!("nonce rng: {e}")))?;
    let random = URL_SAFE_NO_PAD.encode(bytes);
    if prefix.is_empty() {
        Ok(random)
    } else {
        Ok(format!("{prefix}.{random}"))
    }
}

/// Build standard ACME response headers using a pre-generated nonce.
///
/// The nonce was already consumed and the new one inserted atomically in
/// `parse_jws` via `state.nonces.consume_and_insert`, so no DB call is needed here.
///
/// `ca_id` selects the Link header for the correct CA directory.  Pass
/// `state.default_ca_id.as_str()` on legacy routes that have no CA context.
pub(crate) fn acme_headers(state: &AppState, ca_id: &str, nonce: &str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    match HeaderValue::from_str(nonce) {
        Ok(v) => {
            headers.insert(HeaderName::from_static("replay-nonce"), v);
        }
        Err(e) => {
            tracing::error!(error = %e, "nonce produced invalid header value; Replay-Nonce header omitted");
        }
    }
    if let Some(link) = state
        .link_headers
        .get(ca_id)
        .or_else(|| state.link_headers.get(state.default_ca_id.as_str()))
    {
        headers.insert(axum::http::header::LINK, (**link).clone());
    } else {
        tracing::error!(
            ca_id,
            "link header missing for CA — ACME Link header omitted"
        );
    }
    headers
}

/// Wrap a JSON response with ACME headers.
///
/// `body` can be any type implementing `Serialize` — both `serde_json::Value`
/// and typed response structs (e.g. `OrderJson`) are accepted.
///
/// `ca_id` selects the per-CA Link header.  Use `state.default_ca_id.as_str()`
/// on legacy handlers that don't yet carry a `CaId` extractor.
///
/// `nonce` must be a fresh nonce already inserted into the DB (use `ctx.next_nonce`
/// from `parse_jws`, or call `new_nonce` for endpoints that do not use `parse_jws`).
pub(crate) fn json_response<T: serde::Serialize>(
    state: &AppState,
    ca_id: &str,
    status: StatusCode,
    body: T,
    nonce: &str,
) -> Result<Response, AcmeError> {
    let headers = acme_headers(state, ca_id, nonce);
    let mut resp = (status, Json(body)).into_response();
    resp.headers_mut().extend(headers);
    resp.headers_mut().insert(
        axum::http::header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    Ok(resp)
}

/// Parse the payload as JSON, return an error if the payload is empty
/// (POST-as-GET is not allowed here).
pub(crate) fn require_payload<T: serde::de::DeserializeOwned>(
    payload: &[u8],
    ctx: &str,
) -> Result<T, AcmeError> {
    if payload.is_empty() {
        return Err(AcmeError::BadRequest(format!(
            "{ctx}: payload is required (not POST-as-GET)"
        )));
    }
    serde_json::from_slice(payload).map_err(|e| AcmeError::BadRequest(format!("{ctx} JSON: {e}")))
}

pub(crate) use crate::util::unix_now;
pub(crate) use crate::util::unix_to_rfc3339 as fmt_time;

/// Return `true` if `value` ends with `.onion` (any case).
///
/// This is a quick syntactic check; the caller is responsible for validating
/// that it is a properly formed v3 address.
pub(crate) fn is_onion_domain(value: &str) -> bool {
    value.to_ascii_lowercase().ends_with(".onion")
}

/// Compute the challenge types offered for an identifier, applying every
/// eligibility rule the server enforces:
/// - RFC 8555 §7.1.3 + RFC 8737 §3: wildcard DNS identifiers MUST NOT use
///   http-01 or tls-alpn-01 — only dns-01 (and dns-persist-01) are valid.
/// - RFC 9799 §3-4: `.onion` identifiers MUST offer onion-csr-01 and MUST
///   NOT offer dns-01; http-01/tls-alpn-01 are only added when the CA has
///   Tor network connectivity.
/// - RFC 9447: tkauth-01 substitutes for the normal dns-01/http-01 set when
///   tkauth is enabled and a dns-SAN claim encoder is configured, and is the
///   only challenge type for token-authority identifier types.
///
/// Shared by both `new-order` (`order.rs`) and pre-authorization
/// (`authz.rs`) so the two entry points cannot offer a different — and
/// potentially non-compliant — challenge set for the same identifier
/// depending on which flow a client uses.
pub(crate) fn eligible_challenge_types(
    id_type: &str,
    id_value: &str,
    state: &AppState,
) -> &'static [&'static str] {
    let dns_persist_enabled = !state.config.dns_persist_issuer_domains().is_empty();
    let dns_types: &[&str] = if dns_persist_enabled {
        &["http-01", "dns-01", "tls-alpn-01", "dns-persist-01"]
    } else {
        &["http-01", "dns-01", "tls-alpn-01"]
    };
    let wildcard_dns_types: &[&str] = if dns_persist_enabled {
        &["dns-01", "dns-persist-01"]
    } else {
        &["dns-01"]
    };
    let onion_types_with_tor: &[&str] = &["onion-csr-01", "http-01", "tls-alpn-01"];
    let onion_types_no_tor: &[&str] = &["onion-csr-01"];
    let onion_types: &[&str] = if state.config.server.tor_connectivity_enabled {
        onion_types_with_tor
    } else {
        onion_types_no_tor
    };
    let tkauth_dns_san_enabled = state.config.tkauth.as_ref().is_some_and(|t| t.enabled)
        && state.claim_encoder_registry.as_ref().is_some_and(|r| {
            r.values()
                .any(|e| e.authorized_identifier_type() == Some("dns"))
        });
    match id_type {
        "dns" if is_onion_domain(id_value) => onion_types,
        "dns" if id_value.starts_with("*.") => wildcard_dns_types,
        "dns" if tkauth_dns_san_enabled => &["tkauth-01"],
        "dns" => dns_types,
        "ip" => &["http-01", "tls-alpn-01"],
        "email" => &["email-reply-00"],
        "TNAuthList" | "JWTClaimConstraints" | "EnhancedJWTClaimConstraints" => &["tkauth-01"],
        _ => &[],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fmt_time_known_epoch() {
        // Unix epoch = 1970-01-01T00:00:00Z
        assert_eq!(fmt_time(0), "1970-01-01T00:00:00Z");
    }

    #[test]
    fn fmt_time_known_date() {
        // 2024-01-01 00:00:00 UTC = 1704067200
        assert_eq!(fmt_time(1_704_067_200), "2024-01-01T00:00:00Z");
    }

    #[test]
    fn unix_now_is_positive() {
        let t = unix_now();
        assert!(t > 0, "unix_now() should return a positive Unix timestamp");
    }

    #[test]
    fn require_payload_empty_returns_error() {
        let result: Result<serde_json::Value, _> = require_payload(b"", "test-ctx");
        assert!(result.is_err());
        match result.unwrap_err() {
            AcmeError::BadRequest(msg) => {
                assert!(msg.contains("test-ctx"));
                assert!(msg.contains("required"));
            }
            other => panic!("expected BadRequest, got {other:?}"),
        }
    }

    #[test]
    fn require_payload_invalid_json_returns_error() {
        let result: Result<serde_json::Value, _> = require_payload(b"not json", "test-ctx");
        assert!(result.is_err());
        match result.unwrap_err() {
            AcmeError::BadRequest(msg) => assert!(msg.contains("test-ctx")),
            other => panic!("expected BadRequest, got {other:?}"),
        }
    }

    #[test]
    fn require_payload_valid_json() {
        let result: Result<serde_json::Value, _> =
            require_payload(b"{\"key\":\"value\"}", "test-ctx");
        assert!(result.is_ok());
    }
}
