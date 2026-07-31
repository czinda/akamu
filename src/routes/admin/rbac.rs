//! Single source of truth for admin route → role enforcement.
//!
//! [`ADMIN_RBAC_TABLE`] drives both the real enforcement (via
//! [`admin_rbac_gate`], applied as middleware over the whole admin router in
//! `build_admin_router()`) and `tests/admin_rbac.rs`'s coverage tests — there
//! is no separate hand-maintained copy for tests to drift out of sync with.
//!
//! A route with no matching table row is denied (fail-closed): forgetting to
//! add a row for a new route makes that route completely inaccessible, which
//! shows up immediately as a test failure, instead of silently shipping
//! ungated.

use std::sync::Arc;

use axum::extract::{MatchedPath, Request, State};
use axum::http::{Method, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;

use crate::admin::auth::resolve_operator_context;
use crate::audit::{AuditEvent, AuditEventType};
use crate::state::{AppState, OperatorRole};

const ALL_ROLES: &[OperatorRole] = &[
    OperatorRole::Administrator,
    OperatorRole::CaOperations,
    OperatorRole::CaRa,
    OperatorRole::Auditor,
];

/// One admin route's role requirement.
pub struct RbacRoute {
    pub method: Method,
    /// Route template exactly as registered in `build_admin_router()`
    /// (e.g. `/admin/certs/{id}`) — matched against
    /// [`axum::extract::MatchedPath`] at request time.
    pub route_template: &'static str,
    /// A concrete path satisfying `route_template`, used by
    /// `tests/admin_rbac.rs` to build real requests (e.g.
    /// `/admin/certs/nonexistent-cert-id`). Equal to `route_template` for
    /// routes with no path parameters.
    pub example_path: &'static str,
    /// Roles allowed to call this route. `None` means the route handles its
    /// own authentication and is not gated here at all (only
    /// `POST /admin/session/eab`, which authenticates via an HMAC over the
    /// request body rather than `OperatorContext`).
    pub allowed_roles: Option<&'static [OperatorRole]>,
}

pub static ADMIN_RBAC_TABLE: &[RbacRoute] = &[
    RbacRoute {
        method: Method::POST,
        route_template: "/admin/session",
        example_path: "/admin/session",
        allowed_roles: Some(ALL_ROLES),
    },
    RbacRoute {
        method: Method::DELETE,
        route_template: "/admin/session",
        example_path: "/admin/session",
        allowed_roles: Some(ALL_ROLES),
    },
    RbacRoute {
        method: Method::POST,
        route_template: "/admin/session/eab",
        example_path: "/admin/session/eab",
        allowed_roles: None,
    },
    RbacRoute {
        method: Method::GET,
        route_template: "/admin/stats",
        example_path: "/admin/stats",
        allowed_roles: Some(ALL_ROLES),
    },
    RbacRoute {
        method: Method::GET,
        route_template: "/admin/eab",
        example_path: "/admin/eab",
        allowed_roles: Some(ALL_ROLES),
    },
    RbacRoute {
        method: Method::POST,
        route_template: "/admin/eab",
        example_path: "/admin/eab",
        // CaRa intentionally excluded: EAB keys are server-global and must
        // not be provisioned by a CA-scoped operator.
        allowed_roles: Some(&[OperatorRole::Administrator, OperatorRole::CaOperations]),
    },
    RbacRoute {
        method: Method::GET,
        route_template: "/admin/eab/{kid}",
        example_path: "/admin/eab/no-such-kid",
        allowed_roles: Some(ALL_ROLES),
    },
    RbacRoute {
        method: Method::DELETE,
        route_template: "/admin/eab/{kid}",
        example_path: "/admin/eab/no-such-kid",
        allowed_roles: Some(&[OperatorRole::Administrator, OperatorRole::CaOperations]),
    },
    RbacRoute {
        method: Method::GET,
        route_template: "/admin/certs",
        example_path: "/admin/certs",
        allowed_roles: Some(&[
            OperatorRole::Administrator,
            OperatorRole::CaOperations,
            OperatorRole::CaRa,
            OperatorRole::Auditor,
        ]),
    },
    RbacRoute {
        method: Method::GET,
        route_template: "/admin/certs/{id}",
        example_path: "/admin/certs/nonexistent-cert-id",
        allowed_roles: Some(ALL_ROLES),
    },
    RbacRoute {
        method: Method::GET,
        route_template: "/admin/certs/{id}/download",
        example_path: "/admin/certs/nonexistent-cert-id/download",
        allowed_roles: Some(&[
            OperatorRole::Administrator,
            OperatorRole::CaOperations,
            OperatorRole::CaRa,
        ]),
    },
    RbacRoute {
        method: Method::POST,
        route_template: "/admin/revoke",
        example_path: "/admin/revoke",
        allowed_roles: Some(&[
            OperatorRole::Administrator,
            OperatorRole::CaOperations,
            OperatorRole::CaRa,
        ]),
    },
    RbacRoute {
        method: Method::GET,
        route_template: "/admin/profiles",
        example_path: "/admin/profiles",
        allowed_roles: Some(ALL_ROLES),
    },
    RbacRoute {
        method: Method::POST,
        route_template: "/admin/profiles",
        example_path: "/admin/profiles",
        allowed_roles: Some(&[OperatorRole::Administrator]),
    },
    RbacRoute {
        method: Method::GET,
        route_template: "/admin/profiles/{id}",
        example_path: "/admin/profiles/nonexistent-id",
        allowed_roles: Some(ALL_ROLES),
    },
    RbacRoute {
        method: Method::PUT,
        route_template: "/admin/profiles/{id}",
        example_path: "/admin/profiles/nonexistent-id",
        allowed_roles: Some(&[OperatorRole::Administrator]),
    },
    RbacRoute {
        method: Method::DELETE,
        route_template: "/admin/profiles/{id}",
        example_path: "/admin/profiles/nonexistent-id",
        allowed_roles: Some(&[OperatorRole::Administrator]),
    },
    RbacRoute {
        method: Method::GET,
        route_template: "/admin/accounts",
        example_path: "/admin/accounts",
        allowed_roles: Some(ALL_ROLES),
    },
    RbacRoute {
        method: Method::GET,
        route_template: "/admin/account/{id}",
        example_path: "/admin/account/1",
        allowed_roles: Some(ALL_ROLES),
    },
    RbacRoute {
        method: Method::POST,
        route_template: "/admin/account/{id}/deactivate",
        example_path: "/admin/account/1/deactivate",
        allowed_roles: Some(&[OperatorRole::Administrator]),
    },
    RbacRoute {
        method: Method::GET,
        route_template: "/admin/account/{id}/profile-grants",
        example_path: "/admin/account/1/profile-grants",
        allowed_roles: Some(ALL_ROLES),
    },
    RbacRoute {
        method: Method::PUT,
        route_template: "/admin/account/{id}/profile-grants",
        example_path: "/admin/account/1/profile-grants",
        allowed_roles: Some(&[OperatorRole::Administrator, OperatorRole::CaOperations]),
    },
    RbacRoute {
        method: Method::DELETE,
        route_template: "/admin/account/{id}/profile-grants",
        example_path: "/admin/account/1/profile-grants",
        allowed_roles: Some(&[OperatorRole::Administrator]),
    },
    RbacRoute {
        method: Method::GET,
        route_template: "/admin/operators",
        example_path: "/admin/operators",
        allowed_roles: Some(&[OperatorRole::Administrator]),
    },
    RbacRoute {
        method: Method::POST,
        route_template: "/admin/operators",
        example_path: "/admin/operators",
        allowed_roles: Some(&[OperatorRole::Administrator]),
    },
    RbacRoute {
        method: Method::GET,
        route_template: "/admin/operators/{id}",
        example_path: "/admin/operators/1",
        allowed_roles: Some(&[OperatorRole::Administrator]),
    },
    RbacRoute {
        method: Method::PUT,
        route_template: "/admin/operators/{id}",
        example_path: "/admin/operators/1",
        allowed_roles: Some(&[OperatorRole::Administrator]),
    },
    RbacRoute {
        method: Method::PATCH,
        route_template: "/admin/operators/{id}",
        example_path: "/admin/operators/1",
        allowed_roles: Some(&[OperatorRole::Administrator]),
    },
    RbacRoute {
        method: Method::POST,
        route_template: "/admin/operators/{id}/unlock",
        example_path: "/admin/operators/1/unlock",
        allowed_roles: Some(&[OperatorRole::Administrator]),
    },
    RbacRoute {
        method: Method::GET,
        route_template: "/admin/audit",
        example_path: "/admin/audit",
        allowed_roles: Some(&[OperatorRole::Administrator, OperatorRole::Auditor]),
    },
    RbacRoute {
        method: Method::GET,
        route_template: "/admin/orders",
        example_path: "/admin/orders",
        allowed_roles: Some(ALL_ROLES),
    },
    RbacRoute {
        method: Method::GET,
        route_template: "/admin/orders/{id}",
        example_path: "/admin/orders/nonexistent-order-id",
        allowed_roles: Some(ALL_ROLES),
    },
    RbacRoute {
        method: Method::GET,
        route_template: "/admin/delegations",
        example_path: "/admin/delegations",
        allowed_roles: Some(ALL_ROLES),
    },
    RbacRoute {
        method: Method::POST,
        route_template: "/admin/delegations",
        example_path: "/admin/delegations",
        allowed_roles: Some(&[OperatorRole::Administrator, OperatorRole::CaOperations]),
    },
    RbacRoute {
        method: Method::GET,
        route_template: "/admin/delegations/{id}",
        example_path: "/admin/delegations/nonexistent-id",
        allowed_roles: Some(ALL_ROLES),
    },
    RbacRoute {
        method: Method::PUT,
        route_template: "/admin/delegations/{id}",
        example_path: "/admin/delegations/nonexistent-id",
        allowed_roles: Some(&[OperatorRole::Administrator, OperatorRole::CaOperations]),
    },
    RbacRoute {
        method: Method::DELETE,
        route_template: "/admin/delegations/{id}",
        example_path: "/admin/delegations/nonexistent-id",
        allowed_roles: Some(&[OperatorRole::Administrator, OperatorRole::CaOperations]),
    },
    RbacRoute {
        method: Method::GET,
        route_template: "/admin/policy/scopes",
        example_path: "/admin/policy/scopes",
        allowed_roles: Some(&[
            OperatorRole::Administrator,
            OperatorRole::CaOperations,
            OperatorRole::Auditor,
        ]),
    },
    RbacRoute {
        method: Method::GET,
        route_template: "/admin/policy/rules",
        example_path: "/admin/policy/rules",
        allowed_roles: Some(&[
            OperatorRole::Administrator,
            OperatorRole::CaOperations,
            OperatorRole::Auditor,
        ]),
    },
    RbacRoute {
        method: Method::POST,
        route_template: "/admin/policy/rules",
        example_path: "/admin/policy/rules",
        allowed_roles: Some(&[OperatorRole::Administrator, OperatorRole::CaOperations]),
    },
    RbacRoute {
        method: Method::GET,
        route_template: "/admin/policy/rules/{id}",
        example_path: "/admin/policy/rules/nonexistent-id",
        allowed_roles: Some(&[
            OperatorRole::Administrator,
            OperatorRole::CaOperations,
            OperatorRole::Auditor,
        ]),
    },
    RbacRoute {
        method: Method::PUT,
        route_template: "/admin/policy/rules/{id}",
        example_path: "/admin/policy/rules/nonexistent-id",
        allowed_roles: Some(&[OperatorRole::Administrator, OperatorRole::CaOperations]),
    },
    RbacRoute {
        method: Method::DELETE,
        route_template: "/admin/policy/rules/{id}",
        example_path: "/admin/policy/rules/nonexistent-id",
        allowed_roles: Some(&[OperatorRole::Administrator, OperatorRole::CaOperations]),
    },
    RbacRoute {
        method: Method::GET,
        route_template: "/admin/config",
        example_path: "/admin/config",
        allowed_roles: Some(&[OperatorRole::Administrator]),
    },
    RbacRoute {
        method: Method::POST,
        route_template: "/admin/crl/force",
        example_path: "/admin/crl/force",
        allowed_roles: Some(&[OperatorRole::Administrator, OperatorRole::CaOperations]),
    },
    RbacRoute {
        method: Method::POST,
        route_template: "/admin/tkauth/prune-jti",
        example_path: "/admin/tkauth/prune-jti",
        allowed_roles: Some(&[OperatorRole::Administrator, OperatorRole::CaOperations]),
    },
    RbacRoute {
        method: Method::GET,
        route_template: "/admin/cas",
        example_path: "/admin/cas",
        allowed_roles: Some(&[OperatorRole::Administrator, OperatorRole::CaOperations]),
    },
    RbacRoute {
        method: Method::GET,
        route_template: "/admin/cas/{id}",
        example_path: "/admin/cas/default",
        allowed_roles: Some(&[OperatorRole::Administrator, OperatorRole::CaOperations]),
    },
    RbacRoute {
        method: Method::GET,
        route_template: "/admin/cas/{id}/cert",
        example_path: "/admin/cas/default/cert",
        allowed_roles: Some(&[OperatorRole::Administrator, OperatorRole::CaOperations]),
    },
    RbacRoute {
        method: Method::POST,
        route_template: "/admin/ca/{id}/crl/force",
        example_path: "/admin/ca/default/crl/force",
        allowed_roles: Some(&[OperatorRole::Administrator, OperatorRole::CaOperations]),
    },
    RbacRoute {
        method: Method::POST,
        route_template: "/admin/ca/{id}/cross-sign",
        example_path: "/admin/ca/default/cross-sign",
        allowed_roles: Some(&[OperatorRole::Administrator, OperatorRole::CaOperations]),
    },
    RbacRoute {
        method: Method::GET,
        route_template: "/admin/cross-certs",
        example_path: "/admin/cross-certs",
        allowed_roles: Some(&[
            OperatorRole::Administrator,
            OperatorRole::CaOperations,
            OperatorRole::Auditor,
        ]),
    },
    RbacRoute {
        method: Method::GET,
        route_template: "/admin/cross-certs/{id}",
        example_path: "/admin/cross-certs/nonexistent-id",
        allowed_roles: Some(&[
            OperatorRole::Administrator,
            OperatorRole::CaOperations,
            OperatorRole::Auditor,
        ]),
    },
    RbacRoute {
        method: Method::GET,
        route_template: "/admin/mtc/tree-size",
        example_path: "/admin/mtc/tree-size",
        allowed_roles: Some(&[
            OperatorRole::Administrator,
            OperatorRole::CaOperations,
            OperatorRole::Auditor,
        ]),
    },
    RbacRoute {
        method: Method::GET,
        route_template: "/admin/mtc/root",
        example_path: "/admin/mtc/root",
        allowed_roles: Some(&[
            OperatorRole::Administrator,
            OperatorRole::CaOperations,
            OperatorRole::Auditor,
        ]),
    },
    RbacRoute {
        method: Method::GET,
        route_template: "/admin/mtc/landmarks",
        example_path: "/admin/mtc/landmarks",
        allowed_roles: Some(&[
            OperatorRole::Administrator,
            OperatorRole::CaOperations,
            OperatorRole::Auditor,
        ]),
    },
    RbacRoute {
        method: Method::GET,
        route_template: "/admin/mtc/landmark-list",
        example_path: "/admin/mtc/landmark-list",
        allowed_roles: Some(&[
            OperatorRole::Administrator,
            OperatorRole::CaOperations,
            OperatorRole::Auditor,
        ]),
    },
    RbacRoute {
        method: Method::GET,
        route_template: "/admin/mtc/inclusion-proof/{cert_id}",
        example_path: "/admin/mtc/inclusion-proof/nonexistent-cert-id",
        allowed_roles: Some(&[
            OperatorRole::Administrator,
            OperatorRole::CaOperations,
            OperatorRole::Auditor,
        ]),
    },
    RbacRoute {
        method: Method::GET,
        route_template: "/admin/mtc/standalone/{cert_id}",
        example_path: "/admin/mtc/standalone/nonexistent-cert-id",
        allowed_roles: Some(&[OperatorRole::Administrator, OperatorRole::CaOperations]),
    },
    RbacRoute {
        method: Method::GET,
        route_template: "/admin/mtc/landmarks/{seq}/cert",
        example_path: "/admin/mtc/landmarks/0/cert",
        allowed_roles: Some(&[OperatorRole::Administrator, OperatorRole::CaOperations]),
    },
    RbacRoute {
        method: Method::GET,
        route_template: "/admin/mtc/landmarks/{seq}/cert-details",
        example_path: "/admin/mtc/landmarks/0/cert-details",
        allowed_roles: Some(&[
            OperatorRole::Administrator,
            OperatorRole::CaOperations,
            OperatorRole::Auditor,
        ]),
    },
    RbacRoute {
        method: Method::GET,
        route_template: "/admin/mtc/consistency-proof",
        example_path: "/admin/mtc/consistency-proof",
        allowed_roles: Some(&[
            OperatorRole::Administrator,
            OperatorRole::CaOperations,
            OperatorRole::Auditor,
        ]),
    },
    RbacRoute {
        method: Method::GET,
        route_template: "/admin/mtc/subtree-root",
        example_path: "/admin/mtc/subtree-root",
        allowed_roles: Some(&[
            OperatorRole::Administrator,
            OperatorRole::CaOperations,
            OperatorRole::Auditor,
        ]),
    },
    RbacRoute {
        method: Method::GET,
        route_template: "/admin/mtc/revoked-ranges",
        example_path: "/admin/mtc/revoked-ranges",
        allowed_roles: Some(&[
            OperatorRole::Administrator,
            OperatorRole::CaOperations,
            OperatorRole::Auditor,
        ]),
    },
    RbacRoute {
        method: Method::GET,
        route_template: "/admin/mtc/checkpoint",
        example_path: "/admin/mtc/checkpoint",
        allowed_roles: Some(&[
            OperatorRole::Administrator,
            OperatorRole::CaOperations,
            OperatorRole::Auditor,
        ]),
    },
    RbacRoute {
        method: Method::GET,
        route_template: "/admin/mtc/cosignature",
        example_path: "/admin/mtc/cosignature",
        allowed_roles: Some(&[
            OperatorRole::Administrator,
            OperatorRole::CaOperations,
            OperatorRole::Auditor,
        ]),
    },
    RbacRoute {
        method: Method::POST,
        route_template: "/admin/ca/{id}/mtc/force-checkpoint",
        example_path: "/admin/ca/default/mtc/force-checkpoint",
        allowed_roles: Some(&[OperatorRole::Administrator, OperatorRole::CaOperations]),
    },
    RbacRoute {
        method: Method::POST,
        route_template: "/admin/ca/{id}/mtc/force-landmark",
        example_path: "/admin/ca/default/mtc/force-landmark",
        allowed_roles: Some(&[OperatorRole::Administrator, OperatorRole::CaOperations]),
    },
    RbacRoute {
        method: Method::GET,
        route_template: "/admin/ca/{id}/mtc/log-list-entry",
        example_path: "/admin/ca/default/mtc/log-list-entry",
        allowed_roles: Some(&[
            OperatorRole::Administrator,
            OperatorRole::CaOperations,
            OperatorRole::Auditor,
        ]),
    },
    RbacRoute {
        method: Method::GET,
        route_template: "/admin/gossip/status",
        example_path: "/admin/gossip/status",
        allowed_roles: Some(ALL_ROLES),
    },
    RbacRoute {
        method: Method::POST,
        route_template: "/admin/gossip/register",
        example_path: "/admin/gossip/register",
        allowed_roles: Some(&[OperatorRole::Administrator]),
    },
];

/// Middleware enforcing [`ADMIN_RBAC_TABLE`] over the whole admin router.
///
/// Resolves the operator via `resolve_operator_context` at most once per
/// request (never via the `OperatorContext` extractor directly at this
/// point, since several auth paths have side effects — session creation,
/// rate-limit bookkeeping, audit events — that must not run twice), then
/// either denies with the same audit-logged 403 that `require_role!` used to
/// produce, or inserts the resolved `OperatorContext` into the request
/// extensions so the handler's own `operator: OperatorContext` parameter
/// picks it up for free (see `OperatorContext::from_request_parts`).
pub async fn admin_rbac_gate(
    State(state): State<Arc<AppState>>,
    req: Request,
    next: Next,
) -> Response {
    let method = req.method().clone();
    let matched_path = req
        .extensions()
        .get::<MatchedPath>()
        .map(|p| p.as_str().to_owned());

    let Some(path) = matched_path else {
        tracing::error!(%method, "admin_rbac_gate: no MatchedPath extension — denying");
        return forbidden("request did not resolve to a known route");
    };

    let Some(row) = ADMIN_RBAC_TABLE
        .iter()
        .find(|r| r.method == method && r.route_template == path)
    else {
        tracing::error!(%method, path, "admin route missing ADMIN_RBAC_TABLE entry — denying");
        return forbidden("route not covered by RBAC table");
    };

    let Some(allowed) = row.allowed_roles else {
        // e.g. POST /admin/session/eab: authenticates via a body HMAC, not
        // OperatorContext — the handler does its own auth entirely.
        return next.run(req).await;
    };

    let (mut parts, body) = req.into_parts();
    let operator = match resolve_operator_context(&mut parts, &state).await {
        Ok(op) => op,
        Err(resp) => return resp,
    };

    if !allowed.contains(&operator.role) {
        let required = allowed
            .iter()
            .map(|r| r.as_str())
            .collect::<Vec<_>>()
            .join(" | ");
        state
            .record_audit(
                AuditEvent::failure(AuditEventType::AdminAction)
                    .with_principal(operator.name.clone())
                    .with_detail(
                        json!({
                            "error": "insufficient role",
                            "required": required,
                            "actual": operator.role.as_str(),
                        })
                        .to_string(),
                    ),
            )
            .await;
        return forbidden("insufficient role for this operation");
    }

    parts.extensions.insert(operator);
    next.run(Request::from_parts(parts, body)).await
}

fn forbidden(detail: &str) -> Response {
    (
        StatusCode::FORBIDDEN,
        Json(json!({"status": 403, "detail": detail})),
    )
        .into_response()
}
