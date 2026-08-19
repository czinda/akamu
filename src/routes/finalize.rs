//! POST /acme/order/{id}/finalize — RFC 8555 §7.4

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::Response;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::Deserialize;

use synta::{Decoder, Encoding};
use synta_certificate::{der_to_pem, format_dn, Certificate};

use crate::ca;
use crate::crdt_hooks;
use crate::db;
use crate::db::schema::CertificateRow;
use crate::error::AcmeError;
use crate::state::AppState;
use crate::status::{AuthzStatus, CertStatus, OrderStatus};
use crate::validation::claim_encoder::EncodedSan;

use super::order::order_json;
use super::{acme_prefix, json_response, parse_jws, require_payload, unix_now, CaId};

#[derive(Deserialize)]
struct FinalizePayload {
    csr: String, // base64url-encoded DER
}

pub async fn finalize_order(
    State(state): State<Arc<AppState>>,
    ca_id: CaId,
    Path(params): Path<std::collections::HashMap<String, String>>,
    body: Bytes,
) -> Result<Response, AcmeError> {
    let id = params.get("id").ok_or(AcmeError::NotFound)?.clone();
    let (ctx, account_id, order, csr_der) =
        resolve_order_and_authorize(&state, &ca_id.0, &id, body).await?;

    // Best-effort cross-node duplicate-issuance guard: claim exclusive
    // processing ownership of this order before doing any issuance work.
    // This is a local CRDT write that gossips out asynchronously — it can
    // still diverge across a network partition (both sides may claim the
    // same order), which is a known, documented, accepted residual risk
    // (see docs/src/admin/cluster.md's Network Partition Behavior section).
    // Re-claiming your own live claim always succeeds, so a node retrying
    // its own finalize is never blocked by this.
    {
        let ttl = state
            .config
            .gossip
            .as_ref()
            .map(|g| g.ownership_ttl_secs as i64)
            .unwrap_or(150);
        let claimed =
            state
                .crdt
                .write()
                .await
                .claim_order(&order.id, &state.node_id, unix_now(), ttl);
        if !claimed {
            return Err(AcmeError::Conflict(
                "order is currently being processed by another node".into(),
            ));
        }
    }

    // Parse order identifiers.
    let identifiers: Vec<serde_json::Value> = serde_json::from_str(&order.identifiers)
        .map_err(|e| AcmeError::Internal(format!("corrupt identifiers in order {id}: {e}")))?;
    let allowed: Vec<(&str, &str)> = identifiers
        .iter()
        .filter_map(|id| {
            let t = id["type"].as_str()?;
            let v = id["value"].as_str()?;
            Some((t, v))
        })
        .collect();

    // Resolve the CA for this order.  Done early so that profile resolution and
    // authorization checks can run before the expensive CSR and CAA operations.
    let order_ca = state.get_ca(&order.ca_id).ok_or_else(|| {
        AcmeError::Internal(format!("order references unknown CA '{}'", order.ca_id))
    })?;

    // Resolve certificate parameters from the profile registry and run
    // per-profile authorization checks BEFORE validate_csr and CAA so that
    // auth failures are returned without revealing whether the CSR was
    // structurally valid (no timing oracle for identifier-namespace probing).
    let (cert_params, default_profile_applied) = resolve_cert_params(&state, &order, order_ca)?;

    let (validated_csr, extra_other_names) = run_profile_and_csr_checks(
        &state,
        &account_id,
        &order,
        &cert_params,
        default_profile_applied,
        &allowed,
        &csr_der,
    )
    .await?;

    if let Some(resp) = maybe_handle_upstream_delegation(
        &state,
        ctx.jwk_thumbprint.as_deref(),
        &ctx.next_nonce,
        &order,
        &id,
        &csr_der,
    )
    .await?
    {
        return Ok(resp);
    }

    check_caa_for_order(&state, order_ca, &id, &account_id, &allowed).await?;

    let (extra_other_names, extra_dns_names, not_after) = inject_template_and_tkauth_sans(
        &state,
        SanInjectionParams {
            order_id: &id,
            account_id: &account_id,
            cert_params: &cert_params,
            validated_csr: &validated_csr,
            allowed: &allowed,
            order_not_after: order.not_after,
            extra_other_names,
        },
    )
    .await?;

    let issued = issue_leaf_certificate(
        &state,
        order_ca,
        IssueLeafParams {
            cert_params: &cert_params,
            csr_der: &csr_der,
            validated_csr: &validated_csr,
            not_before: order.not_before,
            not_after,
            extra_other_names: &extra_other_names,
            extra_dns_names: &extra_dns_names,
        },
    )
    .await?;

    let (final_cert_der, final_cert_pem, final_mtc_index, mtc_standalone_pending) =
        build_mtc_outputs(&state, order_ca, cert_params.issue_as_mtc, &issued).await?;

    // Extract subject DN from the leaf cert for searchability (FAU_SCR_EXT.1).
    let subject_dn = extract_subject_dn(&issued.cert_der);

    let now = unix_now();

    let (pred_already_replaced, cert_id, authz_ids) = persist_certificate(
        &state,
        PersistCertificateParams {
            order: &order,
            order_id: &id,
            account_id: &account_id,
            issued: &issued,
            final_cert_der,
            final_cert_pem,
            final_mtc_index,
            subject_dn,
            csr_der: &csr_der,
            now,
        },
    )
    .await?;

    let principal = format!("acme:{}", ctx.jwk_thumbprint.as_deref().unwrap_or(""));
    state
        .record_audit_pair(
            crate::audit::AuditEvent::success(crate::audit::AuditEventType::OrderFinalize)
                .with_subject(&id)
                .with_principal(&principal),
            crate::audit::AuditEvent::success(crate::audit::AuditEventType::CertIssue)
                .with_subject(&issued.serial_hex)
                .with_principal(&principal),
        )
        .await;

    // RFC 9773 §5: return 409 alreadyReplaced if another order concurrently
    // replaced the same predecessor certificate during this finalization.
    if pred_already_replaced {
        return Err(AcmeError::CertAlreadyReplaced);
    }

    // Persist standalone DER built by the synchronous MTC sequencing path.
    // This is separate from the DB transaction because set_mtc_standalone_der
    // is a non-critical update — the cert row already has the log index.
    if let Some(standalone_der) = mtc_standalone_pending {
        if let Err(e) =
            db::certs::set_mtc_standalone_der(&state.db, &cert_id, &standalone_der).await
        {
            tracing::error!(cert_id = %cert_id, "store standalone DER: {e}");
        }
    }

    // Build the response from the known post-finalize state without a DB re-fetch.
    let mut updated_order = order;
    updated_order.status = OrderStatus::Valid.as_str().to_string();
    updated_order.certificate_id = Some(issued.id.clone());
    updated_order.updated = now;

    emit_crdt_hooks(
        &state,
        &cert_id,
        &id,
        &account_id,
        &issued,
        &updated_order,
        now,
    )
    .await;

    let order_pfx = acme_prefix(
        &state.config.base_url,
        &updated_order.ca_id,
        &state.default_ca_id,
    );
    let authz_urls: Vec<_> = authz_ids
        .iter()
        .map(|aid| format!("{order_pfx}/authz/{aid}"))
        .collect();

    json_response(
        &state,
        &updated_order.ca_id,
        StatusCode::OK,
        order_json(&updated_order, &authz_urls, &order_pfx),
        &ctx.next_nonce,
    )
}

/// Synchronously append a certificate to the MTC log (§9 sequencing).
///
/// Returns the log index.  The standalone DER is not built here; it is built
/// by `produce_checkpoint` so that cosignatures from configured cosigners are
/// included.  Building it eagerly with `cosignature_ders: &[]` would cause the
/// standalone DER to be stored without cosignatures and then skipped by
/// `produce_checkpoint`'s `mtc_standalone_der IS NULL` filter.
async fn append_and_build_standalone(
    state: &AppState,
    order_ca: &Arc<crate::state::CaState>,
    issued: &crate::ca::issue::IssuedCert,
) -> Result<(i64, Option<Vec<u8>>), AcmeError> {
    let (idx, _proof, _tree_size) =
        append_leaf_locally_or_forward(state, order_ca, &issued.cert_der, &issued.serial_hex)
            .await?;

    Ok((idx as i64, None))
}

/// Append a certificate's leaf to `order_ca`'s MTC log — locally if this node
/// is (or becomes) the elected writer for it, otherwise by forwarding to
/// whichever node currently holds the election (`gossip::mtc_forward`).
///
/// The MTC log is a local, per-node disk file; only the elected writer may
/// append to it without forking the transparency log across nodes. For a
/// single-node deployment this node is always its own uncontested writer,
/// so the fast path below is the only one ever taken — zero forwarding
/// overhead, identical behavior to before this existed.
async fn append_leaf_locally_or_forward(
    state: &AppState,
    order_ca: &Arc<crate::state::CaState>,
    cert_der: &[u8],
    serial_hex: &str,
) -> Result<(u64, Vec<Vec<u8>>, u64), AcmeError> {
    let ca_id = &order_ca.id;
    let now = unix_now();
    let ttl = state
        .config
        .gossip
        .as_ref()
        .map(|g| g.ownership_ttl_secs as i64)
        .unwrap_or(150);

    if state
        .crdt
        .read()
        .await
        .is_mtc_writer(ca_id, &state.node_id, now, ttl)
    {
        return append_leaf_locally(order_ca, cert_der).await;
    }

    // No live writer at all for this CA yet (fresh/idle): claim it and
    // proceed locally — the common case for the first finalize of a given
    // CA, or after the incumbent's lease has lapsed.
    let self_claimed = {
        let mut crdt = state.crdt.write().await;
        if crdt.mtc_writer_claimant(ca_id).is_none() {
            crdt.claim_mtc_writer(ca_id, &state.node_id, now, ttl)
        } else {
            false
        }
    };
    if self_claimed {
        return append_leaf_locally(order_ca, cert_der).await;
    }

    // Someone else holds the election — forward, retrying once against a
    // fresher hint if the election has moved on since our last CRDT view.
    let mut writer_node_id = state
        .crdt
        .read()
        .await
        .mtc_writer_claimant(ca_id)
        .map(str::to_owned);
    let mut last_err = None;
    for _ in 0..2 {
        let Some(node_id) = writer_node_id.clone() else {
            return Err(AcmeError::ServiceUnavailable(format!(
                "no MTC writer known for CA '{ca_id}'; retry finalize"
            )));
        };
        let writer_url = {
            let crdt = state.crdt.read().await;
            crdt.cluster_nodes
                .get(&node_id)
                .map(|n| n.gossip_url.clone())
        };
        let Some(writer_url) = writer_url else {
            return Err(AcmeError::ServiceUnavailable(format!(
                "MTC writer '{node_id}' for CA '{ca_id}' is not a known cluster node"
            )));
        };
        match crate::gossip::mtc_forward::forward_append(
            state,
            ca_id,
            &node_id,
            &writer_url,
            cert_der,
            serial_hex,
        )
        .await?
        {
            crate::gossip::mtc_forward::ForwardOutcome::Success(s) => {
                return Ok((s.leaf_index, s.proof, s.tree_size))
            }
            crate::gossip::mtc_forward::ForwardOutcome::NotWriter { current_writer } => {
                writer_node_id = current_writer.map(|(id, _)| id);
                last_err = Some(AcmeError::ServiceUnavailable(format!(
                    "MTC writer for CA '{ca_id}' changed during forward; retry finalize"
                )));
            }
        }
    }
    Err(last_err.unwrap_or_else(|| {
        AcmeError::ServiceUnavailable(format!(
            "MTC writer election for CA '{ca_id}' unresolved after retry"
        ))
    }))
}

async fn append_leaf_locally(
    order_ca: &Arc<crate::state::CaState>,
    cert_der: &[u8],
) -> Result<(u64, Vec<Vec<u8>>, u64), AcmeError> {
    let ca_mtc = &order_ca.mtc;
    let log = ca_mtc
        .log
        .as_ref()
        .ok_or_else(|| AcmeError::Mtc("MTC log not configured".into()))?;
    let logid_dn = ca_mtc.logid_issuer_dn_der.clone().ok_or_else(|| {
        AcmeError::Mtc("logid_issuer_dn_der not configured; MTC signing key required".into())
    })?;
    let idx =
        crate::mtc::log::append_cert_to_log(log, cert_der.to_vec(), logid_dn, ca_mtc.algorithm)
            .await
            .map_err(|e| AcmeError::Mtc(format!("MTC log append: {e}")))?;
    let (proof, tree_size) = crate::mtc::log::proof_and_tree_size(log, idx)
        .await
        .map_err(|e| AcmeError::Mtc(format!("MTC inclusion proof: {e}")))?;
    Ok((idx, proof, tree_size))
}

/// Extract the RFC 4514 subject DN from a DER-encoded leaf cert, for
/// searchability (FAU_SCR_EXT.1). Returns `None` if the DER fails to parse
/// (should not happen for a cert just issued locally, but this is a
/// non-critical enrichment field, not worth failing finalize over).
fn extract_subject_dn(cert_der: &[u8]) -> Option<String> {
    let mut dec = Decoder::new(cert_der, Encoding::Der);
    dec.decode::<Certificate>()
        .ok()
        .map(|cert| format_dn(cert.tbs_certificate.subject.as_bytes()))
}

/// Emit CRDT gossip hooks for the newly-issued certificate and finalized order.
async fn emit_crdt_hooks(
    state: &AppState,
    cert_id: &str,
    order_id: &str,
    account_id: &str,
    issued: &ca::issue::IssuedCert,
    updated_order: &db::schema::OrderRow,
    now: i64,
) {
    crdt_hooks::on_cert_upsert(
        state,
        crdt_hooks::CertUpsertParams {
            id: cert_id,
            order_id,
            account_id,
            serial_number: &issued.serial_hex,
            status: CertStatus::Valid,
            not_before: issued.not_before,
            not_after: issued.not_after,
            revoked_at: None,
            revocation_reason: None,
            created: now,
            ca_id: &updated_order.ca_id,
        },
    )
    .await;
    crdt_hooks::on_order_upsert(
        state,
        crdt_hooks::OrderUpsertParams {
            id: order_id,
            account_id: &updated_order.account_id,
            status: OrderStatus::Valid,
            expires: updated_order.expires,
            identifiers: &updated_order.identifiers,
            not_before: updated_order.not_before,
            not_after: updated_order.not_after,
            error: updated_order.error.clone(),
            certificate_id: Some(cert_id.to_string()),
            created: updated_order.created,
            updated: now,
            ca_id: &updated_order.ca_id,
        },
    )
    .await;
}

/// CAA check (RFC 8659 + RFC 8657): only when caa_identities is configured.
/// Per-CA identities take precedence; fall back to server-level when the CA
/// does not override them (matching the behaviour in directory.rs). The
/// authz lookup is deferred inside this function so that deployments
/// without CAA pay zero extra DB round-trips during finalization. The
/// account URL is constructed here and passed to check_caa for RFC 8657 §4
/// accounturi enforcement.
async fn check_caa_for_order(
    state: &AppState,
    order_ca: &crate::state::CaState,
    order_id: &str,
    account_id: &str,
    allowed: &[(&str, &str)],
) -> Result<(), AcmeError> {
    let effective_caa: &[String] = if !order_ca.caa_identities.is_empty() {
        &order_ca.caa_identities
    } else {
        &state.config.server.caa_identities
    };
    if effective_caa.is_empty() {
        return Ok(());
    }

    // Build identifier → authz_id map to look up the validated challenge type
    // for each authorization (RFC 8657 validationmethods check).
    let authz_rows = db::authz::list_by_order(&state.db_ro, order_id).await?;
    let mut identifier_to_authz: std::collections::HashMap<(String, String), String> =
        std::collections::HashMap::new();
    for authz in &authz_rows {
        if let Ok(id_obj) = serde_json::from_str::<serde_json::Value>(&authz.identifier) {
            if let (Some(t), Some(v)) = (id_obj["type"].as_str(), id_obj["value"].as_str()) {
                identifier_to_authz.insert((t.to_string(), v.to_string()), authz.id.clone());
                // RFC 9444 §5: an ancestor authz with subdomainAuthAllowed
                // covers all descendant subdomains; record the mapping for
                // each order identifier that is a subdomain of this authz.
                if authz.subdomain_auth_allowed != 0 && t == "dns" {
                    for (id_type, id_value) in allowed {
                        if *id_type == "dns" && *id_value != v {
                            let suffix = format!(".{v}");
                            let bare = id_value.strip_prefix("*.").unwrap_or(id_value);
                            if bare.ends_with(&suffix) {
                                identifier_to_authz
                                    .entry((id_type.to_string(), id_value.to_string()))
                                    .or_insert_with(|| authz.id.clone());
                            }
                        }
                    }
                }
            }
        }
    }

    // Batch-fetch the validated challenge type for every authz referenced
    // above in one query instead of one round trip per dns identifier.
    let referenced_authz_ids: Vec<&str> =
        identifier_to_authz.values().map(String::as_str).collect();
    let validated_types =
        db::challenges::get_validated_types_for_authzs(&state.db_ro, &referenced_authz_ids).await?;

    // Account URL is intentionally server-scoped (not per-CA): RFC 8657
    // accounturi refers to the ACME account resource, which is shared
    // across all CAs in server-scoped mode.
    let account_url = format!("{}/acme/account/{account_id}", state.config.base_url);

    // Collect each dns identifier's CAA-check inputs up front so the
    // lookups themselves (independent DNS queries) can run concurrently
    // below instead of one at a time.
    let mut caa_inputs: Vec<(String, bool, String)> = Vec::new();
    for (id_type, id_value) in allowed {
        if *id_type != "dns" {
            continue; // IP identifiers: CAA is not applicable per RFC 8659.
        }
        let is_wildcard = id_value.starts_with("*.");
        let domain = if is_wildcard {
            id_value[2..].to_string()
        } else {
            id_value.to_string()
        };
        let challenge_type =
            match identifier_to_authz.get(&(id_type.to_string(), id_value.to_string())) {
                Some(authz_id) => validated_types.get(authz_id).cloned().ok_or_else(|| {
                    AcmeError::Internal(format!(
                        "no validated challenge type found for authz {authz_id}"
                    ))
                })?,
                None => String::new(),
            };
        caa_inputs.push((domain, is_wildcard, challenge_type));
    }

    let checks = caa_inputs
        .iter()
        .map(|(domain, is_wildcard, challenge_type)| {
            crate::validation::caa::check_caa(
                crate::validation::caa::CaaParams {
                    domain,
                    ca_identities: effective_caa,
                    is_wildcard: *is_wildcard,
                    challenge_type,
                    account_url: Some(account_url.as_str()),
                    validate_dnssec: state.config.server.validate_dnssec,
                    dot_server_name: state.config.server.dns_dot_server_name.as_deref(),
                },
                state.config.server.dns_resolver_addr.as_deref(),
            )
        });
    futures_util::future::try_join_all(checks).await?;
    Ok(())
}

/// RFC 9115 upstream delegation: when an upstream CA is configured, hand the
/// order to the delegation_upstream background task instead of issuing
/// locally. Returns `Some(response)` when the order was handed off (the
/// caller must return this response immediately), or `None` to continue
/// with local issuance.
async fn maybe_handle_upstream_delegation(
    state: &AppState,
    jwk_thumbprint: Option<&str>,
    next_nonce: &str,
    order: &db::schema::OrderRow,
    order_id: &str,
    csr_der: &[u8],
) -> Result<Option<Response>, AcmeError> {
    if !(state.config.delegation_upstream.is_some() && order.delegation_id.is_some()) {
        return Ok(None);
    }

    let now = unix_now();
    db::orders::set_processing_with_csr_der(&state.db, order_id, csr_der, now).await?;

    let principal = format!("acme:{}", jwk_thumbprint.unwrap_or(""));
    state
        .record_audit(
            crate::audit::AuditEvent::success(crate::audit::AuditEventType::OrderFinalize)
                .with_subject(order_id)
                .with_principal(&principal),
        )
        .await;

    let mut processing_order = order.clone();
    processing_order.status = "processing".to_string();
    processing_order.updated = now;

    let order_pfx = acme_prefix(
        &state.config.base_url,
        &processing_order.ca_id,
        &state.default_ca_id,
    );
    let authz_ids = db::orders::list_authz_ids(&state.db_ro, order_id).await?;
    let authz_urls: Vec<_> = authz_ids
        .iter()
        .map(|aid| format!("{order_pfx}/authz/{aid}"))
        .collect();

    let mut resp = json_response(
        state,
        &processing_order.ca_id,
        StatusCode::OK,
        order_json(&processing_order, &authz_urls, &order_pfx),
        next_nonce,
    )?;
    resp.headers_mut().insert(
        axum::http::header::RETRY_AFTER,
        axum::http::HeaderValue::from_static("5"),
    );
    Ok(Some(resp))
}

/// Parse and verify the finalize JWS, resolve and authorize the target
/// order, and decode the CSR DER from the finalize payload. Bundles the
/// initial guard phase of `finalize_order`: any failure here means the
/// request never reaches CSR/CAA/policy validation or issuance.
async fn resolve_order_and_authorize(
    state: &AppState,
    ca_id: &str,
    order_id: &str,
    body: Bytes,
) -> Result<(super::JwsContext, String, db::schema::OrderRow, Vec<u8>), AcmeError> {
    let pfx = acme_prefix(&state.config.base_url, ca_id, &state.default_ca_id);
    let url = format!("{pfx}/order/{order_id}/finalize");
    let ctx = parse_jws(state, body, &url).await?;

    let account_id = ctx
        .account_id
        .clone()
        .ok_or(AcmeError::Unauthorized("kid required".into()))?;

    let order = db::orders::get_by_id(&state.db_ro, order_id)
        .await?
        .ok_or(AcmeError::NotFound)?;

    if order.ca_id != ca_id {
        return Err(AcmeError::NotFound);
    }
    if order.account_id != account_id {
        return Err(AcmeError::Unauthorized(
            "order belongs to different account".into(),
        ));
    }
    if order.status.parse() != Ok(OrderStatus::Ready) {
        return Err(AcmeError::OrderNotReady);
    }

    let payload: FinalizePayload = require_payload(&ctx.payload, "finalize")?;
    let csr_der = URL_SAFE_NO_PAD
        .decode(&payload.csr)
        .map_err(|e| AcmeError::BadCsr(format!("base64url decode: {e}")))?;

    Ok((ctx, account_id, order, csr_der))
}

/// Resolve certificate parameters from the profile registry (the actual
/// per-profile authorization checks happen afterward, in the caller).
///
/// A single registry read is performed and the result is kept in locals to
/// avoid a TOCTOU window where a concurrent background refresh could cause
/// the cert_params and the auth gate to diverge. Also applies the CRL/OCSP
/// URL override: ProfileRegistry bakes those URLs from the default CA at
/// startup, so when a non-default CA issues via a profile that did not
/// explicitly set them, they're overridden here with the order CA's own
/// infrastructure URLs.
///
/// Returns `(cert_params, default_profile_applied)`.
fn resolve_cert_params(
    state: &AppState,
    order: &db::schema::OrderRow,
    order_ca: &crate::state::CaState,
) -> Result<(crate::profiles::CertificateParameters, bool), AcmeError> {
    let (mut cert_params, default_profile_applied) = if !state.profiles.is_empty() {
        match &order.profile {
            Some(p) => match state.profiles.resolve_for_ca(p, &order.ca_id) {
                Some(params) => (params, false),
                None => {
                    return Err(AcmeError::InvalidProfile(format!(
                        "profile '{p}' is not available for CA '{}'",
                        order.ca_id
                    )));
                }
            },
            None => match state.profiles.resolve_for_ca("default", &order.ca_id) {
                Some(params) => (params, true),
                None => (
                    crate::profiles::CertificateParameters::from_ca(order_ca),
                    false,
                ),
            },
        }
    } else {
        (
            crate::profiles::CertificateParameters::from_ca(order_ca),
            false,
        )
    };

    if order.ca_id != *state.default_ca_id {
        let def = state.default_ca();
        if cert_params.crl_url == def.crl_url {
            cert_params.crl_url = order_ca.crl_url.clone();
        }
        if cert_params.ocsp_url == def.ocsp_url {
            cert_params.ocsp_url = order_ca.ocsp_url.clone();
        }
    }

    Ok((cert_params, default_profile_applied))
}

/// Run per-profile authorization checks, CSR structural validation, policy
/// engine evaluation, and (for delegation orders) CSR-template validation.
///
/// Order matters: profile auth runs before CSR validation so that auth
/// failures are returned without revealing whether the CSR was
/// structurally valid (no timing oracle for identifier-namespace probing);
/// policy evaluation runs after CSR validation so `key_type` is available.
///
/// Returns the validated CSR plus any extra OtherName DERs the profile-auth
/// hook (Option C) requested be added as SANs.
async fn run_profile_and_csr_checks(
    state: &AppState,
    account_id: &str,
    order: &db::schema::OrderRow,
    cert_params: &crate::profiles::CertificateParameters,
    default_profile_applied: bool,
    allowed: &[(&str, &str)],
    csr_der: &[u8],
) -> Result<(ca::csr::ValidatedCsr, Vec<Vec<u8>>), AcmeError> {
    // Per-profile authorization checks (identifier patterns, external hook,
    // account grants). Runs when the client named a profile OR when a
    // "default" profile was silently auto-applied.
    let effective_profile: Option<&str> = order.profile.as_deref().or(if default_profile_applied {
        Some("default")
    } else {
        None
    });
    // Option C: the hook may return extra OtherName DERs via stdout JSON.
    let extra_other_names: Vec<Vec<u8>> = if let Some(profile_name) = effective_profile {
        crate::profiles::auth::check_profile_auth(
            &state.db_ro,
            account_id,
            profile_name,
            cert_params,
            allowed,
        )
        .await?
    } else {
        vec![]
    };

    // Validate CSR (after auth to avoid timing oracle on CSR structure).
    let validated_csr = ca::csr::validate_csr(csr_der, allowed)?;

    // Policy engine evaluation — runs after CSR validation so key_type is available.
    crate::policy::evaluate_issuance_policy(
        state,
        &crate::policy::PolicyCheckParams {
            account_id,
            ca_id: &order.ca_id,
            effective_profile,
            allowed,
            key_type: validated_csr.key_type.as_deref(),
        },
    )
    .await?;

    // RFC 9115 §4: for delegation orders, validate the CSR against the
    // delegation's CSR template.
    if let Some(ref delegation_id) = order.delegation_id {
        let delegation = db::delegations::get_by_id(&state.db_ro, delegation_id)
            .await?
            .ok_or_else(|| {
                AcmeError::Internal(format!(
                    "order references unknown delegation '{delegation_id}'"
                ))
            })?;
        let template: ca::csr_template::CsrTemplate =
            serde_json::from_str(&delegation.csr_template).map_err(|e| {
                AcmeError::Internal(format!(
                    "corrupt csr_template in delegation {delegation_id}: {e}"
                ))
            })?;
        ca::csr_template::validate_csr_against_template(csr_der, &template)?;
    }

    Ok((validated_csr, extra_other_names))
}

/// Parameters for [`persist_certificate`].
struct PersistCertificateParams<'a> {
    order: &'a db::schema::OrderRow,
    order_id: &'a str,
    account_id: &'a str,
    issued: &'a ca::issue::IssuedCert,
    final_cert_der: Vec<u8>,
    final_cert_pem: String,
    final_mtc_index: Option<i64>,
    subject_dn: Option<String>,
    csr_der: &'a [u8],
    now: i64,
}

/// Persist the issued certificate, update the order, mark any predecessor
/// (RFC 9773 `replaces`) as superseded, and fetch the order's authz IDs —
/// all atomically in a single transaction (or via the write-coalescer, when
/// configured) so that a crash between writes cannot leave the DB
/// inconsistent.
///
/// Returns `(pred_already_replaced, cert_id, authz_ids)`, where
/// `pred_already_replaced` is true when the predecessor's `replaced_by` was
/// already set by another concurrent finalization (RFC 9773 §5).
async fn persist_certificate(
    state: &AppState,
    params: PersistCertificateParams<'_>,
) -> Result<(bool, String, Vec<String>), AcmeError> {
    let PersistCertificateParams {
        order,
        order_id,
        account_id,
        issued,
        final_cert_der,
        final_cert_pem,
        final_mtc_index,
        subject_dn,
        csr_der,
        now,
    } = params;

    // If this order carries a `replaces` cert_id, resolve the predecessor UUID
    // before entering the DB transaction (we need an async call for this).
    let pred_cert_uuid: Option<String> = if let Some(ref cid) = order.replaces {
        db::certs::get_by_cert_id(&state.db_ro, cid)
            .await?
            .map(|c| c.id)
    } else {
        None
    };

    let cert_id = issued.id.clone();

    let cert_row = CertificateRow {
        id: issued.id.clone(),
        order_id: order_id.to_string(),
        account_id: account_id.to_string(),
        serial_number: issued.serial_hex.clone(),
        status: CertStatus::Valid.as_str().to_string(),
        der: final_cert_der,
        pem: final_cert_pem,
        not_before: issued.not_before,
        not_after: issued.not_after,
        revoked_at: None,
        revocation_reason: None,
        mtc_log_index: final_mtc_index,
        created: now,
        suggested_window_start: None,
        suggested_window_end: None,
        replaced_by: None,
        subject_dn,
        ca_id: order.ca_id.clone(),
    };
    let star_csr = if order.star_end_date.is_some() {
        Some(csr_der.to_vec())
    } else {
        None
    };
    let pred_already_replaced = if let Some(ref coal) = state.write_coalescer {
        coal.submit_finalize(
            cert_row,
            order_id.to_string(),
            now,
            pred_cert_uuid.clone(),
            star_csr,
        )
        .await?
    } else {
        let mut tx = db::begin_write(&state.db, state.db_kind).await?;

        db::certs::insert(&mut *tx, cert_row).await?;

        db::orders::set_certificate(&mut *tx, order_id, &cert_id, now)
            .await
            .map_err(|e| match e {
                AcmeError::Conflict(_) => AcmeError::OrderNotReady,
                other => other,
            })?;

        let pred_already_replaced = if let Some(ref pred_uuid) = pred_cert_uuid {
            !db::certs::mark_replaced(&mut *tx, pred_uuid, order_id).await?
        } else {
            false
        };

        if let Some(csr) = star_csr {
            db::orders::set_star_csr(&mut *tx, order_id, csr).await?;
        }

        tx.commit().await.map_err(AcmeError::from)?;
        pred_already_replaced
    };
    let authz_ids = db::orders::list_authz_ids(&state.db_ro, order_id).await?;

    Ok((pred_already_replaced, cert_id, authz_ids))
}

/// Parameters for [`issue_leaf_certificate`].
struct IssueLeafParams<'a> {
    cert_params: &'a crate::profiles::CertificateParameters,
    csr_der: &'a [u8],
    validated_csr: &'a ca::csr::ValidatedCsr,
    not_before: Option<i64>,
    not_after: Option<i64>,
    extra_other_names: &'a [Vec<u8>],
    extra_dns_names: &'a [String],
}

/// Issue the certificate — either locally via `spawn_blocking` (CPU-bound
/// crypto) or remotely via the Dogtag REST API (async I/O).
async fn issue_leaf_certificate(
    state: &AppState,
    order_ca: &Arc<crate::state::CaState>,
    params: IssueLeafParams<'_>,
) -> Result<ca::issue::IssuedCert, AcmeError> {
    let IssueLeafParams {
        cert_params,
        csr_der,
        validated_csr,
        not_before,
        not_after,
        extra_other_names,
        extra_dns_names,
    } = params;

    match &order_ca.signing {
        crate::state::SigningBackend::Dogtag(signer) => {
            let profile_override = cert_params.dogtag_profile_id.as_deref();
            ca::dogtag::issue_via_dogtag(signer, &order_ca.cert_der, csr_der, profile_override)
                .await
        }
        crate::state::SigningBackend::Local { .. } => {
            let linter_profile = state.linter_registry.resolve_for_order(
                cert_params.linter.as_deref(),
                order_ca.default_linter.as_deref(),
            )?;

            let ca_arc = Arc::clone(order_ca);
            let csr_owned = validated_csr.clone();
            let params_owned = cert_params.clone();
            let on = extra_other_names.to_vec();
            let dn = extra_dns_names.to_vec();
            tokio::task::spawn_blocking(move || {
                ca::issue::issue_with_params(ca::issue::IssueWithParamsArgs {
                    ca: &ca_arc,
                    csr: &csr_owned,
                    params: &params_owned,
                    not_before_override: not_before,
                    not_after_override: not_after,
                    extra_other_names: &on,
                    extra_dns_names: &dn,
                    linter: &linter_profile,
                })
            })
            .await
            .map_err(|e| AcmeError::Internal(format!("issue task: {e}")))?
        }
    }
}

/// Build the MTC-related outputs for this issuance.
///
/// For `issue_as_mtc` profiles, builds a full StandaloneCertificate from the
/// issued TBSCertificate + an MTC Merkle inclusion proof, done synchronously
/// so `mtc_log_index` is available at DB-insert time. For regular profiles
/// with MTC enabled on the CA, does best-effort background sequencing
/// instead — a log-append failure here does not fail issuance, since MTC is
/// an enhancement, not a requirement, for non-MTC profiles.
///
/// Returns `(final_cert_der, final_cert_pem, final_mtc_index, mtc_standalone_pending)`.
async fn build_mtc_outputs(
    state: &AppState,
    order_ca: &Arc<crate::state::CaState>,
    issue_as_mtc: bool,
    issued: &ca::issue::IssuedCert,
) -> Result<(Vec<u8>, String, Option<i64>, Option<Vec<u8>>), AcmeError> {
    let (final_cert_der, final_cert_pem, mut final_mtc_index) = if issue_as_mtc {
        let ca_mtc = &order_ca.mtc;
        if ca_mtc.log.is_none() {
            return Err(AcmeError::InvalidProfile(
                "profile 'issue_as = \"mtc\"' requires [ca.mtc] to be enabled".into(),
            ));
        }

        let (idx, proof, tree_size) =
            append_leaf_locally_or_forward(state, order_ca, &issued.cert_der, &issued.serial_hex)
                .await
                .map_err(|e| AcmeError::Mtc(format!("MTC log append for MTC-profile cert: {e}")))?;

        let mtc_signing_key = ca_mtc.signing_key.as_ref().ok_or_else(|| {
            AcmeError::InvalidProfile(
                "profile 'issue_as = \"mtc\"' requires [ca.mtc.signing_key] to be configured"
                    .into(),
            )
        })?;
        let spki_der = mtc_signing_key
            .public_key()
            .map_err(|e| AcmeError::Crypto(format!("MTC signing key SPKI for standalone: {e}")))?
            .spki_der()
            .to_vec();
        let standalone_der = crate::mtc::standalone::build_standalone_der(
            crate::mtc::standalone::StandaloneParams {
                cert_der: &issued.cert_der,
                leaf_index: idx,
                proof,
                tree_size,
                spki_der: &spki_der,
                log_algorithm: ca_mtc.algorithm,
                cosignature_ders: &[],
                log_number: ca_mtc.log_number,
                subtree_start: 0,
            },
        )?;

        let pem = String::from_utf8(der_to_pem("STANDALONE MTC CERTIFICATE", &standalone_der))
            .map_err(|_| AcmeError::Internal("MTC PEM bytes are not valid UTF-8".into()))?;

        (standalone_der, pem, Some(idx as i64))
    } else {
        (issued.cert_der.clone(), issued.cert_pem.clone(), None)
    };

    // MTC sequencing for regular (non-MTC) profiles: best-effort.
    // If log append fails, the X.509 cert is still valid — MTC is an enhancement,
    // not a requirement for this profile. The error is logged for operator awareness.
    let mtc_standalone_pending = if issue_as_mtc {
        Some(final_cert_der.clone())
    } else if order_ca.mtc.is_enabled() {
        match append_and_build_standalone(state, order_ca, issued).await {
            Ok((idx, standalone)) => {
                final_mtc_index = Some(idx);
                standalone
            }
            Err(e) => {
                tracing::error!(cert_id = %issued.id, "MTC sequencing: {e}");
                None
            }
        }
    } else {
        None
    };

    Ok((
        final_cert_der,
        final_cert_pem,
        final_mtc_index,
        mtc_standalone_pending,
    ))
}

/// Parameters for [`inject_template_and_tkauth_sans`].
struct SanInjectionParams<'a> {
    order_id: &'a str,
    account_id: &'a str,
    cert_params: &'a crate::profiles::CertificateParameters,
    validated_csr: &'a ca::csr::ValidatedCsr,
    allowed: &'a [(&'a str, &'a str)],
    order_not_after: Option<i64>,
    extra_other_names: Vec<Vec<u8>>,
}

/// Inject SANs from three sources beyond the CSR itself, then enforce the
/// two guarantees that depend on tracking which authorizations contributed
/// tkauth-derived SANs.
///
/// - Option A: expand KPN/MS-UPN templates against CSR DNS SANs.
/// - Option B: account-stored Kerberos principal injected as a KPN
///   OtherName SAN.
/// - Option D: JWTClaimConstraints-derived SANs from validated authority
///   tokens. Two sources of JCC blobs: JWTClaimConstraints identifier
///   authzs (blob is the identifier value), and encoder-backed identifier
///   authzs (e.g. "dns") validated via tkauth-01 (blob is the stored
///   tkvalue retrieved from the JTI cache). OtherName encoders push into
///   the returned `extra_other_names`; DnsName encoders push into
///   `extra_dns_names` (skipping values already present in order
///   identifiers, to avoid duplicate SANs). Every authz that contributed a
///   blob is tracked so the two checks below can use them without a second
///   DB round-trip.
/// - draft-ietf-acme-authority-token-jwtclaimcon §6 step 8: the `atc.ca`
///   flag stored for each tkauth-validated authz must match the CSR's
///   BasicConstraints `cA` field — when no tkauth authzs are present,
///   `cA=TRUE` is never allowed.
/// - RFC 9447 SHOULD: cap `not_after` to the minimum authority-token expiry
///   across all tkauth-validated authzs, so as not to issue a certificate
///   that outlives the token(s) that authorized it.
///
/// Returns `(extra_other_names, extra_dns_names, not_after)`.
async fn inject_template_and_tkauth_sans(
    state: &AppState,
    params: SanInjectionParams<'_>,
) -> Result<(Vec<Vec<u8>>, Vec<String>, Option<i64>), AcmeError> {
    let SanInjectionParams {
        order_id,
        account_id,
        cert_params,
        validated_csr,
        allowed,
        order_not_after,
        mut extra_other_names,
    } = params;

    // Option A: expand KPN/MS-UPN templates against CSR DNS SANs.
    let dns_sans: Vec<&str> = validated_csr
        .sans
        .iter()
        .filter(|s| s.san_type == "dns")
        .map(|s| s.value.as_str())
        .collect();
    for tmpl in &cert_params.kpn_san_templates {
        extra_other_names.extend(
            crate::krb5_san::expand_kpn_template(tmpl, &dns_sans).map_err(AcmeError::Builder)?,
        );
    }
    if let Some(ref tmpl) = cert_params.ms_upn_san_template {
        if let Some(der) =
            crate::krb5_san::expand_ms_upn_template(tmpl, &dns_sans).map_err(AcmeError::Builder)?
        {
            extra_other_names.push(der);
        }
    }

    // Option B: account-stored Kerberos principal injected as KPN OtherName SAN.
    if cert_params.inject_account_kpn {
        if let Some(principal) =
            db::accounts::get_kerberos_principal(&state.db_ro, account_id).await?
        {
            extra_other_names.push(
                crate::krb5_san::encode_principal_str_other_name(&principal)
                    .map_err(AcmeError::Builder)?,
            );
        }
    }

    // Option D: JWTClaimConstraints-derived SANs from validated authority tokens.
    let mut extra_dns_names: Vec<String> = vec![];
    let mut tkauth_authz_ids: Vec<String> = vec![];
    {
        let authz_rows = db::authz::list_by_order(&state.db_ro, order_id).await?;

        if let Some(registry) = &state.claim_encoder_registry {
            for authz in &authz_rows {
                if authz.status.parse() != Ok(AuthzStatus::Valid) {
                    continue;
                }
                let Ok(id_obj) = serde_json::from_str::<serde_json::Value>(&authz.identifier)
                else {
                    tracing::warn!(authz_id = %authz.id, "tkauth finalize: skipping authz with malformed identifier JSON");
                    continue;
                };
                let authz_id_type = id_obj["type"].as_str().unwrap_or("");

                // Obtain the JWTClaimConstraints blob for this authz.
                let blob_opt: Option<String> = if authz_id_type == "JWTClaimConstraints"
                    || authz_id_type == "EnhancedJWTClaimConstraints"
                {
                    id_obj["value"].as_str().map(str::to_string)
                } else {
                    db::tkauth::get_tkvalue_for_authz(&state.db_ro, &authz.id)
                        .await
                        .map_err(|e| {
                            AcmeError::Internal(format!("tkauth finalize: tkvalue lookup: {e}"))
                        })?
                };

                let Some(blob) = blob_opt else {
                    continue;
                };

                // Track for the not_after cap.
                tkauth_authz_ids.push(authz.id.clone());

                let Ok(raw) = URL_SAFE_NO_PAD.decode(&blob) else {
                    tracing::warn!(authz_id = %authz.id, "tkauth finalize: tkvalue is not valid base64url");
                    continue;
                };

                // Parse the JWTClaimConstraints blob: try JSON (server extension),
                // then RFC 8226 DER.  Collect (claim, values) pairs for SAN injection.
                let entries: Vec<(String, Vec<String>)> =
                    if let Ok(constraints) = serde_json::from_slice::<serde_json::Value>(&raw) {
                        constraints["must-include"]
                            .as_array()
                            .map(|arr| {
                                arr.iter()
                                    .filter_map(|e| {
                                        let claim = e["claim"].as_str()?.to_string();
                                        let vals: Vec<String> = e["values"]
                                            .as_array()?
                                            .iter()
                                            .filter_map(|v| v.as_str().map(str::to_string))
                                            .collect();
                                        Some((claim, vals))
                                    })
                                    .collect()
                            })
                            .unwrap_or_default()
                    } else if let Some((_must_include, permitted, _must_exclude)) =
                        crate::validation::tkauth01::parse_jwcc_der(&raw)
                    {
                        permitted
                    } else {
                        tracing::warn!(
                            authz_id = %authz.id,
                            "tkauth finalize: tkvalue blob is not valid JSON or RFC 8226 DER"
                        );
                        continue;
                    };

                for (claim, values) in &entries {
                    let Some(encoder) = registry.get(claim.as_str()) else {
                        continue; // claim not registered — skip silently
                    };
                    // Only encode when the constraint names exactly one value: that
                    // value is definitively what the TA attested.  Multiple permitted
                    // values mean "one of"; we cannot know which matched at finalize time.
                    if values.len() != 1 {
                        if values.len() > 1 {
                            tracing::warn!(
                                authz_id = %authz.id,
                                claim = %claim,
                                "tkauth finalize: skipping multi-value constraint for SAN injection; use a single value"
                            );
                        }
                        continue;
                    }
                    match encoder
                        .encode(values[0].as_str())
                        .map_err(AcmeError::Builder)?
                    {
                        EncodedSan::OtherName(der) => extra_other_names.push(der),
                        EncodedSan::DnsName(name) => {
                            // For encoder-backed identifier authzs (e.g., dns), the dns
                            // name is already in the order identifiers and will appear in
                            // the certificate from the CSR — do not duplicate.
                            let in_order = allowed
                                .iter()
                                .any(|(t, v)| *t == "dns" && *v == name.as_str());
                            if authz_id_type != "EnhancedJWTClaimConstraints" && in_order {
                                continue;
                            }
                            extra_dns_names.push(name);
                        }
                    }
                }
            }
        }

        // Collect JWTClaimConstraints authz IDs not already added via the registry
        // path, so the not_after cap covers all tkauth-validated authzs regardless
        // of whether claim_encoders is configured.
        for authz in &authz_rows {
            if authz.status.parse() != Ok(AuthzStatus::Valid)
                || tkauth_authz_ids.contains(&authz.id)
            {
                continue;
            }
            if let Ok(id_obj) = serde_json::from_str::<serde_json::Value>(&authz.identifier) {
                if matches!(
                    id_obj["type"].as_str(),
                    Some("JWTClaimConstraints") | Some("EnhancedJWTClaimConstraints")
                ) {
                    tkauth_authz_ids.push(authz.id.clone());
                }
            }
        }
    }

    // draft-ietf-acme-authority-token-jwtclaimcon §6 step 8: verify that the atc.ca
    // flag stored for each tkauth-validated authz matches the CSR's BasicConstraints
    // cA field.  When no tkauth authzs are present, cA=TRUE is never allowed.
    {
        let tkauth_ca = if !tkauth_authz_ids.is_empty() {
            let refs: Vec<&str> = tkauth_authz_ids.iter().map(String::as_str).collect();
            db::tkauth::get_any_ca_flag_for_authzs(&state.db_ro, &refs).await?
        } else {
            false
        };
        if validated_csr.ca_cert != tkauth_ca {
            return Err(AcmeError::BadCsr(
                if validated_csr.ca_cert {
                    "CSR asserts cA=TRUE but no authority token permitted CA cert issuance"
                } else {
                    "authority token asserts atc.ca=true but CSR does not assert cA=TRUE"
                }
                .into(),
            ));
        }
    }

    // RFC 9447 SHOULD: do not issue certificates with a longer expiry than the
    // authority token(s) that authorized the order.  Query the JTI cache for the
    // minimum token expiry across all tkauth-validated authzs (JWTClaimConstraints
    // identifiers and encoder-backed identifiers such as dns) and cap not_after.
    let not_after = if !tkauth_authz_ids.is_empty() {
        let refs: Vec<&str> = tkauth_authz_ids.iter().map(String::as_str).collect();
        match db::tkauth::get_min_exp_for_authzs(&state.db_ro, &refs).await? {
            Some(min_exp) => Some(order_not_after.map_or(min_exp, |t| t.min(min_exp))),
            None => order_not_after,
        }
    } else {
        order_not_after
    };

    Ok((extra_other_names, extra_dns_names, not_after))
}
