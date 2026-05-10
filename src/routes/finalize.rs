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
use crate::db;
use crate::db::schema::CertificateRow;
use crate::error::AcmeError;
use crate::state::AppState;

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
    let id = params.get("id").cloned().ok_or(AcmeError::NotFound)?;
    let pfx = acme_prefix(&state.config.base_url, &ca_id.0, &state.default_ca_id);
    let url = format!("{pfx}/order/{id}/finalize");
    let ctx = parse_jws(&state, body, &url).await?;

    let account_id = ctx
        .account_id
        .ok_or(AcmeError::Unauthorized("kid required".into()))?;

    let order = db::orders::get_by_id(&state.db, &id)
        .await?
        .ok_or(AcmeError::NotFound)?;

    if order.ca_id != ca_id.0 {
        return Err(AcmeError::NotFound);
    }
    if order.account_id != account_id {
        return Err(AcmeError::Unauthorized(
            "order belongs to different account".into(),
        ));
    }
    if order.status != "ready" {
        return Err(AcmeError::OrderNotReady);
    }

    let payload: FinalizePayload = require_payload(&ctx.payload, "finalize")?;
    let csr_der = URL_SAFE_NO_PAD
        .decode(&payload.csr)
        .map_err(|e| AcmeError::BadCsr(format!("base64url decode: {e}")))?;

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

    // Validate CSR.
    let validated_csr = ca::csr::validate_csr(&csr_der, &allowed)?;

    // RFC 9115 §4: validate the CSR against the delegation template when present.
    if let Some(ref dlg_id) = order.delegation_id {
        let dlg = db::delegations::get_by_id(&state.db_ro, dlg_id)
            .await?
            .ok_or_else(|| AcmeError::Internal(format!("delegation {dlg_id} not found")))?;
        let template: ca::csr_template::CsrTemplate = serde_json::from_str(&dlg.csr_template)
            .map_err(|e| {
                AcmeError::Internal(format!("corrupt csr_template in delegation {dlg_id}: {e}"))
            })?;
        ca::csr_template::validate_csr_against_template(&csr_der, &template)?;

        // When an upstream CA is configured, transition to processing and hand off
        // to the background delegation driver (implemented in src/delegation_upstream.rs).
        if state.config.delegation_upstream.is_some() {
            let now = unix_now();
            // Atomically set status=processing and store the CSR in one UPDATE so a crash
            // between the two writes cannot leave the order stuck without a CSR.
            db::orders::set_processing_with_csr_der(&state.db, &id, &csr_der, now)
                .await
                .map_err(|e| match e {
                    AcmeError::Conflict(_) => AcmeError::OrderNotReady,
                    other => other,
                })?;
            let mut processing_order = order;
            processing_order.status = "processing".to_string();
            processing_order.updated = now;
            let order_pfx = acme_prefix(
                &state.config.base_url,
                &processing_order.ca_id,
                &state.default_ca_id,
            );
            state
                .record_audit(
                    crate::audit::AuditEvent::success(crate::audit::AuditEventType::OrderFinalize)
                        .with_subject(&id)
                        .with_principal(format!(
                            "acme:{}",
                            ctx.jwk_thumbprint.as_deref().unwrap_or("")
                        )),
                )
                .await;
            return json_response(
                &state,
                &processing_order.ca_id,
                StatusCode::OK,
                order_json(&processing_order, &[], &order_pfx),
                &ctx.next_nonce,
            );
        }
    }

    // draft-aaron-acme-profiles-01: if the order carries a profile name that the
    // registry does not recognise (or is restricted to a different CA), reject at
    // finalize time.
    if let Some(ref p) = order.profile {
        if !state.profiles.is_empty() && state.profiles.resolve_for_ca(p, &order.ca_id).is_none() {
            return Err(AcmeError::InvalidProfile(format!(
                "profile '{p}' is not available for CA '{}'",
                order.ca_id
            )));
        }
    }

    // Resolve the CA for this order.  Must happen before the CAA check because
    // per-CA caa_identities may differ from the server-level default.
    let order_ca = state.get_ca(&order.ca_id).ok_or_else(|| {
        AcmeError::Internal(format!("order references unknown CA '{}'", order.ca_id))
    })?;

    // CAA check (RFC 8659 + RFC 8657): only when caa_identities is configured.
    // Per-CA identities take precedence; fall back to server-level when the CA
    // does not override them (matching the behaviour in directory.rs).
    // The authz lookup is deferred inside this block so that deployments without
    // CAA pay zero extra DB round-trips during finalization.  The account URL is
    // constructed here and passed to check_caa for RFC 8657 §4 accounturi enforcement.
    let effective_caa: &[String] = if !order_ca.caa_identities.is_empty() {
        &order_ca.caa_identities
    } else {
        &state.config.server.caa_identities
    };
    if !effective_caa.is_empty() {
        // Build identifier → authz_id map to look up the validated challenge type
        // for each authorization (RFC 8657 validationmethods check).
        let authz_rows = db::authz::list_by_order(&state.db, &id).await?;
        let mut identifier_to_authz: std::collections::HashMap<(String, String), String> =
            std::collections::HashMap::new();
        for authz in &authz_rows {
            if let Ok(id_obj) = serde_json::from_str::<serde_json::Value>(&authz.identifier) {
                if let (Some(t), Some(v)) = (id_obj["type"].as_str(), id_obj["value"].as_str()) {
                    identifier_to_authz.insert((t.to_string(), v.to_string()), authz.id.clone());
                }
            }
        }

        for (id_type, id_value) in &allowed {
            if *id_type == "dns" {
                let is_wildcard = id_value.starts_with("*.");
                let domain = if is_wildcard {
                    &id_value[2..]
                } else {
                    id_value
                };
                let challenge_type = if let Some(authz_id) =
                    identifier_to_authz.get(&(id_type.to_string(), id_value.to_string()))
                {
                    db::challenges::get_validated_type(&state.db, authz_id)
                        .await?
                        .ok_or_else(|| {
                            AcmeError::Internal(format!(
                                "no validated challenge type found for authz {authz_id}"
                            ))
                        })?
                } else {
                    String::new()
                };
                // Account URL is intentionally server-scoped (not per-CA): RFC 8657
                // accounturi refers to the ACME account resource, which is shared
                // across all CAs in server-scoped mode.
                let account_url = format!("{}/acme/account/{account_id}", state.config.base_url);
                crate::validation::caa::check_caa(
                    crate::validation::caa::CaaParams {
                        domain,
                        ca_identities: effective_caa,
                        is_wildcard,
                        challenge_type: &challenge_type,
                        account_url: Some(account_url.as_str()),
                        validate_dnssec: state.config.server.validate_dnssec,
                        dot_server_name: state.config.server.dns_dot_server_name.as_deref(),
                    },
                    state.config.server.dns_resolver_addr.as_deref(),
                )
                .await?;
            }
            // IP identifiers: CAA is not applicable per RFC 8659.
        }
    }

    // Resolve certificate parameters from the profile registry (or fall back to
    // CA defaults when no profile is requested or the registry is empty).
    // resolve_for_ca() respects ca_ids restrictions so a profile scoped to one CA
    // cannot be applied by a different CA.
    let mut cert_params = match &order.profile {
        Some(p) if !state.profiles.is_empty() => state
            .profiles
            .resolve_for_ca(p, &order.ca_id)
            .unwrap_or_else(|| crate::profiles::CertificateParameters::from_ca(order_ca)),
        _ => crate::profiles::CertificateParameters::from_ca(order_ca),
    };

    // ProfileRegistry bakes CRL/OCSP URLs from the default CA at startup.  When
    // a non-default CA issues via a profile that did not explicitly set those URLs,
    // the baked-in default CA URLs would appear in the certificate.  Override them
    // with the order CA's own infrastructure URLs in that case.
    if order.ca_id != *state.default_ca_id {
        let def = state.default_ca();
        if cert_params.crl_url == def.crl_url {
            cert_params.crl_url = order_ca.crl_url.clone();
        }
        if cert_params.ocsp_url == def.ocsp_url {
            cert_params.ocsp_url = order_ca.ocsp_url.clone();
        }
    }

    // Per-profile authorization checks (identifier patterns, external hook,
    // account grants).  Only meaningful when the order carries a profile.
    if order.profile.is_some() {
        let profile_name = order.profile.as_deref().unwrap_or("");
        crate::profiles::auth::check_profile_auth(
            &state.db,
            &account_id,
            profile_name,
            &cert_params,
            &allowed,
        )
        .await?;
    }

    // Issue the certificate using the resolved parameters.  akamu's own CA
    // signs in all cases; the profile only governs extension content and validity.
    let issued = ca::issue::issue_with_params(
        order_ca,
        &validated_csr,
        &cert_params,
        order.not_before,
        order.not_after,
    )?;

    // For MTC issuance profiles, build a StandaloneCertificate from the issued
    // TBSCertificate + an MTC Merkle inclusion proof.  This is done synchronously
    // before the DB transaction so the mtc_log_index is available at insert time.
    let (final_cert_der, final_cert_pem, final_mtc_index) = if cert_params.issue_as_mtc {
        let Some(log) = &state.mtc.log else {
            return Err(AcmeError::InvalidProfile(
                "profile 'issue_as = \"mtc\"' requires [mtc] to be enabled".into(),
            ));
        };

        let idx =
            crate::mtc::log::append_cert_to_log(log, issued.cert_der.clone(), state.mtc.algorithm)
                .await
                .map_err(|e| AcmeError::Mtc(format!("MTC log append for MTC-profile cert: {e}")))?;

        let (proof, tree_size) = crate::mtc::log::proof_and_tree_size(log, idx)
            .await
            .map_err(|e| {
                AcmeError::Mtc(format!("MTC inclusion proof for cert {}: {e}", issued.id))
            })?;

        let spki_der = order_ca
            .key
            .public_key()
            .map_err(|e| AcmeError::Crypto(format!("MTC key SPKI for standalone: {e}")))?
            .spki_der()
            .to_vec();
        let standalone_der = crate::mtc::standalone::build_standalone_der(
            crate::mtc::standalone::StandaloneParams {
                cert_der: &issued.cert_der,
                leaf_index: idx,
                proof,
                tree_size,
                spki_der: &spki_der,
                log_algorithm: state.mtc.algorithm,
                cosignature_ders: &[],
            },
        )?;

        let pem = String::from_utf8(der_to_pem("STANDALONE MTC CERTIFICATE", &standalone_der))
            .map_err(|_| AcmeError::Internal("MTC PEM bytes are not valid UTF-8".into()))?;

        (standalone_der, pem, Some(idx as i64))
    } else {
        (issued.cert_der.clone(), issued.cert_pem.clone(), None)
    };

    // Extract subject DN from the leaf cert for searchability (FAU_SCR_EXT.1).
    let subject_dn = {
        let mut dec = Decoder::new(&issued.cert_der, Encoding::Der);
        dec.decode::<Certificate>()
            .ok()
            .map(|cert| format_dn(cert.tbs_certificate.subject.as_bytes()))
    };

    let now = unix_now();

    // If this order carries a `replaces` cert_id, resolve the predecessor UUID
    // before entering the DB transaction (we need an async call for this).
    let pred_cert_uuid: Option<String> = if let Some(ref cid) = order.replaces {
        db::certs::get_by_cert_id(&state.db, cid)
            .await?
            .map(|c| c.id)
    } else {
        None
    };

    // Persist the certificate, update the order, and fetch authz IDs atomically
    // in a single transaction so that a crash between writes cannot leave the DB
    // inconsistent.
    let cert_id = issued.id.clone();

    // The transaction returns (authz_ids, pred_already_replaced) so we can signal
    // a concurrent alreadyReplaced conflict (RFC 9773 §5) without a separate
    // DB round-trip.  The bool is true when the predecessor's replaced_by was
    // already set by another concurrent finalization.
    let (authz_ids, pred_already_replaced) = {
        let mut tx = db::begin_write(&state.db, state.db_kind).await?;

        db::certs::insert(
            &mut *tx,
            CertificateRow {
                id: issued.id.clone(),
                order_id: id.clone(),
                account_id: account_id.clone(),
                serial_number: issued.serial_hex.clone(),
                status: "valid".to_string(),
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
            },
        )
        .await?;

        // Conflict means a concurrent finalization already committed this
        // order to 'valid'; surface as OrderNotReady per RFC 8555 §7.4.
        db::orders::set_certificate(&mut *tx, &id, &cert_id, now)
            .await
            .map_err(|e| match e {
                AcmeError::Conflict(_) => AcmeError::OrderNotReady,
                other => other,
            })?;

        // Mark predecessor certificate as replaced (RFC 9773 §5).
        let pred_already_replaced = if let Some(ref pred_uuid) = pred_cert_uuid {
            !db::certs::mark_replaced(&mut *tx, pred_uuid, &id).await?
        } else {
            false
        };

        // For STAR orders, persist the CSR DER atomically with the cert insert
        // so the background reissuance task can never see a valid order without a CSR.
        if order.star_end_date.is_some() {
            db::orders::set_star_csr(&mut *tx, &id, csr_der.clone()).await?;
        }

        // Fetch authz IDs within the same transaction to avoid a separate round-trip.
        let authz_ids = db::orders::list_authz_ids(&mut *tx, &id).await?;

        tx.commit().await.map_err(AcmeError::from)?;
        (authz_ids, pred_already_replaced)
    };

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

    // Optionally append to the MTC log.  Skip when the profile already handled
    // this synchronously above (MTC issuance profiles set final_mtc_index).
    if state.mtc.is_enabled() && !cert_params.issue_as_mtc {
        if let Some(log) = &state.mtc.log {
            let cert_der = issued.cert_der.clone();
            let log = Arc::clone(log);
            let db = state.db.clone();
            let cert_id = issued.id.clone();
            let cert_id_for_log = issued.id.clone();
            let algorithm = state.mtc.algorithm;
            let handle = tokio::spawn(async move {
                match crate::mtc::log::append_cert_to_log(&log, cert_der, algorithm).await {
                    Ok(index) => {
                        if let Err(e) =
                            db::certs::set_mtc_log_index(&db, &cert_id, index as i64).await
                        {
                            tracing::warn!(
                                "cert {cert_id}: MTC log index {index} not saved to DB: {e}"
                            );
                        }
                    }
                    Err(e) => {
                        tracing::error!(cert_id, error = %e, "MTC log append failed — certificate not included in log");
                    }
                }
            });
            tokio::spawn(async move {
                if let Err(e) = handle.await {
                    tracing::error!("cert {cert_id_for_log}: MTC log task panicked: {e:?}");
                }
            });
        }
    }

    // Build the response from the known post-finalize state without a DB re-fetch.
    let mut updated_order = order;
    updated_order.status = "valid".to_string();
    updated_order.certificate_id = Some(issued.id.clone());
    updated_order.updated = now;

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
