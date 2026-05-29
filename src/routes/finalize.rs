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
    let id = params
        .get("id")
        .ok_or(AcmeError::NotFound)?
        .clone();
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

    // Resolve the CA for this order.  Done early so that profile resolution and
    // authorization checks can run before the expensive CSR and CAA operations.
    let order_ca = state.get_ca(&order.ca_id).ok_or_else(|| {
        AcmeError::Internal(format!("order references unknown CA '{}'", order.ca_id))
    })?;

    // Resolve certificate parameters from the profile registry and run
    // per-profile authorization checks BEFORE validate_csr and CAA so that
    // auth failures are returned without revealing whether the CSR was
    // structurally valid (no timing oracle for identifier-namespace probing).
    //
    // A single registry read is performed and the result is kept in locals to
    // avoid a TOCTOU window where a concurrent background refresh could cause
    // the cert_params and the auth gate to diverge.
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
    // account grants).  Runs when the client named a profile OR when a "default"
    // profile was silently auto-applied above.
    let effective_profile: Option<&str> = order.profile.as_deref().or(if default_profile_applied {
        Some("default")
    } else {
        None
    });
    // Option C: the hook may return extra OtherName DERs via stdout JSON.
    let mut extra_other_names: Vec<Vec<u8>> = if let Some(profile_name) = effective_profile {
        crate::profiles::auth::check_profile_auth(
            &state.db,
            &account_id,
            profile_name,
            &cert_params,
            &allowed,
        )
        .await?
    } else {
        vec![]
    };

    // Validate CSR (after auth to avoid timing oracle on CSR structure).
    let validated_csr = ca::csr::validate_csr(&csr_der, &allowed)?;

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

    // Option A: expand KPN/MS-UPN templates against CSR DNS SANs.
    let dns_sans: Vec<&str> = validated_csr
        .sans
        .iter()
        .filter(|s| s.san_type == "dns")
        .map(|s| s.value.as_str())
        .collect();
    for tmpl in &cert_params.kpn_san_templates {
        extra_other_names.extend(
            crate::ca::krb5_san::expand_kpn_template(tmpl, &dns_sans)
                .map_err(AcmeError::Builder)?,
        );
    }
    if let Some(ref tmpl) = cert_params.ms_upn_san_template {
        if let Some(der) = crate::ca::krb5_san::expand_ms_upn_template(tmpl, &dns_sans)
            .map_err(AcmeError::Builder)?
        {
            extra_other_names.push(der);
        }
    }

    // Option B: account-stored Kerberos principal injected as KPN OtherName SAN.
    if cert_params.inject_account_kpn {
        if let Some(principal) =
            db::accounts::get_kerberos_principal(&state.db, &account_id).await?
        {
            extra_other_names.push(
                crate::ca::krb5_san::encode_principal_str_other_name(&principal)
                    .map_err(AcmeError::Builder)?,
            );
        }
    }

    // Option D: JWTClaimConstraints-derived SANs from validated authority tokens.
    //
    // Two sources of JCC blobs:
    //   1. JWTClaimConstraints identifier authzs — blob is the identifier value.
    //   2. Encoder-backed identifier authzs (e.g., "dns") validated via tkauth-01 —
    //      blob is the stored tkvalue retrieved from the JTI cache.
    //
    // OtherName encoders push to `extra_other_names`; DnsName encoders push to
    // `extra_dns_names` (skipping values already present in order identifiers to
    // avoid duplicate SANs).
    //
    // `tkauth_authz_ids` collects all authz IDs that contributed a blob so the
    // not_after cap below can use them without a second DB round-trip.
    let mut extra_dns_names: Vec<String> = vec![];
    let mut tkauth_authz_ids: Vec<String> = vec![];
    {
        let authz_rows = db::authz::list_by_order(&state.db, &id).await?;

        if let Some(registry) = &state.claim_encoder_registry {
            for authz in &authz_rows {
                if authz.status != "valid" {
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
                    db::tkauth::get_tkvalue_for_authz(&state.db, &authz.id)
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
            if authz.status != "valid" || tkauth_authz_ids.contains(&authz.id) {
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
            db::tkauth::get_any_ca_flag_for_authzs(&state.db, &refs).await?
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
        match db::tkauth::get_min_exp_for_authzs(&state.db, &refs).await? {
            Some(min_exp) => Some(order.not_after.map_or(min_exp, |t| t.min(min_exp))),
            None => order.not_after,
        }
    } else {
        order.not_after
    };

    // Issue the certificate using the resolved parameters.  akamu's own CA
    // signs in all cases; the profile only governs extension content and validity.
    let issued = ca::issue::issue_with_params(
        order_ca,
        &validated_csr,
        &cert_params,
        order.not_before,
        not_after,
        &extra_other_names,
        &extra_dns_names,
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

        let mtc_signing_key = state.mtc.signing_key.as_ref().ok_or_else(|| {
            AcmeError::InvalidProfile(
                "profile 'issue_as = \"mtc\"' requires [mtc.signing_key] to be configured".into(),
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

    crdt_hooks::on_cert_upsert(
        &state,
        crdt_hooks::CertUpsertParams {
            id: &cert_id,
            order_id: &id,
            account_id: &account_id,
            serial_number: &issued.serial_hex,
            status: "valid",
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
        &state,
        crdt_hooks::OrderUpsertParams {
            id: &id,
            account_id: &updated_order.account_id,
            status: "valid",
            expires: updated_order.expires,
            identifiers: &updated_order.identifiers,
            not_before: updated_order.not_before,
            not_after: updated_order.not_after,
            error: updated_order.error.clone(),
            certificate_id: Some(cert_id.clone()),
            created: updated_order.created,
            updated: now,
            ca_id: &updated_order.ca_id,
        },
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
