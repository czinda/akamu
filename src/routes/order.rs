//! POST /acme/new-order, POST /acme/order/{id} — RFC 8555 §7.4 + RFC 8739 STAR

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::Response;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::db;
use crate::db::schema::{AuthorizationRow, OrderRow};
use crate::error::AcmeError;
use crate::state::AppState;

use super::{fmt_time, json_response, parse_jws, require_payload, unix_now};

#[derive(Deserialize)]
struct NewOrderIdentifier {
    r#type: String,
    value: String,
    #[serde(default, rename = "ancestorDomain")]
    ancestor_domain: Option<String>,
}

/// RFC 8739 §3.1.1 — auto-renewal parameters in newOrder
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AutoRenewalRequest {
    #[serde(default)]
    start_date: Option<String>, // RFC 3339
    end_date: String, // RFC 3339, required
    lifetime: u64,    // seconds
    #[serde(default)]
    lifetime_adjust: i64, // seconds, default 0
    #[serde(default)]
    allow_certificate_get: bool,
}

#[derive(Deserialize)]
struct NewOrderPayload {
    identifiers: Vec<NewOrderIdentifier>,
    #[serde(default)]
    not_before: Option<String>,
    #[serde(default)]
    not_after: Option<String>,
    #[serde(default)]
    replaces: Option<String>,
    #[serde(rename = "auto-renewal", default)]
    auto_renewal: Option<AutoRenewalRequest>,
    /// draft-aaron-acme-profiles-01: optional profile identifier.
    #[serde(default)]
    profile: Option<String>,
}

/// Parse an RFC 3339 timestamp string to a Unix timestamp.
fn parse_rfc3339(s: &str) -> Result<i64, AcmeError> {
    // We rely on a simple manual parse since no chrono/time crate is available.
    // Expected format: YYYY-MM-DDTHH:MM:SSZ  (or with timezone offset)
    // We use a best-effort parse for the common cases.
    let s = s.trim();
    // Normalise Z suffix
    let s = if s.ends_with('Z') || s.ends_with('z') {
        s[..s.len() - 1].to_string() + "+00:00"
    } else {
        s.to_string()
    };
    // Expected: YYYY-MM-DDTHH:MM:SS+HH:MM
    let err = || AcmeError::BadRequest(format!("invalid RFC 3339 date: '{}'", s));
    let (date_time, tz) = if let Some(pos) = s[10..].find('+') {
        (&s[..10 + pos], &s[10 + pos + 1..])
    } else if let Some(pos) = s[10..].rfind('-') {
        (&s[..10 + pos], &s[10 + pos + 1..])
    } else {
        return Err(err());
    };
    let parts: Vec<&str> = date_time.splitn(2, 'T').collect();
    if parts.len() != 2 {
        return Err(err());
    }
    let date_parts: Vec<&str> = parts[0].split('-').collect();
    let time_parts: Vec<&str> = parts[1].split(':').collect();
    if date_parts.len() != 3 || time_parts.len() != 3 {
        return Err(err());
    }
    let year: i64 = date_parts[0].parse().map_err(|_| err())?;
    let month: i64 = date_parts[1].parse().map_err(|_| err())?;
    let day: i64 = date_parts[2].parse().map_err(|_| err())?;
    let hour: i64 = time_parts[0].parse().map_err(|_| err())?;
    let minute: i64 = time_parts[1].parse().map_err(|_| err())?;
    let sec_str = time_parts[2].split('.').next().unwrap_or(time_parts[2]);
    let second: i64 = sec_str.parse().map_err(|_| err())?;

    // Parse timezone offset HH:MM
    let tz_parts: Vec<&str> = tz.split(':').collect();
    let tz_hours: i64 = tz_parts.first().and_then(|s| s.parse().ok()).unwrap_or(0);
    let tz_mins: i64 = tz_parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(0);
    // Determine sign from original string
    let tz_sign: i64 =
        if date_time.len() < s.len() && s.as_bytes().get(date_time.len()) == Some(&b'-') {
            -1
        } else {
            1
        };
    let tz_offset_secs = tz_sign * (tz_hours * 3600 + tz_mins * 60);

    // Convert to Unix timestamp using simple Gregorian algorithm.
    // Days since Unix epoch (1970-01-01).
    let days = days_since_epoch(year, month, day).ok_or_else(err)?;
    let unix = days * 86400 + hour * 3600 + minute * 60 + second - tz_offset_secs;
    Ok(unix)
}

/// Compute days since Unix epoch for a Gregorian date (no external deps).
fn days_since_epoch(year: i64, month: i64, day: i64) -> Option<i64> {
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) || year < 1970 {
        return None;
    }
    // Use the proleptic Gregorian formula.
    let m = if month <= 2 { month + 12 } else { month };
    let y = if month <= 2 { year - 1 } else { year };
    let k = day + (153 * m - 457) / 5 + 365 * y + y / 4 - y / 100 + y / 400 - 719469;
    Some(k)
}

pub async fn new_order(
    State(state): State<Arc<AppState>>,
    body: Bytes,
) -> Result<Response, AcmeError> {
    let url = format!("{}/acme/new-order", state.config.base_url);
    let ctx = parse_jws(&state, body, &url).await?;

    let account_id = ctx
        .account_id
        .ok_or(AcmeError::Unauthorized("kid required".into()))?;

    // Account validity was already verified by parse_jws (SPKI cache or DB lookup).

    let payload: NewOrderPayload = require_payload(&ctx.payload, "new-order")?;

    // Validate identifiers.
    if payload.identifiers.is_empty() {
        return Err(AcmeError::BadRequest(
            "identifiers must not be empty".into(),
        ));
    }
    for id in &payload.identifiers {
        match id.r#type.as_str() {
            "dns" => {}
            "ip" => {
                // RFC 8738: validate that the value is a syntactically valid IP address
                // (IPv4 dotted-decimal or IPv6 colon-hex per RFC 5952).
                if id.value.parse::<std::net::IpAddr>().is_err() {
                    return Err(AcmeError::BadRequest(format!(
                        "invalid IP address identifier: '{}'",
                        id.value
                    )));
                }
            }
            other => return Err(AcmeError::UnsupportedIdentifier(other.into())),
        }
        // Validate ancestorDomain if present: identifier.value must end with
        // ".<ancestor_domain>" (label-aligned, case-insensitive).
        if let Some(ref ancestor) = id.ancestor_domain {
            let value_lc = id.value.to_ascii_lowercase();
            let ancestor_lc = ancestor.to_ascii_lowercase();
            let suffix = format!(".{}", ancestor_lc);
            if !value_lc.ends_with(&suffix) {
                return Err(AcmeError::BadRequest(
                    "ancestorDomain is not an ancestor of the identifier".into(),
                ));
            }
        }
    }

    // Validate the optional `replaces` cert_id (RFC 9773 §5).
    let validated_replaces: Option<String> = if let Some(ref cert_id) = payload.replaces {
        let pred = db::certs::get_by_cert_id(&state.db, cert_id)
            .await?
            .ok_or(AcmeError::NotFound)?;
        if pred.account_id != account_id {
            return Err(AcmeError::Unauthorized(
                "replaces certificate belongs to different account".into(),
            ));
        }
        if pred.replaced_by.is_some() {
            return Err(AcmeError::CertAlreadyReplaced);
        }
        Some(cert_id.clone())
    } else {
        None
    };

    // draft-aaron-acme-profiles-01: validate profile if specified.
    let order_profile: Option<String> = if let Some(ref p) = payload.profile {
        if !state.config.server.profiles.is_empty()
            && !state.config.server.profiles.contains_key(p.as_str())
        {
            return Err(AcmeError::InvalidProfile(format!(
                "profile '{p}' is not advertised by this server"
            )));
        }
        Some(p.clone())
    } else {
        None
    };

    // RFC 8739 §3.1.1: parse auto-renewal if present.
    let (
        star_start_date,
        star_end_date,
        star_lifetime_secs,
        star_lifetime_adjust_secs,
        star_allow_cert_get,
    ) = if let Some(ref ar) = payload.auto_renewal {
        // RFC 8739 §3.1.1: "notBefore" and "notAfter" MUST NOT be present with auto-renewal.
        if payload.not_before.is_some() || payload.not_after.is_some() {
            return Err(AcmeError::BadRequest(
                "notBefore and notAfter MUST NOT be present in a STAR order".into(),
            ));
        }
        let end_ts = parse_rfc3339(&ar.end_date).map_err(|_| {
            AcmeError::BadRequest("auto-renewal endDate is not valid RFC 3339".into())
        })?;
        let start_ts = if let Some(ref s) = ar.start_date {
            Some(parse_rfc3339(s).map_err(|_| {
                AcmeError::BadRequest("auto-renewal startDate is not valid RFC 3339".into())
            })?)
        } else {
            None
        };
        if ar.lifetime == 0 {
            return Err(AcmeError::BadRequest(
                "auto-renewal lifetime must be > 0".into(),
            ));
        }
        // RFC 8739 §3.1.1: enforce server-configured minimum lifetime and
        // maximum total renewal period when the operator has set them.
        if let Some(min) = state.config.server.star_min_lifetime_secs {
            if ar.lifetime < min {
                return Err(AcmeError::BadRequest(format!(
                    "STAR lifetime {lifetime}s is below server minimum {min}s",
                    lifetime = ar.lifetime,
                )));
            }
        }
        if let Some(max_dur) = state.config.server.star_max_duration_secs {
            let reference_ts = start_ts.unwrap_or_else(unix_now);
            let total_secs = (end_ts - reference_ts).max(0) as u64;
            if total_secs > max_dur {
                return Err(AcmeError::BadRequest(format!(
                    "STAR renewal period {total_secs}s exceeds server maximum {max_dur}s"
                )));
            }
        }
        (
            start_ts,
            Some(end_ts),
            Some(ar.lifetime as i64),
            ar.lifetime_adjust,
            i64::from(ar.allow_certificate_get),
        )
    } else {
        (None, None, None, 0, 0_i64)
    };

    let now = unix_now();
    let expiry = now + state.config.server.order_expiry_secs as i64;
    let authz_expiry = now + state.config.server.authz_expiry_secs as i64;

    let order_id = uuid::Uuid::new_v4().to_string();
    let identifiers_json = serde_json::to_string(
        &payload
            .identifiers
            .iter()
            .map(|id| json!({"type": id.r#type, "value": id.value}))
            .collect::<Vec<_>>(),
    )
    .unwrap();

    // Build all the rows before entering the DB call so we don't need to
    // cross an await boundary inside the transaction closure.
    struct AuthzPlan {
        authz_id: String,
        identifier_json: String,
        wildcard: bool,
        subdomain_auth_allowed: bool,
        challenges: Vec<(String, String)>, // (challenge_id, type)
        token: String,
    }

    let mut authz_plans: Vec<AuthzPlan> = Vec::new();
    let mut authz_urls: Vec<String> = Vec::new();

    for id in &payload.identifiers {
        let authz_id = uuid::Uuid::new_v4().to_string();
        // When ancestorDomain is set, issue the authz against the ancestor domain
        // and mark it subdomainAuthAllowed; the proof is for the ancestor, not
        // the exact subdomain.
        let (authz_type, authz_value, subdomain_auth_allowed) =
            if let Some(ref ancestor) = id.ancestor_domain {
                (id.r#type.as_str(), ancestor.as_str(), true)
            } else {
                (id.r#type.as_str(), id.value.as_str(), false)
            };

        // RFC 9799 §2: .onion domains require special handling.
        // Validate that .onion identifiers use v3 addresses and offer the
        // appropriate challenge types (onion-csr-01; optionally http-01 and
        // tls-alpn-01 for Tor-network-connected CAs; NEVER dns-01).
        if authz_type == "dns"
            && is_onion_domain(authz_value)
            && !crate::validation::onion_csr_01::validate_onion_v3(authz_value)
        {
            return Err(AcmeError::RejectedIdentifier(format!(
                "only v3 .onion addresses are supported (56-char base32 label); \
                 got: {authz_value}"
            )));
        }

        let identifier_json =
            serde_json::to_string(&json!({"type": authz_type, "value": authz_value})).unwrap();
        let token = gen_token();
        // dns-persist-01 is offered only when the operator has explicitly configured
        // an issuer domain — without it the challenge cannot be validated.
        let dns_persist_enabled = state.config.server.dns_persist_issuer_domain.is_some();
        let dns_types: &[&str] = if dns_persist_enabled {
            &["http-01", "dns-01", "tls-alpn-01", "dns-persist-01"]
        } else {
            &["http-01", "dns-01", "tls-alpn-01"]
        };
        // RFC 8555 §7.1.3 + RFC 8737 §3: wildcard identifiers MUST NOT use
        // http-01 or tls-alpn-01; only dns-01 (and dns-persist-01) are valid.
        let wildcard_dns_types: &[&str] = if dns_persist_enabled {
            &["dns-01", "dns-persist-01"]
        } else {
            &["dns-01"]
        };
        // RFC 9799 §3.1.1: for .onion domains MUST offer onion-csr-01 and
        // MUST NOT offer dns-01.  http-01 and tls-alpn-01 are allowed but
        // require Tor-network connectivity for actual validation; we include
        // them so that Tor-capable CAs can use them.
        let onion_types: &[&str] = &["onion-csr-01", "http-01", "tls-alpn-01"];
        let challenge_types: &[&str] = match authz_type {
            "dns" if is_onion_domain(authz_value) => onion_types,
            "dns" if authz_value.starts_with("*.") => wildcard_dns_types,
            "dns" => dns_types,
            "ip" => &["http-01", "tls-alpn-01"],
            _ => &[],
        };
        let challenges = challenge_types
            .iter()
            .map(|&t| (uuid::Uuid::new_v4().to_string(), t.to_string()))
            .collect();
        authz_urls.push(format!("{}/acme/authz/{}", state.config.base_url, authz_id));
        authz_plans.push(AuthzPlan {
            authz_id,
            identifier_json,
            wildcard: authz_value.starts_with("*."),
            subdomain_auth_allowed,
            challenges,
            token,
        });
    }

    // RFC 8555 §7.1.3: persist notBefore/notAfter from the request so the CA
    // can honour them at finalization time.  Parse early so errors surface here
    // rather than inside the transaction closure.
    let order_not_before: Option<i64> = payload
        .not_before
        .as_deref()
        .map(parse_rfc3339)
        .transpose()?;
    let order_not_after: Option<i64> = payload
        .not_after
        .as_deref()
        .map(parse_rfc3339)
        .transpose()?;

    // Write everything inside a single transaction so a partial failure
    // cannot leave orphaned orders, authorizations, or challenges.
    {
        let mut tx = db::begin_write(&state.db, state.db_kind).await?;

        db::orders::insert(
            &mut *tx,
            OrderRow {
                id: order_id.clone(),
                account_id: account_id.clone(),
                status: "pending".to_string(),
                expires: Some(expiry),
                identifiers: identifiers_json.clone(),
                not_before: order_not_before,
                not_after: order_not_after,
                error: None,
                certificate_id: None,
                replaces: validated_replaces.clone(),
                created: now,
                updated: now,
                star_start_date,
                star_end_date,
                star_lifetime_secs,
                star_lifetime_adjust_secs,
                star_allow_cert_get,
                star_canceled_at: None,
                star_csr_der: None,
                profile: order_profile.clone(),
            },
        )
        .await?;

        for plan in &authz_plans {
            db::authz::insert(
                &mut *tx,
                AuthorizationRow {
                    id: plan.authz_id.clone(),
                    order_id: order_id.clone(),
                    account_id: account_id.clone(),
                    status: "pending".to_string(),
                    identifier: plan.identifier_json.clone(),
                    expires: Some(authz_expiry),
                    wildcard: i64::from(plan.wildcard),
                    subdomain_auth_allowed: i64::from(plan.subdomain_auth_allowed),
                    created: now,
                    updated: now,
                },
            )
            .await?;

            if !plan.challenges.is_empty() {
                // Batch all challenge rows for this authz into a single INSERT
                // VALUES (...),(...),(...) statement — one DB round-trip instead
                // of one per challenge type (typically 3 for dns/http/tls-alpn).
                let mut qb = sqlx::QueryBuilder::new(
                    "INSERT INTO challenges \
                     (id, authz_id, type, status, token, validated, error, created, updated) ",
                );
                qb.push_values(plan.challenges.iter(), |mut b, (chall_id, chall_type)| {
                    b.push_bind(chall_id)
                        .push_bind(&plan.authz_id)
                        .push_bind(chall_type)
                        .push_bind("pending")
                        .push_bind(&plan.token)
                        .push_bind(None::<i64>) // validated
                        .push_bind(None::<String>) // error
                        .push_bind(now)
                        .push_bind(now);
                });
                qb.build().execute(&mut *tx).await?;
            }
        }
        tx.commit().await.map_err(AcmeError::from)?;
    }

    let base = &state.config.base_url;
    // Build a temporary OrderRow so we can reuse order_json() and get replaces for free.
    let new_order_row = OrderRow {
        id: order_id.clone(),
        account_id: account_id.clone(),
        status: "pending".to_string(),
        expires: Some(expiry),
        identifiers: identifiers_json.clone(),
        not_before: order_not_before,
        not_after: order_not_after,
        error: None,
        certificate_id: None,
        replaces: validated_replaces,
        created: now,
        updated: now,
        star_start_date,
        star_end_date,
        star_lifetime_secs,
        star_lifetime_adjust_secs,
        star_allow_cert_get,
        star_canceled_at: None,
        star_csr_der: None,
        profile: order_profile,
    };
    let mut resp = json_response(
        &state,
        StatusCode::CREATED,
        order_json(&new_order_row, &authz_urls, base),
        &ctx.next_nonce,
    )?;
    resp.headers_mut().insert(
        axum::http::header::LOCATION,
        format!("{base}/acme/order/{order_id}").parse().unwrap(),
    );
    Ok(resp)
}

/// Payload for POST /acme/order/{id} — either empty (GET-order) or cancellation.
#[derive(Deserialize, Default)]
struct OrderUpdatePayload {
    #[serde(default)]
    status: Option<String>,
}

pub async fn get_order(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    body: Bytes,
) -> Result<Response, AcmeError> {
    let url = format!("{}/acme/order/{}", state.config.base_url, id);
    let ctx = parse_jws(&state, body, &url).await?;

    let account_id = ctx
        .account_id
        .ok_or(AcmeError::Unauthorized("kid required".into()))?;

    // Fetch order and its authz IDs in one DB call.
    let (mut order, authz_ids) = db::orders::get_with_authz_ids(&state.db, &id)
        .await?
        .ok_or(AcmeError::NotFound)?;
    if order.account_id != account_id {
        return Err(AcmeError::Unauthorized(
            "order belongs to different account".into(),
        ));
    }

    // RFC 8739 §3.1.2: handle cancellation if payload contains {"status":"canceled"}.
    if !ctx.payload.is_empty() {
        let update: OrderUpdatePayload = serde_json::from_slice(&ctx.payload)
            .map_err(|e| AcmeError::BadRequest(format!("order update JSON: {e}")))?;

        if update.status.as_deref() == Some("canceled") {
            // Cancellation is only valid for STAR orders.
            if order.star_end_date.is_none() {
                return Err(AcmeError::BadRequest(
                    "cancellation is only valid for STAR (auto-renewal) orders".into(),
                ));
            }
            // RFC 8739 §3.1.2: the order must be in "valid" state to cancel.
            if order.status != "valid" {
                return Err(AcmeError::AutoRenewalCancellationInvalid);
            }
            let now = unix_now();
            db::orders::cancel_star(&state.db, &id, now).await?;
            order.star_canceled_at = Some(now);
            order.status = "canceled".to_string();
            order.updated = now;
        }
    }

    let authz_urls: Vec<_> = authz_ids
        .iter()
        .map(|aid| format!("{}/acme/authz/{}", state.config.base_url, aid))
        .collect();

    json_response(
        &state,
        StatusCode::OK,
        order_json(&order, &authz_urls, &state.config.base_url),
        &ctx.next_nonce,
    )
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// The `auto-renewal` object returned in order responses for STAR orders.
#[derive(Serialize)]
struct AutoRenewalJson {
    #[serde(skip_serializing_if = "Option::is_none", rename = "start-date")]
    start_date: Option<String>,
    #[serde(rename = "end-date")]
    end_date: String,
    lifetime: i64,
    #[serde(rename = "lifetime-adjust", skip_serializing_if = "Option::is_none")]
    lifetime_adjust: Option<i64>,
    #[serde(
        rename = "allow-certificate-get",
        skip_serializing_if = "Option::is_none"
    )]
    allow_certificate_get: Option<bool>,
}

/// Typed ACME order response body. Using `Box<RawValue>` for `identifiers`
/// avoids the `serde_json::from_str` parse + `Vec<Value>` / `HashMap`
/// allocations that the old `json!` macro approach required. The identifiers
/// JSON string stored in the DB is embedded directly into the response without
/// being re-parsed.
#[derive(Serialize)]
pub(crate) struct OrderJson<'a> {
    status: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    expires: Option<String>,
    /// RFC 8555 §7.1.3: echo notBefore/notAfter back in the order object when set.
    #[serde(rename = "notBefore", skip_serializing_if = "Option::is_none")]
    not_before: Option<String>,
    #[serde(rename = "notAfter", skip_serializing_if = "Option::is_none")]
    not_after: Option<String>,
    identifiers: Box<serde_json::value::RawValue>,
    authorizations: &'a [String],
    finalize: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    certificate: Option<String>,
    #[serde(rename = "star-certificate", skip_serializing_if = "Option::is_none")]
    star_certificate: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<Box<serde_json::value::RawValue>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    replaces: Option<&'a str>,
    #[serde(rename = "auto-renewal", skip_serializing_if = "Option::is_none")]
    auto_renewal: Option<AutoRenewalJson>,
    /// draft-aaron-acme-profiles-01
    #[serde(skip_serializing_if = "Option::is_none")]
    profile: Option<&'a str>,
}

pub(crate) fn order_json<'a>(
    order: &'a OrderRow,
    authz_urls: &'a [String],
    base_url: &str,
) -> OrderJson<'a> {
    // Embed identifiers as raw JSON — no parse, no Vec<Value>/HashMap allocs.
    // The stored string is always valid JSON (written by serde_json::to_string).
    let identifiers = serde_json::value::RawValue::from_string(order.identifiers.clone())
        .unwrap_or_else(|_| serde_json::value::RawValue::from_string("[]".to_string()).unwrap());
    // Same for error: embed raw JSON if present; skip if None or unparseable.
    let error = order
        .error
        .as_deref()
        .and_then(|s| serde_json::value::RawValue::from_string(s.to_string()).ok());

    // Build STAR auto-renewal object if this is a STAR order.
    let auto_renewal = order.star_end_date.map(|end_ts| AutoRenewalJson {
        start_date: order.star_start_date.map(fmt_time),
        end_date: fmt_time(end_ts),
        lifetime: order.star_lifetime_secs.unwrap_or(0),
        lifetime_adjust: if order.star_lifetime_adjust_secs != 0 {
            Some(order.star_lifetime_adjust_secs)
        } else {
            None
        },
        allow_certificate_get: if order.star_allow_cert_get != 0 {
            Some(true)
        } else {
            None
        },
    });

    // star-certificate URL: present when order is valid and is a STAR order.
    let star_certificate = if order.star_end_date.is_some() && order.status == "valid" {
        Some(format!("{base_url}/acme/cert/star/{}", order.id))
    } else {
        None
    };

    OrderJson {
        status: &order.status,
        expires: order.expires.map(fmt_time),
        not_before: order.not_before.map(fmt_time),
        not_after: order.not_after.map(fmt_time),
        identifiers,
        authorizations: authz_urls,
        finalize: format!("{base_url}/acme/order/{}/finalize", order.id),
        certificate: if order.status == "valid" && order.star_end_date.is_none() {
            order
                .certificate_id
                .as_ref()
                .map(|c| format!("{base_url}/acme/cert/{c}"))
        } else {
            None
        },
        star_certificate,
        error,
        replaces: order.replaces.as_deref(),
        auto_renewal,
        profile: order.profile.as_deref(),
    }
}

/// Return `true` if `value` ends with `.onion` (any case).
///
/// This is a quick syntactic check; the caller is responsible for validating
/// that it is a properly formed v3 address.
fn is_onion_domain(value: &str) -> bool {
    value.to_ascii_lowercase().ends_with(".onion")
}

fn gen_token() -> String {
    let mut bytes = [0u8; 32];
    getrandom::getrandom(&mut bytes).unwrap_or(());
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    URL_SAFE_NO_PAD.encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_order(
        status: &str,
        expires: Option<i64>,
        cert_id: Option<&str>,
        error: Option<&str>,
    ) -> OrderRow {
        OrderRow {
            id: "order-1".to_string(),
            account_id: "acct-1".to_string(),
            status: status.to_string(),
            expires,
            identifiers: "[{\"type\":\"dns\",\"value\":\"example.com\"}]".to_string(),
            not_before: None,
            not_after: None,
            error: error.map(|s| s.to_string()),
            certificate_id: cert_id.map(|s| s.to_string()),
            replaces: None,
            created: 1_700_000_000,
            updated: 1_700_000_000,
            star_start_date: None,
            star_end_date: None,
            star_lifetime_secs: None,
            star_lifetime_adjust_secs: 0,
            star_allow_cert_get: 0,
            star_canceled_at: None,
            star_csr_der: None,
            profile: None,
        }
    }

    // Helper: serialize the typed OrderJson to a serde_json::Value for assertions.
    fn to_val<'a>(j: OrderJson<'a>) -> serde_json::Value {
        serde_json::to_value(j).unwrap()
    }

    #[test]
    fn order_json_pending_order() {
        let order = make_order("pending", Some(1_700_100_000), None, None);
        let json = to_val(order_json(
            &order,
            &["https://acme.test/acme/authz/a".to_string()],
            "https://acme.test",
        ));
        assert_eq!(json["status"], "pending");
        assert!(json["expires"].as_str().is_some());
        assert!(json["certificate"].is_null() || json.get("certificate").is_none());
        assert!(json["finalize"].as_str().unwrap().contains("order-1"));
    }

    #[test]
    fn order_json_valid_order_includes_certificate() {
        let order = make_order("valid", None, Some("cert-abc"), None);
        let json = to_val(order_json(&order, &[], "https://acme.test"));
        assert_eq!(json["status"], "valid");
        assert!(json["certificate"].as_str().unwrap().contains("cert-abc"));
    }

    #[test]
    fn order_json_invalid_order_includes_error() {
        let order = make_order(
            "invalid",
            None,
            None,
            Some("{\"type\":\"urn:ietf:params:acme:error:connection\",\"detail\":\"failed\"}"),
        );
        let json = to_val(order_json(&order, &[], "https://acme.test"));
        assert_eq!(json["status"], "invalid");
        assert_eq!(
            json["error"]["type"],
            "urn:ietf:params:acme:error:connection"
        );
    }

    #[test]
    fn order_json_no_expires_when_none() {
        let order = make_order("ready", None, None, None);
        let json = to_val(order_json(&order, &[], "https://acme.test"));
        assert!(json.get("expires").is_none() || json["expires"].is_null());
    }

    #[test]
    fn order_json_valid_status_without_cert_no_certificate_field() {
        // valid status but no certificate_id → no "certificate" field
        let order = make_order("valid", None, None, None);
        let json = to_val(order_json(&order, &[], "https://acme.test"));
        // either missing or null
        assert!(json.get("certificate").map_or(true, |v| v.is_null()));
    }

    #[test]
    fn order_json_with_replaces_includes_field() {
        let mut order = make_order("pending", None, None, None);
        order.replaces = Some("akiABC.serialXYZ".to_string());
        let json = to_val(order_json(&order, &[], "https://acme.test"));
        assert_eq!(json["replaces"], "akiABC.serialXYZ");
    }

    #[test]
    fn order_json_without_replaces_omits_field() {
        let order = make_order("pending", None, None, None);
        let json = to_val(order_json(&order, &[], "https://acme.test"));
        assert!(json.get("replaces").map_or(true, |v| v.is_null()));
    }

    #[test]
    fn gen_token_returns_non_empty_string() {
        let t = gen_token();
        assert!(!t.is_empty());
        // Should be base64url without padding — only alphanumeric, '-', '_'
        assert!(t
            .chars()
            .all(|c| c.is_alphanumeric() || c == '-' || c == '_'));
    }

    #[test]
    fn order_json_star_order_includes_auto_renewal() {
        let mut order = make_order("valid", None, Some("cert-xyz"), None);
        order.star_end_date = Some(1_800_000_000);
        order.star_lifetime_secs = Some(86400);
        order.star_allow_cert_get = 1;
        let json = to_val(order_json(&order, &[], "https://acme.test"));
        assert_eq!(json["status"], "valid");
        // star-certificate should be present, not regular certificate
        assert!(json["star-certificate"]
            .as_str()
            .unwrap()
            .contains("order-1"));
        assert!(json.get("certificate").map_or(true, |v| v.is_null()));
        // auto-renewal object present
        let ar = &json["auto-renewal"];
        assert!(ar.is_object());
        assert_eq!(ar["lifetime"], 86400);
        assert_eq!(ar["allow-certificate-get"], true);
    }

    #[test]
    fn order_json_non_star_valid_does_not_have_star_certificate() {
        let order = make_order("valid", None, Some("cert-abc"), None);
        let json = to_val(order_json(&order, &[], "https://acme.test"));
        assert!(json.get("star-certificate").map_or(true, |v| v.is_null()));
        assert!(json["certificate"].as_str().unwrap().contains("cert-abc"));
    }

    #[test]
    fn parse_rfc3339_utc_z() {
        let ts = parse_rfc3339("2025-01-01T00:00:00Z").unwrap();
        // 2025-01-01 = 1735689600
        assert_eq!(ts, 1_735_689_600);
    }

    #[test]
    fn parse_rfc3339_with_offset() {
        // 2025-01-01T01:00:00+01:00 == 2025-01-01T00:00:00Z
        let ts = parse_rfc3339("2025-01-01T01:00:00+01:00").unwrap();
        assert_eq!(ts, 1_735_689_600);
    }

    #[test]
    fn parse_rfc3339_invalid_returns_error() {
        assert!(parse_rfc3339("not-a-date").is_err());
        assert!(parse_rfc3339("2020-13-01T00:00:00Z").is_err()); // month 13 ok structurally but days_since_epoch returns None for year < 1970 check — actually month 13 is > 12 → None
    }

    #[test]
    fn order_json_with_profile_includes_field() {
        let mut order = make_order("pending", None, None, None);
        order.profile = Some("tls-server-auth".to_string());
        let json = to_val(order_json(&order, &[], "https://acme.test"));
        assert_eq!(json["profile"], "tls-server-auth");
    }

    #[test]
    fn order_json_without_profile_omits_field() {
        let order = make_order("pending", None, None, None);
        let json = to_val(order_json(&order, &[], "https://acme.test"));
        assert!(json.get("profile").map_or(true, |v| v.is_null()));
    }
}
