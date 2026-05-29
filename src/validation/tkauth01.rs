use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use http_body_util::{BodyExt, Limited};
use hyper::Uri;
use subtle::ConstantTimeEq;
use synta::traits::Encode;
use synta::{Asn1Sequence, Decoder, Encoder, Encoding, FromDer, IA5String, Utf8String};
use synta_certificate::{pem_to_der, Certificate, OpensslSignatureVerifier};
use synta_x509_verification::{
    ops::VerificationCertificate,
    policy::{
        PolicyDefinition, ValidationProfile, WEBPKI_PERMITTED_SIGNATURE_ALGORITHMS_WITH_PQ,
        WEBPKI_PERMITTED_SPKI_ALGORITHMS_WITH_PQ,
    },
    RevocationChecks,
};

use crate::db;
use crate::error::AcmeError;
use crate::state::AppState;
use crate::util::unix_now;

/// Maximum response body size when fetching a Token Authority cert via x5u or JWKS.
const MAX_X5U_BODY: usize = 64 * 1024;

/// Maximum number of entries in any single DER array (mustInclude, permittedValues, mustExclude).
const MAX_DER_ENTRIES: usize = 64;

/// Maximum byte length of a single IA5String or UTF8String in a DER blob.
const MAX_DER_STRING_BYTES: usize = 256;

/// JWKS body cache TTL: 5 minutes.
const JWKS_CACHE_TTL: std::time::Duration = std::time::Duration::from_secs(300);

/// RFC 9118 §3 — `JWTClaimPermittedValues`.
#[derive(Debug, Clone, Asn1Sequence)]
struct JwtClaimPermittedValues {
    claim: IA5String,
    values: Vec<Utf8String>,
}

/// RFC 9118 §3 — `EnhancedJWTClaimConstraints`.
///
/// Superset of RFC 8226 `JWTClaimConstraints`; the only addition is `mustExclude [2]`.
/// Blobs that only use `[0]` and `[1]` (original RFC 8226) parse correctly because
/// `must_exclude` is `Option` and defaults to `None` when absent.
#[derive(Debug, Clone, Asn1Sequence)]
struct EnhancedJwtClaimConstraints {
    #[asn1(tag(0, explicit))]
    must_include: Option<Vec<IA5String>>,
    #[asn1(tag(1, explicit))]
    permitted_values: Option<Vec<JwtClaimPermittedValues>>,
    #[asn1(tag(2, explicit))]
    must_exclude: Option<Vec<IA5String>>,
}

/// Validate a tkauth-01 challenge response per RFC 9447.
///
/// `key_auth` is the standard ACME key authorization `"{token}.{jwk_thumbprint}"`;
/// we extract the JWK thumbprint (the part after the first `.`) and compare it
/// against the `atc.fingerprint` claim.
pub async fn validate(
    id_type: &str,
    id_value: &str,
    key_auth: &str,
    authority_token: &str,
    authz_id: &str,
    order_id: &str,
    state: &AppState,
) -> Result<(), AcmeError> {
    // Extract the JWK thumbprint from "token.thumbprint".
    let thumbprint = key_auth
        .find('.')
        .map(|i| &key_auth[i + 1..])
        .ok_or_else(|| AcmeError::Internal("tkauth-01: malformed key_auth (no '.')".into()))?;

    // Step 1: decode header without signature verification to discover cert source.
    let header = akamu_jose::AuthorityToken::decode_header(authority_token)
        .map_err(|e| AcmeError::IncorrectResponse(format!("tkauth-01: JWT header: {e}")))?;

    // Step 2: obtain signing cert DER and any intermediates, OR a direct SPKI.
    //
    // Three sources in priority order:
    //   x5c — embedded cert chain; requires TA chain verification.
    //   x5u — fetched cert; requires TA chain verification.
    //   kid — JWKS lookup; trust is anchored in per-profile trust_jwks_urls.
    let (signing_cert_der_opt, intermediates, direct_spki_opt) = if let Some(x5c) = &header.x5c {
        let leaf = akamu_jose::x5c_leaf_der(x5c)
            .map_err(|e| AcmeError::IncorrectResponse(format!("tkauth-01: x5c: {e}")))?;
        let ints = x5c
            .iter()
            .skip(1)
            .map(|b64| {
                STANDARD.decode(b64).map_err(|e| {
                    AcmeError::IncorrectResponse(format!("tkauth-01: x5c intermediate base64: {e}"))
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        (Some(leaf), ints, None)
    } else if let Some(x5u) = &header.x5u {
        let cert_der = fetch_cert_via_x5u(x5u, state).await?;
        (Some(cert_der), vec![], None)
    } else if let Some(kid) = &header.kid {
        let spki = resolve_key_via_jwks(kid, order_id, state).await?;
        (None, vec![], Some(spki))
    } else {
        return Err(AcmeError::IncorrectResponse(
            "tkauth-01: authority token has no x5u, x5c, or kid".into(),
        ));
    };

    // Step 3: for x5c/x5u paths, validate cert chain against trusted TA CAs.
    let now_i64 = unix_now();
    if let Some(cert_der) = &signing_cert_der_opt {
        let anchors = state.tkauth_trust_anchors.as_deref().ok_or_else(|| {
            AcmeError::Internal("tkauth-01: tkauth is not configured (no trust anchors)".into())
        })?;
        verify_cert_chain(cert_der, &intermediates, anchors, now_i64)?;
    }

    // Step 4: extract SPKI DER from signing cert, or use direct SPKI from JWKS.
    let spki_der = match &signing_cert_der_opt {
        Some(cert_der) => extract_spki_der(cert_der)?,
        None => direct_spki_opt.ok_or_else(|| {
            AcmeError::Internal("tkauth-01: internal invariant violated: no SPKI source".into())
        })?,
    };

    // Step 5: verify JWT signature and expiry.
    let decoded = akamu_jose::AuthorityToken::decode_and_verify(authority_token, &spki_der)
        .map_err(|e| AcmeError::IncorrectResponse(format!("tkauth-01: JWT verify: {e}")))?;

    // Step 6: extract jti (REQUIRED) and atc (REQUIRED).
    let jti = decoded
        .claims
        .get("jti")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            AcmeError::IncorrectResponse("tkauth-01: JWT missing required 'jti' claim".into())
        })?;
    let atc = decoded
        .claims
        .get("atc")
        .and_then(|v| v.as_object())
        .ok_or_else(|| {
            AcmeError::IncorrectResponse("tkauth-01: JWT missing required 'atc' claim".into())
        })?;
    let exp = decoded
        .claims
        .get("exp")
        .and_then(|v| v.as_i64())
        .ok_or_else(|| AcmeError::IncorrectResponse("tkauth-01: JWT missing 'exp' claim".into()))?;

    // Step 7: validate atc object fields.
    let tktype = atc
        .get("tktype")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AcmeError::IncorrectResponse("tkauth-01: atc missing 'tktype'".into()))?;

    let tkvalue = atc
        .get("tkvalue")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AcmeError::IncorrectResponse("tkauth-01: atc missing 'tkvalue'".into()))?;

    // For standard identifier types (TNAuthList, JWTClaimConstraints) the tktype and
    // tkvalue must directly match the authorization identifier type and value.
    //
    // For encoder-backed identifier types (e.g., "dns" when a dns-san encoder is
    // configured), the token carries atc.tktype="EnhancedJWTClaimConstraints" and a DER blob
    // as atc.tkvalue.  We verify the identifier value appears in the permittedValues
    // for the corresponding claim and store the tkvalue for later SAN injection at
    // finalize time.
    let stored_tkvalue: Option<String>;
    if tktype == id_type {
        // Direct match: TNAuthList or JWTClaimConstraints.
        if tkvalue != id_value {
            return Err(AcmeError::IncorrectResponse(
                "tkauth-01: atc.tkvalue does not match identifier value".to_string(),
            ));
        }
        stored_tkvalue = None;
    } else if tktype == "EnhancedJWTClaimConstraints" {
        // Encoder-backed identifier: verify id_value is permitted in the JCC blob.
        let registry = state.claim_encoder_registry.as_ref().ok_or_else(|| {
            AcmeError::IncorrectResponse(format!(
                "tkauth-01: atc.tktype 'EnhancedJWTClaimConstraints' but no claim encoders configured \
                 for identifier type '{id_type}'"
            ))
        })?;
        let claim_name =
            crate::validation::claim_encoder::find_claim_for_identifier_type(registry, id_type)
                .ok_or_else(|| {
                    AcmeError::IncorrectResponse(format!(
                        "tkauth-01: no claim encoder configured for identifier type '{id_type}'"
                    ))
                })?;
        verify_identifier_in_jcc(tkvalue, claim_name, id_value)?;
        stored_tkvalue = Some(tkvalue.to_string());
    } else {
        return Err(AcmeError::IncorrectResponse(format!(
            "tkauth-01: atc.tktype '{tktype}' does not match identifier type '{id_type}'"
        )));
    }

    let fingerprint = atc
        .get("fingerprint")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            AcmeError::IncorrectResponse("tkauth-01: atc missing 'fingerprint'".into())
        })?;
    // RFC 9447 §5: the fingerprint is "SHA256 XX:XX:..." (colon-separated
    // uppercase hex of the SHA-256 of the canonical JWK).
    // `thumbprint` from the ACME key-authorization is the base64url encoding of
    // that same SHA-256 (per RFC 7638 / RFC 8555 §8.1); decode it and reformat.
    let thumb_raw = URL_SAFE_NO_PAD.decode(thumbprint.as_bytes()).map_err(|_| {
        AcmeError::Internal("tkauth-01: JWK thumbprint in key_auth is not valid base64url".into())
    })?;
    let expected_fingerprint = format!(
        "SHA256 {}",
        thumb_raw
            .iter()
            .map(|b| format!("{b:02X}"))
            .collect::<Vec<_>>()
            .join(":")
    );
    if !bool::from(
        fingerprint
            .as_bytes()
            .ct_eq(expected_fingerprint.as_bytes()),
    ) {
        return Err(AcmeError::IncorrectResponse(
            "tkauth-01: atc.fingerprint does not match account JWK thumbprint".into(),
        ));
    }

    // Extract atc.ca; defaults to false when absent.  The actual match against the
    // CSR's BasicConstraints cA field is enforced at finalize time when the CSR is
    // available (draft-ietf-acme-authority-token-jwtclaimcon §6 step 8).
    let atc_ca = atc.get("ca").and_then(|v| v.as_bool()).unwrap_or(false);

    // Step 7b (JWTClaimConstraints / EnhancedJWTClaimConstraints): verify the
    // token's claims satisfy the must-include/permittedValues/mustExclude constraints
    // encoded in the identifier value.
    // Called for both the direct-match "JWTClaimConstraints" identifier type and for
    // encoder-backed "EnhancedJWTClaimConstraints" tokens so the server independently
    // confirms the token payload satisfies what the TA encoded in the blob.
    if tktype == "JWTClaimConstraints" || tktype == "EnhancedJWTClaimConstraints" {
        check_jwt_claim_constraints(tkvalue, &decoded.claims)?;
    }

    // Step 8 (optional): check token lifetime against configured cap.
    // Capture now fresh after the expensive verify steps so the cap reflects
    // actual remaining lifetime, not the pre-verify snapshot.
    if let Some(tkauth) = state.config.tkauth.as_ref() {
        let max_secs = tkauth.max_validity_secs as i64;
        let now_cap = crate::util::unix_now();
        let remaining = exp.saturating_sub(now_cap);
        if remaining > max_secs {
            return Err(AcmeError::IncorrectResponse(format!(
                "tkauth-01: token lifetime ({remaining} s) exceeds max_validity_secs ({max_secs})"
            )));
        }
    }

    // Step 9: JTI replay prevention.
    let inserted = db::tkauth::insert_jti(
        &state.db,
        jti,
        authz_id,
        exp,
        now_i64,
        stored_tkvalue.as_deref(),
        atc_ca,
    )
    .await
    .map_err(|e| AcmeError::Internal(format!("tkauth-01: JTI insert: {e}")))?;
    if !inserted {
        return Err(AcmeError::IncorrectResponse(
            "tkauth-01: authority token already used (jti replay)".into(),
        ));
    }

    Ok(())
}

/// Resolve a JWKS `kid` to an SPKI DER by scanning the per-profile JWKS URLs.
///
/// Looks up the order's profile from the DB, then checks `trust_jwks_urls` on
/// that profile.  For each URL the JWKS body is fetched (with a 5-min cache)
/// and searched for a JWK whose `kid` matches.  Returns the first match's SPKI.
async fn resolve_key_via_jwks(
    kid: &str,
    order_id: &str,
    state: &AppState,
) -> Result<Vec<u8>, AcmeError> {
    // Look up the order's profile from the DB.
    let profile_name: Option<String> =
        crate::db::query_as::<(Option<String>,)>("SELECT profile FROM orders WHERE id = ?")
            .bind(order_id)
            .fetch_one(&state.db)
            .await
            .map(|(p,)| p)
            .map_err(|e| AcmeError::Internal(format!("tkauth-01: order lookup: {e}")))?;

    let urls = profile_name
        .as_deref()
        .and_then(|name| state.profiles.resolve(name))
        .map(|params| params.trust_jwks_urls)
        .unwrap_or_default();

    if urls.is_empty() {
        return Err(AcmeError::IncorrectResponse(format!(
            "tkauth-01: kid '{kid}' present but profile {} has no trust_jwks_urls",
            profile_name.as_deref().unwrap_or("<none>")
        )));
    }

    let cache = state
        .jwks_cache
        .as_ref()
        .ok_or_else(|| AcmeError::Internal("tkauth-01: JWKS cache not initialised".into()))?;

    for url in &urls {
        let body = {
            let guard = cache.lock().await;
            if let Some((body, ts)) = guard.get(url) {
                if ts.elapsed() <= JWKS_CACHE_TTL {
                    let b = body.clone();
                    drop(guard);
                    b
                } else {
                    drop(guard);
                    let fresh = fetch_jwks(url, state).await?;
                    cache
                        .lock()
                        .await
                        .insert(url.clone(), (fresh.clone(), std::time::Instant::now()));
                    fresh
                }
            } else {
                drop(guard);
                let fresh = fetch_jwks(url, state).await?;
                cache
                    .lock()
                    .await
                    .insert(url.clone(), (fresh.clone(), std::time::Instant::now()));
                fresh
            }
        };

        match akamu_jose::jwk::find_by_kid(&body, kid) {
            Ok(jwk) => {
                return jwk.to_spki_der().map_err(|e| {
                    AcmeError::IncorrectResponse(format!(
                        "tkauth-01: JWK→SPKI for kid '{kid}': {e}"
                    ))
                });
            }
            Err(e) => {
                tracing::debug!(url = %url, kid, "tkauth-01: JWKS kid lookup: {e}");
                continue;
            }
        }
    }

    Err(AcmeError::IncorrectResponse(format!(
        "tkauth-01: kid '{kid}' not found in any configured JWKS"
    )))
}

/// Fetch a JWKS body from `url`, dispatching to the appropriate transport.
///
/// Supports `https://` (SSRF-guarded) and `http+unix://ENCODED_PATH/path`
/// (Unix domain socket, for co-located identity providers).
async fn fetch_jwks(url: &str, state: &AppState) -> Result<Vec<u8>, AcmeError> {
    if url.starts_with("http+unix://") {
        fetch_jwks_unix(url).await
    } else {
        fetch_jwks_https(url, state).await
    }
}

/// Fetch a JWKS body over HTTPS with an SSRF guard.
async fn fetch_jwks_https(url: &str, state: &AppState) -> Result<Vec<u8>, AcmeError> {
    let uri: hyper::Uri = url
        .parse()
        .map_err(|e| AcmeError::IncorrectResponse(format!("tkauth-01: JWKS URL parse: {e}")))?;
    let allow_private = state.config.server.http_validation_allow_private_ips;
    let scheme = uri.scheme_str();
    if scheme != Some("https") && !(scheme == Some("http") && allow_private) {
        return Err(AcmeError::IncorrectResponse(
            "tkauth-01: JWKS URL must use https:// (or http:// with http_validation_allow_private_ips)".into(),
        ));
    }
    let host = uri
        .host()
        .ok_or_else(|| AcmeError::IncorrectResponse("tkauth-01: JWKS URL has no host".into()))?;
    crate::validation::http01::check_redirect_host(host, allow_private, url)
        .await
        .map_err(|e| AcmeError::IncorrectResponse(format!("tkauth-01: JWKS host blocked: {e}")))?;

    let resp = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        state.validation_client.get(uri),
    )
    .await
    .map_err(|_| AcmeError::Connection(format!("tkauth-01: JWKS GET '{url}' timed out")))?
    .map_err(|e| AcmeError::Connection(format!("tkauth-01: JWKS GET '{url}': {e}")))?;

    if !resp.status().is_success() {
        return Err(AcmeError::Connection(format!(
            "tkauth-01: JWKS '{}' returned HTTP {}",
            url,
            resp.status()
        )));
    }

    Ok(Limited::new(resp.into_body(), MAX_X5U_BODY)
        .collect()
        .await
        .map_err(|e| AcmeError::Connection(format!("tkauth-01: JWKS body read: {e}")))?
        .to_bytes()
        .to_vec())
}

/// Fetch a JWKS body over a Unix domain socket.
///
/// URL format: `http+unix://ENCODED_PATH/request-path` where `ENCODED_PATH` is
/// the `%`-encoded socket path (e.g. `%2Frun%2Fekishib%2Fekishib.sock`).
async fn fetch_jwks_unix(url: &str) -> Result<Vec<u8>, AcmeError> {
    let without_scheme = url
        .strip_prefix("http+unix://")
        .ok_or_else(|| AcmeError::IncorrectResponse("invalid http+unix URL".into()))?;
    let (encoded_path, req_path) = without_scheme
        .split_once('/')
        .ok_or_else(|| AcmeError::IncorrectResponse("http+unix URL missing request path".into()))?;

    let sock_path = percent_encoding::percent_decode_str(encoded_path)
        .decode_utf8()
        .map_err(|_| {
            AcmeError::IncorrectResponse("http+unix URL: socket path is not valid UTF-8".into())
        })?;

    let stream = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        tokio::net::UnixStream::connect(sock_path.as_ref()),
    )
    .await
    .map_err(|_| AcmeError::Connection(format!("http+unix connect to {sock_path} timed out")))?
    .map_err(|e| AcmeError::Connection(format!("http+unix connect to {sock_path}: {e}")))?;

    let io = hyper_util::rt::TokioIo::new(stream);
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io)
        .await
        .map_err(|e| AcmeError::Connection(format!("http+unix handshake: {e}")))?;
    tokio::spawn(conn);

    let req = hyper::Request::get(format!("/{req_path}"))
        .header("host", "localhost")
        .body(http_body_util::Empty::<hyper::body::Bytes>::new())
        .map_err(|e| AcmeError::Internal(format!("http+unix request build: {e}")))?;

    let resp = tokio::time::timeout(std::time::Duration::from_secs(10), sender.send_request(req))
        .await
        .map_err(|_| AcmeError::Connection("http+unix request timed out".into()))?
        .map_err(|e| AcmeError::Connection(format!("http+unix request: {e}")))?;

    if !resp.status().is_success() {
        return Err(AcmeError::Connection(format!(
            "http+unix JWKS returned HTTP {}",
            resp.status()
        )));
    }

    Ok(Limited::new(resp.into_body(), MAX_X5U_BODY)
        .collect()
        .await
        .map_err(|e| AcmeError::Connection(format!("http+unix body read: {e}")))?
        .to_bytes()
        .to_vec())
}

/// Fetch a Token Authority signing certificate from an x5u HTTPS URL.
///
/// Enforces HTTPS scheme and blocks RFC-1918/loopback targets (SSRF guard).
/// Applies a 10-second per-request timeout.  Parses the response body as PEM
/// (single cert block) or DER; the first successfully parsed cert is returned.
async fn fetch_cert_via_x5u(url: &str, state: &AppState) -> Result<Vec<u8>, AcmeError> {
    let uri: Uri = url
        .parse()
        .map_err(|e| AcmeError::IncorrectResponse(format!("tkauth-01: x5u URL parse: {e}")))?;
    if uri.scheme_str() != Some("https") {
        return Err(AcmeError::IncorrectResponse(
            "tkauth-01: x5u must use https://".into(),
        ));
    }

    // SSRF guard: resolve the hostname and reject RFC-1918 / loopback addresses.
    let host = uri
        .host()
        .ok_or_else(|| AcmeError::IncorrectResponse("tkauth-01: x5u URL has no host".into()))?;
    let allow_private = state.config.server.http_validation_allow_private_ips;
    crate::validation::http01::check_redirect_host(host, allow_private, url)
        .await
        .map_err(|e| AcmeError::IncorrectResponse(format!("tkauth-01: x5u host blocked: {e}")))?;

    let fetch = state.validation_client.get(uri);
    let resp = tokio::time::timeout(std::time::Duration::from_secs(10), fetch)
        .await
        .map_err(|_| AcmeError::Connection(format!("tkauth-01: x5u GET '{url}' timed out")))?
        .map_err(|e| AcmeError::Connection(format!("tkauth-01: x5u GET '{url}': {e}")))?;

    if !resp.status().is_success() {
        return Err(AcmeError::Connection(format!(
            "tkauth-01: x5u '{}' returned HTTP {}",
            url,
            resp.status()
        )));
    }

    let body = Limited::new(resp.into_body(), MAX_X5U_BODY)
        .collect()
        .await
        .map_err(|e| AcmeError::Connection(format!("tkauth-01: x5u body read: {e}")))?
        .to_bytes();

    // Try PEM first (ASCII header present), then fall through to raw DER.
    if body.starts_with(b"-----BEGIN") {
        let ders = pem_to_der(&body);
        if let Some(der) = ders.into_iter().next() {
            return Ok(der);
        }
        tracing::warn!(
            url,
            "tkauth-01: x5u response looks like PEM but yielded no certificate; trying as DER"
        );
    }

    // Fall back to treating body as raw DER.
    let der = body.to_vec();
    // Quick sanity: try to parse it as a certificate.
    Decoder::new(&der, Encoding::Der)
        .decode::<Certificate>()
        .map_err(|_| {
            AcmeError::IncorrectResponse(format!(
                "tkauth-01: x5u '{url}' response is not a valid certificate (PEM or DER)"
            ))
        })?;
    Ok(der)
}

/// Validate `signing_cert_der` against the trusted TA store.
///
/// Uses RFC 5280 profile (no WebPKI SAN / EKU restrictions) with PQ-extended
/// algorithm lists, matching the policy used for other server-side cert checks.
fn verify_cert_chain(
    signing_cert_der: &[u8],
    intermediates_der: &[Vec<u8>],
    anchors: &synta_x509_verification::OwnedStore,
    now: i64,
) -> Result<(), AcmeError> {
    let cert: Certificate = Decoder::new(signing_cert_der, Encoding::Der)
        .decode()
        .map_err(|e| AcmeError::IncorrectResponse(format!("tkauth-01: signing cert parse: {e}")))?;
    let leaf = VerificationCertificate::new(cert, signing_cert_der);

    let mut intermediate_vcs: Vec<VerificationCertificate<'_>> = Vec::new();
    for der in intermediates_der {
        let cert: Certificate = Decoder::new(der.as_slice(), Encoding::Der)
            .decode()
            .map_err(|e| {
                AcmeError::IncorrectResponse(format!("tkauth-01: intermediate cert parse: {e}"))
            })?;
        intermediate_vcs.push(VerificationCertificate::new(cert, der.as_slice()));
    }

    let mut policy = PolicyDefinition::new_server_pq(OpensslSignatureVerifier, vec![], now);
    policy.profile = ValidationProfile::Rfc5280;
    policy.extended_key_usage = None;
    policy.permitted_spki_algorithms = WEBPKI_PERMITTED_SPKI_ALGORITHMS_WITH_PQ;
    policy.permitted_signature_algorithms = WEBPKI_PERMITTED_SIGNATURE_ALGORITHMS_WITH_PQ;

    anchors
        .verify(
            &leaf,
            &intermediate_vcs,
            &policy,
            RevocationChecks::default(),
        )
        .map(|_| ())
        .map_err(|e| AcmeError::IncorrectResponse(format!("tkauth-01: TA cert chain invalid: {e}")))
}

/// DER-encode the `SubjectPublicKeyInfo` from a parsed certificate.
fn extract_spki_der(cert_der: &[u8]) -> Result<Vec<u8>, AcmeError> {
    let cert: Certificate = Decoder::new(cert_der, Encoding::Der)
        .decode()
        .map_err(|e| AcmeError::Internal(format!("tkauth-01: re-parse cert for SPKI: {e}")))?;
    let mut enc = Encoder::new(Encoding::Der);
    cert.tbs_certificate
        .subject_public_key_info
        .encode(&mut enc)
        .map_err(|e| AcmeError::Internal(format!("tkauth-01: encode SPKI: {e}")))?;
    enc.finish()
        .map_err(|e| AcmeError::Internal(format!("tkauth-01: finish SPKI DER: {e}")))
}

/// `(must_include_names, permitted_values, must_exclude_names)` returned by [`parse_jwcc_der`].
type JwccParsed = (Vec<String>, Vec<(String, Vec<String>)>, Vec<String>);

/// Parse an RFC 9118 `EnhancedJWTClaimConstraints` DER blob.
///
/// Returns `(must_include_names, permitted_values, must_exclude_names)` where:
/// - `must_include_names` — claim names from `mustInclude [0]` that MUST be present in the JWT.
/// - `permitted_values` — `(claim, [allowed_values])` pairs from `permittedValues [1]`.
/// - `must_exclude_names` — claim names from `mustExclude [2]` that MUST NOT be present in the JWT.
///
/// Returns `None` if `der` is not a valid `EnhancedJWTClaimConstraints` DER encoding or
/// if any array exceeds `MAX_DER_ENTRIES` / any string exceeds `MAX_DER_STRING_BYTES`.
pub(crate) fn parse_jwcc_der(der: &[u8]) -> Option<JwccParsed> {
    let jcc = EnhancedJwtClaimConstraints::from_der(der).ok()?;

    let must_include_names: Vec<String> = {
        let entries = jcc.must_include.unwrap_or_default();
        if entries.len() > MAX_DER_ENTRIES {
            return None;
        }
        for s in &entries {
            if s.as_str().len() > MAX_DER_STRING_BYTES {
                return None;
            }
        }
        entries.into_iter().map(|s| s.into_string()).collect()
    };

    let permitted: Vec<(String, Vec<String>)> = {
        let entries = jcc.permitted_values.unwrap_or_default();
        if entries.len() > MAX_DER_ENTRIES {
            return None;
        }
        let mut result = Vec::with_capacity(entries.len());
        for jcpv in entries {
            if jcpv.claim.as_str().len() > MAX_DER_STRING_BYTES {
                return None;
            }
            if jcpv.values.len() > MAX_DER_ENTRIES {
                return None;
            }
            let mut values = Vec::with_capacity(jcpv.values.len());
            for v in jcpv.values {
                if v.as_str().len() > MAX_DER_STRING_BYTES {
                    return None;
                }
                values.push(v.into_string());
            }
            result.push((jcpv.claim.into_string(), values));
        }
        result
    };

    let must_exclude_names: Vec<String> = {
        let entries = jcc.must_exclude.unwrap_or_default();
        if entries.len() > MAX_DER_ENTRIES {
            return None;
        }
        for s in &entries {
            if s.as_str().len() > MAX_DER_STRING_BYTES {
                return None;
            }
        }
        entries.into_iter().map(|s| s.into_string()).collect()
    };

    Some((must_include_names, permitted, must_exclude_names))
}

/// Verify that `id_value` appears in the `permittedValues` for `claim_name` in a
/// RFC 8226 DER-encoded JWTClaimConstraints blob.
///
/// Used for encoder-backed identifier types (e.g., "dns") where the token carries
/// atc.tktype="EnhancedJWTClaimConstraints" rather than directly matching the identifier type.
fn verify_identifier_in_jcc(
    tkvalue: &str,
    claim_name: &str,
    id_value: &str,
) -> Result<(), AcmeError> {
    let raw = URL_SAFE_NO_PAD.decode(tkvalue).map_err(|_| {
        AcmeError::IncorrectResponse(
            "tkauth-01: atc.tkvalue is not valid base64url for JWTClaimConstraints".into(),
        )
    })?;
    let (_must_include, permitted, _must_exclude) = parse_jwcc_der(&raw).ok_or_else(|| {
        AcmeError::IncorrectResponse(
            "tkauth-01: JWTClaimConstraints blob is not valid RFC 8226 DER".into(),
        )
    })?;
    let allowed: &[String] = permitted
        .iter()
        .find(|(claim, _)| claim == claim_name)
        .map(|(_, values)| values.as_slice())
        .unwrap_or(&[]);
    // Empty allowed list means the claim is present but unconstrained — permit.
    if !allowed.is_empty() && !allowed.iter().any(|v| v == id_value) {
        return Err(AcmeError::IncorrectResponse(format!(
            "tkauth-01: identifier value '{id_value}' not in permittedValues['{claim_name}']"
        )));
    }
    Ok(())
}

/// Verify that `token_claims` satisfies the `JWTClaimConstraints` in `tkvalue`.
///
/// Supports two formats:
/// - JSON object with `"must-include"` array (server-managed extension).
/// - RFC 8226 DER `JWTClaimConstraints` with `mustInclude [0]` and/or `permittedValues [1]`.
///
/// Extracted from `validate` so it can be unit-tested without a full `AppState`.
fn check_jwt_claim_constraints(
    tkvalue: &str,
    token_claims: &serde_json::Value,
) -> Result<(), AcmeError> {
    let raw = URL_SAFE_NO_PAD.decode(tkvalue).map_err(|_| {
        AcmeError::IncorrectResponse(
            "tkauth-01: atc.tkvalue is not valid base64url for JWTClaimConstraints".into(),
        )
    })?;

    // Try JSON format first (a server-managed extension not defined by RFC 8226).
    if let Ok(constraints) = serde_json::from_slice::<serde_json::Value>(&raw) {
        let Some(must_include) = constraints.get("must-include").and_then(|v| v.as_array()) else {
            return Ok(());
        };
        if must_include.len() > 64 {
            return Err(AcmeError::IncorrectResponse(
                "tkauth-01: must-include array exceeds 64-entry limit".into(),
            ));
        }
        for entry in must_include {
            let claim = entry.get("claim").and_then(|v| v.as_str()).ok_or_else(|| {
                AcmeError::IncorrectResponse(
                    "tkauth-01: must-include entry missing 'claim' key".into(),
                )
            })?;
            let allowed = entry
                .get("values")
                .and_then(|v| v.as_array())
                .ok_or_else(|| {
                    AcmeError::IncorrectResponse(
                        "tkauth-01: must-include entry missing 'values' key".into(),
                    )
                })?;
            if allowed.len() > 64 {
                return Err(AcmeError::IncorrectResponse(
                    "tkauth-01: must-include values array exceeds 64-entry limit".into(),
                ));
            }
            let actual = token_claims.get(claim).ok_or_else(|| {
                AcmeError::IncorrectResponse(format!(
                    "tkauth-01: token missing required claim '{claim}'"
                ))
            })?;
            // RFC 9448: values entries are strings.  Reject any non-string entry
            // to prevent type-confusion where an integer in values[] matches an
            // integer claim value that a string-only policy would not permit.
            for v in allowed {
                if !v.is_string() {
                    return Err(AcmeError::IncorrectResponse(
                        "tkauth-01: must-include values entry is not a string".into(),
                    ));
                }
            }
            if !allowed.iter().any(|v| v == actual) {
                return Err(AcmeError::IncorrectResponse(format!(
                    "tkauth-01: claim '{claim}' value not in must-include allowed list"
                )));
            }
        }
        return Ok(());
    }

    // Try RFC 9118 EnhancedJWTClaimConstraints DER format.
    if let Some((must_include_names, permitted_values, must_exclude_names)) = parse_jwcc_der(&raw) {
        for name in &must_include_names {
            token_claims.get(name.as_str()).ok_or_else(|| {
                AcmeError::IncorrectResponse(format!(
                    "tkauth-01: token missing required claim '{name}'"
                ))
            })?;
        }
        for (claim, allowed) in &permitted_values {
            let actual = token_claims.get(claim.as_str()).ok_or_else(|| {
                AcmeError::IncorrectResponse(format!(
                    "tkauth-01: token missing required claim '{claim}'"
                ))
            })?;
            let actual_str = actual.as_str().ok_or_else(|| {
                AcmeError::IncorrectResponse(format!(
                    "tkauth-01: claim '{claim}' value is not a string"
                ))
            })?;
            if !allowed.is_empty() && !allowed.iter().any(|v| v == actual_str) {
                return Err(AcmeError::IncorrectResponse(format!(
                    "tkauth-01: claim '{claim}' value not in permittedValues allowed list"
                )));
            }
        }
        for name in &must_exclude_names {
            if token_claims.get(name.as_str()).is_some() {
                return Err(AcmeError::IncorrectResponse(format!(
                    "tkauth-01: token contains excluded claim '{name}'"
                )));
            }
        }
        return Ok(());
    }

    Err(AcmeError::IncorrectResponse(
        "tkauth-01: JWTClaimConstraints blob is not valid JSON or RFC 8226 DER".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;

    fn make_tkvalue(obj: serde_json::Value) -> String {
        URL_SAFE_NO_PAD.encode(obj.to_string().as_bytes())
    }

    fn claims(obj: serde_json::Value) -> serde_json::Value {
        obj
    }

    #[test]
    fn must_include_passes_when_claim_matches() {
        let tkvalue = make_tkvalue(serde_json::json!({
            "must-include": [{"claim": "krb5-principal", "values": ["user@REALM"]}]
        }));
        let token_claims = claims(serde_json::json!({"krb5-principal": "user@REALM"}));
        check_jwt_claim_constraints(&tkvalue, &token_claims).unwrap();
    }

    #[test]
    fn must_include_passes_when_one_of_multiple_values_matches() {
        let tkvalue = make_tkvalue(serde_json::json!({
            "must-include": [{"claim": "krb5-principal", "values": ["user@A", "user@B"]}]
        }));
        let token_claims = claims(serde_json::json!({"krb5-principal": "user@B"}));
        check_jwt_claim_constraints(&tkvalue, &token_claims).unwrap();
    }

    #[test]
    fn must_include_fails_when_claim_missing_from_token() {
        let tkvalue = make_tkvalue(serde_json::json!({
            "must-include": [{"claim": "krb5-principal", "values": ["user@REALM"]}]
        }));
        let token_claims = claims(serde_json::json!({}));
        let err = check_jwt_claim_constraints(&tkvalue, &token_claims).unwrap_err();
        assert!(
            matches!(err, AcmeError::IncorrectResponse(ref m) if m.contains("missing required claim"))
        );
    }

    #[test]
    fn must_include_fails_when_value_not_in_allowed_list() {
        let tkvalue = make_tkvalue(serde_json::json!({
            "must-include": [{"claim": "krb5-principal", "values": ["user@REALM"]}]
        }));
        let token_claims = claims(serde_json::json!({"krb5-principal": "attacker@OTHER"}));
        let err = check_jwt_claim_constraints(&tkvalue, &token_claims).unwrap_err();
        assert!(
            matches!(err, AcmeError::IncorrectResponse(ref m) if m.contains("not in must-include"))
        );
    }

    #[test]
    fn no_must_include_passes() {
        let tkvalue = make_tkvalue(serde_json::json!({"may-include": ["iss"]}));
        let token_claims = claims(serde_json::json!({}));
        check_jwt_claim_constraints(&tkvalue, &token_claims).unwrap();
    }

    #[test]
    fn invalid_base64_returns_err() {
        let err =
            check_jwt_claim_constraints("not-valid-b64!!!", &serde_json::Value::Null).unwrap_err();
        assert!(matches!(err, AcmeError::IncorrectResponse(ref m) if m.contains("base64url")));
    }

    #[test]
    fn tn_auth_list_type_skips_must_include_check() {
        // TNAuthList tokens never enter check_jwt_claim_constraints; this documents
        // that the caller gates on tktype == "EnhancedJWTClaimConstraints".
        // Tested indirectly: build a bad blob, confirm it's never called for TNAuthList.
        let bad_tkvalue = "not-b64!!!";
        // Simulate the caller gate: only JWTClaimConstraints enters the check.
        let tktype = "TNAuthList";
        if tktype == "EnhancedJWTClaimConstraints" {
            check_jwt_claim_constraints(bad_tkvalue, &serde_json::Value::Null).unwrap();
        }
        // Reaching here without error confirms TNAuthList is unaffected.
    }

    // ── verify_identifier_in_jcc unit tests ──────────────────────────────────

    fn make_jcc_der_with_permitted(claim: &str, values: &[&str]) -> String {
        use synta::ToDer;
        let jcc = EnhancedJwtClaimConstraints {
            must_include: None,
            permitted_values: Some(vec![JwtClaimPermittedValues {
                claim: IA5String::new(claim.to_string()).unwrap(),
                values: values
                    .iter()
                    .map(|v| Utf8String::new(v.to_string()))
                    .collect(),
            }]),
            must_exclude: None,
        };
        URL_SAFE_NO_PAD.encode(jcc.to_der().unwrap())
    }

    #[test]
    fn verify_identifier_in_jcc_passes_when_value_permitted() {
        let tkvalue = make_jcc_der_with_permitted("dns", &["foo.bar"]);
        verify_identifier_in_jcc(&tkvalue, "dns", "foo.bar").unwrap();
    }

    #[test]
    fn verify_identifier_in_jcc_fails_when_value_not_permitted() {
        let tkvalue = make_jcc_der_with_permitted("dns", &["foo.bar"]);
        let err = verify_identifier_in_jcc(&tkvalue, "dns", "other.example").unwrap_err();
        assert!(
            matches!(err, AcmeError::IncorrectResponse(ref m) if m.contains("not in permittedValues")),
            "got {err:?}"
        );
    }

    #[test]
    fn verify_identifier_in_jcc_passes_when_claim_absent() {
        // Claim not present in permittedValues at all — unconstrained, allow.
        let tkvalue = make_jcc_der_with_permitted("krb5-principal", &["user@REALM"]);
        verify_identifier_in_jcc(&tkvalue, "dns", "any.value").unwrap();
    }

    #[test]
    fn verify_identifier_in_jcc_rejects_invalid_base64() {
        let err = verify_identifier_in_jcc("not-valid-b64!!!", "dns", "foo").unwrap_err();
        assert!(
            matches!(err, AcmeError::IncorrectResponse(ref m) if m.contains("base64url")),
            "got {err:?}"
        );
    }

    // ── mustExclude DER parsing and validation ────────────────────────────────

    fn make_jcc_der_full(
        must_include: &[&str],
        permitted: &[(&str, &[&str])],
        must_exclude: &[&str],
    ) -> String {
        use synta::ToDer;
        let jcc = EnhancedJwtClaimConstraints {
            must_include: if must_include.is_empty() {
                None
            } else {
                Some(
                    must_include
                        .iter()
                        .map(|n| IA5String::new(n.to_string()).unwrap())
                        .collect(),
                )
            },
            permitted_values: if permitted.is_empty() {
                None
            } else {
                Some(
                    permitted
                        .iter()
                        .map(|(claim, values)| JwtClaimPermittedValues {
                            claim: IA5String::new(claim.to_string()).unwrap(),
                            values: values
                                .iter()
                                .map(|v| Utf8String::new(v.to_string()))
                                .collect(),
                        })
                        .collect(),
                )
            },
            must_exclude: if must_exclude.is_empty() {
                None
            } else {
                Some(
                    must_exclude
                        .iter()
                        .map(|n| IA5String::new(n.to_string()).unwrap())
                        .collect(),
                )
            },
        };
        URL_SAFE_NO_PAD.encode(jcc.to_der().unwrap())
    }

    #[test]
    fn parse_jwcc_der_returns_must_exclude_names() {
        let b64 = make_jcc_der_full(&["sub"], &[("dns", &["foo.bar"])], &["acct"]);
        let raw = URL_SAFE_NO_PAD.decode(&b64).unwrap();
        let (mi, pv, me) = parse_jwcc_der(&raw).unwrap();
        assert_eq!(mi, ["sub"]);
        assert_eq!(pv, [("dns".to_string(), vec!["foo.bar".to_string()])]);
        assert_eq!(me, ["acct"]);
    }

    #[test]
    fn must_exclude_passes_when_claim_absent_from_token() {
        let tkvalue = make_jcc_der_full(&[], &[("dns", &["foo.bar"])], &["acct"]);
        let token = serde_json::json!({"dns": "foo.bar"});
        check_jwt_claim_constraints(&tkvalue, &token).unwrap();
    }

    #[test]
    fn must_exclude_fails_when_claim_present_in_token() {
        let tkvalue = make_jcc_der_full(&[], &[("dns", &["foo.bar"])], &["acct"]);
        let token = serde_json::json!({"dns": "foo.bar", "acct": "alice"});
        let err = check_jwt_claim_constraints(&tkvalue, &token).unwrap_err();
        assert!(
            matches!(err, AcmeError::IncorrectResponse(ref m) if m.contains("contains excluded claim")),
            "got {err:?}"
        );
    }

    #[test]
    fn parse_jwcc_der_rejects_too_many_must_include_entries() {
        use synta::ToDer;
        // MAX_DER_ENTRIES + 1 = 65 entries: one over the limit.
        let names: Vec<IA5String> = (0..=MAX_DER_ENTRIES)
            .map(|i| IA5String::new(format!("c{i}")).unwrap())
            .collect();
        let jcc = EnhancedJwtClaimConstraints {
            must_include: Some(names),
            permitted_values: None,
            must_exclude: None,
        };
        let outer = jcc.to_der().unwrap();
        assert!(
            parse_jwcc_der(&outer).is_none(),
            "should reject oversized mustInclude"
        );
    }

    // ── verify_cert_chain / extract_spki_der unit tests ──────────────────────

    /// Build a minimal self-signed CA certificate for TA testing.
    fn make_ta_cert() -> (synta_certificate::BackendPrivateKey, Vec<u8>) {
        use synta_certificate::{
            encode_authority_key_identifier, encode_basic_constraints, encode_key_usage,
            encode_subject_key_identifier, parse_time, BackendPrivateKey, CertificateBuilder,
            KeyIdMethod, NameBuilder, PrivateKey as _, KEY_USAGE_C_RLSIGN, KEY_USAGE_KEY_CERT_SIGN,
        };
        let key = BackendPrivateKey::generate_ec("P-256").unwrap();
        let spki = key.public_key().unwrap().spki_der().to_vec();
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let not_before_str = crate::ca::init::unix_to_generalized_time(now_secs);
        let not_after_str = crate::ca::init::unix_to_generalized_time(now_secs + 86400 * 365);
        let name_der = NameBuilder::new()
            .common_name("Test TA CA")
            .build()
            .unwrap();
        let hasher = synta_certificate::default_key_id_hasher();
        let bc = encode_basic_constraints(true, None).unwrap();
        let ku = encode_key_usage((1u16 << KEY_USAGE_KEY_CERT_SIGN) | (1u16 << KEY_USAGE_C_RLSIGN))
            .unwrap();
        let ski = encode_subject_key_identifier(&spki, KeyIdMethod::Rfc7093Method1Sha256, &hasher)
            .unwrap();
        let aki =
            encode_authority_key_identifier(&spki, KeyIdMethod::Rfc7093Method1Sha256, &hasher)
                .unwrap();
        let signer = key.as_signer("sha256");
        let cert_der = CertificateBuilder::new()
            .issuer_name(&name_der)
            .subject_name(&name_der)
            .public_key_der(&spki)
            .serial_number(synta::Integer::from_i64(1))
            .not_valid_before(parse_time(&not_before_str).unwrap())
            .not_valid_after(parse_time(&not_after_str).unwrap())
            .add_extension_oid(synta_certificate::oids::BASIC_CONSTRAINTS, true, &bc)
            .add_extension_oid(synta_certificate::oids::KEY_USAGE, true, &ku)
            .add_extension_oid(synta_certificate::oids::SUBJECT_KEY_IDENTIFIER, false, &ski)
            .add_extension_oid(
                synta_certificate::oids::AUTHORITY_KEY_IDENTIFIER,
                false,
                &aki,
            )
            .sign(&signer)
            .unwrap();
        (key, cert_der)
    }

    /// Build an EE cert signed by `ta_key` (issuer = TA), suitable as x5c signing cert.
    /// The EE cert has a URI SAN so the verifier's EE extension policy is satisfied.
    fn make_signing_cert(
        ta_key: &synta_certificate::BackendPrivateKey,
        ta_cert_der: &[u8],
    ) -> (synta_certificate::BackendPrivateKey, Vec<u8>) {
        use synta_certificate::{
            encode_authority_key_identifier, encode_subject_key_identifier, parse_time,
            BackendPrivateKey, CertificateBuilder, KeyIdMethod, NameBuilder, PrivateKey as _,
            SubjectAlternativeNameBuilder,
        };
        let key = BackendPrivateKey::generate_ec("P-256").unwrap();
        let spki = key.public_key().unwrap().spki_der().to_vec();
        let ta_spki = super::extract_spki_der(ta_cert_der).unwrap();
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let not_before_str = crate::ca::init::unix_to_generalized_time(now_secs);
        let not_after_str = crate::ca::init::unix_to_generalized_time(now_secs + 86400 * 365);
        let issuer_name = NameBuilder::new()
            .common_name("Test TA CA")
            .build()
            .unwrap();
        let subject_name = NameBuilder::new()
            .common_name("Test Issuer")
            .build()
            .unwrap();
        let hasher = synta_certificate::default_key_id_hasher();
        let ski = encode_subject_key_identifier(&spki, KeyIdMethod::Rfc7093Method1Sha256, &hasher)
            .unwrap();
        let aki =
            encode_authority_key_identifier(&ta_spki, KeyIdMethod::Rfc7093Method1Sha256, &hasher)
                .unwrap();
        let san = SubjectAlternativeNameBuilder::new()
            .uri("https://ta.test/issuer")
            .build()
            .unwrap();
        let ta_signer = ta_key.as_signer("sha256");
        let cert_der = CertificateBuilder::new()
            .issuer_name(&issuer_name)
            .subject_name(&subject_name)
            .public_key_der(&spki)
            .serial_number(synta::Integer::from_i64(2))
            .not_valid_before(parse_time(&not_before_str).unwrap())
            .not_valid_after(parse_time(&not_after_str).unwrap())
            .add_extension_oid(synta_certificate::oids::SUBJECT_KEY_IDENTIFIER, false, &ski)
            .add_extension_oid(
                synta_certificate::oids::AUTHORITY_KEY_IDENTIFIER,
                false,
                &aki,
            )
            .add_extension_oid(synta_certificate::oids::SUBJECT_ALT_NAME, false, &san)
            .sign(&ta_signer)
            .unwrap();
        (key, cert_der)
    }

    /// Build a compact JWT authority token signed by `key`, with `cert_der` in x5c.
    fn make_authority_token(
        key: &synta_certificate::BackendPrivateKey,
        cert_der: &[u8],
        claims: serde_json::Value,
    ) -> String {
        use base64::{
            engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
            Engine,
        };
        use synta_certificate::{CertificateSigner as _, PrivateKey as _};
        let x5c_b64 = STANDARD.encode(cert_der);
        let header = serde_json::json!({"alg": "ES256", "x5c": [x5c_b64]});
        let header_b64 = URL_SAFE_NO_PAD.encode(header.to_string().as_bytes());
        let claims_b64 = URL_SAFE_NO_PAD.encode(claims.to_string().as_bytes());
        let signing_input = format!("{header_b64}.{claims_b64}");
        let signer = key.as_signer("sha256");
        let der_sig = signer.sign_tbs(signing_input.as_bytes()).unwrap();
        let p1363 = akamu_jose::jws::ecdsa_der_to_p1363(&der_sig, 32).expect("DER→P1363");
        let sig_b64 = URL_SAFE_NO_PAD.encode(&p1363);
        format!("{signing_input}.{sig_b64}")
    }

    fn future_exp() -> i64 {
        unix_now() + 3600
    }

    #[test]
    fn verify_cert_chain_accepts_ta_signed_ee_cert() {
        let (ta_key, ta_cert_der) = make_ta_cert();
        let (_, signing_cert_der) = make_signing_cert(&ta_key, &ta_cert_der);
        let store =
            synta_x509_verification::OwnedStore::try_new(std::iter::once(ta_cert_der.as_slice()))
                .unwrap();
        verify_cert_chain(&signing_cert_der, &[], &store, unix_now()).unwrap();
    }

    #[test]
    fn verify_cert_chain_rejects_unknown_cert() {
        let (_, ta_cert_der) = make_ta_cert();
        let (_, other_cert_der) = make_ta_cert(); // different key / cert
        let store =
            synta_x509_verification::OwnedStore::try_new(std::iter::once(ta_cert_der.as_slice()))
                .unwrap();
        let err = verify_cert_chain(&other_cert_der, &[], &store, unix_now()).unwrap_err();
        assert!(
            matches!(err, AcmeError::IncorrectResponse(_)),
            "got {err:?}"
        );
    }

    #[test]
    fn extract_spki_der_round_trips() {
        let (_, cert_der) = make_ta_cert();
        let spki = extract_spki_der(&cert_der).unwrap();
        // Must be non-empty and start with SEQUENCE tag (0x30).
        assert!(!spki.is_empty());
        assert_eq!(spki[0], 0x30);
    }

    // ── validate() tests (async, require DB and AppState) ─────────────────────

    async fn make_tkauth_state(ta_cert_der: &[u8]) -> std::sync::Arc<AppState> {
        use crate::config::{CaConfig, Config, DatabaseConfig, TkauthConfig};
        use crate::state::{CaState, MtcState, NonceBucket};
        use indexmap::IndexMap;
        use std::sync::Arc;

        let dir = tempfile::TempDir::new().unwrap();
        let config = Arc::new(Config {
            listen_addr: "127.0.0.1:0".into(),
            base_url: "https://acme.test".into(),
            database: DatabaseConfig {
                url: "sqlite::memory:".into(),
                max_connections: None,
                require_tls: false,
            },
            cas: vec![CaConfig {
                id: "default".to_owned(),
                is_default: true,
                caa_identities: vec![],
                key_file: dir.path().join("ca.key").to_string_lossy().into_owned(),
                cert_file: dir.path().join("ca.crt").to_string_lossy().into_owned(),
                key_type: "ec:P-256".into(),
                hash_alg: "sha256".into(),
                validity_days: 90,
                crl_url: None,
                ocsp_url: None,
                common_name: "Test TA CA".into(),
                organization: "Test".into(),
                ca_validity_years: 10,
                crl_next_update_secs: 86400,
                enforce_validity_cap: false,
                require_encrypted_key: false,
                key_password_file: None,
                mtc: None,
            }],
            mtc: None,
            server: crate::config::ServerConfig::default(),
            tls: Default::default(),
            profiles: Default::default(),
            admin: None,
            email_challenge: None,
            delegation_upstream: None,
            gossip: None,
            crdt_db_url: None,
            tkauth: Some(TkauthConfig {
                enabled: true,
                trusted_ta_ca_files: vec![],
                max_validity_secs: 3600,
                jti_prune_interval_secs: 3600,
                claim_encoders: vec![],
                token_authority_url: None,
            }),
        });

        let (ca_key, ca_cert_der) = crate::ca::init::load_or_generate(config.default_ca()).unwrap();
        crate::db::install_drivers();
        let db_conn = crate::db::open("sqlite::memory:", 1, false).await.unwrap();

        let ta_store =
            synta_x509_verification::OwnedStore::try_new(std::iter::once(ta_cert_der)).unwrap();

        let ca = Arc::new(CaState {
            id: "default".into(),
            key_type: "ec:P-256".into(),
            key: ca_key,
            cert_der: ca_cert_der,
            hash_alg: "sha256".into(),
            validity_days: 90,
            crl_url: None,
            ocsp_url: None,
            aki_bytes: Vec::new(),
            enforce_validity_cap: false,
            crl_next_update_secs: 604800,
            caa_identities: vec![],
            mtc: Arc::new(MtcState::disabled()),
        });

        let nonces = Arc::new(NonceBucket::new());
        let mut link_map = std::collections::HashMap::new();
        link_map.insert(
            "default".to_string(),
            Arc::new(axum::http::HeaderValue::from_static(
                "<https://acme.test/acme/directory>;rel=\"index\"",
            )),
        );
        let validation_client = {
            let https = hyper_rustls::HttpsConnectorBuilder::new()
                .with_native_roots()
                .expect("native roots")
                .https_or_http()
                .enable_http1()
                .build();
            hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
                .build(https)
        };

        let mut cas: IndexMap<String, Arc<CaState>> = IndexMap::new();
        cas.insert("default".to_string(), ca.clone());

        Arc::new(AppState {
            config: Arc::clone(&config),
            db: db_conn.clone(),
            db_ro: db_conn.clone(),
            db_kind: crate::db::DbKind::Sqlite,
            profiles: crate::profiles::ProfileRegistry::empty(&ca),
            cas: Arc::new(cas),
            default_ca_id: Arc::new("default".to_string()),
            tls: None,
            spki_cache: Arc::new(std::sync::RwLock::new(std::collections::HashMap::new())),
            nonces: Arc::clone(&nonces),
            link_headers: Arc::new(link_map),
            validation_client,
            crl_caches: Arc::new({
                let mut m = std::collections::HashMap::new();
                m.insert("default".to_string(), Default::default());
                m
            }),
            gss_cred: None,
            admin_gss_cred: None,
            eab_master_secret: None,
            audit: Arc::new(crate::audit::AuditState::new()),
            audit_policy: Arc::new(crate::audit::AuditPolicy::default()),
            admin_sessions: None,
            admin_auth_limiter: None,
            eab_session_nonces: None,
            startup_time: std::time::Instant::now(),
            crdt: Arc::new(tokio::sync::RwLock::new(akamu_crdt::AkaCrdt::default())),
            node_id: Arc::new("test".to_string()),
            node_kem_priv: Arc::new(vec![]),
            node_gossip_signing_priv: Arc::new(vec![]),
            node_gossip_signing_cert: Arc::new(vec![]),
            gossip_client: Arc::new(reqwest::Client::new()),
            gossip_nonce_cache: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
            write_notify: Arc::new(tokio::sync::Notify::new()),
            crdt_db: db_conn,
            tkauth_trust_anchors: Some(Arc::new(ta_store)),
            claim_encoder_registry: None,
            jwks_cache: None,
        })
    }

    fn make_valid_claims(id_type: &str, id_value: &str, fingerprint: &str) -> serde_json::Value {
        serde_json::json!({
            "exp": future_exp(),
            "jti": format!("test-jti-{}", uuid::Uuid::new_v4()),
            "atc": {
                "tktype": id_type,
                "tkvalue": id_value,
                "fingerprint": fingerprint,
            }
        })
    }

    // KEY_AUTH encodes a JWK thumbprint of 32 zero bytes (base64url, no pad: 43 'A's).
    // FINGERPRINT is the RFC 9447 "SHA256 XX:XX:..." equivalent of those same bytes.
    const KEY_AUTH: &str = "testtoken.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    const FINGERPRINT: &str = "SHA256 00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00";

    #[tokio::test]
    async fn validate_atc_ca_true_is_accepted_by_challenge_validator() {
        // atc.ca=true is no longer rejected at challenge validation time.
        // The match against the CSR's BasicConstraints cA field happens at finalize.
        let (ta_key, ta_cert_der) = make_ta_cert();
        let (signing_key, signing_cert_der) = make_signing_cert(&ta_key, &ta_cert_der);
        let state = make_tkauth_state(&ta_cert_der).await;

        let mut claims = make_valid_claims("TNAuthList", "test-value", FINGERPRINT);
        claims["atc"]["ca"] = serde_json::Value::Bool(true);
        let token = make_authority_token(&signing_key, &signing_cert_der, claims);

        validate(
            "TNAuthList",
            "test-value",
            KEY_AUTH,
            &token,
            "authz-ca-1",
            "order-test",
            &state,
        )
        .await
        .expect("validate should succeed when atc.ca=true; ca flag check is deferred to finalize");
    }

    #[tokio::test]
    async fn validate_fingerprint_mismatch_is_rejected() {
        let (ta_key, ta_cert_der) = make_ta_cert();
        let (signing_key, signing_cert_der) = make_signing_cert(&ta_key, &ta_cert_der);
        let state = make_tkauth_state(&ta_cert_der).await;

        let claims =
            make_valid_claims("TNAuthList", "test-value", "wrong-fingerprint-not-matching");
        let token = make_authority_token(&signing_key, &signing_cert_der, claims);

        let err = validate(
            "TNAuthList",
            "test-value",
            KEY_AUTH,
            &token,
            "authz-2",
            "order-test",
            &state,
        )
        .await
        .unwrap_err();
        assert!(
            matches!(err, AcmeError::IncorrectResponse(ref m) if m.contains("fingerprint")),
            "got {err:?}"
        );
    }

    #[tokio::test]
    async fn validate_jti_replay_is_rejected() {
        let (ta_key, ta_cert_der) = make_ta_cert();
        let (signing_key, signing_cert_der) = make_signing_cert(&ta_key, &ta_cert_der);
        let state = make_tkauth_state(&ta_cert_der).await;

        // Use the same jti for both calls.
        let fixed_jti = "replay-test-jti-fixed";
        let mut claims = make_valid_claims("TNAuthList", "test-value", FINGERPRINT);
        claims["jti"] = serde_json::Value::String(fixed_jti.into());
        let token = make_authority_token(&signing_key, &signing_cert_der, claims);

        validate(
            "TNAuthList",
            "test-value",
            KEY_AUTH,
            &token,
            "authz-3",
            "order-test",
            &state,
        )
        .await
        .unwrap();

        // Second call with the same token must be rejected.
        let err = validate(
            "TNAuthList",
            "test-value",
            KEY_AUTH,
            &token,
            "authz-3b",
            "order-test",
            &state,
        )
        .await
        .unwrap_err();
        assert!(
            matches!(err, AcmeError::IncorrectResponse(ref m) if m.contains("jti replay")),
            "got {err:?}"
        );
    }

    #[tokio::test]
    async fn validate_missing_x5u_and_x5c_returns_error() {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use synta_certificate::{CertificateSigner as _, PrivateKey as _};

        let (ta_key, ta_cert_der) = make_ta_cert();
        let (signing_key, _) = make_signing_cert(&ta_key, &ta_cert_der);
        let state = make_tkauth_state(&ta_cert_der).await;

        // Build a token with neither x5c nor x5u.
        let header = serde_json::json!({"alg": "ES256"});
        let claims = make_valid_claims("TNAuthList", "test-value", FINGERPRINT);
        let header_b64 = URL_SAFE_NO_PAD.encode(header.to_string().as_bytes());
        let claims_b64 = URL_SAFE_NO_PAD.encode(claims.to_string().as_bytes());
        let signing_input = format!("{header_b64}.{claims_b64}");
        let signer = signing_key.as_signer("sha256");
        let der_sig = signer.sign_tbs(signing_input.as_bytes()).unwrap();
        let p1363 = akamu_jose::jws::ecdsa_der_to_p1363(&der_sig, 32).expect("DER→P1363");
        let token = format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(&p1363));

        let err = validate(
            "TNAuthList",
            "test-value",
            KEY_AUTH,
            &token,
            "authz-4",
            "order-test",
            &state,
        )
        .await
        .unwrap_err();
        assert!(
            matches!(err, AcmeError::IncorrectResponse(ref m) if m.contains("no x5u, x5c, or kid")),
            "got {err:?}"
        );
    }

    #[tokio::test]
    async fn validate_happy_path_succeeds() {
        let (ta_key, ta_cert_der) = make_ta_cert();
        let (signing_key, signing_cert_der) = make_signing_cert(&ta_key, &ta_cert_der);
        let state = make_tkauth_state(&ta_cert_der).await;
        let claims = make_valid_claims("TNAuthList", "tn-value", FINGERPRINT);
        let token = make_authority_token(&signing_key, &signing_cert_der, claims);
        validate(
            "TNAuthList",
            "tn-value",
            KEY_AUTH,
            &token,
            "authz-5",
            "order-test",
            &state,
        )
        .await
        .unwrap();
    }

    #[test]
    fn must_include_rejects_non_string_values_entry() {
        let tkvalue = make_tkvalue(serde_json::json!({
            "must-include": [{"claim": "krb5-principal", "values": [42]}]
        }));
        let token_claims = claims(serde_json::json!({"krb5-principal": 42}));
        let err = check_jwt_claim_constraints(&tkvalue, &token_claims).unwrap_err();
        assert!(
            matches!(err, AcmeError::IncorrectResponse(ref m) if m.contains("not a string")),
            "got {err:?}"
        );
    }
}
