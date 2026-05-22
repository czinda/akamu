use http_body_util::{BodyExt, Limited};
use hyper::Uri;
use subtle::ConstantTimeEq;
use synta::traits::Encode;
use synta::{Decoder, Encoder, Encoding};
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

/// Maximum response body size when fetching a Token Authority cert via x5u.
const MAX_X5U_BODY: usize = 64 * 1024;

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

    // Step 2: obtain signing cert DER.
    let signing_cert_der: Vec<u8> = if let Some(x5c) = &header.x5c {
        akamu_jose::x5c_leaf_der(x5c)
            .map_err(|e| AcmeError::IncorrectResponse(format!("tkauth-01: x5c: {e}")))?
    } else if let Some(x5u) = &header.x5u {
        fetch_cert_via_x5u(x5u, state).await?
    } else {
        return Err(AcmeError::IncorrectResponse(
            "tkauth-01: authority token has no x5u or x5c".into(),
        ));
    };

    // Step 3: validate cert chain against trusted TA CAs.
    let anchors = state.tkauth_trust_anchors.as_deref().ok_or_else(|| {
        AcmeError::Internal("tkauth-01: tkauth is not configured (no trust anchors)".into())
    })?;
    let now_i64 = unix_now();
    verify_cert_chain(&signing_cert_der, anchors, now_i64)?;

    // Step 4: extract SPKI DER from signing cert.
    let spki_der = extract_spki_der(&signing_cert_der)?;

    // Step 5: verify JWT signature and exp claim.
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
    if tktype != id_type {
        return Err(AcmeError::IncorrectResponse(format!(
            "tkauth-01: atc.tktype '{tktype}' does not match identifier type '{id_type}'"
        )));
    }

    let tkvalue = atc
        .get("tkvalue")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AcmeError::IncorrectResponse("tkauth-01: atc missing 'tkvalue'".into()))?;
    if tkvalue != id_value {
        return Err(AcmeError::IncorrectResponse(
            "tkauth-01: atc.tkvalue does not match identifier value".to_string(),
        ));
    }

    let fingerprint = atc
        .get("fingerprint")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            AcmeError::IncorrectResponse("tkauth-01: atc missing 'fingerprint'".into())
        })?;
    if fingerprint.trim() != thumbprint.trim() {
        return Err(AcmeError::IncorrectResponse(
            "tkauth-01: atc.fingerprint does not match account JWK thumbprint".into(),
        ));
    }

    // ca must be absent or false — CA cert issuance is not supported.
    if atc.get("ca").and_then(|v| v.as_bool()).unwrap_or(false) {
        return Err(AcmeError::IncorrectResponse(
            "tkauth-01: atc.ca=true is not supported".into(),
        ));
    }

    // Step 8 (optional): check token lifetime against configured cap.
    if let Some(tkauth) = state.config.tkauth.as_ref() {
        let max_secs = tkauth.max_validity_secs as i64;
        if exp - now_i64 > max_secs {
            return Err(AcmeError::IncorrectResponse(format!(
                "tkauth-01: token lifetime ({} s) exceeds max_validity_secs ({max_secs})",
                exp - now_i64
            )));
        }
    }

    // Step 9: JTI replay prevention.
    let inserted = db::tkauth::insert_jti(&state.db, jti, authz_id, exp, now_i64)
        .await
        .map_err(|e| AcmeError::Internal(format!("tkauth-01: JTI insert: {e}")))?;
    if !inserted {
        return Err(AcmeError::IncorrectResponse(
            "tkauth-01: authority token already used (jti replay)".into(),
        ));
    }

    Ok(())
}

/// Fetch a Token Authority signing certificate from an x5u HTTPS URL.
///
/// Enforces HTTPS scheme.  Parses the response body as PEM (single cert block)
/// or DER; the first successfully parsed cert is returned.
async fn fetch_cert_via_x5u(url: &str, state: &AppState) -> Result<Vec<u8>, AcmeError> {
    let uri: Uri = url
        .parse()
        .map_err(|e| AcmeError::IncorrectResponse(format!("tkauth-01: x5u URL parse: {e}")))?;
    if uri.scheme_str() != Some("https") {
        return Err(AcmeError::IncorrectResponse(
            "tkauth-01: x5u must use https://".into(),
        ));
    }

    let resp = state
        .validation_client
        .get(uri)
        .await
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
    anchors: &synta_x509_verification::OwnedStore,
    now: i64,
) -> Result<(), AcmeError> {
    let cert: Certificate = Decoder::new(signing_cert_der, Encoding::Der)
        .decode()
        .map_err(|e| AcmeError::IncorrectResponse(format!("tkauth-01: signing cert parse: {e}")))?;
    let leaf = VerificationCertificate::new(cert, signing_cert_der);

    let mut policy = PolicyDefinition::new_server_pq(OpensslSignatureVerifier, vec![], now);
    policy.profile = ValidationProfile::Rfc5280;
    policy.extended_key_usage = None;
    policy.permitted_spki_algorithms = WEBPKI_PERMITTED_SPKI_ALGORITHMS_WITH_PQ;
    policy.permitted_signature_algorithms = WEBPKI_PERMITTED_SIGNATURE_ALGORITHMS_WITH_PQ;

    anchors
        .verify(&leaf, &[], &policy, RevocationChecks::default())
        .map(|_| ())
        .map_err(|e| AcmeError::Unauthorized(format!("tkauth-01: TA cert chain invalid: {e}")))
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
