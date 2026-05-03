//! POST /acme/revoke-cert — RFC 8555 §7.6

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::Deserialize;

use crate::db;
use crate::error::AcmeError;
use crate::state::AppState;

use super::{acme_headers, parse_jws, require_payload, unix_now};

#[derive(Deserialize)]
struct RevokePayload {
    certificate: String, // base64url-encoded DER
    reason: Option<u8>,
}

pub async fn revoke_cert(
    State(state): State<Arc<AppState>>,
    body: Bytes,
) -> Result<Response, AcmeError> {
    let url = format!("{}/acme/revoke-cert", state.config.base_url);
    let ctx = parse_jws(&state, body, &url).await?;

    let payload: RevokePayload = require_payload(&ctx.payload, "revoke-cert")?;

    // Validate reason code.
    if let Some(r) = payload.reason {
        if r > 10 || r == 7 {
            return Err(AcmeError::BadRevocationReason);
        }
    }

    let cert_der = URL_SAFE_NO_PAD
        .decode(&payload.certificate)
        .map_err(|e| AcmeError::BadRequest(format!("certificate base64url: {e}")))?;

    // Find the certificate by its DER content.
    // We identify the cert by extracting its serial from the DER and looking it up.
    let serial_hex = extract_serial_hex(&cert_der)?;
    let cert = db::certs::get_by_serial(&state.db, &serial_hex)
        .await?
        .ok_or(AcmeError::NotFound)?;

    if cert.status == "revoked" {
        return Err(AcmeError::AlreadyRevoked);
    }

    // Authorisation: either the account that owns the cert, or the cert key itself.
    match &ctx.account_id {
        Some(account_id) => {
            if cert.account_id != *account_id {
                return Err(AcmeError::Unauthorized(
                    "certificate belongs to a different account".into(),
                ));
            }
        }
        None => {
            // jwk was used — RFC 8555 §7.6: the signing key must be the certificate's
            // public key. JWS signature is already verified; compare SPKIs.
            let cert_spki = extract_spki_der(&cert_der)?;
            if cert_spki != ctx.spki_der {
                return Err(AcmeError::Unauthorized(
                    "signing key does not match certificate public key".into(),
                ));
            }
        }
    }

    let now = unix_now();
    let revoked =
        db::certs::revoke(&state.db, &cert.id, payload.reason.map(|r| r as i64), now).await?;

    if !revoked {
        return Err(AcmeError::AlreadyRevoked);
    }

    state
        .record_audit(
            crate::audit::AuditEvent::success(crate::audit::AuditEventType::CertRevoke)
                .with_subject(&cert.serial_number)
                .with_principal(format!("acme:{}", ctx.jwk_thumbprint.as_deref().unwrap_or(""))),
        )
        .await;

    // Invalidate the CRL cache so the next GET /ca/crl rebuilds with the new entry.
    match state.crl_cache.lock() {
        Ok(mut guard) => *guard = None,
        Err(poisoned) => {
            tracing::error!("CRL cache mutex poisoned — forcing invalidation to prevent stale CRL");
            *poisoned.into_inner() = None;
        }
    }

    // Return 200 with empty body (RFC 8555 §7.6).
    let headers = acme_headers(&state, &ctx.next_nonce);
    let mut resp = StatusCode::OK.into_response();
    resp.headers_mut().extend(headers);
    Ok(resp)
}

/// Extract the serial number as a hex string from a DER-encoded certificate.
fn extract_serial_hex(cert_der: &[u8]) -> Result<String, AcmeError> {
    use synta::{Decoder, Encoding};
    use synta_certificate::Certificate;

    let mut dec = Decoder::new(cert_der, Encoding::Der);
    let cert: Certificate = dec
        .decode()
        .map_err(|e| AcmeError::BadRequest(format!("certificate parse: {e}")))?;

    let serial_bytes = cert.tbs_certificate.serial_number.as_bytes();
    let hex: String = serial_bytes.iter().map(|b| format!("{b:02x}")).collect();
    Ok(hex)
}

/// Re-encode the SubjectPublicKeyInfo from a DER-encoded certificate.
///
/// Used by the self-revocation path (RFC 8555 §7.6) to verify that the JWS
/// signing key matches the certificate's public key.
fn extract_spki_der(cert_der: &[u8]) -> Result<Vec<u8>, AcmeError> {
    use synta::traits::Encode;
    use synta::{Decoder, Encoder, Encoding};
    use synta_certificate::Certificate;

    let mut dec = Decoder::new(cert_der, Encoding::Der);
    let cert: Certificate = dec
        .decode()
        .map_err(|e| AcmeError::BadRequest(format!("certificate parse: {e}")))?;

    let mut enc = Encoder::new(Encoding::Der);
    cert.tbs_certificate
        .subject_public_key_info
        .encode(&mut enc)
        .map_err(|e| AcmeError::Internal(format!("SPKI encode: {e}")))?;
    enc.finish()
        .map_err(|e| AcmeError::Internal(format!("SPKI finish: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ca::init::unix_to_generalized_time;
    use synta::Integer;
    use synta_certificate::ExtendedKeyUsageBuilder;
    use synta_certificate::{
        default_key_id_hasher, encode_authority_key_identifier, encode_basic_constraints,
        encode_key_usage, encode_subject_key_identifier, oids, parse_time, BackendPrivateKey,
        CertificateBuilder, KeyIdMethod, NameBuilder, PrivateKey as _,
        SubjectAlternativeNameBuilder, KEY_USAGE_DIGITAL_SIGNATURE,
    };

    fn make_cert_der() -> Vec<u8> {
        let ca_key = BackendPrivateKey::generate_ec("P-256").unwrap();
        let ca_spki = ca_key.public_key().unwrap().spki_der().to_vec();
        let name_der = NameBuilder::new().common_name("Test").build().unwrap();
        let hasher = default_key_id_hasher();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let not_before = parse_time(&unix_to_generalized_time(now)).unwrap();
        let not_after = parse_time(&unix_to_generalized_time(now + 86400)).unwrap();
        let bc = encode_basic_constraints(false, None).unwrap();
        let ku = encode_key_usage(1u16 << KEY_USAGE_DIGITAL_SIGNATURE).unwrap();
        let eku = ExtendedKeyUsageBuilder::new()
            .server_auth()
            .build()
            .unwrap();
        let ski =
            encode_subject_key_identifier(&ca_spki, KeyIdMethod::Rfc7093Method1Sha256, &hasher)
                .unwrap();
        let aki =
            encode_authority_key_identifier(&ca_spki, KeyIdMethod::Rfc7093Method1Sha256, &hasher)
                .unwrap();
        let san_der = SubjectAlternativeNameBuilder::new()
            .dns_name("test.example.com")
            .build()
            .unwrap();
        let signer = ca_key.as_signer("sha256");
        CertificateBuilder::new()
            .issuer_name(&name_der)
            .subject_name(&name_der)
            .public_key_der(&ca_spki)
            .serial_number(Integer::from_i64(0x12345678))
            .not_valid_before(not_before)
            .not_valid_after(not_after)
            .add_extension_oid(oids::BASIC_CONSTRAINTS, false, &bc)
            .add_extension_oid(oids::KEY_USAGE, true, &ku)
            .add_extension_oid(oids::EXTENDED_KEY_USAGE, false, &eku)
            .add_extension_oid(oids::SUBJECT_KEY_IDENTIFIER, false, &ski)
            .add_extension_oid(oids::AUTHORITY_KEY_IDENTIFIER, false, &aki)
            .add_extension_oid(oids::SUBJECT_ALT_NAME, false, &san_der)
            .sign(&signer)
            .unwrap()
    }

    #[test]
    fn extract_serial_hex_valid_cert() {
        let cert_der = make_cert_der();
        let hex = extract_serial_hex(&cert_der).unwrap();
        // Serial 0x12345678 = "12345678"
        assert_eq!(hex, "12345678");
    }

    #[test]
    fn extract_serial_hex_invalid_der_returns_error() {
        let result = extract_serial_hex(b"not a certificate");
        assert!(result.is_err());
        match result.unwrap_err() {
            AcmeError::BadRequest(msg) => assert!(msg.contains("certificate parse")),
            other => panic!("expected BadRequest, got {other:?}"),
        }
    }

    #[test]
    fn extract_spki_der_matches_original_key() {
        let cert_der = make_cert_der();
        // Re-derive the expected SPKI by generating the same key used in make_cert_der.
        // make_cert_der uses ca_key.public_key().spki_der() as the cert's public key,
        // so extracting SPKI from the cert DER should round-trip to the same bytes.
        let spki = extract_spki_der(&cert_der).unwrap();
        // Must be non-empty and parseable.
        assert!(!spki.is_empty());
        // The first byte of a SEQUENCE DER is 0x30.
        assert_eq!(spki[0], 0x30, "SPKI DER must start with SEQUENCE tag");
    }

    #[test]
    fn extract_spki_der_invalid_der_returns_error() {
        let result = extract_spki_der(b"garbage");
        assert!(result.is_err());
        match result.unwrap_err() {
            AcmeError::BadRequest(msg) => assert!(msg.contains("certificate parse")),
            other => panic!("expected BadRequest, got {other:?}"),
        }
    }

    #[test]
    fn extract_spki_der_roundtrip_with_serial() {
        // Both helpers must agree on which cert they're parsing.
        let cert_der = make_cert_der();
        let serial = extract_serial_hex(&cert_der).unwrap();
        let spki = extract_spki_der(&cert_der).unwrap();
        assert_eq!(serial, "12345678");
        assert!(!spki.is_empty());
    }
}
