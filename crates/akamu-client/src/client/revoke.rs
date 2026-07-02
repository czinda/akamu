//! Revocation, ARI (RFC 9773), and certificate-id helpers.

use akamu_jose::{JwsFlattened, JwsKeyRef};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use http_body_util::Full;
use hyper::{body::Bytes, Method, Request, StatusCode};

use crate::{
    account::{Account, AccountKey},
    error::ClientError,
    types::RenewalInfo,
};

use super::{acme_error, AcmeClient};

impl AcmeClient {
    /// Fetch renewal information for a certificate (RFC 9773 ARI).
    ///
    /// `cert_bytes` is either a PEM-encoded certificate chain or a raw
    /// DER-encoded certificate (including MTC `StandaloneCertificate` objects).
    /// Only the first (end-entity) certificate is used.
    ///
    /// Both X.509 `Certificate` and MTC `StandaloneCertificate` encode
    /// `TBSCertificate` as their first SEQUENCE field, so ARI cert-id
    /// construction works for either format.
    ///
    /// Returns `Err` if the server does not advertise an ARI endpoint.
    pub async fn get_renewal_info(&self, cert_bytes: &[u8]) -> Result<RenewalInfo, ClientError> {
        let renewal_info_url = self.renewal_info_url.as_deref().ok_or_else(|| {
            ClientError::Http("server does not support ARI (no renewalInfo in directory)".into())
        })?;

        let (serial_bytes, aki_bytes) = cert_id_from_bytes(cert_bytes)?;

        // Build cert-id and fetch.
        let cert_id = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(&aki_bytes),
            URL_SAFE_NO_PAD.encode(&serial_bytes),
        );
        let url = format!("{}/{}", renewal_info_url.trim_end_matches('/'), cert_id);

        let req = Request::builder()
            .method(Method::GET)
            .uri(&url)
            .body(Full::<Bytes>::new(Bytes::new()))
            .map_err(|e| ClientError::Http(format!("build ARI request: {e}")))?;
        let (status, headers, raw) = self.http_dispatch(req).await?;
        let retry_after_secs = headers
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<u64>().ok());
        let raw = hyper::body::Bytes::from(raw);
        if !status.is_success() {
            return Err(ClientError::Http(format!("get-renewal-info {status}")));
        }
        let body: serde_json::Value = serde_json::from_slice(&raw)
            .map_err(|e| ClientError::Http(format!("parse ARI JSON: {e}")))?;
        let window_start = body["suggestedWindow"]["start"]
            .as_str()
            .ok_or_else(|| ClientError::Http("ARI missing suggestedWindow.start".into()))?
            .to_string();
        let window_end = body["suggestedWindow"]["end"]
            .as_str()
            .ok_or_else(|| ClientError::Http("ARI missing suggestedWindow.end".into()))?
            .to_string();
        Ok(RenewalInfo {
            window_start,
            window_end,
            retry_after_secs,
        })
    }

    /// Revoke a certificate using the account key (RFC 8555 §7.6).
    ///
    /// `cert_der` is the DER-encoded end-entity certificate (not the PEM bundle).
    /// `reason` is an optional CRL reason code (0-10, excluding 7).
    pub async fn revoke_certificate(
        &self,
        acct: &Account,
        cert_der: &[u8],
        reason: Option<u8>,
    ) -> Result<(), ClientError> {
        let cert_b64 = URL_SAFE_NO_PAD.encode(cert_der);
        let mut payload = serde_json::json!({ "certificate": cert_b64 });
        if let Some(r) = reason {
            payload["reason"] = serde_json::json!(r);
        }
        let url = self.revoke_cert_url.clone();
        let (status, body, _) = self
            .post_kid(acct, &url, Some(payload.to_string().as_bytes()))
            .await?;
        if status != StatusCode::OK {
            return Err(acme_error(&body, status, "revoke-cert"));
        }
        Ok(())
    }

    /// Revoke a certificate using the certificate's own private key (RFC 8555 §7.6).
    ///
    /// Use this when the account key is unavailable but the cert's private key is known.
    pub async fn revoke_certificate_with_cert_key(
        &self,
        cert_key: &AccountKey,
        cert_der: &[u8],
        reason: Option<u8>,
    ) -> Result<(), ClientError> {
        let url = &self.revoke_cert_url;
        let cert_b64 = URL_SAFE_NO_PAD.encode(cert_der);
        let mut payload_obj = serde_json::json!({ "certificate": cert_b64 });
        if let Some(r) = reason {
            payload_obj["reason"] = serde_json::json!(r);
        }
        let payload_str = payload_obj.to_string();

        for attempt in 0..5_u8 {
            let nonce = self.fetch_nonce().await?;
            let key_ref = JwsKeyRef::Jwk {
                jwk: cert_key.public_jwk().clone(),
            };
            let jws = JwsFlattened::sign(
                cert_key.private_key(),
                cert_key.alg(),
                &nonce,
                url,
                key_ref,
                Some(payload_str.as_bytes()),
            )?;
            let jws_value = serde_json::to_value(&jws)
                .map_err(|e| ClientError::Jose(akamu_jose::JoseError::Json(e)))?;
            let (status, body, _) = self.post_jws_once(url, &jws_value).await?;
            if body["type"].as_str() == Some("urn:ietf:params:acme:error:badNonce") {
                if attempt == 4 {
                    return Err(ClientError::Http(
                        "badNonce retry limit exceeded".to_string(),
                    ));
                }
                *self.cached_nonce.lock().await = None;
                continue;
            }
            if status != StatusCode::OK {
                return Err(acme_error(&body, status, "revoke-cert"));
            }
            return Ok(());
        }
        unreachable!()
    }
}

/// Extract `(serial_bytes, aki_bytes)` from a PEM or binary-DER certificate.
///
/// Accepts X.509 `Certificate` PEM/DER and MTC `StandaloneCertificate` DER alike,
/// since both begin with `SEQUENCE { TBSCertificate, ... }`.
fn cert_id_from_bytes(cert_bytes: &[u8]) -> Result<(Vec<u8>, Vec<u8>), ClientError> {
    use synta::{Decoder, Encoding};
    use synta_certificate::oids;
    use synta_certificate::owned::{Certificate, TBSCertificate};

    let extract = |tbs: TBSCertificate| -> Result<(Vec<u8>, Vec<u8>), ClientError> {
        let serial = tbs.serial_number.as_bytes().to_vec();
        let extensions = tbs
            .extensions
            .as_ref()
            .ok_or_else(|| ClientError::Crypto("certificate has no extensions".into()))?;
        let aki_ext = extensions
            .iter()
            .find(|e| e.extn_id.components() == oids::AUTHORITY_KEY_IDENTIFIER)
            .ok_or_else(|| ClientError::Crypto("certificate missing AKI extension".into()))?;
        let aki = aki_key_id_bytes(aki_ext.extn_value.as_bytes())
            .ok_or_else(|| ClientError::Crypto("could not parse AKI key identifier".into()))?;
        Ok((serial, aki))
    };

    let cert_ders = synta_certificate::pem_to_der(cert_bytes);
    if let Some(cert_der) = cert_ders.into_iter().next() {
        let cert: Certificate = {
            let mut dec = Decoder::new(&cert_der, Encoding::Der);
            dec.decode()
                .map_err(|e| ClientError::Crypto(format!("cert parse: {e}")))?
        };
        extract(cert.tbs_certificate)
    } else {
        // Binary DER: validate_envelope locates the TBSCertificate TLV.
        let tbs_range = synta_certificate::validate_envelope(cert_bytes).map_err(|_| {
            ClientError::Crypto(
                "no PEM certificate found and binary DER is not a valid SEQUENCE".into(),
            )
        })?;
        let tbs_der = cert_bytes
            .get(tbs_range)
            .ok_or_else(|| ClientError::Crypto("DER input is truncated or malformed".into()))?;
        let tbs: TBSCertificate = {
            let mut dec = Decoder::new(tbs_der, Encoding::Der);
            dec.decode()
                .map_err(|e| ClientError::Crypto(format!("TBSCertificate parse: {e}")))?
        };
        extract(tbs)
    }
}

fn aki_key_id_bytes(ext_value: &[u8]) -> Option<Vec<u8>> {
    // Skip SEQUENCE (tag 0x30 + length).
    if ext_value.len() < 4 || ext_value[0] != 0x30 {
        return None;
    }
    let content_start = if ext_value[1] & 0x80 == 0 {
        2
    } else {
        2 + (ext_value[1] & 0x7f) as usize
    };
    let content = ext_value.get(content_start..)?;
    // [0] IMPLICIT tag = 0x80
    if content.is_empty() || content[0] != 0x80 {
        return None;
    }
    let len = *content.get(1)? as usize;
    content.get(2..2 + len).map(<[u8]>::to_vec)
}

/// Format a JWK thumbprint as an RFC 9447 fingerprint string.
///
/// `thumbprint_b64url` is the base64url (no padding) SHA-256 of the canonical
/// JWK.  Returns `"SHA256 XX:XX:..."` (colon-separated uppercase hex bytes).
pub fn rfc9447_fingerprint(thumbprint_b64url: &str) -> Result<String, ClientError> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;
    let raw = URL_SAFE_NO_PAD
        .decode(thumbprint_b64url)
        .map_err(|e| ClientError::Http(format!("base64url decode thumbprint: {e}")))?;
    Ok(format!(
        "SHA256 {}",
        raw.iter()
            .map(|b| format!("{b:02X}"))
            .collect::<Vec<_>>()
            .join(":")
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cert_id_from_bytes_rejects_garbage() {
        let err = cert_id_from_bytes(b"not a certificate").unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("no PEM certificate found")
                || msg.contains("DER input")
                || msg.contains("parse"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn cert_id_from_bytes_rejects_truncated_der() {
        // A valid SEQUENCE tag/length prefix but truncated body — must not panic.
        let truncated = &[0x30u8, 0x82, 0x01, 0x00, 0x01, 0x02];
        let err = cert_id_from_bytes(truncated).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("no PEM certificate found")
                || msg.contains("DER input")
                || msg.contains("parse"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn aki_key_id_bytes_empty_returns_none() {
        assert!(aki_key_id_bytes(&[]).is_none());
    }

    #[test]
    fn aki_key_id_bytes_wrong_tag_returns_none() {
        assert!(aki_key_id_bytes(&[0x31, 0x04, 0x80, 0x02, 0xAA, 0xBB]).is_none());
    }

    #[test]
    fn aki_key_id_bytes_happy_path() {
        // SEQUENCE { [0] PRIMITIVE 0xAA 0xBB }
        let aki_der = &[0x30u8, 0x04, 0x80, 0x02, 0xAA, 0xBB];
        assert_eq!(aki_key_id_bytes(aki_der), Some(vec![0xAA, 0xBB]));
    }

    #[test]
    fn rfc9447_fingerprint_formats_correctly() {
        // SHA-256 of the empty string, base64url-encoded (no padding).
        // SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        let b64url = "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU";
        let fp = rfc9447_fingerprint(b64url).unwrap();
        assert_eq!(
            fp,
            "SHA256 E3:B0:C4:42:98:FC:1C:14:9A:FB:F4:C8:99:6F:B9:24:\
             27:AE:41:E4:64:9B:93:4C:A4:95:99:1B:78:52:B8:55"
        );
    }

    #[test]
    fn rfc9447_fingerprint_rejects_invalid_base64() {
        let err = rfc9447_fingerprint("not!valid!base64url").unwrap_err();
        assert!(
            err.to_string().contains("base64") || err.to_string().contains("decode"),
            "unexpected error: {err}"
        );
    }
}
