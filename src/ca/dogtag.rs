//! Dogtag PKI CA signing backend.
//!
//! When a `[[ca]]` entry is configured with `[ca.signer] type = "dogtag"`,
//! certificate signing is delegated to an external Dogtag PKI CA via its
//! REST enrollment API.  Akamu acts as a Registration Authority (RA):
//! it validates ACME requests, performs challenge verification, then submits
//! the ACME client's CSR to Dogtag for signing.

use std::sync::Arc;
use std::time::Duration;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use rustls::pki_types::CertificateDer;
use serde::{Deserialize, Serialize};

use crate::config::DogtagSignerConfig;
use crate::error::AcmeError;

/// Dogtag REST API client for certificate enrollment.
///
/// Holds a pre-built HTTPS client with RA agent TLS client certificate
/// authentication.  Constructed once at startup and stored in
/// [`crate::state::SigningBackend::Dogtag`].
#[derive(Debug)]
pub struct DogtagSigner {
    client: reqwest::Client,
    base_url: String,
    default_profile_id: String,
    timeout: Duration,
}

/// Certificate issued by the Dogtag CA.
#[derive(Debug)]
pub struct DogtagIssuedCert {
    pub cert_der: Vec<u8>,
    pub serial_hex: String,
    pub not_before: i64,
    pub not_after: i64,
}

// ── Dogtag REST API request/response types ──────────────────────────────────

#[derive(Serialize)]
struct EnrollmentRequest {
    #[serde(rename = "ProfileID")]
    profile_id: String,
    #[serde(rename = "Renewal")]
    renewal: bool,
    #[serde(rename = "Input")]
    inputs: Vec<ProfileInput>,
}

#[derive(Serialize)]
struct ProfileInput {
    id: String,
    #[serde(rename = "Attribute")]
    attrs: Vec<ProfileAttribute>,
}

#[derive(Serialize)]
struct ProfileAttribute {
    name: String,
    #[serde(rename = "Value")]
    value: String,
}

/// Dogtag returns enrollment results as a `DataCollection<CertRequestInfo>`:
/// `{"total": N, "entries": [...]}`.
#[derive(Deserialize)]
struct EnrollmentResponseCollection {
    entries: Vec<CertRequestInfo>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CertRequestInfo {
    #[serde(rename = "requestID")]
    request_id: String,
    request_status: String,
    #[serde(default)]
    cert_id: Option<String>,
    #[serde(default)]
    operation_result: Option<String>,
    #[serde(default)]
    error_message: Option<String>,
}

#[derive(Deserialize)]
struct CertData {
    #[serde(rename = "Encoded")]
    encoded: String,
}

impl DogtagSigner {
    /// Build a new Dogtag signer client from config.
    ///
    /// Reads the RA agent cert+key PEM files and constructs a `reqwest::Client`
    /// with TLS client certificate authentication.  Uses the
    /// `rustls_native_ossl` crypto provider (OpenSSL-based chain verification)
    /// to match the rest of the Akamu TLS stack.
    pub fn new(cfg: &DogtagSignerConfig) -> Result<Self, AcmeError> {
        if cfg.ra_key_password_file.is_some() {
            return Err(AcmeError::Config(
                "ra_key_password_file is not yet supported; \
                 the RA agent key must be an unencrypted PEM file"
                    .into(),
            ));
        }

        if !cfg.url.starts_with("https://") {
            tracing::warn!(
                "Dogtag URL '{}' does not use HTTPS; \
                 RA agent credentials will be sent in cleartext",
                cfg.url
            );
        }

        let tls_config = build_dogtag_tls_config(cfg)?;

        if cfg.tls_danger_accept_invalid_hostnames {
            tracing::warn!(
                "Dogtag TLS hostname verification disabled — \
                 do not use this setting in production"
            );
        }

        let client = reqwest::Client::builder()
            .use_preconfigured_tls(tls_config)
            .timeout(Duration::from_secs(cfg.timeout_secs))
            .pool_max_idle_per_host(16)
            .cookie_store(true)
            .build()
            .map_err(|e| AcmeError::Config(format!("build Dogtag HTTP client: {e}")))?;

        let base_url = cfg.url.trim_end_matches('/').to_string();

        Ok(Self {
            client,
            base_url,
            default_profile_id: cfg.profile_id.clone(),
            timeout: Duration::from_secs(cfg.timeout_secs),
        })
    }

    /// Probe the Dogtag CA for connectivity and establish an authenticated
    /// session.
    ///
    /// Sends a GET to the Dogtag info endpoint, then authenticates via the
    /// REST login endpoint using the RA agent TLS client certificate.  Logs
    /// warnings on failure but does not return an error (the CA may come up
    /// later).
    pub async fn probe(&self) {
        let url = format!("{}/ca/rest/info", self.base_url);
        match self
            .client
            .get(&url)
            .header("Accept", "application/json")
            .timeout(self.timeout)
            .send()
            .await
        {
            Ok(resp) if resp.status().is_success() => {
                tracing::info!("Dogtag CA at {} is reachable", self.base_url);
            }
            Ok(resp) => {
                tracing::warn!(
                    "Dogtag CA at {} returned HTTP {} during startup probe",
                    self.base_url,
                    resp.status()
                );
                return;
            }
            Err(e) => {
                tracing::warn!(
                    "Dogtag CA at {} unreachable during startup probe: {e:#}",
                    self.base_url
                );
                return;
            }
        }

        if let Err(e) = self.login().await {
            tracing::warn!("Dogtag RA agent login failed: {e:#}");
        }
    }

    /// Authenticate to Dogtag using the RA agent TLS client certificate.
    ///
    /// Dogtag's REST API uses session-based authentication.  This method
    /// POSTs to `/ca/rest/account/login` which establishes a session tied
    /// to the TLS client certificate.  The session cookie is stored in
    /// reqwest's cookie jar and included in subsequent requests.
    async fn login(&self) -> Result<(), AcmeError> {
        let url = format!("{}/ca/rest/account/login", self.base_url);
        let resp = self
            .client
            .post(&url)
            .header("Accept", "application/json")
            .timeout(self.timeout)
            .send()
            .await
            .map_err(|e| AcmeError::Dogtag(format!("RA agent login request failed: {e:#}")))?;

        if resp.status().is_success() {
            tracing::info!("Dogtag RA agent session established");
            Ok(())
        } else {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            Err(AcmeError::Dogtag(format!(
                "RA agent login returned HTTP {status}: {body}"
            )))
        }
    }

    /// POST to a Dogtag REST endpoint, re-establishing the session on 401.
    ///
    /// If the first attempt returns 401 (session expired or not yet
    /// established), calls `login()` and retries once.
    async fn post_with_login_retry<T: Serialize>(
        &self,
        url: &str,
        body: &T,
    ) -> Result<reqwest::Response, AcmeError> {
        let resp = self
            .client
            .post(url)
            .header("Accept", "application/json")
            .header("Content-Type", "application/json")
            .timeout(self.timeout)
            .json(body)
            .send()
            .await
            .map_err(|e| {
                if e.is_timeout() {
                    AcmeError::ServiceUnavailable(format!("Dogtag CA timeout: {e:#}"))
                } else if e.is_connect() {
                    AcmeError::ServiceUnavailable(format!("Dogtag CA unreachable: {e:#}"))
                } else {
                    AcmeError::Dogtag(format!("enrollment request failed: {e:#}"))
                }
            })?;

        if resp.status() != reqwest::StatusCode::UNAUTHORIZED {
            return Ok(resp);
        }

        tracing::debug!("Dogtag returned 401 — re-establishing RA agent session");
        self.login().await?;

        self.client
            .post(url)
            .header("Accept", "application/json")
            .header("Content-Type", "application/json")
            .timeout(self.timeout)
            .json(body)
            .send()
            .await
            .map_err(|e| {
                if e.is_timeout() {
                    AcmeError::ServiceUnavailable(format!("Dogtag CA timeout: {e:#}"))
                } else if e.is_connect() {
                    AcmeError::ServiceUnavailable(format!("Dogtag CA unreachable: {e:#}"))
                } else {
                    AcmeError::Dogtag(format!("enrollment request failed: {e:#}"))
                }
            })
    }

    /// Submit a PKCS#10 CSR to the Dogtag enrollment API and retrieve the
    /// issued certificate.
    ///
    /// The `profile_id` overrides the default Dogtag enrollment profile
    /// when `Some`.
    pub async fn issue_certificate(
        &self,
        csr_der: &[u8],
        profile_id: Option<&str>,
    ) -> Result<DogtagIssuedCert, AcmeError> {
        let profile = profile_id.unwrap_or(&self.default_profile_id);
        let csr_pem = String::from_utf8(synta_certificate::der_to_pem(
            "CERTIFICATE REQUEST",
            csr_der,
        ))
        .map_err(|_| AcmeError::Dogtag("CSR PEM not valid UTF-8".into()))?;

        let enrollment = EnrollmentRequest {
            profile_id: profile.to_string(),
            renewal: false,
            inputs: vec![ProfileInput {
                id: "i1".to_string(),
                attrs: vec![
                    ProfileAttribute {
                        name: "cert_request_type".to_string(),
                        value: "pkcs10".to_string(),
                    },
                    ProfileAttribute {
                        name: "cert_request".to_string(),
                        value: csr_pem,
                    },
                ],
            }],
        };

        let enroll_url = format!("{}/ca/rest/certrequests", self.base_url);
        let resp = self.post_with_login_retry(&enroll_url, &enrollment).await?;

        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(AcmeError::Dogtag(format!(
                "enrollment returned HTTP {status}: {body}"
            )));
        }

        let collection: EnrollmentResponseCollection = resp
            .json()
            .await
            .map_err(|e| AcmeError::Dogtag(format!("parse enrollment response: {e}")))?;

        let enroll_resp =
            collection.entries.into_iter().next().ok_or_else(|| {
                AcmeError::Dogtag("enrollment response contains no entries".into())
            })?;

        match enroll_resp.request_status.as_str() {
            "complete" => {
                if enroll_resp.operation_result.as_deref() == Some("error") {
                    let detail = enroll_resp
                        .error_message
                        .unwrap_or_else(|| "no details".into());
                    return Err(AcmeError::Dogtag(format!(
                        "enrollment completed with error: {detail}"
                    )));
                }
            }
            "pending" => {
                return Err(AcmeError::ServiceUnavailable(
                    "certificate request pending Dogtag agent approval".into(),
                ));
            }
            "rejected" => {
                let detail = enroll_resp
                    .error_message
                    .unwrap_or_else(|| "no details".into());
                return Err(AcmeError::Dogtag(format!(
                    "enrollment rejected by Dogtag: {detail}"
                )));
            }
            other => {
                return Err(AcmeError::Dogtag(format!(
                    "unexpected enrollment status: {other}"
                )));
            }
        }

        let cert_id = enroll_resp.cert_id.ok_or_else(|| {
            AcmeError::Dogtag(format!(
                "enrollment complete but no certId in response (requestID={})",
                enroll_resp.request_id
            ))
        })?;

        if !cert_id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            return Err(AcmeError::Dogtag(format!(
                "unexpected characters in cert_id '{cert_id}'"
            )));
        }

        self.retrieve_cert(&cert_id).await
    }

    /// Retrieve a certificate by ID from the Dogtag REST API.
    async fn retrieve_cert(&self, cert_id: &str) -> Result<DogtagIssuedCert, AcmeError> {
        let cert_url = format!("{}/ca/rest/certs/{}", self.base_url, cert_id);
        let resp = self
            .client
            .get(&cert_url)
            .header("Accept", "application/json")
            .timeout(self.timeout)
            .send()
            .await
            .map_err(|e| AcmeError::Dogtag(format!("cert retrieval failed: {e}")))?;

        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(AcmeError::Dogtag(format!(
                "cert retrieval returned HTTP {status}: {body}"
            )));
        }

        let cert_data: CertData = resp
            .json()
            .await
            .map_err(|e| AcmeError::Dogtag(format!("parse cert response: {e}")))?;

        let cert_b64 = cert_data
            .encoded
            .replace("-----BEGIN CERTIFICATE-----", "")
            .replace("-----END CERTIFICATE-----", "")
            .replace(['\n', '\r'], "");

        let cert_der = BASE64
            .decode(&cert_b64)
            .map_err(|e| AcmeError::Dogtag(format!("decode cert base64: {e}")))?;

        let (serial_hex, not_before, not_after) = parse_cert_metadata(&cert_der)?;

        Ok(DogtagIssuedCert {
            cert_der,
            serial_hex,
            not_before,
            not_after,
        })
    }
}

/// Issue a certificate via an external Dogtag CA and return an [`IssuedCert`](super::issue::IssuedCert)
/// compatible with the rest of the finalization pipeline.
///
/// The `csr_der` is the raw PKCS#10 DER from the ACME client — it is forwarded
/// to Dogtag as-is.  The Dogtag enrollment profile controls the extensions and
/// policy; Akamu's `CertificateParameters` only determines the profile ID
/// override.
pub async fn issue_via_dogtag(
    signer: &DogtagSigner,
    ca_cert_der: &[u8],
    csr_der: &[u8],
    dogtag_profile_id: Option<&str>,
) -> Result<super::issue::IssuedCert, AcmeError> {
    let issued = signer.issue_certificate(csr_der, dogtag_profile_id).await?;

    let leaf_pem = String::from_utf8(synta_certificate::der_to_pem(
        "CERTIFICATE",
        &issued.cert_der,
    ))
    .map_err(|_| AcmeError::Dogtag("issued cert PEM not valid UTF-8".into()))?;
    let ca_pem = String::from_utf8(synta_certificate::der_to_pem("CERTIFICATE", ca_cert_der))
        .map_err(|_| AcmeError::Dogtag("CA cert PEM not valid UTF-8".into()))?;
    let cert_pem = format!("{leaf_pem}{ca_pem}");

    if issued.serial_hex.len() % 2 != 0 {
        return Err(AcmeError::Dogtag(format!(
            "Dogtag returned odd-length serial hex '{}'",
            issued.serial_hex
        )));
    }
    let serial_bytes: Vec<u8> = (0..issued.serial_hex.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&issued.serial_hex[i..i + 2], 16).map_err(|e| {
                AcmeError::Dogtag(format!("invalid serial hex '{}': {e}", issued.serial_hex))
            })
        })
        .collect::<Result<_, _>>()?;

    Ok(super::issue::IssuedCert {
        id: uuid::Uuid::new_v4().to_string(),
        serial_hex: issued.serial_hex,
        serial_bytes,
        cert_der: issued.cert_der,
        cert_pem,
        not_before: issued.not_before,
        not_after: issued.not_after,
    })
}

/// Extract serial number (hex), notBefore, and notAfter from a DER certificate.
fn parse_cert_metadata(cert_der: &[u8]) -> Result<(String, i64, i64), AcmeError> {
    use synta_certificate::Certificate;

    let cert = Certificate::from_der(cert_der)
        .map_err(|e| AcmeError::Dogtag(format!("parse issued cert: {e}")))?;

    let serial_hex: String = cert
        .tbs_certificate
        .serial_number
        .as_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();

    let not_before = time_to_unix(&cert.tbs_certificate.validity.not_before)?;
    let not_after = time_to_unix(&cert.tbs_certificate.validity.not_after)?;

    Ok((serial_hex, not_before, not_after))
}

/// Convert an X.509 `Time` (UTCTime or GeneralizedTime) to a Unix timestamp.
fn time_to_unix(t: &synta_certificate::Time) -> Result<i64, AcmeError> {
    use synta_certificate::Time;
    match t {
        Time::GeneralTime(gt) => Ok(gt.to_unix()),
        Time::UtcTime(ut) => synta::GeneralizedTime::new(
            ut.year, ut.month, ut.day, ut.hour, ut.minute, ut.second, None,
        )
        .map(|gt| gt.to_unix())
        .map_err(|_| AcmeError::Dogtag("invalid UtcTime in Dogtag-issued certificate".into())),
    }
}

// ── TLS configuration ─────────────────────────────────────────────────────────

/// Build a `rustls::ClientConfig` for the Dogtag REST API connection.
///
/// Uses `rustls_native_ossl` for OpenSSL-based chain verification (matching
/// the rest of Akamu's TLS stack), with mTLS client auth via the RA agent
/// cert+key.
fn build_dogtag_tls_config(cfg: &DogtagSignerConfig) -> Result<rustls::ClientConfig, AcmeError> {
    use rustls_native_ossl::cert_verifier::{OsslChainVerifier, OsslServerCertVerifier};

    // ── RA agent client cert + key ──────────────────────────────────────
    let ra_cert_pem = std::fs::read(&cfg.ra_cert_file)
        .map_err(|e| AcmeError::Config(format!("read RA cert '{}': {e}", cfg.ra_cert_file)))?;
    let ra_key_pem = std::fs::read(&cfg.ra_key_file)
        .map_err(|e| AcmeError::Config(format!("read RA key '{}': {e}", cfg.ra_key_file)))?;

    let cert_ders: Vec<CertificateDer<'static>> = synta_certificate::pem_to_der(&ra_cert_pem)
        .into_iter()
        .map(CertificateDer::from)
        .collect();
    if cert_ders.is_empty() {
        return Err(AcmeError::Config(
            "RA cert PEM contains no certificates".into(),
        ));
    }

    let key_blocks = synta_certificate::pem_blocks(&ra_key_pem);
    let key_der = key_blocks
        .into_iter()
        .find(|(label, _)| label.contains("PRIVATE KEY"))
        .map(|(_, der)| der)
        .ok_or_else(|| AcmeError::Config("RA key PEM contains no private key".into()))?;
    let private_key = rustls::pki_types::PrivateKeyDer::try_from(key_der)
        .map_err(|e| AcmeError::Config(format!("parse RA agent private key: {e}")))?;

    // ── CA trust anchors ────────────────────────────────────────────────
    let mut all_ca_ders: Vec<CertificateDer<'_>> = Vec::new();

    if let Some(ref ca_cert_path) = cfg.ca_cert_file {
        let ca_pem = std::fs::read(ca_cert_path).map_err(|e| {
            AcmeError::Config(format!("read Dogtag CA cert '{}': {e}", ca_cert_path))
        })?;
        let extra = synta_certificate::pem_to_der(&ca_pem);
        if extra.is_empty() {
            return Err(AcmeError::Config(
                "Dogtag CA cert PEM contains no certificates".into(),
            ));
        }
        for der in extra {
            all_ca_ders.push(CertificateDer::from(der));
        }
    }

    let native = rustls_native_certs::load_native_certs();
    for cert in &native.certs {
        all_ca_ders.push(CertificateDer::from(cert.as_ref()));
    }

    // ── Chain verifier (OpenSSL) ────────────────────────────────────────
    let chain_verifier = OsslChainVerifier::new(&all_ca_ders)
        .map_err(|e| AcmeError::Config(format!("build Dogtag TLS chain verifier: {e}")))?;

    let verifier = if cfg.tls_danger_accept_invalid_hostnames {
        let bypass = Arc::new(HostnameBypassVerifier {
            inner: chain_verifier,
        });
        OsslServerCertVerifier::builder_with_verifier(bypass).build()
    } else {
        OsslServerCertVerifier::builder_with_verifier(Arc::new(chain_verifier)).build()
    };

    // ── Assemble ClientConfig ───────────────────────────────────────────
    rustls::ClientConfig::builder_with_provider(rustls_native_ossl::default_provider().into())
        .with_safe_default_protocol_versions()
        .map_err(|e| AcmeError::Config(format!("TLS protocol versions: {e}")))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_client_auth_cert(cert_ders, private_key)
        .map_err(|e| AcmeError::Config(format!("RA agent TLS client auth: {e}")))
}

/// Wraps `OsslChainVerifier` to skip hostname verification by passing `None`
/// for `server_name`.  Only used when `tls_danger_accept_invalid_hostnames`
/// is set (development/demo environments).
#[derive(Debug)]
struct HostnameBypassVerifier {
    inner: rustls_native_ossl::cert_verifier::OsslChainVerifier,
}

impl rustls_native_ossl::cert_verifier::CertChainVerifier for HostnameBypassVerifier {
    fn verify_chain(
        &self,
        end_entity: &native_ossl::x509::X509,
        intermediates: &[native_ossl::x509::X509],
        _server_name: Option<&rustls::pki_types::ServerName<'_>>,
        now: rustls::pki_types::UnixTime,
    ) -> Result<(), rustls::Error> {
        self.inner
            .verify_chain(end_entity, intermediates, None, now)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csr_pem_round_trip_via_synta() {
        let fake_der = b"not a real CSR but enough to test encoding";
        let pem = String::from_utf8(synta_certificate::der_to_pem(
            "CERTIFICATE REQUEST",
            fake_der,
        ))
        .unwrap();
        assert!(pem.contains("-----BEGIN CERTIFICATE REQUEST-----"));
        assert!(pem.contains("-----END CERTIFICATE REQUEST-----"));

        let blocks = synta_certificate::pem_blocks(pem.as_bytes());
        let (label, decoded) = blocks.into_iter().next().unwrap();
        assert_eq!(label, "CERTIFICATE REQUEST");
        assert_eq!(&decoded, fake_der);
    }

    #[test]
    fn enrollment_request_serializes() {
        let req = EnrollmentRequest {
            profile_id: "caServerCert".into(),
            renewal: false,
            inputs: vec![ProfileInput {
                id: "i1".into(),
                attrs: vec![
                    ProfileAttribute {
                        name: "cert_request_type".into(),
                        value: "pkcs10".into(),
                    },
                    ProfileAttribute {
                        name: "cert_request".into(),
                        value: "MIIBxDCC...".into(),
                    },
                ],
            }],
        };
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["ProfileID"], "caServerCert");
        assert_eq!(json["Renewal"], false);
        assert_eq!(json["Input"][0]["id"], "i1");
        assert_eq!(
            json["Input"][0]["Attribute"][0]["name"],
            "cert_request_type"
        );
        assert_eq!(json["Input"][0]["Attribute"][0]["Value"], "pkcs10");
    }

    #[test]
    fn enrollment_response_deserializes_complete() {
        let json = r#"{
            "total": 1,
            "entries": [{
                "requestID": "0x2a",
                "requestStatus": "complete",
                "certId": "0x7b",
                "operationResult": "success"
            }]
        }"#;
        let collection: EnrollmentResponseCollection = serde_json::from_str(json).unwrap();
        assert_eq!(collection.entries.len(), 1);
        let resp = &collection.entries[0];
        assert_eq!(resp.request_id, "0x2a");
        assert_eq!(resp.request_status, "complete");
        assert_eq!(resp.cert_id.as_deref(), Some("0x7b"));
        assert_eq!(resp.operation_result.as_deref(), Some("success"));
        assert!(resp.error_message.is_none());
    }

    #[test]
    fn enrollment_response_deserializes_rejected() {
        let json = r#"{
            "total": 1,
            "entries": [{
                "requestID": "0x2b",
                "requestStatus": "rejected",
                "errorMessage": "profile constraint violated"
            }]
        }"#;
        let collection: EnrollmentResponseCollection = serde_json::from_str(json).unwrap();
        let resp = &collection.entries[0];
        assert_eq!(resp.request_status, "rejected");
        assert_eq!(
            resp.error_message.as_deref(),
            Some("profile constraint violated")
        );
    }

    #[test]
    fn enrollment_response_complete_with_error() {
        let json = r#"{
            "total": 1,
            "entries": [{
                "requestID": "0x2c",
                "requestStatus": "complete",
                "operationResult": "error",
                "errorMessage": "internal CA error"
            }]
        }"#;
        let collection: EnrollmentResponseCollection = serde_json::from_str(json).unwrap();
        let resp = &collection.entries[0];
        assert_eq!(resp.request_status, "complete");
        assert_eq!(resp.operation_result.as_deref(), Some("error"));
        assert_eq!(resp.error_message.as_deref(), Some("internal CA error"));
    }

    #[test]
    fn cert_data_deserializes() {
        let json = r#"{"Encoded": "MIIB..."}"#;
        let data: CertData = serde_json::from_str(json).unwrap();
        assert_eq!(data.encoded, "MIIB...");
    }
}
