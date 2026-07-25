//! HTTP client for querying an MTC transparency log server.

use std::sync::Arc;
use std::time::Duration;

use http_body_util::{BodyExt, Full, Limited};
use hyper::{body::Bytes, HeaderMap, Method, Request, StatusCode};
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::{client::legacy::Client, rt::TokioExecutor};
use serde::de::DeserializeOwned;

use percent_encoding::{utf8_percent_encode, AsciiSet, CONTROLS};

use crate::error::ClientError;
use crate::mtc_types::{
    CertFetchResult, ConsistencyProofResponse, InclusionProofResponse, Landmark,
    SubtreeRootResponse, TreeRoot, TreeSize,
};

const PATH_SEGMENT_ENCODE: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'/')
    .add(b'?')
    .add(b'#')
    .add(b'%')
    .add(b'[')
    .add(b']');

type HyperClient = Client<hyper_rustls::HttpsConnector<HttpConnector>, Full<Bytes>>;

const DEFAULT_MAX_RESPONSE_BYTES: usize = 10 * 1024 * 1024;
const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

pub struct MtcClient {
    http: HyperClient,
    mtc_base_url: String,
    max_response_bytes: usize,
    request_timeout: Duration,
}

impl std::fmt::Debug for MtcClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MtcClient")
            .field("mtc_base_url", &self.mtc_base_url)
            .field("max_response_bytes", &self.max_response_bytes)
            .field("request_timeout", &self.request_timeout)
            .finish_non_exhaustive()
    }
}

fn mtc_base_from_directory(directory_url: &str) -> String {
    let url = directory_url.trim_end_matches('/');
    if let Some(prefix) = url.strip_suffix("/directory") {
        format!("{prefix}/mtc")
    } else if url.ends_with("/acme") {
        format!("{url}/mtc")
    } else {
        format!("{url}/acme/mtc")
    }
}

pub fn cert_id_from_url(cert_url: &str) -> Option<&str> {
    let path = cert_url.split('?').next().unwrap_or(cert_url);
    let path = path.split('#').next().unwrap_or(path);
    path.rsplit('/').next().filter(|s| !s.is_empty())
}

impl MtcClient {
    pub fn new(directory_url: &str) -> Result<Self, ClientError> {
        let https = HttpsConnectorBuilder::new()
            .with_provider_and_native_roots(rustls_native_ossl::default_provider())
            .map_err(|e| ClientError::Http(format!("TLS root certs: {e}")))?
            .https_or_http()
            .enable_http1()
            .build();
        let http = Client::builder(TokioExecutor::new()).build(https);
        Ok(Self {
            http,
            mtc_base_url: mtc_base_from_directory(directory_url),
            max_response_bytes: DEFAULT_MAX_RESPONSE_BYTES,
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
        })
    }

    pub fn new_with_extra_root(
        directory_url: &str,
        ca_cert_pem: &[u8],
    ) -> Result<Self, ClientError> {
        use rustls::pki_types::CertificateDer;
        use rustls_native_ossl::cert_verifier::OsslServerCertVerifier;

        let extra_ders = synta_certificate::pem_to_der(ca_cert_pem);
        if extra_ders.is_empty() {
            return Err(ClientError::Http(
                "CA PEM file contains no certificate block".into(),
            ));
        }

        let native = rustls_native_certs::load_native_certs();
        for err in &native.errors {
            tracing::warn!("native cert loading error: {err}");
        }
        let mut all_ca_ders: Vec<CertificateDer<'_>> = native
            .certs
            .iter()
            .map(|c| CertificateDer::from(c.as_ref()))
            .collect();
        for der in &extra_ders {
            all_ca_ders.push(CertificateDer::from(der.as_slice()));
        }

        let chain_verifier = crate::tls_verify::MtcAwareChainVerifier::new(&all_ca_ders)
            .map_err(|e| ClientError::Http(format!("build CA verifier: {e}")))?;
        let verifier =
            OsslServerCertVerifier::builder_with_verifier(Arc::new(chain_verifier)).build();

        let config = rustls::ClientConfig::builder_with_provider(
            rustls_native_ossl::default_provider().into(),
        )
        .with_safe_default_protocol_versions()
        .map_err(|e| ClientError::Http(format!("TLS protocol versions: {e}")))?
        // .dangerous() is required by rustls to install any custom verifier;
        // OsslServerCertVerifier performs full chain verification via OpenSSL.
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth();

        let https = HttpsConnectorBuilder::new()
            .with_tls_config(config)
            .https_or_http()
            .enable_http1()
            .build();
        let http = Client::builder(TokioExecutor::new()).build(https);
        Ok(Self {
            http,
            mtc_base_url: mtc_base_from_directory(directory_url),
            max_response_bytes: DEFAULT_MAX_RESPONSE_BYTES,
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
        })
    }

    pub fn new_https_only(directory_url: &str) -> Result<Self, ClientError> {
        let https = HttpsConnectorBuilder::new()
            .with_provider_and_native_roots(rustls_native_ossl::default_provider())
            .map_err(|e| ClientError::Http(format!("TLS root certs: {e}")))?
            .https_only()
            .enable_http1()
            .build();
        let http = Client::builder(TokioExecutor::new()).build(https);
        Ok(Self {
            http,
            mtc_base_url: mtc_base_from_directory(directory_url),
            max_response_bytes: DEFAULT_MAX_RESPONSE_BYTES,
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
        })
    }

    pub fn set_max_response_bytes(&mut self, limit: usize) {
        self.max_response_bytes = limit;
    }

    pub fn set_request_timeout(&mut self, timeout: Duration) {
        self.request_timeout = timeout;
    }

    async fn get_json<T: DeserializeOwned>(&self, path: &str) -> Result<T, ClientError> {
        let url = format!("{}{}", self.mtc_base_url, path);
        let req = Request::builder()
            .method(Method::GET)
            .uri(&url)
            .body(Full::<Bytes>::new(Bytes::new()))
            .map_err(|e| ClientError::Http(format!("build GET request: {e}")))?;
        let resp = tokio::time::timeout(self.request_timeout, self.http.request(req))
            .await
            .map_err(|_| ClientError::Http(format!("GET {url}: request timed out")))?
            .map_err(|e| ClientError::Http(format!("GET {url}: {e}")))?;
        let status = resp.status();
        let limited = Limited::new(resp.into_body(), self.max_response_bytes);
        let raw = tokio::time::timeout(self.request_timeout, limited.collect())
            .await
            .map_err(|_| ClientError::Http(format!("GET {url}: body read timed out")))?
            .map_err(|e| {
                ClientError::Http(format!(
                    "GET {url}: response body exceeds {}-byte limit or read error: {e}",
                    self.max_response_bytes
                ))
            })?
            .to_bytes()
            .to_vec();
        if !status.is_success() {
            return Err(ClientError::Http(format!(
                "GET {url}: {status}: {}",
                String::from_utf8_lossy(&raw)
            )));
        }
        serde_json::from_slice(&raw)
            .map_err(|e| ClientError::Http(format!("parse JSON from {url}: {e}")))
    }

    async fn get_bytes(&self, path: &str) -> Result<(StatusCode, HeaderMap, Vec<u8>), ClientError> {
        let url = format!("{}{}", self.mtc_base_url, path);
        let req = Request::builder()
            .method(Method::GET)
            .uri(&url)
            .body(Full::<Bytes>::new(Bytes::new()))
            .map_err(|e| ClientError::Http(format!("build GET request: {e}")))?;
        let resp = tokio::time::timeout(self.request_timeout, self.http.request(req))
            .await
            .map_err(|_| ClientError::Http(format!("GET {url}: request timed out")))?
            .map_err(|e| ClientError::Http(format!("GET {url}: {e}")))?;
        let status = resp.status();
        let headers = resp.headers().clone();
        let limited = Limited::new(resp.into_body(), self.max_response_bytes);
        let raw = tokio::time::timeout(self.request_timeout, limited.collect())
            .await
            .map_err(|_| ClientError::Http(format!("GET {url}: body read timed out")))?
            .map_err(|e| {
                ClientError::Http(format!(
                    "GET {url}: response body exceeds {}-byte limit or read error: {e}",
                    self.max_response_bytes
                ))
            })?
            .to_bytes()
            .to_vec();
        Ok((status, headers, raw))
    }

    async fn get_bytes_ok(&self, path: &str) -> Result<Vec<u8>, ClientError> {
        let (status, _, body) = self.get_bytes(path).await?;
        if !status.is_success() {
            return Err(ClientError::Http(format!(
                "GET {}{path}: {status}: {}",
                self.mtc_base_url,
                String::from_utf8_lossy(&body)
            )));
        }
        Ok(body)
    }

    pub async fn tree_size(&self) -> Result<TreeSize, ClientError> {
        self.get_json("/tree-size").await
    }

    pub async fn root(&self) -> Result<TreeRoot, ClientError> {
        self.get_json("/root").await
    }

    pub async fn inclusion_proof(
        &self,
        cert_id: &str,
    ) -> Result<InclusionProofResponse, ClientError> {
        let encoded = utf8_percent_encode(cert_id, PATH_SEGMENT_ENCODE);
        self.get_json(&format!("/inclusion-proof/{encoded}")).await
    }

    pub async fn standalone_cert(&self, cert_id: &str) -> Result<Vec<u8>, ClientError> {
        let encoded = utf8_percent_encode(cert_id, PATH_SEGMENT_ENCODE);
        self.get_bytes_ok(&format!("/cert/{encoded}/standalone"))
            .await
    }

    pub async fn landmark_cert_for(&self, cert_id: &str) -> Result<CertFetchResult, ClientError> {
        let encoded = utf8_percent_encode(cert_id, PATH_SEGMENT_ENCODE);
        let (status, headers, body) = self.get_bytes(&format!("/cert/{encoded}/landmark")).await?;
        if status == StatusCode::SERVICE_UNAVAILABLE {
            let retry = headers
                .get("retry-after")
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or(60);
            return Ok(CertFetchResult::RetryAfter(retry));
        }
        if !status.is_success() {
            return Err(ClientError::Http(format!(
                "GET landmark cert: {status}: {}",
                String::from_utf8_lossy(&body)
            )));
        }
        Ok(CertFetchResult::Ok(body))
    }

    pub async fn landmarks(&self) -> Result<Vec<Landmark>, ClientError> {
        self.get_json("/landmarks").await
    }

    pub async fn landmark_list(&self) -> Result<String, ClientError> {
        let body = self.get_bytes_ok("/landmark-list").await?;
        String::from_utf8(body).map_err(|e| ClientError::Http(format!("invalid UTF-8: {e}")))
    }

    pub async fn landmark_cert(&self, seq: i64) -> Result<CertFetchResult, ClientError> {
        let (status, headers, body) = self.get_bytes(&format!("/landmarks/{seq}/cert")).await?;
        if status == StatusCode::SERVICE_UNAVAILABLE {
            let retry = headers
                .get("retry-after")
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or(60);
            return Ok(CertFetchResult::RetryAfter(retry));
        }
        if !status.is_success() {
            return Err(ClientError::Http(format!(
                "GET landmark cert {seq}: {status}: {}",
                String::from_utf8_lossy(&body)
            )));
        }
        Ok(CertFetchResult::Ok(body))
    }

    pub async fn consistency_proof(
        &self,
        from: u64,
        to: u64,
    ) -> Result<ConsistencyProofResponse, ClientError> {
        self.get_json(&format!("/consistency-proof?from={from}&to={to}"))
            .await
    }

    pub async fn subtree_root(
        &self,
        start: u64,
        end: u64,
    ) -> Result<SubtreeRootResponse, ClientError> {
        self.get_json(&format!("/subtree-root?start={start}&end={end}"))
            .await
    }

    pub async fn revoked_ranges(&self) -> Result<Vec<[i64; 2]>, ClientError> {
        self.get_json("/revoked-ranges").await
    }

    pub async fn tlog_checkpoint(&self) -> Result<String, ClientError> {
        let body = self.get_bytes_ok("/checkpoint").await?;
        String::from_utf8(body).map_err(|e| ClientError::Http(format!("invalid UTF-8: {e}")))
    }

    pub async fn tlog_tile(&self, path: &str) -> Result<Vec<u8>, ClientError> {
        self.get_bytes_ok(&format!("/tile/{path}")).await
    }

    pub async fn tlog_cosignature(&self) -> Result<String, ClientError> {
        let body = self.get_bytes_ok("/cosignature").await?;
        String::from_utf8(body).map_err(|e| ClientError::Http(format!("invalid UTF-8: {e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mtc_base_default_ca() {
        assert_eq!(
            mtc_base_from_directory("https://host/acme/directory"),
            "https://host/acme/mtc"
        );
    }

    #[test]
    fn mtc_base_named_ca() {
        assert_eq!(
            mtc_base_from_directory("https://host/acme/myca/directory"),
            "https://host/acme/myca/mtc"
        );
    }

    #[test]
    fn mtc_base_trailing_slash() {
        assert_eq!(
            mtc_base_from_directory("https://host/acme/directory/"),
            "https://host/acme/mtc"
        );
    }

    #[test]
    fn mtc_base_no_directory_suffix() {
        assert_eq!(
            mtc_base_from_directory("https://host/acme"),
            "https://host/acme/mtc"
        );
    }

    #[test]
    fn mtc_base_bare_url() {
        assert_eq!(
            mtc_base_from_directory("https://host:8556"),
            "https://host:8556/acme/mtc"
        );
    }

    #[test]
    fn cert_id_extraction() {
        assert_eq!(
            cert_id_from_url("https://host/acme/cert/abc123"),
            Some("abc123")
        );
    }

    #[test]
    fn cert_id_from_empty() {
        assert_eq!(cert_id_from_url(""), None);
    }

    #[test]
    fn cert_id_from_trailing_slash() {
        assert_eq!(cert_id_from_url("https://host/acme/cert/"), None);
    }

    #[test]
    fn cert_id_with_query_string() {
        assert_eq!(
            cert_id_from_url("https://host/acme/cert/abc123?foo=bar"),
            Some("abc123")
        );
    }

    #[test]
    fn cert_id_with_fragment() {
        assert_eq!(
            cert_id_from_url("https://host/acme/cert/abc123#section"),
            Some("abc123")
        );
    }

    #[test]
    fn cert_id_with_query_and_fragment() {
        assert_eq!(
            cert_id_from_url("https://host/acme/cert/abc123?k=v#frag"),
            Some("abc123")
        );
    }
}
