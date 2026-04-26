//! External cosignature gathering (§6.2 of draft-ietf-plants-merkle-tree-certs).
//!
//! After a checkpoint is produced, akamu POSTs the DER-encoded Checkpoint to
//! each configured cosigner URL.  The cosigner is expected to return a
//! DER-encoded `SubtreeSignature`.  Failures are logged and skipped — partial
//! success is acceptable; the standalone certificate is built with whatever
//! signatures arrive.
//!
//! HTTPS is required for cosigner URLs in production.  The TLS client is built
//! per-cosigner using the OS native root CA store; when `cosigner_id_cert_pem`
//! is configured for a cosigner, that PEM file is also added to the trust store,
//! enabling cosigners whose TLS certificates chain to an operator-provisioned CA
//! (e.g. another Akāmu instance's CA certificate).

use std::sync::Arc;
use std::time::Duration;

use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::{Method, Request};
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use rustls::pki_types::CertificateDer;
use rustls::{ClientConfig, RootCertStore};
use synta_certificate::pem_to_der;

use crate::config::CosignerConfig;
use crate::error::AcmeError;

const COSIGNER_TIMEOUT_SECS: u64 = 30;

/// Build a rustls `ClientConfig` that trusts the OS native root CAs, plus an
/// optional operator-supplied CA certificate (for cosigners using a private PKI).
fn build_cosigner_tls_config(
    cosigner_ca_pem_path: Option<&str>,
) -> Result<ClientConfig, AcmeError> {
    let mut roots = RootCertStore::empty();

    // Load OS native root CAs.
    let native = rustls_native_certs::load_native_certs();
    roots.add_parsable_certificates(native.certs);
    if !native.errors.is_empty() {
        tracing::warn!(
            errors = native.errors.len(),
            "some native root CA certs could not be loaded"
        );
    }

    // Add the per-cosigner CA cert when configured (e.g. an Akāmu CA cert).
    if let Some(path) = cosigner_ca_pem_path {
        let pem = std::fs::read(path)
            .map_err(|e| AcmeError::Tls(format!("read cosigner CA '{path}': {e}")))?;
        let ders = pem_to_der(&pem);
        if ders.is_empty() {
            return Err(AcmeError::Tls(format!(
                "cosigner CA file '{path}' contains no PEM certificate blocks"
            )));
        }
        for der in ders {
            roots
                .add(CertificateDer::from(der))
                .map_err(|e| AcmeError::Tls(format!("add cosigner CA cert from '{path}': {e}")))?;
        }
    }

    Ok(
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
            .map_err(|e| AcmeError::Tls(format!("rustls protocol versions: {e}")))?
            .with_root_certificates(roots)
            .with_no_client_auth(),
    )
}

/// POST `checkpoint_der` to each configured cosigner and return the DER-encoded
/// `SubtreeSignature` responses as `(cosigner_url, signature_der)` pairs.
///
/// Each request is issued sequentially with a 30-second per-cosigner timeout.
/// Failures are logged and skipped; partial success is acceptable.
pub async fn gather_cosignatures(
    checkpoint_der: &[u8],
    cosigners: &[CosignerConfig],
) -> Vec<(String, Vec<u8>)> {
    if cosigners.is_empty() {
        return Vec::new();
    }

    let body_bytes = Bytes::copy_from_slice(checkpoint_der);
    let mut results = Vec::new();

    for cosigner in cosigners {
        let url = cosigner.url.clone();

        // Build a per-cosigner HTTPS client that trusts the cosigner's custom CA.
        let tls_config = match build_cosigner_tls_config(cosigner.cosigner_id_cert_pem.as_deref()) {
            Ok(cfg) => cfg,
            Err(e) => {
                tracing::warn!(url = %url, "build cosigner TLS config: {e}");
                continue;
            }
        };
        let https = HttpsConnectorBuilder::new()
            .with_tls_config(tls_config)
            .https_or_http()
            .enable_http1()
            .build();
        let client = Client::builder(TokioExecutor::new()).build::<_, Full<Bytes>>(https);

        let req = match Request::builder()
            .method(Method::POST)
            .uri(&url)
            .header("Content-Type", "application/octet-stream")
            .body(Full::new(body_bytes.clone()))
        {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(url = %url, "build cosigner request: {e}");
                continue;
            }
        };

        let resp = match tokio::time::timeout(
            Duration::from_secs(COSIGNER_TIMEOUT_SECS),
            client.request(req),
        )
        .await
        {
            Err(_) => {
                tracing::warn!(
                    url = %url,
                    timeout_secs = COSIGNER_TIMEOUT_SECS,
                    "cosigner request timed out"
                );
                continue;
            }
            Ok(Err(e)) => {
                tracing::warn!(url = %url, "cosigner request failed: {e}");
                continue;
            }
            Ok(Ok(r)) => r,
        };

        let status = resp.status();
        match resp.into_body().collect().await {
            Ok(collected) => {
                if status.is_success() {
                    let der = collected.to_bytes().to_vec();
                    if der.is_empty() {
                        tracing::warn!(url = %url, "cosigner returned empty body");
                    } else {
                        tracing::debug!(url = %url, bytes = der.len(), "cosignature received");
                        results.push((url, der));
                    }
                } else {
                    tracing::warn!(
                        url = %url,
                        status = %status,
                        "cosigner returned non-2xx status"
                    );
                }
            }
            Err(e) => tracing::warn!(url = %url, "read cosigner response body: {e}"),
        }
    }

    results
}
