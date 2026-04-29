//! External cosignature gathering (§6.2 of draft-ietf-plants-merkle-tree-certs).
//!
//! After a checkpoint is produced, akamu POSTs the DER-encoded Checkpoint to
//! each configured cosigner URL.  The cosigner is expected to return a
//! DER-encoded `SubtreeSignature`.  Failures are logged and skipped — partial
//! success is acceptable; the standalone certificate is built with whatever
//! signatures arrive.
//!
//! HTTPS is required for cosigner URLs in production.  The TLS client is built
//! once per cosigner at server startup using the OS native root CA store; when
//! `cosigner_id_cert_pem` is configured, that PEM file is also added to the
//! trust store, enabling cosigners whose TLS certificates chain to an
//! operator-provisioned CA (e.g. another Akāmu instance's CA certificate).
//! Using a pre-built `CosignerClient` avoids re-reading PEM files on every
//! checkpoint and surfaces misconfigured cosigners at startup rather than
//! silently at checkpoint time.

use std::time::Duration;

use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::{Method, Request};
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use rustls::pki_types::CertificateDer;
use rustls::{ClientConfig, RootCertStore};
use synta::traits::Encode;
use synta::{Decoder, Encoder, Encoding};
use synta_certificate::owned::Certificate;
use synta_certificate::{pem_to_der, OpensslSignatureVerifier, SignatureVerifier as _};
use synta_mtc::types::{CosignerID, SubtreeSignature};

use crate::config::CosignerConfig;
use crate::error::AcmeError;

const COSIGNER_TIMEOUT_SECS: u64 = 30;

type HttpsClient = Client<hyper_rustls::HttpsConnector<HttpConnector>, Full<Bytes>>;

/// Pre-parsed verification material for a configured cosigner.
///
/// Loaded once at startup from `cosigner_id_cert_pem`.  Allows verifying the
/// `SubtreeSignature` returned by the cosigner without re-reading the cert file.
#[derive(Clone)]
struct CosignerVerifier {
    /// Expected `CosignerID` (issuer + serial) — must match `SubtreeSignature.cosigner`.
    expected_id: CosignerID,
    /// DER-encoded `SubjectPublicKeyInfo` of the cosigner's signing key.
    spki_der: Vec<u8>,
}

/// A cosigner URL paired with its pre-built HTTPS client.
///
/// Built once at server startup (see `build_cosigner_client`) and stored in
/// `MtcState`.  Re-using one `Client` per cosigner preserves the connection
/// pool across checkpoint intervals.
pub struct CosignerClient {
    pub(crate) url: String,
    client: HttpsClient,
    /// Verification key — `Some` when `cosigner_id_cert_pem` is configured.
    verifier: Option<CosignerVerifier>,
}

/// Build a `CosignerClient` that connects over plain HTTP (no TLS).
///
/// Intended for integration tests only; compiled only with `--features test-utils`.
#[cfg(feature = "test-utils")]
pub fn build_cosigner_client_http(url: String) -> CosignerClient {
    let tls_config = build_tls_config(None).expect("native roots for test cosigner client");
    let https = HttpsConnectorBuilder::new()
        .with_tls_config(tls_config)
        .https_or_http()
        .enable_http1()
        .build();
    let client = Client::builder(TokioExecutor::new()).build::<_, Full<Bytes>>(https);
    CosignerClient {
        url,
        client,
        verifier: None,
    }
}

/// Build a `CosignerClient` for `cfg`, loading native root CAs and any
/// optional per-cosigner CA certificate from disk.
///
/// Returns an error if the PEM file is missing or contains no certificate
/// blocks; a warning is logged for individual native-CA load failures.
pub fn build_cosigner_client(cfg: &CosignerConfig) -> Result<CosignerClient, AcmeError> {
    let tls_config = build_tls_config(cfg.cosigner_id_cert_pem.as_deref())?;
    let https = HttpsConnectorBuilder::new()
        .with_tls_config(tls_config)
        .https_only()
        .enable_http1()
        .build();
    let client = Client::builder(TokioExecutor::new()).build::<_, Full<Bytes>>(https);

    let verifier = cfg
        .cosigner_id_cert_pem
        .as_deref()
        .map(load_cosigner_verifier)
        .transpose()?;

    Ok(CosignerClient {
        url: cfg.url.clone(),
        client,
        verifier,
    })
}

/// Load a cosigner's ID cert PEM and extract the SPKI + CosignerID for
/// verifying `SubtreeSignature` responses at checkpoint time.
fn load_cosigner_verifier(pem_path: &str) -> Result<CosignerVerifier, AcmeError> {
    let pem = std::fs::read(pem_path)
        .map_err(|e| AcmeError::Tls(format!("read cosigner ID cert '{pem_path}': {e}")))?;
    let der = pem_to_der(&pem)
        .into_iter()
        .next()
        .ok_or_else(|| AcmeError::Tls(format!("cosigner ID cert '{pem_path}': no PEM block")))?;

    let cert: Certificate = Decoder::new(&der, Encoding::Der)
        .decode()
        .map_err(|e| AcmeError::Tls(format!("parse cosigner ID cert: {e}")))?;

    // DER-encode SPKI.
    let mut enc = Encoder::new(Encoding::Der);
    cert.tbs_certificate
        .subject_public_key_info
        .encode(&mut enc)
        .map_err(|e| AcmeError::Tls(format!("encode cosigner SPKI: {e}")))?;
    let spki_der = enc
        .finish()
        .map_err(|e| AcmeError::Tls(format!("finish cosigner SPKI DER: {e}")))?;

    // Derive CosignerID: DER-encode issuer then re-decode as synta_mtc::Name.
    let mut enc2 = Encoder::new(Encoding::Der);
    cert.tbs_certificate
        .issuer
        .encode(&mut enc2)
        .map_err(|e| AcmeError::Tls(format!("encode cosigner issuer: {e}")))?;
    let issuer_der = enc2
        .finish()
        .map_err(|e| AcmeError::Tls(format!("finish cosigner issuer DER: {e}")))?;
    let mtc_issuer = Decoder::new(&issuer_der, Encoding::Der)
        .decode::<synta_mtc::types::Name>()
        .map_err(|e| AcmeError::Tls(format!("decode cosigner issuer as MTC Name: {e}")))?;

    let expected_id = CosignerID {
        issuer: mtc_issuer,
        serial_number: cert.tbs_certificate.serial_number.clone(),
    };

    Ok(CosignerVerifier {
        expected_id,
        spki_der,
    })
}

/// Verify a `SubtreeSignature` DER returned by a cosigner.
///
/// Checks:
/// 1. `cosigner` field matches the expected `CosignerID` (issuer + serial).
/// 2. `signature` over the original checkpoint DER is valid under the cosigner's SPKI.
fn verify_subtree_signature(
    checkpoint_der: &[u8],
    response_der: &[u8],
    v: &CosignerVerifier,
) -> Result<(), String> {
    let sig = SubtreeSignature::from_der(response_der)
        .map_err(|e| format!("parse SubtreeSignature: {e}"))?;

    if sig.cosigner != v.expected_id {
        return Err("SubtreeSignature.cosigner does not match expected CosignerID".into());
    }

    // DER-encode the signature algorithm from the response.
    let mut enc = Encoder::new(Encoding::Der);
    sig.signature_algorithm
        .encode(&mut enc)
        .map_err(|e| format!("encode sig_alg: {e}"))?;
    let sig_alg_der = enc
        .finish()
        .map_err(|e| format!("finish sig_alg DER: {e}"))?;

    // The cosigner signed the raw checkpoint DER bytes.
    let signature_bits = sig.signature.as_bytes();

    OpensslSignatureVerifier
        .verify_certificate_signature(checkpoint_der, &sig_alg_der, signature_bits, &v.spki_der)
        .map_err(|e| format!("cosignature cryptographic verification failed: {e}"))
}

fn build_tls_config(cosigner_ca_pem_path: Option<&str>) -> Result<ClientConfig, AcmeError> {
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

    Ok(ClientConfig::builder_with_provider(std::sync::Arc::new(
        rustls_native_ossl::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
    .map_err(|e| AcmeError::Tls(format!("rustls protocol versions: {e}")))?
    .with_root_certificates(roots)
    .with_no_client_auth())
}

/// POST `checkpoint_der` to each cosigner and return the DER-encoded
/// `SubtreeSignature` responses as `(cosigner_url, signature_der)` pairs.
///
/// All cosigners are contacted in parallel with a 30-second per-cosigner
/// timeout.  Failures are logged and skipped; partial success is acceptable.
pub async fn gather_cosignatures(
    checkpoint_der: &[u8],
    cosigners: &[CosignerClient],
) -> Vec<(String, Vec<u8>)> {
    if cosigners.is_empty() {
        return Vec::new();
    }

    let body_bytes = Bytes::copy_from_slice(checkpoint_der);

    let handles: Vec<_> = cosigners
        .iter()
        .map(|cosigner| {
            let url = cosigner.url.clone();
            let client = cosigner.client.clone();
            let body = body_bytes.clone();
            let verifier = cosigner.verifier.clone();
            tokio::spawn(async move { post_to_cosigner(url, client, body, verifier).await })
        })
        .collect();

    let mut results = Vec::new();
    for handle in handles {
        match handle.await {
            Ok(Some(pair)) => results.push(pair),
            Ok(None) => {}
            Err(e) => tracing::warn!("cosigner task panicked: {e}"),
        }
    }
    results
}

async fn post_to_cosigner(
    url: String,
    client: HttpsClient,
    body_bytes: Bytes,
    verifier: Option<CosignerVerifier>,
) -> Option<(String, Vec<u8>)> {
    // Clone before move into request body — Bytes clone is O(1).
    let checkpoint_bytes = body_bytes.clone();

    let req = match Request::builder()
        .method(Method::POST)
        .uri(&url)
        .header("Content-Type", "application/octet-stream")
        .body(Full::new(body_bytes))
    {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(url = %url, "build cosigner request: {e}");
            return None;
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
            return None;
        }
        Ok(Err(e)) => {
            tracing::warn!(url = %url, "cosigner request failed: {e}");
            return None;
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
                    return None;
                }
                if let Some(ref v) = verifier {
                    if let Err(e) = verify_subtree_signature(checkpoint_bytes.as_ref(), &der, v) {
                        tracing::warn!(url = %url, "cosignature rejected: {e}");
                        return None;
                    }
                }
                tracing::debug!(url = %url, bytes = der.len(), "cosignature accepted");
                Some((url, der))
            } else {
                tracing::warn!(
                    url = %url,
                    status = %status,
                    "cosigner returned non-2xx status"
                );
                None
            }
        }
        Err(e) => {
            tracing::warn!(url = %url, status = %status, "read cosigner response body: {e}");
            None
        }
    }
}
