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

use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Bytes;
use hyper::{Method, Request};
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use rustls::pki_types::CertificateDer;
use rustls::{ClientConfig, RootCertStore};
use synta::traits::Encode;
use synta::{Decoder, Encoder, Encoding, RelativeOid};
use synta_certificate::owned::Certificate;
use synta_certificate::{
    pem_to_der, AlgorithmIdentifier, DataHasher as _, OpensslSignatureVerifier,
    SignatureVerifier as _,
};
use synta_mtc::cosignature::{
    validate_cosignature_quorum_with_crypto, CosignaturePolicy,
    CosignerVerifier as MtcCosignerVerifier,
};
use synta_mtc::types::{Checkpoint, CosignerID, Subtree, SubtreeSignature};

use crate::config::CosignerConfig;
use crate::error::AcmeError;

const COSIGNER_TIMEOUT_SECS: u64 = 30;

/// Parameters for building a CA self-cosignature.
pub struct SelfCosignatureParams<'a> {
    pub signing_key: &'a synta_certificate::BackendPrivateKey,
    pub signing_hash_alg: &'a str,
    pub trust_anchor_id_der: &'a [u8],
    pub checkpoint_der: &'a [u8],
    pub subtree_start: u64,
    pub subtree_end: u64,
    pub subtree_root_bytes: &'a [u8],
    pub log_origin: &'a str,
}

/// Produce the CA's mandatory self-cosignature (§5.4).
///
/// Returns a DER-encoded `SubtreeSignature` in the same format as external
/// cosigners, so the downstream standalone-cert builder treats it uniformly.
///
/// `trust_anchor_id_der` is the DER-encoded `RelativeOid` of the CA's
/// own `TrustAnchorID`.  `checkpoint_der` is the DER-encoded `Checkpoint`
/// that was just produced and signed.
pub fn build_ca_self_cosignature(params: &SelfCosignatureParams<'_>) -> Result<Vec<u8>, AcmeError> {
    use synta::types::primitive::Integer;
    use synta::types::string::OctetString;
    use synta::{BitString, Encoding};
    use synta_certificate::{CertificateSigner as _, PrivateKey as _};

    let cosigner_oid: RelativeOid = Decoder::new(params.trust_anchor_id_der, Encoding::Der)
        .decode()
        .map_err(|e| AcmeError::Mtc(format!("decode CA trust_anchor_id ROID: {e}")))?;

    let checkpoint: Checkpoint<'_> = Decoder::new(params.checkpoint_der, Encoding::Der)
        .decode()
        .map_err(|e| AcmeError::Mtc(format!("decode Checkpoint for self-cosig: {e}")))?;

    let subtree = Subtree {
        start: Integer::from(params.subtree_start),
        end: Integer::from(params.subtree_end),
        value: OctetString::from(params.subtree_root_bytes.to_vec()),
    };

    let cosigned_msg = akamu_mtc_wire::build_cosigned_message(
        &cosigner_oid,
        &subtree,
        &checkpoint,
        params.log_origin,
    )
    .map_err(|e| AcmeError::Mtc(format!("build CosignedMessage for self-cosig: {e}")))?;

    let signer = params.signing_key.as_signer(params.signing_hash_alg);
    let sig_bytes = signer
        .sign_tbs(&cosigned_msg)
        .map_err(|e| AcmeError::Mtc(format!("sign CA self-cosignature: {e}")))?;

    let pub_key = params
        .signing_key
        .public_key()
        .map_err(|e| AcmeError::Mtc(format!("CA self-cosig public key: {e}")))?;
    let spki_der = pub_key.spki_der().to_vec();
    let spki: synta_certificate::SubjectPublicKeyInfo = Decoder::new(&spki_der, Encoding::Der)
        .decode()
        .map_err(|e| AcmeError::Mtc(format!("decode SPKI for self-cosig sig_alg: {e}")))?;
    let sig_alg_der = synta_certificate::signing_algorithm_der(
        &spki.algorithm.algorithm,
        params.signing_hash_alg,
    )
    .ok_or_else(|| AcmeError::Mtc("unsupported key/hash combination for CA self-cosig".into()))?;
    let sig_alg: AlgorithmIdentifier<'_> = Decoder::new(&sig_alg_der, Encoding::Der)
        .decode()
        .map_err(|e| AcmeError::Mtc(format!("decode self-cosig AlgorithmIdentifier: {e}")))?;

    let sig = BitString::new(sig_bytes, 0)
        .map_err(|e| AcmeError::Mtc(format!("BitString for self-cosig: {e}")))?;

    let subtree_sig = SubtreeSignature {
        cosigner: cosigner_oid,
        subtree,
        checkpoint,
        signature_algorithm: sig_alg,
        signature: sig,
    };

    subtree_sig
        .to_der()
        .map_err(|e| AcmeError::Mtc(format!("encode CA self-cosig SubtreeSignature: {e}")))
}

type HttpsClient = Client<hyper_rustls::HttpsConnector<HttpConnector>, Full<Bytes>>;

/// Pre-parsed verification material for a configured cosigner.
///
/// Loaded once at startup from `cosigner_id_cert_pem` and `trust_anchor_id`.
/// Allows verifying the `SubtreeSignature` returned by the cosigner without
/// re-reading the cert file on each checkpoint.
#[derive(Clone)]
struct AkamuCosignerVerifier {
    /// Expected `TrustAnchorID` OID components — for identity comparison.
    /// `None` when no `trust_anchor_id` is configured; OID check is skipped.
    expected_cosigner_oid: Option<Vec<u32>>,
    /// DER-encoded `SubjectPublicKeyInfo` of the cosigner's signing key.
    spki_der: Vec<u8>,
}

impl MtcCosignerVerifier for AkamuCosignerVerifier {
    fn verify_cosignature(
        &self,
        cosigner_id: &CosignerID,
        algorithm: &AlgorithmIdentifier<'_>,
        signed_data: &[u8],
        signature: &[u8],
    ) -> synta_mtc::Result<()> {
        use synta_mtc::Error;

        // Callers must not build a verifier with no checks configured.
        if self.expected_cosigner_oid.is_none() && self.spki_der.is_empty() {
            return Err(Error::invalid_input(
                "AkamuCosignerVerifier has no identity or key check configured",
            ));
        }

        // Identity check: TrustAnchorID OID must match when configured.
        if let Some(ref expected) = self.expected_cosigner_oid {
            if cosigner_id.components() != expected.as_slice() {
                return Err(Error::invalid_input(
                    "SubtreeSignature cosigner TrustAnchorID OID does not match expected",
                ));
            }
        }

        // Cryptographic verification against the cosigner cert's SPKI.
        let mut enc = Encoder::new(Encoding::Der);
        algorithm
            .encode(&mut enc)
            .map_err(|e| Error::invalid_input(format!("encode sig_alg: {e}")))?;
        let sig_alg_der = enc
            .finish()
            .map_err(|e| Error::invalid_input(format!("finish sig_alg DER: {e}")))?;

        OpensslSignatureVerifier
            .verify_certificate_signature(signed_data, &sig_alg_der, signature, &self.spki_der)
            .map_err(|e| {
                Error::invalid_input(format!(
                    "cosignature cryptographic verification failed: {e}"
                ))
            })?;

        Ok(())
    }
}

/// A cosigner URL paired with its pre-built HTTPS client.
///
/// Built once at server startup (see `build_cosigner_client`) and stored in
/// `MtcState`.  Re-using one `Client` per cosigner preserves the connection
/// pool across checkpoint intervals.
pub struct CosignerClient {
    pub(crate) url: String,
    client: HttpsClient,
    /// Verification material — `Some` when `cosigner_id_cert_pem` is configured.
    verifier: Option<AkamuCosignerVerifier>,
    /// Human-readable name for the discovery endpoint.
    pub(crate) friendly_name: Option<String>,
    /// Dotted-decimal TrustAnchorID OID of this cosigner.
    pub(crate) trust_anchor_id: Option<String>,
    /// Hex-encoded SHA-256 hash of the cosigner's SPKI DER.
    pub(crate) key_sha256: Option<String>,
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
        friendly_name: None,
        trust_anchor_id: None,
        key_sha256: None,
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

    let verifier = if cfg.cosigner_id_cert_pem.is_some() {
        // cert present (OID may or may not also be set — both cases are valid)
        Some(load_cosigner_verifier(
            cfg.cosigner_id_cert_pem.as_deref(),
            cfg.trust_anchor_id.as_deref(),
        )?)
    } else if cfg.trust_anchor_id.is_some() {
        // OID set but no cert: OID-only "verification" provides no cryptographic
        // assurance — anyone who knows the OID could forge a cosignature.
        return Err(AcmeError::Tls(format!(
            "cosigner '{}': trust_anchor_id is set but cosigner_id_cert_pem is absent; \
             OID-only verification provides no cryptographic assurance — \
             configure cosigner_id_cert_pem to enable signature verification",
            cfg.url
        )));
    } else {
        None
    };

    let key_sha256 = verifier
        .as_ref()
        .filter(|v| !v.spki_der.is_empty())
        .map(|v| {
            synta_certificate::default_data_hasher()
                .hash_data("sha256", &v.spki_der)
                .map(|hash| native_ossl::util::hex_encode(&hash))
        })
        .transpose()
        .map_err(|e| AcmeError::Tls(format!("hash cosigner SPKI: {e}")))?;

    Ok(CosignerClient {
        url: cfg.url.clone(),
        client,
        verifier,
        friendly_name: cfg.friendly_name.clone(),
        trust_anchor_id: cfg.trust_anchor_id.clone(),
        key_sha256,
    })
}

/// Build an `AkamuCosignerVerifier` from an optional PEM cert path and an
/// optional `TrustAnchorID` OID string.
///
/// At least one of the two arguments should be `Some`; callers should not
/// invoke this when both are `None` (the verifier would skip all checks).
fn load_cosigner_verifier(
    pem_path: Option<&str>,
    trust_anchor_id: Option<&str>,
) -> Result<AkamuCosignerVerifier, AcmeError> {
    // Parse the expected TrustAnchorID OID when configured.
    let expected_cosigner_oid = trust_anchor_id
        .map(|oid_str| {
            oid_str
                .parse::<RelativeOid>()
                .map(|oid| oid.components().to_vec())
                .map_err(|e| {
                    AcmeError::Tls(format!(
                        "parse cosigner trust_anchor_id ROID '{oid_str}': {e}"
                    ))
                })
        })
        .transpose()?;

    // Extract SPKI from cert PEM when configured, for cryptographic verification.
    let spki_der = pem_path
        .map(|path| {
            let pem = std::fs::read(path)
                .map_err(|e| AcmeError::Tls(format!("read cosigner ID cert '{path}': {e}")))?;
            let der = pem_to_der(&pem).into_iter().next().ok_or_else(|| {
                AcmeError::Tls(format!("cosigner ID cert '{path}': no PEM block"))
            })?;

            let cert: Certificate = Decoder::new(&der, Encoding::Der)
                .decode()
                .map_err(|e| AcmeError::Tls(format!("parse cosigner ID cert: {e}")))?;

            let mut enc = Encoder::new(Encoding::Der);
            cert.tbs_certificate
                .subject_public_key_info
                .encode(&mut enc)
                .map_err(|e| AcmeError::Tls(format!("encode cosigner SPKI: {e}")))?;
            enc.finish()
                .map_err(|e| AcmeError::Tls(format!("finish cosigner SPKI DER: {e}")))
        })
        .transpose()?
        .unwrap_or_default();

    Ok(AkamuCosignerVerifier {
        expected_cosigner_oid,
        spki_der,
    })
}

/// Verify a `SubtreeSignature` DER returned by a cosigner.
///
/// Uses `validate_cosignature_quorum_with_crypto` which builds the TLS-encoded
/// `CosignedMessage` (spec §5.4.1) internally and delegates cryptographic
/// verification to `AkamuCosignerVerifier::verify_cosignature`.
fn verify_subtree_signature(
    response_der: &[u8],
    v: &AkamuCosignerVerifier,
    log_origin: &str,
) -> Result<(), String> {
    let sig = SubtreeSignature::from_der(response_der)
        .map_err(|e| format!("parse SubtreeSignature: {e}"))?;

    let mut policy = CosignaturePolicy::default();
    policy.min_cosignatures = 1;
    policy.max_cosignatures = 1;
    policy.allow_duplicate_cosigners = false;

    validate_cosignature_quorum_with_crypto(&[sig], &policy, v, log_origin)
        .map_err(|e| format!("cosignature verification failed: {e}"))
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
    log_origin: &str,
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
            let origin = log_origin.to_string();
            tokio::spawn(async move { post_to_cosigner(url, client, body, verifier, origin).await })
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
    verifier: Option<AkamuCosignerVerifier>,
    log_origin: String,
) -> Option<(String, Vec<u8>)> {
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

    // Limit response body to 16 KiB to prevent memory exhaustion from a misbehaving cosigner.
    const MAX_RESPONSE_BYTES: usize = 16 * 1024;
    let body_bytes = match Limited::new(resp.into_body(), MAX_RESPONSE_BYTES)
        .collect()
        .await
    {
        Ok(collected) => collected.to_bytes(),
        Err(e) => {
            tracing::warn!(url = %url, status = %status, "read cosigner response body: {e}");
            return None;
        }
    };

    if !status.is_success() {
        // Log the first 256 bytes of the error body for diagnostics.
        let snippet = &body_bytes[..body_bytes.len().min(256)];
        tracing::warn!(
            url = %url,
            status = %status,
            body = %String::from_utf8_lossy(snippet),
            "cosigner returned non-2xx status"
        );
        return None;
    }

    let der = body_bytes.to_vec();
    if der.is_empty() {
        tracing::warn!(url = %url, "cosigner returned empty body");
        return None;
    }

    if let Some(ref v) = verifier {
        if let Err(e) = verify_subtree_signature(&der, v, &log_origin) {
            tracing::warn!(url = %url, "cosignature rejected: {e}");
            return None;
        }
    } else {
        tracing::warn!(
            url = %url,
            "cosignature accepted WITHOUT identity or cryptographic verification; \
             configure cosigner_id_cert_pem and/or trust_anchor_id to enable verification"
        );
    }

    tracing::debug!(url = %url, bytes = der.len(), "cosignature accepted");
    Some((url, der))
}
