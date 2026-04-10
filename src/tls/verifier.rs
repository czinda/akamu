//! rustls `ClientCertVerifier` backed by `synta-x509-verification`.
//!
//! Trust anchors are pre-parsed once at startup via `OwnedStore::try_new` and
//! re-used across all connections — no DER re-parsing per handshake.
//!
//! Composite ML-DSA+classical TLS 1.3 `CertificateVerify` signatures are routed
//! through the OpenSSL EVP interface (pqc-prs fork).  Classical schemes delegate
//! to the ring crypto provider.

use std::sync::Arc;

use rustls::client::danger::HandshakeSignatureValid;
use rustls::pki_types::{CertificateDer, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{DigitallySignedStruct, DistinguishedName, Error as TlsError, SignatureScheme};
use synta::{Decoder, Encoding};
use synta_certificate::{Certificate, OpensslSignatureVerifier};
use synta_x509_verification::{
    ops::VerificationCertificate,
    policy::{PolicyDefinition, ValidationProfile},
    OwnedStore, RevocationChecks,
    WEBPKI_PERMITTED_SIGNATURE_ALGORITHMS, WEBPKI_PERMITTED_SIGNATURE_ALGORITHMS_WITH_PQ,
    WEBPKI_PERMITTED_SPKI_ALGORITHMS, WEBPKI_PERMITTED_SPKI_ALGORITHMS_WITH_PQ,
};

use crate::config::ClientAuthConfig;

/// rustls `ClientCertVerifier` that delegates chain validation to
/// `synta-x509-verification` with a configurable profile, depth, and algorithm
/// policy.  Optionally accepts composite ML-DSA+classical hybrid schemes.
pub struct SyntaClientCertVerifier {
    /// Pre-parsed trust anchors — owned, `Send + Sync`, shared across connections.
    owned_store: Arc<OwnedStore>,
    /// DN hints pre-computed once at startup (returned cheaply on every handshake).
    root_hints: Vec<DistinguishedName>,
    required: bool,
    profile: ValidationProfile,
    max_chain_depth: u8,
    minimum_rsa_modulus: usize,
    allow_post_quantum: bool,
}

impl std::fmt::Debug for SyntaClientCertVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SyntaClientCertVerifier")
            .field("required", &self.required)
            .field("allow_post_quantum", &self.allow_post_quantum)
            .finish()
    }
}

impl SyntaClientCertVerifier {
    /// Build the verifier, parsing CA DER bytes once via `OwnedStore::try_new`.
    ///
    /// Returns `Err` if any CA certificate is malformed.
    pub fn new(ca_ders: &[Vec<u8>], config: &ClientAuthConfig) -> Result<Self, String> {
        let profile = match config.profile.as_str() {
            "rfc5280" => ValidationProfile::Rfc5280,
            _ => ValidationProfile::WebPki,
        };

        // Pre-compute DN hints once (parse subject from raw DER).
        let root_hints: Vec<DistinguishedName> = ca_ders
            .iter()
            .filter_map(|der| {
                let cert: Certificate = Decoder::new(der, Encoding::Der).decode().ok()?;
                Some(DistinguishedName::from(
                    cert.tbs_certificate.subject.0.to_vec(),
                ))
            })
            .collect();

        // Parse and own trust anchors for the process lifetime.
        let owned_store = OwnedStore::try_new(ca_ders.iter().map(|d| d.as_slice()))
            .map_err(|e| format!("build client-auth trust store: {e}"))?;

        Ok(Self {
            owned_store: Arc::new(owned_store),
            root_hints,
            required: config.required,
            profile,
            max_chain_depth: config.max_chain_depth,
            minimum_rsa_modulus: config.minimum_rsa_modulus,
            allow_post_quantum: config.allow_post_quantum,
        })
    }
}

impl ClientCertVerifier for SyntaClientCertVerifier {
    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> bool {
        self.required
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &self.root_hints
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<ClientCertVerified, TlsError> {
        // Clone DER into owned buffers: CertificateDer borrows are short-lived.
        let leaf_der: Vec<u8> = end_entity.as_ref().to_vec();
        let inter_ders: Vec<Vec<u8>> =
            intermediates.iter().map(|c| c.as_ref().to_vec()).collect();
        let validation_time = now.as_secs() as i64;

        // Parse leaf (borrows from leaf_der on the stack).
        let leaf_cert: Certificate = Decoder::new(&leaf_der, Encoding::Der)
            .decode()
            .map_err(|e| TlsError::General(format!("leaf cert parse: {e}")))?;
        let leaf_vc = VerificationCertificate::new(leaf_cert, &leaf_der);

        // Parse intermediates (each borrows from its own owned DER).
        let inter_vcs: Vec<VerificationCertificate<'_>> = inter_ders
            .iter()
            .map(|der| {
                let cert: Certificate = Decoder::new(der, Encoding::Der)
                    .decode()
                    .map_err(|e| TlsError::General(format!("intermediate cert parse: {e}")))?;
                Ok(VerificationCertificate::new(cert, der.as_slice()))
            })
            .collect::<Result<_, TlsError>>()?;

        // Build validation policy.
        let (spki_algs, sig_algs) = if self.allow_post_quantum {
            (
                WEBPKI_PERMITTED_SPKI_ALGORITHMS_WITH_PQ,
                WEBPKI_PERMITTED_SIGNATURE_ALGORITHMS_WITH_PQ,
            )
        } else {
            (
                WEBPKI_PERMITTED_SPKI_ALGORITHMS,
                WEBPKI_PERMITTED_SIGNATURE_ALGORITHMS,
            )
        };
        let mut policy =
            PolicyDefinition::new_client(OpensslSignatureVerifier, validation_time);
        policy.profile = self.profile;
        policy.max_chain_depth = self.max_chain_depth;
        policy.minimum_rsa_modulus = self.minimum_rsa_modulus;
        policy.permitted_spki_algorithms = spki_algs;
        policy.permitted_signature_algorithms = sig_algs;

        // Trust anchors are already parsed — no re-parsing per connection.
        self.owned_store
            .verify(&leaf_vc, &inter_vcs, &policy, RevocationChecks::default())
            .map(|_| ClientCertVerified::assertion())
            .map_err(|e| TlsError::General(format!("client cert verification failed: {e}")))
    }

    /// TLS 1.2 `CertificateVerify` — all schemes delegated to ring.
    /// Composite ML-DSA schemes are TLS 1.3 only and never appear here.
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    /// TLS 1.3 `CertificateVerify`.
    ///
    /// Classical schemes delegate to ring.
    /// Composite ML-DSA+classical schemes route through OpenSSL (pqc-prs fork).
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        if crate::tls::schemes::is_composite(dss.scheme) {
            verify_composite_tls13_signature(message, cert, dss)
        } else {
            rustls::crypto::verify_tls13_signature(
                message,
                cert,
                dss,
                &rustls::crypto::ring::default_provider().signature_verification_algorithms,
            )
        }
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        let mut schemes = vec![
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ED25519,
        ];
        if self.allow_post_quantum {
            // Advertise hybrid composite schemes so clients with composite keys
            // can produce a CertificateVerify the server can verify.
            schemes.extend_from_slice(crate::tls::schemes::COMPOSITE_SCHEMES);
        }
        schemes
    }
}

// ── Composite ML-DSA+classical TLS 1.3 signature verification ─────────────────

/// Verify a composite ML-DSA+classical `CertificateVerify` signature.
///
/// Extracts the composite public key from the leaf certificate DER using synta,
/// then calls the OpenSSL EVP interface (pqc-prs fork) which handles both
/// the classical and ML-DSA components with "and" semantics.
fn verify_composite_tls13_signature(
    message: &[u8],
    cert: &CertificateDer<'_>,
    dss: &DigitallySignedStruct,
) -> Result<HandshakeSignatureValid, TlsError> {
    // Extract the composite SubjectPublicKeyInfo DER from the raw cert bytes
    // without re-parsing the certificate — cert_byte_ranges gives the exact
    // SPKI TLV byte range within the original DER.
    let cert_der: &[u8] = cert.as_ref();
    let ranges = synta_certificate::cert_byte_ranges(cert_der)
        .ok_or_else(|| TlsError::General("composite verify: extract SPKI range".into()))?;
    let spki_der = &cert_der[ranges.subject_public_key_info];

    verify_composite_via_openssl(dss.scheme, message, spki_der, dss.signature())
        .map(|_| HandshakeSignatureValid::assertion())
        .map_err(|e| TlsError::General(format!("composite signature verification failed: {e}")))
}

/// Verify a composite ML-DSA+classical signature using the OpenSSL EVP interface.
///
/// `PKey::public_key_from_der(spki_der)` loads the composite key via the
/// pqc-prs fork's d2i_PUBKEY path. `Verifier::verify` validates both components
/// in one call — OpenSSL handles the "and" semantics internally.
///
/// If the pqc-prs fork does not yet expose composite NIDs via the Rust binding,
/// this will return an error at runtime; the fix is to extend the Rust openssl
/// bindings in the pqc-prs fork, not this crate.
fn verify_composite_via_openssl(
    scheme: SignatureScheme,
    message: &[u8],
    spki_der: &[u8],
    sig_bytes: &[u8],
) -> Result<(), String> {
    use openssl::pkey::PKey;
    use openssl::sign::Verifier as OpenSslVerifier;

    let pkey = PKey::public_key_from_der(spki_der)
        .map_err(|e| format!("load composite public key: {e}"))?;

    let digest = composite_digest(scheme)?;

    let mut verifier = OpenSslVerifier::new(digest, &pkey)
        .map_err(|e| format!("create composite verifier: {e}"))?;
    verifier
        .update(message)
        .map_err(|e| format!("verifier update: {e}"))?;
    verifier
        .verify(sig_bytes)
        .map_err(|e| format!("composite verify: {e}"))?
        .then_some(())
        .ok_or_else(|| "composite signature invalid".to_string())
}

/// Select the message digest for a composite ML-DSA TLS scheme.
fn composite_digest(scheme: SignatureScheme) -> Result<openssl::hash::MessageDigest, String> {
    use openssl::hash::MessageDigest;
    use crate::tls::schemes::*;
    match scheme {
        SignatureScheme::Unknown(MLDSA44_ECDSA_P256_SHA256)     => Ok(MessageDigest::sha256()),
        SignatureScheme::Unknown(MLDSA44_RSA2048_PKCS15_SHA256) => Ok(MessageDigest::sha256()),
        SignatureScheme::Unknown(MLDSA44_RSA2048_PSS_SHA256)    => Ok(MessageDigest::sha256()),
        SignatureScheme::Unknown(MLDSA44_ED25519_SHA512)        => Ok(MessageDigest::sha512()),
        SignatureScheme::Unknown(MLDSA65_ECDSA_P256_SHA512)     => Ok(MessageDigest::sha512()),
        SignatureScheme::Unknown(MLDSA65_ECDSA_P384_SHA512)     => Ok(MessageDigest::sha512()),
        SignatureScheme::Unknown(MLDSA65_RSA3072_PKCS15_SHA384) => Ok(MessageDigest::sha384()),
        SignatureScheme::Unknown(MLDSA65_RSA3072_PSS_SHA384)    => Ok(MessageDigest::sha384()),
        SignatureScheme::Unknown(MLDSA65_ED25519_SHA512)        => Ok(MessageDigest::sha512()),
        SignatureScheme::Unknown(MLDSA87_ECDSA_P384_SHA512)     => Ok(MessageDigest::sha512()),
        SignatureScheme::Unknown(MLDSA87_ECDSA_P521_SHA512)     => Ok(MessageDigest::sha512()),
        SignatureScheme::Unknown(MLDSA87_ED448_SHA512)          => Ok(MessageDigest::sha512()),
        other => Err(format!("unknown composite scheme {other:?}")),
    }
}
