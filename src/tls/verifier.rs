//! rustls `ClientCertVerifier` backed by `synta-x509-verification` policy,
//! wired into the `rustls-native-ossl` chain-verifier framework.
//!
//! `SyntaChainVerifier` implements the pluggable `CertChainVerifier` trait from
//! `rustls-native-ossl`, translating from native-ossl `X509` types back to the
//! synta `VerificationCertificate` / `OwnedStore` API so full policy (chain depth,
//! RSA modulus, profile, PQ algorithm set) is enforced.
//!
//! `SyntaClientCertVerifier` wraps an `OsslClientCertVerifier` (which carries the
//! synta chain verifier) and adds:
//!   - configurable `client_auth_mandatory` (`required` field)
//!   - composite ML-DSA+classical TLS 1.3 `CertificateVerify` routing
//!   - `allow_post_quantum` scheme advertising

use std::sync::Arc;

use native_ossl::x509::X509;
use rustls::client::danger::HandshakeSignatureValid;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{DigitallySignedStruct, DistinguishedName, Error as TlsError, SignatureScheme};
use rustls_native_ossl::cert_verifier::{CertChainVerifier, OsslClientCertVerifier};
use synta::{Decoder, Encoding};
use synta_certificate::{Certificate, OpensslSignatureVerifier};
use synta_x509_verification::{
    ops::VerificationCertificate,
    policy::{PolicyDefinition, ValidationProfile},
    OwnedStore, RevocationChecks, WEBPKI_PERMITTED_SIGNATURE_ALGORITHMS,
    WEBPKI_PERMITTED_SIGNATURE_ALGORITHMS_WITH_PQ, WEBPKI_PERMITTED_SPKI_ALGORITHMS,
    WEBPKI_PERMITTED_SPKI_ALGORITHMS_WITH_PQ,
};

use crate::config::ClientAuthConfig;

// ── SyntaChainVerifier ─────────────────────────────────────────────────────────

/// `CertChainVerifier` implementation backed by `synta-x509-verification`.
///
/// Converts native-ossl `X509` certificates (as supplied by the rustls-native-ossl
/// framework) back to DER and then uses `OwnedStore::verify` with a full
/// `PolicyDefinition` (profile, chain depth, RSA modulus, PQ algorithm set).
struct SyntaChainVerifier {
    owned_store: Arc<OwnedStore>,
    ca_ders: Arc<Vec<Vec<u8>>>,
    profile: ValidationProfile,
    max_chain_depth: u8,
    minimum_rsa_modulus: usize,
    allow_post_quantum: bool,
}

impl std::fmt::Debug for SyntaChainVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SyntaChainVerifier")
            .field("allow_post_quantum", &self.allow_post_quantum)
            .finish_non_exhaustive()
    }
}

impl CertChainVerifier for SyntaChainVerifier {
    fn verify_chain(
        &self,
        end_entity: &X509,
        intermediates: &[X509],
        _server_name: Option<&ServerName<'_>>,
        now: UnixTime,
    ) -> Result<(), TlsError> {
        // Convert native-ossl X509 values back to DER (zero copies avoided;
        // OpenSSL DER encoding is cheap compared to chain validation).
        let leaf_der = end_entity
            .to_der()
            .map_err(|e| TlsError::General(format!("leaf cert DER encode: {e}")))?;
        let inter_ders: Vec<Vec<u8>> = intermediates
            .iter()
            .enumerate()
            .map(|(i, c)| {
                c.to_der()
                    .map_err(|e| TlsError::General(format!("intermediate {i} DER encode: {e}")))
            })
            .collect::<Result<_, _>>()?;

        // Parse leaf cert with synta.
        let leaf_cert: Certificate = Decoder::new(&leaf_der, Encoding::Der)
            .decode()
            .map_err(|e| TlsError::General(format!("leaf cert synta parse: {e}")))?;
        let leaf_vc = VerificationCertificate::new(leaf_cert, &leaf_der);

        // Parse intermediates with synta.
        let inter_vcs: Vec<VerificationCertificate<'_>> = inter_ders
            .iter()
            .map(|der| {
                let cert: Certificate = Decoder::new(der, Encoding::Der).decode().map_err(|e| {
                    TlsError::General(format!("intermediate cert synta parse: {e}"))
                })?;
                Ok(VerificationCertificate::new(cert, der.as_slice()))
            })
            .collect::<Result<_, TlsError>>()?;

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

        let validation_time = now.as_secs() as i64;
        let mut policy = PolicyDefinition::new_client(OpensslSignatureVerifier, validation_time);
        policy.profile = self.profile;
        policy.max_chain_depth = self.max_chain_depth;
        policy.minimum_rsa_modulus = self.minimum_rsa_modulus;
        policy.permitted_spki_algorithms = spki_algs;
        policy.permitted_signature_algorithms = sig_algs;

        let result = self
            .owned_store
            .verify(&leaf_vc, &inter_vcs, &policy, RevocationChecks::default())
            .map(|_| ());
        match result {
            Ok(()) => Ok(()),
            Err(e) => {
                let msg = e.to_string();
                if akamu_client::tls_verify::is_mtc_extension_error(&msg) {
                    akamu_client::tls_verify::validate_mtc_ca_extensions(
                        std::iter::once(leaf_der.as_slice())
                            .chain(inter_ders.iter().map(|d| d.as_slice()))
                            .chain(self.ca_ders.iter().map(|d| d.as_slice())),
                    )
                    .map_err(|mtc_err| {
                        TlsError::General(format!("client cert verification failed: {mtc_err}"))
                    })
                } else {
                    Err(TlsError::General(format!(
                        "client cert verification failed: {e}"
                    )))
                }
            }
        }
    }
}

// ── SyntaClientCertVerifier ────────────────────────────────────────────────────

/// rustls `ClientCertVerifier` that delegates chain validation to
/// `synta-x509-verification` via the `OsslClientCertVerifier` framework.
///
/// Chain policy (profile, depth, RSA modulus, PQ algorithms) is enforced by
/// `SyntaChainVerifier`.  Composite ML-DSA+classical TLS 1.3 `CertificateVerify`
/// signatures are handled inline via native-ossl EVP DigestVerify.
pub struct SyntaClientCertVerifier {
    /// Inner verifier from rustls-native-ossl, carries the SyntaChainVerifier.
    inner: OsslClientCertVerifier,
    required: bool,
    allow_post_quantum: bool,
    /// Crypto provider — built once at construction, shared across all handshakes.
    provider: Arc<rustls::crypto::CryptoProvider>,
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

        let synta_verifier = Arc::new(SyntaChainVerifier {
            owned_store: Arc::new(owned_store),
            ca_ders: Arc::new(ca_ders.to_vec()),
            profile,
            max_chain_depth: config.max_chain_depth,
            minimum_rsa_modulus: config.minimum_rsa_modulus,
            allow_post_quantum: config.allow_post_quantum,
        });

        let inner = OsslClientCertVerifier::builder_with_verifier(synta_verifier)
            .with_root_hint_subjects(root_hints)
            .build();

        Ok(Self {
            inner,
            required: config.required,
            allow_post_quantum: config.allow_post_quantum,
            provider: Arc::new(rustls_native_ossl::default_provider()),
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
        self.inner.root_hint_subjects()
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<ClientCertVerified, TlsError> {
        self.inner
            .verify_client_cert(end_entity, intermediates, now)
    }

    /// TLS 1.2 `CertificateVerify` — all schemes delegated to rustls-native-ossl.
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
            &self.provider.signature_verification_algorithms,
        )
    }

    /// TLS 1.3 `CertificateVerify`.
    ///
    /// Classical schemes delegate to rustls-native-ossl.
    /// Composite ML-DSA+classical schemes route through native-ossl EVP DigestVerify.
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
                &self.provider.signature_verification_algorithms,
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
/// then calls the native-ossl EVP DigestVerify interface which handles both
/// the classical and ML-DSA components with "and" semantics.
fn verify_composite_tls13_signature(
    message: &[u8],
    cert: &CertificateDer<'_>,
    dss: &DigitallySignedStruct,
) -> Result<HandshakeSignatureValid, TlsError> {
    let cert_der: &[u8] = cert.as_ref();
    let ranges = synta_certificate::cert_byte_ranges(cert_der)
        .ok_or_else(|| TlsError::General("composite verify: extract SPKI range".into()))?;
    let spki_der = &cert_der[ranges.subject_public_key_info];

    verify_composite_via_openssl(dss.scheme, message, spki_der, dss.signature())
        .map(|_| HandshakeSignatureValid::assertion())
        .map_err(|e| TlsError::General(format!("composite signature verification failed: {e}")))
}

/// Verify a composite ML-DSA+classical signature using native-ossl EVP DigestVerify.
fn verify_composite_via_openssl(
    scheme: SignatureScheme,
    message: &[u8],
    spki_der: &[u8],
    sig_bytes: &[u8],
) -> Result<(), String> {
    use native_ossl::pkey::{Pkey, Public, SignInit, Verifier};

    let pkey = Pkey::<Public>::from_der(spki_der)
        .map_err(|e| format!("load composite public key: {e}"))?;
    let digest = composite_digest(scheme)?;
    let mut verifier = Verifier::new(
        &pkey,
        &SignInit {
            digest: Some(&digest),
            params: None,
        },
    )
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
fn composite_digest(scheme: SignatureScheme) -> Result<native_ossl::digest::DigestAlg, String> {
    use crate::tls::schemes::*;
    let name = match scheme {
        SignatureScheme::Unknown(MLDSA44_ECDSA_P256_SHA256) => c"SHA2-256",
        SignatureScheme::Unknown(MLDSA44_RSA2048_PKCS15_SHA256) => c"SHA2-256",
        SignatureScheme::Unknown(MLDSA44_RSA2048_PSS_SHA256) => c"SHA2-256",
        SignatureScheme::Unknown(MLDSA44_ED25519_SHA512) => c"SHA2-512",
        SignatureScheme::Unknown(MLDSA65_ECDSA_P256_SHA512) => c"SHA2-512",
        SignatureScheme::Unknown(MLDSA65_ECDSA_P384_SHA512) => c"SHA2-512",
        SignatureScheme::Unknown(MLDSA65_RSA3072_PKCS15_SHA512) => c"SHA2-512",
        SignatureScheme::Unknown(MLDSA65_RSA3072_PSS_SHA512) => c"SHA2-512",
        SignatureScheme::Unknown(MLDSA65_ED25519_SHA512) => c"SHA2-512",
        SignatureScheme::Unknown(MLDSA87_ECDSA_P384_SHA512) => c"SHA2-512",
        SignatureScheme::Unknown(MLDSA87_ED448_SHAKE256) => c"SHAKE256",
        other => return Err(format!("unknown composite scheme {other:?}")),
    };
    native_ossl::digest::DigestAlg::fetch(name, None)
        .map_err(|e| format!("fetch digest for composite scheme: {e}"))
}
