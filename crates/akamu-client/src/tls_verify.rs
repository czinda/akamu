//! MTC-aware TLS certificate chain verifier.
//!
//! Wraps OpenSSL's `X509_verify_cert` like `OsslChainVerifier` but handles
//! the critical `id-pe-mtcCertificationAuthority` extension (OID
//! `1.3.6.1.4.1.44363.47.2`) that OpenSSL does not recognise.  After standard
//! chain verification passes (with `X509_V_FLAG_IGNORE_CRITICAL`), every
//! unknown critical extension in the verified chain is validated through
//! `synta_mtc::builder::ca_extension::parse_mtc_ca_extension`.

use std::sync::Arc;

use native_ossl::x509::{X509Store, X509StoreCtx, X509};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{CertificateError, Error};
use rustls_native_ossl::cert_verifier::CertChainVerifier;

/// OpenSSL verification flag: skip rejection of unknown critical extensions.
///
/// Value from `<openssl/x509_vfy.h>`: `X509_V_FLAG_IGNORE_CRITICAL 0x10`.
const X509_V_FLAG_IGNORE_CRITICAL: u64 = 0x10;

/// Certificate chain verifier that understands MTC CA extensions.
///
/// Use in place of `OsslChainVerifier` when connecting to an ACME server
/// whose CA certificate carries the critical `id-pe-mtcCertificationAuthority`
/// extension.
pub struct MtcAwareChainVerifier {
    store: Arc<X509Store>,
}

impl std::fmt::Debug for MtcAwareChainVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MtcAwareChainVerifier")
            .finish_non_exhaustive()
    }
}

impl Clone for MtcAwareChainVerifier {
    fn clone(&self) -> Self {
        MtcAwareChainVerifier {
            store: Arc::clone(&self.store),
        }
    }
}

impl MtcAwareChainVerifier {
    /// Build a verifier that trusts the given DER-encoded CA certificates.
    ///
    /// Sets `X509_V_FLAG_IGNORE_CRITICAL` on the trust store so that OpenSSL
    /// does not reject certificates with the MTC CA extension.  Unknown
    /// critical extensions are validated after chain verification succeeds.
    ///
    /// # Errors
    ///
    /// Returns an error if any certificate cannot be parsed or added to the
    /// OpenSSL trust store, or if the flag cannot be set.
    pub fn new(ca_certs: &[CertificateDer<'_>]) -> Result<Self, Error> {
        let mut store =
            X509Store::new().map_err(|e| Error::General(format!("trust store init: {e}")))?;
        for der in ca_certs {
            let cert = X509::from_der(der.as_ref())
                .map_err(|e| Error::General(format!("parse CA cert: {e}")))?;
            store
                .add_cert(&cert)
                .map_err(|e| Error::General(format!("add CA cert: {e}")))?;
        }
        store
            .set_flags(X509_V_FLAG_IGNORE_CRITICAL)
            .map_err(|e| Error::General(format!("set IGNORE_CRITICAL: {e}")))?;
        Ok(MtcAwareChainVerifier {
            store: Arc::new(store),
        })
    }
}

impl CertChainVerifier for MtcAwareChainVerifier {
    fn verify_chain(
        &self,
        end_entity: &X509,
        intermediates: &[X509],
        server_name: Option<&ServerName<'_>>,
        now: UnixTime,
    ) -> Result<(), Error> {
        let mut ctx = X509StoreCtx::new().map_err(|e| Error::General(format!("ctx alloc: {e}")))?;
        ctx.init_with_chain(&self.store, end_entity, intermediates)
            .map_err(|e| Error::General(format!("ctx init: {e}")))?;
        ctx.set_time(now.as_secs())
            .map_err(|e| Error::General(format!("set time: {e}")))?;

        match server_name {
            Some(ServerName::DnsName(name)) => {
                ctx.set_host(name.as_ref())
                    .map_err(|e| Error::General(format!("set host: {e}")))?;
            }
            Some(ServerName::IpAddress(ip)) => {
                let ip_str = std::net::IpAddr::from(*ip).to_string();
                ctx.set_ip(&ip_str)
                    .map_err(|e| Error::General(format!("set ip: {e}")))?;
            }
            None => {}
            Some(_) => {
                return Err(Error::UnsupportedNameType);
            }
        }

        match ctx.verify() {
            Ok(true) => {}
            Ok(false) => return Err(ossl_verify_error_to_rustls(ctx.error())),
            Err(e) => return Err(Error::General(format!("verify: {e}"))),
        }

        // Chain verification passed.  Now check that every unknown critical
        // extension in the verified chain is a valid MTC CA extension.
        for cert in ctx.chain() {
            let has_unknown_critical = (0..cert.extension_count()).any(|i| {
                cert.extension(i)
                    .is_some_and(|ext| ext.is_critical() && ext.nid() == 0)
            });
            if !has_unknown_critical {
                continue;
            }

            let der = cert
                .to_der()
                .map_err(|e| Error::General(format!("cert to_der: {e}")))?;

            match synta_mtc::builder::ca_extension::parse_mtc_ca_extension(&der) {
                Ok(Some(_)) => {
                    tracing::debug!("MTC CA extension validated on certificate in chain");
                }
                Ok(None) => {
                    return Err(Error::InvalidCertificate(CertificateError::Other(
                        rustls::OtherError(Arc::new(UnhandledCriticalExtension)),
                    )));
                }
                Err(e) => {
                    tracing::warn!("MTC CA extension parse failed: {e}");
                    return Err(Error::InvalidCertificate(CertificateError::Other(
                        rustls::OtherError(Arc::new(MalformedMtcExtension(e.to_string()))),
                    )));
                }
            }
        }

        Ok(())
    }
}

/// Map an OpenSSL `X509_V_ERR_*` error code to the closest rustls error.
fn ossl_verify_error_to_rustls(err_code: i32) -> Error {
    const X509_V_ERR_CERT_HAS_EXPIRED: i32 = 10;
    const X509_V_ERR_CERT_NOT_YET_VALID: i32 = 9;
    const X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT: i32 = 2;
    const X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY: i32 = 20;
    const X509_V_ERR_CERT_SIGNATURE_FAILURE: i32 = 7;
    const X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT: i32 = 18;
    const X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN: i32 = 19;
    const X509_V_ERR_CERT_REVOKED: i32 = 23;
    const X509_V_ERR_INVALID_CA: i32 = 24;
    const X509_V_ERR_CERT_UNTRUSTED: i32 = 27;
    const X509_V_ERR_HOSTNAME_MISMATCH: i32 = 62;
    const X509_V_ERR_IP_ADDRESS_MISMATCH: i32 = 64;

    if err_code == 0 {
        return Error::General(
            "X509_verify_cert returned false with no error code (X509_V_OK)".to_owned(),
        );
    }

    Error::InvalidCertificate(match err_code {
        X509_V_ERR_CERT_HAS_EXPIRED => CertificateError::Expired,
        X509_V_ERR_CERT_NOT_YET_VALID => CertificateError::NotValidYet,
        X509_V_ERR_CERT_SIGNATURE_FAILURE => CertificateError::BadSignature,
        X509_V_ERR_CERT_REVOKED => CertificateError::Revoked,
        X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT
        | X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY
        | X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT
        | X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN
        | X509_V_ERR_INVALID_CA
        | X509_V_ERR_CERT_UNTRUSTED => CertificateError::UnknownIssuer,
        X509_V_ERR_HOSTNAME_MISMATCH | X509_V_ERR_IP_ADDRESS_MISMATCH => {
            CertificateError::NotValidForName
        }
        _ => CertificateError::Other(rustls::OtherError(Arc::new(OsslVerifyError(err_code)))),
    })
}

#[derive(Debug)]
struct OsslVerifyError(i32);

impl std::fmt::Display for OsslVerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "OpenSSL X509_verify_cert error {}", self.0)
    }
}

impl std::error::Error for OsslVerifyError {}

#[derive(Debug)]
struct UnhandledCriticalExtension;

impl std::fmt::Display for UnhandledCriticalExtension {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("certificate contains an unhandled critical extension")
    }
}

impl std::error::Error for UnhandledCriticalExtension {}

#[derive(Debug)]
struct MalformedMtcExtension(String);

impl std::fmt::Display for MalformedMtcExtension {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "malformed MTC CA extension: {}", self.0)
    }
}

impl std::error::Error for MalformedMtcExtension {}

/// Check whether an OpenSSL verification error message indicates rejection
/// due to the critical MTC CA extension (OID `1.3.6.1.4.1.44363.47.2`).
pub fn is_mtc_extension_error(msg: &str) -> bool {
    msg.contains("unrecognised critical extension") && msg.contains("1.3.6.1.4.1.44363.47.2")
}

/// Validate MTC CA extensions on certificates in the chain.
///
/// Returns `Ok(())` if every certificate either has no MTC CA extension or has
/// a well-formed `MTCCertificationAuthority` ASN.1 structure.
///
/// This is the shared validation logic used by both the client-side
/// `MtcAwareChainVerifier` and the server-side `SyntaChainVerifier`.
pub fn validate_mtc_ca_extensions<'a>(
    cert_ders: impl Iterator<Item = &'a [u8]>,
) -> Result<(), String> {
    for der in cert_ders {
        match synta_mtc::builder::ca_extension::parse_mtc_ca_extension(der) {
            Ok(Some(_)) => {
                tracing::debug!("MTC CA extension validated on certificate in chain");
            }
            Ok(None) => {}
            Err(e) => {
                return Err(format!("malformed MTC CA extension: {e}"));
            }
        }
    }
    Ok(())
}
