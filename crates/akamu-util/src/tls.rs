//! PEM loading helpers for TLS servers.
//!
//! Uses the same `synta_certificate` primitives already present in the akamu
//! ecosystem.

use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use synta_certificate::{pem_to_der, BackendPrivateKey};

/// Load a PEM certificate chain → `Vec<CertificateDer<'static>>`.
///
/// Each PEM block is one DER certificate; the slice is ordered leaf-first.
pub fn load_server_cert_chain(path: &str) -> Result<Vec<CertificateDer<'static>>, String> {
    let pem = std::fs::read(path).map_err(|e| format!("read TLS cert '{path}': {e}"))?;
    let ders = pem_to_der(&pem);
    if ders.is_empty() {
        return Err(format!("TLS cert file '{path}' contains no PEM blocks"));
    }
    Ok(ders.into_iter().map(CertificateDer::from).collect())
}

/// Load a PEM private key → `PrivateKeyDer<'static>` (PKCS#8 form).
///
/// Accepts unencrypted PKCS#8 or SEC1 (EC) PEM; converts to PKCS#8 DER for rustls.
pub fn load_server_private_key(path: &str) -> Result<PrivateKeyDer<'static>, String> {
    let pem = std::fs::read(path).map_err(|e| format!("read TLS key '{path}': {e}"))?;
    let key = BackendPrivateKey::from_pem(&pem, None)
        .map_err(|e| format!("parse TLS key '{path}': {e}"))?;
    let der = key
        .to_der()
        .map_err(|e| format!("serialize TLS key '{path}': {e}"))?;
    Ok(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(der)))
}
