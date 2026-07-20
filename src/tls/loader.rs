//! PEM loading helpers for the TLS server.
//!
//! Uses the same `synta_certificate` primitives already present in `ca/init.rs`.

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

/// Load CA PEM files → flat `Vec` of DER blobs for the client-auth trust store.
pub fn load_ca_certs(ca_files: &[String]) -> Result<Vec<Vec<u8>>, String> {
    let mut all: Vec<Vec<u8>> = Vec::new();
    for path in ca_files {
        let pem = std::fs::read(path).map_err(|e| format!("read client-auth CA '{path}': {e}"))?;
        let ders = pem_to_der(&pem);
        if ders.is_empty() {
            return Err(format!(
                "client-auth CA file '{path}' contains no PEM blocks"
            ));
        }
        all.extend(ders);
    }
    Ok(all)
}
