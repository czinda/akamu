//! TLS server certificate bootstrap.
//!
//! If both `cert_file` and `key_file` exist, returns immediately — the operator
//! has supplied their own certificate.  If both are absent, generates a new
//! private key and a server certificate signed by the Akāmu CA, then writes
//! both PEM files to disk.
//!
//! The CA-signed certificate means any client that already trusts the Akāmu CA
//! will also trust the TLS connection without additional configuration.
//! The cert chain written to `cert_file` is `leaf + CA` (PEM-concatenated) so
//! TLS clients see a complete chain.

use synta_certificate::der_to_pem;

use crate::ca::init::generate_backend_key;
use crate::ca::issue::sign_server_cert;
use crate::config::TlsConfig;
use crate::state::CaState;

/// Ensure TLS cert and key files exist, generating them from the CA if absent.
///
/// Analogous to `ca::init::load_or_generate`.
pub fn load_or_generate(tls: &TlsConfig, ca: &CaState) -> Result<(), String> {
    let cert_exists = std::path::Path::new(&tls.cert_file).exists();
    let key_exists = std::path::Path::new(&tls.key_file).exists();

    if cert_exists && key_exists {
        return Ok(());
    }
    if cert_exists != key_exists {
        return Err(format!(
            "TLS cert and key must both be present or both absent; \
             cert='{}' exists={cert_exists}, key='{}' exists={key_exists}",
            tls.cert_file, tls.key_file
        ));
    }

    tracing::info!(
        "TLS cert/key absent — generating server certificate signed by Akāmu CA \
         (cert='{}', key='{}', server_name='{}', key_type='{}')",
        tls.cert_file,
        tls.key_file,
        tls.server_name,
        tls.bootstrap_key_type
    );

    // Generate a fresh server key using the configured algorithm.
    let server_key = generate_backend_key(&tls.bootstrap_key_type).map_err(|e| {
        format!(
            "generate TLS server key (type '{}'): {e}",
            tls.bootstrap_key_type
        )
    })?;

    // Build a CA-signed server certificate.
    let cert_der =
        sign_server_cert(&tls.server_name, &server_key, ca).map_err(|e| {
            format!("sign TLS server cert: {e}")
        })?;

    // Write private key PEM.
    let key_pem = server_key
        .to_pem(None)
        .map_err(|e| format!("TLS key to PEM: {e}"))?;
    std::fs::write(&tls.key_file, &key_pem)
        .map_err(|e| format!("write TLS key '{}': {e}", tls.key_file))?;

    // Write cert chain PEM: leaf cert + CA cert (PEM-concatenated).
    let mut chain: Vec<u8> = der_to_pem("CERTIFICATE", &cert_der);
    chain.extend_from_slice(&der_to_pem("CERTIFICATE", &ca.cert_der));
    std::fs::write(&tls.cert_file, &chain)
        .map_err(|e| format!("write TLS cert '{}': {e}", tls.cert_file))?;

    tracing::info!("TLS server certificate generated successfully");
    Ok(())
}
