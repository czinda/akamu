//! Standalone TLS server support for Akāmu.
//!
//! When `[tls] enabled = true` is set in config.toml, Akāmu binds as a native
//! TLS server using the rustls crypto backend (OpenSSL provider via
//! rustls-native-ossl) instead of delegating TLS termination to an upstream
//! reverse proxy.
//!
//! Optional mutual TLS (`[tls.client_auth]`) validates client certificates
//! through `synta-x509-verification` with a configurable CAB Forum or RFC 5280
//! profile, including support for hybrid composite ML-DSA+classical chains when
//! `allow_post_quantum = true`.
//!
//! Bootstrap: if `cert_file`/`key_file` are absent, `init::load_or_generate`
//! generates a server certificate signed by the Akāmu CA at startup.

pub mod init;
pub mod loader;
pub mod schemes;
pub mod verifier;

use std::sync::Arc;

/// Build a `rustls::ServerConfig` from the `[tls]` configuration section.
///
/// Called once at startup; the resulting config is passed to
/// `tokio_rustls::TlsAcceptor::from`.
pub fn build_rustls_server_config(
    tls: &crate::config::TlsConfig,
) -> Result<rustls::ServerConfig, String> {
    let certs = loader::load_server_cert_chain(&tls.cert_file)?;
    let key = loader::load_server_private_key(&tls.key_file)?;
    let provider = Arc::new(rustls_native_ossl::default_provider());

    let versions: Vec<&'static rustls::SupportedProtocolVersion> = tls
        .protocols
        .iter()
        .filter_map(|p| match p.as_str() {
            "TLSv1.2" => Some(&rustls::version::TLS12),
            "TLSv1.3" => Some(&rustls::version::TLS13),
            other => {
                tracing::warn!("unknown TLS protocol '{other}', ignoring");
                None
            }
        })
        .collect();

    if versions.is_empty() {
        return Err("tls.protocols must include TLSv1.2 and/or TLSv1.3".into());
    }

    let builder = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&versions)
        .map_err(|e| format!("TLS protocol versions: {e}"))?;

    let cfg = if let Some(client_auth) = &tls.client_auth {
        let ca_ders = loader::load_ca_certs(&client_auth.ca_files)?;
        // Parses trust anchors once via OwnedStore::try_new; returns Err on malformed cert.
        let verifier = Arc::new(
            verifier::SyntaClientCertVerifier::new(&ca_ders, client_auth)
                .map_err(|e| format!("client-auth verifier: {e}"))?,
        );
        builder.with_client_cert_verifier(verifier)
    } else {
        builder.with_no_client_auth()
    }
    .with_single_cert(certs, key)
    .map_err(|e| format!("TLS server certificate: {e}"))?;

    Ok(cfg)
}
