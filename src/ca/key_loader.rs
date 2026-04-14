//! CA private key loading — file-based PEM or PKCS#11 token URI.
//!
//! [`CaKeyLoader`] examines the configured `key_file` value and routes to the
//! appropriate loading path.  File-based keys support auto-generation on first
//! run; PKCS#11 keys must already exist in the token.

use synta_certificate::BackendPrivateKey;

use crate::config::CaConfig;
use crate::error::AcmeError;

/// How the CA private key is sourced.
#[derive(Debug)]
pub enum CaKeySource<'a> {
    /// Filesystem PEM file.
    File(&'a str),
    /// PKCS#11 token URI (`pkcs11:…`).
    Pkcs11Uri(&'a str),
}

/// Determines the key source from configuration and loads the key.
pub struct CaKeyLoader<'a> {
    config: &'a CaConfig,
}

impl<'a> CaKeyLoader<'a> {
    pub fn new(config: &'a CaConfig) -> Self {
        Self { config }
    }

    /// Classify the configured key source.
    pub fn source(&self) -> CaKeySource<'_> {
        if self.config.key_file.starts_with("pkcs11:") {
            CaKeySource::Pkcs11Uri(&self.config.key_file)
        } else {
            CaKeySource::File(&self.config.key_file)
        }
    }

    /// True if this source supports auto-generating a new key (file only).
    pub fn can_generate(&self) -> bool {
        matches!(self.source(), CaKeySource::File(_))
    }

    /// Load the private key from whichever source is configured.
    ///
    /// For PKCS#11 URIs the pkcs11-provider (OpenSSL) or NSS secmod database
    /// must be configured externally before calling this — e.g. via
    /// `OPENSSL_CONF`.
    pub fn load_key(&self) -> Result<BackendPrivateKey, AcmeError> {
        match self.source() {
            CaKeySource::File(path) => {
                let pem = std::fs::read(path)
                    .map_err(|e| AcmeError::Internal(format!("read CA key '{}': {e}", path)))?;
                BackendPrivateKey::from_pem(&pem, None)
                    .map_err(|e| AcmeError::Crypto(format!("parse CA key: {e}")))
            }
            CaKeySource::Pkcs11Uri(uri) => BackendPrivateKey::from_pkcs11_uri(uri)
                .map_err(|e| AcmeError::Crypto(format!("PKCS#11 key load: {e}"))),
        }
    }
}
