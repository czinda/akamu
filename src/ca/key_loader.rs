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
    /// Create a loader bound to `config`.
    ///
    /// Does not open any files or connect to any token; call [`load_key`] to
    /// perform the actual I/O.
    ///
    /// [`load_key`]: CaKeyLoader::load_key
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
    ///
    /// When `require_encrypted_key` is set in the CA config, file-based PEM
    /// keys must use PKCS#8 encrypted format (`ENCRYPTED PRIVATE KEY`).
    pub fn load_key(&self) -> Result<BackendPrivateKey, AcmeError> {
        match self.source() {
            CaKeySource::File(path) => {
                let pem = std::fs::read(path)
                    .map_err(|e| AcmeError::Internal(format!("read CA key '{}': {e}", path)))?;

                let password = if self.config.require_encrypted_key {
                    Self::require_encrypted_pem(&pem)?;
                    Some(Self::read_password(self.config)?)
                } else {
                    None
                };

                BackendPrivateKey::from_pem(&pem, password.as_deref().map(|s| s.as_bytes()))
                    .map_err(|e| AcmeError::Crypto(format!("parse CA key: {e}")))
            }
            CaKeySource::Pkcs11Uri(uri) => BackendPrivateKey::from_pkcs11_uri(uri)
                .map_err(|e| AcmeError::Crypto(format!("PKCS#11 key load: {e}"))),
        }
    }

    /// Verify the PEM data contains an encrypted private key header.
    fn require_encrypted_pem(pem: &[u8]) -> Result<(), AcmeError> {
        let pem_str = std::str::from_utf8(pem)
            .map_err(|_| AcmeError::Config("CA key file is not valid UTF-8".to_owned()))?;
        if pem_str.contains("-----BEGIN ENCRYPTED PRIVATE KEY-----") {
            Ok(())
        } else {
            Err(AcmeError::Config(
                "ca.require_encrypted_key is set but the CA key file contains an unencrypted \
                 private key; use PKCS#8 encrypted PEM or a PKCS#11 URI"
                    .to_owned(),
            ))
        }
    }

    /// Read the decryption passphrase from `key_password_file`.
    fn read_password(config: &CaConfig) -> Result<String, AcmeError> {
        let path = config.key_password_file.as_deref().ok_or_else(|| {
            AcmeError::Config(
                "ca.require_encrypted_key is set but ca.key_password_file is not configured"
                    .to_owned(),
            )
        })?;
        let raw = std::fs::read_to_string(path)
            .map_err(|e| AcmeError::Config(format!("read ca.key_password_file '{}': {e}", path)))?;
        Ok(raw.trim_end_matches('\n').trim_end_matches('\r').to_owned())
    }
}
