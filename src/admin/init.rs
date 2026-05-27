//! Admin bootstrap.
//!
//! Runs at startup when `[admin]` is configured: if
//! `bootstrap_operator_cert_file`/`bootstrap_operator_key_file` are configured
//! and the files are absent, *and* the operators table is currently empty,
//! generates a client certificate signed by the Akāmu CA, writes both PEM
//! files to disk, and inserts an Administrator row into the database.  On
//! every subsequent startup the files exist and the row exists — no-op.
//!
//! Alternatively, if `bootstrap_operator_pkcs12_file` is configured, the key
//! and certificate are written as a single PKCS#12 bundle instead of separate
//! PEM files.

use std::io::Write as _;

use synta_certificate::der_to_pem;
use synta_certificate::{
    certs_from_pkcs12, OpensslDecryptor, OpensslPkcs12Encryptor, Pkcs12Builder,
};

use crate::ca::init::{generate_backend_key, unix_to_generalized_time};
use crate::ca::issue::sign_admin_cert;
use crate::config::AdminConfig;
use crate::db::Db;
use crate::error::AcmeError;
use crate::state::CaState;
use crate::util::{sha256_hex, unix_now};

/// Generate and register the initial Administrator operator if the operators
/// table is empty.
///
/// Three independent bootstrap paths:
///
/// - **GSSAPI** — if `bootstrap_operator_gssapi_principal` is set and the
///   operators table is empty, insert an Administrator row with that principal.
///   This is a one-time operation: on subsequent startups the row already exists.
///
/// - **mTLS cert (PEM)** — if `bootstrap_operator_cert_file` / `bootstrap_operator_key_file`
///   are set and the files are absent and the operators table is empty, generate
///   a client certificate, write the PEM files, and insert an Administrator row.
///   On subsequent startups the files already exist so this becomes a no-op.
///
/// - **mTLS cert (PKCS#12)** — if `bootstrap_operator_pkcs12_file` is set and
///   the file is absent and the operators table is empty, generate a client
///   certificate and key, bundle them into a PKCS#12 file, and insert an
///   Administrator row.  On subsequent startups the file already exists — no-op.
pub async fn bootstrap_operator_if_needed(
    cfg: &AdminConfig,
    ca: &CaState,
    db: &Db,
) -> Result<(), AcmeError> {
    // ── GSSAPI-only bootstrap ─────────────────────────────────────────────────
    // Runs only when no cert bootstrap is configured; when a cert bootstrap is
    // also configured the GSSAPI principal is stored on the same operator row
    // by the cert bootstrap path below.
    if cfg.bootstrap_operator_pkcs12_file.is_none() && cfg.bootstrap_operator_cert_file.is_none() {
        if let Some(ref principal) = cfg.bootstrap_operator_gssapi_principal {
            let existing = crate::db::operators::get_by_principal(db, principal)
                .await
                .map_err(|e| AcmeError::Config(format!("operators DB lookup: {e}")))?;
            if existing.is_none() {
                let empty = crate::db::operators::is_empty(db)
                    .await
                    .map_err(|e| AcmeError::Config(format!("operators DB check: {e}")))?;
                if !empty {
                    return Err(AcmeError::Config(format!(
                        "bootstrap GSSAPI principal '{principal}' is not registered \
                     but operators already exist in the database; \
                     add the operator manually with akamuctl or remove \
                     bootstrap_operator_gssapi_principal from the config"
                    )));
                }
                tracing::info!(
                    "no operators found — registering bootstrap Administrator operator \
                 (name='{}', gssapi_principal='{principal}')",
                    cfg.bootstrap_operator_name,
                );
                let now = unix_to_generalized_time(unix_now());
                let inserted = crate::db::operators::insert_if_absent(
                    db,
                    &cfg.bootstrap_operator_name,
                    "administrator",
                    None,
                    Some(principal.as_str()),
                    "", // administrator is always server-wide
                    &now,
                )
                .await
                .map_err(|e| AcmeError::Config(format!("insert bootstrap GSSAPI operator: {e}")))?;
                if inserted {
                    tracing::info!(
                    "bootstrap Administrator '{}' registered with GSSAPI principal '{principal}'",
                    cfg.bootstrap_operator_name,
                );
                } else {
                    tracing::warn!(
                    "bootstrap Administrator '{}' already exists (concurrent startup?); skipping",
                    cfg.bootstrap_operator_name,
                );
                }
            }
            return Ok(());
        }
    } // end GSSAPI-only bootstrap guard

    // ── mTLS cert bootstrap (PKCS#12) ─────────────────────────────────────────
    if let Some(ref p12_path) = cfg.bootstrap_operator_pkcs12_file {
        let password = cfg.bootstrap_operator_pkcs12_password.as_str();
        if std::path::Path::new(p12_path).exists() {
            // File already on disk.  Verify the DB row also exists to catch
            // the partial-write scenario (file written, DB insert crashed).
            let fingerprint = read_cert_fingerprint_from_p12(p12_path, password)?;
            let existing = crate::db::operators::get_by_fingerprint(db, &fingerprint)
                .await
                .map_err(|e| AcmeError::Config(format!("operators DB lookup: {e}")))?;
            if existing.is_none() {
                return Err(AcmeError::Config(format!(
                    "bootstrap operator PKCS#12 file exists ('{p12_path}') \
                     but no matching operator row was found in the database; \
                     re-register manually with akamuctl or delete the file to re-provision"
                )));
            }
            return Ok(());
        }

        let empty = crate::db::operators::is_empty(db)
            .await
            .map_err(|e| AcmeError::Config(format!("operators DB check: {e}")))?;
        if !empty {
            return Err(AcmeError::Config(format!(
                "bootstrap operator PKCS#12 file ('{p12_path}') is absent \
                 but operators already exist in the database; \
                 either restore the file or remove bootstrap_operator_pkcs12_file \
                 from the config and manage operators via akamuctl"
            )));
        }

        tracing::info!(
            "no operators found — generating bootstrap Administrator operator \
             (name='{}', pkcs12='{}', key_type='{}')",
            cfg.bootstrap_operator_name,
            p12_path,
            cfg.bootstrap_key_type,
        );

        let key = generate_backend_key(&cfg.bootstrap_key_type)
            .map_err(|e| AcmeError::Config(format!("generate bootstrap operator key: {e}")))?;
        let cert_der = sign_admin_cert(&cfg.bootstrap_operator_name, &key, ca)
            .map_err(|e| AcmeError::Config(format!("sign bootstrap operator cert: {e}")))?;
        let fingerprint = sha256_hex(&cert_der)
            .map_err(|e| AcmeError::Config(format!("bootstrap operator cert fingerprint: {e}")))?;

        let key_der = key
            .to_der()
            .map_err(|e| AcmeError::Config(format!("bootstrap operator key to DER: {e}")))?;
        let p12_der = build_pkcs12(&cert_der, &key_der, password)
            .map_err(|e| AcmeError::Config(format!("build PKCS#12 bundle: {e}")))?;
        write_secret_file(p12_path, &p12_der).map_err(|e| {
            AcmeError::Config(format!(
                "write bootstrap operator PKCS#12 '{p12_path}': {e}"
            ))
        })?;

        let now = unix_to_generalized_time(unix_now());
        let gssapi_principal = cfg.bootstrap_operator_gssapi_principal.as_deref();
        let inserted = crate::db::operators::insert_if_absent(
            db,
            &cfg.bootstrap_operator_name,
            "administrator",
            Some(&fingerprint),
            gssapi_principal,
            "",
            &now,
        )
        .await
        .map_err(|e| AcmeError::Config(format!("insert bootstrap operator: {e}")))?;
        if inserted {
            tracing::info!(
                "bootstrap Administrator '{}' registered (fingerprint prefix: {}…{})",
                cfg.bootstrap_operator_name,
                &fingerprint[..16],
                gssapi_principal
                    .map(|p| format!(", gssapi_principal='{p}'"))
                    .unwrap_or_default(),
            );
        } else {
            tracing::warn!(
                "bootstrap Administrator '{}' already exists (concurrent startup?); skipping",
                cfg.bootstrap_operator_name,
            );
        }
        return Ok(());
    }

    // ── mTLS cert bootstrap (PEM) ─────────────────────────────────────────────
    let (Some(cert_path), Some(key_path)) = (
        &cfg.bootstrap_operator_cert_file,
        &cfg.bootstrap_operator_key_file,
    ) else {
        return Ok(());
    };

    let cert_exists = std::path::Path::new(cert_path).exists();
    let key_exists = std::path::Path::new(key_path).exists();

    if cert_exists && key_exists {
        // Files already on disk.  Verify the DB row also exists to catch
        // the partial-write scenario (files written, DB insert crashed).
        let fingerprint = read_cert_fingerprint(cert_path)?;
        let existing = crate::db::operators::get_by_fingerprint(db, &fingerprint)
            .await
            .map_err(|e| AcmeError::Config(format!("operators DB lookup: {e}")))?;
        if existing.is_none() {
            return Err(AcmeError::Config(format!(
                "bootstrap operator cert/key files exist ('{cert_path}', '{key_path}') \
                 but no matching operator row was found in the database; \
                 re-register manually with akamuctl or delete the files to re-provision"
            )));
        }
        return Ok(());
    }
    if cert_exists != key_exists {
        return Err(AcmeError::Config(format!(
            "bootstrap operator cert and key must both be present or both absent; \
             cert='{cert_path}' exists={cert_exists}, key='{key_path}' exists={key_exists}"
        )));
    }

    // Files absent — only proceed if the operators table is empty to avoid
    // silently creating a second Administrator on a misconfigured restart.
    let empty = crate::db::operators::is_empty(db)
        .await
        .map_err(|e| AcmeError::Config(format!("operators DB check: {e}")))?;

    if !empty {
        return Err(AcmeError::Config(format!(
            "bootstrap operator cert/key ('{cert_path}', '{key_path}') are absent \
             but operators already exist in the database; \
             either restore the files or remove bootstrap_operator_cert_file / \
             bootstrap_operator_key_file from the config and manage operators via akamuctl"
        )));
    }

    tracing::info!(
        "no operators found — generating bootstrap Administrator operator \
         (name='{}', cert='{}', key='{}', key_type='{}')",
        cfg.bootstrap_operator_name,
        cert_path,
        key_path,
        cfg.bootstrap_key_type,
    );

    let key = generate_backend_key(&cfg.bootstrap_key_type)
        .map_err(|e| AcmeError::Config(format!("generate bootstrap operator key: {e}")))?;

    let cert_der = sign_admin_cert(&cfg.bootstrap_operator_name, &key, ca)
        .map_err(|e| AcmeError::Config(format!("sign bootstrap operator cert: {e}")))?;

    let fingerprint = sha256_hex(&cert_der)
        .map_err(|e| AcmeError::Config(format!("bootstrap operator cert fingerprint: {e}")))?;

    let key_pem = key
        .to_pem(None)
        .map_err(|e| AcmeError::Config(format!("bootstrap operator key to PEM: {e}")))?;
    write_secret_file(key_path, &key_pem).map_err(|e| {
        AcmeError::Config(format!("write bootstrap operator key '{key_path}': {e}"))
    })?;

    let cert_pem = der_to_pem("CERTIFICATE", &cert_der);
    std::fs::write(cert_path, &cert_pem).map_err(|e| {
        AcmeError::Config(format!("write bootstrap operator cert '{cert_path}': {e}"))
    })?;

    let now = unix_to_generalized_time(unix_now());
    let gssapi_principal = cfg.bootstrap_operator_gssapi_principal.as_deref();
    // Use INSERT OR IGNORE semantics: if a concurrent startup already inserted
    // the row, this is a no-op and we log a warning rather than failing.
    let inserted = crate::db::operators::insert_if_absent(
        db,
        &cfg.bootstrap_operator_name,
        "administrator",
        Some(&fingerprint),
        gssapi_principal,
        "", // administrator is always server-wide
        &now,
    )
    .await
    .map_err(|e| AcmeError::Config(format!("insert bootstrap operator: {e}")))?;

    if inserted {
        tracing::info!(
            "bootstrap Administrator '{}' registered (fingerprint prefix: {}…{})",
            cfg.bootstrap_operator_name,
            &fingerprint[..16],
            gssapi_principal
                .map(|p| format!(", gssapi_principal='{p}'"))
                .unwrap_or_default(),
        );
    } else {
        tracing::warn!(
            "bootstrap Administrator '{}' already exists (concurrent startup?); skipping",
            cfg.bootstrap_operator_name,
        );
    }
    Ok(())
}

// ── Private helpers ───────────────────────────────────────────────────────────

/// Write `data` to `path` with mode 0o600 (owner read/write only).
/// Creates the file if absent; truncates it if it exists.
fn write_secret_file(path: &str, data: &[u8]) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        f.write_all(data)
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, data)
    }
}

/// Read the PEM certificate at `path` and compute its SHA-256 fingerprint.
fn read_cert_fingerprint(path: &str) -> Result<String, AcmeError> {
    let pem =
        std::fs::read(path).map_err(|e| AcmeError::Config(format!("read cert '{path}': {e}")))?;
    let ders = synta_certificate::pem_to_der(&pem);
    let der = ders
        .into_iter()
        .next()
        .ok_or_else(|| AcmeError::Config(format!("cert file '{path}' contains no certificates")))?;
    sha256_hex(&der).map_err(|e| AcmeError::Config(format!("fingerprint '{path}': {e}")))
}

/// Read the PKCS#12 bundle at `path`, extract the first certificate, and
/// compute its SHA-256 fingerprint.
fn read_cert_fingerprint_from_p12(path: &str, password: &str) -> Result<String, AcmeError> {
    let der = std::fs::read(path)
        .map_err(|e| AcmeError::Config(format!("read PKCS#12 '{path}': {e}")))?;
    let certs = certs_from_pkcs12(&der, password.as_bytes(), &OpensslDecryptor)
        .map_err(|e| AcmeError::Config(format!("parse PKCS#12 '{path}': {e}")))?;
    let cert_der = certs
        .into_iter()
        .next()
        .ok_or_else(|| AcmeError::Config(format!("PKCS#12 '{path}' contains no certificates")))?;
    sha256_hex(&cert_der).map_err(|e| AcmeError::Config(format!("fingerprint '{path}': {e}")))
}

/// Bundle `cert_der` and unencrypted PKCS#8 `key_der` into a PKCS#12 DER blob.
fn build_pkcs12(cert_der: &[u8], key_der: &[u8], password: &str) -> Result<Vec<u8>, String> {
    Pkcs12Builder::new()
        .certificate(cert_der)
        .private_key(key_der)
        .build(password.as_bytes(), &OpensslPkcs12Encryptor::new())
        .map_err(|e| e.to_string())
}
