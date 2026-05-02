//! Admin listener bootstrap.
//!
//! Two independent auto-provisioning steps run at startup when `[admin]` is
//! configured:
//!
//! 1. **Server certificate** — if `cert_file`/`key_file` are absent, generates
//!    a TLS server certificate for the admin listener, signed by the Akāmu CA
//!    and written as PEM.  Analogous to `tls::init::load_or_generate`.
//!
//! 2. **Bootstrap operator** — if `bootstrap_operator_cert_file`/
//!    `bootstrap_operator_key_file` are configured and the files are absent,
//!    *and* the operators table is currently empty, generates a client
//!    certificate signed by the Akāmu CA, writes both PEM files to disk, and
//!    inserts an Administrator row into the database.  On every subsequent
//!    startup the files exist and the row exists, so this becomes a no-op.

use synta_certificate::der_to_pem;

use crate::admin::auth::sha256_hex;
use crate::ca::init::{generate_backend_key, unix_to_generalized_time};
use crate::ca::issue::{sign_admin_cert, sign_server_cert};
use crate::config::AdminConfig;
use crate::db::Db;
use crate::state::CaState;
use crate::util::unix_now;

/// Ensure the admin listener TLS cert and key files exist, generating them from
/// the Akāmu CA if absent.
pub fn load_or_generate_server_cert(cfg: &AdminConfig, ca: &CaState) -> Result<(), String> {
    let cert_exists = std::path::Path::new(&cfg.cert_file).exists();
    let key_exists = std::path::Path::new(&cfg.key_file).exists();

    if cert_exists && key_exists {
        return Ok(());
    }
    if cert_exists != key_exists {
        return Err(format!(
            "admin cert and key must both be present or both absent; \
             cert='{}' exists={cert_exists}, key='{}' exists={key_exists}",
            cfg.cert_file, cfg.key_file
        ));
    }

    tracing::info!(
        "admin server cert/key absent — generating certificate signed by Akāmu CA \
         (cert='{}', key='{}', server_name='{}', key_type='{}')",
        cfg.cert_file,
        cfg.key_file,
        cfg.server_name,
        cfg.bootstrap_key_type,
    );

    let key = generate_backend_key(&cfg.bootstrap_key_type)
        .map_err(|e| format!("generate admin server key (type '{}'): {e}", cfg.bootstrap_key_type))?;

    let cert_der = sign_server_cert(&cfg.server_name, &key, ca)
        .map_err(|e| format!("sign admin server cert: {e}"))?;

    let key_pem = key
        .to_pem(None)
        .map_err(|e| format!("admin server key to PEM: {e}"))?;
    std::fs::write(&cfg.key_file, &key_pem)
        .map_err(|e| format!("write admin key '{}': {e}", cfg.key_file))?;

    // Chain: leaf + CA cert so clients can build a complete chain.
    let mut chain = der_to_pem("CERTIFICATE", &cert_der);
    chain.extend_from_slice(&der_to_pem("CERTIFICATE", &ca.cert_der));
    std::fs::write(&cfg.cert_file, &chain)
        .map_err(|e| format!("write admin cert '{}': {e}", cfg.cert_file))?;

    tracing::info!("admin server certificate generated successfully");
    Ok(())
}

/// Generate and register the initial Administrator operator if the operators
/// table is empty and the bootstrap cert/key files are configured but absent.
///
/// This is a one-time operation: on every subsequent startup the files already
/// exist so the function returns immediately without touching the database.
pub async fn bootstrap_operator_if_needed(
    cfg: &AdminConfig,
    ca: &CaState,
    db: &Db,
) -> Result<(), String> {
    let (Some(cert_path), Some(key_path)) = (
        &cfg.bootstrap_operator_cert_file,
        &cfg.bootstrap_operator_key_file,
    ) else {
        return Ok(());
    };

    let cert_exists = std::path::Path::new(cert_path).exists();
    let key_exists = std::path::Path::new(key_path).exists();

    if cert_exists && key_exists {
        return Ok(());
    }
    if cert_exists != key_exists {
        return Err(format!(
            "bootstrap operator cert and key must both be present or both absent; \
             cert='{cert_path}' exists={cert_exists}, key='{key_path}' exists={key_exists}"
        ));
    }

    // Files absent — only proceed if the operators table is empty to avoid
    // silently creating a second Administrator on a misconfigured restart.
    let empty = crate::db::operators::is_empty(db)
        .await
        .map_err(|e| format!("operators DB check: {e}"))?;

    if !empty {
        return Err(format!(
            "bootstrap operator cert/key ('{cert_path}', '{key_path}') are absent \
             but operators already exist in the database; \
             either restore the files or remove bootstrap_operator_cert_file / \
             bootstrap_operator_key_file from the config and manage operators via akamuctl"
        ));
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
        .map_err(|e| format!("generate bootstrap operator key: {e}"))?;

    let cert_der = sign_admin_cert(&cfg.bootstrap_operator_name, &key, ca)
        .map_err(|e| format!("sign bootstrap operator cert: {e}"))?;

    let fingerprint = sha256_hex(&cert_der)
        .map_err(|e| format!("bootstrap operator cert fingerprint: {e}"))?;

    let key_pem = key
        .to_pem(None)
        .map_err(|e| format!("bootstrap operator key to PEM: {e}"))?;
    std::fs::write(key_path, &key_pem)
        .map_err(|e| format!("write bootstrap operator key '{key_path}': {e}"))?;

    let cert_pem = der_to_pem("CERTIFICATE", &cert_der);
    std::fs::write(cert_path, &cert_pem)
        .map_err(|e| format!("write bootstrap operator cert '{cert_path}': {e}"))?;

    let now = unix_to_generalized_time(unix_now());
    crate::db::operators::insert(
        db,
        &cfg.bootstrap_operator_name,
        "administrator",
        Some(&fingerprint),
        None,
        &now,
    )
    .await
    .map_err(|e| format!("insert bootstrap operator: {e}"))?;

    tracing::info!(
        "bootstrap Administrator '{}' registered (fingerprint prefix: {}…)",
        cfg.bootstrap_operator_name,
        &fingerprint[..16],
    );
    Ok(())
}
