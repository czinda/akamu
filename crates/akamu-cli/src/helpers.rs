#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt as _;
use std::{
    fs,
    io::Write as _,
    path::{Path, PathBuf},
};

use akamu_client::{fetch_eab_via_gssapi, AccountKey};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

use crate::args::EabFlags;

/// Derive the ACME directory URL for a specific CA.
///
/// When `ca` is provided and `server` does not already end in `/directory`,
/// returns `{server}/acme/{ca}/directory`.  Otherwise returns `server` as-is.
pub(crate) fn resolve_directory_url(server: &str, ca: Option<&str>) -> String {
    if server.ends_with("/directory") {
        return server.to_owned();
    }
    match ca {
        Some(ca_id) => {
            let base = server.trim_end_matches('/');
            format!("{base}/acme/{ca_id}/directory")
        }
        None => server.to_owned(),
    }
}

/// Return the account URL sidecar path for a given account key and CA.
///
/// When `ca` is `Some(id)` and `id != "default"`, produces
/// `<key>.<ca_id>.account-url` to isolate per-CA account registrations.
/// Otherwise produces the legacy `<key>.account-url`.
pub(crate) fn account_url_path_for_ca(key_path: &Path, ca: Option<&str>) -> PathBuf {
    let mut p = key_path.to_path_buf();
    let mut name = p.file_name().unwrap_or_default().to_os_string();
    match ca {
        Some(id) if id != "default" => {
            // Sanitize: strip any path separators or characters unsafe in filenames
            // so a server-supplied CA ID cannot escape the intended directory.
            let safe_id: String = id
                .chars()
                .map(|c| {
                    if c.is_alphanumeric() || c == '-' || c == '_' {
                        c
                    } else {
                        '_'
                    }
                })
                .collect();
            name.push(format!(".{safe_id}.account-url"));
        }
        _ => {
            name.push(".account-url");
        }
    }
    p.set_file_name(name);
    p
}

pub(crate) fn save_account_url_for_ca(
    key_path: &Path,
    ca: Option<&str>,
    url: &str,
) -> Result<(), String> {
    let p = account_url_path_for_ca(key_path, ca);
    write_private_file(&p, url.as_bytes())
}

pub(crate) fn load_account_url_for_ca(key_path: &Path, ca: Option<&str>) -> Result<String, String> {
    let p = account_url_path_for_ca(key_path, ca);
    fs::read_to_string(&p).map_err(|e| format!("read {}: {e}", p.display()))
}

pub(crate) fn load_or_generate_key(path: &Path, key_type: &str) -> Result<AccountKey, String> {
    if path.exists() {
        load_key(path)
    } else {
        let key = AccountKey::generate(key_type).map_err(|e| e.to_string())?;
        let pem = key.to_pem().map_err(|e| e.to_string())?;
        write_private_file(path, &pem)?;
        println!("Generated new {} key → {}", key_type, path.display());
        Ok(key)
    }
}

pub(crate) fn load_key(path: &Path) -> Result<AccountKey, String> {
    let pem = fs::read(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    AccountKey::from_pem(&pem).map_err(|e| e.to_string())
}

/// Write `data` to `path` with mode 0o600 (owner-read/write only).
/// Enforces 0o600 even when overwriting a pre-existing file.
pub(crate) fn write_private_file(path: &Path, data: &[u8]) -> Result<(), String> {
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    opts.mode(0o600);
    let mut f = opts
        .open(path)
        .map_err(|e| format!("open {}: {e}", path.display()))?;
    f.write_all(data)
        .map_err(|e| format!("write {}: {e}", path.display()))?;
    // mode(0o600) only applies on O_CREAT; explicitly enforce on existing files.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("chmod {}: {e}", path.display()))?;
    }
    Ok(())
}

pub(crate) fn build_eab_options(
    flags: &EabFlags,
) -> Result<Option<(String, Vec<u8>, String)>, String> {
    flags.to_eab_options()
}

/// Construct the EAB identity URL from the ACME server directory URL.
///
/// Extracts the scheme + host (+ port) and appends `/acme/eab`.
pub(crate) fn derive_eab_url(server_url: &str) -> Result<String, String> {
    let without_scheme = server_url
        .split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or(server_url);
    let host_port = without_scheme.split('/').next().unwrap_or("");
    if host_port.is_empty() {
        return Err(format!(
            "cannot extract host from server URL '{server_url}'"
        ));
    }
    let scheme = server_url.split("://").next().unwrap_or("https");
    Ok(format!("{scheme}://{host_port}/acme/eab"))
}

pub(crate) async fn negotiate_gssapi_eab(
    keytab: &Path,
    dir_url: &str,
) -> Result<Option<(String, Vec<u8>, String)>, String> {
    let eab_url = derive_eab_url(dir_url)?;
    let result = fetch_eab_via_gssapi(
        &eab_url,
        keytab.to_str().ok_or("keytab path is not valid UTF-8")?,
    )
    .await
    .map_err(|e| e.to_string())?;
    eprintln!("GSSAPI authenticated as: {}", result.principal);
    match (result.kid, result.hmac_key, result.alg) {
        (Some(kid), Some(hmac_key_b64u), Some(alg)) => {
            let hmac_key = URL_SAFE_NO_PAD
                .decode(&hmac_key_b64u)
                .map_err(|e| format!("EAB hmac_key decode: {e}"))?;
            Ok(Some((kid, hmac_key, alg)))
        }
        _ => {
            eprintln!(
                "Note: server did not return EAB credentials \
                 (eab_master_secret not configured); proceeding without EAB."
            );
            Ok(None)
        }
    }
}
