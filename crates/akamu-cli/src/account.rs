use std::{fs, sync::Arc};

use akamu_client::{AccountOptions, AcmeClient, EabOptions};

use crate::args::{DeregisterArgs, KeyChangeArgs, RegisterArgs, ShowArgs, UpdateArgs};
use crate::helpers::{
    account_url_path_for_ca, build_eab_options, load_account_url_for_ca, load_key,
    load_or_generate_key, negotiate_gssapi_eab, resolve_directory_url, save_account_url_for_ca,
    write_private_file,
};

// ── account register ──────────────────────────────────────────────────────────

pub(crate) async fn cmd_register(args: RegisterArgs) -> Result<(), String> {
    let dir_url = resolve_directory_url(&args.server, args.ca.as_deref());
    let key = load_or_generate_key(&args.account_key, &args.key_type)?;
    let key = Arc::new(key);

    let client = AcmeClient::new(&dir_url).await.map_err(|e| e.to_string())?;

    let gssapi_eab = match args.eab.gssapi_keytab.as_ref() {
        Some(keytab) => negotiate_gssapi_eab(keytab, &dir_url).await?,
        None => None,
    };

    let cli_eab = build_eab_options(&args.eab)?;
    let eab = gssapi_eab.or(cli_eab);
    let contact_refs: Vec<&str> = args.contacts.iter().map(String::as_str).collect();

    let opts = AccountOptions {
        contacts: &contact_refs,
        agree_tos: args.agree_tos,
        eab: eab.as_ref().map(|(kid, hmac, alg)| EabOptions {
            kid,
            hmac_key: hmac,
            alg,
        }),
    };

    let account = client
        .new_account(Arc::clone(&key), &opts)
        .await
        .map_err(|e| e.to_string())?;

    save_account_url_for_ca(&args.account_key, args.ca.as_deref(), &account.url)?;
    println!("Registered: {}", account.url);
    Ok(())
}

// ── account deregister ────────────────────────────────────────────────────────

pub(crate) async fn cmd_deregister(args: DeregisterArgs) -> Result<(), String> {
    let dir_url = resolve_directory_url(&args.server, args.ca.as_deref());
    let key = load_key(&args.account_key)?;
    let key = Arc::new(key);
    let account_url = load_account_url_for_ca(&args.account_key, args.ca.as_deref())?;

    let client = AcmeClient::new(&dir_url).await.map_err(|e| e.to_string())?;

    // Reconstruct a minimal Account with the stored URL.
    let account = akamu_client::Account::new(account_url.clone(), "valid".to_string(), vec![], key);

    client
        .deactivate_account(&account)
        .await
        .map_err(|e| e.to_string())?;

    // Remove the stored account URL.
    let url_path = account_url_path_for_ca(&args.account_key, args.ca.as_deref());
    if let Err(e) = fs::remove_file(&url_path) {
        if e.kind() != std::io::ErrorKind::NotFound {
            eprintln!(
                "Warning: account deactivated but could not remove sidecar {}: {e}. \
                 Future commands may attempt to use the deactivated account.",
                url_path.display()
            );
        }
    }
    println!("Deactivated: {account_url}");
    Ok(())
}

// ── account show ──────────────────────────────────────────────────────────────

pub(crate) async fn cmd_show(args: ShowArgs) -> Result<(), String> {
    let dir_url = resolve_directory_url(&args.server, args.ca.as_deref());
    let key = load_key(&args.account_key)?;
    let key = Arc::new(key);
    let account_url = load_account_url_for_ca(&args.account_key, args.ca.as_deref())?;

    let client = AcmeClient::new(&dir_url).await.map_err(|e| e.to_string())?;
    let account = akamu_client::Account::new(account_url, "valid".into(), vec![], key);
    let account = client
        .get_account(&account)
        .await
        .map_err(|e| e.to_string())?;

    println!("URL:     {}", account.url);
    println!("Status:  {}", account.status);
    if account.contacts.is_empty() {
        println!("Contact: (none)");
    } else {
        for c in &account.contacts {
            println!("Contact: {c}");
        }
    }
    Ok(())
}

// ── account update ────────────────────────────────────────────────────────────

pub(crate) async fn cmd_update(args: UpdateArgs) -> Result<(), String> {
    let dir_url = resolve_directory_url(&args.server, args.ca.as_deref());
    let key = load_key(&args.account_key)?;
    let key = Arc::new(key);
    let account_url = load_account_url_for_ca(&args.account_key, args.ca.as_deref())?;

    let client = AcmeClient::new(&dir_url).await.map_err(|e| e.to_string())?;
    let account = akamu_client::Account::new(account_url, "valid".into(), vec![], key);
    let contact_refs: Vec<&str> = args.contacts.iter().map(String::as_str).collect();
    let updated = client
        .update_account(&account, &contact_refs)
        .await
        .map_err(|e| e.to_string())?;

    println!("Updated account: {}", updated.url);
    for c in &updated.contacts {
        println!("  Contact: {c}");
    }
    Ok(())
}

// ── account key-change ────────────────────────────────────────────────────────

pub(crate) async fn cmd_key_change(args: KeyChangeArgs) -> Result<(), String> {
    let dir_url = resolve_directory_url(&args.server, args.ca.as_deref());
    let old_key = load_key(&args.account_key)?;
    let old_key = Arc::new(old_key);
    let account_url = load_account_url_for_ca(&args.account_key, args.ca.as_deref())?;

    let new_key = load_or_generate_key(&args.new_key, &args.new_key_type)?;
    let new_key = Arc::new(new_key);

    let client = AcmeClient::new(&dir_url).await.map_err(|e| e.to_string())?;
    let account = akamu_client::Account::new(account_url.clone(), "valid".into(), vec![], old_key);
    let _updated = client
        .key_change(&account, Arc::clone(&new_key))
        .await
        .map_err(|e| e.to_string())?;

    // Overwrite the account key file with the new key.
    let new_pem = new_key.to_pem().map_err(|e| e.to_string())?;
    write_private_file(&args.account_key, &new_pem)?;
    // The account URL stays the same — sidecar file is unchanged.
    println!(
        "Key changed. New key written to {}",
        args.account_key.display()
    );
    println!("Account URL unchanged: {account_url}");
    Ok(())
}
