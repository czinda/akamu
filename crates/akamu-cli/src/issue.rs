use std::{fs, path::PathBuf, sync::Arc};

use akamu_client::{
    AccountOptions, AcmeClient, Challenge, ChallengeSolver as _, Dns01Helper, DnsHookSolver,
    DnsPersist01Helper, EabOptions, Http01Solver, Identifier, RenewalConfig, TlsAlpn01Solver,
};

use crate::args::CommonCertArgs;
use crate::helpers::{
    build_eab_options, load_account_url_for_ca, load_or_generate_key, negotiate_gssapi_eab,
    resolve_directory_url, save_account_url_for_ca, write_private_file,
};

// ── poll helper ───────────────────────────────────────────────────────────────

/// Poll for order completion with a configurable timeout.
pub(crate) async fn poll_with_timeout(
    client: &AcmeClient,
    account: &akamu_client::Account,
    order_url: &str,
    timeout_secs: u64,
) -> Result<akamu_client::Order, String> {
    client
        .poll_order(
            account,
            order_url,
            std::time::Duration::from_secs(timeout_secs),
        )
        .await
        .map_err(|e| e.to_string())
}

// ── issue ─────────────────────────────────────────────────────────────────────

pub(crate) async fn cmd_issue(
    args: CommonCertArgs,
    delegation: Option<&str>,
    account_url: Option<&str>,
) -> Result<(), String> {
    let account_key_path = args.account_key.ok_or("--account-key is required")?;
    let out_path = args.out.ok_or("--out is required")?;

    let using_jwtcc = args.challenge_type == "tkauth-01" && args.jwtcc.is_some();
    if args.domains.is_empty() && !using_jwtcc {
        return Err("at least one --domain is required (or --jwtcc for tkauth-01)".into());
    }

    let dir_url = resolve_directory_url(&args.server, args.ca.as_deref());

    // Load or generate the account key.
    let key = load_or_generate_key(&account_key_path, &args.key_type)?;
    let key = Arc::new(key);

    let client = if let Some(ca_path) = &args.server_ca {
        let pem =
            fs::read(ca_path).map_err(|e| format!("--server-ca {}: {e}", ca_path.display()))?;
        AcmeClient::new_with_extra_root(&dir_url, &pem)
            .await
            .map_err(|e| e.to_string())?
    } else {
        AcmeClient::new(&dir_url).await.map_err(|e| e.to_string())?
    };

    // Load existing account or register a new one.
    let account = if let Some(url) = account_url {
        akamu_client::Account::new(
            url.to_string(),
            "valid".to_string(),
            vec![],
            Arc::clone(&key),
        )
    } else if let Ok(url) = load_account_url_for_ca(&account_key_path, args.ca.as_deref()) {
        akamu_client::Account::new(url, "valid".to_string(), vec![], Arc::clone(&key))
    } else {
        let gssapi_eab = match args.eab.gssapi_keytab.as_ref() {
            Some(keytab) => negotiate_gssapi_eab(keytab, &dir_url).await?,
            None => None,
        };
        let cli_eab = build_eab_options(&args.eab)?;
        let eab = gssapi_eab.or(cli_eab);
        let opts = AccountOptions {
            contacts: &[],
            agree_tos: true,
            eab: eab.as_ref().map(|(kid, hmac, alg)| EabOptions {
                kid,
                hmac_key: hmac,
                alg,
            }),
        };
        let acct = client
            .new_account(Arc::clone(&key), &opts)
            .await
            .map_err(|e| format!("register: {e}"))?;
        save_account_url_for_ca(&account_key_path, args.ca.as_deref(), &acct.url)?;
        println!("Registered new account: {}", acct.url);
        acct
    };

    // Validate challenge type and wildcard compatibility (not needed for delegation orders).
    if delegation.is_none() {
        match args.challenge_type.as_str() {
            "http-01" | "tls-alpn-01" => {
                // http-01 and tls-alpn-01 cannot validate wildcard identifiers
                // (RFC 8555 §8.3 and RFC 8737 §3).
                let wildcards: Vec<&str> = args
                    .domains
                    .iter()
                    .filter(|d| d.starts_with("*."))
                    .map(String::as_str)
                    .collect();
                if !wildcards.is_empty() {
                    return Err(format!(
                        "{} cannot validate wildcard identifiers: {}; use --challenge dns-01",
                        args.challenge_type,
                        wildcards.join(", ")
                    ));
                }
            }
            "dns-01" | "dns-persist-01" => {}
            "onion-csr-01" => {
                if args.onion_key.is_none() {
                    return Err("--onion-key is required for onion-csr-01 challenges".to_string());
                }
            }
            "tkauth-01" => {
                if args.tkauth_url.is_none() {
                    return Err("--tkauth-url is required for tkauth-01 challenges".to_string());
                }
                if args.tkauth_keytab.is_none() {
                    return Err("--tkauth-keytab is required for tkauth-01 challenges".to_string());
                }
            }
            other => {
                return Err(format!(
                    "unsupported challenge type '{other}'; supported: http-01, dns-01, dns-persist-01, tls-alpn-01, onion-csr-01, tkauth-01"
                ));
            }
        }
    }

    // Start the http-01 challenge responder only when needed (skip for delegation).
    let solver = if delegation.is_none() && args.challenge_type == "http-01" {
        let s = Http01Solver::new(args.http_port);
        s.start()
            .await
            .map_err(|e| format!("start http-01 solver: {e}"))?;
        Some(s)
    } else {
        None
    };

    // Start the tls-alpn-01 challenge responder only when needed (skip for delegation).
    let mut tls_solver: Option<TlsAlpn01Solver> =
        if delegation.is_none() && args.challenge_type == "tls-alpn-01" {
            let mut s = TlsAlpn01Solver::new(args.tls_port);
            s.start()
                .await
                .map_err(|e| format!("start tls-alpn-01 solver: {e}"))?;
            Some(s)
        } else {
            None
        };

    // Compute the RFC 9447 fingerprint once (needed per-authz for tkauth-01).
    let tkauth_fingerprint: Option<String> =
        if delegation.is_none() && args.challenge_type == "tkauth-01" {
            Some(
                akamu_client::rfc9447_fingerprint(account.thumbprint())
                    .map_err(|e| format!("rfc9447 fingerprint: {e}"))?,
            )
        } else {
            None
        };

    // Place the order.
    let ids: Vec<Identifier> = if using_jwtcc {
        vec![Identifier {
            r#type: "EnhancedJWTClaimConstraints".to_string(),
            value: args.jwtcc.clone().unwrap(),
        }]
    } else {
        args.domains.iter().map(Identifier::dns).collect()
    };
    let order = if let Some(deleg_url) = delegation {
        client
            .new_order_with_delegation(&account, &ids, deleg_url, args.profile.as_deref())
            .await
            .map_err(|e| e.to_string())?
    } else {
        client
            .new_order_with_profile(&account, &ids, args.profile.as_deref())
            .await
            .map_err(|e| e.to_string())?
    };
    // Capture the server-echoed profile (may differ from args.profile if the server
    // auto-selected a default; used when writing the .renewal.toml sidecar).
    let server_profile = order.profile.clone();

    // Delegation orders should have no authorizations.
    if delegation.is_some() && !order.authorizations.is_empty() {
        return Err(
            "delegation order returned authorizations; server may not support RFC 9115".into(),
        );
    }

    // Satisfy all authorizations.
    //
    // Phase 1: prepare (present/deploy) and trigger each challenge.  Manual
    // dns-01 / dns-persist-01 challenges prompt the user per-domain and defer
    // triggering until all TXT records are in place.
    let mut http01_tokens: Vec<String> = Vec::new();
    let mut tls_alpn01_domains: Vec<String> = Vec::new();
    let mut dns01_cleanups: Vec<(String, String, String)> = Vec::new();
    let mut deferred_challenges: Vec<Challenge> = Vec::new();
    let mut pending_authz_urls: Vec<String> = Vec::new();
    let mut any_challenged = false;

    for authz_url in &order.authorizations {
        let authz = client
            .get_authorization(&account, authz_url)
            .await
            .map_err(|e| e.to_string())?;

        if authz.status == "valid" {
            continue; // already satisfied
        }
        pending_authz_urls.push(authz_url.clone());
        any_challenged = true;

        match args.challenge_type.as_str() {
            "http-01" => {
                let challenge = authz.find_challenge("http-01").ok_or_else(|| {
                    format!("no http-01 challenge for {}", authz.identifier.value)
                })?;
                let token = challenge
                    .token
                    .as_deref()
                    .ok_or("challenge missing token")?;
                let key_auth = account.key_authorization(token);

                let s = solver.as_ref().unwrap();
                s.present(token, &key_auth)
                    .await
                    .map_err(|e| e.to_string())?;

                client
                    .trigger_challenge(&account, challenge)
                    .await
                    .map_err(|e| e.to_string())?;

                http01_tokens.push(token.to_string());
            }
            "dns-01" => {
                let challenge = authz
                    .find_challenge("dns-01")
                    .ok_or_else(|| format!("no dns-01 challenge for {}", authz.identifier.value))?;
                let token = challenge
                    .token
                    .as_deref()
                    .ok_or("challenge missing token")?;
                let key_auth = account.key_authorization(token);
                let base_domain = authz.identifier.value.trim_start_matches("*.");

                if let Some(hook) = &args.dns_hook {
                    let s = DnsHookSolver::new(hook.clone());
                    s.deploy(base_domain, token, &key_auth)
                        .await
                        .map_err(|e| format!("dns hook deploy: {e}"))?;
                    client
                        .trigger_challenge(&account, challenge)
                        .await
                        .map_err(|e| e.to_string())?;
                    dns01_cleanups.push((base_domain.to_string(), token.to_string(), key_auth));
                } else {
                    let txt_value = Dns01Helper::txt_value(&key_auth).map_err(|e| e.to_string())?;
                    eprintln!();
                    eprintln!("DNS-01 challenge for {}:", authz.identifier.value);
                    eprintln!("  Name:  _acme-challenge.{}.", base_domain);
                    eprintln!("  Type:  TXT");
                    eprintln!("  Value: {}", txt_value);
                    eprintln!();
                    eprint!(
                        "Press Enter after the TXT record has propagated (Ctrl-C to abort)... "
                    );
                    tokio::task::spawn_blocking(|| -> Result<(), String> {
                        use std::io::{self, BufRead};
                        match io::stdin().lock().lines().next() {
                            Some(Ok(_)) => Ok(()),
                            Some(Err(e)) => Err(format!("dns-01 stdin read error: {e}")),
                            None => Err("stdin closed (EOF) — aborting dns-01 challenge".into()),
                        }
                    })
                    .await
                    .map_err(|e| format!("dns-01 stdin wait: {e}"))??;
                    deferred_challenges.push(challenge.clone());
                }
            }
            "dns-persist-01" => {
                let challenge = authz.find_challenge("dns-persist-01").ok_or_else(|| {
                    format!("no dns-persist-01 challenge for {}", authz.identifier.value)
                })?;
                let issuer_domain = challenge
                    .issuer_domain_names
                    .as_deref()
                    .and_then(|v| v.first())
                    .ok_or_else(|| {
                        format!(
                            "dns-persist-01 challenge for {} has no issuer-domain-names",
                            authz.identifier.value
                        )
                    })?;
                let is_wildcard = authz.identifier.value.starts_with("*.");
                let base_domain = authz.identifier.value.trim_start_matches("*.");
                let txt_record = if is_wildcard {
                    DnsPersist01Helper::txt_record_wildcard(issuer_domain, &account.url)
                } else {
                    DnsPersist01Helper::txt_record(issuer_domain, &account.url)
                };

                if let Some(hook) = &args.dns_hook {
                    let s = DnsHookSolver::new(hook.clone());
                    s.deploy_persist(base_domain, &txt_record)
                        .await
                        .map_err(|e| format!("dns hook deploy: {e}"))?;
                    client
                        .trigger_challenge(&account, challenge)
                        .await
                        .map_err(|e| e.to_string())?;
                } else {
                    eprintln!();
                    eprintln!("DNS-persist-01 challenge for {}:", authz.identifier.value);
                    eprintln!("  Name:  _validation-persist.{}.", base_domain);
                    eprintln!("  Type:  TXT");
                    eprintln!("  Value: {}", txt_record);
                    eprintln!();
                    eprintln!("This is a long-lived TXT record; it only needs to be set once.");
                    eprint!(
                        "Press Enter after the TXT record has propagated (Ctrl-C to abort)... "
                    );
                    tokio::task::spawn_blocking(|| -> Result<(), String> {
                        use std::io::{self, BufRead};
                        match io::stdin().lock().lines().next() {
                            Some(Ok(_)) => Ok(()),
                            Some(Err(e)) => Err(format!("dns-persist-01 stdin read error: {e}")),
                            None => {
                                Err("stdin closed (EOF) — aborting dns-persist-01 challenge".into())
                            }
                        }
                    })
                    .await
                    .map_err(|e| format!("dns-persist-01 stdin wait: {e}"))??;
                    deferred_challenges.push(challenge.clone());
                }
            }
            "tls-alpn-01" => {
                let challenge = authz.find_challenge("tls-alpn-01").ok_or_else(|| {
                    format!("no tls-alpn-01 challenge for {}", authz.identifier.value)
                })?;
                let token = challenge
                    .token
                    .as_deref()
                    .ok_or("challenge missing token")?;
                let key_auth = account.key_authorization(token);

                tls_solver
                    .as_ref()
                    .unwrap()
                    .present(&authz.identifier.value, &authz.identifier.r#type, &key_auth)
                    .await
                    .map_err(|e| format!("tls-alpn-01 present: {e}"))?;

                client
                    .trigger_challenge(&account, challenge)
                    .await
                    .map_err(|e| format!("trigger tls-alpn-01: {e}"))?;

                tls_alpn01_domains.push(authz.identifier.value.clone());
            }
            "onion-csr-01" => {
                let challenge = authz.find_challenge("onion-csr-01").ok_or_else(|| {
                    format!("no onion-csr-01 challenge for {}", authz.identifier.value)
                })?;
                let token = challenge
                    .token
                    .as_deref()
                    .ok_or("challenge missing token")?;
                let key_auth = account.key_authorization(token);

                let onion_key_path = args.onion_key.as_ref().unwrap(); // guarded above
                let hs_pem = std::fs::read(onion_key_path)
                    .map_err(|e| format!("read onion key {}: {e}", onion_key_path.display()))?;
                let csr_der =
                    akamu_client::build_onion_csr(&authz.identifier.value, &key_auth, &hs_pem)
                        .map_err(|e| format!("build onion CSR: {e}"))?;

                client
                    .trigger_challenge_onion(&account, &challenge.url, &csr_der)
                    .await
                    .map_err(|e| format!("trigger onion-csr-01: {e}"))?;
            }
            "tkauth-01" => {
                let challenge = authz.find_challenge("tkauth-01").ok_or_else(|| {
                    format!("no tkauth-01 challenge for {}", authz.identifier.value)
                })?;
                // tkvalue is the ACME identifier value (the JWTClaimConstraints blob),
                // NOT the challenge token.  The TA echoes it in atc.tkvalue; the server
                // checks atc.tkvalue == id_value to bind the token to this order.
                let tkvalue = authz.identifier.value.as_str();
                let ta_url = args.tkauth_url.as_deref().unwrap(); // guarded above
                let keytab = args.tkauth_keytab.as_ref().unwrap(); // guarded above
                let fingerprint = tkauth_fingerprint.as_deref().unwrap(); // set when tkauth-01

                let jwt = akamu_client::fetch_authority_token(
                    ta_url,
                    tkvalue,
                    fingerprint,
                    keytab
                        .to_str()
                        .ok_or("tkauth-keytab path is not valid UTF-8")?,
                )
                .await
                .map_err(|e| format!("fetch authority token: {e}"))?;

                client
                    .trigger_challenge_tkauth(&account, &challenge.url, &jwt)
                    .await
                    .map_err(|e| format!("trigger tkauth-01: {e}"))?;
            }
            _ => unreachable!(),
        }
    }

    // Phase 2 + 3: trigger deferred challenges and poll.  Wrapped so that
    // Phase 4 cleanup always runs regardless of success or failure.
    let poll_result: Result<(), String> = async {
        // Phase 2: trigger deferred challenges (manual dns-01 / dns-persist-01).
        for challenge in &deferred_challenges {
            client
                .trigger_challenge(&account, challenge)
                .await
                .map_err(|e| e.to_string())?;
        }

        // Phase 2b: briefly wait for the ACME server's validation requests
        // before polling (RFC 8555 §7.5.1).  Use a short timeout — the
        // validation request may arrive via a path invisible to the client
        // (proxied, internal, or test environments), so a timeout here is
        // expected and non-fatal; we proceed to poll the authorization
        // regardless.
        let validation_wait = std::time::Duration::from_secs(10);
        if let Some(s) = solver.as_ref() {
            for token in &http01_tokens {
                if s.wait_for_validation(token, validation_wait).await.is_err() {
                    eprintln!(
                        "Note: did not observe http-01 validation request; proceeding to poll"
                    );
                }
            }
        }
        if let Some(s) = tls_solver.as_ref() {
            for domain in &tls_alpn01_domains {
                if s.wait_for_validation(domain, validation_wait)
                    .await
                    .is_err()
                {
                    eprintln!(
                        "Note: did not observe tls-alpn-01 validation request; proceeding to poll"
                    );
                }
            }
        }

        // Phase 3: poll each authorization until valid/invalid (RFC 8555 §7.5.1),
        // then poll the order until "ready".
        let timeout = std::time::Duration::from_secs(args.poll_timeout);
        if any_challenged {
            for authz_url in &pending_authz_urls {
                client
                    .poll_authorization(&account, authz_url, timeout)
                    .await
                    .map_err(|e| e.to_string())?;
            }
            poll_with_timeout(&client, &account, &order.url, args.poll_timeout).await?;
        }
        Ok(())
    }
    .await;

    // Phase 4: cleanup (always runs).
    if let Some(s) = solver.as_ref() {
        for token in &http01_tokens {
            let _ = s.cleanup(token).await;
        }
    }
    if let Some(hook) = &args.dns_hook {
        let s = DnsHookSolver::new(hook.clone());
        for (domain, token, key_auth) in &dns01_cleanups {
            let _ = s.clean(domain, token, key_auth).await;
        }
    }
    if let Some(mut s) = tls_solver.take() {
        s.cleanup();
    }

    poll_result?;

    // Load or generate the certificate private key.
    let cert_key_path: PathBuf = args.cert_key.clone().unwrap_or_else(|| {
        let mut p = out_path.clone();
        let mut name = p.file_name().unwrap_or_default().to_os_string();
        name.push(".key.pem");
        p.set_file_name(name);
        p
    });

    let cert_key = if cert_key_path.exists() {
        akamu_client::AccountKey::from_pem(
            &fs::read(&cert_key_path)
                .map_err(|e| format!("read {}: {e}", cert_key_path.display()))?,
        )
        .map_err(|e| e.to_string())?
    } else {
        let k = akamu_client::AccountKey::generate(&args.cert_key_type)
            .map_err(|e| format!("generate cert key: {e}"))?;
        let pem = k.to_pem().map_err(|e| e.to_string())?;
        write_private_file(&cert_key_path, &pem)?;
        println!("Certificate key saved to {}", cert_key_path.display());
        k
    };

    // Build the CSR.
    let csr_der = if using_jwtcc && args.domains.is_empty() {
        // JWTClaimConstraints-only orders: no DNS SANs in the CSR; the server
        // adds any claim-derived OtherName SANs during finalization.
        akamu_client::build_subject_only_csr("EnhancedJWTClaimConstraints", cert_key.private_key())
            .map_err(|e| e.to_string())?
    } else {
        let domain_refs: Vec<&str> = args.domains.iter().map(String::as_str).collect();
        akamu_client::build_csr(&domain_refs, cert_key.private_key()).map_err(|e| e.to_string())?
    };

    // Finalize and download.
    let order = client
        .finalize(&account, &order, &csr_der)
        .await
        .map_err(|e| e.to_string())?;

    let order = if order.certificate.is_some() {
        order
    } else {
        poll_with_timeout(&client, &account, &order.url, args.poll_timeout).await?
    };

    let cert_url = order
        .certificate
        .as_deref()
        .ok_or("order has no certificate URL after finalization")?;

    let pem = client
        .download_certificate(&account, cert_url)
        .await
        .map_err(|e| e.to_string())?;

    fs::write(&out_path, &pem).map_err(|e| format!("write {}: {e}", out_path.display()))?;
    println!("Certificate written to {}", out_path.display());
    println!("Certificate URL:  {}", cert_url);
    println!("Certificate key:  {}", cert_key_path.display());

    // Write .renewal.toml sidecar so `akamu-cli renew --renewal-config` can reload all settings.
    let renewal_config = RenewalConfig {
        server: args.server.clone(),
        ca: args.ca.clone(),
        domains: ids,
        account_key: account_key_path.clone(),
        account_url: Some(account.url.clone()),
        account_key_type: args.key_type.clone(),
        cert_path: out_path.clone(),
        cert_key_path: cert_key_path.clone(),
        cert_key_type: args.cert_key_type.clone(),
        challenge_type: args.challenge_type.clone(),
        http_port: args.http_port,
        tls_port: args.tls_port,
        onion_key: args.onion_key.clone(),
        poll_timeout: args.poll_timeout,
        contacts: vec![],
        eab_kid: args.eab.eab_kid.clone(),
        eab_key: args.eab.eab_key.clone(),
        eab_alg: args.eab.eab_alg.clone(),
        gssapi_keytab: args.eab.gssapi_keytab.clone(),
        dns_hook: args.dns_hook.clone(),
        profile: args.profile.or(server_profile),
        tkauth_url: args.tkauth_url.clone(),
        tkauth_keytab: args.tkauth_keytab.clone(),
        jwtcc: args.jwtcc.clone(),
    };
    let toml_str = toml::to_string_pretty(&renewal_config)
        .map_err(|e| format!("serialize renewal config: {e}"))?;
    let mut renewal_path = out_path.clone().into_os_string();
    renewal_path.push(".renewal.toml");
    let renewal_path = std::path::PathBuf::from(renewal_path);
    write_private_file(&renewal_path, toml_str.as_bytes())?;
    println!("Renewal config:   {}", renewal_path.display());
    println!(
        "To renew: akamu-cli renew --renewal-config {}",
        renewal_path.display()
    );
    if args.eab.eab_key.is_some() {
        eprintln!(
            "Note: EAB HMAC key is NOT saved in the renewal config for security reasons. \
             Re-supply --eab-key on each renewal."
        );
    }
    Ok(())
}
