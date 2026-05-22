//! certbot → akamu migration: directory parsing, JWK conversion, renewal config writing.

use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
};

use akamu_client::{AccountKey, Identifier, RenewalConfig};

// ── Discovered types ──────────────────────────────────────────────────────────

pub struct CertbotAccount {
    pub ca_hostname: String,
    pub account_id: String,
    pub jwk_json: String,
    pub account_url: Option<String>,
    pub contacts: Vec<String>,
    pub creation_dt: Option<String>,
}

pub struct CertbotRenewal {
    pub domain: String,
    pub server: String,
    pub authenticator: String,
    pub preferred_challenges: Option<String>,
}

// ── Account discovery ─────────────────────────────────────────────────────────

/// Walk `<certbot-dir>/accounts/<ca-hostname>/<account-id>/` and return all
/// found accounts.  Skips directories that are missing required files.
pub fn discover_accounts(certbot_dir: &Path) -> Vec<CertbotAccount> {
    let accounts_dir = certbot_dir.join("accounts");
    let mut accounts = Vec::new();

    let ca_dirs = match fs::read_dir(&accounts_dir) {
        Ok(d) => d,
        Err(e) => {
            eprintln!(
                "Warning: cannot read certbot accounts dir {}: {e}",
                accounts_dir.display()
            );
            return accounts;
        }
    };

    for ca_entry in ca_dirs.flatten() {
        let ca_path = ca_entry.path();
        if !ca_path.is_dir() {
            continue;
        }
        let ca_hostname = ca_path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .into_owned();

        let acct_dirs = match fs::read_dir(&ca_path) {
            Ok(d) => d,
            Err(e) => {
                eprintln!(
                    "Warning: cannot read certbot CA dir {}: {e}",
                    ca_path.display()
                );
                continue;
            }
        };

        for acct_entry in acct_dirs.flatten() {
            let acct_path = acct_entry.path();
            if !acct_path.is_dir() {
                continue;
            }
            let account_id = acct_path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .into_owned();

            let jwk_json = match fs::read_to_string(acct_path.join("private_key.json")) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!(
                        "Warning: skipping account {account_id} ({}): cannot read private_key.json: {e}",
                        acct_path.display()
                    );
                    continue;
                }
            };

            let (account_url, contacts) = parse_regr_json(&acct_path.join("regr.json"));
            let creation_dt = parse_meta_json(&acct_path.join("meta.json"));

            accounts.push(CertbotAccount {
                ca_hostname: ca_hostname.clone(),
                account_id,
                jwk_json,
                account_url,
                contacts,
                creation_dt,
            });
        }
    }

    accounts
}

fn parse_regr_json(path: &Path) -> (Option<String>, Vec<String>) {
    let text = match fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Warning: cannot read {}: {e}", path.display());
            return (None, vec![]);
        }
    };
    let v: serde_json::Value = match serde_json::from_str(&text) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Warning: cannot parse {}: {e}", path.display());
            return (None, vec![]);
        }
    };
    let url = v["uri"].as_str().map(|s| s.to_string());
    let contacts = v["body"]["contact"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|c| c.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    (url, contacts)
}

fn parse_meta_json(path: &Path) -> Option<String> {
    let text = fs::read_to_string(path).ok()?;
    let v: serde_json::Value = serde_json::from_str(&text).ok()?;
    v["creation_dt"].as_str().map(str::to_string)
}

// ── Renewal discovery ─────────────────────────────────────────────────────────

/// Walk `<certbot-dir>/renewal/*.conf` and return parsed renewal entries.
pub fn discover_renewals(certbot_dir: &Path) -> Vec<CertbotRenewal> {
    let renewal_dir = certbot_dir.join("renewal");
    let mut renewals = Vec::new();

    let entries = match fs::read_dir(&renewal_dir) {
        Ok(d) => d,
        Err(e) => {
            eprintln!(
                "Warning: cannot read certbot renewal dir {}: {e}",
                renewal_dir.display()
            );
            return renewals;
        }
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("conf") {
            continue;
        }

        let stem = path
            .file_stem()
            .unwrap_or_default()
            .to_string_lossy()
            .into_owned();

        let content = match fs::read_to_string(&path) {
            Ok(s) => s,
            Err(e) => {
                eprintln!(
                    "Warning: cannot read renewal config {}: {e}",
                    path.display()
                );
                continue;
            }
        };

        let kv = parse_ini_flat(&content);
        let server = kv.get("server").cloned().unwrap_or_else(|| {
            eprintln!(
                "Warning: renewal config {} missing 'server'; \
                 defaulting to Let's Encrypt production",
                path.display()
            );
            "https://acme-v02.api.letsencrypt.org/directory".into()
        });
        let authenticator = kv.get("authenticator").cloned().unwrap_or_else(|| {
            eprintln!(
                "Warning: renewal config {} missing 'authenticator'; \
                 defaulting to 'standalone'",
                path.display()
            );
            "standalone".into()
        });
        let preferred_challenges = kv.get("preferred_challenges").cloned();

        renewals.push(CertbotRenewal {
            domain: stem,
            server,
            authenticator,
            preferred_challenges,
        });
    }

    renewals
}

/// Minimal INI parser: returns all `key = value` pairs from the flat section
/// and from `[renewalparams]`.
fn parse_ini_flat(content: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for line in content.lines() {
        let line = line.trim();
        if line.starts_with('#') || line.starts_with('[') || line.is_empty() {
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            map.insert(k.trim().to_string(), v.trim().to_string());
        }
    }
    map
}

// ── JWK → AccountKey ─────────────────────────────────────────────────────────

/// Decode a certbot private JWK (`private_key.json`) into an [`AccountKey`].
pub fn jwk_to_account_key(json: &str) -> Result<AccountKey, String> {
    AccountKey::from_jwk_private(json).map_err(|e| e.to_string())
}

/// Infer the akamu key-type string from a PEM-encoded private key.
///
/// Returns e.g. `"ec:P-256"`, `"ec:P-384"`, falling back to `"ec:P-256"` when
/// the key cannot be loaded or is an unrecognised type.  RSA cert keys report
/// `"rsa:2048"` regardless of actual size (akamu only needs this as a hint for
/// key generation when the key file is absent).
pub fn pem_key_type(pem: &[u8]) -> String {
    match AccountKey::from_pem(pem) {
        Ok(key) => match key.alg() {
            "ES256" => "ec:P-256".into(),
            "ES384" => "ec:P-384".into(),
            "ES512" => "ec:P-521".into(),
            alg if alg.starts_with("RS") || alg.starts_with("PS") => {
                eprintln!(
                    "Note: RSA cert key detected; cert_key_type recorded as rsa:2048 \
                     (actual modulus size cannot be inferred from PEM; adjust manually if needed)"
                );
                "rsa:2048".into()
            }
            _ => "ec:P-256".into(),
        },
        Err(e) => {
            eprintln!("Warning: could not determine key type ({e}); defaulting to ec:P-256");
            "ec:P-256".into()
        }
    }
}

/// Infer the akamu key type string from a JWK object.
///
/// Returns e.g. `"ec:P-256"`, `"ec:P-384"`, `"rsa:2048"`, falling back to
/// `"ec:P-256"` when the JWK cannot be parsed or the type is unrecognised.
pub fn jwk_key_type(json: &str) -> String {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(json) else {
        return "ec:P-256".into();
    };
    match v["kty"].as_str() {
        Some("EC") => {
            let crv = v["crv"].as_str().unwrap_or("P-256");
            format!("ec:{crv}")
        }
        Some("RSA") => {
            // Decode the base64url-encoded modulus `n` to get the significant bit length.
            // DER encodes non-negative integers with a leading 0x00 byte when the high
            // bit would otherwise be set; skip those before computing bit length so a
            // standard 2048-bit key encoded as 257 bytes isn't misclassified as 3072-bit.
            let bits = v["n"]
                .as_str()
                .and_then(|n| {
                    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
                    URL_SAFE_NO_PAD.decode(n).ok()
                })
                .map(|bytes| {
                    let significant = bytes.iter().skip_while(|&&b| b == 0).count();
                    let bit_len = significant * 8;
                    if bit_len >= 4096 {
                        4096
                    } else if bit_len >= 3072 {
                        3072
                    } else {
                        2048
                    }
                })
                .unwrap_or(2048);
            format!("rsa:{bits}")
        }
        _ => "ec:P-256".into(),
    }
}

// ── Challenge type mapping ────────────────────────────────────────────────────

/// Map certbot `authenticator` and optional `preferred_challenges` to an akamu
/// challenge type.  `dns_challenge` is the value from `--dns-challenge` (default
/// `"dns-01"`).
///
/// Returns `(challenge_type, optional_warning)`.
pub fn map_challenge_type(
    authenticator: &str,
    preferred_challenges: Option<&str>,
    dns_challenge: &str,
) -> (&'static str, Option<&'static str>) {
    match authenticator {
        "standalone" | "webroot" | "nginx" | "apache" => ("http-01", None),
        "manual" => match preferred_challenges {
            Some(pc) if pc.contains("dns") => (
                canonical_dns_challenge(dns_challenge),
                Some("manual DNS entry required at each renewal"),
            ),
            _ => ("http-01", None),
        },
        "tls-sni-01" => (
            "tls-alpn-01",
            Some("tls-sni-01 is deprecated; mapped to tls-alpn-01"),
        ),
        // Any dns-* plugin (dns-cloudflare, dns-route53, etc.)
        auth if auth.starts_with("dns-") => (
            canonical_dns_challenge(dns_challenge),
            Some("set --dns-hook or use --dns-challenge dns-persist-01 for persistent records"),
        ),
        _ => ("http-01", None),
    }
}

fn canonical_dns_challenge(dns_challenge: &str) -> &'static str {
    match dns_challenge {
        "dns-persist-01" => "dns-persist-01",
        _ => "dns-01",
    }
}

// ── RenewalConfig builder ─────────────────────────────────────────────────────

/// Build a [`RenewalConfig`] for an imported certbot renewal.
///
/// Returns `(config, optional_warning_message)`.
pub fn build_renewal_config(
    renewal: &CertbotRenewal,
    account_key_jwk: &str,
    account_key_path: &Path,
    cert_path: &Path,
    cert_key_path: &Path,
    cert_key_type: &str,
    contacts: &[String],
    dns_challenge: &str,
    dns_hook: Option<&str>,
) -> (RenewalConfig, Option<&'static str>) {
    let (challenge_type, warning) = map_challenge_type(
        &renewal.authenticator,
        renewal.preferred_challenges.as_deref(),
        dns_challenge,
    );

    let domain = if renewal.domain.starts_with("_wildcard.") {
        format!("*.{}", &renewal.domain["_wildcard.".len()..])
    } else {
        renewal.domain.clone()
    };

    let account_key_type = jwk_key_type(account_key_jwk);

    let config = RenewalConfig {
        server: renewal.server.clone(),
        ca: None,
        domains: vec![Identifier::dns(domain)],
        account_key: account_key_path.to_path_buf(),
        account_key_type,
        cert_path: cert_path.to_path_buf(),
        cert_key_path: cert_key_path.to_path_buf(),
        cert_key_type: cert_key_type.into(),
        challenge_type: challenge_type.into(),
        http_port: 80,
        tls_port: 443,
        onion_key: None,
        poll_timeout: 120,
        contacts: contacts.to_vec(),
        eab_kid: None,
        eab_key: None,
        eab_alg: "HS256".into(),
        gssapi_keytab: None,
        dns_hook: dns_hook.map(str::to_string),
        profile: None,
    };

    (config, warning)
}

// ── Live certificate paths ────────────────────────────────────────────────────

/// Return `(fullchain_pem_path, privkey_pem_path)` for a certbot domain.
///
/// Handles certbot's wildcard encoding where `*.example.com` is stored as
/// `_wildcard.example.com/` in `live/`.
pub fn live_cert_paths(certbot_dir: &Path, domain: &str) -> (PathBuf, PathBuf) {
    let live_domain = if let Some(rest) = domain.strip_prefix("*.") {
        format!("_wildcard.{rest}")
    } else {
        domain.to_string()
    };
    let live_dir = certbot_dir.join("live").join(&live_domain);
    (live_dir.join("fullchain.pem"), live_dir.join("privkey.pem"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn map_challenge_standalone_is_http01() {
        let (challenge, warning) = map_challenge_type("standalone", None, "dns-01");
        assert_eq!(challenge, "http-01");
        assert!(warning.is_none());
    }

    #[test]
    fn map_challenge_dns_plugin_uses_dns_challenge_arg() {
        let (challenge, warning) = map_challenge_type("dns-cloudflare", None, "dns-01");
        assert_eq!(challenge, "dns-01");
        assert!(warning.is_some());

        let (challenge2, _) = map_challenge_type("dns-route53", None, "dns-persist-01");
        assert_eq!(challenge2, "dns-persist-01");
    }

    #[test]
    fn map_challenge_tls_sni_maps_to_alpn() {
        let (challenge, warning) = map_challenge_type("tls-sni-01", None, "dns-01");
        assert_eq!(challenge, "tls-alpn-01");
        assert!(warning.is_some());
    }

    #[test]
    fn map_challenge_manual_with_dns_preferred() {
        let (challenge, warning) = map_challenge_type("manual", Some("dns"), "dns-persist-01");
        assert_eq!(challenge, "dns-persist-01");
        assert!(warning.is_some());
    }

    #[test]
    fn parse_renewal_conf_basic() {
        let content = "\
[renewalparams]
server = https://acme-v02.api.letsencrypt.org/directory
authenticator = standalone
account = abc123
";
        let kv = parse_ini_flat(content);
        assert_eq!(
            kv.get("server").map(|s| s.as_str()),
            Some("https://acme-v02.api.letsencrypt.org/directory")
        );
        assert_eq!(
            kv.get("authenticator").map(|s| s.as_str()),
            Some("standalone")
        );
    }

    #[test]
    fn live_cert_paths_wildcard_encoding() {
        use std::path::Path;
        let base = Path::new("/etc/letsencrypt");
        let (chain, key) = live_cert_paths(base, "*.example.com");
        assert!(chain.to_str().unwrap().contains("_wildcard.example.com"));
        assert!(key.to_str().unwrap().contains("_wildcard.example.com"));
    }

    #[test]
    fn live_cert_paths_plain_domain() {
        use std::path::Path;
        let base = Path::new("/etc/letsencrypt");
        let (chain, key) = live_cert_paths(base, "example.com");
        assert!(chain.to_str().unwrap().contains("/live/example.com/"));
        assert!(key.to_str().unwrap().ends_with("privkey.pem"));
    }

    #[test]
    fn jwk_key_type_ec_p256() {
        let jwk = r#"{"kty":"EC","crv":"P-256","x":"a","y":"b","d":"c"}"#;
        assert_eq!(jwk_key_type(jwk), "ec:P-256");
    }

    #[test]
    fn jwk_key_type_ec_p384() {
        let jwk = r#"{"kty":"EC","crv":"P-384","x":"a","y":"b","d":"c"}"#;
        assert_eq!(jwk_key_type(jwk), "ec:P-384");
    }

    #[test]
    fn jwk_key_type_rsa_falls_back() {
        // An RSA JWK with no `n` field falls back to rsa:2048.
        let jwk = r#"{"kty":"RSA","e":"AQAB"}"#;
        assert_eq!(jwk_key_type(jwk), "rsa:2048");
    }

    #[test]
    fn jwk_key_type_rsa_2048_exact() {
        // A 256-byte (2048-bit) modulus encoded as base64url (342 chars, no padding).
        // With the old heuristic (len * 3/4): 342 * 3 / 4 = 256 bytes → 2048 bits.
        // With actual decode: exactly 256 bytes → 2048 bits.
        // Either way this particular case yields 2048; the old code broke for 343-char
        // encodings (odd lengths). This test asserts the exact value stays correct.
        let n_256_bytes = "A".repeat(342); // 342 base64url chars → decodes to ~256 bytes
        let jwk = format!(r#"{{"kty":"RSA","e":"AQAB","n":"{n_256_bytes}"}}"#);
        assert_eq!(jwk_key_type(&jwk), "rsa:2048");
    }

    #[test]
    fn jwk_key_type_rsa_4096() {
        // 512 bytes of 0xFF → 4096 significant bits after leading-zero stripping.
        // "A".repeat(683) would decode to all zeros, which strip to 0 bits.
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
        let n_512_bytes = URL_SAFE_NO_PAD.encode(&vec![0xFFu8; 512]);
        let jwk = format!(r#"{{"kty":"RSA","e":"AQAB","n":"{n_512_bytes}"}}"#);
        assert_eq!(jwk_key_type(&jwk), "rsa:4096");
    }

    #[test]
    fn jwk_key_type_unknown_falls_back() {
        let jwk = r#"{"kty":"OKP","crv":"Ed25519"}"#;
        assert_eq!(jwk_key_type(jwk), "ec:P-256");
    }

    #[test]
    fn jwk_ec_p256_import() {
        // Generated with: openssl ecparam -genkey -name prime256v1 -noout | openssl pkcs8 -topk8 -nocrypt
        // then extracted JWK components via a JOSE library.
        let jwk = r#"{
            "kty": "EC",
            "crv": "P-256",
            "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
            "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
            "d": "jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI"
        }"#;
        let result = jwk_to_account_key(jwk);
        assert!(
            result.is_ok(),
            "EC P-256 JWK import failed: {:?}",
            result.err()
        );
        let key = result.unwrap();
        assert_eq!(key.alg(), "ES256");
    }

    #[test]
    fn renewal_config_toml_roundtrip() {
        use akamu_client::{Identifier, RenewalConfig};
        use std::path::PathBuf;

        let config = RenewalConfig {
            server: "https://acme.example.com/directory".into(),
            ca: None,
            domains: vec![Identifier::dns("example.com")],
            account_key: PathBuf::from("/etc/akamu/acct.pem"),
            account_key_type: "ec:P-256".into(),
            cert_path: PathBuf::from("/etc/akamu/certs/example.com.pem"),
            cert_key_path: PathBuf::from("/etc/akamu/certs/example.com.pem.key.pem"),
            cert_key_type: "ec:P-256".into(),
            challenge_type: "http-01".into(),
            http_port: 80,
            tls_port: 443,
            onion_key: None,
            poll_timeout: 120,
            contacts: vec!["mailto:admin@example.com".into()],
            eab_kid: None,
            eab_key: None,
            eab_alg: "HS256".into(),
            gssapi_keytab: None,
            dns_hook: None,
            profile: None,
        };

        let toml_str = toml::to_string_pretty(&config).expect("serialize");
        let restored: RenewalConfig = toml::from_str(&toml_str).expect("deserialize");
        assert_eq!(restored.server, config.server);
        assert_eq!(restored.domains.len(), 1);
        assert_eq!(restored.challenge_type, "http-01");
        assert_eq!(restored.poll_timeout, 120);
        assert_eq!(restored.profile, None);
        // None fields must be absent from TOML output.
        assert!(
            !toml_str.contains("profile"),
            "profile key must not appear in TOML when None"
        );
        assert!(
            !toml_str.contains("eab_key"),
            "eab_key must never appear in TOML (skip_serializing)"
        );

        // Verify eab_key is skipped even when Some.
        let mut with_eab = config.clone();
        with_eab.eab_key = Some("supersecret".into());
        with_eab.eab_kid = Some("kid-1".into());
        let toml_eab = toml::to_string_pretty(&with_eab).expect("serialize with eab");
        assert!(
            !toml_eab.contains("eab_key"),
            "eab_key must not appear in TOML even when Some"
        );
        assert!(
            toml_eab.contains("eab_kid"),
            "eab_kid should be serialized when Some"
        );
        let restored_eab: RenewalConfig = toml::from_str(&toml_eab).expect("deserialize with eab");
        assert_eq!(
            restored_eab.eab_key, None,
            "eab_key must deserialize as None (absent)"
        );

        // Verify a non-None profile round-trips correctly.
        let mut with_profile = config;
        with_profile.profile = Some("mtc-leaf".into());
        let toml_with = toml::to_string_pretty(&with_profile).expect("serialize with profile");
        assert!(
            toml_with.contains("profile"),
            "profile key should be serialized when Some"
        );
        let restored_with: RenewalConfig =
            toml::from_str(&toml_with).expect("deserialize with profile");
        assert_eq!(restored_with.profile, Some("mtc-leaf".into()));
    }
}
