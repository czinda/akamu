//! ACME server binary entry point.
//!
//! Usage: `akamu [/path/to/config.toml]`
//! Defaults to `config.toml` in the current working directory.

use std::sync::Arc;

use tracing_subscriber::EnvFilter;

use akamu::config::{Config, MtcSigningKeyConfig};
use akamu::journal::JournalWriter;
use akamu::listen::{parse_listen_target, remove_stale_socket, uds_marker_layer, ListenTarget};
use akamu::state::{
    AppStateBuilder, CaState, CrlCache, MtcState, NonceBucket, SigningBackend, TlsState,
};
use akamu::{ca, db, delegation_upstream, mtc, routes, star};
use indexmap::IndexMap;

use akamu::gossip;

#[tokio::main]
async fn main() {
    // ── Logging ───────────────────────────────────────────────────────────────
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    if let Err(e) = run().await {
        tracing::error!("fatal: {e}");
        std::process::exit(1);
    }
}

/// Derive a stable node identity string from a signing public key's SPKI DER.
///
/// Uses the RFC 7093 Method 1 key identifier (leftmost 20 bytes of SHA-256
/// of the BIT STRING value) then base64url-encodes the result.  This gives a
/// stable 28-character string that changes only when the node re-generates its
/// signing key.
fn derive_node_id(spki_der: &[u8]) -> Option<String> {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    let aki = ca::init::compute_aki_from_spki(spki_der)?;
    Some(URL_SAFE_NO_PAD.encode(&aki))
}

/// Load or auto-generate the dedicated MTC signing key.
///
/// Reuses `generate_backend_key` and `BackendPrivateKey::from_pem` from the CA
/// key loading path.  The file is created with the same PEM format.
fn load_or_generate_mtc_key(
    cfg: &MtcSigningKeyConfig,
) -> Result<synta_certificate::BackendPrivateKey, String> {
    use std::path::Path;
    use synta_certificate::BackendPrivateKey;

    if Path::new(&cfg.key_file).exists() {
        let pem = std::fs::read(&cfg.key_file)
            .map_err(|e| format!("read MTC signing key '{}': {e}", cfg.key_file))?;
        BackendPrivateKey::from_pem(&pem, None)
            .map_err(|e| format!("parse MTC signing key '{}': {e}", cfg.key_file))
    } else {
        tracing::info!(
            "generating new MTC signing key ({}) → {}",
            cfg.key_type,
            cfg.key_file
        );
        let key = ca::init::generate_backend_key(&cfg.key_type)
            .map_err(|e| format!("generate MTC signing key: {e}"))?;
        let pem = key
            .to_pem(None)
            .map_err(|e| format!("MTC signing key to PEM: {e}"))?;
        akamu::util::write_key_file(&cfg.key_file, &pem)
            .map_err(|e| format!("write MTC signing key '{}': {e}", cfg.key_file))?;
        Ok(key)
    }
}

fn init_mtc_for_ca(
    ca_id: &str,
    mtc_cfg: &akamu::config::MtcConfig,
) -> Result<Arc<MtcState>, String> {
    use std::sync::atomic::AtomicI64;

    let mtc_algorithm: synta_mtc::crypto::HashAlgorithm = mtc_cfg
        .hash_alg
        .parse()
        .map_err(|e| format!("CA '{ca_id}': invalid mtc.hash_alg: {e}"))?;

    let (mtc_signing_key, mtc_signing_hash_alg) = if let Some(ref sk_cfg) = mtc_cfg.signing_key {
        tracing::info!(ca_id, "loading MTC signing key from '{}'", sk_cfg.key_file);
        let key = load_or_generate_mtc_key(sk_cfg)?;
        (Some(key), sk_cfg.hash_alg.clone())
    } else {
        (None, "sha256".to_string())
    };

    let cosigner_clients: Vec<_> = mtc_cfg
        .cosigners
        .iter()
        .filter_map(|c| match mtc::cosign::build_cosigner_client(c) {
            Ok(client) => Some(client),
            Err(e) => {
                tracing::warn!(ca_id, url = %c.url, "build cosigner client: {e}");
                None
            }
        })
        .collect();

    tracing::info!(ca_id, "opening MTC log at '{}'", mtc_cfg.log_path);
    let log_lock = mtc::log::acquire_log_lock(&mtc_cfg.log_path).map_err(|e| format!("{e}"))?;
    let log = mtc::log::open_or_create(&mtc_cfg.log_path, mtc_algorithm)
        .map_err(|e| format!("CA '{ca_id}': MTC log init: {e}"))?;
    let file_alg = log.algorithm();
    if file_alg != mtc_algorithm {
        return Err(format!(
            "CA '{ca_id}': MTC log file '{}' was created with {} but config specifies {}; \
             delete the log file to recreate with the new algorithm",
            mtc_cfg.log_path, file_alg, mtc_algorithm,
        ));
    }
    let trust_anchor_id_der = mtc_cfg
        .trust_anchor_id
        .as_deref()
        .map(|oid_str| {
            use synta::traits::Encode;
            let oid: synta::RelativeOid = oid_str.parse().map_err(|e| {
                format!("CA '{ca_id}': invalid mtc.trust_anchor_id ROID '{oid_str}': {e}")
            })?;
            let mut enc = synta::Encoder::new(synta::Encoding::Der);
            oid.encode(&mut enc)
                .map_err(|e| format!("CA '{ca_id}': encode trust_anchor_id OID: {e}"))?;
            enc.finish()
                .map_err(|e| format!("CA '{ca_id}': finish trust_anchor_id OID DER: {e}"))
        })
        .transpose()?;

    let logid_issuer_dn_der = if let Some(ref key) = mtc_signing_key {
        let spki_der = key
            .public_key()
            .map_err(|e| format!("CA '{ca_id}': MTC signing key SPKI: {e}"))?
            .spki_der()
            .to_vec();
        Some(
            mtc::standalone::build_logid_issuer_dn_der(&spki_der, mtc_algorithm)
                .map_err(|e| format!("CA '{ca_id}': build LogID issuer DN: {e}"))?,
        )
    } else {
        None
    };

    if trust_anchor_id_der.is_none() && mtc_cfg.enabled {
        tracing::warn!(
            ca_id,
            "MTC enabled but mtc.trust_anchor_id is not set; \
             CA self-cosignature will not be produced (§5.4 requires it)"
        );
    }

    let shared = Arc::new(tokio::sync::Mutex::new(log));
    Ok(Arc::new(MtcState {
        log: Some(shared),
        algorithm: mtc_algorithm,
        signing_key: mtc_signing_key,
        signing_hash_alg: mtc_signing_hash_alg,
        cosigner_clients,
        _log_lock: Some(log_lock),
        checkpoint_interval_secs: mtc_cfg.checkpoint_interval_secs,
        checkpoint_retention_count: mtc_cfg.checkpoint_retention_count,
        landmark_interval_secs: mtc_cfg.landmark_interval_secs,
        max_active_landmarks: mtc_cfg.max_active_landmarks,
        log_number: mtc_cfg.log_number,
        tree_minimum_index: mtc_cfg.tree_minimum_index,
        trust_anchor_id_der,
        logid_issuer_dn_der,
        last_checkpoint: AtomicI64::new(0),
        last_landmark: AtomicI64::new(0),
    }))
}

fn derive_crdt_db_url(main_url: &str) -> String {
    if main_url.contains(":memory:") {
        return "sqlite::memory:".to_string();
    }
    // sqlite:///absolute/path/akamu.db  →  sqlite:///absolute/path/akamu_crdt.db
    // sqlite:relative.db                →  sqlite:relative_crdt.db
    if main_url.starts_with("sqlite:") {
        if let Some(path) = main_url.strip_prefix("sqlite:") {
            if let Some(stem) = path.strip_suffix(".db") {
                return format!("sqlite:{stem}_crdt.db");
            }
        }
    }
    // Non-SQLite or unrecognised format: reuse same URL with a separate pool.
    main_url.to_string()
}

async fn run() -> Result<(), String> {
    // ── Configuration ─────────────────────────────────────────────────────────
    let config_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "config.toml".to_string());

    tracing::info!("loading config from '{config_path}'");
    let config = Config::from_file(&config_path)?;

    // Set GSS_USE_PROXY before the first GSSAPI call so MIT Kerberos intercepts
    // gss_acquire_cred_from() via gssproxy.  No krb5/GSSAPI C library thread exists
    // yet at this point in startup, so the write is not concurrent with any getenv.
    let needs_gssproxy = config.server.gssapi.as_ref().is_some_and(|g| g.gssproxy)
        || config
            .admin
            .as_ref()
            .and_then(|a| a.gssapi.as_ref())
            .is_some_and(|g| g.gssproxy);
    if needs_gssproxy {
        // SAFETY: no krb5/GSSAPI C library thread has been created yet; the only
        // concurrent threads are tokio worker threads, which do not call getenv.
        unsafe { std::env::set_var("GSS_USE_PROXY", "yes") };
        tracing::info!("gssproxy mode enabled: GSS_USE_PROXY=yes");
    }

    // CA/B Forum BR §7.1.3.2.1: SHA-1 prohibited in certificate/CRL signatures since 2026-09-15.
    // CA/B Forum BR §6.3.2 validity caps: 200 days since 2026-03-15, 100 from 2027-03-15.
    for ca_cfg in &config.cas {
        let alg = ca_cfg.hash_alg.to_lowercase();
        if alg == "sha1" || alg == "sha-1" {
            return Err(format!(
                "ca[{}].hash_alg='{}' is prohibited by CA/B Forum BR §7.1.3.2.1 \
                 (SHA-1 sunset 2026-09-15); use 'sha256', 'sha384', or 'sha512'",
                ca_cfg.id, ca_cfg.hash_alg
            ));
        }
        if ca_cfg.validity_days > 200 {
            tracing::warn!(
                "ca[{}].validity_days={} exceeds the 200-day CA/B Forum BR limit \
                 (§6.3.2, since 2026-03-15); certificates issued by this CA cannot \
                 be used in public WebPKI chains",
                ca_cfg.id,
                ca_cfg.validity_days
            );
        } else if ca_cfg.validity_days > 100 {
            tracing::warn!(
                "ca[{}].validity_days={} will exceed the upcoming 100-day CA/B Forum \
                 BR limit (§6.3.2, from 2027-03-15)",
                ca_cfg.id,
                ca_cfg.validity_days
            );
        }
    }

    if config.server.account_scope == "ca" {
        return Err("server.account_scope = \"ca\" is not yet supported; \
             remove the setting or set it to \"server\" to start the server."
            .to_string());
    }

    let config = Arc::new(config);

    // ── Database ──────────────────────────────────────────────────────────────
    db::install_drivers();
    let db_kind = db::DbKind::from_url(&config.database.url);
    let max_connections = config.database.max_connections.unwrap_or(match db_kind {
        db::DbKind::Sqlite => 1,
        _ => 10,
    });
    tracing::info!("opening database '{}'", config.database.url);
    let db = db::open(
        &config.database.url,
        max_connections,
        config.database.require_tls,
    )
    .await
    .map_err(|e| format!("database init: {e}"))?;

    let db_ro = match db::open_ro(&config.database.url, 4)
        .await
        .map_err(|e| format!("read-only database pool: {e}"))?
    {
        Some(ro) => {
            tracing::info!("opened read-only pool (4 connections)");
            ro
        }
        None => db.clone(),
    };

    let write_coalescer =
        if db_kind == db::DbKind::Sqlite && !config.database.url.contains(":memory:") {
            match db::coalescer::WriteCoalescer::new(&config.database.url).await {
                Ok(c) => {
                    tracing::info!("write coalescer active (SQLite batching)");
                    Some(std::sync::Arc::new(c))
                }
                Err(e) => {
                    tracing::warn!("write coalescer init failed, using pool: {e}");
                    None
                }
            }
        } else {
            None
        };

    // Sweep DB nonces older than 24 h at startup (best-effort; handles any
    // nonces written by a previous process that used the DB-backed store).
    let _ = db::nonces::sweep_expired(&db, 86400).await;

    // ── CRDT database (separate pool for cluster tables) ─────────────────────
    // Derive the CRDT DB URL from config or from the main DB URL by appending
    // `_crdt` before the `.db` extension (SQLite only).  For `:memory:` the
    // CRDT DB is also in-memory; for non-SQLite backends the same URL is used
    // with a separate pool (contention benefit still applies via independent
    // connection management).
    let crdt_db_url = config
        .crdt_db_url
        .clone()
        .unwrap_or_else(|| derive_crdt_db_url(&config.database.url));
    let crdt_db = akamu_crdt::db::open_crdt_db(&crdt_db_url)
        .await
        .map_err(|e| format!("CRDT database init: {e}"))?;
    tracing::info!(url = %crdt_db_url, "CRDT database opened");

    // ── CRDT node identity bootstrap ──────────────────────────────────────────
    // Tell the CRDT DB layer which SQL placeholder style to use.
    akamu_crdt::db::init_db_kind(
        matches!(db_kind, db::DbKind::Postgres),
        matches!(db_kind, db::DbKind::MariaDb),
    );

    // Load or generate the node's gossip key material.
    //
    // The signing private key is stored as PEM bytes (BackendPrivateKey serialisation).
    // The KEM private key is stored as PKCS8 DER (native_ossl format).
    // The signing certificate is a minimal self-signed X.509 v3 DER for CMS embedding.
    //
    // A stable `node_id` is derived from the signing public key SPKI DER so the
    // identity survives restarts without storing a separate UUID.
    const LOCAL_KEY: &str = "local";

    struct NodeGossipKeys {
        node_id: String,
        kem_priv_pkcs8: Vec<u8>,
        sign_priv_pem: Vec<u8>,
        sign_cert_der: Vec<u8>,
    }

    let node_keys: NodeGossipKeys = {
        let maybe_row = akamu_crdt::db::load_node_keys(&crdt_db, LOCAL_KEY)
            .await
            .map_err(|e| format!("load node keys: {e}"))?;

        // Helper: build a minimal self-signed cert for a PEM-encoded signing key.
        let build_sign_cert = |sign_priv_pem: &[u8], nid: &str| -> Result<Vec<u8>, String> {
            let sign_key =
                native_ossl::pkey::Pkey::<native_ossl::pkey::Private>::from_pem(sign_priv_pem)
                    .map_err(|e| format!("load signing key from PEM: {e}"))?;
            let mut name =
                native_ossl::x509::X509NameOwned::new().map_err(|e| format!("X509Name: {e}"))?;
            name.add_entry_by_txt(c"CN", nid.as_bytes())
                .map_err(|e| format!("X509Name add CN: {e}"))?;
            let serial: i64 = {
                let mut buf = [0u8; 7]; // 7 bytes → 56-bit positive i64
                native_ossl::rand::Rand::fill(&mut buf)
                    .map_err(|e| format!("getrandom for cert serial: {e}"))?;
                buf.iter().fold(0i64, |acc, &b| (acc << 8) | i64::from(b))
            };
            let cert = native_ossl::x509::X509Builder::new()
                .map_err(|e| format!("X509Builder: {e}"))?
                .set_version(2)
                .map_err(|e| format!("X509Builder version: {e}"))?
                .set_serial_number(serial)
                .map_err(|e| format!("X509Builder serial: {e}"))?
                .set_not_before_offset(0)
                .map_err(|e| format!("X509Builder not_before: {e}"))?
                .set_not_after_offset(2 * 365 * 86400)
                .map_err(|e| format!("X509Builder not_after: {e}"))?
                .set_subject_name(&name)
                .map_err(|e| format!("X509Builder subject: {e}"))?
                .set_issuer_name(&name)
                .map_err(|e| format!("X509Builder issuer: {e}"))?
                .set_public_key(&sign_key)
                .map_err(|e| format!("X509Builder pubkey: {e}"))?
                .sign(&sign_key, None)
                .map_err(|e| format!("X509Builder sign: {e}"))?
                .build()
                .to_der()
                .map_err(|e| format!("X509 to_der: {e}"))?;
            Ok(cert)
        };

        if let Some(row) = maybe_row {
            let nid = derive_node_id(&row.signing_public_key_der)
                .ok_or_else(|| "could not derive node_id from stored signing key".to_string())?;

            // Upgrade nodes that were bootstrapped before Phase 4: a real KEM key
            // is >100 bytes; the old placeholder was 32 random bytes.
            let (kem_priv, kem_pub) = if row.kem_private_key_der.len() > 100 {
                (
                    row.kem_private_key_der.clone(),
                    row.kem_public_key_der.clone(),
                )
            } else {
                tracing::info!("upgrading node KEM key to ML-KEM-768");
                let kem_key = native_ossl::pkey::KeygenCtx::new(c"ML-KEM-768")
                    .map_err(|e| format!("ML-KEM-768 keygen ctx: {e}"))?
                    .generate()
                    .map_err(|e| format!("ML-KEM-768 keygen: {e}"))?;
                let priv_der = kem_key
                    .to_pkcs8_der()
                    .map_err(|e| format!("ML-KEM-768 pkcs8: {e}"))?;
                let pub_spki = kem_key
                    .public_key_to_der()
                    .map_err(|e| format!("ML-KEM-768 spki: {e}"))?;
                (priv_der, pub_spki)
            };

            let sign_cert = if row.signing_certificate_der.is_empty() {
                tracing::info!("generating self-signed gossip signing certificate");
                build_sign_cert(&row.signing_private_key_der, &nid)?
            } else {
                row.signing_certificate_der.clone()
            };

            // Persist upgrade if anything changed.
            if kem_priv != row.kem_private_key_der || sign_cert != row.signing_certificate_der {
                akamu_crdt::db::save_node_keys(
                    &crdt_db,
                    &akamu_crdt::db::NodeKeysRow {
                        node_id: LOCAL_KEY.to_string(),
                        kem_private_key_der: kem_priv.clone(),
                        kem_public_key_der: kem_pub.clone(),
                        signing_private_key_der: row.signing_private_key_der.clone(),
                        signing_public_key_der: row.signing_public_key_der.clone(),
                        signing_certificate_der: sign_cert.clone(),
                        created_at: row.created_at,
                    },
                )
                .await
                .map_err(|e| format!("upgrade node keys: {e}"))?;
            }

            NodeGossipKeys {
                node_id: nid,
                kem_priv_pkcs8: kem_priv,
                sign_priv_pem: row.signing_private_key_der,
                sign_cert_der: sign_cert,
            }
        } else {
            tracing::info!("generating new node gossip keys (ec:P-256 + ML-KEM-768)");

            let sign_key = ca::init::generate_backend_key("ec:P-256")
                .map_err(|e| format!("node signing key gen: {e}"))?;
            let sign_pub = sign_key
                .public_key()
                .map_err(|e| format!("node signing pub key: {e}"))?;
            let sign_pub_der = sign_pub.spki_der().to_vec();
            let sign_priv_pem = sign_key
                .to_pem(None)
                .map_err(|e| format!("node signing key to PEM: {e}"))?;

            let nid = derive_node_id(&sign_pub_der)
                .ok_or_else(|| "could not derive node_id from new signing key".to_string())?;
            tracing::info!(node_id = %nid, "new node identity assigned");

            let kem_key = native_ossl::pkey::KeygenCtx::new(c"ML-KEM-768")
                .map_err(|e| format!("ML-KEM-768 keygen ctx: {e}"))?
                .generate()
                .map_err(|e| format!("ML-KEM-768 keygen: {e}"))?;
            let kem_priv_pkcs8 = kem_key
                .to_pkcs8_der()
                .map_err(|e| format!("ML-KEM-768 pkcs8: {e}"))?;
            let kem_pub_spki = kem_key
                .public_key_to_der()
                .map_err(|e| format!("ML-KEM-768 spki: {e}"))?;

            let sign_cert_der = build_sign_cert(&sign_priv_pem, &nid)?;

            let created_at = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64;

            akamu_crdt::db::save_node_keys(
                &crdt_db,
                &akamu_crdt::db::NodeKeysRow {
                    node_id: LOCAL_KEY.to_string(),
                    kem_private_key_der: kem_priv_pkcs8.clone(),
                    kem_public_key_der: kem_pub_spki.clone(),
                    signing_private_key_der: sign_priv_pem.clone(),
                    signing_public_key_der: sign_pub_der.clone(),
                    signing_certificate_der: sign_cert_der.clone(),
                    created_at,
                },
            )
            .await
            .map_err(|e| format!("save node keys: {e}"))?;

            NodeGossipKeys {
                node_id: nid,
                kem_priv_pkcs8,
                sign_priv_pem,
                sign_cert_der,
            }
        }
    };

    // C-4: node private keys are stored unencrypted (PKCS#8 plaintext) in the
    // local DB.  In a production deployment the DB file should reside on an
    // encrypted volume.  HSM-backed key storage is not yet supported.
    tracing::warn!(
        "gossip node private keys are stored as plaintext PKCS#8 in the local DB — \
         ensure the database file resides on an encrypted volume"
    );

    // Load CRDT state from the local DB, then insert/refresh this node's own
    // entry so delta gossip can identify which entries originated here.
    let crdt_initial = akamu_crdt::db::load_from_db(&db, &crdt_db, &node_keys.node_id)
        .await
        .map_err(|e| format!("CRDT load from DB: {e}"))?;
    // Seed the process-global generation counter from the highest local_gen
    // persisted in the DB.  Without this, CRDT_GENERATION starts at 0 after
    // every restart, so the first gossip round after restart includes every
    // entry (local_gen > 0 = CRDT_GENERATION), forcing a full-state push
    // instead of a minimal delta.
    let max_gen = crdt_initial.max_local_gen();
    if max_gen > 0 {
        akamu_crdt::CRDT_GENERATION.fetch_max(max_gen, std::sync::atomic::Ordering::Release);
    }
    let crdt = std::sync::Arc::new(tokio::sync::RwLock::new(crdt_initial));
    let node_id = std::sync::Arc::new(node_keys.node_id.clone());
    tracing::info!(node_id = %node_id, crdt_gen = max_gen, "CRDT state loaded from DB");

    // Seed EAB keys from config into the DB (INSERT OR IGNORE — never overwrites
    // keys that were provisioned or consumed by the runtime admin endpoint).
    let now_ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    for (kid, hmac_key_b64u) in &config.server.eab_keys {
        if let Err(e) =
            db::eab::insert_if_absent(&db, kid, hmac_key_b64u, now_ts, None, "sha256").await
        {
            tracing::warn!("failed to seed EAB key '{kid}': {e}");
        }
    }
    if !config.server.eab_keys.is_empty() {
        tracing::info!(
            "seeded {} EAB key(s) from config",
            config.server.eab_keys.len()
        );
    }

    // ── CA keys and certificates (one per [[ca]] entry) ───────────────────────
    let mut cas_map: IndexMap<String, Arc<CaState>> = IndexMap::new();
    let mut crl_caches_map: std::collections::HashMap<String, CrlCache> =
        std::collections::HashMap::new();

    for ca_cfg in &config.cas {
        // Build the signing backend and load the CA certificate.
        let (signing, ca_cert_der, ca_aki_bytes) = if ca_cfg.is_external_signer() {
            // Dogtag backend: cert_file is the Dogtag CA chain, no local key.
            let dogtag_cfg = match &ca_cfg.signer {
                Some(akamu::config::SignerConfig::Dogtag(cfg)) => cfg,
                _ => {
                    return Err(format!(
                        "CA '{}': is_external_signer() true but signer is not Dogtag",
                        ca_cfg.id
                    ));
                }
            };
            tracing::info!(
                "loading Dogtag-backed CA '{}' (url={})",
                ca_cfg.id,
                dogtag_cfg.url
            );
            let signer = ca::dogtag::DogtagSigner::new(dogtag_cfg)
                .map_err(|e| format!("CA '{}' Dogtag init: {e}", ca_cfg.id))?;
            signer.probe().await;

            let cert_pem = std::fs::read(&ca_cfg.cert_file)
                .map_err(|e| format!("CA '{}' cert: {e}", ca_cfg.id))?;
            let cert_der = synta_certificate::pem_to_der(&cert_pem)
                .into_iter()
                .next()
                .ok_or_else(|| format!("CA '{}': cert_file has no PEM blocks", ca_cfg.id))?;

            // Extract SPKI from the CA certificate (no local key to derive from).
            let spki_der = ca::init::extract_spki_from_cert_der(&cert_der)
                .ok_or_else(|| format!("CA '{}': cannot extract SPKI from cert", ca_cfg.id))?;
            let aki_bytes = ca::init::compute_aki_from_spki(&spki_der)
                .ok_or_else(|| format!("CA '{}': cannot compute AKI from cert SPKI", ca_cfg.id))?;

            (
                SigningBackend::Dogtag(Arc::new(signer)),
                cert_der,
                aki_bytes,
            )
        } else {
            // Local signing backend.
            tracing::info!(
                "loading CA '{}' from '{}'",
                ca_cfg.id,
                ca_cfg.key_file.as_deref().unwrap_or("<none>")
            );
            let (ca_key, cert_der) = ca::init::load_or_generate(ca_cfg)
                .map_err(|e| format!("CA '{}' init: {e}", ca_cfg.id))?;

            let spki_der = ca_key
                .public_key()
                .map_err(|e| format!("CA '{}' public key: {e}", ca_cfg.id))?
                .spki_der()
                .to_vec();
            let aki_bytes = ca::init::compute_aki_from_spki(&spki_der)
                .ok_or_else(|| format!("CA '{}': cannot compute AKI from SPKI", ca_cfg.id))?;

            (
                SigningBackend::Local {
                    key: Box::new(ca_key),
                },
                cert_der,
                aki_bytes,
            )
        };

        // Derive CRL/OCSP URLs if not set explicitly in config.
        // Dogtag CAs cannot serve CRL/OCSP locally (no signing key), so skip
        // auto-derivation — the operator must configure explicit URLs pointing
        // to Dogtag's own CRL/OCSP endpoints.
        let crl_url = ca_cfg.crl_url.clone().or_else(|| {
            if ca_cfg.is_external_signer() {
                return None;
            }
            if ca_cfg.is_default {
                Some(format!("{}/ca/crl", config.base_url))
            } else {
                Some(format!("{}/ca/{}/crl", config.base_url, ca_cfg.id))
            }
        });
        let ocsp_url = ca_cfg.ocsp_url.clone().or_else(|| {
            if ca_cfg.is_external_signer() {
                return None;
            }
            if ca_cfg.is_default {
                Some(format!("{}/ca/ocsp", config.base_url))
            } else {
                Some(format!("{}/ca/{}/ocsp", config.base_url, ca_cfg.id))
            }
        });

        // Per-CA MTC init: use [ca.mtc] if present, else fall back to global [mtc].
        let effective_mtc = ca_cfg.mtc.as_ref().or(config.mtc.as_ref());
        let ca_mtc = if let Some(mtc_cfg) = effective_mtc {
            if mtc_cfg.enabled {
                init_mtc_for_ca(&ca_cfg.id, mtc_cfg)?
            } else {
                Arc::new(MtcState::disabled())
            }
        } else {
            Arc::new(MtcState::disabled())
        };

        let ca_state = Arc::new(CaState {
            id: ca_cfg.id.clone(),
            key_type: ca_cfg.key_type.clone(),
            signing,
            cert_der: ca_cert_der,
            hash_alg: ca_cfg.hash_alg.clone(),
            validity_days: ca_cfg.validity_days,
            crl_url,
            ocsp_url,
            aki_bytes: ca_aki_bytes,
            enforce_validity_cap: ca_cfg.enforce_validity_cap,
            crl_next_update_secs: ca_cfg.crl_next_update_secs,
            caa_identities: ca_cfg.caa_identities.clone(),
            mtc: ca_mtc,
        });
        crl_caches_map.insert(ca_cfg.id.clone(), Default::default());
        cas_map.insert(ca_cfg.id.clone(), ca_state);
    }

    let default_ca_id = config
        .cas
        .iter()
        .find(|c| c.is_default)
        .map(|c| c.id.clone())
        .unwrap_or_else(|| config.cas[0].id.clone());

    // Convenience alias for the default CA (used by code not yet updated to
    // look up the CA from the request context).
    let ca = cas_map
        .get(&default_ca_id)
        .expect("default CA present in map")
        .clone();

    // ── Certificate profile registry ──────────────────────────────────────────
    let profile_registry = if config.profiles.providers.is_empty() {
        tracing::info!("profiles: no providers configured; using CA defaults for all orders");
        akamu::profiles::ProfileRegistry::empty(&ca)
    } else {
        tracing::info!(
            "profiles: loading from {} provider(s)",
            config.profiles.providers.len()
        );
        akamu::profiles::ProfileRegistry::new(&config.profiles, &ca)
            .await
            .map_err(|e| format!("profile registry init: {e}"))?
    };

    // ── TLS bootstrap (auto-generate cert/key if absent) ─────────────────────
    if config.tls.enabled {
        if !ca.has_local_key() {
            return Err(format!(
                "TLS is enabled but the default CA '{}' uses an external signer; \
                 TLS bootstrap requires a CA with a local signing key",
                default_ca_id
            ));
        }
        akamu::tls::init::load_or_generate(&config.tls, &ca)
            .map_err(|e| format!("TLS init: {e}"))?;
    }

    // ── Admin bootstrap ───────────────────────────────────────────────────────
    if let Some(ref admin_cfg) = config.admin {
        if !ca.has_local_key() {
            return Err(format!(
                "admin API is configured but the default CA '{}' uses an external signer; \
                 admin certificate bootstrap requires a CA with a local signing key",
                default_ca_id
            ));
        }
        admin_cfg
            .validate()
            .map_err(|e| format!("admin config: {e}"))?;
        akamu::admin::init::bootstrap_operator_if_needed(admin_cfg, &ca, &db)
            .await
            .map_err(|e| format!("admin operator bootstrap: {e}"))?;
    }

    // Deprecation warning for global [mtc] section.
    if config.mtc.is_some() {
        let any_per_ca = config.cas.iter().any(|c| c.mtc.is_some());
        if !any_per_ca {
            tracing::warn!(
                "global [mtc] section is deprecated; move MTC config into each [[ca]] \
                 block as [ca.mtc].  The global section is used as a fallback for CAs \
                 without [ca.mtc]."
            );
        }
    }

    // ── TLS state (lean; heavy OwnedStore lives inside SyntaClientCertVerifier) ─
    let tls_state = if config.tls.enabled {
        config.tls.client_auth.as_ref().map(|client_auth| {
            Arc::new(TlsState {
                client_auth_config: client_auth.clone(),
            })
        })
    } else {
        None
    };

    // ── GSSAPI server credential ──────────────────────────────────────────────
    if !config.server.trusted_proxies.is_empty() && config.server.gssapi.is_some() {
        return Err(
            "server.trusted_proxies and server.gssapi cannot both be configured; \
             they are mutually exclusive authentication mechanisms"
                .into(),
        );
    }

    let gss_cred = if let Some(ref gcfg) = config.server.gssapi {
        tracing::info!(
            "initializing GSSAPI credential for service '{}'",
            gcfg.service_name
        );
        if !config.tls.enabled {
            tracing::warn!(
                "GSSAPI is configured without TLS; SPNEGO tokens are not protected against \
                 interception or relay attacks — enable TLS or use a TLS-terminating proxy"
            );
        }
        let cred = if gcfg.gssproxy {
            tracing::info!("acquiring GSSAPI credential via gssproxy");
            akamu_gssapi::GssServerCred::from_gssproxy(&gcfg.service_name)
                .map_err(|e| format!("GSSAPI credential init (gssproxy): {e}"))?
        } else {
            let keytab = gcfg
                .keytab_file
                .as_deref()
                .ok_or("[server.gssapi]: keytab_file is required when gssproxy = false")?;
            tracing::info!("acquiring GSSAPI credential from keytab: '{keytab}'");
            akamu_gssapi::GssServerCred::acquire(&gcfg.service_name, keytab)
                .map_err(|e| format!("GSSAPI credential init: {e}"))?
        };
        Some(Arc::new(cred))
    } else {
        None
    };

    // ── Admin-specific GSSAPI credential ──────────────────────────────────────
    let admin_gss_cred = if let Some(ref admin_cfg) = config.admin {
        if let Some(ref gcfg) = admin_cfg.gssapi {
            tracing::info!(
                "initializing admin GSSAPI credential for service '{}'",
                gcfg.service_name
            );
            let cred = if gcfg.gssproxy {
                tracing::info!("acquiring admin GSSAPI credential via gssproxy");
                akamu_gssapi::GssServerCred::from_gssproxy(&gcfg.service_name)
                    .map_err(|e| format!("admin GSSAPI credential init (gssproxy): {e}"))?
            } else {
                let keytab = gcfg
                    .keytab_file
                    .as_deref()
                    .ok_or("[admin.gssapi]: keytab_file is required when gssproxy = false")?;
                tracing::info!("acquiring admin GSSAPI credential from keytab: '{keytab}'");
                akamu_gssapi::GssServerCred::acquire(&gcfg.service_name, keytab)
                    .map_err(|e| format!("admin GSSAPI credential init: {e}"))?
            };
            Some(Arc::new(cred))
        } else {
            None
        }
    } else {
        None
    };

    // ── EAB master secret ─────────────────────────────────────────────────────
    let eab_master_secret = match config.server.eab_master_secret.as_deref() {
        None => None,
        Some(b64u) => {
            use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
            let bytes = URL_SAFE_NO_PAD
                .decode(b64u)
                .map_err(|e| format!("eab_master_secret base64url decode error: {e}"))?;
            if bytes.len() < 32 {
                return Err(format!(
                    "eab_master_secret must be ≥ 32 bytes after decoding, got {}",
                    bytes.len()
                ));
            }
            tracing::info!(
                "EAB HKDF master secret loaded ({} bytes); \
                 /acme/eab will return full credentials",
                bytes.len()
            );
            Some(Arc::new(akamu_util::SecretBuffer::from_bytes(&bytes)))
        }
    };

    // ── tkauth Token Authority trust anchors (RFC 9447) ──────────────────────
    let tkauth_trust_anchors = if let Some(tkauth) = config.tkauth.as_ref().filter(|t| t.enabled) {
        let ca_ders = akamu::tls::loader::load_ca_certs(&tkauth.trusted_ta_ca_files)
            .map_err(|e| format!("tkauth trust anchors: {e}"))?;
        let store =
            synta_x509_verification::OwnedStore::try_new(ca_ders.iter().map(|d| d.as_slice()))
                .map_err(|e| format!("build tkauth trust store: {e}"))?;
        tracing::info!(
            count = ca_ders.len(),
            "loaded tkauth Token Authority trust anchors"
        );
        Some(Arc::new(store))
    } else {
        None
    };

    // ── Claim-to-extension encoder registry (RFC 9447 JWTClaimConstraints) ─────
    let claim_encoder_registry = if let Some(tkauth) = config.tkauth.as_ref().filter(|t| t.enabled)
    {
        if tkauth.claim_encoders.is_empty() {
            None
        } else {
            let reg = akamu::validation::claim_encoder::build_registry(&tkauth.claim_encoders)
                .map_err(|e| format!("tkauth claim encoders: {e}"))?;
            tracing::info!(count = reg.len(), "registered tkauth claim encoders");
            Some(Arc::new(reg))
        }
    } else {
        None
    };

    // ── JWKS body cache for kid-signed authority tokens (RFC 9447) ──────────
    let jwks_cache = if config.tkauth.as_ref().is_some_and(|t| t.enabled) {
        Some(Arc::new(tokio::sync::Mutex::new(
            std::collections::HashMap::<String, (Vec<u8>, std::time::Instant)>::new(),
        )))
    } else {
        None
    };

    // ── Per-CA Link headers ───────────────────────────────────────────────────
    let link_headers_map: std::collections::HashMap<String, Arc<axum::http::HeaderValue>> = config
        .cas
        .iter()
        .map(|ca_cfg| {
            let url = if ca_cfg.is_default {
                format!("<{}/acme/directory>;rel=\"index\"", config.base_url)
            } else {
                format!(
                    "<{}/acme/{}/directory>;rel=\"index\"",
                    config.base_url, ca_cfg.id
                )
            };
            let hv = Arc::new(
                axum::http::HeaderValue::from_str(&url)
                    .expect("base_url + CA ID produce a valid Link header value"),
            );
            (ca_cfg.id.clone(), hv)
        })
        .collect();

    // ── Application state ─────────────────────────────────────────────────────
    // Use the first 11 chars of node_id as the nonce prefix (~64 bits of unique
    // node identity) so that nonces are node-scoped and rejected by other nodes.
    debug_assert!(
        node_id.len() >= 11,
        "node_id too short for nonce prefix: {} chars",
        node_id.len()
    );
    let nonce_prefix = node_id.get(..11).unwrap_or(&node_id).to_string();
    let nonces = Arc::new(NonceBucket::with_prefix(nonce_prefix));
    let journal = Arc::new(if let Some(ref path) = config.server.audit_log_file {
        JournalWriter::with_file(path).map_err(|e| format!("audit log file '{path}': {e}"))?
    } else {
        JournalWriter::new("akamu")
    });
    let mut builder = AppStateBuilder::new(
        Arc::clone(&config),
        db.clone(),
        db_kind,
        Arc::new(cas_map),
        Arc::new(default_ca_id),
    )
    .db_ro(db_ro)
    .profiles(profile_registry.clone())
    .nonces(Arc::clone(&nonces))
    .link_headers(Arc::new(link_headers_map))
    .crl_caches(Arc::new(crl_caches_map))
    .audit_policy(Arc::new(
        config
            .admin
            .as_ref()
            .map(akamu::audit::AuditPolicy::from_admin_config)
            .unwrap_or_default(),
    ))
    .journal(journal)
    .crdt(crdt)
    .node_id(node_id)
    .node_kem_priv(Arc::new(node_keys.kem_priv_pkcs8))
    .node_gossip_signing_priv(Arc::new(node_keys.sign_priv_pem))
    .node_gossip_signing_cert(Arc::new(node_keys.sign_cert_der))
    .gossip_client(Arc::new(
        reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .expect("gossip reqwest client build failed"),
    ))
    .crdt_db(crdt_db);
    if let Some(tls) = tls_state {
        builder = builder.tls(tls);
    }
    if let Some(gc) = gss_cred {
        builder = builder.gss_cred(gc);
    }
    if let Some(agc) = admin_gss_cred {
        builder = builder.admin_gss_cred(agc);
    }
    if let Some(ems) = eab_master_secret {
        builder = builder.eab_master_secret(ems);
    }
    if config.admin.is_some() {
        builder = builder
            .admin_sessions(Arc::new(tokio::sync::Mutex::new(
                std::collections::HashMap::new(),
            )))
            .admin_auth_limiter(Arc::new(tokio::sync::Mutex::new(
                std::collections::HashMap::new(),
            )))
            .eab_session_nonces(Arc::new(tokio::sync::Mutex::new(
                std::collections::HashMap::new(),
            )));
    }
    if let Some(ta) = tkauth_trust_anchors {
        builder = builder.tkauth_trust_anchors(ta);
    }
    if let Some(cr) = claim_encoder_registry {
        builder = builder.claim_encoder_registry(cr);
    }
    if let Some(jc) = jwks_cache {
        builder = builder.jwks_cache(jc);
    }
    if let Some(wc) = write_coalescer {
        builder = builder.write_coalescer(wc);
    }
    let state = builder.build();

    // ── Startup audit records ─────────────────────────────────────────────────
    let key_file_exists = config
        .default_ca()
        .key_file
        .as_deref()
        .is_some_and(|p| std::path::Path::new(p).exists());
    let key_event_type = if key_file_exists {
        akamu::audit::AuditEventType::KeyLoad
    } else {
        akamu::audit::AuditEventType::KeyGenerate
    };
    state
        .record_audit(akamu::audit::AuditEvent::success(key_event_type))
        .await;
    state
        .record_audit(akamu::audit::AuditEvent::success(
            akamu::audit::AuditEventType::CaStart,
        ))
        .await;

    // Spawn background profile refresh task (no-op when no providers configured).
    profile_registry.spawn_refresh_task();

    // Periodically sweep expired in-memory nonces (every 15 minutes, 24 h TTL).
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(900));
        interval.tick().await; // skip immediate first tick
        loop {
            interval.tick().await;
            nonces.sweep_expired(86400);
        }
    });

    // ── MTC checkpoint background task ───────────────────────────────────────
    let _checkpoint_task = mtc::checkpoint::spawn_checkpoint_task(Arc::clone(&state));

    // ── MTC landmark allocation background task ──────────────────────────────
    let _landmark_task = mtc::landmark::spawn_landmark_task(Arc::clone(&state));

    // ── STAR background reissuance task ──────────────────────────────────────
    let _star_task = star::spawn(Arc::clone(&state));

    // ── RFC 9115 IdO→CA upstream delegation task ──────────────────────────────
    let _delegation_task = delegation_upstream::spawn(Arc::clone(&state));

    // ── Gossip background loop (disabled when [gossip] section is absent) ─────
    // Wrapped in a supervisor that restarts the loop if it panics.
    // Clean exit or cancellation (server shutdown) terminates the supervisor.
    if state.config.gossip.is_some() {
        let state_for_gossip = Arc::clone(&state);
        tokio::spawn(async move {
            loop {
                let s = Arc::clone(&state_for_gossip);
                match tokio::spawn(gossip::gossip_loop::run(s)).await {
                    Ok(()) => break, // clean exit = server shutting down
                    Err(e) if e.is_cancelled() => break,
                    Err(e) => {
                        tracing::error!(err = %e, "gossip loop panicked; restarting in 5s");
                        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                    }
                }
            }
        });
    }

    // ── RFC 9447 tkauth JTI pruning background task ──────────────────────────
    if let Some(tkauth_cfg) = config.tkauth.as_ref().filter(|t| t.enabled) {
        let prune_interval = tkauth_cfg.jti_prune_interval_secs;
        let state_for_jti = Arc::clone(&state);
        tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(std::time::Duration::from_secs(prune_interval));
            interval.tick().await; // skip immediate first tick
            loop {
                interval.tick().await;
                let now = akamu::util::unix_now();
                match crate::db::tkauth::purge_expired(&state_for_jti.db, now).await {
                    Ok(n) if n > 0 => {
                        tracing::debug!(deleted = n, "tkauth JTI cache pruned");
                    }
                    Ok(_) => {}
                    Err(e) => tracing::warn!(err = %e, "tkauth JTI cache prune failed"),
                }
            }
        });
    }

    // ── HTTP / TLS server (serves ACME, admin API, and web UI) ──────────────
    let static_dir = config
        .server
        .webui
        .as_ref()
        .and_then(|w| w.static_dir.as_deref())
        .map(std::path::PathBuf::from);
    let router = routes::build_router(Arc::clone(&state), static_dir.as_deref());

    // ── Systemd socket activation (try listenfd before config-based bind) ─────
    let mut listenfd = listenfd::ListenFd::from_env();
    if listenfd.len() > 1 {
        tracing::warn!(
            count = listenfd.len(),
            "listenfd: more than one socket FD available; only index 0 (Unix) is consumed"
        );
    }
    if let Some(std_listener) = listenfd.take_unix_listener(0).map_err(|e| {
        format!(
            "systemd passed an fd that is not a Unix stream socket ({}); \
             only Unix socket activation is supported — verify ListenStream= \
             in your .socket unit points to a filesystem path, not a TCP address",
            e
        )
    })? {
        if config.tls.enabled {
            return Err("TLS cannot be used with a Unix domain socket listener".to_owned());
        }
        std_listener
            .set_nonblocking(true)
            .map_err(|e| format!("set_nonblocking: {e}"))?;
        let listener = tokio::net::UnixListener::from_std(std_listener)
            .map_err(|e| format!("tokio UnixListener: {e}"))?;
        tracing::info!(
            base_url = %config.base_url,
            "ACME server on systemd-activated Unix socket"
        );
        let router = router.layer(axum::middleware::from_fn(uds_marker_layer));
        axum::serve(listener, router.into_make_service())
            .with_graceful_shutdown(async {
                let mut sigterm =
                    tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                        .expect("failed to install SIGTERM handler");
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {},
                    _ = sigterm.recv() => {},
                }
                tracing::info!("received shutdown signal; stopping server");
            })
            .await
            .map_err(|e| format!("server error: {e}"))?;
    } else if config.tls.enabled {
        let mut server_cfg = akamu::tls::build_rustls_server_config(&config.tls)
            .map_err(|e| format!("TLS config: {e}"))?;
        server_cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_cfg));

        // Pre-compute tls-server-end-point channel binding (RFC 5929 §4) once at
        // startup so each connection can inject it without re-reading the cert.
        // Returns None for ML-DSA server certs (no defined hash algorithm).
        let tls_channel_binding: Option<Arc<Vec<u8>>> = {
            match akamu::tls::leaf_cert_der(&config.tls) {
                Err(e) => {
                    tracing::warn!("could not load leaf cert for channel binding: {e}");
                    None
                }
                Ok(der) => {
                    let b = akamu::tls::channel_binding::tls_server_endpoint_binding(&der);
                    if b.is_none() {
                        tracing::info!(
                            "TLS server cert uses ML-DSA or unknown algorithm; \
                             GSSAPI channel bindings disabled"
                        );
                    }
                    b.map(Arc::new)
                }
            }
        };

        let addr = match parse_listen_target(&config.listen_addr, "AKAMU_LISTEN")? {
            ListenTarget::Tcp(a) => a,
            ListenTarget::Unix(_) => {
                return Err("TLS cannot be used with a Unix domain socket listener".to_owned());
            }
        };
        let listener = tokio::net::TcpListener::bind(addr)
            .await
            .map_err(|e| format!("bind '{}': {e}", addr))?;
        tracing::info!(
            listen_addr = %addr,
            base_url = %config.base_url,
            "ACME server listening with TLS"
        );
        let shutdown = tokio::signal::ctrl_c();
        tokio::pin!(shutdown);
        loop {
            tokio::select! {
                _ = &mut shutdown => {
                    tracing::info!("received shutdown signal; stopping TLS server");
                    break;
                }
                result = listener.accept() => {
                    let (stream, peer_addr) = result.map_err(|e| format!("accept: {e}"))?;
                    let acceptor = acceptor.clone();
                    let router = router.clone();
                    let tls_channel_binding = tls_channel_binding.clone();
                    tokio::spawn(async move {
                        let tls = match acceptor.accept(stream).await {
                            Ok(s) => s,
                            Err(e) => {
                                tracing::warn!("TLS handshake failed: {e}");
                                return;
                            }
                        };
                        // Extract peer cert before moving tls into TokioIo.
                        let peer_cert: Option<Vec<u8>> = tls
                            .get_ref()
                            .1
                            .peer_certificates()
                            .and_then(|c| c.first())
                            .map(|c| c.as_ref().to_vec());
                        let io = hyper_util::rt::TokioIo::new(tls);
                        use tower::ServiceExt as _;
                        let svc = hyper::service::service_fn(
                            move |mut req: hyper::Request<hyper::body::Incoming>| {
                                req.extensions_mut()
                                    .insert(axum::extract::ConnectInfo(peer_addr));
                                if let Some(ref der) = peer_cert {
                                    req.extensions_mut().insert(
                                        akamu::admin::auth::PeerClientCert(der.clone()),
                                    );
                                }
                                if let Some(ref binding) = tls_channel_binding {
                                    req.extensions_mut().insert(
                                        akamu::tls::channel_binding::TlsServerEndpointBinding(
                                            binding.as_ref().clone(),
                                        ),
                                    );
                                }
                                let router = router.clone();
                                async move {
                                    let req = req.map(axum::body::Body::new);
                                    Ok::<_, std::convert::Infallible>(
                                        router.oneshot(req).await.expect("axum Router is infallible"),
                                    )
                                }
                            },
                        );
                        if let Err(e) = hyper_util::server::conn::auto::Builder::new(
                            hyper_util::rt::TokioExecutor::new(),
                        )
                        .serve_connection(io, svc)
                        .await
                        {
                            tracing::warn!("TLS connection error: {e}");
                        }
                    });
                }
            }
        }
    } else {
        match parse_listen_target(&config.listen_addr, "AKAMU_LISTEN")? {
            ListenTarget::Tcp(addr) => {
                let listener = tokio::net::TcpListener::bind(addr)
                    .await
                    .map_err(|e| format!("bind '{}': {e}", addr))?;
                tracing::info!(
                    "ACME server listening on {} (base_url={})",
                    addr,
                    config.base_url
                );
                axum::serve(
                    listener,
                    router.into_make_service_with_connect_info::<std::net::SocketAddr>(),
                )
                .with_graceful_shutdown(async {
                    tokio::signal::ctrl_c().await.ok();
                    tracing::info!("received shutdown signal; stopping server");
                })
                .await
                .map_err(|e| format!("server error: {e}"))?;
            }
            ListenTarget::Unix(path) => {
                remove_stale_socket(&path).await?;
                let listener = tokio::net::UnixListener::bind(&path)
                    .map_err(|e| format!("bind unix '{}': {e}", path))?;
                tracing::info!(
                    path = %path,
                    base_url = %config.base_url,
                    "ACME server listening on Unix socket"
                );
                let router = router.layer(axum::middleware::from_fn(uds_marker_layer));
                axum::serve(listener, router.into_make_service())
                    .with_graceful_shutdown(async {
                        let mut sigterm = tokio::signal::unix::signal(
                            tokio::signal::unix::SignalKind::terminate(),
                        )
                        .expect("failed to install SIGTERM handler");
                        tokio::select! {
                            _ = tokio::signal::ctrl_c() => {},
                            _ = sigterm.recv() => {},
                        }
                        tracing::info!("received shutdown signal; stopping server");
                    })
                    .await
                    .map_err(|e| format!("server error: {e}"))?;
                // Best-effort cleanup of the socket file after graceful shutdown.
                let _ = std::fs::remove_file(&path);
            }
        }
    }

    state
        .record_audit(akamu::audit::AuditEvent::success(
            akamu::audit::AuditEventType::CaStop,
        ))
        .await;

    Ok(())
}
