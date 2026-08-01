//! Integration smoke test: two-node gossip bootstrap.
//!
//! Marked `#[ignore]` — run with:
//!   cargo test -p akamu --test gossip_bootstrap -- --ignored
//!
//! Requires two free loopback ports.  Spins up two in-process Akamu nodes,
//! creates an account on node A, waits for gossip to propagate, then verifies
//! the account is visible on node B's CRDT.

use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use indexmap::IndexMap;
use serde_json::{json, Value};
use synta_certificate::{BackendPrivateKey, CertificateSigner as _, PrivateKey as _};
use tempfile::TempDir;
use tokio::net::TcpListener;

use akamu::ca;
use akamu::config::{CaConfig, Config, DatabaseConfig, GossipConfig, MtcConfig, ServerConfig};
use akamu::db;
use akamu::routes;
use akamu::state::{AppState, AppStateBuilder, CaState, MtcState, NonceBucket};

// ── Node identity helpers ─────────────────────────────────────────────────────

struct NodeIdentity {
    node_id: String,
    kem_priv_pkcs8: Vec<u8>,
    kem_pub_spki: Vec<u8>,
    sign_priv_pem: Vec<u8>,
    sign_cert_der: Vec<u8>,
    sign_pub_spki: Vec<u8>,
}

/// Generate a fresh ML-KEM-768 + ECDSA-P256 node identity using the same logic
/// as the production server startup path in `src/main.rs`.
fn generate_node_identity() -> NodeIdentity {
    // ECDSA P-256 signing key via synta-certificate (same as in production).
    let sign_key = BackendPrivateKey::generate_ec("P-256").expect("ECDSA keygen");
    let sign_pub = sign_key.public_key().expect("signing pub key");
    let sign_pub_spki = sign_pub.spki_der().to_vec();
    let sign_priv_pem = sign_key.to_pem(None).expect("signing key to PEM");

    // node_id = base64url(AKI(signing_spki)).  AKI is SHA-256[:20] of the SPKI.
    let aki = ca::init::compute_aki_from_spki(&sign_pub_spki).expect("compute AKI");
    let node_id = URL_SAFE_NO_PAD.encode(&aki);

    // Self-signed X.509 certificate for CMS SignedData (gossip authentication).
    let native_sign_key =
        native_ossl::pkey::Pkey::<native_ossl::pkey::Private>::from_pem(&sign_priv_pem)
            .expect("native_ossl sign key from PEM");
    let mut name = native_ossl::x509::X509NameOwned::new().expect("X509Name");
    name.add_entry_by_txt(c"CN", node_id.as_bytes())
        .expect("CN");
    let serial: i64 = {
        let mut buf = [0u8; 7];
        native_ossl::rand::Rand::fill(&mut buf).expect("getrandom for cert serial");
        buf.iter().fold(0i64, |acc, &b| (acc << 8) | i64::from(b))
    };
    let sign_cert_der = native_ossl::x509::X509Builder::new()
        .expect("X509Builder")
        .set_version(2)
        .expect("version")
        .set_serial_number(serial)
        .expect("serial")
        .set_not_before_offset(0)
        .expect("not_before")
        .set_not_after_offset(365 * 86400)
        .expect("not_after")
        .set_subject_name(&name)
        .expect("subject")
        .set_issuer_name(&name)
        .expect("issuer")
        .set_public_key(&native_sign_key)
        .expect("pubkey")
        .sign(&native_sign_key, None)
        .expect("sign")
        .build()
        .to_der()
        .expect("to_der");

    // ML-KEM-768 key via native_ossl (same as production).
    let kem_key = native_ossl::pkey::KeygenCtx::new(c"ML-KEM-768")
        .expect("ML-KEM-768 ctx")
        .generate()
        .expect("ML-KEM-768 keygen");
    let kem_priv_pkcs8 = kem_key.to_pkcs8_der().expect("KEM PKCS8");
    let kem_pub_spki = kem_key.public_key_to_der().expect("KEM SPKI");

    NodeIdentity {
        node_id,
        kem_priv_pkcs8,
        kem_pub_spki,
        sign_priv_pem,
        sign_cert_der,
        sign_pub_spki,
    }
}

// ── Node builder ──────────────────────────────────────────────────────────────

struct NodeHandle {
    state: Arc<AppState>,
    _tempdir: TempDir,
}

struct SpawnParams {
    base_url: String,
    listener: TcpListener,
    identity: NodeIdentity,
    peer_urls: Vec<String>,
}

async fn spawn_node(params: SpawnParams) -> NodeHandle {
    let SpawnParams {
        base_url,
        listener,
        identity,
        peer_urls,
    } = params;
    let dir = TempDir::new().unwrap();
    let db_path = format!("sqlite:{}", dir.path().join("node.db").display());

    let gossip_cfg = if peer_urls.is_empty() {
        None
    } else {
        Some(GossipConfig {
            peers: peer_urls,
            interval_secs: 2,
            tombstone_ttl_secs: 604_800,
            ownership_ttl_secs: 150,
            gossip_envelope_max_age_secs: 300,
            clock_skew_tolerance_secs: 30,
            fan_out: 0,
        })
    };

    let config = Arc::new(Config {
        listen_addr: "127.0.0.1:0".into(),
        base_url: base_url.clone(),
        database: DatabaseConfig {
            url: db_path.clone(),
            max_connections: Some(4),
            require_tls: false,
        },
        cas: vec![CaConfig {
            id: "default".to_owned(),
            is_default: true,
            caa_identities: vec![],
            key_file: Some(dir.path().join("ca.key").to_string_lossy().into_owned()),
            cert_file: dir.path().join("ca.crt").to_string_lossy().into_owned(),
            key_type: "ec:P-256".into(),
            hash_alg: "sha256".into(),
            validity_days: 90,
            crl_url: None,
            ocsp_url: None,
            common_name: "Bootstrap Test CA".into(),
            organization: "Test Org".into(),
            ca_validity_years: 10,
            crl_next_update_secs: 86400,
            enforce_validity_cap: false,
            require_encrypted_key: false,
            key_password_file: None,
            mtc: None,
            default_linter: None,
            signer: None,
        }],
        mtc: Some(MtcConfig {
            log_path: "/dev/null".into(),
            enabled: false,
            signing_key: None,
            checkpoint_interval_secs: 3600,
            cosigners: vec![],
            landmark_interval_secs: 86400,
            max_active_landmarks: 100,
            checkpoint_retention_count: 1000,
            hash_alg: "sha256".into(),
            log_number: 1,
            tree_minimum_index: None,
            trust_anchor_id: None,
            contact: None,
            friendly_name: None,
        }),
        server: ServerConfig::default(),
        tls: Default::default(),
        profiles: Default::default(),
        linter: Default::default(),
        admin: None,
        email_challenge: None,
        delegation_upstream: None,
        gossip: gossip_cfg,
        crdt_db_url: None,
        tkauth: None,
        policy: None,
    });

    let (ca_key, ca_cert_der) = ca::init::load_or_generate(config.default_ca()).unwrap();
    let ca_spki_der = ca_key.public_key().unwrap().spki_der().to_vec();
    let ca_aki_bytes = ca::init::compute_aki_from_spki(&ca_spki_der).unwrap_or_default();

    db::install_drivers();
    let db_conn = db::open(&db_path, 4, false).await.unwrap();
    akamu_crdt::db::init_db_kind(false, false);

    let ca = Arc::new(CaState {
        id: "default".into(),
        key_type: "ec:P-256".into(),
        crl_next_update_secs: 86400,
        signing: akamu::state::SigningBackend::Local {
            key: Box::new(ca_key),
        },
        cert_der: ca_cert_der,
        hash_alg: "sha256".into(),
        validity_days: 90,
        crl_url: None,
        ocsp_url: None,
        aki_bytes: ca_aki_bytes,
        enforce_validity_cap: false,
        caa_identities: vec![],
        mtc: Arc::new(MtcState::disabled()),
        default_linter: None,
        cached_der: std::sync::OnceLock::new(),
        lint_store: std::sync::OnceLock::new(),
    });

    let now_ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    let mut crdt = akamu_crdt::AkaCrdt::default();
    crdt.cluster_nodes.upsert(
        identity.node_id.clone(),
        akamu_crdt::AkaNodeEntry {
            node_id: identity.node_id.clone(),
            gossip_url: base_url.clone(),
            kem_public_key_der: identity.kem_pub_spki.clone(),
            gossip_signing_pub_key_der: identity.sign_pub_spki.clone(),
            gossip_signing_cert_der: identity.sign_cert_der.clone(),
            ca_ids: vec!["default".to_string()],
            registered_at: now_ts,
        },
        now_ts,
        &identity.node_id,
    );

    let nonce_prefix = identity
        .node_id
        .get(..11)
        .unwrap_or(&identity.node_id)
        .to_string();
    let nonces = Arc::new(NonceBucket::with_prefix(nonce_prefix));

    let mut ca_map = IndexMap::new();
    ca_map.insert("default".to_string(), ca.clone());

    let state = AppStateBuilder::new(
        Arc::clone(&config),
        db_conn.clone(),
        db::DbKind::Sqlite,
        Arc::new(ca_map),
        Arc::new("default".to_string()),
    )
    .nonces(Arc::clone(&nonces))
    .crdt(Arc::new(tokio::sync::RwLock::new(crdt)))
    .node_id(Arc::new(identity.node_id))
    .node_kem_priv(Arc::new(identity.kem_priv_pkcs8))
    .node_gossip_signing_priv(Arc::new(identity.sign_priv_pem))
    .node_gossip_signing_cert(Arc::new(identity.sign_cert_der))
    .build();

    if state.config.gossip.is_some() {
        tokio::spawn(akamu::gossip::gossip_loop::run(Arc::clone(&state)));
    }

    let router: Router = routes::build_router(Arc::clone(&state), None, false);
    tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });

    NodeHandle {
        state,
        _tempdir: dir,
    }
}

// ── ACME JWS helpers ──────────────────────────────────────────────────────────

async fn get_nonce(client: &reqwest::Client, base_url: &str) -> String {
    client
        .head(format!("{base_url}/acme/new-nonce"))
        .send()
        .await
        .unwrap()
        .headers()
        .get("replay-nonce")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string()
}

fn make_jwk(key: &BackendPrivateKey) -> Value {
    let pub_key = key.public_key().unwrap();
    let (x_bytes, y_bytes) = pub_key.ec_affine_coordinates().unwrap().unwrap();
    let pad_coord = |b: Vec<u8>| -> String {
        let mut padded = vec![0u8; 32];
        let start = 32usize.saturating_sub(b.len());
        padded[start..].copy_from_slice(&b[..b.len().min(32)]);
        URL_SAFE_NO_PAD.encode(padded)
    };
    json!({
        "kty": "EC",
        "crv": "P-256",
        "x": pad_coord(x_bytes),
        "y": pad_coord(y_bytes),
    })
}

fn sign_jws(key: &BackendPrivateKey, header: Value, payload: Option<Value>) -> Value {
    let header_b64 = URL_SAFE_NO_PAD.encode(header.to_string().as_bytes());
    let payload_b64 = match &payload {
        Some(p) => URL_SAFE_NO_PAD.encode(p.to_string().as_bytes()),
        None => String::new(),
    };
    let signing_input = format!("{header_b64}.{payload_b64}");
    let signer = key.as_signer("sha256");
    let der_sig = signer.sign_tbs(signing_input.as_bytes()).unwrap();
    let p1363 = ecdsa_der_to_p1363(&der_sig, 32).expect("DER→P1363");
    json!({
        "protected": header_b64,
        "payload": payload_b64,
        "signature": URL_SAFE_NO_PAD.encode(p1363),
    })
}

fn ecdsa_der_to_p1363(der: &[u8], half: usize) -> Option<Vec<u8>> {
    fn strip_tlv(buf: &[u8], tag: u8) -> Option<&[u8]> {
        if *buf.first()? != tag {
            return None;
        }
        let first = *buf.get(1)?;
        let (len, rest) = if first < 0x80 {
            (first as usize, &buf[2..])
        } else if first == 0x81 {
            (*buf.get(2)? as usize, &buf[3..])
        } else {
            return None;
        };
        rest.get(..len)
    }
    fn strip_int(buf: &[u8]) -> Option<(&[u8], &[u8])> {
        if *buf.first()? != 0x02 {
            return None;
        }
        let first = *buf.get(1)?;
        let (len, rest) = if first < 0x80 {
            (first as usize, &buf[2..])
        } else if first == 0x81 {
            (*buf.get(2)? as usize, &buf[3..])
        } else {
            return None;
        };
        let val = rest.get(..len)?;
        let val = val.strip_prefix(&[0x00u8]).unwrap_or(val);
        Some((val, &rest[len..]))
    }
    let inner = strip_tlv(der, 0x30)?;
    let (r, rest) = strip_int(inner)?;
    let (s, _) = strip_int(rest)?;
    if r.len() > half || s.len() > half {
        return None;
    }
    let mut out = vec![0u8; half * 2];
    out[half - r.len()..half].copy_from_slice(r);
    out[half * 2 - s.len()..].copy_from_slice(s);
    Some(out)
}

// ── The test ──────────────────────────────────────────────────────────────────

#[tokio::test]
#[ignore]
async fn gossip_bootstrap_account_propagates() {
    let listener_a = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let listener_b = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port_a = listener_a.local_addr().unwrap().port();
    let port_b = listener_b.local_addr().unwrap().port();
    let url_a = format!("http://127.0.0.1:{port_a}");
    let url_b = format!("http://127.0.0.1:{port_b}");

    let id_a = generate_node_identity();
    let id_b = generate_node_identity();

    // Start node B first so it is already accepting connections when A's gossip fires.
    let node_b = spawn_node(SpawnParams {
        base_url: url_b.clone(),
        listener: listener_b,
        identity: id_b,
        peer_urls: vec![url_a.clone()],
    })
    .await;

    let node_a = spawn_node(SpawnParams {
        base_url: url_a.clone(),
        listener: listener_a,
        identity: id_a,
        peer_urls: vec![url_b.clone()],
    })
    .await;

    // Seed each node's CRDT with the other's cluster_nodes entry so gossip
    // encryption works from round 1 (no bootstrapping full-state exchange needed).
    {
        let mut crdt_a = node_a.state.crdt.write().await;
        let b_entries: Vec<_> = node_b
            .state
            .crdt
            .read()
            .await
            .cluster_nodes
            .live_values()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        for (k, v) in b_entries {
            crdt_a.cluster_nodes.upsert(k.clone(), v, 0, &k);
        }
    }
    {
        let mut crdt_b = node_b.state.crdt.write().await;
        let a_entries: Vec<_> = node_a
            .state
            .crdt
            .read()
            .await
            .cluster_nodes
            .live_values()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        for (k, v) in a_entries {
            crdt_b.cluster_nodes.upsert(k.clone(), v, 0, &k);
        }
    }

    // Let the HTTP servers warm up.
    tokio::time::sleep(Duration::from_millis(300)).await;

    // ── Create account on node A ──────────────────────────────────────────────
    let client = reqwest::Client::new();
    let acct_key = BackendPrivateKey::generate_ec("P-256").unwrap();

    let nonce = get_nonce(&client, &url_a).await;
    let new_account_url = format!("{url_a}/acme/new-account");
    let header = json!({
        "alg": "ES256",
        "nonce": nonce,
        "url": new_account_url,
        "jwk": make_jwk(&acct_key),
    });
    let jws = sign_jws(
        &acct_key,
        header,
        Some(json!({ "termsOfServiceAgreed": true })),
    );

    let resp = client
        .post(&new_account_url)
        .header("content-type", "application/jose+json")
        .body(serde_json::to_vec(&jws).unwrap())
        .send()
        .await
        .unwrap();

    assert!(
        resp.status().is_success(),
        "new-account on node A failed: {}",
        resp.status()
    );
    let acct_url = resp
        .headers()
        .get("location")
        .expect("Location header missing")
        .to_str()
        .unwrap()
        .to_string();
    let acct_id = acct_url.rsplit('/').next().unwrap().to_string();

    // ── Wait 3 × gossip_interval (2 s) = 6 s + buffer ───────────────────────
    tokio::time::sleep(Duration::from_secs(8)).await;

    // ── Assert account is visible on node B ───────────────────────────────────
    let crdt_b = node_b.state.crdt.read().await;
    assert!(
        crdt_b.accounts.get(&acct_id).is_some(),
        "Account {acct_id} not found in node B's CRDT after gossip; \
         accounts present in B: {}",
        crdt_b.accounts.live_values().count()
    );
    let acct_b = crdt_b.accounts.get(&acct_id).unwrap();
    assert_eq!(acct_b.status, "valid", "Account status on node B is wrong");
}
