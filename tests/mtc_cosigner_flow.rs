//! Integration test: ACME certificate issuance → MTC checkpoint → standalone
//! certificate verification.
//!
//! Flow:
//!  1. Spawn an inline MTC cosigner HTTP server (implements `POST /sign`).
//!  2. Start the akamu ACME+MTC server on a random port with MTC enabled and
//!     the inline cosigner configured.
//!  3. Use `akamu-client` to register an account, place an order for
//!     `127.0.0.1`, solve the http-01 challenge, finalize, and download the
//!     issued certificate.
//!  4. Call `produce_checkpoint()` directly to force a checkpoint and gather
//!     the cosignature from the inline cosigner.
//!  5. Download the standalone MTC certificate via
//!     `GET /acme/mtc/cert/{id}/standalone`.
//!  6. Parse the standalone cert as a standard X.509 `Certificate` and verify:
//!     - `signatureAlgorithm` == `id-alg-mtcProof`,
//!     - `serialNumber` > 0 (the log entry index),
//!     - `signatureValue` decodes as a valid TLS-encoded `MtcProof`,
//!     - the `MtcProof` contains at least one cosignature from the inline cosigner,
//!     - the embedded inclusion proof verifies against the server's current root.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::Router;
use synta::types::primitive::Integer;
use synta::types::string::OctetString;
use synta::{BitString, Decoder, Encoding, ObjectIdentifier};
use synta_certificate::owned::Certificate as OwnedCert;
use synta_certificate::{
    BackendPrivateKey, CertificateSigner as _, NameBuilder, PrivateKey as _,
    SubjectAlternativeNameBuilder,
};
use synta_mtc::crypto::mtcproof::MtcProof;
use synta_mtc::crypto::{
    hash_log_entry, verify_inclusion_proof, verify_subtree_inclusion_proof, HashAlgorithm,
};
use synta_mtc::types::constants::ID_ALG_MTC_PROOF_EXP;
use synta_mtc::types::{Checkpoint, MerkleTreeCertEntry, Subtree, SubtreeSignature};
use tokio::net::TcpListener;

use akamu::config::{
    CaConfig, Config, CosignerConfig, DatabaseConfig, MtcConfig, MtcSigningKeyConfig, ServerConfig,
};
use akamu::mtc::checkpoint::{produce_checkpoint, CheckpointParams};
use akamu::mtc::cosign::build_cosigner_client_http;
use akamu::mtc::log;
use akamu::state::{AppState, CaState, MtcState, NonceBucket};
use akamu::{ca, db, routes};

use akamu_client::{AccountKey, AccountOptions, AcmeClient, Identifier};

// ── Port utilities ────────────────────────────────────────────────────────────

/// Bind to port 0 to let the OS pick a free port, returning both the port and
/// the bound listener so the binding is held continuously (no TOCTOU window).
fn bind_free_port() -> (u16, std::net::TcpListener) {
    let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind to port 0");
    l.set_nonblocking(true).expect("set_nonblocking");
    let port = l.local_addr().expect("local_addr").port();
    (port, l)
}

// ── Inline cosigner ───────────────────────────────────────────────────────────

/// OID used as `TrustAnchorID` for the inline test cosigner.
/// Uses the experimental MTC arc: 1.3.6.1.4.1.44363.47.10.1
const TEST_COSIGNER_OID: &str = "1.3.6.1.4.1.44363.47.10.1";

/// OID used as the CA's own `TrustAnchorID` for self-cosignatures (§5.4).
const TEST_CA_TRUST_ANCHOR_OID: &str = "1.3.6.1.4.1.44363.47.10.2";

/// Minimal shared state for the inline cosigner HTTP server.
struct CosignerState {
    signing_key: BackendPrivateKey,
    hash_alg: String,
    sig_alg_der: Vec<u8>,
    /// DER-encoded `TrustAnchorID` ObjectIdentifier for this test cosigner.
    cosigner_oid_der: Vec<u8>,
}

/// DER-encode an OID from its dotted-decimal string representation.
fn encode_oid_der(oid_str: &str) -> Vec<u8> {
    use synta::traits::Encode;
    use synta::{Encoder, Encoding};
    let oid: ObjectIdentifier = oid_str.parse().expect("valid OID string");
    let mut enc = Encoder::new(Encoding::Der);
    oid.encode(&mut enc).expect("encode OID");
    enc.finish().expect("finish OID DER")
}

/// Derive the DER-encoded `AlgorithmIdentifier` for a key/hash combination.
fn sig_alg_der(key: &BackendPrivateKey, hash_alg: &str) -> Vec<u8> {
    let pub_key = key.public_key().unwrap();
    let spki_der = pub_key.spki_der().to_vec();
    let mut dec = synta::Decoder::new(&spki_der, synta::Encoding::Der);
    let spki: synta_certificate::SubjectPublicKeyInfo = dec.decode().unwrap();
    synta_certificate::signing_algorithm_der(&spki.algorithm.algorithm, hash_alg).unwrap()
}

/// Axum handler for `POST /sign` — mirrors the production cosigner handler.
async fn cosigner_sign(State(state): State<Arc<CosignerState>>, body: Bytes) -> impl IntoResponse {
    let checkpoint: Checkpoint = match Decoder::new(&body, Encoding::Der).decode() {
        Ok(c) => c,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                format!("invalid Checkpoint DER: {e}"),
            )
                .into_response()
        }
    };

    let tree_size = match checkpoint.tree_size.as_u64() {
        Ok(n) if n > 0 => n,
        _ => return (StatusCode::BAD_REQUEST, "tree_size out of range").into_response(),
    };

    let root_bytes = checkpoint.root_value.as_bytes().to_vec();
    let subtree = Subtree {
        start: Integer::from(0u64),
        end: Integer::from(tree_size),
        value: OctetString::from(root_bytes),
    };

    // Decode the CosignerID (TrustAnchorID = ObjectIdentifier) from stored DER.
    let cosigner_id: ObjectIdentifier =
        match Decoder::new(&state.cosigner_oid_der, Encoding::Der).decode() {
            Ok(oid) => oid,
            Err(e) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("decode cosigner OID: {e}"),
                )
                    .into_response()
            }
        };

    // log_origin per §5.3.1: should be "oid/<log TrustAnchorID>".
    // Uses hash algorithm OID to match synta-mtc's internal computation.
    let log_origin = format!("oid/{}", checkpoint.log_id.hash_algorithm.algorithm);

    // Build and sign the TLS-encoded CosignedMessage (spec §5.4.1).
    let cosigned_msg = match akamu_mtc_wire::build_cosigned_message(
        &cosigner_id,
        &subtree,
        &checkpoint,
        &log_origin,
    ) {
        Ok(msg) => msg,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("build CosignedMessage: {e}"),
            )
                .into_response()
        }
    };
    let signer = state.signing_key.as_signer(&state.hash_alg);
    let sig_bytes = match signer.sign_tbs(&cosigned_msg) {
        Ok(s) => s,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, format!("sign: {e}")).into_response(),
    };

    let sig_alg: synta_certificate::AlgorithmIdentifier =
        match Decoder::new(&state.sig_alg_der, Encoding::Der).decode() {
            Ok(alg) => alg,
            Err(e) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("decode sig_alg: {e}"),
                )
                    .into_response()
            }
        };

    let sig = match BitString::new(sig_bytes, 0) {
        Ok(s) => s,
        Err(e) => {
            return (StatusCode::INTERNAL_SERVER_ERROR, format!("bitstring: {e}")).into_response()
        }
    };

    let subtree_sig = SubtreeSignature {
        cosigner: cosigner_id,
        subtree,
        checkpoint,
        signature_algorithm: sig_alg,
        signature: sig,
    };

    let der = match subtree_sig.to_der() {
        Ok(d) => d,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("encode SubtreeSignature: {e}"),
            )
                .into_response()
        }
    };

    (
        StatusCode::OK,
        [("content-type", "application/octet-stream")],
        der,
    )
        .into_response()
}

/// Start the inline cosigner on `std_listener` and return its URL.
///
/// The caller must have obtained `std_listener` via `bind_free_port()` to avoid
/// the TOCTOU race that exists when a port is bound and then dropped before use.
async fn start_cosigner(std_listener: std::net::TcpListener) -> String {
    let port = std_listener.local_addr().expect("local_addr").port();
    let signing_key = BackendPrivateKey::generate_ec("P-256").expect("generate cosigner key");
    let hash_alg = "sha256".to_owned();
    let alg_der = sig_alg_der(&signing_key, &hash_alg);
    let cosigner_oid_der = encode_oid_der(TEST_COSIGNER_OID);

    let state = Arc::new(CosignerState {
        signing_key,
        hash_alg,
        sig_alg_der: alg_der,
        cosigner_oid_der,
    });

    let app = Router::new()
        .route("/sign", post(cosigner_sign))
        .with_state(state);

    let listener = TcpListener::from_std(std_listener).expect("tokio TcpListener from std");
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    format!("http://127.0.0.1:{port}/sign")
}

// ── http-01 challenge solver ──────────────────────────────────────────────────

type TokenStore = Arc<RwLock<HashMap<String, String>>>;

/// Start a minimal http-01 challenge server on `std_listener` and return the token store.
async fn start_http01_solver(std_listener: std::net::TcpListener) -> TokenStore {
    let store: TokenStore = Arc::new(RwLock::new(HashMap::new()));
    let store_clone = Arc::clone(&store);

    let app = Router::new().route(
        "/.well-known/acme-challenge/{token}",
        get(move |Path(token): Path<String>| {
            let s = Arc::clone(&store_clone);
            async move { s.read().unwrap().get(&token).cloned().unwrap_or_default() }
        }),
    );

    let listener = TcpListener::from_std(std_listener).expect("tokio TcpListener from std");
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    store
}

// ── akamu server setup ────────────────────────────────────────────────────────

async fn build_akamu_state(
    dir: &std::path::Path,
    base_url: &str,
    http01_port: u16,
    cosigner_url: &str,
) -> Arc<AppState> {
    let mtc_log_path = dir.join("mtc.log").to_string_lossy().into_owned();
    let mtc_key_file = dir.join("mtc.key").to_string_lossy().into_owned();

    let config = Arc::new(Config {
        listen_addr: "127.0.0.1:0".into(),
        base_url: base_url.into(),
        database: DatabaseConfig {
            url: "sqlite::memory:".into(),
            max_connections: None,
            require_tls: false,
        },
        cas: vec![CaConfig {
            id: "default".to_owned(),

            is_default: true,

            caa_identities: vec![],
            key_file: dir.join("ca.key").to_string_lossy().into_owned(),
            cert_file: dir.join("ca.crt").to_string_lossy().into_owned(),
            key_type: "ec:P-256".into(),
            hash_alg: "sha256".into(),
            validity_days: 90,
            crl_url: None,
            ocsp_url: None,
            common_name: "MTC Test CA".into(),
            organization: "Test".into(),
            ca_validity_years: 10,
            crl_next_update_secs: 86400,
            enforce_validity_cap: false,
            require_encrypted_key: false,
            key_password_file: None,
            mtc: None,
        }],
        mtc: Some(MtcConfig {
            log_path: mtc_log_path.clone(),
            enabled: true,
            signing_key: Some(MtcSigningKeyConfig {
                key_file: mtc_key_file.clone(),
                key_type: "ec:P-256".into(),
                hash_alg: "sha256".into(),
            }),
            checkpoint_interval_secs: 3600,
            cosigners: vec![CosignerConfig {
                url: cosigner_url.into(),
                cosigner_id_cert_pem: None,
                trust_anchor_id: Some(TEST_COSIGNER_OID.into()),
            }],
            landmark_interval_secs: 86400,
            max_active_landmarks: 100,
            checkpoint_retention_count: 1000,
            hash_alg: "sha256".into(),
            log_number: 1,
            tree_minimum_index: None,
            trust_anchor_id: Some(TEST_CA_TRUST_ANCHOR_OID.into()),
        }),
        server: {
            let mut s = ServerConfig::default();
            s.http_validation_port = http01_port;
            s.http_validation_allow_private_ips = true;
            s
        },
        tls: Default::default(),
        profiles: Default::default(),
        admin: None,
        email_challenge: None,
        delegation_upstream: None,
        tkauth: None,
        gossip: None,
        crdt_db_url: None,
    });

    let (ca_key, ca_cert_der) = ca::init::load_or_generate(config.default_ca()).unwrap();
    let ca_spki_der = ca_key.public_key().unwrap().spki_der().to_vec();
    let ca_aki_bytes = ca::init::compute_aki_from_spki(&ca_spki_der).unwrap_or_default();

    db::install_drivers();
    let db_conn = db::open("sqlite::memory:", 1, false).await.unwrap();

    // Generate MTC signing key directly (avoids needing to call main.rs helpers).
    let mtc_key = BackendPrivateKey::generate_ec("P-256").unwrap();
    let mtc_key_pem = mtc_key.to_pem(None).unwrap();
    std::fs::write(&mtc_key_file, &mtc_key_pem).unwrap();

    // Open a real file-backed MTC log.
    let raw_log = log::open_or_create(&mtc_log_path, HashAlgorithm::Sha256).unwrap();
    let shared_log = Arc::new(tokio::sync::Mutex::new(raw_log));

    // Build a cosigner client that speaks plain HTTP (for tests only).
    let cosigner_client = build_cosigner_client_http(cosigner_url.to_owned());

    let ca = Arc::new(CaState {
        id: "default".into(),
        key_type: "ec:P-256".into(),
        key: ca_key,
        cert_der: ca_cert_der,
        hash_alg: "sha256".into(),
        validity_days: 90,
        crl_url: None,
        ocsp_url: None,
        aki_bytes: ca_aki_bytes,
        crl_next_update_secs: 86400,
        enforce_validity_cap: false,
        caa_identities: vec![],
        mtc: {
            let mtc_spki = mtc_key.public_key().unwrap().spki_der().to_vec();
            let logid_dn =
                akamu::mtc::standalone::build_logid_issuer_dn_der(&mtc_spki, HashAlgorithm::Sha256)
                    .unwrap();
            Arc::new(MtcState {
                log: Some(shared_log),
                algorithm: HashAlgorithm::Sha256,
                signing_key: Some(mtc_key),
                signing_hash_alg: "sha256".into(),
                cosigner_clients: vec![cosigner_client],
                _log_lock: None,
                checkpoint_interval_secs: 3600,
                checkpoint_retention_count: 1000,
                landmark_interval_secs: 86400,
                max_active_landmarks: 100,
                last_checkpoint: std::sync::atomic::AtomicI64::new(0),
                last_landmark: std::sync::atomic::AtomicI64::new(0),
                log_number: 1,
                tree_minimum_index: None,
                trust_anchor_id_der: Some(encode_oid_der(TEST_CA_TRUST_ANCHOR_OID)),
                logid_issuer_dn_der: Some(logid_dn),
            })
        },
    });

    Arc::new(AppState {
        config: Arc::clone(&config),
        db: db_conn.clone(),
        db_ro: db_conn.clone(),
        db_kind: db::DbKind::Sqlite,
        profiles: akamu::profiles::ProfileRegistry::empty(&ca),
        cas: {
            let mut _cas = indexmap::IndexMap::new();
            _cas.insert("default".to_string(), ca.clone());
            Arc::new(_cas)
        },
        default_ca_id: Arc::new("default".to_string()),
        tls: None,
        spki_cache: Arc::new(RwLock::new(HashMap::new())),
        nonces: Arc::new(NonceBucket::new()),
        link_headers: {
            let mut _lh = std::collections::HashMap::new();
            _lh.insert(
                "default".to_string(),
                Arc::new(
                    axum::http::HeaderValue::from_str(&format!(
                        "<{base_url}/acme/directory>;rel=\"index\""
                    ))
                    .unwrap(),
                ),
            );
            Arc::new(_lh)
        },
        validation_client: {
            let https = hyper_rustls::HttpsConnectorBuilder::new()
                .with_native_roots()
                .expect("native roots")
                .https_or_http()
                .enable_http1()
                .build();
            hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
                .build(https)
        },
        crl_caches: {
            let mut _cc = std::collections::HashMap::new();
            _cc.insert("default".to_string(), Default::default());
            Arc::new(_cc)
        },
        audit: std::sync::Arc::new(akamu::audit::AuditState::new()),
        audit_policy: std::sync::Arc::new(akamu::audit::AuditPolicy::default()),
        journal: std::sync::Arc::new(akamu::journal::JournalWriter::with_daemon()),
        admin_sessions: None,
        admin_auth_limiter: None,
        eab_session_nonces: None,
        admin_gss_cred: None,
        startup_time: std::time::Instant::now(),
        crdt: Arc::new(tokio::sync::RwLock::new(akamu_crdt::AkaCrdt::default())),
        node_id: Arc::new("test".to_string()),
        node_kem_priv: Arc::new(vec![]),
        node_gossip_signing_priv: Arc::new(vec![]),
        node_gossip_signing_cert: Arc::new(vec![]),
        gossip_client: Arc::new(reqwest::Client::new()),
        gossip_nonce_cache: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
        write_notify: Arc::new(tokio::sync::Notify::new()),
        gss_cred: None,
        eab_master_secret: None,
        crdt_db: db_conn.clone(),
        tkauth_trust_anchors: None,
        claim_encoder_registry: None,
        jwks_cache: None,
        write_coalescer: None,
    })
}

// ── The integration test ──────────────────────────────────────────────────────

#[tokio::test]
async fn acme_issue_and_mtc_standalone_with_cosigner() {
    let _ = tracing_subscriber::fmt().with_env_filter("warn").try_init();

    let dir = tempfile::TempDir::new().unwrap();

    // ── Phase 1: bind ports atomically (no TOCTOU window) ────────────────────
    let (_, cosigner_std_listener) = bind_free_port();
    let (akamu_port, akamu_std_listener) = bind_free_port();
    let (http01_port, http01_std_listener) = bind_free_port();

    // ── Phase 2: start cosigner ──────────────────────────────────────────────
    let cosigner_url = start_cosigner(cosigner_std_listener).await;

    // ── Phase 3: start http-01 solver ───────────────────────────────────────
    let challenge_store = start_http01_solver(http01_std_listener).await;

    // ── Phase 4: build and start akamu ───────────────────────────────────────
    let base_url = format!("http://127.0.0.1:{akamu_port}");
    let state = build_akamu_state(dir.path(), &base_url, http01_port, &cosigner_url).await;
    let router = routes::build_router(Arc::clone(&state), None);

    let listener = TcpListener::from_std(akamu_std_listener).expect("tokio TcpListener from std");
    tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });

    // Give the server a moment to start accepting connections.
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // ── Phase 5: ACME flow via akamu-client ──────────────────────────────────
    let dir_url = format!("{base_url}/acme/directory");
    let acme = AcmeClient::new(&dir_url)
        .await
        .expect("ACME directory fetch");

    let account_key = Arc::new(AccountKey::generate("ec:P-256").unwrap());
    let account = acme
        .new_account(
            Arc::clone(&account_key),
            &AccountOptions {
                contacts: &[],
                agree_tos: true,
                eab: None,
            },
        )
        .await
        .expect("new_account");

    // Order for IP 127.0.0.1 (avoids DNS resolution; http-01 validates via IP).
    let order = acme
        .new_order(&account, &[Identifier::ip("127.0.0.1")])
        .await
        .expect("new_order");

    // Solve all pending authorizations.
    for auth_url in &order.authorizations {
        let auth = acme
            .get_authorization(&account, auth_url)
            .await
            .expect("get_authorization");

        if auth.status == "valid" {
            continue;
        }

        let challenge = auth
            .find_challenge("http-01")
            .expect("http-01 challenge not found");

        let token = challenge.token.as_deref().expect("challenge token");
        let key_auth = account_key.key_authorization(token);

        // Serve the token on the solver port that akamu is configured to check.
        challenge_store
            .write()
            .unwrap()
            .insert(token.to_owned(), key_auth);

        acme.trigger_challenge(&account, &challenge)
            .await
            .expect("trigger_challenge");
    }

    // Poll until all authorizations are valid and order is ready.
    let ready_order = acme
        .poll_order(&account, &order.url)
        .await
        .expect("poll_order ready");

    // ── Phase 6: finalize and download certificate ────────────────────────────
    // Build a CSR with an IP SAN for 127.0.0.1.
    let ee_key = BackendPrivateKey::generate_ec("P-256").unwrap();
    let ee_pub = ee_key.public_key().unwrap();
    let spki_der = ee_pub.spki_der().to_vec();

    let name_der = NameBuilder::new().common_name("127.0.0.1").build().unwrap();
    let san_der = SubjectAlternativeNameBuilder::new()
        .ip_address(&[127, 0, 0, 1])
        .build()
        .unwrap();
    let csr_signer = ee_key.as_signer("sha256");
    let csr_der = synta_certificate::CsrBuilder::new()
        .subject_name(&name_der)
        .public_key_der(&spki_der)
        .add_extension_oid(synta_certificate::oids::SUBJECT_ALT_NAME, false, &san_der)
        .sign(&csr_signer)
        .unwrap();

    let finalized = acme
        .finalize(&account, &ready_order, &csr_der)
        .await
        .expect("finalize");

    let valid_order = acme
        .poll_order(&account, &finalized.url)
        .await
        .expect("poll_order valid");

    let cert_url = valid_order.certificate.expect("certificate URL");
    let _cert_pem = acme
        .download_certificate(&account, &cert_url)
        .await
        .expect("download certificate");

    // Extract the certificate ID (last path segment of the download URL).
    let cert_id = cert_url.rsplit('/').next().unwrap().to_owned();

    // ── Phase 7: trigger MTC checkpoint ──────────────────────────────────────
    {
        let ca = state.default_ca();
        let mtc = &ca.mtc;
        let log = mtc.log.as_ref().expect("MTC log");
        let signing_key = mtc.signing_key.as_ref().expect("MTC signing key");

        produce_checkpoint(CheckpointParams {
            log,
            signing_key,
            signing_hash_alg: &mtc.signing_hash_alg,
            log_algorithm: mtc.algorithm,
            db: &state.db,
            ca_id: &ca.id,
            cosigners: &mtc.cosigner_clients,
            log_number: mtc.log_number,
            tree_minimum_index: mtc.tree_minimum_index,
            trust_anchor_id_der: mtc.trust_anchor_id_der.as_deref(),
        })
        .await
        .expect("produce_checkpoint");
    }

    // Allow time for cosignature requests to complete.
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    // ── Phase 8: fetch standalone MTC certificate ─────────────────────────────
    let standalone_url = format!("{base_url}/acme/mtc/cert/{cert_id}/standalone");

    // Use a plain HTTP client — all test endpoints are http:// so no TLS needed.
    let http_client: hyper_util::client::legacy::Client<
        _,
        http_body_util::Full<hyper::body::Bytes>,
    > = hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
        .build_http();

    let resp = http_client
        .get(standalone_url.parse().unwrap())
        .await
        .expect("GET standalone");

    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "standalone cert endpoint must return 200"
    );
    assert_eq!(
        resp.headers()
            .get(axum::http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or(""),
        "application/pkix-cert",
        "standalone endpoint must return Content-Type: application/pkix-cert"
    );
    assert_eq!(
        resp.headers()
            .get("x-mtc-version")
            .and_then(|v| v.to_str().ok())
            .unwrap_or(""),
        akamu::routes::mtc::MTC_DRAFT_VERSION,
        "standalone endpoint must return X-MTC-Version: {}",
        akamu::routes::mtc::MTC_DRAFT_VERSION
    );

    let body_bytes = http_body_util::BodyExt::collect(resp.into_body())
        .await
        .unwrap()
        .to_bytes();
    let standalone_der: Vec<u8> = body_bytes.to_vec();
    assert!(
        !standalone_der.is_empty(),
        "standalone cert DER must be non-empty"
    );

    // ── Phase 9: parse and verify the X.509 MTC standalone certificate ──────────

    // 9a. Parse as a standard X.509 Certificate (spec §5 format).
    let cert = OwnedCert::from_der(&standalone_der)
        .expect("parse standalone cert as X.509 Certificate (id-alg-mtcProof format)");

    // 9b. Both signatureAlgorithm fields must be id-alg-mtcProof.
    assert_eq!(
        cert.signature_algorithm.algorithm.components(),
        ID_ALG_MTC_PROOF_EXP,
        "outer signatureAlgorithm must be id-alg-mtcProof"
    );
    assert_eq!(
        cert.tbs_certificate.signature.algorithm.components(),
        ID_ALG_MTC_PROOF_EXP,
        "TBS signatureAlgorithm must be id-alg-mtcProof"
    );

    // 9c. serialNumber = (log_number << 48) | entry_index (draft-04 §6.1).
    let serial = cert
        .tbs_certificate
        .serial_number
        .as_u64()
        .expect("serialNumber as u64");
    let entry_index = serial & ((1u64 << 48) - 1);
    let log_number = serial >> 48;
    assert_eq!(log_number, 1, "log_number in serial must be 1");
    // entry_index 0 is valid (first cert appended to an empty log).

    // 9d. signatureValue is a TLS-encoded MtcProof (not a cryptographic signature).
    let proof_bytes = cert.signature_value.as_bytes();
    let mtc_proof = MtcProof::decode(proof_bytes).expect("decode MtcProof from signatureValue");

    // 9e. produce_checkpoint() contacts the cosigner and embeds the result as an
    // MtcSignature in the proof.  Verify at least one cosignature is present.
    assert!(
        !mtc_proof.signatures.is_empty(),
        "MtcProof must contain at least one cosignature from the inline cosigner"
    );
    assert!(
        !mtc_proof.signatures[0].cosigner_id.is_empty(),
        "cosigner_id must be non-empty DER"
    );
    assert!(
        !mtc_proof.signatures[0].signature_value.is_empty(),
        "cosignature signature_value must be non-empty"
    );

    // 9f. First checkpoint produces a full-tree proof: start == 0, end > 0.
    assert_eq!(
        mtc_proof.start, 0,
        "MtcProof start must be 0 for first-checkpoint full-tree proof"
    );
    assert!(mtc_proof.end > 0, "MtcProof end must be positive");

    // 9g–9h: verify the inclusion proof.
    verify_mtc_proof(&http_client, &base_url, &cert_id, entry_index, &mtc_proof).await;

    // ── Phase 10: issue second cert → second checkpoint → subtree proof ─────
    //
    // A second order for the same identifier reuses the already-valid
    // authorization, so no challenge solving is needed.

    let order2 = acme
        .new_order(&account, &[Identifier::ip("127.0.0.1")])
        .await
        .expect("new_order (2nd)");
    for auth_url in &order2.authorizations {
        let auth = acme
            .get_authorization(&account, auth_url)
            .await
            .expect("get_authorization (2nd)");
        if auth.status == "valid" {
            continue;
        }
        let challenge = auth
            .find_challenge("http-01")
            .expect("http-01 challenge not found (2nd)");
        let token = challenge.token.as_deref().expect("challenge token (2nd)");
        let key_auth = account_key.key_authorization(token);
        challenge_store
            .write()
            .unwrap()
            .insert(token.to_owned(), key_auth);
        acme.trigger_challenge(&account, &challenge)
            .await
            .expect("trigger_challenge (2nd)");
    }
    let ready2 = acme
        .poll_order(&account, &order2.url)
        .await
        .expect("poll_order ready (2nd)");

    let ee_key2 = BackendPrivateKey::generate_ec("P-256").unwrap();
    let ee_pub2 = ee_key2.public_key().unwrap();
    let spki_der2 = ee_pub2.spki_der().to_vec();
    let csr_signer2 = ee_key2.as_signer("sha256");
    let csr_der2 = synta_certificate::CsrBuilder::new()
        .subject_name(&name_der)
        .public_key_der(&spki_der2)
        .add_extension_oid(synta_certificate::oids::SUBJECT_ALT_NAME, false, &san_der)
        .sign(&csr_signer2)
        .unwrap();
    let finalized2 = acme
        .finalize(&account, &ready2, &csr_der2)
        .await
        .expect("finalize (2nd)");
    let valid2 = acme
        .poll_order(&account, &finalized2.url)
        .await
        .expect("poll_order valid (2nd)");
    let cert_url2 = valid2.certificate.expect("certificate URL (2nd)");
    let _cert_pem2 = acme
        .download_certificate(&account, &cert_url2)
        .await
        .expect("download certificate (2nd)");
    let cert_id2 = cert_url2.rsplit('/').next().unwrap().to_owned();

    // Trigger second checkpoint — this should produce subtree-relative proofs.
    {
        let ca = state.default_ca();
        let mtc = &ca.mtc;
        produce_checkpoint(CheckpointParams {
            log: mtc.log.as_ref().unwrap(),
            signing_key: mtc.signing_key.as_ref().unwrap(),
            signing_hash_alg: &mtc.signing_hash_alg,
            log_algorithm: mtc.algorithm,
            db: &state.db,
            ca_id: &ca.id,
            cosigners: &mtc.cosigner_clients,
            log_number: mtc.log_number,
            tree_minimum_index: mtc.tree_minimum_index,
            trust_anchor_id_der: mtc.trust_anchor_id_der.as_deref(),
        })
        .await
        .expect("produce_checkpoint (2nd)");
    }
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    // Fetch the second standalone cert and verify subtree proof.
    let standalone_url2 = format!("{base_url}/acme/mtc/cert/{cert_id2}/standalone");
    let resp2 = http_client
        .get(standalone_url2.parse().unwrap())
        .await
        .expect("GET standalone (2nd)");
    assert_eq!(resp2.status(), StatusCode::OK);
    let body2 = http_body_util::BodyExt::collect(resp2.into_body())
        .await
        .unwrap()
        .to_bytes();
    let cert2 = OwnedCert::from_der(&body2).expect("parse 2nd standalone cert");

    let serial2 = cert2
        .tbs_certificate
        .serial_number
        .as_u64()
        .expect("serial (2nd)");
    let entry_index2 = serial2 & ((1u64 << 48) - 1);

    let proof_bytes2 = cert2.signature_value.as_bytes();
    let mtc_proof2 = MtcProof::decode(proof_bytes2).expect("decode MtcProof (2nd)");

    assert!(
        !mtc_proof2.signatures.is_empty(),
        "second standalone cert must have cosignatures"
    );

    // The second checkpoint should produce subtree-relative proofs (start > 0)
    // if alignment passes.  With prev_tree_size=1, tree_size=2: subtree [1,2),
    // size=1, alignment=1, 1%1==0 → aligned.
    assert!(
        mtc_proof2.start > 0,
        "second checkpoint should use subtree proof (start > 0), got start={}",
        mtc_proof2.start
    );
    assert!(
        mtc_proof2.end > mtc_proof2.start,
        "MtcProof end ({}) must exceed start ({})",
        mtc_proof2.end,
        mtc_proof2.start
    );

    verify_mtc_proof(
        &http_client,
        &base_url,
        &cert_id2,
        entry_index2,
        &mtc_proof2,
    )
    .await;
}

/// Verify an MtcProof's inclusion proof against the server's tree state.
///
/// For full-tree proofs (start == 0): verifies against the server's full root.
/// For subtree proofs (start > 0): fetches the subtree root via
/// `/acme/mtc/subtree-root` and uses `verify_subtree_inclusion_proof`.
async fn verify_mtc_proof(
    http_client: &hyper_util::client::legacy::Client<
        hyper_util::client::legacy::connect::HttpConnector,
        http_body_util::Full<hyper::body::Bytes>,
    >,
    base_url: &str,
    cert_id: &str,
    entry_index: u64,
    mtc_proof: &MtcProof,
) {
    // Single-leaf subtree: empty proof means the cert IS the root.
    let subtree_size = mtc_proof.end - mtc_proof.start;
    if mtc_proof.inclusion_proof.is_empty() {
        assert!(
            subtree_size <= 1,
            "inclusion proof is empty but subtree has {subtree_size} leaves"
        );
        return;
    }

    // Reconstruct the leaf hash from the standalone cert's TBS.
    // The standalone cert has the LogID as issuer (matching what the log stored),
    // so the leaf hash computed here matches the one in the Merkle tree.
    let standalone_resp = http_client
        .get(
            format!("{base_url}/acme/mtc/cert/{cert_id}/standalone")
                .parse()
                .unwrap(),
        )
        .await
        .expect("GET standalone cert DER");
    assert_eq!(standalone_resp.status(), StatusCode::OK);
    let standalone_bytes = http_body_util::BodyExt::collect(standalone_resp.into_body())
        .await
        .unwrap()
        .to_bytes();
    let standalone_cert: synta_certificate::Certificate<'_> =
        Decoder::new(&standalone_bytes, Encoding::Der)
            .decode()
            .expect("parse standalone cert DER");
    let log_entry = synta_mtc::integration::tbs_certificate_to_log_entry(
        &standalone_cert.tbs_certificate,
        HashAlgorithm::Sha256,
    )
    .expect("build log entry from standalone TBS cert");
    let entry = MerkleTreeCertEntry::TbsCertEntry(log_entry);
    let leaf_hash = hash_log_entry(HashAlgorithm::Sha256, &entry, &[]).expect("hash_log_entry");

    let sibling_hashes: Vec<Vec<u8>> = mtc_proof
        .inclusion_proof
        .chunks(32)
        .map(|c| c.to_vec())
        .collect();

    if mtc_proof.start > 0 {
        // Subtree proof — fetch the subtree root from the server.
        let subtree_resp = http_client
            .get(
                format!(
                    "{base_url}/acme/mtc/subtree-root?start={}&end={}",
                    mtc_proof.start, mtc_proof.end
                )
                .parse()
                .unwrap(),
            )
            .await
            .expect("GET subtree-root");
        assert_eq!(subtree_resp.status(), StatusCode::OK);
        let subtree_body = http_body_util::BodyExt::collect(subtree_resp.into_body())
            .await
            .unwrap()
            .to_bytes();
        let subtree_json: serde_json::Value =
            serde_json::from_slice(&subtree_body).expect("parse subtree-root JSON");
        let subtree_root = parse_hex_hash(
            subtree_json["rootHash"]
                .as_str()
                .expect("rootHash in subtree response"),
        );

        verify_subtree_inclusion_proof(
            HashAlgorithm::Sha256,
            entry_index,
            mtc_proof.start,
            mtc_proof.end,
            &leaf_hash,
            &sibling_hashes,
            &subtree_root,
        )
        .expect("subtree inclusion proof must verify");
    } else {
        // Full-tree proof — verify against the server's full root.
        let root_resp = http_client
            .get(format!("{base_url}/acme/mtc/root").parse().unwrap())
            .await
            .expect("GET /acme/mtc/root");
        assert_eq!(root_resp.status(), StatusCode::OK);
        let root_body = http_body_util::BodyExt::collect(root_resp.into_body())
            .await
            .unwrap()
            .to_bytes();
        let root_json: serde_json::Value =
            serde_json::from_slice(&root_body).expect("parse root JSON");
        let server_root = parse_hex_hash(
            root_json["rootHash"]
                .as_str()
                .expect("rootHash in root response"),
        );

        verify_inclusion_proof(
            HashAlgorithm::Sha256,
            entry_index,
            mtc_proof.end,
            &leaf_hash,
            &sibling_hashes,
            &server_root,
        )
        .expect("full-tree inclusion proof must verify");
    }
}

fn parse_hex_hash(hex_str: &str) -> Vec<u8> {
    assert!(
        hex_str.len() % 2 == 0,
        "hex hash must have even length, got: {hex_str:?}"
    );
    (0..hex_str.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex_str[i..i + 2], 16).expect("valid hex"))
        .collect()
}
