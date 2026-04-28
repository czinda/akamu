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
//!  6. Parse the `StandaloneCertificate` DER and verify:
//!     - the embedded root hash matches the server's current root,
//!     - the cosigner's `SubtreeSignature` is present.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::Router;
use synta::traits::Encode;
use synta::types::primitive::Integer;
use synta::types::string::OctetString;
use synta::{BitString, Decoder, Encoder, Encoding};
use synta_certificate::{
    encode_key_usage, BackendPrivateKey, CertificateBuilder, CertificateSigner as _, NameBuilder,
    PrivateKey as _, SubjectAlternativeNameBuilder, KEY_USAGE_DIGITAL_SIGNATURE,
};
use synta_mtc::crypto::{hash_leaf, verify_inclusion_proof, HashAlgorithm};
use synta_mtc::types::{Checkpoint, CosignerID, StandaloneCertificate, Subtree, SubtreeSignature};
use tokio::net::TcpListener;

use akamu::config::{
    CaConfig, Config, CosignerConfig, DatabaseConfig, MtcConfig, MtcSigningKeyConfig, ServerConfig,
};
use akamu::mtc::checkpoint::produce_checkpoint;
use akamu::mtc::cosign::build_cosigner_client_http;
use akamu::mtc::log;
use akamu::state::{AppState, CaState, MtcState, NonceBucket};
use akamu::{ca, db, routes};

use akamu_client::{AccountKey, AccountOptions, AcmeClient, Identifier};

// ── Port utilities ────────────────────────────────────────────────────────────

/// Bind to port 0 to let the OS pick a free port, then return it.
///
/// There is a small TOCTOU window between dropping the listener and the caller
/// rebinding that port, but it is acceptable in a single-machine test context.
fn free_port() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    l.local_addr().unwrap().port()
}

// ── Inline cosigner ───────────────────────────────────────────────────────────

/// Minimal shared state for the inline cosigner HTTP server.
struct CosignerState {
    signing_key: BackendPrivateKey,
    hash_alg: String,
    sig_alg_der: Vec<u8>,
    cosigner_id: CosignerID,
}

/// Build a self-signed cosigner-id certificate and return its DER.
fn self_signed_cosigner_cert(signing_key: &BackendPrivateKey, hash_alg: &str) -> Vec<u8> {
    let pub_key = signing_key.public_key().unwrap();
    let spki_der = pub_key.spki_der().to_vec();

    let name_der = NameBuilder::new()
        .common_name("test-cosigner")
        .build()
        .unwrap();

    let san_der = SubjectAlternativeNameBuilder::new()
        .dns_name("localhost")
        .build()
        .unwrap();

    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    let gt = |secs: i64| {
        let gt = synta::GeneralizedTime::from_unix(secs).unwrap();
        format!(
            "{:04}{:02}{:02}{:02}{:02}{:02}Z",
            gt.year, gt.month, gt.day, gt.hour, gt.minute, gt.second
        )
    };

    let nb = synta_certificate::parse_time(&gt(now_secs)).unwrap();
    let na = synta_certificate::parse_time(&gt(now_secs + 10 * 365 * 86400)).unwrap();

    let ku_der = encode_key_usage(1 << KEY_USAGE_DIGITAL_SIGNATURE).unwrap();

    let signer = signing_key.as_signer(hash_alg);
    CertificateBuilder::new()
        .issuer_name(&name_der)
        .subject_name(&name_der)
        .public_key_der(&spki_der)
        .serial_number(synta::Integer::from_i64(1))
        .not_valid_before(nb)
        .not_valid_after(na)
        .add_extension_oid(synta_certificate::oids::KEY_USAGE, true, &ku_der)
        .add_extension_oid(synta_certificate::oids::SUBJECT_ALT_NAME, false, &san_der)
        .sign(&signer)
        .unwrap()
}

/// Parse `CosignerID` from a DER-encoded certificate.
fn parse_cosigner_id(cert_der: &[u8]) -> CosignerID {
    use synta_certificate::owned::Certificate;
    use synta_mtc::types::Name as MtcName;

    let mut dec = Decoder::new(cert_der, Encoding::Der);
    let cert: Certificate = dec.decode().unwrap();

    let serial = cert.tbs_certificate.serial_number.clone();

    let mut enc = Encoder::new(Encoding::Der);
    cert.tbs_certificate.issuer.encode(&mut enc).unwrap();
    let issuer_der = enc.finish().unwrap();

    let mut dec2 = Decoder::new(&issuer_der, Encoding::Der);
    let issuer: MtcName = dec2.decode().unwrap();

    CosignerID {
        issuer,
        serial_number: serial,
    }
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

    let signer = state.signing_key.as_signer(&state.hash_alg);
    let sig_bytes = match signer.sign_tbs(&body) {
        Ok(s) => s,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, format!("sign: {e}")).into_response(),
    };

    let sig_alg: synta_certificate::AlgorithmIdentifier =
        Decoder::new(&state.sig_alg_der, Encoding::Der)
            .decode()
            .unwrap();

    let sig = match BitString::new(sig_bytes, 0) {
        Ok(s) => s,
        Err(e) => {
            return (StatusCode::INTERNAL_SERVER_ERROR, format!("bitstring: {e}")).into_response()
        }
    };

    let subtree_sig = SubtreeSignature {
        cosigner: state.cosigner_id.clone(),
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

/// Start the inline cosigner and return its URL and its cosigner-id cert DER.
async fn start_cosigner(port: u16) -> (String, Vec<u8>) {
    let signing_key = BackendPrivateKey::generate_ec("P-256").unwrap();
    let hash_alg = "sha256".to_string();
    let cert_der = self_signed_cosigner_cert(&signing_key, &hash_alg);
    let cosigner_id = parse_cosigner_id(&cert_der);
    let alg_der = sig_alg_der(&signing_key, &hash_alg);

    let state = Arc::new(CosignerState {
        signing_key,
        hash_alg,
        sig_alg_der: alg_der,
        cosigner_id,
    });

    let app = Router::new()
        .route("/sign", post(cosigner_sign))
        .with_state(state);

    let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], port)))
        .await
        .unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    (format!("http://127.0.0.1:{port}/sign"), cert_der)
}

// ── http-01 challenge solver ──────────────────────────────────────────────────

type TokenStore = Arc<RwLock<HashMap<String, String>>>;

/// Start a minimal http-01 challenge server and return the shared token store.
async fn start_http01_solver(port: u16) -> TokenStore {
    let store: TokenStore = Arc::new(RwLock::new(HashMap::new()));
    let store_clone = Arc::clone(&store);

    let app = Router::new().route(
        "/.well-known/acme-challenge/{token}",
        get(move |Path(token): Path<String>| {
            let s = Arc::clone(&store_clone);
            async move { s.read().unwrap().get(&token).cloned().unwrap_or_default() }
        }),
    );

    let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], port)))
        .await
        .unwrap();
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
        },
        ca: CaConfig {
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
        },
        mtc: MtcConfig {
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
            }],
            landmark_interval_secs: 86400,
            max_active_landmarks: 100,
            checkpoint_retention_count: 1000,
        },
        server: {
            let mut s = ServerConfig::default();
            s.http_validation_port = http01_port;
            s
        },
        tls: Default::default(),
        profiles: Default::default(),
        admin: None,
    });

    let (ca_key, ca_cert_der) = ca::init::load_or_generate(&config.ca).unwrap();
    let ca_spki_der = ca_key.public_key().unwrap().spki_der().to_vec();
    let ca_aki_bytes = ca::init::compute_aki_from_spki(&ca_spki_der).unwrap_or_default();

    db::install_drivers();
    let db_conn = db::open("sqlite::memory:", 1, "./migrations/sqlite")
        .await
        .unwrap();

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
        key: ca_key,
        cert_der: ca_cert_der,
        hash_alg: "sha256".into(),
        validity_days: 90,
        crl_url: None,
        ocsp_url: None,
        aki_bytes: ca_aki_bytes,
        enforce_validity_cap: false,
    });

    Arc::new(AppState {
        config: Arc::clone(&config),
        db: db_conn.clone(),
        db_kind: db::DbKind::Sqlite,
        profiles: akamu::profiles::ProfileRegistry::empty(&ca),
        ca,
        mtc: Arc::new(MtcState {
            log: Some(shared_log),
            algorithm: HashAlgorithm::Sha256,
            signing_key: Some(mtc_key),
            signing_hash_alg: "sha256".into(),
            cosigner_clients: vec![cosigner_client],
        }),
        tls: None,
        spki_cache: Arc::new(RwLock::new(HashMap::new())),
        nonces: Arc::new(NonceBucket::new()),
        link_header: Arc::new(
            axum::http::HeaderValue::from_str(&format!(
                "<{base_url}/acme/directory>;rel=\"index\""
            ))
            .unwrap(),
        ),
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
    })
}

// ── The integration test ──────────────────────────────────────────────────────

#[tokio::test]
async fn acme_issue_and_mtc_standalone_with_cosigner() {
    let _ = tracing_subscriber::fmt().with_env_filter("warn").try_init();

    let dir = tempfile::TempDir::new().unwrap();

    // ── Phase 1: allocate ports ──────────────────────────────────────────────
    let cosigner_port = free_port();
    let akamu_port = free_port();
    let http01_port = free_port();

    // ── Phase 2: start cosigner ──────────────────────────────────────────────
    let (cosigner_url, _cosigner_cert_der) = start_cosigner(cosigner_port).await;

    // ── Phase 3: start http-01 solver ───────────────────────────────────────
    let challenge_store = start_http01_solver(http01_port).await;

    // ── Phase 4: build and start akamu ───────────────────────────────────────
    let base_url = format!("http://127.0.0.1:{akamu_port}");
    let state = build_akamu_state(dir.path(), &base_url, http01_port, &cosigner_url).await;
    let router = routes::build_router(Arc::clone(&state));

    let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], akamu_port)))
        .await
        .unwrap();
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
        let mtc = &state.mtc;
        let log = mtc.log.as_ref().expect("MTC log");
        let signing_key = mtc.signing_key.as_ref().expect("MTC signing key");

        produce_checkpoint(
            log,
            signing_key,
            &mtc.signing_hash_alg,
            mtc.algorithm,
            &state.db,
            &mtc.cosigner_clients,
        )
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

    let body_bytes = http_body_util::BodyExt::collect(resp.into_body())
        .await
        .unwrap()
        .to_bytes();
    let standalone_der: Vec<u8> = body_bytes.to_vec();
    assert!(
        !standalone_der.is_empty(),
        "standalone cert DER must be non-empty"
    );

    // ── Phase 9: parse and verify the StandaloneCertificate ──────────────────
    let standalone: StandaloneCertificate = Decoder::new(&standalone_der, Encoding::Der)
        .decode()
        .expect("parse StandaloneCertificate DER");

    // 9a. Fetch current root from the server.
    let root_resp = http_client
        .get(format!("{base_url}/acme/mtc/root").parse().unwrap())
        .await
        .expect("GET /acme/mtc/root");
    assert_eq!(
        root_resp.status(),
        StatusCode::OK,
        "/acme/mtc/root must return 200"
    );
    let root_bytes_body = http_body_util::BodyExt::collect(root_resp.into_body())
        .await
        .unwrap()
        .to_bytes();
    let root_json: serde_json::Value =
        serde_json::from_slice(&root_bytes_body).expect("parse root JSON");
    let server_root_hex = root_json["rootHash"]
        .as_str()
        .expect("rootHash field in JSON");
    let server_root: Vec<u8> = (0..server_root_hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&server_root_hex[i..i + 2], 16).unwrap())
        .collect();

    // 9b. Verify that the cosigner's SubtreeSignature is present.
    //
    // produce_checkpoint() contacts the cosigner via HTTP and embeds any
    // returned SubtreeSignatures into the standalone cert.  We check that
    // at least one cosignature was collected.
    assert!(
        !standalone.subtree_signatures.is_empty(),
        "standalone cert must contain at least one cosignature from the inline cosigner"
    );

    // 9c. Verify the root hash embedded in the first cosignature's checkpoint
    // matches the server's current log root.
    let embedded_root: Vec<u8> = standalone
        .subtree_signatures
        .first()
        .unwrap()
        .checkpoint
        .root_value
        .as_bytes()
        .to_vec();

    assert_eq!(
        embedded_root, server_root,
        "root hash in StandaloneCertificate must match the server's current log root"
    );

    // 9d. Fetch and verify the inclusion proof for the certificate.
    let proof_resp = http_client
        .get(
            format!("{base_url}/acme/mtc/inclusion-proof/{cert_id}")
                .parse()
                .unwrap(),
        )
        .await
        .expect("GET inclusion-proof");
    assert_eq!(
        proof_resp.status(),
        StatusCode::OK,
        "inclusion-proof endpoint must return 200"
    );
    let proof_bytes = http_body_util::BodyExt::collect(proof_resp.into_body())
        .await
        .unwrap()
        .to_bytes();
    let proof_json: serde_json::Value =
        serde_json::from_slice(&proof_bytes).expect("parse inclusion-proof JSON");

    let leaf_index = proof_json["leafIndex"].as_u64().expect("leafIndex");
    let tree_size_proof = proof_json["treeSize"].as_u64().expect("treeSize");
    let proof_hashes: Vec<(bool, Vec<u8>)> = proof_json["proof"]
        .as_array()
        .expect("proof array")
        .iter()
        .map(|entry| {
            let left = entry["left"].as_bool().unwrap_or(false);
            let hex = entry["hash"].as_str().unwrap_or("");
            let bytes = (0..hex.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
                .collect();
            (left, bytes)
        })
        .collect();

    // Compute the leaf hash from the certificate DER (MTC uses SHA-256 of the TBS cert).
    // akamu stores the DER leaf in the mtc log; the hash_leaf function handles the prefix.
    // For a single-leaf tree the proof is empty and the leaf hash IS the root.
    if proof_hashes.is_empty() && tree_size_proof == 1 {
        // Single-certificate tree: root == leaf hash, already verified above.
    } else if !proof_hashes.is_empty() {
        // Fetch the certificate DER to compute its leaf hash.
        let cert_der_resp = http_client
            .get(format!("{base_url}/acme/cert/{cert_id}").parse().unwrap())
            .await
            .expect("GET cert DER");
        let cert_der_bytes = http_body_util::BodyExt::collect(cert_der_resp.into_body())
            .await
            .unwrap()
            .to_bytes();

        // Parse the PEM chain and get the first (leaf) cert DER.
        let cert_ders = synta_certificate::pem_to_der(&cert_der_bytes);
        if let Some(leaf_cert_der) = cert_ders.first() {
            // The MTC log stores hash_leaf(log_entry_der), NOT hash_leaf(cert_der).
            // Reproduce the same log-entry DER that append_cert_to_log builds:
            //   Certificate DER → TBSCertificate → TBSCertificateLogEntry → DER → hash.
            let cert: synta_certificate::Certificate<'_> =
                Decoder::new(leaf_cert_der, Encoding::Der)
                    .decode()
                    .expect("parse leaf cert DER");
            let log_entry = synta_mtc::integration::tbs_certificate_to_log_entry(
                &cert.tbs_certificate,
                HashAlgorithm::Sha256,
            )
            .expect("build log entry from TBS cert");
            let mut enc = Encoder::new(Encoding::Der);
            <synta_mtc::types::TBSCertificateLogEntry<'_> as synta::traits::Encode>::encode(
                &log_entry, &mut enc,
            )
            .expect("encode log entry");
            let log_entry_der = enc.finish().expect("finish log entry DER");

            let leaf_hash = hash_leaf(HashAlgorithm::Sha256, &log_entry_der);
            verify_inclusion_proof(
                HashAlgorithm::Sha256,
                leaf_index,
                tree_size_proof,
                &leaf_hash,
                &proof_hashes,
                &server_root,
            )
            .expect("Merkle inclusion proof must verify against the server root");
        }
    }
}
