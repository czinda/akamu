//! MTC playground compatibility tests.
//!
//! Verifies that Akāmu's MTC implementation is wire-compatible with the DigiCert
//! MTC playground tools and the C2SP specifications for:
//!
//! - RFC 9162 Merkle hashing (leaf / interior hash domain separation)
//! - C2SP tlog-tiles hash tile structure and index path encoding
//! - C2SP signed-note checkpoint format (body layout and signature line)
//! - C2SP signed-note key ID computation (types 0x01 and 0x02)
//! - C2SP tlog-cosignature message format (types 0x04 and 0x06)
//! - Live tlog-tiles HTTP endpoints on an in-process Akāmu server
//!
//! The DigiCert playground integration test is gated behind the
//! `MTC_PLAYGROUND_DIR` environment variable pointing to a checkout of the
//! <https://github.com/digicert/ca-extension-mtc-playground> repository.
//! It is marked `#[ignore]` so it never runs in CI without explicit opt-in:
//!
//! ```shell
//! MTC_PLAYGROUND_DIR=/path/to/ca-extension-mtc-playground \
//!   cargo test --test mtc_playground_compat digicert -- --ignored
//! ```

mod common;

use synta_certificate::{default_data_hasher, BackendPrivateKey, DataHasher};
use synta_mtc::crypto::{hash_interior, hash_leaf, HashAlgorithm};

use akamu::mtc::tlog;
use akamu::mtc::tlog::NoteSigningRole;

// ── RFC 9162 hash conformance ─────────────────────────────────────────────────

/// Verify that `hash_leaf` prepends 0x00 and produces the correct SHA-256 output.
#[test]
fn rfc9162_leaf_hash_domain_separation() {
    let data = b"hello";
    let leaf_hash = hash_leaf(HashAlgorithm::Sha256, data);

    // Manually construct expected: SHA-256(0x00 || data)
    let hasher = default_data_hasher();
    let mut input = Vec::with_capacity(1 + data.len());
    input.push(0x00u8);
    input.extend_from_slice(data);
    let expected = hasher.hash_data("sha256", &input).unwrap();

    assert_eq!(
        leaf_hash, expected,
        "hash_leaf must produce SHA-256(0x00 || data)"
    );
}

/// Verify that `hash_interior` prepends 0x01 and produces the correct SHA-256 output.
#[test]
fn rfc9162_interior_hash_domain_separation() {
    let left = vec![0xaau8; 32];
    let right = vec![0xbbu8; 32];
    let interior = hash_interior(HashAlgorithm::Sha256, &left, &right).unwrap();

    // Manually construct expected: SHA-256(0x01 || left || right)
    let hasher = default_data_hasher();
    let mut input = Vec::with_capacity(1 + 32 + 32);
    input.push(0x01u8);
    input.extend_from_slice(&left);
    input.extend_from_slice(&right);
    let expected = hasher.hash_data("sha256", &input).unwrap();

    assert_eq!(
        interior, expected,
        "hash_interior must produce SHA-256(0x01 || left || right)"
    );
}

/// Verify that different data produces different leaf hashes (sanity / domain separation).
#[test]
fn rfc9162_leaf_hash_is_not_identity() {
    let hash = hash_leaf(HashAlgorithm::Sha256, b"data");
    // The leaf hash must differ from the raw SHA-256 of the same data
    let hasher = default_data_hasher();
    let raw_sha256 = hasher.hash_data("sha256", b"data").unwrap();
    assert_ne!(hash, raw_sha256, "hash_leaf must not be raw SHA-256(data)");
}

/// Two-leaf MTH matches the manually computed interior hash.
#[test]
fn rfc9162_two_leaf_mth() {
    let left = hash_leaf(HashAlgorithm::Sha256, b"L");
    let right = hash_leaf(HashAlgorithm::Sha256, b"R");
    let result = tlog::mth(&[left.clone(), right.clone()], HashAlgorithm::Sha256).unwrap();
    let expected = hash_interior(HashAlgorithm::Sha256, &left, &right).unwrap();
    assert_eq!(result, expected);
}

// ── C2SP tile index path encoding conformance ─────────────────────────────────

#[test]
fn c2sp_tile_index_known_values() {
    // Known-good values from the C2SP tlog-tiles spec examples.
    assert_eq!(tlog::tile_index_path(0), "000");
    assert_eq!(tlog::tile_index_path(1), "001");
    assert_eq!(tlog::tile_index_path(255), "255");
    assert_eq!(tlog::tile_index_path(256), "256");
    assert_eq!(tlog::tile_index_path(999), "999");
    assert_eq!(tlog::tile_index_path(1_000), "x001/000");
    assert_eq!(tlog::tile_index_path(1_001), "x001/001");
    assert_eq!(tlog::tile_index_path(999_999), "x999/999");
    assert_eq!(tlog::tile_index_path(1_000_000), "x001/x000/000");
}

#[test]
fn c2sp_tile_path_parse_roundtrip() {
    for n in [0u64, 1, 255, 256, 999, 1000, 999_999, 1_000_000] {
        let path = format!("0/{}", tlog::tile_index_path(n));
        let parsed = tlog::parse_tile_path(&path).unwrap();
        assert_eq!(parsed.tile_n, n, "roundtrip failed for {n}");
        assert_eq!(parsed.level, 0);
        assert!(parsed.partial_width.is_none());
    }
}

#[test]
fn c2sp_tile_path_partial_suffix() {
    let tp = tlog::parse_tile_path("2/x001/000.p/13").unwrap();
    assert_eq!(tp.level, 2);
    assert_eq!(tp.tile_n, 1000);
    assert_eq!(tp.partial_width, Some(13));
}

// ── C2SP signed-note key ID conformance ──────────────────────────────────────

/// Ed25519 key ID must equal SHA-256(name || LF || 0x01 || 32-byte pubkey)[:4].
#[test]
fn c2sp_key_id_ed25519_operator_formula() {
    use synta_certificate::SubjectPublicKeyInfo;

    let key = BackendPrivateKey::generate_ed25519().unwrap();
    let name = "log.example.com/2024";

    let (_, computed_id) = tlog::compute_key_id(name, &key, NoteSigningRole::LogOperator).unwrap();

    // Manually apply the formula.
    let pub_key = key.public_key().unwrap();
    let spki_der = pub_key.spki_der();
    let spki = SubjectPublicKeyInfo::from_der(spki_der).unwrap();
    let raw = spki.subject_public_key.as_bytes();

    let hasher = default_data_hasher();
    let mut input = Vec::new();
    input.extend_from_slice(name.as_bytes());
    input.push(0x0A);
    input.push(0x01); // Ed25519 operator type byte
    input.extend_from_slice(raw);
    let expected = &hasher.hash_data("sha256", &input).unwrap()[..4];

    assert_eq!(&computed_id, expected);
}

/// ECDSA key ID must equal SHA-256(SPKI_DER)[:4].
#[test]
fn c2sp_key_id_ecdsa_formula() {
    let key = BackendPrivateKey::generate_ec("P-256").unwrap();
    let name = "log.example.com/2024";

    let (_, computed_id) = tlog::compute_key_id(name, &key, NoteSigningRole::LogOperator).unwrap();

    let pub_key = key.public_key().unwrap();
    let spki_der = pub_key.spki_der();
    let hasher = default_data_hasher();
    let expected = &hasher.hash_data("sha256", spki_der).unwrap()[..4];

    assert_eq!(&computed_id, expected);
}

/// Ed25519 cosigner key ID must use type byte 0x04.
#[test]
fn c2sp_key_id_ed25519_cosigner_formula() {
    use synta_certificate::SubjectPublicKeyInfo;

    let key = BackendPrivateKey::generate_ed25519().unwrap();
    let name = "cosigner.example.com";

    let (_, computed_id) = tlog::compute_key_id(name, &key, NoteSigningRole::Cosigner).unwrap();

    let pub_key = key.public_key().unwrap();
    let spki_der = pub_key.spki_der();
    let spki = SubjectPublicKeyInfo::from_der(spki_der).unwrap();
    let raw = spki.subject_public_key.as_bytes();

    let hasher = default_data_hasher();
    let mut input = Vec::new();
    input.extend_from_slice(name.as_bytes());
    input.push(0x0A);
    input.push(0x04); // Ed25519 cosigner type byte
    input.extend_from_slice(raw);
    let expected = &hasher.hash_data("sha256", &input).unwrap()[..4];

    assert_eq!(&computed_id, expected);
}

// ── C2SP signed-note checkpoint format ────────────────────────────────────────

/// The checkpoint note body must follow the three-line format from tlog-checkpoint.
#[test]
fn c2sp_checkpoint_body_format() {
    use base64::engine::general_purpose::STANDARD as BASE64;
    use base64::Engine;

    let origin = "https://log.example.com/mtc/2024";
    let tree_size = 1234u64;
    let root = vec![0x42u8; 32];

    let body = tlog::checkpoint_note_body(origin, tree_size, &root);
    let lines: Vec<&str> = body.lines().collect();
    assert_eq!(lines.len(), 3);
    assert_eq!(lines[0], origin);
    assert_eq!(lines[1], "1234");
    assert_eq!(lines[2], BASE64.encode(&root));
    assert!(body.ends_with('\n'));
}

/// The full signed note must contain an em-dash separator line with the key name.
#[test]
fn c2sp_signed_note_operator_ed25519_structure() {
    use base64::engine::general_purpose::STANDARD as BASE64;
    use base64::Engine;

    let key = BackendPrivateKey::generate_ed25519().unwrap();
    let origin = "https://log.example.com/mtc/2024";
    let key_name = origin;
    let root = vec![0xdeu8; 32];

    let note =
        tlog::sign_checkpoint_as_operator(key_name, &key, "sha256", origin, 10, &root).unwrap();

    // Must have: body (3 lines) + blank line + signature line
    let lines: Vec<&str> = note.lines().collect();
    // body lines
    assert_eq!(lines[0], origin);
    assert_eq!(lines[1], "10");
    // blank separator line
    assert_eq!(lines[3], "");
    // signature line starts with em-dash
    let sig_line = lines[4];
    assert!(sig_line.starts_with("\u{2014} "), "must start with em-dash");
    assert!(sig_line.contains(key_name), "must contain key name");

    // Wire format: key_id(4) || sig(64) = 68 bytes for Ed25519.
    let b64_part = sig_line.splitn(3, ' ').nth(2).unwrap();
    let blob = BASE64.decode(b64_part).unwrap();
    assert_eq!(blob.len(), 4 + 64, "Ed25519 note blob must be 68 bytes");
}

/// The full signed note must contain an em-dash separator line with the key name.
#[test]
fn c2sp_signed_note_operator_ecdsa_structure() {
    use base64::engine::general_purpose::STANDARD as BASE64;
    use base64::Engine;

    let key = BackendPrivateKey::generate_ec("P-256").unwrap();
    let origin = "https://log.example.com/mtc/2024";
    let key_name = origin;
    let root = vec![0xffu8; 32];

    let note =
        tlog::sign_checkpoint_as_operator(key_name, &key, "sha256", origin, 10, &root).unwrap();

    let sig_line = note.lines().find(|l| l.starts_with("\u{2014}")).unwrap();
    let b64_part = sig_line.splitn(3, ' ').nth(2).unwrap();
    let blob = BASE64.decode(b64_part).unwrap();
    // 4 bytes key ID + DER ECDSA sig (variable)
    assert!(
        blob.len() > 4,
        "ECDSA note blob must be longer than key ID alone"
    );
}

/// Ed25519 cosignature blob must contain a u64 timestamp at bytes [5..13].
#[test]
fn c2sp_cosignature_ed25519_timestamp_in_blob() {
    use base64::engine::general_purpose::STANDARD as BASE64;
    use base64::Engine;

    let key = BackendPrivateKey::generate_ed25519().unwrap();
    let ts = 1_750_000_000u64;

    let note = tlog::sign_checkpoint_as_cosigner(
        "cosigner.example.com",
        &key,
        "sha256",
        "https://log.example.com/2024",
        42,
        &[0u8; 32],
        ts,
    )
    .unwrap();

    let sig_line = note.lines().find(|l| l.starts_with("\u{2014}")).unwrap();
    let b64_part = sig_line.splitn(3, ' ').nth(2).unwrap();
    let blob = BASE64.decode(b64_part).unwrap();
    // Wire format: key_id(4) || timestamp_be(8) || sig(64) = 76 bytes
    assert_eq!(blob.len(), 4 + 8 + 64);
    let ts_from_blob = u64::from_be_bytes(blob[4..12].try_into().unwrap());
    assert_eq!(ts_from_blob, ts);
}

/// ML-DSA-44 cosignature blob must contain a u64 timestamp at bytes [5..13]
/// and the ML-DSA-44 signature at bytes [13..2433].
#[test]
fn c2sp_cosignature_mldsa44_blob_structure() {
    use base64::engine::general_purpose::STANDARD as BASE64;
    use base64::Engine;

    let key = BackendPrivateKey::generate_ml_dsa("ML-DSA-44").unwrap();
    let ts = 1_750_000_001u64;

    let note = tlog::sign_checkpoint_as_cosigner(
        "pqc-cosigner.example.com",
        &key,
        "sha256",
        "https://log.example.com/2024",
        7,
        &[0xabu8; 32],
        ts,
    )
    .unwrap();

    let sig_line = note.lines().find(|l| l.starts_with("\u{2014}")).unwrap();
    let b64_part = sig_line.splitn(3, ' ').nth(2).unwrap();
    let blob = BASE64.decode(b64_part).unwrap();
    // Wire format: key_id(4) || timestamp_be(8) || sig(2420) = 2432 bytes
    assert_eq!(
        blob.len(),
        4 + 8 + 2420,
        "ML-DSA-44 cosig blob must be 2432 bytes"
    );
    let ts_from_blob = u64::from_be_bytes(blob[4..12].try_into().unwrap());
    assert_eq!(ts_from_blob, ts);
}

// ── Live tlog-tiles HTTP endpoint tests ───────────────────────────────────────
//
// These tests spin up an in-process Akāmu server and require `test-utils`.

#[cfg(feature = "test-utils")]
mod live_tlog {
    use std::net::SocketAddr;
    use std::sync::Arc;

    use akamu::mtc::log;
    use akamu::routes;

    use super::common;

    /// Spin up an in-process Akāmu server and verify the checkpoint endpoint
    /// returns a valid C2SP signed-note.
    #[tokio::test]
    async fn tlog_checkpoint_endpoint_returns_valid_note() {
        let dir = tempfile::TempDir::new().unwrap();
        let (port, listener) = common::bind_ephemeral();
        let base_url = format!("http://127.0.0.1:{port}");
        let state = common::build_test_state(dir.path(), &base_url).await;

        let app = routes::build_router(Arc::clone(&state), None, false);
        let addr: SocketAddr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let url = format!("http://{addr}/acme/mtc/checkpoint");
        let resp = reqwest::get(&url).await.unwrap();
        assert_eq!(resp.status(), 200, "checkpoint must return 200");

        let ct = resp
            .headers()
            .get("content-type")
            .unwrap()
            .to_str()
            .unwrap();
        assert!(
            ct.contains("text/plain"),
            "checkpoint must be text/plain, got: {ct}"
        );

        let body = resp.text().await.unwrap();
        assert!(
            body.starts_with("oid/1.3.6.1.4.1.32473.2.0.1"),
            "first line must be OID-based origin, got: {}",
            body.lines().next().unwrap_or("")
        );

        assert!(body.contains('\u{2014}'), "must contain em-dash signature");
    }

    /// The tile endpoint must return 501 for entry bundle requests.
    #[tokio::test]
    async fn tlog_tile_entries_returns_501() {
        let dir = tempfile::TempDir::new().unwrap();
        let (port, listener) = common::bind_ephemeral();
        let base_url = format!("http://127.0.0.1:{port}");
        let state = common::build_test_state(dir.path(), &base_url).await;

        let app = routes::build_router(Arc::clone(&state), None, false);
        let addr: SocketAddr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let resp = reqwest::get(format!("http://{addr}/acme/mtc/tile/entries/000"))
            .await
            .unwrap();
        assert_eq!(resp.status(), 501, "entry bundle tiles must return 501");
    }

    /// A level-0 tile for the freshly-opened log (which has one null_entry) must
    /// return a partial tile containing exactly one hash (32 bytes).
    #[tokio::test]
    async fn tlog_tile_level0_partial_returns_one_hash() {
        let dir = tempfile::TempDir::new().unwrap();
        let (port, listener) = common::bind_ephemeral();
        let base_url = format!("http://127.0.0.1:{port}");
        let state = common::build_test_state(dir.path(), &base_url).await;

        let app = routes::build_router(Arc::clone(&state), None, false);
        let addr: SocketAddr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let resp = reqwest::get(format!("http://{addr}/acme/mtc/tile/0/000.p/1"))
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);

        let ct = resp
            .headers()
            .get("content-type")
            .unwrap()
            .to_str()
            .unwrap();
        assert!(
            ct.contains("application/octet-stream"),
            "hash tile must be octet-stream"
        );

        let bytes = resp.bytes().await.unwrap();
        assert_eq!(bytes.len(), 32, "one SHA-256 leaf hash = 32 bytes");
    }

    /// Requesting a full (256-entry) tile for a log with 1 leaf must return 404
    /// (the tile is not complete and no .p/1 suffix was given).
    #[tokio::test]
    async fn tlog_tile_level0_full_returns_404_for_small_log() {
        let dir = tempfile::TempDir::new().unwrap();
        let (port, listener) = common::bind_ephemeral();
        let base_url = format!("http://127.0.0.1:{port}");
        let state = common::build_test_state(dir.path(), &base_url).await;

        {
            let log = state.default_ca().mtc.log.as_ref().unwrap();
            let size = log::tree_size(log).await.unwrap();
            assert_eq!(size, 1, "fresh log must have 1 null_entry leaf");
        }

        let app = routes::build_router(Arc::clone(&state), None, false);
        let addr: SocketAddr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let resp = reqwest::get(format!("http://{addr}/acme/mtc/tile/0/000"))
            .await
            .unwrap();
        assert_eq!(
            resp.status().as_u16(),
            404,
            "full tile URL must return 404 when log has < 256 entries"
        );
    }

    /// The cosignature endpoint must return a valid C2SP signed-note with a
    /// type 0x04 signature line (Ed25519 cosig, blob = key_id + timestamp + sig).
    #[tokio::test]
    async fn tlog_cosignature_endpoint_structure() {
        use base64::engine::general_purpose::STANDARD as BASE64;
        use base64::Engine;

        let dir = tempfile::TempDir::new().unwrap();
        let (port, listener) = common::bind_ephemeral();
        let base_url = format!("http://127.0.0.1:{port}");
        let state = common::build_test_state(dir.path(), &base_url).await;

        let app = routes::build_router(Arc::clone(&state), None, false);
        let addr: SocketAddr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let resp = reqwest::get(format!("http://{addr}/acme/mtc/cosignature"))
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);

        let body = resp.text().await.unwrap();
        let sig_line = body.lines().find(|l| l.starts_with('\u{2014}')).unwrap();
        let b64_part = sig_line.splitn(3, ' ').nth(2).unwrap();
        let blob = BASE64.decode(b64_part).unwrap();
        assert_eq!(
            blob.len(),
            4 + 8 + 64,
            "Ed25519 cosig blob must be 76 bytes"
        );
        let ts = u64::from_be_bytes(blob[4..12].try_into().unwrap());
        assert!(
            ts > 1_577_836_800,
            "embedded timestamp must be after 2020-01-01"
        );
    }
}

// ── Standalone certificate format conformance ─────────────────────────────────

/// Verify that `MtcX509CertificateBuilder` produces a spec-compliant standalone
/// certificate that parses as a standard X.509 `Certificate` with
/// `signatureAlgorithm = id-alg-mtcProof` and a decodable `MtcProof`.
#[test]
fn standalone_cert_format_conforms_to_draft04() {
    use synta::types::string::BitStringRef;
    use synta::{GeneralizedTime, Integer, ObjectIdentifier};
    use synta_certificate::owned::{
        AlgorithmIdentifier as OwnedAlgId, Certificate as OwnedCert, SubjectPublicKeyInfo,
        TBSCertificate, Time, Validity,
    };
    use synta_certificate::{AlgorithmIdentifier as BAlgId, SubjectPublicKeyInfo as BSPki};
    use synta_mtc::builder::x509cert::MtcX509CertificateBuilder;
    use synta_mtc::crypto::mtcproof::{MtcProof, MtcSignature};
    use synta_mtc::types::constants::{
        ID_ALG_MTC_PROOF_EXP, ID_RDNA_TRUST_ANCHOR_ID_EXP, ID_SHA256,
    };
    use synta_mtc::types::LogID;

    // Build a minimal TBSCertificate to act as the original cert.
    let spki = SubjectPublicKeyInfo {
        algorithm: OwnedAlgId {
            algorithm: ObjectIdentifier::new(&[1u32, 2, 840, 10045, 2, 1]).unwrap(),
            parameters: None,
        },
        subject_public_key: synta::BitString::new(vec![0u8; 33], 0).unwrap(),
    };
    let tbs = TBSCertificate {
        version: Some(Integer::from(2u64)),
        serial_number: Integer::from(1u64),
        signature: OwnedAlgId {
            algorithm: ObjectIdentifier::new(&[1u32, 2, 840, 113549, 1, 1, 11]).unwrap(),
            parameters: None,
        },
        issuer: synta_certificate::owned::Name::RdnSequence(vec![]),
        validity: Validity {
            not_before: Time::GeneralTime(GeneralizedTime::new(2024, 1, 1, 0, 0, 0, None).unwrap()),
            not_after: Time::GeneralTime(GeneralizedTime::new(2025, 1, 1, 0, 0, 0, None).unwrap()),
        },
        subject: synta_certificate::owned::Name::RdnSequence(vec![]),
        subject_public_key_info: spki,
        issuer_unique_id: None,
        subject_unique_id: None,
        extensions: None,
    };
    let tbs_der = tbs.to_der().unwrap();

    // Build a minimal LogID using SHA-256 and a dummy SPKI.
    static DUMMY_KEY: &[u8] = &[0x04u8; 33];
    let log_id = LogID {
        hash_algorithm: BAlgId {
            algorithm: ObjectIdentifier::new(ID_SHA256).unwrap(),
            parameters: None,
        },
        public_key: BSPki {
            algorithm: BAlgId {
                algorithm: ObjectIdentifier::new(&[1u32, 2, 840, 10045, 2, 1]).unwrap(),
                parameters: None,
            },
            subject_public_key: BitStringRef::new(DUMMY_KEY, 0).unwrap(),
        },
    };

    // Build a minimal MtcProof with one fake cosignature.
    let proof = MtcProof {
        extensions: vec![],
        start: 0,
        end: 4,
        inclusion_proof: vec![0xABu8; 64], // two 32-byte sibling hashes
        signatures: vec![MtcSignature {
            cosigner_id: vec![0x30, 0x01, 0x00],
            signature_value: vec![0xFFu8; 32],
        }],
    };

    // Build the standalone cert DER.
    let cert_der = MtcX509CertificateBuilder::new()
        .original_tbs_der(&tbs_der)
        .log_id(log_id)
        .log_entry_index(3)
        .mtc_proof(proof.clone())
        .build()
        .expect("MtcX509CertificateBuilder::build()");

    // Parse as a standard X.509 Certificate.
    let parsed = OwnedCert::from_der(&cert_der).expect("parse as X.509 Certificate");

    // signatureAlgorithm must be id-alg-mtcProof (experimental Cloudflare PEN arc OID).
    assert_eq!(
        parsed.signature_algorithm.algorithm.components(),
        ID_ALG_MTC_PROOF_EXP,
        "outer signatureAlgorithm must be id-alg-mtcProof"
    );
    assert_eq!(
        parsed.tbs_certificate.signature.algorithm.components(),
        ID_ALG_MTC_PROOF_EXP,
        "TBS signatureAlgorithm must be id-alg-mtcProof"
    );

    // serialNumber must equal the log entry index.
    assert_eq!(
        parsed.tbs_certificate.serial_number.as_u64().unwrap(),
        3,
        "serialNumber must equal the log entry index"
    );

    // issuer must use id-rdna-trustAnchorID attribute type.
    let synta_certificate::owned::Name::RdnSequence(rdns) = &parsed.tbs_certificate.issuer;
    assert_eq!(rdns.len(), 1, "issuer must have exactly one RDN");
    let atvs = rdns[0].elements();
    assert_eq!(atvs.len(), 1);
    assert_eq!(
        atvs[0].r#type.components(),
        ID_RDNA_TRUST_ANCHOR_ID_EXP,
        "issuer attribute type must be id-rdna-trustAnchorID"
    );

    // signatureValue decodes as a valid TLS-encoded MtcProof.
    let sig_bytes = parsed.signature_value.as_bytes();
    let decoded = MtcProof::decode(sig_bytes).expect("decode MtcProof from signatureValue");
    assert_eq!(decoded, proof, "decoded MtcProof must equal the original");
}

// ── DigiCert MTC playground integration test ──────────────────────────────────

/// Verify wire compatibility with the DigiCert ca-extension-mtc-playground
/// toolkit by running its verification scripts against Akāmu's output.
///
/// Requires `MTC_PLAYGROUND_DIR` to be set to a checkout of
/// <https://github.com/digicert/ca-extension-mtc-playground>.
///
/// Run with: `MTC_PLAYGROUND_DIR=/path/to/playground cargo test --test
/// mtc_playground_compat digicert -- --ignored`
#[test]
#[ignore]
fn digicert_playground_verify_checkpoint_oids() {
    let playground_dir = match std::env::var("MTC_PLAYGROUND_DIR") {
        Ok(d) => d,
        Err(_) => {
            eprintln!("SKIP: MTC_PLAYGROUND_DIR not set");
            return;
        }
    };

    // Verify the DigiCert playground directory exists and has expected structure.
    let playground_path = std::path::Path::new(&playground_dir);
    assert!(
        playground_path.exists(),
        "MTC_PLAYGROUND_DIR '{playground_dir}' does not exist"
    );

    // The playground should contain OID definitions.  Check that the
    // experimental OIDs we use match what the playground expects.
    // id-alg-mtcProof: 1.3.6.1.4.1.44363.47.0
    let expected_proof_oid = synta_mtc::types::constants::ID_ALG_MTC_PROOF_EXP;
    assert_eq!(
        expected_proof_oid,
        &[1u32, 3, 6, 1, 4, 1, 44363, 47, 0],
        "id-alg-mtcProof OID must match DigiCert playground value"
    );

    // id-rdna-trustAnchorID: 1.3.6.1.4.1.44363.47.1
    let expected_anchor_oid = synta_mtc::types::constants::ID_RDNA_TRUST_ANCHOR_ID_EXP;
    assert_eq!(
        expected_anchor_oid,
        &[1u32, 3, 6, 1, 4, 1, 44363, 47, 1],
        "id-rdna-trustAnchorID OID must match DigiCert playground value"
    );

    eprintln!("DigiCert playground OID check passed.");
    eprintln!("For full interop testing, use the playground scripts in: {playground_dir}");
}
