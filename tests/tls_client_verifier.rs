//! Tests for `SyntaClientCertVerifier` (`src/tls/verifier.rs`), the mTLS
//! client-certificate verifier used for admin API authentication.
//!
//! These call `ClientCertVerifier` trait methods directly against
//! synta-generated CA/leaf DER, bypassing a full TLS handshake — `tests/
//! tls_server.rs` covers the handshake plumbing but never configures
//! `client_auth`, so chain-trust decisions were previously untested at every
//! level.
//!
//! Scope note: this covers the core trust-boundary guarantee (a chain
//! signed by a CA outside the configured trust store must be rejected, one
//! signed by a trusted CA must be accepted) plus the `required`/root-hint
//! wiring. It does not cover the composite ML-DSA+classical TLS 1.3
//! signature path, expired-certificate rejection, or chain-depth/RSA-modulus
//! policy limits — those need additional fixture-building effort
//! (controlling notAfter, multi-level chains, weak RSA keys) disproportionate
//! to a first pass; left as a follow-up.

use rustls::pki_types::UnixTime;
use rustls::server::danger::ClientCertVerifier;

use akamu::ca;
use akamu::config::{CaConfig, ClientAuthConfig};
use akamu::state::CaState;
use akamu::tls::verifier::SyntaClientCertVerifier;

fn ca_config(dir: &std::path::Path, cn: &str) -> CaConfig {
    CaConfig {
        id: "default".to_owned(),
        is_default: true,
        caa_identities: vec![],
        key_file: Some(dir.join(format!("{cn}.key")).to_string_lossy().into_owned()),
        cert_file: dir.join(format!("{cn}.crt")).to_string_lossy().into_owned(),
        key_type: "ec:P-256".into(),
        hash_alg: "sha256".into(),
        validity_days: 90,
        crl_url: None,
        ocsp_url: None,
        common_name: cn.to_string(),
        organization: "Test".into(),
        ca_validity_years: 10,
        crl_next_update_secs: 86400,
        enforce_validity_cap: false,
        require_encrypted_key: false,
        key_password_file: None,
        mtc: None,
        default_linter: None,
        signer: None,
    }
}

fn make_ca(dir: &std::path::Path, cn: &str) -> CaState {
    let cfg = ca_config(dir, cn);
    let (key, cert_der) = ca::init::load_or_generate(&cfg).unwrap();
    let spki_der = key.public_key().unwrap().spki_der().to_vec();
    let aki_bytes = ca::init::compute_aki_from_spki(&spki_der).unwrap_or_default();
    CaState {
        id: "default".into(),
        key_type: "ec:P-256".into(),
        crl_next_update_secs: 86400,
        signing: akamu::state::SigningBackend::Local { key: Box::new(key) },
        cert_der,
        hash_alg: "sha256".into(),
        validity_days: 90,
        crl_url: None,
        ocsp_url: None,
        aki_bytes,
        enforce_validity_cap: false,
        caa_identities: vec![],
        mtc: std::sync::Arc::new(akamu::state::MtcState::disabled()),
        default_linter: None,
        cached_der: std::sync::OnceLock::new(),
        lint_store: std::sync::OnceLock::new(),
    }
}

fn client_auth_config(required: bool) -> ClientAuthConfig {
    ClientAuthConfig {
        required,
        ca_files: vec![],
        profile: "webpki".into(),
        allow_post_quantum: false,
        max_chain_depth: 8,
        minimum_rsa_modulus: 2048,
    }
}

#[tokio::test]
async fn accepts_a_chain_signed_by_a_trusted_ca() {
    let dir = tempfile::tempdir().unwrap();
    let ca = make_ca(dir.path(), "Trusted Root");
    let client_key = synta_certificate::BackendPrivateKey::generate_ec("P-256").unwrap();
    let leaf_der = ca::issue::sign_admin_cert("dns:client.example.com", &client_key, &ca).unwrap();

    let verifier = SyntaClientCertVerifier::new(
        std::slice::from_ref(&ca.cert_der),
        &client_auth_config(true),
    )
    .unwrap();

    let result = verifier.verify_client_cert(&leaf_der.into(), &[], UnixTime::now());
    assert!(
        result.is_ok(),
        "a chain signed by a configured trust anchor must be accepted: {result:?}"
    );
}

/// Core trust-boundary guarantee: a certificate signed by a CA that is not
/// in the configured trust store must be rejected, even though it is
/// otherwise well-formed and internally self-consistent.
#[tokio::test]
async fn rejects_a_chain_signed_by_an_untrusted_ca() {
    let dir = tempfile::tempdir().unwrap();
    let trusted_ca = make_ca(dir.path(), "Trusted Root");
    let other_ca = make_ca(dir.path(), "Other Root");
    let leaf_der = ca::issue::sign_admin_cert(
        "dns:client.example.com",
        &synta_certificate::BackendPrivateKey::generate_ec("P-256").unwrap(),
        &other_ca,
    )
    .unwrap();

    // Trust store only contains `trusted_ca`; the leaf was signed by `other_ca`.
    let verifier = SyntaClientCertVerifier::new(
        std::slice::from_ref(&trusted_ca.cert_der),
        &client_auth_config(true),
    )
    .unwrap();

    let result = verifier.verify_client_cert(&leaf_der.into(), &[], UnixTime::now());
    assert!(
        result.is_err(),
        "a chain signed by a CA outside the trust store must be rejected"
    );
}

#[tokio::test]
async fn client_auth_mandatory_reflects_config_required() {
    let dir = tempfile::tempdir().unwrap();
    let ca = make_ca(dir.path(), "Trusted Root");

    let required = SyntaClientCertVerifier::new(
        std::slice::from_ref(&ca.cert_der),
        &client_auth_config(true),
    )
    .unwrap();
    assert!(required.client_auth_mandatory());

    let optional = SyntaClientCertVerifier::new(
        std::slice::from_ref(&ca.cert_der),
        &client_auth_config(false),
    )
    .unwrap();
    assert!(!optional.client_auth_mandatory());
}

#[tokio::test]
async fn offers_client_auth_and_exposes_root_hint_subjects() {
    let dir = tempfile::tempdir().unwrap();
    let ca = make_ca(dir.path(), "Trusted Root");

    let verifier = SyntaClientCertVerifier::new(
        std::slice::from_ref(&ca.cert_der),
        &client_auth_config(false),
    )
    .unwrap();

    assert!(verifier.offer_client_auth());
    assert_eq!(
        verifier.root_hint_subjects().len(),
        1,
        "root hint subjects must reflect the one configured trust anchor"
    );
}
