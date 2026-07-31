//! Fail-closed behavior tests for `src/admin/init.rs::bootstrap_operator_if_needed`.
//!
//! This function has no `AppState` dependency — only a `CaState`, a `Db`, and
//! an `AdminConfig` — so tests build those three directly rather than a full
//! integration-test router.

use std::sync::Arc;

use akamu::admin::init::bootstrap_operator_if_needed;
use akamu::ca;
use akamu::config::{AdminConfig, CaConfig};
use akamu::db;
use akamu::state::{CaState, MtcState};

fn base_ca_config(dir: &std::path::Path) -> CaConfig {
    CaConfig {
        id: "default".to_owned(),
        is_default: true,
        caa_identities: vec![],
        key_file: Some(dir.join("ca.key").to_string_lossy().into_owned()),
        cert_file: dir.join("ca.crt").to_string_lossy().into_owned(),
        key_type: "ec:P-256".into(),
        hash_alg: "sha256".into(),
        validity_days: 90,
        crl_url: None,
        ocsp_url: None,
        common_name: "Bootstrap Test CA".into(),
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

async fn build_ca_and_db(dir: &std::path::Path) -> (CaState, db::Db) {
    let ca_cfg = base_ca_config(dir);
    let (ca_key, ca_cert_der) = ca::init::load_or_generate(&ca_cfg).unwrap();
    let ca_spki_der = ca_key.public_key().unwrap().spki_der().to_vec();
    let aki_bytes = ca::init::compute_aki_from_spki(&ca_spki_der).unwrap_or_default();

    db::install_drivers();
    let db_conn = db::open("sqlite::memory:", 1, false).await.unwrap();

    let ca = CaState {
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
        aki_bytes,
        enforce_validity_cap: false,
        caa_identities: vec![],
        mtc: Arc::new(MtcState::disabled()),
        default_linter: None,
        cached_der: std::sync::OnceLock::new(),
        lint_store: std::sync::OnceLock::new(),
    };
    (ca, db_conn)
}

fn base_admin_config() -> AdminConfig {
    AdminConfig {
        bootstrap_key_type: "ec:P-256".into(),
        bootstrap_operator_cert_file: None,
        bootstrap_operator_key_file: None,
        bootstrap_operator_pkcs12_file: None,
        bootstrap_operator_pkcs12_password: "".into(),
        bootstrap_operator_name: "admin".into(),
        bootstrap_operator_gssapi_principal: None,
        proxy_auth: None,
        gssapi: None,
        session_ttl_secs: 3600,
        session_lock_secs: 900,
        auth_rate_limit: 20,
        audit_max_events: None,
        audit_overflow: "drop_oldest".into(),
        audit_alarm_threshold: 10,
        audit_alarm_action: "syslog".into(),
        max_failed_auth: 5,
        lockout_duration_secs: 1800,
    }
}

#[tokio::test]
async fn no_bootstrap_configured_is_a_no_op() {
    let dir = tempfile::tempdir().unwrap();
    let (ca, db) = build_ca_and_db(dir.path()).await;
    let cfg = base_admin_config();

    bootstrap_operator_if_needed(&cfg, &ca, &db).await.unwrap();
    assert!(db::operators::is_empty(&db).await.unwrap());
}

#[tokio::test]
async fn gssapi_bootstrap_registers_administrator_on_empty_table() {
    let dir = tempfile::tempdir().unwrap();
    let (ca, db) = build_ca_and_db(dir.path()).await;
    let mut cfg = base_admin_config();
    cfg.bootstrap_operator_gssapi_principal = Some("admin@REALM".into());

    bootstrap_operator_if_needed(&cfg, &ca, &db).await.unwrap();

    let op = db::operators::get_by_principal(&db, "admin@REALM")
        .await
        .unwrap()
        .expect("bootstrap operator must be registered");
    assert_eq!(op.role, "administrator");
    assert_eq!(op.name, "admin");
    assert_eq!(op.ca_id, "", "administrator must be server-wide scoped");
}

#[tokio::test]
async fn gssapi_bootstrap_is_idempotent_when_principal_already_registered() {
    let dir = tempfile::tempdir().unwrap();
    let (ca, db) = build_ca_and_db(dir.path()).await;
    let mut cfg = base_admin_config();
    cfg.bootstrap_operator_gssapi_principal = Some("admin@REALM".into());

    bootstrap_operator_if_needed(&cfg, &ca, &db).await.unwrap();
    // Second call (simulating a restart) must not error or duplicate the row.
    bootstrap_operator_if_needed(&cfg, &ca, &db).await.unwrap();

    let count = db::operators::list(&db, 1000, 0).await.unwrap().len();
    assert_eq!(count, 1, "restart must not create a second operator row");
}

/// Fail-closed guarantee: if the configured bootstrap principal isn't already
/// registered but the operators table is non-empty (some other operator
/// exists), refuse rather than silently creating a second Administrator —
/// this is very likely a misconfiguration (e.g. principal typo after a
/// previous successful bootstrap under a different principal).
#[tokio::test]
async fn gssapi_bootstrap_fails_closed_when_table_nonempty_without_matching_principal() {
    let dir = tempfile::tempdir().unwrap();
    let (ca, db) = build_ca_and_db(dir.path()).await;
    db::operators::insert(
        &db,
        "existing-op",
        "administrator",
        None,
        Some("someone-else@REALM"),
        "",
        "2024-01-01T00:00:00Z",
    )
    .await
    .unwrap();

    let mut cfg = base_admin_config();
    cfg.bootstrap_operator_gssapi_principal = Some("admin@REALM".into());

    let err = bootstrap_operator_if_needed(&cfg, &ca, &db)
        .await
        .unwrap_err();
    assert!(matches!(err, akamu::error::AcmeError::Config(_)));
    assert!(
        db::operators::get_by_principal(&db, "admin@REALM")
            .await
            .unwrap()
            .is_none(),
        "no operator must have been created for the unregistered principal"
    );
}

#[tokio::test]
async fn pkcs12_bootstrap_creates_file_and_operator_on_empty_table() {
    let dir = tempfile::tempdir().unwrap();
    let (ca, db) = build_ca_and_db(dir.path()).await;
    let p12_path = dir.path().join("admin.p12");
    let mut cfg = base_admin_config();
    cfg.bootstrap_operator_pkcs12_file = Some(p12_path.to_string_lossy().into_owned());

    bootstrap_operator_if_needed(&cfg, &ca, &db).await.unwrap();

    assert!(p12_path.exists(), "PKCS#12 bundle must be written");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(&p12_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "PKCS#12 bundle must be owner-only readable");
    }

    let rows = db::operators::list(&db, 1000, 0).await.unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].role, "administrator");
    assert!(rows[0].cert_fingerprint.is_some());
}

#[tokio::test]
async fn pkcs12_bootstrap_is_idempotent_across_restarts() {
    let dir = tempfile::tempdir().unwrap();
    let (ca, db) = build_ca_and_db(dir.path()).await;
    let p12_path = dir.path().join("admin.p12");
    let mut cfg = base_admin_config();
    cfg.bootstrap_operator_pkcs12_file = Some(p12_path.to_string_lossy().into_owned());

    bootstrap_operator_if_needed(&cfg, &ca, &db).await.unwrap();
    // Simulate a restart: file and DB row both already exist.
    bootstrap_operator_if_needed(&cfg, &ca, &db).await.unwrap();

    let rows = db::operators::list(&db, 1000, 0).await.unwrap();
    assert_eq!(rows.len(), 1, "restart must not create a second operator");
}

/// Fail-closed guarantee: a PKCS#12 file on disk with no matching DB row
/// indicates a partial write (e.g. the process crashed between writing the
/// file and inserting the row) — refuse rather than silently re-generating a
/// second, different bootstrap identity.
#[tokio::test]
async fn pkcs12_bootstrap_fails_closed_on_partial_write() {
    let dir = tempfile::tempdir().unwrap();
    let (ca, db) = build_ca_and_db(dir.path()).await;
    let p12_path = dir.path().join("admin.p12");
    let mut cfg = base_admin_config();
    cfg.bootstrap_operator_pkcs12_file = Some(p12_path.to_string_lossy().into_owned());

    bootstrap_operator_if_needed(&cfg, &ca, &db).await.unwrap();
    // Simulate the partial-write scenario: DB row lost (e.g. DB reset) but
    // the file survives.
    sqlx::query("DELETE FROM operators")
        .execute(&db)
        .await
        .unwrap();

    let err = bootstrap_operator_if_needed(&cfg, &ca, &db)
        .await
        .unwrap_err();
    assert!(matches!(err, akamu::error::AcmeError::Config(_)));
}

/// Fail-closed guarantee: refuse to bootstrap a second Administrator when the
/// PKCS#12 file is absent (e.g. deleted) but the operators table already has
/// rows from a prior bootstrap — this would otherwise silently mint a new
/// identity alongside the existing one.
#[tokio::test]
async fn pkcs12_bootstrap_fails_closed_when_file_absent_but_table_nonempty() {
    let dir = tempfile::tempdir().unwrap();
    let (ca, db) = build_ca_and_db(dir.path()).await;
    db::operators::insert(
        &db,
        "existing-op",
        "administrator",
        Some("deadbeef"),
        None,
        "",
        "2024-01-01T00:00:00Z",
    )
    .await
    .unwrap();

    let p12_path = dir.path().join("admin.p12");
    let mut cfg = base_admin_config();
    cfg.bootstrap_operator_pkcs12_file = Some(p12_path.to_string_lossy().into_owned());

    let err = bootstrap_operator_if_needed(&cfg, &ca, &db)
        .await
        .unwrap_err();
    assert!(matches!(err, akamu::error::AcmeError::Config(_)));
    assert!(
        !p12_path.exists(),
        "no file must be written on the fail-closed path"
    );
}

#[tokio::test]
async fn pem_bootstrap_creates_files_and_operator_on_empty_table() {
    let dir = tempfile::tempdir().unwrap();
    let (ca, db) = build_ca_and_db(dir.path()).await;
    let cert_path = dir.path().join("admin.crt");
    let key_path = dir.path().join("admin.key");
    let mut cfg = base_admin_config();
    cfg.bootstrap_operator_cert_file = Some(cert_path.to_string_lossy().into_owned());
    cfg.bootstrap_operator_key_file = Some(key_path.to_string_lossy().into_owned());

    bootstrap_operator_if_needed(&cfg, &ca, &db).await.unwrap();

    assert!(cert_path.exists());
    assert!(key_path.exists());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(&key_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "private key file must be owner-only readable");
    }

    let rows = db::operators::list(&db, 1000, 0).await.unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].role, "administrator");
}

/// Fail-closed guarantee: an asymmetric on-disk state (only one of cert/key
/// present) is ambiguous — it could mean a partially-completed bootstrap or
/// operator tampering — and must not be silently "fixed" by regenerating the
/// missing half.
#[tokio::test]
async fn pem_bootstrap_fails_closed_on_asymmetric_file_state() {
    let dir = tempfile::tempdir().unwrap();
    let (ca, db) = build_ca_and_db(dir.path()).await;
    let cert_path = dir.path().join("admin.crt");
    let key_path = dir.path().join("admin.key");
    std::fs::write(&cert_path, b"not a real cert, just needs to exist").unwrap();

    let mut cfg = base_admin_config();
    cfg.bootstrap_operator_cert_file = Some(cert_path.to_string_lossy().into_owned());
    cfg.bootstrap_operator_key_file = Some(key_path.to_string_lossy().into_owned());

    let err = bootstrap_operator_if_needed(&cfg, &ca, &db)
        .await
        .unwrap_err();
    assert!(matches!(err, akamu::error::AcmeError::Config(_)));
    assert!(db::operators::is_empty(&db).await.unwrap());
}

/// Fail-closed guarantee: PEM files on disk with no matching DB row indicate
/// a partial write, same as the PKCS#12 case.
#[tokio::test]
async fn pem_bootstrap_fails_closed_on_partial_write() {
    let dir = tempfile::tempdir().unwrap();
    let (ca, db) = build_ca_and_db(dir.path()).await;
    let cert_path = dir.path().join("admin.crt");
    let key_path = dir.path().join("admin.key");
    let mut cfg = base_admin_config();
    cfg.bootstrap_operator_cert_file = Some(cert_path.to_string_lossy().into_owned());
    cfg.bootstrap_operator_key_file = Some(key_path.to_string_lossy().into_owned());

    bootstrap_operator_if_needed(&cfg, &ca, &db).await.unwrap();
    sqlx::query("DELETE FROM operators")
        .execute(&db)
        .await
        .unwrap();

    let err = bootstrap_operator_if_needed(&cfg, &ca, &db)
        .await
        .unwrap_err();
    assert!(matches!(err, akamu::error::AcmeError::Config(_)));
}
