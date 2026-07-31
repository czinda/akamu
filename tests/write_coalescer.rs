//! Tests for `WriteCoalescer` (`src/db/coalescer.rs`).
//!
//! The coalescer opens its own dedicated `AnyConnection` outside the main
//! sqlx pool (needed for `BEGIN IMMEDIATE`/`SAVEPOINT` control) and requires
//! `PRAGMA journal_mode=WAL`, which SQLite rejects on `:memory:` databases —
//! unlike every other test in this suite, these need a real file-backed
//! database. The schema is created by opening the file once through the
//! normal `db::open` (which runs migrations), then the coalescer connects
//! to the same file separately.

use tempfile::TempDir;

use akamu::db;
use akamu::db::coalescer::{CoalescerAuthzPlan, WriteCoalescer};
use akamu::db::schema::{AccountRow, AuthorizationRow, CertificateRow, OrderRow};
use akamu::error::AcmeError;

async fn open_file_backed(dir: &TempDir) -> (db::Db, String) {
    let url = format!("sqlite:{}", dir.path().join("coalescer-test.db").display());
    db::install_drivers();
    let pool = db::open(&url, 4, false).await.unwrap();
    (pool, url)
}

async fn insert_account(db: &db::Db, account_id: &str) {
    db::accounts::insert(
        db,
        AccountRow {
            id: account_id.to_string(),
            status: "valid".to_string(),
            contact: None,
            public_key: vec![0u8; 4],
            jwk_thumbprint: format!("thumb-{account_id}"),
            created: 1_700_000_000,
            updated: 1_700_000_000,
            profile_grants: None,
            ca_id: String::new(),
            kerberos_principal: None,
        },
    )
    .await
    .unwrap();
}

fn sample_order(id: &str, account_id: &str) -> OrderRow {
    OrderRow {
        id: id.to_string(),
        account_id: account_id.to_string(),
        status: "pending".to_string(),
        expires: None,
        identifiers: "[{\"type\":\"dns\",\"value\":\"example.com\"}]".to_string(),
        not_before: None,
        not_after: None,
        error: None,
        certificate_id: None,
        replaces: None,
        created: 1_700_000_000,
        updated: 1_700_000_000,
        star_start_date: None,
        star_end_date: None,
        star_lifetime_secs: None,
        star_lifetime_adjust_secs: 0,
        star_allow_cert_get: 0,
        star_canceled_at: None,
        star_csr_der: None,
        profile: None,
        ca_id: "default".to_string(),
        delegation_id: None,
        allow_cert_get: 0,
        upstream_order_url: None,
        upstream_cert_url: None,
    }
}

fn sample_authz(id: &str, order_id: &str, account_id: &str) -> AuthorizationRow {
    AuthorizationRow {
        id: id.to_string(),
        order_id: order_id.to_string(),
        account_id: account_id.to_string(),
        status: "pending".to_string(),
        identifier: "{\"type\":\"dns\",\"value\":\"example.com\"}".to_string(),
        expires: None,
        wildcard: 0,
        subdomain_auth_allowed: 0,
        created: 1_700_000_000,
        updated: 1_700_000_000,
        ca_id: "default".to_string(),
    }
}

fn sample_cert(id: &str, order_id: &str, account_id: &str) -> CertificateRow {
    CertificateRow {
        id: id.to_string(),
        order_id: order_id.to_string(),
        account_id: account_id.to_string(),
        serial_number: format!("serial-{id}"),
        status: "valid".to_string(),
        der: vec![0x30, 0x00],
        pem: "-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n".to_string(),
        not_before: 1_700_000_000,
        not_after: 1_800_000_000,
        revoked_at: None,
        revocation_reason: None,
        mtc_log_index: None,
        created: 1_700_000_000,
        suggested_window_start: None,
        suggested_window_end: None,
        replaced_by: None,
        subject_dn: None,
        ca_id: "default".to_string(),
    }
}

#[tokio::test]
async fn submit_new_account_persists_row_and_marks_eab_used() {
    let dir = TempDir::new().unwrap();
    let (pool, url) = open_file_backed(&dir).await;
    db::eab::insert_if_absent(&pool, "kid-1", "aGVsbG8", 1_700_000_000, None, "sha256")
        .await
        .unwrap();
    let coalescer = WriteCoalescer::new(&url).await.unwrap();

    coalescer
        .submit_new_account(
            AccountRow {
                id: "acct-1".into(),
                status: "valid".into(),
                contact: None,
                public_key: vec![1, 2, 3],
                jwk_thumbprint: "thumb-1".into(),
                created: 1_700_000_100,
                updated: 1_700_000_100,
                profile_grants: None,
                ca_id: String::new(),
                kerberos_principal: None,
            },
            Some("kid-1".to_string()),
            1_700_000_100,
        )
        .await
        .unwrap();

    let account = db::accounts::get_by_id(&pool, "acct-1")
        .await
        .unwrap()
        .expect("account must be persisted");
    assert_eq!(account.jwk_thumbprint, "thumb-1");

    let eab = db::eab::get_by_kid(&pool, "kid-1").await.unwrap().unwrap();
    assert!(
        eab.used_at.is_some(),
        "EAB key must be marked used atomically with the account insert"
    );
}

#[tokio::test]
async fn submit_new_order_persists_order_authz_and_challenges_together() {
    let dir = TempDir::new().unwrap();
    let (pool, url) = open_file_backed(&dir).await;
    insert_account(&pool, "acct-1").await;
    let coalescer = WriteCoalescer::new(&url).await.unwrap();

    coalescer
        .submit_new_order(
            sample_order("order-1", "acct-1"),
            vec![CoalescerAuthzPlan {
                authz: sample_authz("authz-1", "order-1", "acct-1"),
                challenges: vec![("chall-1".to_string(), "http-01".to_string())],
                token: "test-token".to_string(),
            }],
            None,
        )
        .await
        .unwrap();

    assert!(db::orders::get_by_id(&pool, "order-1")
        .await
        .unwrap()
        .is_some());
    assert!(db::authz::get_by_id(&pool, "authz-1")
        .await
        .unwrap()
        .is_some());
    let challenges = db::challenges::list_by_authz(&pool, "authz-1")
        .await
        .unwrap();
    assert_eq!(challenges.len(), 1);
    assert_eq!(challenges[0].id, "chall-1");
}

/// Fail-closed / idempotency guarantee: `submit_on_valid` only transitions a
/// challenge that is currently `processing` — replaying a validation result
/// for a challenge that already moved on (or never existed) must be a no-op,
/// not silently re-apply state.
#[tokio::test]
async fn submit_on_valid_is_noop_when_challenge_not_processing() {
    let dir = TempDir::new().unwrap();
    let (pool, url) = open_file_backed(&dir).await;
    insert_account(&pool, "acct-1").await;
    db::orders::insert(&pool, sample_order("order-1", "acct-1"))
        .await
        .unwrap();
    db::authz::insert(&pool, sample_authz("authz-1", "order-1", "acct-1"))
        .await
        .unwrap();
    // No challenge row exists at all — the id below doesn't match anything.
    let coalescer = WriteCoalescer::new(&url).await.unwrap();

    let (challenge_transitioned, order_ready) = coalescer
        .submit_on_valid(
            "nonexistent-challenge".to_string(),
            "authz-1".to_string(),
            "order-1".to_string(),
            1_700_000_200,
        )
        .await
        .unwrap();

    assert!(!challenge_transitioned);
    assert!(!order_ready);
    let authz = db::authz::get_by_id(&pool, "authz-1")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        authz.status, "pending",
        "authz must not be advanced when the challenge transition didn't happen"
    );
}

/// Encodes the actual multi-authz finalization rule: an order only becomes
/// `ready` once *every* authorization on it is valid, not just the one whose
/// challenge just completed. This is what makes `submit_on_valid`'s `NOT
/// EXISTS` guard correct instead of a one-authz-is-enough shortcut.
#[tokio::test]
async fn submit_on_valid_marks_order_ready_only_once_all_authzs_are_valid() {
    let dir = TempDir::new().unwrap();
    let (pool, url) = open_file_backed(&dir).await;
    insert_account(&pool, "acct-1").await;
    db::orders::insert(&pool, sample_order("order-1", "acct-1"))
        .await
        .unwrap();
    db::authz::insert(&pool, sample_authz("authz-1", "order-1", "acct-1"))
        .await
        .unwrap();
    db::authz::insert(&pool, sample_authz("authz-2", "order-1", "acct-1"))
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO challenges (id, authz_id, type, status, token, created, updated) \
         VALUES ('chall-1', 'authz-1', 'http-01', 'processing', 'tok1', 1700000000, 1700000000), \
                ('chall-2', 'authz-2', 'http-01', 'processing', 'tok2', 1700000000, 1700000000)",
    )
    .execute(&pool)
    .await
    .unwrap();
    let coalescer = WriteCoalescer::new(&url).await.unwrap();

    let (transitioned_1, order_ready_1) = coalescer
        .submit_on_valid(
            "chall-1".to_string(),
            "authz-1".to_string(),
            "order-1".to_string(),
            1_700_000_300,
        )
        .await
        .unwrap();
    assert!(transitioned_1);
    assert!(
        !order_ready_1,
        "order must stay pending while authz-2 is still unresolved"
    );

    let (transitioned_2, order_ready_2) = coalescer
        .submit_on_valid(
            "chall-2".to_string(),
            "authz-2".to_string(),
            "order-1".to_string(),
            1_700_000_301,
        )
        .await
        .unwrap();
    assert!(transitioned_2);
    assert!(
        order_ready_2,
        "order must become ready once the last authz turns valid"
    );

    let order = db::orders::get_by_id(&pool, "order-1")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(order.status, "ready");
}

/// `exec_finalize` must translate the underlying `Conflict` (from
/// `set_certificate`'s atomic `WHERE status = 'ready'` guard) into the
/// ACME-meaningful `OrderNotReady`, not leak the raw DB conflict — this is
/// the one place `execute_op`'s per-op error mapping is exercised.
#[tokio::test]
async fn submit_finalize_on_a_non_ready_order_returns_order_not_ready() {
    let dir = TempDir::new().unwrap();
    let (pool, url) = open_file_backed(&dir).await;
    insert_account(&pool, "acct-1").await;
    // Order is left in 'pending' — never transitioned to 'ready'.
    db::orders::insert(&pool, sample_order("order-1", "acct-1"))
        .await
        .unwrap();
    let coalescer = WriteCoalescer::new(&url).await.unwrap();

    let err = coalescer
        .submit_finalize(
            sample_cert("cert-1", "order-1", "acct-1"),
            "order-1".to_string(),
            1_700_000_400,
            None,
            None,
        )
        .await
        .unwrap_err();

    assert!(
        matches!(err, AcmeError::OrderNotReady),
        "expected OrderNotReady, got {err:?}"
    );
    assert!(
        db::certs::get_by_id(&pool, "cert-1")
            .await
            .unwrap()
            .is_none(),
        "the certificate insert must have rolled back via its SAVEPOINT, not been left orphaned"
    );
}

/// The coalescer's whole purpose is batching concurrent submissions into one
/// `BEGIN IMMEDIATE…COMMIT`; this drives enough concurrent callers that the
/// loop's `try_recv` drain observes more than one queued op per batch, and
/// asserts every one of them still lands correctly.
#[tokio::test]
async fn concurrent_submissions_all_persist_correctly() {
    let dir = TempDir::new().unwrap();
    let (pool, url) = open_file_backed(&dir).await;
    let coalescer = std::sync::Arc::new(WriteCoalescer::new(&url).await.unwrap());

    let mut handles = Vec::new();
    for i in 0..20 {
        let coalescer = std::sync::Arc::clone(&coalescer);
        handles.push(tokio::spawn(async move {
            coalescer
                .submit_new_account(
                    AccountRow {
                        id: format!("acct-{i}"),
                        status: "valid".into(),
                        contact: None,
                        public_key: vec![i as u8],
                        jwk_thumbprint: format!("thumb-{i}"),
                        created: 1_700_000_000,
                        updated: 1_700_000_000,
                        profile_grants: None,
                        ca_id: String::new(),
                        kerberos_principal: None,
                    },
                    None,
                    1_700_000_000,
                )
                .await
        }));
    }

    for h in handles {
        h.await.unwrap().unwrap();
    }

    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM accounts")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(
        count, 20,
        "every concurrently-submitted account must persist"
    );
}
