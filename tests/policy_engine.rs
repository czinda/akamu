//! Fail-closed behavior tests for the issuance ABAC policy engine's rebuild
//! and evaluate paths (`src/policy.rs`).
//!
//! These exercise `rebuild_issuance_policy`/`evaluate_issuance_policy`
//! directly against a real (in-memory SQLite) `AppState`, rather than the
//! engine crate's own unit tests (`crates/akamu-policy/src/engine.rs`), which
//! cover rule matching but never call the root-crate rebuild/evaluate
//! wrappers or exercise `policy_rebuild_lock`.

mod common;

use std::sync::Arc;
use std::time::Duration;

use akamu::db;
use akamu::db::schema::PolicyRuleRow;
use akamu::policy::{evaluate_issuance_policy, rebuild_issuance_policy, PolicyCheckParams};
use akamu::state::AppState;
use akamu_policy::config::PolicyMode;
use akamu_policy::engine::IssuancePolicyEngine;

const DENY_ALL: &str = r#"{"name":"deny-all","type":"deny"}"#;
const CORRUPT_JSON: &str = r#"{"name": not valid json"#;

async fn state_with_mode(dir: &std::path::Path, mode: PolicyMode) -> Arc<AppState> {
    let mut state = common::build_test_state(dir, "https://acme.test").await;
    let engine = Arc::new(IssuancePolicyEngine::new(mode, vec![], vec![]).unwrap());
    Arc::get_mut(&mut state).unwrap().issuance_policy = engine;
    state
}

async fn insert_rule(db: &db::Db, id: &str, rule_json: &str, enabled: bool) {
    let now = "2024-01-01T00:00:00Z".to_string();
    db::policy_rules::insert(
        db,
        &PolicyRuleRow {
            id: id.to_string(),
            scope: "issuance".to_string(),
            name: id.to_string(),
            rule_json: rule_json.to_string(),
            enabled: i64::from(enabled),
            created_at: now.clone(),
            updated_at: now,
            created_by: None,
        },
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn rebuild_with_no_rules_succeeds() {
    let tmp = tempfile::tempdir().unwrap();
    let state = state_with_mode(tmp.path(), PolicyMode::Enforce).await;

    rebuild_issuance_policy(&state).await.unwrap();
    assert_eq!(state.issuance_policy.rule_count(), 0);
}

#[tokio::test]
async fn rebuild_installs_valid_rules() {
    let tmp = tempfile::tempdir().unwrap();
    let state = state_with_mode(tmp.path(), PolicyMode::Enforce).await;
    insert_rule(&state.db, "r1", DENY_ALL, true).await;

    rebuild_issuance_policy(&state).await.unwrap();
    assert_eq!(state.issuance_policy.rule_count(), 1);
}

#[tokio::test]
async fn rebuild_skips_disabled_rules() {
    let tmp = tempfile::tempdir().unwrap();
    let state = state_with_mode(tmp.path(), PolicyMode::Enforce).await;
    insert_rule(&state.db, "r1", DENY_ALL, false).await;

    rebuild_issuance_policy(&state).await.unwrap();
    assert_eq!(state.issuance_policy.rule_count(), 0);
}

/// Core fail-closed guarantee: in enforce mode, a corrupt rule must not be
/// silently dropped from an otherwise-installed policy. The rebuild is
/// rejected outright and the previously-installed engine is left untouched,
/// rather than installing an incomplete rule set that could unintentionally
/// permit issuance the operator meant to deny.
#[tokio::test]
async fn rebuild_enforce_mode_rejects_corrupt_rule_and_preserves_old_engine() {
    let tmp = tempfile::tempdir().unwrap();
    let state = state_with_mode(tmp.path(), PolicyMode::Enforce).await;
    insert_rule(&state.db, "r1", DENY_ALL, true).await;
    rebuild_issuance_policy(&state).await.unwrap();
    assert_eq!(state.issuance_policy.rule_count(), 1);

    insert_rule(&state.db, "r2", CORRUPT_JSON, true).await;
    let err = rebuild_issuance_policy(&state).await.unwrap_err();
    assert!(
        matches!(
            err,
            akamu::policy::PolicyRebuildError::CorruptRules { skipped: 1, .. }
        ),
        "expected CorruptRules{{skipped: 1}}, got {err:?}"
    );
    // The engine installed by the first, successful rebuild must still be in
    // effect — a rejected rebuild must not clear or partially apply anything.
    assert_eq!(state.issuance_policy.rule_count(), 1);
}

/// Shadow mode's fail-open counterpart: a corrupt rule is logged and skipped,
/// but the rebuild still proceeds with whatever rules did parse, since shadow
/// mode never blocks issuance regardless of policy completeness.
#[tokio::test]
async fn rebuild_shadow_mode_proceeds_with_incomplete_rule_set() {
    let tmp = tempfile::tempdir().unwrap();
    let state = state_with_mode(tmp.path(), PolicyMode::Shadow).await;
    insert_rule(&state.db, "r1", DENY_ALL, true).await;
    insert_rule(&state.db, "r2", CORRUPT_JSON, true).await;

    rebuild_issuance_policy(&state).await.unwrap();
    assert_eq!(state.issuance_policy.rule_count(), 1);
}

#[tokio::test]
async fn evaluate_enforce_mode_denies_on_policy_deny() {
    let tmp = tempfile::tempdir().unwrap();
    let state = state_with_mode(tmp.path(), PolicyMode::Enforce).await;
    insert_rule(&state.db, "r1", DENY_ALL, true).await;
    rebuild_issuance_policy(&state).await.unwrap();

    let allowed = [("dns", "example.com")];
    let params = PolicyCheckParams {
        account_id: "acct-1",
        ca_id: "default",
        effective_profile: None,
        allowed: &allowed,
        key_type: None,
    };
    let result = evaluate_issuance_policy(&state, &params).await;
    assert!(
        matches!(result, Err(akamu::error::AcmeError::Unauthorized(_))),
        "expected Unauthorized, got {result:?}"
    );
}

/// Shadow mode must never block issuance: a policy deny is only logged, and
/// the request proceeds as if the policy engine were not consulted.
#[tokio::test]
async fn evaluate_shadow_mode_allows_despite_policy_deny() {
    let tmp = tempfile::tempdir().unwrap();
    let state = state_with_mode(tmp.path(), PolicyMode::Shadow).await;
    insert_rule(&state.db, "r1", DENY_ALL, true).await;
    rebuild_issuance_policy(&state).await.unwrap();

    let allowed = [("dns", "example.com")];
    let params = PolicyCheckParams {
        account_id: "acct-1",
        ca_id: "default",
        effective_profile: None,
        allowed: &allowed,
        key_type: None,
    };
    evaluate_issuance_policy(&state, &params).await.unwrap();
}

/// Regression test for the concurrent-rebuild race fixed by
/// `policy_rebuild_lock` (task #26): `rebuild_issuance_policy` must not
/// proceed while another holder has the lock, and must resume as soon as it
/// is released. Directly exercising the shared lock is more deterministic
/// than trying to race two `rebuild_issuance_policy` calls against each
/// other, since the actual interleaving of the two DB reads/installs would
/// otherwise depend on unpredictable task scheduling.
#[tokio::test]
async fn rebuild_serializes_on_policy_rebuild_lock() {
    let tmp = tempfile::tempdir().unwrap();
    let state = state_with_mode(tmp.path(), PolicyMode::Enforce).await;

    let guard = state.policy_rebuild_lock.lock().await;
    let blocked =
        tokio::time::timeout(Duration::from_millis(100), rebuild_issuance_policy(&state)).await;
    assert!(
        blocked.is_err(),
        "rebuild_issuance_policy must block while policy_rebuild_lock is held elsewhere"
    );

    drop(guard);
    let unblocked =
        tokio::time::timeout(Duration::from_millis(500), rebuild_issuance_policy(&state)).await;
    assert!(
        unblocked.is_ok(),
        "rebuild_issuance_policy must proceed once the lock is released"
    );
}
