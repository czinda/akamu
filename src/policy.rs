//! Shared issuance-policy rebuild logic.
//!
//! Used by startup (`main.rs`), admin CRUD handlers, and gossip merge.

use crate::db;
use crate::state::AppState;

/// Typed error for policy rebuild failures.
#[derive(Debug, thiserror::Error)]
pub enum PolicyRebuildError {
    #[error("DB load failed: {0}")]
    DbLoad(String),
    #[error("{skipped} corrupt rules skipped (ids: {ids:?})")]
    CorruptRules { skipped: usize, ids: Vec<String> },
    #[error("engine rebuild failed: {0}")]
    Engine(String),
}

/// Result of parsing DB policy rules — includes both parsed rules and skip count.
pub struct ParsedDbRules {
    pub rules: Vec<akamu_policy::config::PolicyRuleConfig>,
    pub skipped: usize,
    pub skipped_ids: Vec<String>,
}

/// Parse enabled DB policy rules, logging and skipping corrupt entries.
pub fn parse_db_rules(rows: &[db::policy_rules::PolicyRuleRow]) -> ParsedDbRules {
    let mut rules = Vec::new();
    let mut skipped_ids: Vec<String> = Vec::new();

    for row in rows.iter().filter(|row| row.enabled != 0) {
        match serde_json::from_str::<akamu_policy::config::PolicyRuleConfig>(&row.rule_json) {
            Ok(cfg) => rules.push(cfg),
            Err(e) => {
                tracing::error!(
                    rule_id = %row.id,
                    rule_name = %row.name,
                    "corrupt policy rule skipped: {e}"
                );
                skipped_ids.push(row.id.clone());
            }
        }
    }

    if !skipped_ids.is_empty() {
        tracing::error!(
            count = skipped_ids.len(),
            ids = ?skipped_ids,
            "policy rebuild: corrupt rules omitted — policy may be incomplete"
        );
    }

    ParsedDbRules {
        skipped: skipped_ids.len(),
        skipped_ids,
        rules,
    }
}

/// Reload all enabled issuance-scope policy rules from the database and
/// rebuild the in-memory policy engine.  Uses the read-write pool (`state.db`)
/// to avoid stale reads after admin CRUD or CRDT persistence.
///
/// In enforce mode, refuses to rebuild when any rules are corrupt to prevent
/// silent policy bypass.
///
/// Holds `state.policy_rebuild_lock` for the entire read+build+install
/// sequence so concurrent rebuilds (e.g. an admin CRUD call racing a
/// gossip-triggered rebuild) apply in the order they observed the database,
/// instead of racing to install whichever finishes its build first — which
/// could silently overwrite a newer rule set with a stale one. See the lock's
/// doc comment on `AppState` for the full scenario.
pub async fn rebuild_issuance_policy(state: &AppState) -> Result<(), PolicyRebuildError> {
    let _guard = state.policy_rebuild_lock.lock().await;
    let rows = db::policy_rules::list_by_scope(&state.db, "issuance")
        .await
        .map_err(|e| {
            let msg = format!("{e}");
            tracing::error!("policy rebuild: DB load failed: {e}");
            PolicyRebuildError::DbLoad(msg)
        })?;

    let parsed = parse_db_rules(&rows);

    if parsed.skipped > 0 {
        use akamu_policy::config::PolicyMode;
        if *state.issuance_policy.mode() == PolicyMode::Enforce {
            tracing::error!(
                skipped = parsed.skipped,
                ids = ?parsed.skipped_ids,
                "policy rebuild REJECTED in enforce mode: corrupt rules would be silently dropped"
            );
            return Err(PolicyRebuildError::CorruptRules {
                skipped: parsed.skipped,
                ids: parsed.skipped_ids,
            });
        }
        tracing::warn!(
            skipped = parsed.skipped,
            ids = ?parsed.skipped_ids,
            "policy rebuild proceeding with incomplete rule set (shadow mode)"
        );
    }

    state.issuance_policy.rebuild(parsed.rules).map_err(|e| {
        let msg = format!("{e}");
        tracing::error!("policy rebuild failed: {e}");
        PolicyRebuildError::Engine(msg)
    })
}

/// Attempt a policy rebuild, deferring to next gossip round on failure.
/// Returns `true` if the rebuild succeeded, `false` if it failed and was
/// deferred.
pub async fn rebuild_or_defer(state: &AppState, context: &str) -> bool {
    if let Err(e) = rebuild_issuance_policy(state).await {
        tracing::error!("{context}: {e}");
        state
            .policy_rebuild_needed
            .store(true, std::sync::atomic::Ordering::Release);
        false
    } else {
        true
    }
}

/// Parameters for issuance policy evaluation.
pub struct PolicyCheckParams<'a> {
    pub account_id: &'a str,
    pub ca_id: &'a str,
    pub effective_profile: Option<&'a str>,
    pub allowed: &'a [(&'a str, &'a str)],
    pub key_type: Option<&'a str>,
}

/// Evaluate the issuance policy engine against the current request context.
///
/// Returns `Ok(())` when the policy allows issuance (or when the engine is in
/// shadow mode).  In enforce mode, a deny decision returns `Err(AcmeError)`.
pub async fn evaluate_issuance_policy(
    state: &AppState,
    params: &PolicyCheckParams<'_>,
) -> Result<(), crate::error::AcmeError> {
    use akamu_policy::config::PolicyMode;
    use akamu_policy::Decision;

    let enforce = *state.issuance_policy.mode() == PolicyMode::Enforce;

    // TODO: cache profile_grants and kerberos_principal per account to avoid
    // 2 DB round-trips per finalize.  These change infrequently relative to
    // issuance frequency — follow the spki_cache pattern with TTL-based
    // invalidation.
    let mut account_groups: Vec<String> = Vec::new();
    let mut data_incomplete = false;
    match db::accounts::get_profile_grants(&state.db_ro, params.account_id).await {
        Ok(Some(Some(grants_json))) => match serde_json::from_str::<Vec<String>>(&grants_json) {
            Ok(grants) => account_groups.extend(grants),
            Err(e) => {
                if enforce {
                    tracing::error!(account = %params.account_id, "policy DENY: corrupt profile grants JSON: {e}");
                    return Err(crate::error::AcmeError::Unauthorized(
                        "certificate issuance denied by issuance policy".into(),
                    ));
                }
                tracing::error!(account = %params.account_id, "policy shadow: corrupt profile grants JSON (shadow allows, enforce would deny): {e}");
                data_incomplete = true;
            }
        },
        Ok(Some(None)) => {
            tracing::debug!(account = %params.account_id, "policy: no profile grants stored for account");
        }
        Ok(None) => {
            tracing::debug!(account = %params.account_id, "policy: account not found for profile grants lookup");
        }
        Err(e) => {
            if enforce {
                tracing::error!(account = %params.account_id, "policy DENY: failed to load profile grants: {e}");
                return Err(crate::error::AcmeError::Unauthorized(
                    "certificate issuance denied by issuance policy".into(),
                ));
            }
            tracing::error!(account = %params.account_id, "policy shadow: failed to load profile grants (shadow allows, enforce would deny): {e}");
            data_incomplete = true;
        }
    }
    match db::accounts::get_kerberos_principal(&state.db_ro, params.account_id).await {
        Ok(Some(principal)) => account_groups.push(principal),
        Ok(None) => {
            tracing::debug!(account = %params.account_id, "policy: no kerberos principal for account");
        }
        Err(e) => {
            if enforce {
                tracing::error!(account = %params.account_id, "policy DENY: failed to load kerberos principal: {e}");
                return Err(crate::error::AcmeError::Unauthorized(
                    "certificate issuance denied by issuance policy".into(),
                ));
            }
            tracing::error!(account = %params.account_id, "policy shadow: failed to load kerberos principal (shadow allows, enforce would deny): {e}");
            data_incomplete = true;
        }
    }

    let mut policy_builder = akamu_policy::request::IssuanceRequest::builder()
        .account(params.account_id)
        .account_groups(&account_groups)
        .ca(params.ca_id)
        .identifiers(params.allowed);
    if let Some(profile_name) = params.effective_profile {
        policy_builder = policy_builder.profile(profile_name);
    }
    if let Some(kt) = params.key_type {
        policy_builder = policy_builder.key_type(kt);
    }

    match policy_builder.build() {
        Ok(policy_req) => {
            let explained = state.issuance_policy.evaluate_explained(&policy_req);
            let policy_allowed = explained.decision == Decision::Allow;

            if !policy_allowed {
                let rule_names: Vec<_> = explained.matched_rules.iter().map(|r| &r.name).collect();
                if enforce {
                    tracing::warn!(
                        account = %params.account_id,
                        profile = ?params.effective_profile,
                        ca = %params.ca_id,
                        matched_rules = ?rule_names,
                        "policy DENY: issuance blocked by policy"
                    );
                    return Err(crate::error::AcmeError::Unauthorized(
                        "certificate issuance denied by issuance policy".into(),
                    ));
                }
                if state.issuance_policy.rule_count() == 0 {
                    tracing::debug!(
                        account = %params.account_id,
                        profile = ?params.effective_profile,
                        ca = %params.ca_id,
                        "policy shadow: no rules configured, skipping comparison"
                    );
                } else if data_incomplete {
                    tracing::warn!(
                        account = %params.account_id,
                        profile = ?params.effective_profile,
                        ca = %params.ca_id,
                        legacy = "Allow",
                        policy = "Deny",
                        matched_rules = ?rule_names,
                        "policy shadow: INCOMPLETE DATA — deny may be due to missing context"
                    );
                } else {
                    tracing::warn!(
                        account = %params.account_id,
                        profile = ?params.effective_profile,
                        ca = %params.ca_id,
                        legacy = "Allow",
                        policy = "Deny",
                        matched_rules = ?rule_names,
                        "policy shadow: MISMATCH"
                    );
                }
            } else if data_incomplete {
                tracing::warn!(
                    account = %params.account_id,
                    profile = ?params.effective_profile,
                    policy = "Allow",
                    "policy evaluation: allow with INCOMPLETE DATA — decision may differ under enforce mode"
                );
            } else {
                tracing::debug!(
                    account = %params.account_id,
                    profile = ?params.effective_profile,
                    policy = "Allow",
                    "policy evaluation: allow"
                );
            }
        }
        Err(e) => {
            if enforce {
                tracing::error!(
                    account = %params.account_id,
                    error = %e,
                    "policy DENY: failed to build issuance request in enforce mode"
                );
                return Err(crate::error::AcmeError::Unauthorized(
                    "certificate issuance denied by issuance policy".into(),
                ));
            }
            tracing::error!(
                account = %params.account_id,
                error = %e,
                "policy shadow: failed to build issuance request (shadow allows, enforce would deny)"
            );
        }
    }

    Ok(())
}
