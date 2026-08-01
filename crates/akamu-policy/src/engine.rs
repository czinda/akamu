use crate::config::{AbacRuleKind, PolicyMode, PolicyRuleConfig};
use crate::matcher::{GlobMatcher, RegexMatcher};
use crate::request::IssuanceRequest;
use crate::{dimension, PolicyError};
use abac_rs::{AbacPolicy, AbacRule, Decision, ExplainedDecision, TemporalAbacRule};
use std::sync::Mutex;

/// Thread-safe issuance policy engine.
///
/// Uses `std::sync::Mutex` because `AbacPolicy::evaluate` requires `&mut self`
/// — not for the LRU cache (which abac-rs updates through its own interior
/// lock, so it doesn't need `&mut self`), but for the lazy index rebuild
/// (`build_indexes`: composite index, bloom filters, compiled evaluator,
/// deny index) that runs on first evaluation after any rule change. The
/// lock hold-time is microseconds for typical rule counts (expected max
/// ~1000 rules), so contention is minimal in practice.
pub struct IssuancePolicyEngine {
    policy: Mutex<AbacPolicy>,
    mode: PolicyMode,
    toml_rules: Vec<PolicyRuleConfig>,
}

impl std::fmt::Debug for IssuancePolicyEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IssuancePolicyEngine")
            .field("mode", &self.mode)
            .field("toml_rules", &self.toml_rules.len())
            .finish()
    }
}

/// Result of [`IssuancePolicyEngine::build_policy`]: the built policy plus
/// the names of any rules skipped because they failed semantic validation
/// (bad regex, empty name, invalid time window) after already passing
/// `PolicyRuleConfig` deserialization.
struct BuiltPolicy {
    policy: AbacPolicy,
    skipped: Vec<String>,
}

impl IssuancePolicyEngine {
    /// Builds an engine from static TOML rules and dynamic DB rules,
    /// converting both into one compiled [`abac_rs::AbacPolicy`].
    ///
    /// In Enforce mode, fails if any rule failed semantic validation (see
    /// `build_policy`) rather than silently installing an incomplete rule set.
    pub fn new(
        mode: PolicyMode,
        toml_rules: Vec<PolicyRuleConfig>,
        db_rules: Vec<PolicyRuleConfig>,
    ) -> Result<Self, PolicyError> {
        let built = Self::build_policy(&toml_rules, &db_rules)?;
        Self::guard_skipped(mode, "build", &built.skipped)?;
        Ok(Self {
            policy: Mutex::new(built.policy),
            mode,
            toml_rules,
        })
    }

    /// In Enforce mode, refuse to proceed when any rule was skipped for
    /// semantic-validation failure — installing a filtered rule set could
    /// silently permit issuance an operator meant to deny. In Shadow mode,
    /// log and let the caller proceed with the incomplete set, since shadow
    /// mode never blocks issuance on policy completeness.
    fn guard_skipped(
        mode: PolicyMode,
        action: &str,
        skipped: &[String],
    ) -> Result<(), PolicyError> {
        if skipped.is_empty() {
            return Ok(());
        }
        if mode == PolicyMode::Enforce {
            tracing::error!(
                skipped = skipped.len(),
                names = ?skipped,
                "policy {action} REJECTED in enforce mode: rules failed semantic validation"
            );
            return Err(PolicyError::InvalidRule(format!(
                "{} rule(s) failed semantic validation: {skipped:?}",
                skipped.len()
            )));
        }
        tracing::warn!(
            skipped = skipped.len(),
            names = ?skipped,
            "policy {action} proceeding with incomplete rule set (shadow mode)"
        );
        Ok(())
    }

    /// Convert `toml_rules`/`db_rules` into an `AbacPolicy`, skipping (rather
    /// than aborting the whole build on) any individual rule that fails
    /// semantic validation — mirroring `parse_db_rules`'s per-row
    /// skip-and-count behavior for JSON-deserialization failures one layer
    /// up, instead of letting a single bad rule discard every rule already
    /// successfully converted.
    fn build_policy(
        toml_rules: &[PolicyRuleConfig],
        db_rules: &[PolicyRuleConfig],
    ) -> Result<BuiltPolicy, PolicyError> {
        let mut regular_rules: Vec<AbacRule> = Vec::new();
        let mut temporal_rules: Vec<TemporalAbacRule> = Vec::new();
        let mut skipped: Vec<String> = Vec::new();

        for cfg in toml_rules.iter().chain(db_rules.iter()) {
            match cfg.to_abac_rule() {
                Ok(AbacRuleKind::Regular(r)) => regular_rules.push(r),
                Ok(AbacRuleKind::Temporal(t)) => temporal_rules.push(t),
                Err(e) => {
                    tracing::error!(
                        rule_name = %cfg.name,
                        "policy rebuild: rule failed semantic validation, skipping: {e}"
                    );
                    skipped.push(cfg.name.clone());
                }
            }
        }

        let mut builder = AbacPolicy::builder()
            .rules(regular_rules)
            .matcher(dimension::IDENTIFIER, Box::new(RegexMatcher::new()))
            .matcher(dimension::ACCOUNT_GROUP, Box::new(GlobMatcher));

        if !temporal_rules.is_empty() {
            builder = builder.temporal_rules(temporal_rules);
        }

        let policy = builder.build().map_err(PolicyError::Policy)?;

        Ok(BuiltPolicy { policy, skipped })
    }

    /// Locks `self.policy`, recovering from poison rather than propagating
    /// a panic from one caller into every other caller of this engine.
    fn lock_policy(&self) -> std::sync::MutexGuard<'_, AbacPolicy> {
        self.policy.lock().unwrap_or_else(|e| {
            tracing::error!("policy engine mutex was poisoned, recovering");
            e.into_inner()
        })
    }

    /// Single-identifier evaluation. Production issuance code should prefer
    /// [`Self::evaluate_explained_identifiers`], which folds a multi-SAN
    /// order's identifiers into one aggregate decision — calling this
    /// directly against a folded multi-SAN request could reintroduce the
    /// collapse bug that method exists to fix. Kept `pub` (not `pub(crate)`)
    /// because this crate's CI runs `cargo build`/`cargo clippy` without
    /// `--all-targets`, which would flag a `pub(crate)` item used only by
    /// `#[cfg(test)]` code as dead code under `-D warnings`.
    pub fn evaluate(&self, request: &IssuanceRequest) -> Decision {
        self.lock_policy().evaluate(&request.0)
    }

    /// See [`Self::evaluate`] — same caveat and the same reason for staying `pub`.
    pub fn evaluate_explained(&self, request: &IssuanceRequest) -> ExplainedDecision {
        self.lock_policy().evaluate_explained(&request.0)
    }

    /// Evaluate `base` once per identifier (SAN) and return one
    /// [`ExplainedDecision`] per identifier, or a single evaluation of `base`
    /// unchanged when `identifiers` is empty.
    ///
    /// A multi-SAN order cannot be represented as a single [`IssuanceRequest`]
    /// without collapsing to one identifier (see `IssuanceRequest::with_identifier`),
    /// so callers must evaluate every identifier independently and treat the
    /// request as allowed only if every result is `Decision::Allow` — a
    /// single denied identifier must not be maskable by a benign one riding
    /// along in the same order.
    ///
    /// Holds the engine's mutex for the whole multi-identifier evaluation
    /// (rather than once per identifier) so a concurrent `rebuild()` cannot
    /// install a new rule set partway through: without this, a deny rule
    /// added mid-evaluation could apply to some identifiers of the order but
    /// not others, letting the overall request through even though the
    /// just-installed policy would have denied it if applied consistently.
    /// Reuses one cloned working copy of `base` across identifiers (mutating
    /// its identifier dimension per iteration) instead of cloning the whole
    /// request once per identifier.
    ///
    /// This still calls the uncached `evaluate_explained` per identifier —
    /// abac-rs's cheaper `evaluate()` bypasses the LRU cache/deny-index/
    /// compiled-evaluator fast paths' opposite (`evaluate_explained` is the
    /// one that bypasses them), and there is currently no way to construct
    /// an `ExplainedDecision` from a plain `Decision` to use `evaluate()` as
    /// a fast path and only fall back to `evaluate_explained` when the
    /// aggregate result is `Deny`. `abac_rs::ExplainedDecision::new` closes
    /// this gap upstream; switch to the two-pass (cheap-then-explained)
    /// strategy once this crate's `abac-rs` dependency is bumped to a
    /// version that includes it.
    pub fn evaluate_explained_identifiers(
        &self,
        base: &IssuanceRequest,
        identifiers: &[(&str, &str)],
    ) -> Result<Vec<ExplainedDecision>, PolicyError> {
        let mut policy = self.lock_policy();

        if identifiers.is_empty() {
            // `base` carries no identifier attribute in this branch, so any
            // identifier-scoped rule (e.g. a deny rule matching a specific
            // SAN) cannot match and is silently skipped for this evaluation.
            // A well-formed multi-SAN order always has at least one
            // identifier, so reaching this with an empty slice means an
            // upstream caller lost data — log loudly so it isn't invisible.
            tracing::warn!(
                "evaluate_explained_identifiers called with zero identifiers; \
                 identifier-scoped policy rules will not be evaluated for this request"
            );
            return Ok(vec![policy.evaluate_explained(&base.0)]);
        }

        let mut working = IssuanceRequest(base.0.clone());
        identifiers
            .iter()
            .map(|(id_type, id_value)| {
                working.set_identifier(id_type, id_value)?;
                Ok(policy.evaluate_explained(&working.0))
            })
            .collect()
    }

    /// Whether this engine is enforcing decisions (`Enforce`) or only
    /// logging them for comparison against legacy behavior (`Shadow`).
    pub fn mode(&self) -> PolicyMode {
        self.mode
    }

    /// Rebuilds the compiled policy from the engine's original TOML rules
    /// plus a fresh set of DB rules (e.g. after an admin CRUD change or a
    /// gossip merge), atomically swapping it in on success.
    ///
    /// In Enforce mode, refuses to install an incomplete rule set (see
    /// `build_policy`) and leaves the previously-installed policy in
    /// effect, rather than silently weakening it.
    pub fn rebuild(&self, db_rules: Vec<PolicyRuleConfig>) -> Result<(), PolicyError> {
        let built = Self::build_policy(&self.toml_rules, &db_rules)?;
        Self::guard_skipped(self.mode, "rebuild", &built.skipped)?;
        *self.lock_policy() = built.policy;
        Ok(())
    }

    /// Number of rules currently compiled into the engine (for observability
    /// — e.g. the admin API and shadow-mode logging use this to distinguish
    /// "no rules configured" from an actual policy deny).
    pub fn rule_count(&self) -> usize {
        self.lock_policy().rule_count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::*;
    use crate::request::IssuanceRequest;

    fn allow_rule(name: &str, profile: &str) -> PolicyRuleConfig {
        PolicyRuleConfig {
            name: name.into(),
            rule_type: RuleTypeConfig::Allow,
            profile: Some(vec![profile.into()]),
            ..Default::default()
        }
    }

    fn deny_rule(name: &str, profile: &str) -> PolicyRuleConfig {
        PolicyRuleConfig {
            name: name.into(),
            rule_type: RuleTypeConfig::Deny,
            profile: Some(vec![profile.into()]),
            ..Default::default()
        }
    }

    /// A rule that parses fine as `PolicyRuleConfig` (valid JSON/TOML shape)
    /// but fails `to_abac_rule`'s semantic validation — an unterminated
    /// regex group in its identifier pattern.
    fn semantically_invalid_rule(name: &str) -> PolicyRuleConfig {
        PolicyRuleConfig {
            name: name.into(),
            rule_type: RuleTypeConfig::Deny,
            identifier: Some(vec!["(unterminated".into()]),
            ..Default::default()
        }
    }

    fn deny_rule_identifier(name: &str, pattern: &str) -> PolicyRuleConfig {
        PolicyRuleConfig {
            name: name.into(),
            rule_type: RuleTypeConfig::Deny,
            identifier: Some(vec![pattern.into()]),
            ..Default::default()
        }
    }

    fn allow_rule_identifier(name: &str, pattern: &str) -> PolicyRuleConfig {
        PolicyRuleConfig {
            name: name.into(),
            rule_type: RuleTypeConfig::Allow,
            identifier: Some(vec![pattern.into()]),
            ..Default::default()
        }
    }

    fn allow_rule_account_group(name: &str, pattern: &str) -> PolicyRuleConfig {
        PolicyRuleConfig {
            name: name.into(),
            rule_type: RuleTypeConfig::Allow,
            account_group: Some(vec![pattern.into()]),
            ..Default::default()
        }
    }

    #[test]
    fn engine_allows_matching_rule() {
        let engine = IssuancePolicyEngine::new(
            PolicyMode::Enforce,
            vec![allow_rule("allow-tls", "tls-server")],
            vec![],
        )
        .unwrap();

        let req = IssuanceRequest::builder()
            .account("acct-1")
            .profile("tls-server")
            .ca("prod")
            .build()
            .unwrap();

        assert_eq!(engine.evaluate(&req), Decision::Allow);
    }

    #[test]
    fn engine_denies_when_no_matching_rule() {
        let engine = IssuancePolicyEngine::new(
            PolicyMode::Enforce,
            vec![allow_rule("allow-tls", "tls-server")],
            vec![],
        )
        .unwrap();

        let req = IssuanceRequest::builder()
            .account("acct-1")
            .profile("code-signing")
            .ca("prod")
            .build()
            .unwrap();

        assert_eq!(engine.evaluate(&req), Decision::Deny);
    }

    #[test]
    fn deny_overrides_allow() {
        let engine = IssuancePolicyEngine::new(
            PolicyMode::Enforce,
            vec![
                allow_rule("allow-tls", "tls-server"),
                deny_rule("deny-tls", "tls-server"),
            ],
            vec![],
        )
        .unwrap();

        let req = IssuanceRequest::builder()
            .account("acct-1")
            .profile("tls-server")
            .ca("prod")
            .build()
            .unwrap();

        assert_eq!(engine.evaluate(&req), Decision::Deny);
    }

    #[test]
    fn rebuild_adds_new_rules() {
        let engine = IssuancePolicyEngine::new(PolicyMode::Enforce, vec![], vec![]).unwrap();

        let req = IssuanceRequest::builder()
            .profile("tls-server")
            .ca("prod")
            .build()
            .unwrap();
        assert_eq!(engine.evaluate(&req), Decision::Deny);

        engine
            .rebuild(vec![allow_rule("db-allow-tls", "tls-server")])
            .unwrap();
        assert_eq!(engine.evaluate(&req), Decision::Allow);
    }

    /// A single semantically-invalid rule must not discard every other rule
    /// that did convert successfully — Enforce mode still refuses to
    /// install an incomplete set (below), but the failure must not look
    /// like "the whole rule set was corrupt" when only one entry was.
    #[test]
    fn new_enforce_mode_rejects_when_any_rule_fails_semantic_validation() {
        let err = IssuancePolicyEngine::new(
            PolicyMode::Enforce,
            vec![
                deny_rule("good-deny", "tls-server"),
                semantically_invalid_rule("bad-rule"),
            ],
            vec![],
        )
        .unwrap_err();
        assert!(
            matches!(err, PolicyError::InvalidRule(_)),
            "expected InvalidRule, got {err:?}"
        );
    }

    /// Shadow mode's fail-open counterpart: a semantically-invalid rule is
    /// logged and skipped, and construction proceeds with the rules that did
    /// convert — mirroring `rebuild_shadow_mode_proceeds_with_incomplete_rule_set`
    /// in tests/policy_engine.rs, which covers the JSON-parse-level version
    /// of this same contract.
    #[test]
    fn new_shadow_mode_proceeds_with_incomplete_rule_set() {
        let engine = IssuancePolicyEngine::new(
            PolicyMode::Shadow,
            vec![
                deny_rule("good-deny", "tls-server"),
                semantically_invalid_rule("bad-rule"),
            ],
            vec![],
        )
        .unwrap();
        assert_eq!(engine.rule_count(), 1);

        let req = IssuanceRequest::builder()
            .profile("tls-server")
            .ca("prod")
            .build()
            .unwrap();
        assert_eq!(engine.evaluate(&req), Decision::Deny);
    }

    /// `rebuild`'s Enforce-mode counterpart to the `new` test above: a
    /// rebuild that would install an incomplete rule set must fail and
    /// leave the previously-installed policy in effect, matching
    /// `rebuild_enforce_mode_rejects_corrupt_rule_and_preserves_old_engine`'s
    /// guarantee for the JSON-parse-level failure class.
    #[test]
    fn rebuild_enforce_mode_rejects_semantically_invalid_rule_and_preserves_old_policy() {
        let engine = IssuancePolicyEngine::new(
            PolicyMode::Enforce,
            vec![allow_rule("allow-tls", "tls-server")],
            vec![],
        )
        .unwrap();
        assert_eq!(engine.rule_count(), 1);

        let err = engine
            .rebuild(vec![semantically_invalid_rule("bad-rule")])
            .unwrap_err();
        assert!(
            matches!(err, PolicyError::InvalidRule(_)),
            "expected InvalidRule, got {err:?}"
        );
        assert_eq!(
            engine.rule_count(),
            1,
            "a rejected rebuild must not clear or partially apply anything"
        );
    }

    #[test]
    fn explained_returns_matching_rule_name() {
        let engine = IssuancePolicyEngine::new(
            PolicyMode::Enforce,
            vec![allow_rule("my-allow-rule", "tls-server")],
            vec![],
        )
        .unwrap();

        let req = IssuanceRequest::builder()
            .profile("tls-server")
            .ca("prod")
            .build()
            .unwrap();

        let explained = engine.evaluate_explained(&req);
        assert_eq!(explained.decision, Decision::Allow);
        assert_eq!(explained.matched_rules[0].name, "my-allow-rule");
    }

    #[test]
    fn temporal_rule_expired_does_not_match() {
        let rule = PolicyRuleConfig {
            name: "expired-allow".into(),
            rule_type: RuleTypeConfig::Allow,
            profile: Some(vec!["tls-server".into()]),
            valid_until: Some("2020-01-01T00:00:00Z".into()),
            ..Default::default()
        };
        let engine = IssuancePolicyEngine::new(PolicyMode::Enforce, vec![rule], vec![]).unwrap();

        let req = IssuanceRequest::builder()
            .profile("tls-server")
            .ca("prod")
            .build()
            .unwrap();

        assert_eq!(engine.evaluate(&req), Decision::Deny);
    }

    #[test]
    fn temporal_rule_future_does_not_match() {
        let rule = PolicyRuleConfig {
            name: "future-allow".into(),
            rule_type: RuleTypeConfig::Allow,
            profile: Some(vec!["tls-server".into()]),
            valid_from: Some("2099-01-01T00:00:00Z".into()),
            ..Default::default()
        };
        let engine = IssuancePolicyEngine::new(PolicyMode::Enforce, vec![rule], vec![]).unwrap();

        let req = IssuanceRequest::builder()
            .profile("tls-server")
            .ca("prod")
            .build()
            .unwrap();

        assert_eq!(engine.evaluate(&req), Decision::Deny);
    }

    #[test]
    fn temporal_rule_within_window_matches() {
        let rule = PolicyRuleConfig {
            name: "active-allow".into(),
            rule_type: RuleTypeConfig::Allow,
            profile: Some(vec!["tls-server".into()]),
            valid_from: Some("2020-01-01T00:00:00Z".into()),
            valid_until: Some("2099-12-31T23:59:59Z".into()),
            ..Default::default()
        };
        let engine = IssuancePolicyEngine::new(PolicyMode::Enforce, vec![rule], vec![]).unwrap();

        let req = IssuanceRequest::builder()
            .profile("tls-server")
            .ca("prod")
            .build()
            .unwrap();

        assert_eq!(engine.evaluate(&req), Decision::Allow);
    }

    /// Regression test for a bypass where only the last identifier of a
    /// multi-SAN order was ever evaluated: a deny rule targeting an earlier
    /// identifier must still block the whole request.
    #[test]
    fn multi_identifier_deny_on_any_identifier_blocks_request() {
        let engine = IssuancePolicyEngine::new(
            PolicyMode::Enforce,
            vec![
                allow_rule_identifier("allow-corp", r"dns:.*\.corp\.example\.com$"),
                deny_rule_identifier("deny-internal", r"dns:.*\.internal\.example\.com$"),
            ],
            vec![],
        )
        .unwrap();

        let base = IssuanceRequest::builder()
            .account("acct-1")
            .ca("prod")
            .build()
            .unwrap();

        // The disallowed identifier is listed first, followed by a benign one
        // that an allow rule would otherwise cover.
        let results = engine
            .evaluate_explained_identifiers(
                &base,
                &[
                    ("dns", "host.internal.example.com"),
                    ("dns", "app.corp.example.com"),
                ],
            )
            .unwrap();

        assert_eq!(results.len(), 2);
        assert!(
            results.iter().any(|r| r.decision == Decision::Deny),
            "a deny rule matching any single SAN must produce at least one Deny result, \
             even when another SAN in the same order would be allowed"
        );
    }

    #[test]
    fn multi_identifier_all_allowed_when_every_identifier_matches() {
        let engine = IssuancePolicyEngine::new(
            PolicyMode::Enforce,
            vec![allow_rule_identifier(
                "allow-corp",
                r"dns:.*\.corp\.example\.com$",
            )],
            vec![],
        )
        .unwrap();

        let base = IssuanceRequest::builder()
            .account("acct-1")
            .ca("prod")
            .build()
            .unwrap();

        let results = engine
            .evaluate_explained_identifiers(
                &base,
                &[("dns", "a.corp.example.com"), ("dns", "b.corp.example.com")],
            )
            .unwrap();

        assert!(results.iter().all(|r| r.decision == Decision::Allow));
    }

    #[test]
    fn evaluate_explained_identifiers_empty_falls_back_to_base_request() {
        let engine = IssuancePolicyEngine::new(
            PolicyMode::Enforce,
            vec![allow_rule("allow-tls", "tls-server")],
            vec![],
        )
        .unwrap();

        let base = IssuanceRequest::builder()
            .profile("tls-server")
            .ca("prod")
            .build()
            .unwrap();

        let results = engine.evaluate_explained_identifiers(&base, &[]).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].decision, Decision::Allow);
    }

    /// Regression test for a real, reproduced bypass in `abac-rs`'s composite
    /// index (fixed upstream in bac-rules commit "fix(abac-rs): index rules
    /// with an undeclared dimension as All", not yet in a released
    /// `abac-rs` version this workspace depends on): a rule declaring zero
    /// dimensions (e.g. a global deny-all) was silently pruned from
    /// `find_candidates`'s results the moment any other rule in the same
    /// policy caused a dimension to be indexed, even though
    /// `AbacPolicyCore::rule_matches` would have matched it. `#[ignore]`d
    /// until `akamu-policy`'s `abac-rs` dependency is bumped past the
    /// version carrying this bug — un-ignore it as part of that upgrade.
    #[test]
    #[ignore = "requires an abac-rs release with the composite-index dimension_all fix"]
    fn zero_dimension_deny_all_rule_survives_unrelated_rule_indexing() {
        let engine = IssuancePolicyEngine::new(
            PolicyMode::Enforce,
            vec![
                PolicyRuleConfig {
                    name: "deny-all".into(),
                    rule_type: RuleTypeConfig::Deny,
                    ..Default::default()
                },
                allow_rule_identifier("allow-corp", r"dns:.*\.corp\.example\.com$"),
            ],
            vec![],
        )
        .unwrap();

        let req = IssuanceRequest::builder()
            .account("acct-1")
            .ca("prod")
            .build()
            .unwrap()
            .with_identifier("dns", "app.corp.example.com")
            .unwrap();

        assert_eq!(
            engine.evaluate(&req),
            Decision::Deny,
            "a zero-dimension deny-all rule must still apply even after another \
             rule in the same policy causes the 'identifier' dimension to be \
             indexed by abac-rs's composite index"
        );
    }

    /// End-to-end proof that `account_group` grants (backed by `GlobMatcher`)
    /// actually work through a real engine. `GlobMatcher`'s glob-matching and
    /// `IssuanceRequestBuilder::account_groups`'s sentinel-plus-groups
    /// plumbing are each unit-tested in isolation elsewhere, but nothing
    /// previously proved the wiring between them — a regression breaking
    /// either side would not have failed any existing test.
    #[test]
    fn account_group_allow_rule_grants_matching_group_and_denies_others() {
        let engine = IssuancePolicyEngine::new(
            PolicyMode::Enforce,
            vec![allow_rule_account_group("allow-prod-infra", "prod-*")],
            vec![],
        )
        .unwrap();

        let granted = IssuanceRequest::builder()
            .account("acct-1")
            .account_groups(vec!["prod-infra".into()])
            .ca("prod")
            .build()
            .unwrap();
        assert_eq!(
            engine.evaluate(&granted),
            Decision::Allow,
            "a request whose account_groups includes a group matching the \
             rule's glob pattern must be allowed"
        );

        let ungranted = IssuanceRequest::builder()
            .account("acct-2")
            .account_groups(vec!["dev-infra".into()])
            .ca("prod")
            .build()
            .unwrap();
        assert_eq!(
            engine.evaluate(&ungranted),
            Decision::Deny,
            "a request whose account_groups does not match the rule's glob \
             pattern must fall through to default-deny"
        );
    }
}
