use crate::config::{AbacRuleKind, PolicyMode, PolicyRuleConfig};
use crate::matcher::{GlobMatcher, RegexMatcher};
use crate::request::IssuanceRequest;
use crate::{dimension, PolicyError};
use abac_rs::{AbacPolicy, AbacRule, Decision, ExplainedDecision, TemporalAbacRule};
use std::sync::Mutex;

/// Thread-safe issuance policy engine.
///
/// Uses `std::sync::Mutex` because `AbacPolicy::evaluate` requires `&mut self`
/// (for internal bloom-filter and LRU cache updates). The lock hold-time is
/// microseconds for typical rule counts (expected max ~1000 rules), so
/// contention is minimal in practice.
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

impl IssuancePolicyEngine {
    pub fn new(
        mode: PolicyMode,
        toml_rules: Vec<PolicyRuleConfig>,
        db_rules: Vec<PolicyRuleConfig>,
    ) -> Result<Self, PolicyError> {
        let policy = Self::build_policy(&toml_rules, &db_rules)?;
        Ok(Self {
            policy: Mutex::new(policy),
            mode,
            toml_rules,
        })
    }

    fn build_policy(
        toml_rules: &[PolicyRuleConfig],
        db_rules: &[PolicyRuleConfig],
    ) -> Result<AbacPolicy, PolicyError> {
        let mut regular_rules: Vec<AbacRule> = Vec::new();
        let mut temporal_rules: Vec<TemporalAbacRule> = Vec::new();

        for cfg in toml_rules.iter().chain(db_rules.iter()) {
            match cfg.to_abac_rule()? {
                AbacRuleKind::Regular(r) => regular_rules.push(r),
                AbacRuleKind::Temporal(t) => temporal_rules.push(t),
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

        Ok(policy)
    }

    pub fn evaluate(&self, request: &IssuanceRequest) -> Decision {
        let mut policy = self.policy.lock().unwrap_or_else(|e| {
            tracing::error!("policy engine mutex was poisoned, recovering");
            e.into_inner()
        });
        policy.evaluate(&request.0)
    }

    pub fn evaluate_explained(&self, request: &IssuanceRequest) -> ExplainedDecision {
        let mut policy = self.policy.lock().unwrap_or_else(|e| {
            tracing::error!("policy engine mutex was poisoned, recovering");
            e.into_inner()
        });
        policy.evaluate_explained(&request.0)
    }

    pub fn mode(&self) -> &PolicyMode {
        &self.mode
    }

    pub fn rebuild(&self, db_rules: Vec<PolicyRuleConfig>) -> Result<(), PolicyError> {
        let new_policy = Self::build_policy(&self.toml_rules, &db_rules)?;
        let mut guard = self.policy.lock().unwrap_or_else(|e| {
            tracing::error!("policy engine mutex was poisoned, recovering");
            e.into_inner()
        });
        *guard = new_policy;
        Ok(())
    }

    pub fn rule_count(&self) -> usize {
        let policy = self.policy.lock().unwrap_or_else(|e| {
            tracing::error!("policy engine mutex was poisoned, recovering");
            e.into_inner()
        });
        policy.rule_count()
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
}
