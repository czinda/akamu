use crate::config::{PolicyMode, PolicyRuleConfig};
use crate::matcher::{GlobMatcher, RegexMatcher};
use crate::request::IssuanceRequest;
use crate::{dimension, PolicyError};
use abac_rs::{AbacPolicy, Decision, ExplainedDecision};
use std::sync::Mutex;

/// Thread-safe issuance policy engine.
///
/// Uses `std::sync::Mutex` because `AbacPolicy::evaluate` requires `&mut self`
/// (for internal bloom-filter and LRU cache updates). The lock hold-time is
/// microseconds for typical rule counts, so contention is minimal in practice.
pub struct IssuancePolicyEngine {
    policy: Mutex<AbacPolicy>,
    mode: PolicyMode,
    toml_rules: Vec<PolicyRuleConfig>,
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
        let mut abac_rules = Vec::new();
        for cfg in toml_rules.iter().chain(db_rules.iter()) {
            abac_rules.push(cfg.to_abac_rule()?);
        }

        let policy = AbacPolicy::builder()
            .rules(abac_rules)
            .matcher(dimension::IDENTIFIER, Box::new(RegexMatcher::new()))
            .matcher(dimension::ACCOUNT_GROUP, Box::new(GlobMatcher))
            .build()
            .map_err(PolicyError::Policy)?;

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
}
