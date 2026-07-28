use crate::{dimension, PolicyError};
use abac_rs::{AbacRule, AttributeType};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum PolicyMode {
    #[default]
    Shadow,
    Enforce,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum RuleTypeConfig {
    #[default]
    Allow,
    Deny,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct PolicyRuleConfig {
    pub name: String,
    #[serde(rename = "type")]
    pub rule_type: RuleTypeConfig,
    pub profile: Option<Vec<String>>,
    pub ca: Option<Vec<String>>,
    pub account: Option<Vec<String>>,
    pub account_group: Option<Vec<String>>,
    pub identifier: Option<Vec<String>>,
    pub key_type: Option<Vec<String>>,
    pub valid_from: Option<String>,
    pub valid_until: Option<String>,
    pub enabled: Option<bool>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PolicyConfig {
    #[serde(default)]
    pub mode: PolicyMode,
    pub rules_file: Option<String>,
    #[serde(default)]
    pub rules: Vec<PolicyRuleConfig>,
}

impl PolicyRuleConfig {
    pub fn uuid_v5(&self, scope: &str) -> String {
        let namespace = uuid::Uuid::new_v5(&uuid::Uuid::NAMESPACE_DNS, b"akamu.policy");
        let key = format!("{scope}/{}", self.name);
        uuid::Uuid::new_v5(&namespace, key.as_bytes()).to_string()
    }

    pub fn to_abac_rule(&self) -> Result<AbacRule, PolicyError> {
        self.to_abac_rule_scoped("issuance")
    }

    pub fn to_abac_rule_scoped(&self, scope: &str) -> Result<AbacRule, PolicyError> {
        if self.valid_from.is_some() || self.valid_until.is_some() {
            tracing::warn!(
                rule = %self.name,
                "valid_from/valid_until are not yet enforced — rule will be active regardless of time bounds"
            );
        }

        if let Some(ref patterns) = self.identifier {
            crate::matcher::validate_regex_patterns(patterns)?;
        }

        let mut builder = AbacRule::builder(&self.name);

        builder = match self.rule_type {
            RuleTypeConfig::Deny => builder.deny(),
            RuleTypeConfig::Allow => builder,
        };

        builder = builder.enabled(self.enabled.unwrap_or(true));
        builder = builder.id(self.uuid_v5(scope));

        builder = set_dimension(builder, dimension::PROFILE, self.profile.as_deref());
        builder = set_dimension(builder, dimension::CA, self.ca.as_deref());
        builder = set_dimension(builder, dimension::ACCOUNT, self.account.as_deref());
        builder = set_dimension(builder, dimension::ACCOUNT_GROUP, self.account_group.as_deref());
        builder = set_dimension(builder, dimension::IDENTIFIER, self.identifier.as_deref());
        builder = set_dimension(builder, dimension::KEY_TYPE, self.key_type.as_deref());

        Ok(builder.build())
    }
}

fn set_dimension(
    builder: abac_rs::AbacRuleBuilder,
    dim: &str,
    values: Option<&[String]>,
) -> abac_rs::AbacRuleBuilder {
    match values {
        Some(vals) => {
            let attrs = vals.iter().map(|v| AttributeType::String(v.clone()));
            builder.dimension_values(dim, attrs)
        }
        None => builder,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deserialize_minimal_rule() {
        let toml_str = r#"
            name = "deny-all"
            type = "deny"
        "#;
        let rule: PolicyRuleConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(rule.name, "deny-all");
        assert!(matches!(rule.rule_type, RuleTypeConfig::Deny));
    }

    #[test]
    fn deserialize_full_rule() {
        let toml_str = r#"
            name = "prod-web"
            type = "allow"
            profile = ["tls-server"]
            ca = ["prod"]
            account_group = ["prod-infra"]
            identifier = ["dns:.*\\.prod\\.example\\.com$"]
            key_type = ["ec:P-256"]
            valid_until = "2026-12-31T23:59:59Z"
            enabled = true
        "#;
        let rule: PolicyRuleConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(rule.profile.as_ref().unwrap(), &["tls-server"]);
    }

    #[test]
    fn to_abac_rule_sets_dimensions() {
        let cfg = PolicyRuleConfig {
            name: "test".into(),
            rule_type: RuleTypeConfig::Allow,
            profile: Some(vec!["tls".into()]),
            ..Default::default()
        };
        let rule = cfg.to_abac_rule().unwrap();
        assert_eq!(rule.name, "test");
        assert!(rule.is_enabled());
    }

    #[test]
    fn uuid_v5_deterministic() {
        let cfg = PolicyRuleConfig {
            name: "test-rule".into(),
            rule_type: RuleTypeConfig::Allow,
            ..Default::default()
        };
        let u1 = cfg.uuid_v5("issuance");
        let u2 = cfg.uuid_v5("issuance");
        assert_eq!(u1, u2);
    }

    #[test]
    fn uuid_v5_differs_across_scopes() {
        let cfg = PolicyRuleConfig {
            name: "test-rule".into(),
            rule_type: RuleTypeConfig::Allow,
            ..Default::default()
        };
        assert_ne!(cfg.uuid_v5("issuance"), cfg.uuid_v5("revocation"));
    }

    #[test]
    fn policy_config_defaults_to_shadow() {
        let toml_str = r#"
            rules = []
        "#;
        let cfg: PolicyConfig = toml::from_str(toml_str).unwrap();
        assert!(matches!(cfg.mode, PolicyMode::Shadow));
    }
}
