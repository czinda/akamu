//! Translates the older, profile-centric authorization model
//! (`ProfileConfig`'s `ca_ids`/`allowed_identifier_patterns`/
//! `require_account_grant` fields) into an equivalent [`PolicyRuleConfig`]
//! allow rule, so both models can be evaluated through one policy engine
//! instead of maintaining two separate authorization code paths.

use crate::config::{PolicyRuleConfig, RuleTypeConfig};

/// Builds an allow rule equivalent to profile `profile_name`'s legacy
/// authorization settings.
///
/// The rule's name is prefixed `_compat_` to mark it as a generated
/// (not operator-authored) rule and avoid colliding with a real rule of the
/// same name; `require_account_grant` maps to an `account_group` dimension
/// requiring `profile_name` itself as the granted group, matching
/// `ProfileConfig`'s "grant this profile's name via `profile_grants`" contract.
pub fn translate_profile_to_rule(
    profile_name: &str,
    ca_ids: &[String],
    allowed_identifier_patterns: &[String],
    require_account_grant: bool,
) -> PolicyRuleConfig {
    let mut rule = PolicyRuleConfig {
        name: format!("_compat_{profile_name}"),
        rule_type: RuleTypeConfig::Allow,
        profile: Some(vec![profile_name.to_string()]),
        enabled: Some(true),
        ..Default::default()
    };

    if !ca_ids.is_empty() {
        rule.ca = Some(ca_ids.to_vec());
    }

    if !allowed_identifier_patterns.is_empty() {
        rule.identifier = Some(allowed_identifier_patterns.to_vec());
    }

    if require_account_grant {
        rule.account_group = Some(vec![profile_name.to_string()]);
    }

    rule
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn translate_ca_ids_only() {
        let rule = translate_profile_to_rule("ec-tls", &["ec".into()], &[], false);
        assert_eq!(rule.ca.as_ref().unwrap(), &["ec"]);
        assert_eq!(rule.profile.as_ref().unwrap(), &["ec-tls"]);
    }

    #[test]
    fn translate_patterns_only() {
        let rule = translate_profile_to_rule("web", &[], &[r"dns:.*\.example\.com$".into()], false);
        assert_eq!(
            rule.identifier.as_ref().unwrap(),
            &[r"dns:.*\.example\.com$"]
        );
    }

    #[test]
    fn translate_require_grant() {
        let rule = translate_profile_to_rule("clientauth", &[], &[], true);
        assert_eq!(rule.account_group.as_ref().unwrap(), &["clientauth"]);
    }

    #[test]
    fn translate_no_restrictions_produces_open_allow() {
        let rule = translate_profile_to_rule("default", &[], &[], false);
        assert!(rule.ca.is_none());
        assert!(rule.identifier.is_none());
        assert!(rule.account_group.is_none());
    }

    #[test]
    fn translate_combined() {
        let rule = translate_profile_to_rule(
            "prod-web",
            &["prod".into()],
            &[r"dns:.*\.prod\.example\.com$".into()],
            true,
        );
        assert!(rule.ca.is_some());
        assert!(rule.identifier.is_some());
        assert!(rule.account_group.is_some());
    }
}
