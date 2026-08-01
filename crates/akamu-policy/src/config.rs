use crate::{dimension, PolicyError};
use abac_rs::{AbacRule, AttributeType, TemporalAbacRule};
use serde::{Deserialize, Serialize};
use time::format_description::well_known::Rfc3339;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum PolicyMode {
    #[default]
    Shadow,
    Enforce,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum RuleTypeConfig {
    #[default]
    Allow,
    Deny,
}

/// The canonical, internal representation of a policy rule.
///
/// This is what [`Self::to_abac_rule_scoped`] compiles, what
/// [`crate::engine::IssuancePolicyEngine`] operates on for both TOML- and
/// DB-sourced rules, what gets serialized into the DB's `rule_json` column,
/// and what `parse_db_rules` deserializes that column back into. It is
/// deliberately a separate type from [`TomlPolicyRuleConfig`] (the TOML
/// config-file schema) and [`PolicyRuleRequest`] (the admin API's request
/// shape) — even though all three currently share the same 11 fields — so
/// each surface's schema can evolve independently (e.g. a future DB-only
/// metadata field, or a future TOML-only shorthand) without forcing a
/// matching change onto the other two.
///
/// `deny_unknown_fields`: a misspelled field name (e.g. `identifer` for
/// `identifier`) would otherwise silently deserialize as if the field were
/// absent — `None` on a dimension field means "no restriction" — turning a
/// typo'd deny rule into a silent no-op or an allow rule into an
/// unintentionally broader grant, with no error at any layer.
///
/// On each `Option<Vec<String>>` dimension field, `None` means "unrestricted"
/// (the dimension is omitted from the built rule). An explicit empty list
/// (`Some(vec![])`, e.g. `identifier = []` in TOML) means the opposite — it
/// constrains the dimension to a set with no members, so it can never match
/// — and is rejected by `to_abac_rule_scoped` rather than silently accepted
/// as a no-op rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
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

/// The TOML config-file schema for a policy rule (embedded in the server's
/// main config under `[policy]` and in an optional external `rules_file`).
///
/// Converted into the canonical [`PolicyRuleConfig`] via [`From`] before
/// being compiled — see [`PolicyRuleConfig`]'s doc comment for why this is a
/// separate type rather than reusing the canonical one directly.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct TomlPolicyRuleConfig {
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

impl From<TomlPolicyRuleConfig> for PolicyRuleConfig {
    fn from(cfg: TomlPolicyRuleConfig) -> Self {
        Self {
            name: cfg.name,
            rule_type: cfg.rule_type,
            profile: cfg.profile,
            ca: cfg.ca,
            account: cfg.account,
            account_group: cfg.account_group,
            identifier: cfg.identifier,
            key_type: cfg.key_type,
            valid_from: cfg.valid_from,
            valid_until: cfg.valid_until,
            enabled: cfg.enabled,
        }
    }
}

/// The admin HTTP API's request-body shape for a policy rule (the `rule`
/// field of `POST`/`PUT /admin/policy/rules`).
///
/// Converted into the canonical [`PolicyRuleConfig`] via [`From`] before
/// validation (`to_abac_rule`) and storage — see [`PolicyRuleConfig`]'s doc
/// comment for why this is a separate type rather than reusing the
/// canonical one directly.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct PolicyRuleRequest {
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

impl From<PolicyRuleRequest> for PolicyRuleConfig {
    fn from(cfg: PolicyRuleRequest) -> Self {
        Self {
            name: cfg.name,
            rule_type: cfg.rule_type,
            profile: cfg.profile,
            ca: cfg.ca,
            account: cfg.account,
            account_group: cfg.account_group,
            identifier: cfg.identifier,
            key_type: cfg.key_type,
            valid_from: cfg.valid_from,
            valid_until: cfg.valid_until,
            enabled: cfg.enabled,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyConfig {
    #[serde(default)]
    pub mode: PolicyMode,
    pub rules_file: Option<String>,
    #[serde(default)]
    pub rules: Vec<TomlPolicyRuleConfig>,
}

#[derive(Debug)]
pub enum AbacRuleKind {
    Regular(AbacRule),
    Temporal(TemporalAbacRule),
}

fn parse_rfc3339_millis(s: &str) -> Result<u64, PolicyError> {
    let dt = time::OffsetDateTime::parse(s, &Rfc3339)
        .map_err(|e| PolicyError::InvalidRule(format!("invalid RFC 3339 timestamp '{s}': {e}")))?;
    let secs = dt.unix_timestamp();
    if secs < 0 {
        return Err(PolicyError::InvalidRule(format!(
            "timestamp '{s}' is before Unix epoch"
        )));
    }
    Ok(secs as u64 * 1000 + dt.millisecond() as u64)
}

impl PolicyRuleConfig {
    pub fn uuid_v5(&self, scope: &str) -> String {
        static NAMESPACE: std::sync::OnceLock<uuid::Uuid> = std::sync::OnceLock::new();
        let namespace = NAMESPACE
            .get_or_init(|| uuid::Uuid::new_v5(&uuid::Uuid::NAMESPACE_DNS, b"akamu.policy"));
        let key = format!("{scope}/{}", self.name);
        uuid::Uuid::new_v5(namespace, key.as_bytes()).to_string()
    }

    pub fn to_abac_rule(&self) -> Result<AbacRuleKind, PolicyError> {
        self.to_abac_rule_scoped("issuance")
    }

    pub fn to_abac_rule_scoped(&self, scope: &str) -> Result<AbacRuleKind, PolicyError> {
        if self.name.is_empty() {
            return Err(PolicyError::InvalidRule(
                "rule name must not be empty".into(),
            ));
        }

        // `None` means "unrestricted" (the dimension is omitted from the
        // built rule entirely — see set_dimension's doc comment). An
        // explicit empty list looks like the same thing to a human editing
        // config but means the opposite: it inserts a dimension constraint
        // that can never be satisfied, making the whole rule permanently
        // inert. Reject it outright rather than silently shipping a
        // no-op — for a deny rule, a no-op is a silent bypass of whatever
        // the rule was meant to restrict.
        for (dim_name, values) in [
            ("profile", &self.profile),
            ("ca", &self.ca),
            ("account", &self.account),
            ("account_group", &self.account_group),
            ("identifier", &self.identifier),
            ("key_type", &self.key_type),
        ] {
            if values.as_ref().is_some_and(|v| v.is_empty()) {
                return Err(PolicyError::InvalidRule(format!(
                    "rule '{}': dimension '{dim_name}' is an explicit empty list, which can \
                     never match — omit the field entirely for \"no restriction\" instead",
                    self.name
                )));
            }
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
        builder = set_dimension(
            builder,
            dimension::ACCOUNT_GROUP,
            self.account_group.as_deref(),
        );
        builder = set_dimension(builder, dimension::IDENTIFIER, self.identifier.as_deref());
        builder = set_dimension(builder, dimension::KEY_TYPE, self.key_type.as_deref());

        let rule = builder.build();

        let from = self
            .valid_from
            .as_deref()
            .map(parse_rfc3339_millis)
            .transpose()?;
        let until = self
            .valid_until
            .as_deref()
            .map(parse_rfc3339_millis)
            .transpose()?;

        if from.is_some() || until.is_some() {
            let temporal = TemporalAbacRule::new(rule, from, until)?;
            Ok(AbacRuleKind::Temporal(temporal))
        } else {
            Ok(AbacRuleKind::Regular(rule))
        }
    }
}

/// Sets `dim` to the given values, or leaves it unset ("unrestricted") when
/// `values` is `None`.
///
/// Deliberately does *not* call `dimension_all(dim)` for the `None` case:
/// `AbacPolicyCore::rule_matches` requires the *request* to carry a value for
/// any dimension the rule explicitly declares — including one declared as
/// `AttributeValue::All` — so a rule using `dimension_all` still fails to
/// match a request that never set that attribute at all. Requests built by
/// `IssuanceRequestBuilder` set `profile`/`key_type` conditionally, so an
/// omitted dimension must remain truly absent from the rule to stay
/// unconstrained regardless of what the request does or doesn't set. The
/// upstream fix for the composite index silently pruning a rule that omits a
/// dimension another rule declares belongs in `abac-rs` itself (which can fix
/// index construction without touching rule-matching semantics), not here.
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
        let rule: TomlPolicyRuleConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(rule.name, "deny-all");
        assert!(matches!(rule.rule_type, RuleTypeConfig::Deny));
    }

    /// A misspelled dimension field must be a hard error, not a silent
    /// no-op — see the `deny_unknown_fields` doc comment on
    /// `PolicyRuleConfig` for the failure mode this prevents.
    #[test]
    fn deserialize_rejects_unknown_field() {
        let toml_str = r#"
            name = "deny-internal"
            type = "deny"
            identifer = ["dns:.*\\.internal\\.example\\.com$"]
        "#;
        let err = toml::from_str::<TomlPolicyRuleConfig>(toml_str).unwrap_err();
        assert!(
            err.to_string().contains("identifer") || err.to_string().contains("unknown field"),
            "expected an unknown-field error, got: {err}"
        );
    }

    #[test]
    fn policy_config_rejects_unknown_field() {
        let toml_str = r#"
            mode = "enforce"
            rulez = []
        "#;
        assert!(toml::from_str::<PolicyConfig>(toml_str).is_err());
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
        let rule: TomlPolicyRuleConfig = toml::from_str(toml_str).unwrap();
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
        let kind = cfg.to_abac_rule().unwrap();
        match kind {
            AbacRuleKind::Regular(rule) => {
                assert_eq!(rule.name, "test");
                assert!(rule.is_enabled());
            }
            AbacRuleKind::Temporal(_) => panic!("expected Regular, got Temporal"),
        }
    }

    /// See the `None`-vs-`Some(vec![])` doc comment on `PolicyRuleConfig`:
    /// an explicit empty list must be rejected, not silently accepted as an
    /// unmatchable (and therefore inert) rule.
    #[test]
    fn to_abac_rule_rejects_explicit_empty_identifier_list() {
        let cfg = PolicyRuleConfig {
            name: "deny-nothing".into(),
            rule_type: RuleTypeConfig::Deny,
            identifier: Some(vec![]),
            ..Default::default()
        };
        let err = cfg.to_abac_rule().unwrap_err();
        assert!(
            matches!(err, PolicyError::InvalidRule(ref msg) if msg.contains("identifier")),
            "expected InvalidRule mentioning 'identifier', got {err:?}"
        );
    }

    #[test]
    fn to_abac_rule_rejects_explicit_empty_account_group_list() {
        let cfg = PolicyRuleConfig {
            name: "allow-nobody".into(),
            rule_type: RuleTypeConfig::Allow,
            account_group: Some(vec![]),
            ..Default::default()
        };
        let err = cfg.to_abac_rule().unwrap_err();
        assert!(
            matches!(err, PolicyError::InvalidRule(ref msg) if msg.contains("account_group")),
            "expected InvalidRule mentioning 'account_group', got {err:?}"
        );
    }

    #[test]
    fn parse_rfc3339_millis_valid() {
        let ms = parse_rfc3339_millis("2026-01-15T12:30:00Z").unwrap();
        assert_eq!(ms, 1768480200000);
    }

    #[test]
    fn parse_rfc3339_millis_with_subseconds() {
        let ms = parse_rfc3339_millis("2026-01-15T12:30:00.500Z").unwrap();
        assert_eq!(ms, 1768480200500);
    }

    #[test]
    fn parse_rfc3339_millis_rejects_invalid() {
        assert!(parse_rfc3339_millis("not-a-timestamp").is_err());
    }

    #[test]
    fn to_abac_rule_returns_temporal_with_valid_from() {
        let cfg = PolicyRuleConfig {
            name: "timed".into(),
            rule_type: RuleTypeConfig::Allow,
            valid_from: Some("2026-01-01T00:00:00Z".into()),
            ..Default::default()
        };
        assert!(matches!(
            cfg.to_abac_rule().unwrap(),
            AbacRuleKind::Temporal(_)
        ));
    }

    #[test]
    fn to_abac_rule_returns_temporal_with_valid_until() {
        let cfg = PolicyRuleConfig {
            name: "expiring".into(),
            rule_type: RuleTypeConfig::Allow,
            valid_until: Some("2026-12-31T23:59:59Z".into()),
            ..Default::default()
        };
        assert!(matches!(
            cfg.to_abac_rule().unwrap(),
            AbacRuleKind::Temporal(_)
        ));
    }

    #[test]
    fn to_abac_rule_returns_regular_without_temporal() {
        let cfg = PolicyRuleConfig {
            name: "always".into(),
            rule_type: RuleTypeConfig::Deny,
            ..Default::default()
        };
        assert!(matches!(
            cfg.to_abac_rule().unwrap(),
            AbacRuleKind::Regular(_)
        ));
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

    #[test]
    fn all_dimensions_have_config_fields() {
        let dims = [
            dimension::ACCOUNT,
            dimension::ACCOUNT_GROUP,
            dimension::PROFILE,
            dimension::CA,
            dimension::IDENTIFIER,
            dimension::KEY_TYPE,
        ];
        let cfg = PolicyRuleConfig {
            name: "dim-check".into(),
            rule_type: RuleTypeConfig::Allow,
            account: Some(vec!["a".into()]),
            account_group: Some(vec!["g".into()]),
            profile: Some(vec!["p".into()]),
            ca: Some(vec!["c".into()]),
            identifier: Some(vec!["dns:.*".into()]),
            key_type: Some(vec!["ec:P-256".into()]),
            ..Default::default()
        };
        let rule = match cfg.to_abac_rule().unwrap() {
            AbacRuleKind::Regular(r) => r,
            AbacRuleKind::Temporal(t) => t.into_inner(),
        };
        for dim in dims {
            assert!(
                rule.get_dimension(dim).is_some(),
                "dimension '{dim}' missing from AbacRule — PolicyRuleConfig or set_dimension is out of sync"
            );
        }
    }

    #[test]
    fn toml_policy_rule_config_into_policy_rule_config_preserves_fields() {
        let toml_rule = TomlPolicyRuleConfig {
            name: "toml-rule".into(),
            rule_type: RuleTypeConfig::Deny,
            profile: Some(vec!["tls-server".into()]),
            ca: Some(vec!["prod".into()]),
            account: Some(vec!["acct-1".into()]),
            account_group: Some(vec!["group-1".into()]),
            identifier: Some(vec!["dns:.*".into()]),
            key_type: Some(vec!["ec:P-256".into()]),
            valid_from: Some("2026-01-01T00:00:00Z".into()),
            valid_until: Some("2026-12-31T23:59:59Z".into()),
            enabled: Some(false),
        };
        let cfg: PolicyRuleConfig = toml_rule.clone().into();
        assert_eq!(cfg.name, toml_rule.name);
        assert_eq!(cfg.rule_type, toml_rule.rule_type);
        assert_eq!(cfg.profile, toml_rule.profile);
        assert_eq!(cfg.ca, toml_rule.ca);
        assert_eq!(cfg.account, toml_rule.account);
        assert_eq!(cfg.account_group, toml_rule.account_group);
        assert_eq!(cfg.identifier, toml_rule.identifier);
        assert_eq!(cfg.key_type, toml_rule.key_type);
        assert_eq!(cfg.valid_from, toml_rule.valid_from);
        assert_eq!(cfg.valid_until, toml_rule.valid_until);
        assert_eq!(cfg.enabled, toml_rule.enabled);
    }

    #[test]
    fn policy_rule_request_into_policy_rule_config_preserves_fields() {
        let request = PolicyRuleRequest {
            name: "api-rule".into(),
            rule_type: RuleTypeConfig::Allow,
            profile: Some(vec!["web".into()]),
            ca: None,
            account: None,
            account_group: Some(vec!["prod-infra".into()]),
            identifier: Some(vec!["dns:.*\\.example\\.com$".into()]),
            key_type: None,
            valid_from: None,
            valid_until: None,
            enabled: Some(true),
        };
        let cfg: PolicyRuleConfig = request.clone().into();
        assert_eq!(cfg.name, request.name);
        assert_eq!(cfg.rule_type, request.rule_type);
        assert_eq!(cfg.profile, request.profile);
        assert_eq!(cfg.ca, request.ca);
        assert_eq!(cfg.account, request.account);
        assert_eq!(cfg.account_group, request.account_group);
        assert_eq!(cfg.identifier, request.identifier);
        assert_eq!(cfg.key_type, request.key_type);
        assert_eq!(cfg.valid_from, request.valid_from);
        assert_eq!(cfg.valid_until, request.valid_until);
        assert_eq!(cfg.enabled, request.enabled);
    }

    /// Mirrors `deserialize_rejects_unknown_field` for the admin-API input
    /// path (JSON, not TOML) — this is the client-input surface where
    /// typo-protection matters most.
    #[test]
    fn policy_rule_request_rejects_unknown_field() {
        let json = r#"{"name": "deny-internal", "type": "deny", "identifer": ["x"]}"#;
        let err = serde_json::from_str::<PolicyRuleRequest>(json).unwrap_err();
        assert!(
            err.to_string().contains("identifer") || err.to_string().contains("unknown field"),
            "expected an unknown-field error, got: {err}"
        );
    }
}
