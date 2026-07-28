//! Policy rule management subcommands (akamuctl policy …).

use serde_json::{json, Value};

use crate::client::AdminClient;
use crate::error::CtlError;
use crate::output::{print, Format};
use crate::urlenc;

pub async fn list_rules(client: &AdminClient, fmt: &Format, scope: &str) -> Result<(), CtlError> {
    let resp = client
        .get(&format!("/admin/policy/rules?scope={}", urlenc(scope)))
        .await?;
    print(fmt, &resp);
    Ok(())
}

pub struct AddRuleParams<'a> {
    pub name: &'a str,
    pub rule_type: &'a str,
    pub profile: &'a [String],
    pub ca: &'a [String],
    pub account: &'a [String],
    pub account_group: &'a [String],
    pub identifier: &'a [String],
    pub key_type: &'a [String],
    pub valid_from: Option<&'a str>,
    pub valid_until: Option<&'a str>,
    pub scope: &'a str,
    pub enabled: bool,
}

pub async fn add_rule(
    client: &AdminClient,
    fmt: &Format,
    p: AddRuleParams<'_>,
) -> Result<(), CtlError> {
    let mut rule = json!({
        "type": p.rule_type,
    });
    if !p.profile.is_empty() {
        rule["profile"] = json!(p.profile);
    }
    if !p.ca.is_empty() {
        rule["ca"] = json!(p.ca);
    }
    if !p.account.is_empty() {
        rule["account"] = json!(p.account);
    }
    if !p.account_group.is_empty() {
        rule["account_group"] = json!(p.account_group);
    }
    if !p.identifier.is_empty() {
        rule["identifier"] = json!(p.identifier);
    }
    if !p.key_type.is_empty() {
        rule["key_type"] = json!(p.key_type);
    }
    if let Some(vf) = p.valid_from {
        rule["valid_from"] = json!(vf);
    }
    if let Some(vu) = p.valid_until {
        rule["valid_until"] = json!(vu);
    }

    let body = json!({
        "scope": p.scope,
        "name": p.name,
        "rule": rule,
        "enabled": p.enabled,
    });
    let resp = client.post("/admin/policy/rules", Some(&body)).await?;
    print(fmt, &resp);
    Ok(())
}

pub async fn remove_rule(
    client: &AdminClient,
    fmt: &Format,
    name: Option<&str>,
    id: Option<&str>,
    scope: &str,
) -> Result<(), CtlError> {
    let rule_id = if let Some(id) = id {
        id.to_string()
    } else if let Some(name) = name {
        let resp = client
            .get(&format!("/admin/policy/rules?scope={}", urlenc(scope)))
            .await?;
        let rules: Vec<Value> = serde_json::from_value(resp)
            .map_err(|e| CtlError::Api(format!("failed to parse policy rules response: {e}")))?;
        let found = rules.iter().find(|r| r["name"].as_str() == Some(name));
        match found {
            Some(r) => {
                let rid = r["id"]
                    .as_str()
                    .ok_or_else(|| CtlError::Api("rule has no 'id' field".into()))?;
                if rid.is_empty() {
                    return Err(CtlError::Api("rule has empty 'id' field".into()));
                }
                rid.to_string()
            }
            None => {
                return Err(CtlError::Api(format!(
                    "rule '{name}' not found in scope '{scope}'"
                )))
            }
        }
    } else {
        return Err(CtlError::Api("--name or --id required".into()));
    };

    client
        .delete(&format!("/admin/policy/rules/{rule_id}"))
        .await?;
    print(fmt, &json!({"status": "removed", "id": rule_id}));
    Ok(())
}
