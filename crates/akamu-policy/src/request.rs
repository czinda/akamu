use crate::dimension;
use crate::PolicyError;
use abac_rs::{AbacRequest, AttributeType};

#[derive(Debug)]
pub struct IssuanceRequest(pub(crate) AbacRequest);

#[derive(Debug)]
pub struct IssuanceRequestBuilder {
    req: AbacRequest,
    error: Option<PolicyError>,
}

impl IssuanceRequestBuilder {
    pub fn new() -> Self {
        Self {
            req: AbacRequest::new(),
            error: None,
        }
    }

    fn try_add(&mut self, dim: &str, value: AttributeType, groups: Vec<AttributeType>) {
        if self.error.is_some() {
            return;
        }
        if let Err(e) = self.req.add_attribute(dim, value, groups) {
            self.error = Some(PolicyError::Request(e));
        }
    }

    pub fn account(mut self, id: &str) -> Self {
        self.try_add(dimension::ACCOUNT, AttributeType::String(id.into()), vec![]);
        self
    }

    pub fn account_groups(mut self, groups: &[String]) -> Self {
        let group_attrs: Vec<AttributeType> = groups
            .iter()
            .map(|g| AttributeType::String(g.clone()))
            .collect();
        self.try_add(
            dimension::ACCOUNT_GROUP,
            AttributeType::String("_account_".into()),
            group_attrs,
        );
        self
    }

    pub fn profile(mut self, name: &str) -> Self {
        self.try_add(
            dimension::PROFILE,
            AttributeType::String(name.into()),
            vec![],
        );
        self
    }

    pub fn ca(mut self, id: &str) -> Self {
        self.try_add(dimension::CA, AttributeType::String(id.into()), vec![]);
        self
    }

    pub fn identifiers(mut self, ids: &[(&str, &str)]) -> Self {
        for (id_type, id_value) in ids {
            let formatted = format!("{id_type}:{id_value}");
            self.try_add(
                dimension::IDENTIFIER,
                AttributeType::String(formatted),
                vec![],
            );
        }
        self
    }

    pub fn key_type(mut self, kt: &str) -> Self {
        self.try_add(
            dimension::KEY_TYPE,
            AttributeType::String(kt.into()),
            vec![],
        );
        self
    }

    pub fn build(self) -> Result<IssuanceRequest, PolicyError> {
        if let Some(e) = self.error {
            return Err(e);
        }
        Ok(IssuanceRequest(self.req))
    }
}

impl Default for IssuanceRequestBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl IssuanceRequest {
    pub fn builder() -> IssuanceRequestBuilder {
        IssuanceRequestBuilder::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builder_sets_all_dimensions() {
        let req = IssuanceRequest::builder()
            .account("acct-1")
            .account_groups(&["prod-infra".into()])
            .profile("tls-server")
            .ca("prod")
            .identifiers(&[("dns", "example.com")])
            .key_type("ec:P-256")
            .build()
            .unwrap();
        assert!(!req.0.attributes().is_empty());
    }

    #[test]
    fn builder_empty_identifiers_ok() {
        let req = IssuanceRequest::builder()
            .account("acct-1")
            .profile("default")
            .ca("default")
            .build()
            .unwrap();
        assert!(!req.0.attributes().is_empty());
    }
}
