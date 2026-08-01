use crate::dimension;
use crate::PolicyError;
use abac_rs::{AbacRequest, AttributeType};

/// Prints only the set of dimension names, never their values — an
/// `IssuanceRequest`/`IssuanceRequestBuilder` carries account IDs, Kerberos
/// principals (as `account_group` values), and per-SAN identifiers
/// (including literal email addresses for `email-reply-00`), so a derived
/// `Debug` would leak PII into any log or panic message that formats one.
fn fmt_dimensions_only(
    name: &str,
    req: &AbacRequest,
    f: &mut std::fmt::Formatter<'_>,
) -> std::fmt::Result {
    let mut dims: Vec<&str> = req.attributes().keys().map(String::as_str).collect();
    dims.sort_unstable();
    f.debug_struct(name).field("dimensions", &dims).finish()
}

pub struct IssuanceRequest(pub(crate) AbacRequest);

impl std::fmt::Debug for IssuanceRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        fmt_dimensions_only("IssuanceRequest", &self.0, f)
    }
}

pub struct IssuanceRequestBuilder {
    req: AbacRequest,
    error: Option<PolicyError>,
}

impl std::fmt::Debug for IssuanceRequestBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut dims: Vec<&str> = self.req.attributes().keys().map(String::as_str).collect();
        dims.sort_unstable();
        f.debug_struct("IssuanceRequestBuilder")
            .field("dimensions", &dims)
            .field("error", &self.error)
            .finish()
    }
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

    pub fn account_groups(mut self, groups: Vec<String>) -> Self {
        let group_attrs: Vec<AttributeType> =
            groups.into_iter().map(AttributeType::String).collect();
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

    /// Returns a clone of this request with the identifier dimension set to
    /// `id_type:id_value`.
    ///
    /// `AbacRequest` stores exactly one value (plus OR-matched groups) per
    /// dimension, so a multi-SAN order cannot be represented as a single
    /// request without collapsing to one identifier. Callers evaluating a
    /// multi-SAN order must call this once per identifier and combine the
    /// resulting decisions (see `IssuancePolicyEngine::evaluate_explained_identifiers`).
    pub fn with_identifier(&self, id_type: &str, id_value: &str) -> Result<Self, PolicyError> {
        let mut req = Self(self.0.clone());
        req.set_identifier(id_type, id_value)?;
        Ok(req)
    }

    /// Sets the identifier dimension on `self` in place to `id_type:id_value`,
    /// overwriting any identifier previously set on this request.
    ///
    /// Unlike `with_identifier`, this mutates `self` rather than cloning —
    /// used by `IssuancePolicyEngine::evaluate_explained_identifiers` to
    /// evaluate every identifier of a multi-SAN order against one working
    /// copy instead of cloning the whole request once per identifier.
    pub(crate) fn set_identifier(
        &mut self,
        id_type: &str,
        id_value: &str,
    ) -> Result<(), PolicyError> {
        let formatted = format!("{id_type}:{id_value}");
        self.0
            .add_attribute(
                dimension::IDENTIFIER,
                AttributeType::String(formatted),
                vec![],
            )
            .map_err(PolicyError::Request)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Asserts each setter's exact dimension value, not just that *some*
    /// attribute got set — the previous `!attributes().is_empty()` assertion
    /// could not fail if e.g. `.key_type(...)` or `.account_groups(...)`
    /// silently stopped doing anything, as long as any other setter still
    /// worked.
    #[test]
    fn builder_sets_all_dimensions() {
        let req = IssuanceRequest::builder()
            .account("acct-1")
            .account_groups(vec!["prod-infra".into()])
            .profile("tls-server")
            .ca("prod")
            .key_type("ec:P-256")
            .build()
            .unwrap()
            .with_identifier("dns", "example.com")
            .unwrap();

        assert_eq!(
            req.0.get_value(dimension::ACCOUNT),
            Some(&AttributeType::String("acct-1".into()))
        );
        assert_eq!(
            req.0.get_groups(dimension::ACCOUNT_GROUP),
            Some(&[AttributeType::String("prod-infra".into())][..])
        );
        assert_eq!(
            req.0.get_value(dimension::PROFILE),
            Some(&AttributeType::String("tls-server".into()))
        );
        assert_eq!(
            req.0.get_value(dimension::CA),
            Some(&AttributeType::String("prod".into()))
        );
        assert_eq!(
            req.0.get_value(dimension::KEY_TYPE),
            Some(&AttributeType::String("ec:P-256".into()))
        );
        assert_eq!(
            req.0.get_value(dimension::IDENTIFIER),
            Some(&AttributeType::String("dns:example.com".into()))
        );
    }

    #[test]
    fn builder_empty_identifiers_ok() {
        let req = IssuanceRequest::builder()
            .account("acct-1")
            .profile("default")
            .ca("default")
            .build()
            .unwrap();
        assert_eq!(
            req.0.get_value(dimension::ACCOUNT),
            Some(&AttributeType::String("acct-1".into()))
        );
        assert_eq!(
            req.0.get_value(dimension::PROFILE),
            Some(&AttributeType::String("default".into()))
        );
        assert_eq!(
            req.0.get_value(dimension::CA),
            Some(&AttributeType::String("default".into()))
        );
        assert_eq!(
            req.0.get_value(dimension::IDENTIFIER),
            None,
            "no identifier was set, and none should be assumed"
        );
    }

    #[test]
    fn with_identifier_does_not_mutate_base_request() {
        let base = IssuanceRequest::builder()
            .account("acct-1")
            .ca("prod")
            .build()
            .unwrap();

        let a = base.with_identifier("dns", "a.example.com").unwrap();
        let b = base.with_identifier("dns", "b.example.com").unwrap();

        assert_eq!(base.0.get_value(dimension::IDENTIFIER), None);
        assert_eq!(
            a.0.get_value(dimension::IDENTIFIER),
            Some(&AttributeType::String("dns:a.example.com".into()))
        );
        assert_eq!(
            b.0.get_value(dimension::IDENTIFIER),
            Some(&AttributeType::String("dns:b.example.com".into()))
        );
    }

    #[test]
    fn set_identifier_mutates_in_place_and_overwrites() {
        let mut req = IssuanceRequest::builder()
            .account("acct-1")
            .ca("prod")
            .build()
            .unwrap();

        req.set_identifier("dns", "a.example.com").unwrap();
        assert_eq!(
            req.0.get_value(dimension::IDENTIFIER),
            Some(&AttributeType::String("dns:a.example.com".into()))
        );

        req.set_identifier("dns", "b.example.com").unwrap();
        assert_eq!(
            req.0.get_value(dimension::IDENTIFIER),
            Some(&AttributeType::String("dns:b.example.com".into())),
            "a second set_identifier call must overwrite, not accumulate"
        );
    }

    /// `IssuanceRequest`/`IssuanceRequestBuilder` carry PII (account IDs,
    /// Kerberos principals, and per-SAN identifiers including literal email
    /// addresses for `email-reply-00`) — `{:?}` must never print any of it,
    /// even though listing which dimensions are set is fine.
    #[test]
    fn debug_redacts_attribute_values() {
        let req = IssuanceRequest::builder()
            .account("super-secret-account-id")
            .account_groups(vec!["kerberos/principal@EXAMPLE.COM".into()])
            .build()
            .unwrap()
            .with_identifier("email", "victim@example.com")
            .unwrap();

        let debug = format!("{req:?}");
        assert!(
            !debug.contains("super-secret-account-id")
                && !debug.contains("kerberos/principal@EXAMPLE.COM")
                && !debug.contains("victim@example.com"),
            "Debug output leaked a value: {debug}"
        );
        assert!(
            debug.contains(dimension::ACCOUNT) && debug.contains(dimension::IDENTIFIER),
            "Debug output should still list which dimensions are set: {debug}"
        );
    }
}
