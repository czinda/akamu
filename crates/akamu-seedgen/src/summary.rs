//! Structured summary output (text and JSON).

use crate::{
    postprocess::PostprocessStats,
    scenarios::{ScenarioOutcome, TargetState},
    setup::DevCredentials,
    spec::SeedSpec,
};

#[derive(Debug, serde::Serialize)]
pub struct Summary {
    pub cas: usize,
    pub cross_signs: usize,
    pub profiles: usize,
    pub accounts_total: usize,
    pub accounts_deactivated: usize,
    pub certs_valid: usize,
    pub certs_revoked: usize,
    pub certs_expired: usize,
    pub certs_near_expiry: usize,
    pub certs_ari_chains: usize,
    pub orders_total: usize,
    pub orders_star_active: usize,
    pub orders_star_canceled: usize,
    pub orders_delegation: usize,
    pub orders_pending: usize,
    pub orders_invalid: usize,
    pub output_path: String,
    /// EAB kid for the seeded dev admin operator.
    pub admin_kid: String,
    /// HMAC key (base64url) for the seeded dev admin operator.
    pub admin_hmac_key: String,
}

impl Summary {
    pub fn build(
        spec: &SeedSpec,
        outcomes: &[ScenarioOutcome],
        stats: &PostprocessStats,
        output_path: &str,
        creds: &DevCredentials,
    ) -> Self {
        let mut accounts_total = 0;
        let mut accounts_deactivated = 0;
        let mut orders_star_active = 0;
        let mut orders_star_canceled = 0;
        let mut orders_delegation = 0;
        let mut orders_pending = 0;
        let mut orders_invalid = 0;

        for o in outcomes {
            accounts_total += o.account_count;
            orders_star_active += o.star_active_order_urls.len();
            orders_star_canceled += o.star_canceled_order_urls.len();
            orders_delegation += o.delegation_order_urls.len();
            orders_pending += o.pending_order_urls.len();
            orders_invalid += o.invalid_order_urls.len();
        }

        for s in &spec.scenario {
            accounts_deactivated += s.accounts.deactivated;
        }

        let certs_issued: usize = outcomes.iter().map(|o| o.issued.len()).sum();
        let orders_regular = certs_issued;
        let orders_total = orders_regular
            + orders_star_active
            + orders_star_canceled
            + orders_delegation
            + orders_pending
            + orders_invalid;

        Summary {
            cas: spec.ca.len(),
            cross_signs: spec.cross_sign.len(),
            profiles: spec.profile.len(),
            accounts_total,
            accounts_deactivated,
            certs_valid: count_state(outcomes, |s| matches!(s, TargetState::Valid)),
            certs_revoked: stats.revoked,
            certs_expired: stats.expired,
            certs_near_expiry: stats.near_expiry,
            certs_ari_chains: stats.ari_chains_linked,
            orders_total,
            orders_star_active,
            orders_star_canceled,
            orders_delegation,
            orders_pending,
            orders_invalid: stats.invalid_orders,
            output_path: output_path.to_string(),
            admin_kid: creds.kid.clone(),
            admin_hmac_key: creds.hmac_key_b64u.clone(),
        }
    }

    /// Print a human-readable summary to stdout.
    pub fn print_text(&self) {
        println!("=== akamu-seedgen summary ===");
        println!("CAs:              {}", self.cas);
        println!("Cross-signs:      {}", self.cross_signs);
        println!("Profiles:         {}", self.profiles);
        println!(
            "Accounts:         {} total  ({} deactivated)",
            self.accounts_total, self.accounts_deactivated
        );
        println!("Orders:           {}", self.orders_total);
        println!("  STAR active:    {}", self.orders_star_active);
        println!("  STAR canceled:  {}", self.orders_star_canceled);
        println!("  delegation:     {}", self.orders_delegation);
        println!("  pending:        {}", self.orders_pending);
        println!("  invalid:        {}", self.orders_invalid);
        println!(
            "Certificates:     {}",
            self.certs_valid
                + self.certs_revoked
                + self.certs_expired
                + self.certs_near_expiry
                + self.certs_ari_chains * 3
        );
        println!("  valid:          {}", self.certs_valid);
        println!("  revoked:        {}", self.certs_revoked);
        println!("  expired:        {}", self.certs_expired);
        println!("  near-expiry:    {}", self.certs_near_expiry);
        println!(
            "  ARI chains:     {} ({} certs)",
            self.certs_ari_chains,
            self.certs_ari_chains * 3
        );
        println!("Output:           {}", self.output_path);
        println!();
        println!("Web UI login (EAB tab at /ui/login):");
        println!("  Key ID (kid):        {}", self.admin_kid);
        println!("  HMAC key (base64url): {}", self.admin_hmac_key);
    }

    /// Print JSON to stdout.
    pub fn print_json(&self) {
        println!("{}", serde_json::to_string_pretty(self).unwrap_or_default());
    }
}

fn count_state<F>(outcomes: &[ScenarioOutcome], pred: F) -> usize
where
    F: Fn(&TargetState) -> bool,
{
    outcomes
        .iter()
        .flat_map(|o| o.issued.iter())
        .filter(|(_, state)| pred(state))
        .count()
}
