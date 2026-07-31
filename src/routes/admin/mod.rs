//! Admin API endpoints — `/admin/…`
//!
//! All routes require operator authentication via mTLS client certificate or
//! GSSAPI/Kerberos session token (see `crate::admin::auth`).  When the `[admin]`
//! section is absent the routes return 404.
//!
//! # Route → role matrix
//!
//! Role enforcement is centralized in [`rbac::admin_rbac_gate`], a middleware
//! applied over the whole admin router in `build_admin_router()`
//! (`src/routes/mod.rs`), driven by [`rbac::ADMIN_RBAC_TABLE`]. A route with
//! no matching table row is denied — there's no way for a new route to ship
//! without a role requirement, since forgetting the row makes the route
//! completely inaccessible rather than silently ungated. Individual handlers
//! no longer call a `require_role!` macro; the gate runs before any
//! handler-specific extractor, so a malformed request body/query can no
//! longer leak a validation-error status ahead of the role check.
//!
//! `tests/admin_rbac.rs` imports `ADMIN_RBAC_TABLE` directly rather than
//! keeping its own copy. The human-readable prose matrix in
//! `docs/src/user/operator-roles.md` remains hand-maintained against this
//! table (one manual sync point instead of the three this used to be).

pub mod accounts;
pub mod audit;
pub mod cas;
pub mod certs;
pub mod delegations;
pub mod eab;
pub mod error;
pub mod mtc;
pub mod operators;
pub mod policy;
pub mod profiles;
pub mod rbac;
pub mod stats;
pub mod tkauth;

// ── Re-exports ────────────────────────────────────────────────────────────────

pub use self::accounts::{
    delete_account_profile_grants, get_account, get_account_profile_grants, get_accounts,
    get_order, get_orders, post_account_deactivate, put_account_profile_grants,
};
pub use self::audit::get_audit;
pub use self::cas::{
    get_ca, get_ca_cert, get_cas, get_cross_cert, get_cross_certs, post_ca_crl_force,
    post_ca_cross_sign, CrossCertsQuery, CrossSignPayload, CrossSignSubject,
};
pub use self::certs::{get_cert, get_cert_download, get_certs, post_crl_force, post_revoke};
pub use self::delegations::{
    delegation_row_to_json, delete_delegation, get_delegation_admin, get_delegations,
    post_delegations, put_delegation,
};
pub use self::eab::{delete_eab, get_eab, get_eab_key, post_eab};
pub use self::mtc::{
    get_checkpoint as get_mtc_checkpoint, get_consistency_proof as get_mtc_consistency_proof,
    get_cosignature as get_mtc_cosignature, get_inclusion_proof as get_mtc_inclusion_proof,
    get_landmark_cert as get_mtc_landmark_cert,
    get_landmark_cert_details as get_mtc_landmark_cert_details,
    get_landmark_list as get_mtc_landmark_list, get_landmarks as get_mtc_landmarks,
    get_log_list_entry as get_mtc_log_list_entry, get_revoked_ranges as get_mtc_revoked_ranges,
    get_root as get_mtc_root, get_standalone as get_mtc_standalone,
    get_subtree_root as get_mtc_subtree_root, get_tree_size as get_mtc_tree_size,
    post_force_checkpoint as post_mtc_force_checkpoint,
    post_force_landmark as post_mtc_force_landmark,
};
pub use self::operators::{
    get_operator, get_operators, patch_operator, post_operators, put_operator, unlock_operator,
};
pub use self::policy::{
    delete_policy_rule, get_policy_rule, get_policy_rules, get_policy_scopes, post_policy_rule,
    put_policy_rule,
};
pub use self::profiles::{delete_profile, get_profile, get_profiles, post_profiles, put_profile};
pub use self::stats::{get_config, get_stats};
pub use self::tkauth::post_tkauth_prune_jti;

// ── Shared helpers ────────────────────────────────────────────────────────────

/// Serialize an optional list of profile grants to a JSON string for DB storage.
///
/// Used by both `accounts` (profile-grants endpoints) and `eab` (EAB key creation).
pub(super) fn grants_to_json(grants: Option<Vec<String>>) -> Result<Option<String>, String> {
    match grants {
        None => Ok(None),
        Some(ref vec) if vec.is_empty() => Ok(None),
        Some(ref vec) => serde_json::to_string(vec)
            .map(Some)
            .map_err(|e| format!("serialize profile_grants: {e}")),
    }
}

pub(super) use akamu_client::cert_text::describe_cert_der;
pub(super) use akamu_client::cert_text::describe_landmark_cert_der;
