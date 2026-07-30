//! Admin API endpoints — `/admin/…`
//!
//! All routes require operator authentication via mTLS client certificate or
//! GSSAPI/Kerberos session token (see `crate::admin::auth`).  When the `[admin]`
//! section is absent the routes return 404.
//!
//! # Route → role matrix
//!
//! | Route | administrator | ca_operations | ca_ra | auditor |
//! |-------|:---:|:---:|:---:|:---:|
//! | `POST /admin/session` | ✓ | ✓ | ✓ | ✓ |
//! | `DELETE /admin/session` | ✓ | ✓ | ✓ | ✓ |
//! | `POST /admin/session/eab` | ✓ | ✓ | ✓ | ✓ |
//! | `GET /admin/operators` | ✓ | | | |
//! | `POST /admin/operators` | ✓ | | | |
//! | `GET /admin/operators/{id}` | ✓ | | | |
//! | `PUT /admin/operators/{id}` | ✓ | | | |
//! | `PATCH /admin/operators/{id}` | ✓ | | | |
//! | `POST /admin/operators/{id}/unlock` | ✓ | | | |
//! | `GET /admin/audit` | ✓ | | | ✓ |
//! | `GET /admin/certs` | ✓ | ✓ | | ✓ |
//! | `GET /admin/certs/{id}` | ✓ | ✓ | | ✓ |
//! | `GET /admin/certs/{id}/download` | ✓ | ✓ | | |
//! | `GET /admin/profiles` | ✓ | ✓ | ✓ | ✓ |
//! | `POST /admin/profiles` | ✓ | | | |
//! | `PUT /admin/profiles/{id}` | ✓ | | | |
//! | `GET /admin/profiles/{id}` | ✓ | ✓ | ✓ | ✓ |
//! | `DELETE /admin/profiles/{id}` | ✓ | | | |
//! | `GET /admin/accounts` | ✓ | ✓ | ✓ | ✓ |
//! | `GET /admin/account/{id}` | ✓ | ✓ | ✓ | ✓ |
//! | `POST /admin/account/{id}/deactivate` | ✓ | | | |
//! | `GET /admin/account/{id}/profile-grants` | ✓ | ✓ | ✓ | ✓ |
//! | `PUT /admin/account/{id}/profile-grants` | ✓ | ✓ | | |
//! | `DELETE /admin/account/{id}/profile-grants` | ✓ | | | |
//! | `POST /admin/eab` | ✓ | ✓ | | |
//! | `GET /admin/eab/{kid}` | ✓ | ✓ | ✓ | ✓ |
//! | `DELETE /admin/eab/{kid}` | ✓ | ✓ | | |
//! | `GET /admin/eab` | ✓ | ✓ | ✓ | ✓ |
//! | `GET /admin/orders` | ✓ | ✓ | ✓ | ✓ |
//! | `GET /admin/orders/{id}` | ✓ | ✓ | ✓ | ✓ |
//! | `GET /admin/config` | ✓ | | | |
//! | `POST /admin/crl/force` | ✓ | ✓ | | |
//! | `POST /admin/revoke` | ✓ | ✓ | ✓ | |
//! | `GET /admin/stats` | ✓ | ✓ | ✓ | ✓ |
//! | `GET /admin/cas` | ✓ | ✓ | | |
//! | `GET /admin/cas/{id}` | ✓ | ✓ | | |
//! | `GET /admin/cas/{id}/cert` | ✓ | ✓ | | |
//! | `POST /admin/ca/{id}/crl/force` | ✓ | ✓ | | |
//! | `POST /admin/ca/{id}/cross-sign` | ✓ | ✓ | | |
//! | `GET /admin/cross-certs` | ✓ | ✓ | | ✓ |
//! | `GET /admin/cross-certs/{id}` | ✓ | ✓ | | ✓ |
//! | `GET /admin/delegations` | ✓ | ✓ | ✓ | ✓ |
//! | `POST /admin/delegations` | ✓ | ✓ | | |
//! | `GET /admin/delegations/{id}` | ✓ | ✓ | ✓ | ✓ |
//! | `PUT /admin/delegations/{id}` | ✓ | ✓ | | |
//! | `DELETE /admin/delegations/{id}` | ✓ | ✓ | | |
//! | `POST /admin/tkauth/prune-jti` | ✓ | ✓ | | |
//! | `GET /admin/mtc/tree-size` | ✓ | ✓ | | ✓ |
//! | `GET /admin/mtc/root` | ✓ | ✓ | | ✓ |
//! | `GET /admin/mtc/landmarks` | ✓ | ✓ | | ✓ |
//! | `GET /admin/mtc/landmark-list` | ✓ | ✓ | | ✓ |
//! | `GET /admin/mtc/inclusion-proof/{cert_id}` | ✓ | ✓ | | ✓ |
//! | `GET /admin/mtc/standalone/{cert_id}` | ✓ | ✓ | | |
//! | `GET /admin/mtc/landmarks/{seq}/cert` | ✓ | ✓ | | |
//! | `GET /admin/mtc/landmarks/{seq}/cert-details` | ✓ | ✓ | | ✓ |
//! | `GET /admin/mtc/consistency-proof` | ✓ | ✓ | | ✓ |
//! | `GET /admin/mtc/subtree-root` | ✓ | ✓ | | ✓ |
//! | `GET /admin/mtc/revoked-ranges` | ✓ | ✓ | | ✓ |
//! | `GET /admin/mtc/checkpoint` | ✓ | ✓ | | ✓ |
//! | `GET /admin/mtc/cosignature` | ✓ | ✓ | | ✓ |
//! | `POST /admin/ca/{id}/mtc/force-checkpoint` | ✓ | ✓ | | |
//! | `POST /admin/ca/{id}/mtc/force-landmark` | ✓ | ✓ | | |
//! | `GET /admin/ca/{id}/mtc/log-list-entry` | ✓ | ✓ | | ✓ |
//! | `GET /admin/gossip/status` | ✓ | ✓ | ✓ | ✓ |
//! | `POST /admin/gossip/register` | ✓ | | | |
//! | `GET /admin/policy/scopes` | ✓ | ✓ | | ✓ |
//! | `GET /admin/policy/rules` | ✓ | ✓ | | ✓ |
//! | `GET /admin/policy/rules/{id}` | ✓ | ✓ | | ✓ |
//! | `POST /admin/policy/rules` | ✓ | ✓ | | |
//! | `PUT /admin/policy/rules/{id}` | ✓ | ✓ | | |
//! | `DELETE /admin/policy/rules/{id}` | ✓ | ✓ | | |

pub mod accounts;
pub mod audit;
pub mod cas;
pub mod certs;
pub mod delegations;
pub mod eab;
pub mod mtc;
pub mod operators;
pub mod policy;
pub mod profiles;
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
