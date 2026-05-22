//! Direct library calls for setting up profiles and cross-certificates.
//!
//! Bypasses the admin HTTP routes so we never need operator credentials.

use std::sync::Arc;

use akamu::{
    ca::issue::issue_ca_cert,
    db,
    db::schema::CrossCertRow,
    profiles::{builtin::key_usage_from_names, CertificateParameters},
    state::AppState,
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use rand::RngCore;
use synta_certificate::KEY_USAGE_DIGITAL_SIGNATURE;
use uuid::Uuid;

use crate::spec::{CrossSignSpec, ProfileSpec};

/// Credentials for the seeded dev admin operator (printed at the end of the run).
pub struct DevCredentials {
    /// EAB key ID — enter in the web UI login form.
    pub kid: String,
    /// HMAC key in base64url encoding — enter in the web UI login form.
    pub hmac_key_b64u: String,
}

/// Create a seeded dev administrator operator and EAB key for web UI login.
///
/// Inserts one `operators` row (role=administrator, dummy GSSAPI principal to
/// satisfy the schema CHECK constraint) and one linked `eab_keys` row.  The
/// returned `DevCredentials` are printed at the end of the summary so the dev
/// can paste them directly into the web UI login form.
///
/// The HMAC key is derived from `rng`, so it is reproducible given the same
/// seed.  The RNG is always advanced by 32 bytes regardless of whether the
/// operator already exists, so `global_rng` position is stable across resume
/// runs.
pub async fn create_dev_admin(
    state: &Arc<AppState>,
    rng: &mut impl RngCore,
) -> Result<DevCredentials, String> {
    let mut key_bytes = [0u8; 32];
    rng.fill_bytes(&mut key_bytes);
    let hmac_key_b64u = URL_SAFE_NO_PAD.encode(key_bytes);

    let kid = "seedgen-admin".to_string();

    // Idempotent: skip DB writes if operator already exists (resume mode).
    let already_exists = db::operators::get_by_principal(&state.db, "seedgen-admin@SEEDGEN.LOCAL")
        .await
        .map_err(|e| format!("check dev admin operator: {e}"))?
        .is_some();

    if !already_exists {
        let now_unix = akamu::util::unix_now();
        let now = akamu::util::unix_to_rfc3339(now_unix);

        // Dummy GSSAPI principal satisfies the schema's NOT NULL check; it is
        // never used for actual authentication (EAB login does not check it).
        db::operators::insert(
            &state.db,
            "seedgen-admin",
            "administrator",
            None,
            Some("seedgen-admin@SEEDGEN.LOCAL"),
            "",
            &now,
        )
        .await
        .map_err(|e| format!("create dev admin operator: {e}"))?;

        let op = db::operators::get_by_principal(&state.db, "seedgen-admin@SEEDGEN.LOCAL")
            .await
            .map_err(|e| format!("look up dev admin operator: {e}"))?
            .ok_or("dev admin operator not found after insert")?;

        db::eab::insert_with_grants(
            &state.db,
            &kid,
            &hmac_key_b64u,
            None,
            Some(op.id),
            "sha256",
            now_unix,
        )
        .await
        .map_err(|e| format!("create dev admin EAB key: {e}"))?;
    }

    Ok(DevCredentials { kid, hmac_key_b64u })
}

/// Register all profiles from the spec into the in-process ProfileRegistry.
pub fn register_profiles(state: &Arc<AppState>, profiles: &[ProfileSpec]) {
    for p in profiles {
        let key_usage_bits = if p.key_usage.is_empty() {
            1u16 << KEY_USAGE_DIGITAL_SIGNATURE
        } else {
            key_usage_from_names(&p.key_usage)
        };

        // Resolve validity_days: use spec value or CA default.
        let default_ca = state.default_ca();
        let validity_days = p.validity_days.unwrap_or(default_ca.validity_days);

        let params = CertificateParameters {
            validity_days,
            hash_alg: default_ca.hash_alg.clone(),
            key_usage_bits,
            extended_key_usages: p.eku.clone(),
            crl_url: None,
            ocsp_url: None,
            allowed_key_types: p.allowed_key_types.clone(),
            certificate_policies: vec![],
            issue_as_mtc: false,
            allowed_identifier_patterns: p.allowed_identifiers.clone(),
            identifier_match_all: true,
            auth_hook: None,
            auth_hook_timeout_secs: 30,
            require_account_grant: p.require_account_grant,
            ca_ids: p.ca_ids.clone(),
            kpn_san_templates: vec![],
            ms_upn_san_template: None,
            inject_account_kpn: false,
        };

        let added = state
            .profiles
            .add_profile(p.id.clone(), p.description.clone(), params);
        // spec.rs validate() already rejects duplicate profile IDs; if we reach
        // this branch something has gone wrong in the caller.
        assert!(added, "profile '{}' already registered — duplicate IDs should have been caught by spec validation", p.id);
        if !added {
            tracing::warn!(id = %p.id, "profile already exists — skipped");
        } else {
            tracing::info!(id = %p.id, "profile registered");
        }
    }
}

/// Issue cross-certificates for all cross-sign pairs in the spec.
pub async fn issue_cross_certs(
    state: &Arc<AppState>,
    cross_signs: &[CrossSignSpec],
) -> Result<usize, String> {
    let mut count = 0;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock is set to before the Unix epoch")
        .as_secs() as i64;

    for cs in cross_signs {
        let issuer_ca = state
            .get_ca(&cs.issuer)
            .ok_or_else(|| format!("cross-sign: issuer CA '{}' not found", cs.issuer))?
            .clone();

        let subject_cert_der = state
            .get_ca(&cs.subject)
            .ok_or_else(|| format!("cross-sign: subject CA '{}' not found", cs.subject))?
            .cert_der
            .clone();

        let issued = issue_ca_cert(&issuer_ca, &subject_cert_der, cs.validity_years)
            .map_err(|e| format!("cross-sign {}->{}: {e}", cs.issuer, cs.subject))?;

        let row = CrossCertRow {
            id: Uuid::new_v4().to_string(),
            issuer_ca_id: cs.issuer.clone(),
            subject_ca_id: Some(cs.subject.clone()),
            subject_dn: issued.subject_dn.clone(),
            subject_spki: issued.subject_spki_der,
            cross_cert_der: issued.cert_der,
            cross_cert_pem: issued.cert_pem,
            not_before: issued.not_before,
            not_after: issued.not_after,
            serial_number: issued.serial_hex,
            created: now,
        };

        db::cross_certs::insert(&state.db, &row)
            .await
            .map_err(|e| format!("cross-sign DB insert {}->{}: {e}", cs.issuer, cs.subject))?;

        tracing::info!(
            issuer = %cs.issuer,
            subject = %cs.subject,
            subject_dn = %issued.subject_dn,
            "cross-cert issued"
        );
        count += 1;
    }

    Ok(count)
}
