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

pub mod accounts;
pub mod audit;
pub mod cas;
pub mod certs;
pub mod delegations;
pub mod eab;
pub mod operators;
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
pub use self::operators::{
    get_operator, get_operators, patch_operator, post_operators, put_operator, unlock_operator,
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

/// Produce an openssl-style text description of a DER-encoded certificate.
///
/// Used by `certs` (cert detail) and `cas` (CA detail + cross-cert detail).
pub(super) fn describe_cert_der(der: &[u8]) -> Option<String> {
    use std::fmt::Write as FmtWrite;
    use synta::{Decoder, Encoding};
    use synta_certificate::{
        decode_extensions, decode_public_key_info, extension_oid_name, format_dn,
        format_extension_value, identify_public_key_algorithm, identify_signature_algorithm,
        Certificate, PublicKeyInfo, Time,
    };

    let mut decoder = Decoder::new(der, Encoding::Der);
    let cert: Certificate = decoder.decode().ok()?;
    let tbs = &cert.tbs_certificate;
    let mut out = String::new();

    let version = tbs
        .version
        .as_ref()
        .and_then(|v| v.as_i64().ok())
        .map(|v| v + 1)
        .unwrap_or(1);

    let _ = writeln!(out, "Certificate:");
    let _ = writeln!(out, "    Data:");
    let _ = writeln!(out, "        Version: {} (0x{:x})", version, version - 1);

    let serial_bytes = tbs.serial_number.as_bytes();
    if serial_bytes.len() <= 8 {
        let mut val: u64 = 0;
        for b in serial_bytes {
            val = (val << 8) | (*b as u64);
        }
        let _ = writeln!(out, "        Serial Number: {} (0x{:x})", val, val);
    } else {
        let hex = serial_bytes
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join(":");
        let _ = writeln!(out, "        Serial Number: {}", hex);
    }

    let sig_alg = identify_signature_algorithm(&tbs.signature.algorithm);
    let _ = writeln!(out, "        Signature Algorithm: {}", sig_alg);
    let _ = writeln!(out, "        Issuer: {}", format_dn(tbs.issuer.as_bytes()));
    let _ = writeln!(out, "        Validity");

    fn fmt_time(t: &Time) -> String {
        const M: [&str; 12] = [
            "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
        ];
        match t {
            Time::UtcTime(u) => format!(
                "{} {:2} {:02}:{:02}:{:02} {} GMT",
                M.get((u.month - 1) as usize).unwrap_or(&"???"),
                u.day,
                u.hour,
                u.minute,
                u.second,
                u.year,
            ),
            Time::GeneralTime(g) => format!(
                "{} {:2} {:02}:{:02}:{:02} {} GMT",
                M.get((g.month - 1) as usize).unwrap_or(&"???"),
                g.day,
                g.hour,
                g.minute,
                g.second,
                g.year,
            ),
        }
    }

    let _ = writeln!(
        out,
        "            Not Before: {}",
        fmt_time(&tbs.validity.not_before)
    );
    let _ = writeln!(
        out,
        "            Not After : {}",
        fmt_time(&tbs.validity.not_after)
    );
    let _ = writeln!(
        out,
        "        Subject: {}",
        format_dn(tbs.subject.as_bytes())
    );

    let spki = &tbs.subject_public_key_info;
    let pub_alg = identify_public_key_algorithm(&spki.algorithm.algorithm).unwrap_or("unknown");
    let _ = writeln!(out, "        Subject Public Key Info:");
    let _ = writeln!(out, "            Public Key Algorithm: {}", pub_alg);

    fn write_hex(out: &mut String, data: &[u8], per_line: usize, indent: usize) {
        let pad = " ".repeat(indent);
        let chunks: Vec<_> = data.chunks(per_line).collect();
        for (i, chunk) in chunks.iter().enumerate() {
            let _ = write!(out, "{}", pad);
            for (j, b) in chunk.iter().enumerate() {
                if j > 0 {
                    let _ = write!(out, ":");
                }
                let _ = write!(out, "{:02x}", b);
            }
            if i < chunks.len() - 1 {
                let _ = write!(out, ":");
            }
            let _ = writeln!(out);
        }
    }

    match decode_public_key_info(
        &spki.algorithm.algorithm,
        spki.algorithm.parameters.as_ref(),
        spki.subject_public_key.as_bytes(),
        spki.subject_public_key.bit_len(),
    ) {
        PublicKeyInfo::Rsa {
            modulus,
            exponent,
            bit_count,
        } => {
            let _ = writeln!(out, "                Public-Key: ({} bit)", bit_count);
            let _ = writeln!(out, "                Modulus:");
            write_hex(&mut out, &modulus, 15, 20);
            let _ = writeln!(
                out,
                "                Exponent: {} (0x{:x})",
                exponent, exponent
            );
        }
        PublicKeyInfo::Ec {
            key_bytes,
            bit_count,
            curve_short_name,
            curve_nist_name,
            curve_oid_str,
        } => {
            let _ = writeln!(out, "                Public-Key: ({} bit)", bit_count);
            let _ = writeln!(out, "                pub:");
            write_hex(&mut out, &key_bytes, 15, 20);
            let name = curve_short_name.map(str::to_owned).unwrap_or(curve_oid_str);
            let _ = writeln!(out, "                ASN1 OID: {}", name);
            if let Some(nist) = curve_nist_name {
                let _ = writeln!(out, "                NIST CURVE: {}", nist);
            }
        }
        PublicKeyInfo::Unknown {
            key_bytes,
            bit_count,
            ..
        } => {
            let _ = writeln!(out, "                Public-Key: ({} bit)", bit_count);
            let _ = writeln!(out, "                pub:");
            write_hex(&mut out, &key_bytes, 15, 20);
        }
    }

    if let Some(exts_raw) = &tbs.extensions {
        let exts = decode_extensions(exts_raw.as_bytes());
        if !exts.is_empty() {
            let _ = writeln!(out, "        X509v3 extensions:");
            for ext in &exts {
                let name = extension_oid_name(&ext.extn_id);
                let critical = ext.critical.map(bool::from).unwrap_or(false);
                if critical {
                    let _ = writeln!(out, "            {}: critical", name);
                } else {
                    let _ = writeln!(out, "            {}:", name);
                }
                if let Some(val) = format_extension_value(ext) {
                    let _ = writeln!(out, "                {}", val);
                }
            }
        }
    }

    let _ = writeln!(out, "    Signature Algorithm: {}", sig_alg);
    let _ = writeln!(out, "    Signature Value:");
    write_hex(&mut out, cert.signature_value.as_bytes(), 18, 8);

    Some(out)
}
