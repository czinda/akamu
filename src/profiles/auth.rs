//! Per-profile authorization checks applied at certificate finalization.
//!
//! Mechanism:
//!
//! 1. **Identifier patterns** — regex patterns matched against each order
//!    identifier formatted as `"type:value"`.  Controlled by
//!    `allowed_identifier_patterns` / `identifier_match_all` in
//!    [`CertificateParameters`].

use crate::error::AcmeError;
use crate::profiles::CertificateParameters;

/// Run all configured authorization checks for a profile.
///
/// `identifiers` is a slice of `(type, value)` pairs from the ACME order
/// (e.g. `[("dns", "example.com"), ("dns", "*.example.com")]`).
///
/// Returns `Ok(())` when every enabled check passes, or the first
/// `Err(AcmeError::Unauthorized(_))` / `Err(AcmeError::InvalidProfile(_))`
/// encountered.
pub async fn check_profile_auth(
    _db: &crate::db::Db,
    _account_id: &str,
    _profile_name: &str,
    params: &CertificateParameters,
    identifiers: &[(&str, &str)],
) -> Result<(), AcmeError> {
    if !params.allowed_identifier_patterns.is_empty() {
        check_identifier_patterns(
            identifiers,
            &params.allowed_identifier_patterns,
            params.identifier_match_all,
        )?;
    }

    Ok(())
}

// ── Identifier pattern check ──────────────────────────────────────────────────

fn check_identifier_patterns(
    identifiers: &[(&str, &str)],
    patterns: &[String],
    match_all: bool,
) -> Result<(), AcmeError> {
    if identifiers.is_empty() {
        return Ok(());
    }

    let compiled: Vec<regex::Regex> = patterns
        .iter()
        .map(|p| {
            regex::Regex::new(p)
                .map_err(|e| AcmeError::InvalidProfile(format!("auth pattern '{p}': {e}")))
        })
        .collect::<Result<Vec<_>, _>>()?;

    for (id_type, id_value) in identifiers {
        let subject = format!("{id_type}:{id_value}");
        let matches_any_pattern = compiled.iter().any(|re| re.is_match(&subject));

        if match_all && !matches_any_pattern {
            return Err(AcmeError::Unauthorized(format!(
                "identifier '{subject}' is not permitted for this profile"
            )));
        }
        if !match_all && matches_any_pattern {
            // "any" mode: one matching identifier is enough — pass immediately.
            return Ok(());
        }
    }

    // "any" mode exhausted all identifiers without a match.
    if !match_all {
        return Err(AcmeError::Unauthorized(
            "no identifier matches the profile's allowed pattern(s)".into(),
        ));
    }

    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn patterns_match_all_passes_when_all_match() {
        let ids = [("dns", "example.com"), ("dns", "www.example.com")];
        let patterns = vec![
            r"dns:.*\.example\.com$".to_string(),
            r"dns:example\.com$".to_string(),
        ];
        assert!(check_identifier_patterns(&ids, &patterns, true).is_ok());
    }

    #[test]
    fn patterns_match_all_fails_on_unmatched_id() {
        let ids = [("dns", "example.com"), ("dns", "evil.net")];
        let patterns = vec![r"dns:.*example\.com".to_string()];
        let err = check_identifier_patterns(&ids, &patterns, true).unwrap_err();
        assert!(matches!(err, AcmeError::Unauthorized(_)));
    }

    #[test]
    fn patterns_match_any_passes_on_single_match() {
        let ids = [("dns", "example.com"), ("dns", "other.net")];
        let patterns = vec![r"dns:example\.com$".to_string()];
        assert!(check_identifier_patterns(&ids, &patterns, false).is_ok());
    }

    #[test]
    fn patterns_match_any_fails_when_none_match() {
        let ids = [("dns", "evil.net"), ("dns", "also.evil.net")];
        let patterns = vec![r"dns:.*example\.com".to_string()];
        let err = check_identifier_patterns(&ids, &patterns, false).unwrap_err();
        assert!(matches!(err, AcmeError::Unauthorized(_)));
    }

    #[test]
    fn patterns_empty_ids_always_passes() {
        let patterns = vec![r"dns:.*".to_string()];
        assert!(check_identifier_patterns(&[], &patterns, true).is_ok());
        assert!(check_identifier_patterns(&[], &patterns, false).is_ok());
    }

    #[test]
    fn invalid_pattern_returns_invalid_profile() {
        let ids = [("dns", "example.com")];
        let patterns = vec!["[invalid".to_string()];
        let err = check_identifier_patterns(&ids, &patterns, true).unwrap_err();
        assert!(matches!(err, AcmeError::InvalidProfile(_)));
    }
}
