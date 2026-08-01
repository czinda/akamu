use abac_rs::{AttributeType, AttributeValue, Matcher};
use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex};

/// Maximum length of a single regex pattern accepted at validation time.
pub const MAX_REGEX_PATTERN_LEN: usize = 1024;

/// Maximum number of regex patterns per dimension in a single rule.
pub const MAX_REGEX_PATTERNS_PER_DIM: usize = 64;

const MAX_CACHE_ENTRIES: NonZeroUsize = NonZeroUsize::new(1024).unwrap();

/// Wraps `pattern` in a non-capturing group anchored to the whole string
/// (`^(?:pattern)$`), unless it is already fully anchored — preventing a
/// pattern like `dns:.*\.example\.com` from matching as an unintended
/// substring (e.g. `dns:www.example.com.evil.org`).
///
/// Used identically by both `validate_regex_patterns` (rule-creation time)
/// and `RegexMatcher::get_or_compile` (match time) so that "this pattern
/// validated" and "this pattern will compile at match time" are provably
/// the same claim, rather than two independently-maintained transformations
/// of the same string that could silently diverge.
fn anchor_pattern(pattern: &str) -> std::borrow::Cow<'_, str> {
    if pattern.starts_with('^') && pattern.ends_with('$') {
        std::borrow::Cow::Borrowed(pattern)
    } else {
        std::borrow::Cow::Owned(format!("^(?:{pattern})$"))
    }
}

pub struct RegexMatcher {
    cache: Mutex<lru::LruCache<String, Arc<regex::Regex>>>,
}

impl std::fmt::Debug for RegexMatcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RegexMatcher")
            .field("cache_capacity", &MAX_CACHE_ENTRIES)
            .finish()
    }
}

impl RegexMatcher {
    pub fn new() -> Self {
        Self {
            cache: Mutex::new(lru::LruCache::new(MAX_CACHE_ENTRIES)),
        }
    }

    fn get_or_compile(&self, pattern: &str) -> Option<Arc<regex::Regex>> {
        let mut cache = self.cache.lock().unwrap_or_else(|e| {
            tracing::error!("regex cache mutex was poisoned, recovering");
            e.into_inner()
        });
        if let Some(re) = cache.get(pattern) {
            return Some(Arc::clone(re));
        }
        let anchored = anchor_pattern(pattern);
        match regex::Regex::new(&anchored) {
            Ok(re) => {
                let re = Arc::new(re);
                cache.put(pattern.to_string(), Arc::clone(&re));
                Some(re)
            }
            Err(e) => {
                // Every pattern reaching here already passed
                // `validate_regex_patterns` at rule-creation time, so
                // reaching this branch means the anchoring transform below
                // diverged from validation's (see Finding 13 / the shared
                // `anchor_pattern` helper) — an invariant violation, not a
                // routine input-validation failure, hence `error!` not `warn!`.
                //
                // Returning `None` (no match) here is deliberate, not an
                // oversight: this matcher has no way to know whether the
                // caller is checking an allow rule or a deny rule for this
                // dimension. Unconditionally returning "matches" to fail
                // closed for deny rules would simultaneously make allow
                // rules fail *open* (falsely granting whatever the broken
                // pattern was meant to gate) — trading a narrow, mitigated
                // risk for a broader one. "No match" is safe for allow rules
                // (falls through to default-deny) and only a residual risk
                // for deny rules sharing this exact pattern, which
                // unification with validation is meant to make unreachable.
                tracing::error!(
                    pattern,
                    error = %e,
                    "invariant violation: regex pattern passed validation but failed to \
                     compile at evaluation time — search DB for rules containing this \
                     pattern to identify the source; treating as no-match"
                );
                None
            }
        }
    }
}

impl Default for RegexMatcher {
    fn default() -> Self {
        Self::new()
    }
}

impl Matcher for RegexMatcher {
    fn matches(
        &self,
        rule_value: &AttributeValue,
        request_value: &AttributeType,
        request_groups: &[AttributeType],
    ) -> bool {
        match rule_value {
            AttributeValue::All => true,
            AttributeValue::Specific(patterns) => {
                let check = |val: &AttributeType| -> bool {
                    let s = match val {
                        AttributeType::String(s) => s.as_str(),
                        _ => return false,
                    };
                    patterns.iter().any(|pattern| {
                        let pat = match pattern {
                            AttributeType::String(s) => s.as_str(),
                            _ => return false,
                        };
                        self.get_or_compile(pat)
                            .map(|re| re.is_match(s))
                            .unwrap_or(false)
                    })
                };
                check(request_value) || request_groups.iter().any(check)
            }
        }
    }

    fn supports_bloom_filter(&self) -> bool {
        false
    }

    fn name(&self) -> &str {
        "regex"
    }
}

#[derive(Debug, Clone, Copy)]
pub struct GlobMatcher;

impl Matcher for GlobMatcher {
    fn matches(
        &self,
        rule_value: &AttributeValue,
        request_value: &AttributeType,
        request_groups: &[AttributeType],
    ) -> bool {
        match rule_value {
            AttributeValue::All => true,
            AttributeValue::Specific(patterns) => {
                let check = |val: &AttributeType| -> bool {
                    let s = match val {
                        AttributeType::String(s) => s.as_str(),
                        _ => return false,
                    };
                    patterns.iter().any(|p| {
                        let pat = match p {
                            AttributeType::String(s) => s.as_str(),
                            _ => return false,
                        };
                        glob_match::glob_match(pat, s)
                    })
                };
                check(request_value) || request_groups.iter().any(check)
            }
        }
    }

    fn supports_bloom_filter(&self) -> bool {
        false
    }

    fn name(&self) -> &str {
        "glob"
    }
}

/// Validate that all regex patterns in a rule config compile successfully,
/// enforcing size and count limits to prevent resource exhaustion.
///
/// Compiles the same anchored form `RegexMatcher::get_or_compile` will use
/// at match time (via the shared `anchor_pattern` helper), not the raw
/// pattern — otherwise a pattern could pass validation here while its
/// anchored form fails to compile at match time.
pub fn validate_regex_patterns(patterns: &[String]) -> Result<(), crate::PolicyError> {
    if patterns.len() > MAX_REGEX_PATTERNS_PER_DIM {
        return Err(crate::PolicyError::Validation(format!(
            "too many regex patterns ({}, max {MAX_REGEX_PATTERNS_PER_DIM})",
            patterns.len()
        )));
    }
    for pat in patterns {
        if pat.len() > MAX_REGEX_PATTERN_LEN {
            return Err(crate::PolicyError::Validation(format!(
                "regex pattern too long ({} chars, max {MAX_REGEX_PATTERN_LEN})",
                pat.len()
            )));
        }
        regex::Regex::new(&anchor_pattern(pat))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn specific(vals: &[&str]) -> AttributeValue {
        AttributeValue::from_values(vals.iter().map(|v| AttributeType::String(v.to_string())))
    }

    fn str_attr(s: &str) -> AttributeType {
        AttributeType::String(s.into())
    }

    #[test]
    fn regex_matcher_matches_pattern() {
        let m = RegexMatcher::new();
        let rule_val = specific(&[r"dns:.*\.example\.com"]);
        assert!(m.matches(&rule_val, &str_attr("dns:www.example.com"), &[]));
        assert!(!m.matches(&rule_val, &str_attr("dns:evil.net"), &[]));
        // auto-anchoring prevents substring matches
        assert!(!m.matches(&rule_val, &str_attr("dns:www.example.com.evil.org"), &[]));
    }

    #[test]
    fn regex_matcher_all_matches_everything() {
        let m = RegexMatcher::new();
        assert!(m.matches(&AttributeValue::All, &str_attr("anything"), &[]));
    }

    #[test]
    fn regex_matcher_no_bloom_filter() {
        assert!(!RegexMatcher::new().supports_bloom_filter());
    }

    #[test]
    fn anchor_pattern_wraps_unanchored_patterns() {
        assert_eq!(anchor_pattern("abc"), "^(?:abc)$");
    }

    #[test]
    fn anchor_pattern_leaves_fully_anchored_patterns_unchanged() {
        assert_eq!(anchor_pattern("^abc$"), "^abc$");
    }

    /// Regression guard for Finding 13: `validate_regex_patterns` and
    /// `RegexMatcher::get_or_compile` must compile the exact same anchored
    /// string via the shared `anchor_pattern` helper, so "validated" and
    /// "will compile at match time" are provably the same claim rather than
    /// two independently-maintained transforms that could silently diverge.
    #[test]
    fn validate_and_match_time_anchoring_agree() {
        let pattern = r"dns:.*\.example\.com$"; // ends in `$` but doesn't start with `^`
        assert!(validate_regex_patterns(&[pattern.to_string()]).is_ok());
        let m = RegexMatcher::new();
        assert!(m.get_or_compile(pattern).is_some());
    }

    #[test]
    fn regex_matcher_caches_compiled_patterns() {
        let m = RegexMatcher::new();
        let rule_val = specific(&[r"^hello$"]);
        m.matches(&rule_val, &str_attr("hello"), &[]);
        m.matches(&rule_val, &str_attr("hello"), &[]);
        let mut cache = m.cache.lock().unwrap();
        assert_eq!(cache.len(), 1);
        assert!(cache.get("^hello$").is_some());
    }

    #[test]
    fn regex_matcher_invalid_pattern_returns_false() {
        let m = RegexMatcher::new();
        let rule_val = specific(&[r"[invalid"]);
        assert!(!m.matches(&rule_val, &str_attr("anything"), &[]));
    }

    #[test]
    fn validate_regex_patterns_ok() {
        assert!(validate_regex_patterns(&[r"^test$".into(), r".*\.com$".into()]).is_ok());
    }

    #[test]
    fn validate_regex_patterns_rejects_invalid() {
        assert!(validate_regex_patterns(&[r"[invalid".into()]).is_err());
    }

    #[test]
    fn glob_matcher_matches_kerberos_principal() {
        let m = GlobMatcher;
        let rule_val = specific(&["host/*@EXAMPLE.COM"]);
        assert!(m.matches(
            &rule_val,
            &str_attr("host/web1.example.com@EXAMPLE.COM"),
            &[],
        ));
        assert!(!m.matches(&rule_val, &str_attr("admin@EXAMPLE.COM"), &[]));
    }

    #[test]
    fn glob_matcher_checks_groups() {
        let m = GlobMatcher;
        let rule_val = specific(&["prod-infra"]);
        assert!(m.matches(&rule_val, &str_attr("_account_"), &[str_attr("prod-infra")],));
    }

    /// Mirrors `regex_matcher_no_bloom_filter`. This flag tells abac-rs not
    /// to bloom-filter-prefilter a pattern-matched dimension; if it were
    /// ever flipped to `true` without a matching change to how glob
    /// patterns get indexed, abac-rs could pre-filter out a deny rule whose
    /// glob pattern would have matched — a silent policy bypass, not a
    /// crash — so this is worth pinning down explicitly rather than relying
    /// on the type's default.
    #[test]
    fn glob_matcher_no_bloom_filter() {
        assert!(!GlobMatcher.supports_bloom_filter());
    }
}
