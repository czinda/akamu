use abac_rs::{AttributeType, AttributeValue, Matcher};
use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex};

/// Maximum length of a single regex pattern accepted at validation time.
pub const MAX_REGEX_PATTERN_LEN: usize = 1024;

/// Maximum number of regex patterns per dimension in a single rule.
pub const MAX_REGEX_PATTERNS_PER_DIM: usize = 64;

const MAX_CACHE_ENTRIES: NonZeroUsize = NonZeroUsize::new(1024).unwrap();

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
        let anchored = if pattern.starts_with('^') && pattern.ends_with('$') {
            pattern.to_string()
        } else {
            format!("^(?:{pattern})$")
        };
        match regex::Regex::new(&anchored) {
            Ok(re) => {
                let re = Arc::new(re);
                cache.put(pattern.to_string(), Arc::clone(&re));
                Some(re)
            }
            Err(e) => {
                tracing::warn!(
                    pattern,
                    error = %e,
                    "regex pattern failed to compile at evaluation time — search DB for rules containing this pattern to identify the source"
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
        regex::Regex::new(pat)?;
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
}
