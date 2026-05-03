# Audit Overview

**Project:** Akāmu ACME Server  
**Date:** 2026-05-03  
**Method:** 15-iteration STRIDE + OWASP Top 10 bounded loop  
**Scope:** Entire Rust workspace (src/, crates/, migrations/)

## Summary

| Severity | Count |
|----------|-------|
| Critical | 0 |
| High | 0 |
| Medium | 5 |
| Low | 3 |
| Info/Unknown | 1 |
| Clean vectors | 7 |

No critical or high findings.  The codebase demonstrates strong security fundamentals:
UUID v4 identifiers throughout, parameterised SQL everywhere, constant-time session
token comparison, CSPRNG-backed token generation, and comprehensive JWS/EAB
verification.

The five MEDIUM findings cluster into two themes:

1. **Race conditions** — EAB TOCTOU (F-2) and concurrent finalization (F-4) both
   follow the same pattern: a check outside a transaction that should be inside it.
   Both are one-line SQL fixes.

2. **Audit gaps** — FAU_ARP.1 alarm is dead (F-1) and key-change is unlogged (F-5).
   The audit infrastructure is solid; these are missing callsites, not architectural
   problems.

The SSRF finding (F-3) is genuine but requires a valid ACME account and an unusual
order (IP identifier with http-01).  The fix is straightforward — extend the
existing `is_blocked_ip` check to the initial connection.

## Files Produced

| File | Contents |
|------|----------|
| findings.md | Detailed write-up of all 8 findings |
| owasp-coverage.md | OWASP Top 10 check-off table |
| recommendations.md | Prioritised fix list with code pointers |
| attack-surface-map.md | All ACME + Admin entry points, data flows, abuse paths |
| threat-model.md | Assets, trust boundaries, STRIDE matrix |
| security-audit-results.tsv | Machine-readable per-iteration result log |
