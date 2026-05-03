# OWASP Top 10 Coverage

| Category | Checked | Finding |
|----------|---------|---------|
| A01 Broken Access Control | ✓ | LOW — 3 read-only admin endpoints use any-role (F-7) |
| A02 Cryptographic Failures | ✓ | Clean — JWS, EAB HMAC, session tokens all sound |
| A03 Injection | ✓ | Clean — sqlx QueryBuilder with parameterised binds throughout |
| A04 Insecure Design | ✓ | MEDIUM — EAB TOCTOU (F-2), finalize race (F-4); LOW — body limit (F-8) |
| A05 Security Misconfiguration | ✓ | LOW-MEDIUM — internal error detail in 500 responses (F-6) |
| A06 Vulnerable Components | ⚠ | UNKNOWN — cargo-audit not available; lockfile not scanned |
| A07 Identification / Authentication | ✓ | Clean — JWS algorithm confusion mitigated; session entropy sound |
| A08 Software / Data Integrity | ✓ | Clean — CSR SANs validated against order identifiers; EAB HMAC verified |
| A09 Logging / Monitoring | ✓ | MEDIUM — FAU_ARP.1 dead code (F-1), key-change not audited (F-5) |
| A10 SSRF | ✓ | MEDIUM — HTTP-01 initial connection bypasses is_blocked_ip (F-3) |
