# Threat Model — Akāmu ACME Server

**Generated:** 2026-05-03  **Scope:** Entire codebase

## Assets

| Asset | Location | Priority |
|-------|----------|----------|
| CA private key | Disk (configurable path) | Critical |
| Issued certificates + private keys of subscribers | DB (certs table) | Critical |
| Admin operator session tokens | In-memory HashMap | Critical |
| Admin operator cert fingerprints / GSSAPI principals | DB (operators table) | Critical |
| EAB HMAC keys | DB (eab_keys table) + config (eab_master_secret) | Critical |
| Account public keys (JWK thumbprints) | DB (accounts table) | High |
| ACME nonces | In-memory + DB (nonces table) | High |
| Audit log | DB (audit_events table) | High |
| MTC log + signing key | Disk | High |
| DNS/HTTP challenge material | External (transient) | Medium |
| DB connection credentials | Config file / env | High |

## Trust Boundaries

```
Internet clients ←→ ACME listener (public, JWS-authenticated)
Admin clients    ←→ Admin listener (mTLS + GSSAPI + Bearer token)
ACME server      ←→ SQLite/Postgres/MariaDB (internal network)
ACME server      ←→ Challenge target (outbound HTTP/DNS validation)
ACME server      ←→ DNS resolver (outbound DNS for CAA + dns-01)
Cosigner         ←→ Admin listener of main server (mTLS)
akamuctl CLI     ←→ Admin listener (Bearer token)
```

## STRIDE Threat Matrix

| Asset | Spoofing | Tampering | Repudiation | Info Disclosure | DoS | Elevation |
|-------|----------|-----------|-------------|-----------------|-----|-----------|
| JWS signatures | JWK/kid confusion, algorithm downgrade | Replayed JWS | No audit if sig fails silently | Error detail leaks | Nonce exhaustion | Account takeover via key confusion |
| Admin sessions | Fake Bearer token | — | Admin actions without audit trail? | Token in logs? | — | RBAC bypass |
| EAB keys | Replay used key | Tamper HMAC | — | Leaked via error | — | Bypass EAB requirement |
| CA key | — | Sign arbitrary cert | — | Exposed path in error | — | Any cert signed |
| DB queries | — | SQL injection | — | DB error detail in response | — | Data exfiltration |
| Challenge validation | DNS spoofing (rebinding) | SSRF via HTTP-01 target | — | Internal net scan | — | Cert for domain not owned |
| Audit log | — | Delete/overflow | Overflow drops events | — | FAU_STG.4 overflow | Erase evidence |
| Session tokens | Brute force? | — | — | Token entropy | — | Admin impersonation |
