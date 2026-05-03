# Attack Surface Map — Akāmu ACME Server

## ACME Entry Points (public, JWS-authenticated)

| Endpoint | Method | Auth | Risk Areas |
|----------|--------|------|------------|
| /acme/new-account | POST | JWK | Account creation, EAB bypass, ToS bypass |
| /acme/account/{id} | POST | KID | IDOR, deactivation |
| /acme/new-order | POST | KID | Identifier injection, STAR abuse |
| /acme/order/{id} | POST | KID | IDOR |
| /acme/order/{id}/finalize | POST | KID | CSR injection, CAA bypass, profile abuse |
| /acme/authz/{id} | POST | KID | IDOR |
| /acme/challenge/{authz_id}/{chall_id} | POST | KID | SSRF via HTTP-01 callback |
| /acme/certificate/{id} | GET/POST | KID | IDOR on cert download |
| /acme/revoke-cert | POST | JWK/KID | Auth bypass, reason abuse |
| /acme/key-change | POST | JWK+KID | Key rollover abuse |
| /acme/new-nonce | HEAD/GET | None | Nonce exhaustion |
| /acme/directory | GET | None | Info disclosure |

## Admin Entry Points (mTLS + GSSAPI + Bearer)

| Endpoint | Method | Role | Risk Areas |
|----------|--------|------|------------|
| /admin/session | POST | — | Auth bypass, token generation |
| /admin/session | DELETE | Any | Session fixation |
| /admin/operators | GET/POST | Auditor/Admin | Privilege escalation |
| /admin/operators/{id} | PATCH | Admin | Deactivation bypass |
| /admin/accounts/{id}/profile-grants | GET/PUT/DELETE | Admin | Data injection |
| /admin/eab | GET/POST | Admin | EAB key management |
| /admin/eab/{kid} | DELETE | Admin | Race on deletion |
| /admin/audit | GET | Auditor | Log tampering |
| /admin/certs | GET | Auditor | Bulk certificate exposure |
| /admin/crl/force | POST | CA_Operator | DoS via CRL regeneration |
| /admin/revoke | POST | CA_Operator | Unauthorized revocation |
| /admin/stats | GET | Auditor | Info disclosure |

## Data Flows

```
ACME client → POST /acme/new-account → JWS verify → DB lookup → DB insert
ACME client → POST /acme/order/{id}/finalize → CSR validate → CAA lookup → CA sign → DB insert
ACME client → POST /acme/challenge → HTTP-01/DNS-01 probe → external host
Admin client → POST /admin/session → mTLS/GSSAPI/Bearer verify → session create
```

## Abuse Paths

1. **EAB bypass**: Create account without EAB when `external_account_required=true` is misconfigured
2. **Nonce replay**: Reuse a nonce within the replay window
3. **IDOR chain**: GET /acme/certificate/{id} for another account's cert
4. **SSRF via HTTP-01**: Trigger HTTP validation against internal IPs
5. **JWK/KID confusion**: Use JWK on KID-required endpoints or vice versa
6. **CSR SAN injection**: Submit CSR with SANs not in the order identifiers
7. **Profile privilege escalation**: Access profile-restricted endpoints without grants
8. **Admin RBAC bypass**: Call CA_Operator-restricted endpoints as Auditor
9. **Audit overflow attack**: Flood audit log to trigger drop/halt and erase evidence
10. **Race condition finalization**: Submit two concurrent finalizations for same order
