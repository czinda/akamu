# Security Findings — Akāmu ACME Server

**Audit date:** 2026-05-03  **Iterations:** 15  **Method:** STRIDE + OWASP Top 10

---

## MEDIUM findings (5)

### F-1: FAU_ARP.1 security alarm is dead code — `SecurityViolation` never emitted

**File:** `src/audit.rs:63`  
**OWASP:** A09 — Security Logging and Monitoring Failures  
**STRIDE:** Repudiation  

`AuditEventType::SecurityViolation` exists and the rolling-window alarm logic in
`src/audit.rs:357–386` counts these events and halts the server when the threshold is
exceeded.  However, no production code path ever calls
`state.record_audit(AuditEvent::*(...::SecurityViolation))`.  The alarm counter
stays at zero; FAU_ARP.1 can never fire.

**Fix:** Emit `SecurityViolation` from the appropriate detection points.
Candidates: EAB HMAC failure after N attempts per IP, JWS signature failure burst,
admin credential rejection burst.

---

### F-2: EAB key consumption — TOCTOU race allows double account creation

**Files:** `src/routes/account.rs:120`, `src/db/eab.rs:113`  
**OWASP:** A04 — Insecure Design  
**STRIDE:** Tampering  

The EAB `used_at IS NULL` check at line 120 of `account.rs` reads from the DB
*outside* the write transaction that later calls `mark_used`.  Two concurrent
`POST /acme/new-account` requests sharing the same `kid` + HMAC secret can both
pass the guard, both verify the HMAC, and both insert accounts before either
`mark_used` runs.

`mark_used` is:
```sql
UPDATE eab_keys SET used_at = ? WHERE kid = ?
```
There is no `WHERE used_at IS NULL` guard, so the second update silently overwrites
the first `used_at` timestamp without returning an error.  Result: two accounts
created from one EAB key.

**Fix:**
```sql
UPDATE eab_keys SET used_at = ? WHERE kid = ? AND used_at IS NULL
```
Treat `rows_affected() == 0` as "already consumed" and return a conflict error.
Alternatively, perform the `get_by_kid` *inside* the write transaction using
`SELECT … FOR UPDATE` (Postgres/MariaDB) or `BEGIN IMMEDIATE` (SQLite).

---

### F-3: SSRF via HTTP-01 — initial connection not filtered for private IPs

**Files:** `src/validation/http01.rs:128`, `src/routes/order.rs:357`  
**OWASP:** A10 — Server-Side Request Forgery  
**STRIDE:** Information Disclosure  

`is_blocked_ip` is only called inside `check_redirect_host()`, which runs on
*redirect* responses.  The initial `client.get(uri)` at line 128 of `http01.rs`
goes to the domain/IP literal without any private-address check.

`order.rs:357` creates `http-01` challenges for `"ip"` identifier type:
```rust
"ip" => &["http-01", "tls-alpn-01"],
```
An attacker with a valid ACME account can order a certificate for `192.168.1.1`,
trigger the http-01 challenge, and cause the server to send:
```
GET http://192.168.1.1/.well-known/acme-challenge/<token>
```
directly to an internal host.  The error response can reveal whether the service
responded, and with what HTTP status, enabling internal port scanning.

**Fix:** Before the loop at line 128, resolve the initial host and call
`is_blocked_ip`.  For IP-literal identifiers, call `is_blocked_ip` directly on the
parsed IP before constructing the URL.  Alternatively, refuse `http-01` for all
RFC-1918/loopback/link-local IP identifiers at order creation time.

---

### F-4: Double-certificate race on concurrent order finalization

**Files:** `src/db/orders.rs:129`, `src/routes/finalize.rs:50`  
**OWASP:** A04 — Insecure Design  
**STRIDE:** Tampering  

`finalize_order` fetches the order and checks `status == "ready"` *outside* the
DB write transaction.  Two concurrent finalize requests for the same order can
both pass this check, both sign distinct certificates (different UUIDs and serials),
and both commit.

`set_certificate` at `orders.rs:129`:
```sql
UPDATE orders SET status = 'valid', certificate_id = ?, updated = ? WHERE id = ?
```
has no `WHERE status = 'ready'` guard.  The second write overwrites
`certificate_id`, leaving the first certificate as an unreferenced orphan in
`certificates`.  Both certificates are cryptographically valid and signed by the CA.

**Fix:**
```sql
UPDATE orders SET status = 'valid', certificate_id = ?, updated = ?
WHERE id = ? AND status = 'ready'
```
Treat `rows_affected() == 0` as "order already finalized" and return
`AcmeError::OrderNotReady` or `Conflict`.

---

### F-5: Key-change action emits no audit event

**File:** `src/routes/key_change.rs`  
**OWASP:** A09 — Security Logging and Monitoring Failures  
**STRIDE:** Repudiation  

`POST /acme/key-change` replaces the account's long-term signing key — the most
privileged mutation an ACME account can make.  The handler completes successfully
without calling `state.record_audit(...)`.  There is no `AuditEventType::KeyChange`
variant.

An attacker who gains temporary access to an account and rolls the key leaves no
audit trail.  The only forensic signal would be the absence of subsequent
`AuthJwsOk` events from the original key.

**Fix:** Add `AuditEventType::KeyChange` to `src/audit.rs` and emit it on success
in `key_change.rs`, including the old JWK thumbprint and new JWK thumbprint in
the `detail` field.

---

## LOW findings (3)

### F-6: Internal error detail leaked in HTTP 500 responses

**File:** `src/error.rs:113–126, 232–248`  
**OWASP:** A05 — Security Misconfiguration  
**STRIDE:** Information Disclosure  

`AcmeError::Database(e.to_string())` carries the raw sqlx error string, which
includes table names, column names, SQL fragments, and driver detail.
`AcmeError::Crypto`, `Builder`, `Mtc`, and `Internal` similarly carry internal
messages.  `IntoResponse` at line 239 places `self.to_string()` directly in the
`detail` field of every RFC 7807 error response.

```rust
let body = json!({
    "type": self.acme_type(),
    "status": status.as_u16(),
    "detail": self.to_string(),   // ← leaks internal state for 5xx variants
});
```

**Fix:** For 5xx responses (`status.is_server_error()`), replace `self.to_string()`
with a generic string such as `"internal server error"`.  The full detail is already
logged via `tracing::error!` at line 234 for operators to investigate.

---

### F-7: Read-only admin endpoints accept any authenticated role

**File:** `src/routes/admin.rs:409, 525, 760`  
**OWASP:** A01 — Broken Access Control  
**STRIDE:** Elevation of Privilege  

Three handlers use `let _ = operator; // any role`:
- `get_account_profile_grants` — exposes profile grant assignments for any account
- `get_eab` — lists EAB key metadata (kid, created, used_at, profile_grants)
- `get_stats` — exposes aggregate server statistics

The attack surface map specifies `Admin` or `Auditor` roles for these endpoints.
All three still require a valid admin session (authentication is enforced by
`OperatorContext`), but any role — including `CaRa` or `CaOperations` — can read
EAB metadata or profile grants.

**Fix (optional):** Add `require_role!(operator, state, Administrator | Auditor)` or
`require_role!(operator, state, Administrator | CaOperations | Auditor)` to each
handler, depending on intended policy.  Update the attack surface map to document
the policy decision if "any authenticated admin" is intentional.

---

### F-8: `max_body_bytes = 0` disables all body limits instead of using axum default

**File:** `src/routes/mod.rs:149`  
**OWASP:** A04 — Insecure Design  
**STRIDE:** Denial of Service  

The comment at line 61 says:
> `max_body_bytes = 0` means "use axum's built-in default (2 MiB)"

But the code at line 149 calls `DefaultBodyLimit::disable()` when `max_body == 0`,
which *removes* the shared body limit rather than keeping axum's 2 MiB default.
Since `default_max_body_bytes()` returns `65536`, the default deployment is
unaffected.  An operator who explicitly sets `max_body_bytes = 0` expecting the
axum default would instead get unlimited body reads.

**Fix:** Either document that `0` means "unlimited" (and update the comment) or
treat `0` as "use axum default" by using
`DefaultBodyLimit::max(2 * 1024 * 1024)` when `max_body == 0`.

---

## INFO / Clean vectors (7)

| Vector | Result |
|--------|--------|
| JWS algorithm confusion (A07/S) | CLEAN — SPKI from DB, no "none" path, crypto lib rejects cross-type |
| IDOR on account/order/authz/cert (A01/E) | CLEAN — UUID v4 IDs, account_id ownership checked everywhere |
| EAB HMAC algorithm selection (A02/T) | CLEAN — HS256/384/512 only, constant-time, all claims verified |
| SQL injection (A03/T) | CLEAN — QueryBuilder: static push + parameterised push_bind; no user data in raw SQL |
| Session token entropy (A02/T) | CLEAN — 32-byte getrandom, 256-bit entropy, subtle::ConstantTimeEq |
| PII in logs (A09/I) | CLEAN — contacts/HMAC keys/SPKIs not logged; thumbprints used as audit principals |
| Dependency CVEs (A06) | UNKNOWN — cargo-audit not installed; recommend CI integration |
