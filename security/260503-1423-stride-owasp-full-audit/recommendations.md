# Remediation Recommendations

Priority order: MEDIUM before LOW; quickest fixes first within each band.

## MEDIUM — Fix before next production deploy

### R-1: Add `WHERE used_at IS NULL` to EAB mark_used (F-2)
`src/db/eab.rs:113` — one-line SQL change + treat rows_affected==0 as conflict.
Prevents double account creation from a single EAB key under concurrent load.

### R-2: Add `WHERE status = 'ready'` to set_certificate (F-4)
`src/db/orders.rs:129` — one-line SQL change + map rows_affected==0 to
`AcmeError::Conflict("order already finalized")`.
Prevents double certificate issuance from concurrent finalize requests.

### R-3: Guard HTTP-01 initial connection against private IPs (F-3)
`src/validation/http01.rs` — before the redirect loop, resolve the initial URI host
and call `is_blocked_ip`.  For IP-literal identifiers, call it directly.
Prevents ACME server from probing internal HTTP services.

### R-4: Add KeyChange audit event (F-5)
`src/audit.rs` — add `AuditEventType::KeyChange` variant.
`src/routes/key_change.rs` — emit success event with old/new thumbprints in detail.
Provides repudiation trail for the most privileged account mutation.

### R-5: Emit SecurityViolation from detection points (F-1)
Decide which events should trigger `SecurityViolation` (e.g. EAB HMAC failure burst,
JWS failure burst, admin auth failure burst).  Wire them up so FAU_ARP.1 can fire.

## LOW — Fix within next sprint

### R-6: Suppress internal detail in 500 error responses (F-6)
`src/error.rs:IntoResponse` — when `status.is_server_error()`, set
`detail = "internal server error"` instead of `self.to_string()`.
Full detail already logged via `tracing::error!`.

### R-7: Add role restrictions to read-only admin endpoints (F-7)
`src/routes/admin.rs:409,525,760` — add `require_role!` or document "any role"
as intentional policy in the attack surface map.

### R-8: Fix body limit comment / behaviour for max_body_bytes = 0 (F-8)
`src/routes/mod.rs:149` — either change `DefaultBodyLimit::disable()` to
`DefaultBodyLimit::max(2 * 1024 * 1024)` for the zero case, or update the comment
to say `0` means "unlimited" (and add a warning log).

## INFO — Install cargo-audit in CI

```
cargo install cargo-audit
cargo audit
```
Run on every PR merge.  Consider also `cargo deny` for license + advisory scanning.
