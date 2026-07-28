# Operator Roles

> **Operator Guide** — This section is for administrators who deploy and run Akāmu. It covers configuration, account management, certificate issuance policies, and operational concerns. If you are building an ACME client or integrating with the API, see the [API Reference](../client/protocol.md). If you are contributing to Akāmu itself, see the [Implementation Guide](../developer/architecture.md).

Akamu's admin API uses role-based access control to enforce least privilege and
separation of duties. Every admin request is authenticated, and every operator
has exactly one role. The role determines which endpoints the operator may call.
Roles are assigned at operator creation time and can be changed later by an
`administrator`.

Understanding the roles before provisioning operators is important: a
mis-scoped operator can either have too much access (a security risk) or too
little (causing operational failures).

## Role hierarchy

The four roles form a strict access hierarchy. Higher roles have a superset of
the read permissions of lower roles, but lower roles do NOT inherit write
permissions from higher roles.

```
administrator
    |-- ca_operations
    |       |-- ca_ra (read only within own CA scope)
    |               |-- auditor (read only, no CA data)
```

More precisely:

- `administrator` can call every endpoint.
- `ca_operations` can call everything `administrator` can except operator
  management, server config reads, and profile write operations.
- `ca_ra` is a scoped RA role. It can do a subset of `ca_operations` reads but
  only within its assigned CA, and can revoke and issue EAB keys. It cannot see
  other CAs or perform any CA infrastructure operations.
- `auditor` is read-only and cannot perform any write operations.

## Per-role reference

### `administrator`

The `administrator` role is for PKI administrators who need full control over
the server. Assign it to the smallest possible number of humans and avoid using
it for automated service accounts.

**Key capabilities:**
- All endpoints without restriction.
- Create, update, activate, deactivate, and unlock operators.
- Read and write certificate profiles.
- Read server configuration.
- Manage EAB keys (create and delete).
- Revoke certificates from any CA.
- Force CRL regeneration for any CA or all CAs.
- Cross-sign CAs.
- Manage RFC 9115 delegation objects.
- Query and force MTC transparency log operations (checkpoints, landmarks).
- Deactivate ACME accounts.
- Query the audit log.

**Key restrictions:**
- None. This role has full access.

**CA scope (optional):** An `administrator` operator can be assigned a `ca_id`
scope.  When scoped, the administrator's visibility of policy rules is limited
to rules matching the assigned CA.  An unscoped `administrator` has server-wide
access to all endpoints.

**Typical use case:** A human PKI administrator who needs to bootstrap the
system, manage other operators, update certificate profiles, or respond to a
security incident that requires account deactivation or forced revocation.

**Example:**

```bash
akamuctl operator add \
    --name alice \
    --role administrator \
    --cert-file /etc/akamu/alice-client.pem
```

---

### `ca_operations`

The `ca_operations` role is for automated CA infrastructure processes and
operations staff who manage the certificate lifecycle but do not need to manage
operators or read the server configuration.

**Key capabilities:**
- List and view CAs and their certificates.
- Download CA certificates.
- Force CRL regeneration (global and per-CA).
- Cross-sign CAs.
- List, view, and download issued certificates.
- Create and delete EAB keys.
- Revoke certificates from any CA.
- Manage RFC 9115 delegation objects (create, update, delete).
- Query and force MTC transparency log operations (checkpoints, landmarks).
- Manage ACME account profile grants (set but not clear).
- View accounts, orders, profiles, EAB keys, stats.
- Query the audit log.

**Key restrictions:**
- Cannot manage operators (no access to `/admin/operators` endpoints).
- Cannot read server configuration (`GET /admin/config`).
- Cannot write certificate profiles (no `POST`, `PUT`, or `DELETE` on profiles).
- Cannot deactivate ACME accounts.
- Cannot clear account profile grant lists.

**CA scope (optional):** A `ca_operations` operator can be assigned a `ca_id`
scope.  When scoped, the operator's visibility is limited to the assigned CA:
`GET /admin/cas` returns only that CA, CRL/cross-sign operations are restricted
to the scoped CA, and certificate and order queries are automatically filtered.
Unlike `ca_ra`, a `ca_id` scope is **optional** for `ca_operations`; an
unscoped `ca_operations` operator has server-wide access.

**EAB keys and CA scope:** Even a scoped `ca_operations` operator may create
EAB keys.  EAB keys are not bound to any CA — they are used for ACME account
registration which is server-global — so this is intentional.  Only an
`administrator` may set `for_operator_id` when creating an EAB key via
`POST /admin/eab` to assign it to a different operator for web UI login.

**Typical use case:** A CI/CD pipeline that issues EAB keys for new devices, or
an operations team member who manages revocation and CRL generation without
having the ability to create new operators.

**Example:**

```bash
akamuctl operator add \
    --name ci-pipeline \
    --role ca_operations \
    --cert-file /etc/akamu/ci-client.pem
```

---

### `ca_ra`

The `ca_ra` role is for front-line registration authority (RA) staff or
automated RA services that operate on behalf of a single specific CA. This role
is intentionally narrow: it cannot see data from other CAs and cannot perform
any CA infrastructure operations.

**Key capabilities:**
- View EAB keys.
- List and view certificates issued by the scoped CA only.
- Download certificates issued by the scoped CA only.
- Revoke certificates issued by the scoped CA only.
- View accounts and orders (filtered to the scoped CA automatically).
- View profiles, delegations, stats.

**Key restrictions:**
- Cannot create or delete EAB keys (`POST /admin/eab`, `DELETE /admin/eab/{kid}`).
- Cannot list or view CAs (`GET /admin/cas`, `GET /admin/cas/{id}`).
- Cannot see cross-certificates.
- Cannot force CRL regeneration.
- Cannot cross-sign CAs.
- Cannot manage operators.
- Cannot read server configuration.
- Cannot write certificate profiles or delegation objects.
- Cannot manage ACME accounts (deactivate, set/clear profile grants).
- Cannot query the audit log.
- Cannot view or act on certificates from a CA other than its assigned `ca_id`.
- **Requires a `ca_id` scope to be assigned.** An unscoped `ca_ra` operator is
  rejected at every restricted endpoint with `403 Forbidden`.

**Special requirement — `ca_id`:** See [CA scope](#ca-scope) below.

**Typical use case:** A registration authority system at a branch office that
accepts certificate requests for a specific CA (for example, `rsa`), issues EAB
keys for new ACME clients, and revokes certificates when devices are
decommissioned, without having any visibility into the rest of the PKI.

**Example:**

```bash
akamuctl operator add \
    --name branch-ra \
    --role ca_ra \
    --ca-id rsa \
    --cert-file /etc/akamu/branch-ra.pem
```

---

### `auditor`

The `auditor` role is for security auditors, compliance officers, and monitoring
systems that need read access to the server's operational data but must never be
able to make changes.

**Key capabilities:**
- Query the audit event log (`GET /admin/audit`).
- Query MTC transparency log state (tree size, root, landmarks, proofs, checkpoint).
- List and view issued certificates (across all CAs).
- List and view EAB keys.
- List and view accounts, orders, and profiles.
- View delegations.
- View cross-certificates.
- View server statistics.

**Key restrictions:**
- No write operations at all.
- Cannot view CA details or CA certificates.
- Cannot download certificate content (PEM/DER).
- Cannot view server configuration.
- Cannot manage operators.

**CA scope (optional):** An `auditor` operator can be assigned a `ca_id` scope.
When scoped, the auditor only sees policy rules that match the assigned CA.  An
unscoped `auditor` sees all policy rules.

**Typical use case:** A security operations center tool that polls the audit log
for anomalies, or a compliance dashboard that tracks certificate issuance counts
and expiry windows.

**Example:**

```bash
akamuctl operator add \
    --name soc-monitor \
    --role auditor \
    --gssapi-principal soc-svc@EXAMPLE.COM
```

## Permission matrix

The table below is the authoritative route-by-role matrix derived from the
server source code. `Y` means the role is permitted. Where `ca_ra` is permitted
on a cert or account endpoint, the server automatically enforces the CA scope
filter — the operator only sees data belonging to its assigned CA.

| Method | Path | administrator | ca_operations | ca_ra | auditor |
|--------|------|:---:|:---:|:---:|:---:|
| `POST` | `/admin/session` | Y | Y | Y | Y |
| `DELETE` | `/admin/session` | Y | Y | Y | Y |
| `GET` | `/admin/operators` | Y | | | |
| `POST` | `/admin/operators` | Y | | | |
| `GET` | `/admin/operators/{id}` | Y | | | |
| `PUT` | `/admin/operators/{id}` | Y | | | |
| `PATCH` | `/admin/operators/{id}` | Y | | | |
| `POST` | `/admin/operators/{id}/unlock` | Y | | | |
| `GET` | `/admin/audit` | Y | | | Y |
| `GET` | `/admin/profiles` | Y | Y | Y | Y |
| `GET` | `/admin/profiles/{id}` | Y | Y | Y | Y |
| `POST` | `/admin/profiles` | Y | | | |
| `PUT` | `/admin/profiles/{id}` | Y | | | |
| `DELETE` | `/admin/profiles/{id}` | Y | | | |
| `GET` | `/admin/accounts` | Y | Y | Y | Y |
| `GET` | `/admin/account/{id}` | Y | Y | Y | Y |
| `POST` | `/admin/account/{id}/deactivate` | Y | | | |
| `GET` | `/admin/account/{id}/profile-grants` | Y | Y | Y | Y |
| `PUT` | `/admin/account/{id}/profile-grants` | Y | Y | | |
| `DELETE` | `/admin/account/{id}/profile-grants` | Y | | | |
| `GET` | `/admin/certs` | Y | Y | Y (scoped) | Y |
| `GET` | `/admin/certs/{id}` | Y | Y | Y (scoped) | Y |
| `GET` | `/admin/certs/{id}/download` | Y | Y | Y (scoped) | |
| `POST` | `/admin/eab` | Y | Y | | |
| `GET` | `/admin/eab/{kid}` | Y | Y | Y | Y |
| `DELETE` | `/admin/eab/{kid}` | Y | Y | | |
| `GET` | `/admin/eab` | Y | Y | Y | Y |
| `GET` | `/admin/orders` | Y | Y | Y (scoped) | Y |
| `GET` | `/admin/orders/{id}` | Y | Y | Y | Y |
| `GET` | `/admin/config` | Y | | | |
| `POST` | `/admin/crl/force` | Y | Y | | |
| `POST` | `/admin/revoke` | Y | Y | Y (scoped) | |
| `GET` | `/admin/stats` | Y | Y | Y | Y |
| `GET` | `/admin/cas` | Y | Y | | |
| `GET` | `/admin/cas/{id}` | Y | Y | | |
| `GET` | `/admin/cas/{id}/cert` | Y | Y | | |
| `POST` | `/admin/ca/{id}/crl/force` | Y | Y | | |
| `POST` | `/admin/ca/{id}/cross-sign` | Y | Y | | |
| `GET` | `/admin/cross-certs` | Y | Y | | Y |
| `GET` | `/admin/cross-certs/{id}` | Y | Y | | Y |
| `GET` | `/admin/delegations` | Y | Y | Y | Y |
| `POST` | `/admin/delegations` | Y | Y | | |
| `GET` | `/admin/delegations/{id}` | Y | Y | Y | Y |
| `PUT` | `/admin/delegations/{id}` | Y | Y | | |
| `DELETE` | `/admin/delegations/{id}` | Y | Y | | |
| `GET` | `/admin/mtc/tree-size` | Y | Y | | Y |
| `GET` | `/admin/mtc/root` | Y | Y | | Y |
| `GET` | `/admin/mtc/landmarks` | Y | Y | | Y |
| `GET` | `/admin/mtc/landmark-list` | Y | Y | | Y |
| `GET` | `/admin/mtc/landmarks/{seq}/cert` | Y | Y | | |
| `GET` | `/admin/mtc/landmarks/{seq}/cert-details` | Y | Y | | Y |
| `GET` | `/admin/mtc/inclusion-proof/{cert_id}` | Y | Y | | Y |
| `GET` | `/admin/mtc/standalone/{cert_id}` | Y | Y | | |
| `GET` | `/admin/mtc/consistency-proof` | Y | Y | | Y |
| `GET` | `/admin/mtc/subtree-root` | Y | Y | | Y |
| `GET` | `/admin/mtc/revoked-ranges` | Y | Y | | Y |
| `GET` | `/admin/mtc/checkpoint` | Y | Y | | Y |
| `GET` | `/admin/mtc/cosignature` | Y | Y | | Y |
| `POST` | `/admin/ca/{id}/mtc/force-checkpoint` | Y | Y | | |
| `POST` | `/admin/ca/{id}/mtc/force-landmark` | Y | Y | | |
| `GET` | `/admin/policy/scopes` | Y | Y | | Y |
| `GET` | `/admin/policy/rules` | Y | Y | | Y |
| `GET` | `/admin/policy/rules/{id}` | Y | Y | | Y |
| `POST` | `/admin/policy/rules` | Y | | | |
| `PUT` | `/admin/policy/rules/{id}` | Y | | | |
| `DELETE` | `/admin/policy/rules/{id}` | Y | | | |

**Note on `ca_ra` scoping:** When `ca_ra` is listed as permitted on a cert,
account, or order endpoint, the server silently overrides any `ca_id` query
parameter the operator supplies and substitutes the operator's assigned `ca_id`.
An unscoped `ca_ra` (one with an empty `ca_id`) is rejected at all such
endpoints with `403 Forbidden`.

## Creating operators

All operator creation requires the `administrator` role.

### Create an mTLS operator

```bash
# administrator — full access human admin
akamuctl operator add \
    --name alice \
    --role administrator \
    --cert-file /etc/akamu/alice-client.pem

# ca_operations — automated CA pipeline
akamuctl operator add \
    --name ca-pipeline \
    --role ca_operations \
    --cert-file /etc/akamu/pipeline-client.pem

# ca_ra — scoped RA for the 'rsa' CA
akamuctl operator add \
    --name branch-ra \
    --role ca_ra \
    --ca-id rsa \
    --cert-file /etc/akamu/branch-ra.pem

# administrator scoped to a single CA for policy management
akamuctl operator add \
    --name ca-admin \
    --role administrator \
    --ca-id prod \
    --cert-file /etc/akamu/ca-admin.pem

# auditor — read-only monitoring
akamuctl operator add \
    --name soc-monitor \
    --role auditor \
    --cert-file /etc/akamu/soc-monitor.pem
```

The `--cert-file` flag accepts a PEM file. `akamuctl` computes the SHA-256
fingerprint of the DER-encoded leaf certificate locally and sends only the
fingerprint to the server. The private key never leaves the operator's machine.

### Create a GSSAPI/Kerberos operator

```bash
akamuctl operator add \
    --name bob \
    --role auditor \
    --gssapi-principal bob@EXAMPLE.COM
```

### Dual-credential operator

An operator can authenticate by either mTLS or GSSAPI by supplying both
credentials at creation time:

```bash
akamuctl operator add \
    --name carol \
    --role ca_operations \
    --cert-file /etc/akamu/carol-client.pem \
    --gssapi-principal carol@EXAMPLE.COM
```

### Change an operator's role

```bash
# Promote an auditor to ca_operations
akamuctl operator update 4 --role ca_operations

# Assign a ca_ra operator to a different CA
akamuctl operator update 5 --role ca_ra --ca-id ec
```

When a role or CA scope changes, all active sessions for that operator are
invalidated immediately.

## Choosing a role

Use this guide to decide which role to assign:

| Scenario | Role |
|----------|------|
| Full PKI administrator who bootstraps the system and manages operators | `administrator` |
| CI/CD pipeline that provisions EAB keys for new devices | `ca_operations` |
| Automated system that revokes certificates across all CAs | `ca_operations` |
| Branch RA service that views EAB keys and revokes certs for one CA | `ca_ra` |
| External ACME client (NDC) that registers via a specific CA | `ca_ra` |
| Security operations center monitoring tool | `auditor` |
| Compliance dashboard that tracks issuance counts | `auditor` |
| Human auditor reviewing the audit log for a compliance audit | `auditor` |
| Administrator managing policy rules for a specific CA only | `administrator` (with `--ca-id`) |
| Viewing policy rules across all CAs (read-only) | `auditor` or `ca_operations` |

When in doubt, start with `auditor` and escalate only when a required operation
fails. The server returns `403 Forbidden` with a clear error message when a role
is insufficient for a requested endpoint.

## CA scope

All operator roles support an optional `ca_id` scope that restricts the
operator to data belonging to a single CA.  The `ca_id` must be the ID string
of a CA configured in the server's `[ca.*]` sections (for example, `"rsa"` or
`"ec"`).  For `ca_ra`, a CA scope is mandatory; for all other roles it is
optional (empty = server-wide).

**Why `ca_ra` requires it:** Without a CA scope, a `ca_ra` operator would have
server-wide revocation and EAB-issuance authority, which defeats the purpose of
the role. The server enforces this: any `ca_ra` operator that reaches a
restricted endpoint with an empty `ca_id` receives `403 Forbidden`.

**What it controls:**

- `GET /admin/certs`: the `ca_id` query parameter is ignored; only certs from
  the scoped CA are returned.
- `GET /admin/certs/{id}/download`: the server returns `404 Not Found` if the
  certificate belongs to a different CA.
- `POST /admin/revoke`: `403 Forbidden` if the target certificate belongs to a
  different CA.
- `GET /admin/accounts` and `GET /admin/orders`: automatically filtered to the
  scoped CA.

**Assigning a CA scope at creation:**

```bash
akamuctl operator add \
    --name branch-ra \
    --role ca_ra \
    --ca-id rsa \
    --cert-file /etc/akamu/branch-ra.pem
```

**Changing the CA scope after creation:**

```bash
# Move the operator to a different CA
akamuctl operator update 5 --role ca_ra --ca-id ec
```

The `--ca-id` flag is accepted for all roles.  For `ca_ra`, it is mandatory;
for all other roles, it is optional (empty = server-wide).  CA-scoped operators
of any role see only policy rules that match their assigned CA.

**Revoking without a scope:** If you need to create a `ca_ra` operator without
a CA scope initially and assign the scope in a second step, use `operator add`
followed by `operator update`:

```bash
# Step 1: create with scope (required at creation if role is ca_ra)
akamuctl operator add --name branch-ra --role ca_ra --ca-id rsa \
    --cert-file /etc/akamu/branch-ra.pem

# Later: reassign to a different CA
akamuctl operator update 7 --role ca_ra --ca-id ec
```

There is no way to store a `ca_ra` operator with an empty `ca_id`; the server
rejects such a request at `POST /admin/operators` with `400 Bad Request`.

## Authentication methods

Operators authenticate to the admin API using one or more of three mechanisms:

- **mTLS client certificate** — the operator presents a TLS client certificate
  during the handshake. The server looks up the SHA-256 fingerprint of the
  DER-encoded leaf in the `operators` table. This is the recommended mechanism
  for automated service accounts.

- **GSSAPI/Kerberos** — the operator sends an `Authorization: Negotiate` header
  with a SPNEGO token. The server validates the token and looks up the extracted
  principal in the `operators` table. This is the recommended mechanism for
  human operators in organizations with Kerberos infrastructure.

- **Bearer session token** — after a successful mTLS or GSSAPI login, the
  returned token is used for subsequent requests. Session tokens idle-expire
  after `session_ttl_secs` (default one hour).

An operator record can hold both a `cert_fingerprint` and a `gssapi_principal`,
allowing the same logical operator to authenticate by either method.

For configuration details and security notes on GSSAPI, see
[EAB and Kerberos Authentication](eab-kerberos.md). For the full authentication
protocol including session token expiry and the bounded session store, see
[Admin API and Operator Management](admin-api.md).
