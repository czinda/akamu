# akamuctl — Admin CLI

`akamuctl` is the command-line tool for administering a running akamu server or
cosigner daemon.  It talks to the admin REST API over HTTPS with mTLS or session
token authentication and prints results as a human-readable table or as JSON.

## Installation

Build from source alongside the rest of the workspace:

```bash
cargo build -p akamuctl --release
```

The binary is placed at `target/release/akamuctl`.

## Quick start

```bash
# Log in (authenticates via mTLS and caches a session token)
akamuctl --server-url https://admin.example.com:9443 \
          --ca-cert /etc/akamu/admin-ca.pem \
          --cert    /etc/akamu/operator.pem \
          --key     /etc/akamu/operator.key \
          login

# List operators
akamuctl operator list

# Add an EAB key
akamuctl eab add --kid acmeclient-001 \
                 --hmac-key c2VjcmV0LWhtYWMta2V5LWJ1ZmZlcg

# Query audit log for the last 20 failed events
akamuctl audit --outcome failure --limit 20
```

After `login` succeeds, the session token is written to
`~/.config/akamu/session.json` and reused automatically for subsequent
commands until it expires (default 1 hour).

## Configuration file

`akamuctl` reads `~/.config/akamu/akamuctl.toml` if it exists.
Command-line flags take precedence over the config file.

### Full example

```toml
[server]
url       = "https://admin.example.com:9443"
ca_cert   = "/etc/akamu/admin-ca.pem"
cert_file = "/etc/akamu/operator.pem"
key_file  = "/etc/akamu/operator.key"

[cosigner]
url       = "https://cosigner.example.com:9444"
ca_cert   = "/etc/akamu/cosigner-ca.pem"
cert_file = "/etc/akamu/operator.pem"
key_file  = "/etc/akamu/operator.key"
```

### `[server]`

| Key | Description |
|-----|-------------|
| `url` | Admin listener URL (e.g. `https://127.0.0.1:9443`). |
| `ca_cert` | PEM CA certificate used to verify the server's TLS certificate. When absent, the system trust store is used. |
| `cert_file` | PEM client certificate presented for mTLS authentication. |
| `key_file` | PEM private key matching `cert_file`. |

### `[cosigner]`

Same fields as `[server]`, applied when running `cosigner` subcommands.
Falls back to `[server]` values for any field that is absent.

## Global flags

| Flag | Short | Description |
|------|-------|-------------|
| `--config FILE` | `-c` | Path to the `akamuctl.toml` config file. |
| `--server-url URL` | | Admin listener URL (overrides config). |
| `--ca-cert FILE` | | CA certificate for server TLS verification. |
| `--cert FILE` | | mTLS client certificate. |
| `--key FILE` | | mTLS client private key. |
| `--output FORMAT` | `-o` | Output format: `table` (default) or `json`. |

## Session management

### `login`

Authenticate with the server and save a session token:

```bash
akamuctl login
```

Presents the configured mTLS client certificate to `POST /admin/session`.
On success the returned token is saved to `~/.config/akamu/session.json`
with mode `0600` (user-readable only).  Subsequent commands reuse this token
without re-presenting the client certificate.  A 30-second expiry margin
triggers automatic re-authentication before the server would reject the token.

### `logout`

Invalidate the cached session token:

```bash
akamuctl logout
```

Calls `DELETE /admin/session` on the server and clears the local cache.

### `stats`

Print live server counters:

```bash
akamuctl stats
```

Returns server version, uptime, and totals for accounts, certificates, EAB keys,
and audit events.  All authenticated roles may call this command.

## Operator management

Operator management requires the `administrator` role.

### `operator list`

List all operators (active and inactive):

```bash
akamuctl operator list
```

### `operator add`

Register a new operator.  At least one of `--cert-file` or `--gssapi-principal`
must be provided.

```bash
# mTLS operator: extract fingerprint from the certificate file
akamuctl operator add \
    --name alice \
    --role administrator \
    --cert-file /etc/akamu/alice-client.pem

# GSSAPI/Kerberos operator
akamuctl operator add \
    --name bob \
    --role auditor \
    --gssapi-principal bob@EXAMPLE.COM
```

Accepted roles: `administrator`, `ca_operations`, `ca_ra`, `auditor`.

When `--cert-file` is given, `akamuctl` computes the SHA-256 fingerprint of the
DER-encoded certificate leaf locally and sends only the fingerprint to the server.
The private key never leaves the operator's machine.

### `operator remove`

Deactivate an operator (the operator record is retained for audit purposes):

```bash
akamuctl operator remove 3
```

The numeric argument is the operator `id` shown by `operator list`.  Deactivating
an operator immediately invalidates any active sessions for that operator.

### `operator activate`

Re-enable a previously deactivated operator:

```bash
akamuctl operator activate 3
```

## EAB key management

### `eab list`

List all EAB keys:

```bash
akamuctl eab list          # all keys
akamuctl eab list --used   # only consumed keys
akamuctl eab list --unused # only unconsumed keys
```

All authenticated roles may list EAB keys.

### `eab add`

Provision a new EAB key, optionally restricting it to specific certificate
profiles:

```bash
# Auto-generate kid and HMAC key on the server
akamuctl eab add

# Provide explicit values
akamuctl eab add --kid my-device-001 \
                 --hmac-key c2VjcmV0LWhtYWMta2V5LWJ1ZmZlcg

# Restrict to named profiles
akamuctl eab add --kid my-device-001 \
                 --profile tlsserver \
                 --profile codesigning
```

Requires the `administrator`, `ca_operations`, or `ca_ra` role.

### `eab remove`

Deactivate an EAB key before it has been used:

```bash
akamuctl eab remove my-device-001
```

Requires the `administrator` or `ca_operations` role.

## Certificate operations

### `cert list`

Search issued certificates:

```bash
akamuctl cert list
akamuctl cert list --serial 0a1b2c3d --limit 5
akamuctl cert list --subject "CN=device.example.com" \
                   --status active --limit 50
akamuctl cert list --after 2026-01-01T00:00:00Z \
                   --before 2026-06-01T00:00:00Z
```

| Flag | Description |
|------|-------------|
| `--serial HEX` | Filter by hex serial number. |
| `--subject TEXT` | Filter by subject distinguished name substring. |
| `--after RFC3339` | Issued at or after this timestamp. |
| `--before RFC3339` | Issued at or before this timestamp. |
| `--status VALUE` | `active` or `revoked`. |
| `--limit N` | Maximum results (default 20). |
| `--offset N` | Pagination offset (default 0). |

Requires the `administrator`, `ca_operations`, or `auditor` role.

### `revoke`

Revoke a certificate by its internal ID:

```bash
akamuctl revoke <cert-id>
akamuctl revoke <cert-id> --reason 1   # keyCompromise
```

The revocation reason code follows RFC 5280 §5.3.1 (0 = unspecified,
1 = keyCompromise, 3 = affiliationChanged, 4 = superseded, etc.).
Revoking immediately invalidates the CRL cache so the next CRL request
reflects the change.

Requires the `administrator`, `ca_operations`, or `ca_ra` role.

### `crl-force`

Force immediate CRL regeneration without waiting for the next scheduled update:

```bash
akamuctl crl-force
```

Requires the `administrator` or `ca_operations` role.

## Account profile grants

Profile grants restrict which certificate profiles an ACME account may request.
When an account has no grants configured (the default), it may request any profile.

### `account grants get`

Show current profile grants for an account:

```bash
akamuctl account grants get <account-uuid>
```

### `account grants set`

Replace all profile grants for an account:

```bash
akamuctl account grants set <account-uuid> \
    --profile tlsserver \
    --profile codesigning
```

Requires the `administrator` or `ca_operations` role.

### `account grants clear`

Remove all profile restrictions (restore unrestricted access):

```bash
akamuctl account grants clear <account-uuid>
```

Requires the `administrator` role.

## Audit log

### `audit`

Query the structured audit event log:

```bash
akamuctl audit                                # most recent 100 events
akamuctl audit --type cert.issue              # certificate issuance events
akamuctl audit --outcome failure --limit 50   # failed operations
akamuctl audit --subject <account-uuid>       # events for a specific account
akamuctl audit --from 2026-05-01T00:00:00Z \
               --until 2026-05-02T00:00:00Z   # time range
```

| Flag | Description |
|------|-------------|
| `--type TYPE` | Filter by event type string (see [event types](#audit-event-types)). |
| `--subject ID` | Filter by subject (JWK thumbprint, account UUID, certificate serial, etc.). |
| `--from RFC3339` | Events at or after this timestamp. |
| `--until RFC3339` | Events at or before this timestamp. |
| `--outcome VALUE` | `success` or `failure`. |
| `--limit N` | Maximum results (default 100). |
| `--offset N` | Pagination offset (default 0). |

Results are returned newest-first.

Requires the `administrator` or `auditor` role.

### Audit event types

| Event type | Description |
|------------|-------------|
| `ca.start` | Server startup. |
| `ca.stop` | Server shutdown. |
| `account.create` | New ACME account registered. |
| `account.deactivate` | Account deactivated. |
| `order.create` | New certificate order created. |
| `order.finalize` | Order finalization attempted. |
| `cert.issue` | Certificate issued. |
| `cert.revoke` | Certificate revoked. |
| `crl.generate` | CRL generated. |
| `key.generate` | Signing or CA key generated. |
| `key.load` | Signing or CA key loaded from disk. |
| `auth.jws.ok` | ACME JWS request authentication succeeded. |
| `auth.jws.fail` | ACME JWS request authentication failed. |
| `auth.challenge.ok` | ACME challenge validation succeeded. |
| `auth.challenge.fail` | ACME challenge validation failed. |
| `eab.use` | EAB key consumed by account registration. |
| `eab.reject` | EAB key rejected (unknown, used, or MAC mismatch). |
| `admin.login` | Operator authenticated to the admin API. |
| `admin.logout` | Operator session invalidated. |
| `admin.action` | Administrative action performed (operator CRUD, EAB management, etc.). |
| `security.violation` | Security anomaly detected. |

## Cosigner administration

`akamuctl` can also query the admin interface of an `akamu-cosigner` daemon.
Configure the cosigner connection in `[cosigner]` in the config file, or pass
`--server-url` and TLS flags directly.

### `cosigner status`

Check whether the cosigner is running:

```bash
akamuctl cosigner status
```

Returns `{"status":"ok","uptime_secs":…}`.

### `cosigner stats`

Show cosigner signing statistics:

```bash
akamuctl cosigner stats
```

Returns uptime, total checkpoints signed, and the timestamp of the most recent
signing operation.

## Output formats

By default, `akamuctl` prints results as aligned tables.  Use `--output json`
(or `-o json`) to get pretty-printed JSON suitable for scripting:

```bash
akamuctl -o json operator list | jq '.operators[] | select(.role == "auditor")'
```

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | Success. |
| 1 | General error (HTTP, network, JSON parse failure). |
| 2 | Authentication error (session expired, certificate rejected). |
| 3 | Configuration error (missing or invalid config file or flag). |
