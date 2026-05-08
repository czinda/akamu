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
# Log in via mTLS client certificate (caches a session token)
akamuctl --server-url https://admin.example.com:9443 \
          --ca-cert /etc/akamu/certs/ca.cert.pem \
          --cert    /etc/akamu/certs/operator.cert.pem \
          --key     /etc/akamu/certs/operator.key.pem \
          login

# Log in via Kerberos/GSSAPI (uses the ambient ccache from 'kinit')
akamuctl --server-url https://admin.example.com:9443 login --gssapi

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

Use `akamuctl config generate` to print an annotated template you can save as a
starting point:

```bash
akamuctl config generate > ~/.config/akamu/akamuctl.toml
```

### Full example

```toml
[server]
url            = "https://admin.example.com:9443"
ca_cert        = "/etc/akamu/certs/ca.cert.pem"
cert_file      = "/etc/akamu/certs/operator.cert.pem"
key_file       = "/etc/akamu/certs/operator.key.pem"
# Optional: override the GSSAPI SPN used by 'akamuctl login --gssapi'.
# When absent the SPN is derived automatically as HTTP@<hostname>.
# gssapi_service = "HTTP@admin.example.com"

[cosigner]
url            = "https://cosigner.example.com:9444"
ca_cert        = "/etc/akamu/certs/ca.cert.pem"
cert_file      = "/etc/akamu/certs/operator.cert.pem"
key_file       = "/etc/akamu/certs/operator.key.pem"
# gssapi_service = "HTTP@cosigner.example.com"
```

### `[server]`

| Key | Description |
|-----|-------------|
| `url` | Admin listener URL (e.g. `https://127.0.0.1:9443`). |
| `ca_cert` | PEM CA certificate used to verify the server's TLS certificate. When absent, the system trust store is used. |
| `cert_file` | PEM client certificate presented for mTLS authentication. |
| `key_file` | PEM private key matching `cert_file`. |
| `gssapi_service` | GSSAPI service principal name used by `akamuctl login --gssapi`. Overrides the automatic `HTTP@<hostname>` derivation from `url`. |

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
# mTLS — uses cert_file / key_file from config or --cert / --key flags
akamuctl login

# GSSAPI/Kerberos — uses the ambient Kerberos credential cache
kinit alice@EXAMPLE.COM   # obtain a TGT if not already present
akamuctl login --gssapi
```

Both forms POST to `/admin/session`.  On success the returned token is saved to
`~/.config/akamu/session.json` with mode `0600` (user-readable only).
Subsequent commands reuse this token without re-authenticating.  A 30-second
expiry margin triggers automatic re-authentication before the server would
reject the token.

#### `--gssapi` flag

Sends an `Authorization: Negotiate` header built from the ambient Kerberos
ccache instead of presenting an mTLS client certificate.  No keytab is
required — only a valid TGT (run `kinit` first).

The GSSAPI service principal name (SPN) is resolved as follows:

1. If `gssapi_service` is set in `[server]` config, it is used as-is.
2. Otherwise the SPN is derived from the server URL as `HTTP@<hostname>`,
   where `<hostname>` is determined by:
   - Loopback names (`localhost`, `localhost.localdomain`, `ip6-localhost`,
     `ip6-loopback`) and loopback IP addresses (`127.x.x.x`, `::1`) →
     replaced with the machine's own FQDN via `gethostname(2)` and
     forward/reverse DNS.
   - Non-loopback IP addresses → resolved to a hostname via a DNS PTR
     lookup using hickory-resolver; a warning is printed and the bare IP
     is used as a fallback if reverse DNS fails.
   - DNS hostnames → used directly.

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

### `whoami`

Show the locally cached session identity without contacting the server:

```bash
akamuctl whoami
```

Displays the server URL and token expiry time for both the main server and
cosigner sessions (if cached).

## Operator management

Operator management requires the `administrator` role.

### `operator list`

List all operators (active and inactive):

```bash
akamuctl operator list
```

### `operator show`

Show the details of a single operator:

```bash
akamuctl operator show 3
```

Returns all fields including certificate fingerprint, GSSAPI principal,
creation time, last-seen timestamp, and active status.

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

### `operator update`

Update fields of an existing operator.  Only provided flags are changed; omitted
fields remain unchanged.

```bash
# Change role
akamuctl operator update 3 --role ca_operations

# Replace client certificate
akamuctl operator update 3 --cert-file /etc/akamu/alice-new.pem

# Assign a CA scope to a ca_ra operator
akamuctl operator update 5 --role ca_ra --ca-id rsa

# Update multiple fields at once
akamuctl operator update 3 --name "Alice Smith" --role administrator \
    --gssapi-principal alice@NEWREALM.COM
```

When the new role is `ca_ra`, `--ca-id` must also be provided. Setting
`--role ca_ra` without a CA scope is rejected by the server.

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

### `operator unlock`

Reset the failed-authentication counter for a locked-out operator:

```bash
akamuctl operator unlock 3
```

Use this when an operator has been locked out due to exceeding
`max_failed_auth` in the server configuration. Calls
`POST /admin/operators/{id}/unlock` (FIA_AFL.1).

Requires the `administrator` role.

## EAB key management

### `eab list`

List all EAB keys:

```bash
akamuctl eab list          # all keys
akamuctl eab list --used   # only consumed keys
akamuctl eab list --unused # only unconsumed keys
```

All authenticated roles may list EAB keys.

### `eab show`

Show details of a single EAB key:

```bash
akamuctl eab show my-device-001
```

Returns the key identifier, creation time, usage status, and profile grants.

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
| `--ca CA_ID` | Filter by CA ID. Only certificates issued by the named CA are returned. |
| `--serial HEX` | Filter by hex serial number. |
| `--subject TEXT` | Filter by subject distinguished name substring. |
| `--after RFC3339` | Issued at or after this timestamp. |
| `--before RFC3339` | Issued at or before this timestamp. |
| `--status VALUE` | `active` or `revoked`. |
| `--limit N` | Maximum results (default 20). |
| `--offset N` | Pagination offset (default 0). |

Requires the `administrator`, `ca_operations`, or `auditor` role.

### `cert show`

Show a certificate's metadata (no PEM/DER content):

```bash
akamuctl cert show <cert-uuid>
```

Returns order ID, account ID, serial number, validity window (`not_before`,
`not_after`), revocation status, MTC log index, and ARI renewal window
(`suggested_window_start`, `suggested_window_end`).

Requires the `administrator`, `ca_operations`, or `auditor` role.

### `cert download`

Download a certificate's content as PEM or DER:

```bash
# Print PEM to stdout (default)
akamuctl cert download <cert-uuid>

# Save DER to a file
akamuctl cert download <cert-uuid> --format der -o cert.der

# Save PEM to a file
akamuctl cert download <cert-uuid> --format pem -o cert.pem
```

Requires the `administrator` or `ca_operations` role.

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

Force immediate CRL regeneration for the default CA without waiting for the
next scheduled update:

```bash
akamuctl crl-force
```

To force regeneration for a specific CA use the `ca crl-force` subcommand
(see [CA management](#ca-management) below).

Requires the `administrator` or `ca_operations` role.

## Account management

### `account list`

List ACME accounts with optional status filtering:

```bash
akamuctl account list
akamuctl account list --status valid --limit 50
akamuctl account list --status deactivated
```

| Flag | Description |
|------|-------------|
| `--ca CA_ID` | Filter by CA ID. Only accounts registered via the named CA's `new-account` endpoint are returned. |
| `--status VALUE` | `valid` or `deactivated`. |
| `--limit N` | Maximum results (default 100). |
| `--offset N` | Pagination offset (default 0). |

All authenticated roles may list accounts.

### `account show`

Show details of a single ACME account:

```bash
akamuctl account show <account-uuid>
```

Returns status, contact information, JWK thumbprint, creation and update times,
and profile grants.

### `account deactivate`

Admin-initiated account deactivation:

```bash
akamuctl account deactivate <account-uuid>
```

The account is set to `deactivated` status and can no longer create orders
or issue certificates.

Requires the `administrator` role.

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

## CA management

In multi-CA deployments, these subcommands let you inspect the configured
CAs, issue cross-certificates, and force per-CA CRL regeneration.

### `ca list`

List all configured CAs:

```bash
akamuctl ca list
```

Returns each CA's ID, default flag, key type, hash algorithm, CRL URL, and
OCSP URL. All authenticated roles may call this command.

### `ca show`

Show details of a single CA:

```bash
akamuctl ca show rsa
```

### `ca cert`

Print the CA certificate PEM for the specified CA:

```bash
akamuctl ca cert rsa
akamuctl ca cert rsa -o /etc/akamu/rsa-ca.cert.pem
```

### `ca crl-force`

Force immediate CRL regeneration for a specific CA:

```bash
akamuctl ca crl-force rsa
akamuctl ca crl-force ec
```

Requires the `administrator` or `ca_operations` role.

### `ca cross-sign`

Issue a cross-certificate from one CA to another:

```bash
# Cross-sign another configured CA by its ID
akamuctl ca cross-sign rsa --subject-ca ec --validity-years 5

# Cross-sign an externally provided CA certificate
akamuctl ca cross-sign rsa --subject-cert /path/to/partner-ca.pem \
    --validity-years 3
```

The issuer CA (`rsa` in the examples above) signs the subject's public key.
The resulting cross-certificate has `pathLenConstraint = 0`.

Requires the `administrator` or `ca_operations` role.

## Cross-certificate management

### `cross-cert list`

List stored cross-certificates:

```bash
akamuctl cross-cert list
akamuctl cross-cert list --issuer-ca rsa
akamuctl cross-cert list --subject-ca ec
```

| Flag | Description |
|------|-------------|
| `--issuer-ca CA_ID` | Filter by issuing CA ID. |
| `--subject-ca CA_ID` | Filter by subject CA ID. |
| `--limit N` | Maximum results (default 100). |
| `--offset N` | Pagination offset (default 0). |

### `cross-cert download`

Download a cross-certificate by UUID:

```bash
akamuctl cross-cert download <cross-cert-uuid>
akamuctl cross-cert download <cross-cert-uuid> --format pem -o cross.pem
```

Requires any authenticated role.

## Delegation management

RFC 9115 delegation objects associate a CSR template (and optional CNAME map) with an ACME
account, allowing NDC (Name Delegation Consumer) clients to obtain certificates without
running a challenge responder.  These commands require `delegation_enabled = true` in the
server configuration.

Read operations (`delegation list`, `delegation show`) are available to all authenticated
roles.  Write operations (`delegation add`, `delegation update`, `delegation remove`)
require the `administrator` or `ca_operations` role.

### `delegation list`

List all delegation objects, optionally filtered to a single account:

```bash
akamuctl delegation list
akamuctl delegation list --account-id <account-uuid>
```

Returns each delegation's UUID, account ID, CSR template, CNAME map, creation timestamp,
and last-updated timestamp.

### `delegation show`

Show a single delegation object by its UUID:

```bash
akamuctl delegation show <delegation-uuid>
```

### `delegation add`

Create a delegation for an account.  The CSR template is a JSON file following RFC 9115 §4.
The CNAME map is an optional JSON object mapping source FQDNs to target FQDNs.

```bash
akamuctl delegation add \
    --account-id <account-uuid> \
    --csr-template /path/to/template.json

akamuctl delegation add \
    --account-id <account-uuid> \
    --csr-template /path/to/template.json \
    --cname-map /path/to/cname-map.json
```

Minimal CSR template example (`template.json`):

```json
{
  "keyTypes": [{"type": "EC", "curve": "P-256"}],
  "subject": {
    "commonName": {},
    "organization": "ExampleCorp"
  },
  "extensions": {
    "subjectAltName": {},
    "keyUsage": ["digitalSignature"],
    "extendedKeyUsage": ["1.3.6.1.5.5.7.3.1"]
  }
}
```

CNAME map example (`cname-map.json`):

```json
{
  "cdn.example.com": "cdn.provider.example"
}
```

The CSR template is validated against the RFC 9115 §4 schema at write time.  A malformed
template is rejected before it is stored.

### `delegation update`

Replace the CSR template and optionally the CNAME map for an existing delegation.  The
`account_id` is immutable and cannot be changed.

```bash
# Replace template, keep existing CNAME map unchanged
akamuctl delegation update <delegation-uuid> \
    --csr-template /path/to/new-template.json

# Replace template and CNAME map
akamuctl delegation update <delegation-uuid> \
    --csr-template /path/to/new-template.json \
    --cname-map /path/to/new-cname-map.json

# Replace template and remove the CNAME map
akamuctl delegation update <delegation-uuid> \
    --csr-template /path/to/new-template.json \
    --clear-cname-map
```

`--cname-map` and `--clear-cname-map` are mutually exclusive.

### `delegation remove`

Delete a delegation object.  Returns an error if one or more active orders still reference
this delegation (the orders must be finalized or expired first).

```bash
akamuctl delegation remove <delegation-uuid>
```

Returns a `409 Conflict` error when active orders reference the delegation.

## Profile management

### `profile list`

List all loaded certificate profiles with their parameters:

```bash
akamuctl profile list
```

Returns the profile ID, description, validity period (days), hash algorithm,
extended key usages, and whether MTC issuance is enabled.

All authenticated roles may list profiles.

### `profile add`

Add a new certificate profile to the runtime cache:

```bash
akamuctl profile add codesigning --params-file /tmp/codesigning.json
```

The JSON file must contain the profile parameters accepted by
`POST /admin/profiles`. At minimum it should include `description`;
all other fields have defaults. Example file:

```json
{
  "description": "Code signing certificate",
  "validity_days": 365,
  "extended_key_usages": ["code_signing"],
  "require_account_grant": true
}
```

Requires the `administrator` role.

### `profile update`

Replace an existing certificate profile in the runtime cache:

```bash
akamuctl profile update codesigning --params-file /tmp/codesigning-v2.json
```

The JSON file uses the same schema as `profile add` (without the `id` field).
Requires the `administrator` role.

### `profile remove`

Remove a certificate profile from the runtime cache:

```bash
akamuctl profile remove codesigning
```

Requires the `administrator` role.

## Order management

### `order list`

List certificate orders with optional filters:

```bash
akamuctl order list
akamuctl order list --account-id <account-uuid>
akamuctl order list --status pending --limit 50
```

| Flag | Description |
|------|-------------|
| `--ca CA_ID` | Filter by CA ID. Only orders placed against the named CA are returned. |
| `--account-id UUID` | Filter by account UUID. |
| `--status VALUE` | Filter by order status (`pending`, `ready`, `processing`, `valid`, `invalid`). |
| `--limit N` | Maximum results (default 100). |
| `--offset N` | Pagination offset (default 0). |

All authenticated roles may list orders.

### `order show`

Show a single order's details:

```bash
akamuctl order show <order-uuid>
```

Returns identifiers, associated authorization IDs, certificate ID (if issued),
profile, and timing fields (`created`, `updated`, `expires`, `not_before`,
`not_after`).

All authenticated roles may view order details.

## Server configuration

### `server-config`

Show the server's redacted runtime configuration:

```bash
akamuctl server-config
```

Returns the base URL, whether MTC is enabled, CAA identities, DNSSEC validation
setting, and a masked database URL.

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
| `delegation.create` | RFC 9115 delegation object created. |
| `delegation.update` | RFC 9115 delegation object updated. |
| `delegation.delete` | RFC 9115 delegation object deleted. |
| `security.violation` | Security anomaly detected. |

## Cosigner administration

`akamuctl` can also administer the `akamu-cosigner` daemon.
Configure the cosigner connection in `[cosigner]` in the config file, or pass
`--server-url` and TLS flags directly.

### `cosigner login`

Authenticate with the cosigner admin API and cache the session token:

```bash
akamuctl cosigner login
```

Uses the `[cosigner]` TLS settings from the config file (or falls back to
`[server]` settings if `[cosigner]` is not configured).

### `cosigner logout`

Invalidate the cosigner session token:

```bash
akamuctl cosigner logout
```

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

### `cosigner config`

Show the cosigner's redacted runtime configuration:

```bash
akamuctl cosigner config
```

Requires the `administrator` role on the cosigner.

## Configuration utilities

### `config generate`

Print an annotated example `akamuctl.toml` to stdout:

```bash
akamuctl config generate > ~/.config/akamu/akamuctl.toml
```

### `config validate`

Validate the current configuration file:

```bash
akamuctl config validate
```

Checks that the server URL is well-formed and that all referenced files
(CA certificate, client certificate, private key) exist on disk.  Reports
warnings and errors for each issue found.

## Shell completions

### `completions`

Generate shell completion scripts:

```bash
# Bash
akamuctl completions bash > /etc/bash_completion.d/akamuctl

# Zsh
akamuctl completions zsh > ~/.zfunc/_akamuctl

# Fish
akamuctl completions fish > ~/.config/fish/completions/akamuctl.fish
```

Supported shells: `bash`, `zsh`, `fish`, `elvish`, `powershell`.

## Output formats

By default, `akamuctl` prints results as aligned tables.  Use `--output json`
(or `-o json`) to get pretty-printed JSON suitable for scripting:

```bash
akamuctl -o json operator list | jq '.operators[] | select(.role == "auditor")'
```

### Table output

When the server response is a JSON object with a single array-valued field
(the common case for paginated endpoints such as `cert list` and `audit`),
the array is rendered as an aligned table and any remaining scalar fields
(e.g. `total`, `offset`, `limit`) are printed as a key-value footer
below the table.  When the response is a plain JSON array the table is
printed directly.  Scalar responses are printed as a single line.

When a paginated query returns no rows, `(no results)` is printed instead
of an empty table.

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | Success. |
| 1 | General error (HTTP, network, JSON parse failure). |
| 2 | Authentication error (session expired, certificate rejected). |
| 3 | Configuration error (missing or invalid config file or flag). |
