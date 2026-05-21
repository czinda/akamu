# akamu-cli — Command Reference

`akamu-cli` is a command-line ACME client that wraps `akamu-client`. It covers the full ACME lifecycle: account management, certificate issuance with multiple challenge types, ARI-aware renewal, revocation, and migration from other ACME clients.

## Installation

### Build from source

```bash
cargo build -p akamu-cli --release
```

The binary is placed at `target/release/akamu-cli`.

```bash
sudo install -m 0755 target/release/akamu-cli /usr/local/bin/akamu-cli
```

### cargo install (from a local checkout)

```bash
cargo install --path crates/akamu-cli
```

This installs the binary to `~/.cargo/bin/akamu-cli`.

## Command tree

```
akamu-cli
  account
    register       Register a new ACME account
    deregister     Deactivate an existing account (RFC 8555 §7.3.7)
    show           Print current account URL, status, and contacts
    update         Update account contact list
    key-change     Roll the account key to a new key (RFC 8555 §7.3.5)
  issue            Obtain a certificate (http-01 / dns-01 / dns-persist-01 /
                   tls-alpn-01 / onion-csr-01)
  renew            ARI-aware renewal (RFC 9773); skips issuance if outside window
  revoke           Revoke a certificate via account key or certificate's own key
  import
    certbot        Import accounts and certificates from a certbot installation
```

## Subcommands

### account register

Register a new ACME account and save the account URL to a sidecar file.

```
akamu-cli account register --server URL --account-key FILE [OPTIONS]
```

| Flag | Required | Description |
|---|---|---|
| `--server URL` | yes | ACME directory URL. Default: Let's Encrypt production. |
| `--account-key FILE` | yes | Path to the account key PEM file. Generated and saved if the file does not exist. |
| `--key-type TYPE` | no | Key type to generate when the key file does not exist. Default: `ec:P-256`. |
| `--contact URI` | no | Contact URI (e.g. `mailto:admin@example.com`). Repeatable. |
| `--agree-tos` | no | Agree to the server's Terms of Service. |
| `--eab-kid KID` | no | External Account Binding key ID. Mutually exclusive with `--gssapi-keytab`. |
| `--eab-key KEY_B64U` | no | EAB HMAC key encoded as base64url (no padding). Mutually exclusive with `--gssapi-keytab`. |
| `--eab-alg ALG` | no | EAB HMAC algorithm: `HS256`, `HS384`, or `HS512`. Default: `HS256`. |
| `--gssapi-keytab PATH` | no | Path to a Kerberos keytab file. When set, the CLI performs a GSSAPI-authenticated `GET /acme/eab` request and logs the authenticated principal. Mutually exclusive with `--eab-kid` / `--eab-key`. |

After registration the account URL is written to `<account-key>.account-url` (see [Sidecar files](#sidecar-files)).

### account deregister

Deactivate an existing account (RFC 8555 §7.3.7).

```
akamu-cli account deregister --server URL --account-key FILE
```

The account URL is read from `<account-key>.account-url`. After deactivation the sidecar file is removed.

### account show

Fetch the current account state from the server and print it.

```
akamu-cli account show --server URL --account-key FILE
```

Output example:

```
URL:     https://acme.example.com/acme/account/1234
Status:  valid
Contact: mailto:admin@example.com
```

### account update

Update the contact list for an existing account.

```
akamu-cli account update --server URL --account-key FILE [--contact URI ...]
```

| Flag | Required | Description |
|---|---|---|
| `--server URL` | yes | ACME directory URL |
| `--account-key FILE` | yes | Account key PEM file |
| `--contact URI` | no (repeatable) | New contact URI. Omit entirely to clear all contacts. |

### account key-change

Roll the account key to a new key (RFC 8555 §7.3.5). The server atomically replaces the account key. The new key is written back to `--account-key`, overwriting the old one. The account URL sidecar file is unchanged.

```
akamu-cli account key-change --server URL --account-key FILE --new-key FILE [OPTIONS]
```

| Flag | Required | Description |
|---|---|---|
| `--server URL` | yes | ACME directory URL |
| `--account-key FILE` | yes | Current account key PEM file |
| `--new-key FILE` | yes | New key PEM file. Generated if the file does not exist. |
| `--new-key-type TYPE` | no | Key type for generation when `--new-key` file is absent. Default: `ec:P-256`. |

After success, `--account-key` contains the new key.

### issue

Obtain a certificate for one or more domains.

```
akamu-cli issue --server URL --account-key FILE -d DOMAIN --out FILE [OPTIONS]
```

| Flag | Required | Description |
|---|---|---|
| `--server URL` | yes | ACME directory URL |
| `--account-key FILE` | yes | Account key PEM file |
| `-d DOMAIN` | yes (repeatable) | Domain to include. First value becomes the CN. |
| `--out FILE` | yes | Output path for the PEM bundle (leaf + chain). |
| `--key-type TYPE` | no | Account key type when generating a new key. Default: `ec:P-256`. |
| `--cert-key-type TYPE` | no | Certificate key type. Default: `ec:P-256`. |
| `--cert-key FILE` | no | Reuse an existing certificate private key PEM file. Generated and saved alongside `--out` if absent. |
| `--challenge TYPE` | no | Challenge type: `http-01`, `dns-01`, `dns-persist-01`, `tls-alpn-01`, `onion-csr-01`. Default: `http-01`. |
| `--dns-hook CMD` | no | Hook script for dns-01 / dns-persist-01 automation. See [DNS hook interface](#dns-hook-interface). |
| `--http-port PORT` | no | Port for the built-in http-01 solver. Default: `80`. |
| `--tls-port PORT` | no | Port for the built-in tls-alpn-01 solver. Default: `443`. |
| `--onion-key FILE` | required for `onion-csr-01` | Ed25519 hidden-service private key PEM file. |
| `--poll-timeout SECS` | no | Maximum seconds to wait for order/challenge validation. Default: `120`. |
| `--profile NAME` | no | Certificate profile name (draft-aaron-acme-profiles-01). Sent as `"profile"` in the `newOrder` payload. The server may echo a different name (e.g. `"default"`) if auto-selection applies; the echoed value is stored in the renewal sidecar. |
| `--eab-kid KID` | no | EAB key ID (used if no account exists yet). Mutually exclusive with `--gssapi-keytab`. |
| `--eab-key KEY_B64U` | no | EAB HMAC key (base64url). Mutually exclusive with `--gssapi-keytab`. |
| `--gssapi-keytab PATH` | no | Path to a Kerberos keytab file. When set and no account URL sidecar exists, the CLI performs a GSSAPI-authenticated `GET /acme/eab` before registering. Mutually exclusive with `--eab-kid` / `--eab-key`. |

If the account URL sidecar file does not exist, `issue` registers a new account first.

The `http-01` and `tls-alpn-01` challenge types cannot validate wildcard identifiers (RFC 8555 §8.3, RFC 8737 §3). Use `dns-01` or `dns-persist-01` for `*.example.com`.

The certificate private key is generated and saved to `<out>.key.pem` unless `--cert-key` is provided.

After every successful issuance, a [renewal configuration sidecar](#renewal-configuration-sidecar) is written to `<out>.renewal.toml`.

### renew

Check the ARI renewal window (RFC 9773) for an existing certificate, then issue a replacement if renewal is suggested or `--force` is given.

```
akamu-cli renew --server URL --account-key FILE -d DOMAIN --out FILE [OPTIONS]
```

| Flag | Required | Description |
|---|---|---|
| `--server URL` | yes (unless `--renewal-config` is used) | ACME directory URL |
| `--account-key FILE` | yes (unless `--renewal-config` is used) | Account key PEM file |
| `-d DOMAIN` | yes (unless `--renewal-config` is used) | Domains for the new certificate |
| `--out FILE` | yes (unless `--renewal-config` is used) | Output path for the new PEM bundle |
| `--renewal-config FILE` | no | Load all settings from a `.renewal.toml` file. Explicit CLI flags override individual fields from the file. |
| `--cert FILE` | no | Existing certificate PEM to check against ARI. Without this flag, no ARI check is performed. |
| `--force` | no | Renew unconditionally, skipping the ARI window check. |
| `--challenge TYPE` | no | Same values as `issue`. Default: `http-01`. |
| `--dns-hook CMD` | no | Hook script for dns-01 / dns-persist-01 automation. See [DNS hook interface](#dns-hook-interface). |
| `--http-port PORT` | no | Default: `80`. |
| `--tls-port PORT` | no | Default: `443`. |
| `--onion-key FILE` | no | Required for `onion-csr-01`. |
| `--poll-timeout SECS` | no | Default: `120`. |
| `--key-type TYPE` | no | Account key type. Default: `ec:P-256`. |
| `--cert-key-type TYPE` | no | Certificate key type. Default: `ec:P-256`. |
| `--cert-key FILE` | no | Reuse an existing certificate private key PEM file instead of generating a new one. Useful for HPKP / TLSA key pinning scenarios where the public key must remain stable across renewals. |
| `--profile NAME` | no | Certificate profile name (draft-aaron-acme-profiles-01). Stored in the renewal sidecar so subsequent `renew` calls request the same profile. |
| `--eab-kid KID` | no | EAB key ID. Mutually exclusive with `--gssapi-keytab`. |
| `--eab-key KEY_B64U` | no | EAB HMAC key (base64url). Mutually exclusive with `--gssapi-keytab`. |
| `--gssapi-keytab PATH` | no | Path to a Kerberos keytab file for GSSAPI-authenticated EAB. Mutually exclusive with `--eab-kid` / `--eab-key`. |

Behavior when `--cert` is given (or when `--renewal-config` is used and the cert file from the config exists) and `--force` is not:

- If the current time is before the ARI window start, the command exits without issuing and prints a message.
- If the current time is within (or past) the window, issuance proceeds.
- If the server does not support ARI or returns an error, issuance proceeds with a warning.

When `--renewal-config FILE` is provided, all settings are loaded from the TOML file (written by `issue` or `import certbot`). This makes cron-based renewal straightforward:

```bash
akamu-cli renew --renewal-config /etc/ssl/example.com/fullchain.pem.renewal.toml
```

### revoke

Revoke an issued certificate (RFC 8555 §7.6).

```
akamu-cli revoke --server URL --account-key FILE --cert FILE [OPTIONS]
```

| Flag | Required | Description |
|---|---|---|
| `--server URL` | yes | ACME directory URL |
| `--account-key FILE` | yes | Account key PEM file (used unless `--cert-key` is given) |
| `--cert FILE` | yes | PEM file containing the certificate to revoke |
| `--reason N` | no | CRL reason code: 0–6 or 8–10 (7 is not valid). Omit for unspecified. |
| `--cert-key FILE` | no | Certificate's own private key PEM file. When provided, revocation is signed with the certificate key instead of the account key (self-revocation). |

Self-revocation (via `--cert-key`) is useful when the ACME account key is unavailable.

### import certbot

Import ACME account keys and certificate renewal configurations from an existing certbot installation.

```
akamu-cli import certbot [OPTIONS]
```

| Flag | Required | Description |
|---|---|---|
| `--certbot-dir DIR` | no | Certbot configuration directory. Default: `/etc/letsencrypt`. |
| `--account-key FILE` | yes (unless `--list`) | Output path for the imported account key PEM. Must not already exist. |
| `--server URL` | no | Import only the account registered with this CA URL. Required when multiple accounts are found. |
| `-d DOMAIN` | no (repeatable) | Limit certificate import to these domains. Default: all discovered domains. |
| `--cert-dir DIR` | yes (when importing certificates) | Directory to write imported certificate chains and keys. Created if absent. |
| `--dns-challenge TYPE` | no | Challenge type to use for DNS-based certbot configs: `dns-01` or `dns-persist-01`. Default: `dns-01`. |
| `--dns-hook CMD` | no | Hook script to embed in generated renewal configs for DNS TXT record management. |
| `--dry-run` | no | Show what would be done without writing any files. |
| `--list` | no | List all discoverable accounts and certificate renewal configurations, then exit. |

#### What the importer does

1. Walks `<certbot-dir>/accounts/<ca-hostname>/<account-id>/` to discover accounts. Each account directory must contain `private_key.json` (the account key in JWK format) and `regr.json` (the registration response with account URL and contacts).

2. Converts the certbot JWK private key to a PEM file written to `--account-key`. Writes the account URL to `<account-key>.account-url` as an [account URL sidecar](#sidecar-files).

3. Walks `<certbot-dir>/renewal/*.conf` to discover certificate configurations. For each matching domain, copies `live/<domain>/fullchain.pem` and `live/<domain>/privkey.pem` into `--cert-dir` with mode `0o600`, then writes a `.renewal.toml` sidecar (see [Renewal configuration sidecar](#renewal-configuration-sidecar)). If either the certificate chain or the private key file cannot be read (for example, due to a permissions issue), the renewal sidecar is not written for that domain and a warning is printed.

4. Prints the `akamu-cli renew --renewal-config` command for each imported certificate.

#### Challenge type mapping

Certbot's authenticator field is mapped to an akamu challenge type as follows:

| Certbot authenticator | akamu challenge type |
|---|---|
| `standalone`, `webroot`, `nginx`, `apache` | `http-01` |
| `manual` with `preferred_challenges = dns` | value of `--dns-challenge` |
| `manual` (no DNS preference) | `http-01` |
| Any `dns-*` plugin (dns-cloudflare, dns-route53, etc.) | value of `--dns-challenge` |
| `tls-sni-01` | `tls-alpn-01` (with a deprecation warning) |

When a DNS-based challenge type is selected but no `--dns-hook` was supplied, the importer emits a warning for each affected domain (unless `--dry-run` is set) reminding you to add a hook script before the next renewal.

#### Certificate key type detection

The importer reads the actual key PEM file from `live/<domain>/privkey.pem` to determine the key type (`ec:P-256`, `rsa:2048`, etc.) stored in the renewal sidecar. This ensures the sidecar accurately reflects the key material rather than relying on filename heuristics.

#### Wildcard domain handling

Certbot stores wildcard certificates under `live/_wildcard.<domain>/`. The importer decodes this convention automatically: `_wildcard.example.com` becomes `*.example.com` in the generated renewal configuration file.

#### Prerequisites

- The importer reads certbot's `live/` and `accounts/` directories. On most systems these are owned by root with mode 0700. Run the importer as root or with sufficient privilege to read them.
- The `--account-key` output path must not already exist.
- All output files (account key, certificate chain, certificate key, renewal sidecar) are written with mode `0o600`.

#### Example

```bash
# List what would be imported
akamu-cli import certbot --list

# Dry run (shows actions without writing files)
sudo akamu-cli import certbot \
  --account-key /etc/akamu/acct.pem \
  --cert-dir /etc/akamu/certs \
  --dry-run

# Full import from Let's Encrypt production, with a DNS hook for future renewals
sudo akamu-cli import certbot \
  --account-key /etc/akamu/acct.pem \
  --server https://acme-v02.api.letsencrypt.org/directory \
  --cert-dir /etc/akamu/certs \
  --dns-challenge dns-01 \
  --dns-hook /etc/akamu/hooks/dns-update.sh

# Import only specific domains
sudo akamu-cli import certbot \
  --account-key /etc/akamu/acct.pem \
  --cert-dir /etc/akamu/certs \
  -d example.com \
  -d "*.example.com"
```

After import, renew each certificate with:

```bash
akamu-cli renew --renewal-config /etc/akamu/certs/example.com.pem.renewal.toml
```

## File permissions

All output files written by `akamu-cli` — account keys, certificate private keys, account URL sidecars, and renewal configuration sidecars — are created with mode `0o600` (owner read/write only). When overwriting a pre-existing file, the mode is explicitly re-applied so that stale group or world permissions left by a previous tool are corrected.

## Sidecar files

### Account URL sidecar

When you register an account (or when `issue` or `import certbot` creates one), `akamu-cli` writes the account URL to a file named `<account-key>.account-url` in the same directory as the account key. For example, if your account key is `~/.akamu/account.pem`, the sidecar is `~/.akamu/account.pem.account-url`.

The `issue`, `renew`, `deregister`, `account show`, `account update`, and `account key-change` subcommands read this file to find the account URL without re-registering.

If the sidecar is missing and you run `issue`, the CLI registers a new account first. If the sidecar is missing and you run `deregister`, the command fails with an error.

Keep the key file and its sidecar together and back them up. If you lose the account key, you cannot deactivate or otherwise manage the account.

### Renewal configuration sidecar

After every successful `issue` (and after `import certbot`), `akamu-cli` writes a TOML file named `<out>.renewal.toml` alongside the certificate chain. This file captures every parameter needed to repeat the issuance and is consumed by `renew --renewal-config`.

#### File format

```toml
server          = "https://acme.example.com/acme/directory"
account_key     = "/etc/akamu/account.pem"
account_key_type = "ec:P-256"
cert_path       = "/etc/ssl/example.com/fullchain.pem"
cert_key_path   = "/etc/ssl/example.com/fullchain.pem.key.pem"
cert_key_type   = "ec:P-256"
challenge_type  = "dns-01"
http_port       = 80
tls_port        = 443
poll_timeout    = 120
eab_alg         = "HS256"

[[domains]]
type  = "dns"
value = "example.com"

[[domains]]
type  = "dns"
value = "*.example.com"

# Optional fields (omit when not applicable):
onion_key       = "/path/to/hs_key.pem"
contacts        = ["mailto:admin@example.com"]
eab_kid         = "kid-from-ca"
# eab_key is intentionally omitted: the HMAC key is never written to this file.
gssapi_keytab   = "/etc/akamu/http.keytab"
dns_hook        = "/etc/akamu/hooks/dns-update.sh"
profile         = "tlsserver"
```

#### Fields

| Field | Default | Description |
|---|---|---|
| `server` | — | ACME directory URL |
| `domains` | — | Array of `{type, value}` identifier objects |
| `account_key` | — | Path to the account private key PEM |
| `account_key_type` | `"ec:P-256"` | Key type string for the account key |
| `cert_path` | — | Output path for the certificate chain PEM |
| `cert_key_path` | — | Output path for the certificate private key PEM |
| `cert_key_type` | `"ec:P-256"` | Key type string for the certificate key |
| `challenge_type` | `"http-01"` | ACME challenge type |
| `http_port` | `80` | Port for the http-01 solver |
| `tls_port` | `443` | Port for the tls-alpn-01 solver |
| `onion_key` | — | Path to the Ed25519 onion service key (onion-csr-01 only) |
| `poll_timeout` | `120` | Seconds to wait for challenge validation |
| `contacts` | `[]` | Contact URIs registered with the account |
| `eab_kid` | — | EAB key ID |
| `eab_alg` | `"HS256"` | EAB HMAC algorithm |
| `gssapi_keytab` | — | Path to a Kerberos keytab for GSSAPI-authenticated EAB (mutually exclusive with `eab_kid`) |
| `dns_hook` | — | Hook script path for DNS TXT record management |
| `profile` | — | Certificate profile name (draft-aaron-acme-profiles-01). When set, passed as `"profile"` in the `newOrder` payload on renewal. Populated from the server's echoed value after issuance. |

> The `eab_key` HMAC secret is **never written** to the renewal sidecar. Supply it again via `--eab-key` or `--gssapi-keytab` if EAB is required for the renewal account.

Fields that have defaults are optional in the TOML file. Existing configs with fewer fields remain forward-compatible as new optional fields are added.

## DNS hook interface

When `--dns-hook CMD` is passed with a DNS-based challenge type (`dns-01` or `dns-persist-01`), `akamu-cli` delegates TXT record management to an external script instead of waiting for manual input.

The hook script is invoked as:

```
<CMD> add
<CMD> remove
```

All values are passed through environment variables only (never as command-line arguments, which would be visible in `/proc/<pid>/cmdline`):

| Variable | Value |
|---|---|
| `AKAMU_DOMAIN` | DNS name being validated (base domain, wildcard prefix stripped) |
| `AKAMU_TOKEN` | ACME challenge token |
| `AKAMU_TXT` | TXT record value: `base64url(SHA-256(key_authorization))` |
| `AKAMU_KEY_AUTH` | Full key authorization string (`<token>.<account-key-thumbprint>`) |

An exit code of `0` means success. Any non-zero exit code is treated as a failure; stderr from the script is captured and included in the error message.

For `dns-01`, the hook is called with `add` before challenge validation and with `remove` after the challenge completes (whether it succeeds or fails). For `dns-persist-01`, the hook is only called with `add`; on success the TXT record is left in place (it is a long-lived record tied to the account key, not the token).

### Minimal hook example

```bash
#!/usr/bin/env bash
# /etc/akamu/hooks/dns-nsupdate.sh
set -euo pipefail

ZONE="example.com."
RECORD="_acme-challenge.${AKAMU_DOMAIN}."

case "$1" in
  add)
    nsupdate -k /etc/akamu/ddns.key <<EOF
server ns1.example.com
zone ${ZONE}
update add ${RECORD} 60 TXT "${AKAMU_TXT}"
send
EOF
    ;;
  remove)
    nsupdate -k /etc/akamu/ddns.key <<EOF
server ns1.example.com
zone ${ZONE}
update delete ${RECORD} TXT
send
EOF
    ;;
esac
```

Make the hook executable:

```bash
chmod 0755 /etc/akamu/hooks/dns-nsupdate.sh
```

Then use it with `issue` or `renew`:

```bash
akamu-cli issue \
  --account-key ~/.akamu/account.pem \
  -d "*.example.com" \
  --challenge dns-01 \
  --dns-hook /etc/akamu/hooks/dns-nsupdate.sh \
  --out /etc/ssl/example.com/wildcard.pem
```

## Example sessions

### Register, issue (http-01), and deregister

```bash
# 1. Register an account
akamu-cli account register \
  --server https://acme.example.com/acme/directory \
  --account-key ~/.akamu/account.pem \
  --key-type ec:P-256 \
  --contact mailto:admin@example.com \
  --agree-tos

# 2. Issue a certificate
akamu-cli issue \
  --server https://acme.example.com/acme/directory \
  --account-key ~/.akamu/account.pem \
  -d example.com \
  -d www.example.com \
  --out /etc/ssl/example.com/fullchain.pem

# 3. Deregister the account
akamu-cli account deregister \
  --server https://acme.example.com/acme/directory \
  --account-key ~/.akamu/account.pem
```

Port 80 must be reachable from the ACME server for http-01 validation. The CLI starts a temporary HTTP server during challenge validation and shuts it down afterwards.

### Issue with tls-alpn-01

Port 443 must be reachable from the ACME server. Wildcard domains are not supported.

```bash
akamu-cli issue \
  --server https://acme.example.com/acme/directory \
  --account-key ~/.akamu/account.pem \
  -d example.com \
  --challenge tls-alpn-01 \
  --tls-port 443 \
  --out /etc/ssl/example.com/fullchain.pem
```

### Issue with dns-01 (wildcard, manual)

Without `--dns-hook`, dns-01 is interactive: the CLI prints the TXT record to add and waits for you to press Enter.

```bash
akamu-cli issue \
  --server https://acme.example.com/acme/directory \
  --account-key ~/.akamu/account.pem \
  -d "*.example.com" \
  --challenge dns-01 \
  --out /etc/ssl/example.com/wildcard.pem
```

Output:
```
DNS-01 challenge for *.example.com:
  Name:  _acme-challenge.example.com.
  Type:  TXT
  Value: <base64url>

Press Enter after the TXT record has propagated (Ctrl-C to abort)...
```

### Issue with dns-01 (wildcard, automated hook)

```bash
akamu-cli issue \
  --server https://acme.example.com/acme/directory \
  --account-key ~/.akamu/account.pem \
  -d "*.example.com" \
  --challenge dns-01 \
  --dns-hook /etc/akamu/hooks/dns-nsupdate.sh \
  --out /etc/ssl/example.com/wildcard.pem
```

### Issue with onion-csr-01 (RFC 9799)

```bash
akamu-cli issue \
  --server https://acme.example.com/acme/directory \
  --account-key ~/.akamu/account.pem \
  -d myservice.onion \
  --challenge onion-csr-01 \
  --onion-key ~/.tor/hs_ed25519_secret_key.pem \
  --out /etc/ssl/myservice/fullchain.pem
```

### ARI-aware renewal (manual flags)

```bash
# Check ARI window; issue only if inside it
akamu-cli renew \
  --server https://acme.example.com/acme/directory \
  --account-key ~/.akamu/account.pem \
  -d example.com \
  --cert /etc/ssl/example.com/fullchain.pem \
  --out /etc/ssl/example.com/fullchain.pem

# Force renewal regardless of ARI window
akamu-cli renew \
  --server https://acme.example.com/acme/directory \
  --account-key ~/.akamu/account.pem \
  -d example.com \
  --cert /etc/ssl/example.com/fullchain.pem \
  --out /etc/ssl/example.com/fullchain.pem \
  --force
```

### ARI-aware renewal from a renewal config

After `issue` has written a `.renewal.toml` sidecar, renewals require only one flag:

```bash
akamu-cli renew \
  --renewal-config /etc/ssl/example.com/fullchain.pem.renewal.toml
```

The command checks ARI using the certificate path stored in the config, and re-issues only if the renewal window is open (or if `--force` is added). A new `.renewal.toml` is written after each successful renewal.

This form is suitable for use from cron or a systemd timer:

```
# /etc/cron.d/akamu-renew
0 3 * * * root akamu-cli renew --renewal-config /etc/ssl/example.com/fullchain.pem.renewal.toml
```

### Revoke a certificate

```bash
# Via account key
akamu-cli revoke \
  --server https://acme.example.com/acme/directory \
  --account-key ~/.akamu/account.pem \
  --cert /etc/ssl/example.com/fullchain.pem \
  --reason 1

# Self-revocation (account key unavailable)
akamu-cli revoke \
  --server https://acme.example.com/acme/directory \
  --account-key ~/.akamu/account.pem \
  --cert /etc/ssl/example.com/fullchain.pem \
  --cert-key /etc/ssl/example.com/fullchain.pem.key.pem
```

### Roll the account key

```bash
akamu-cli account key-change \
  --server https://acme.example.com/acme/directory \
  --account-key ~/.akamu/account.pem \
  --new-key ~/.akamu/account-new.pem \
  --new-key-type ec:P-384
```

After success, `~/.akamu/account.pem` contains the new key and the old key is no longer accepted by the server.

### Show and update account contacts

```bash
akamu-cli account show \
  --server https://acme.example.com/acme/directory \
  --account-key ~/.akamu/account.pem

akamu-cli account update \
  --server https://acme.example.com/acme/directory \
  --account-key ~/.akamu/account.pem \
  --contact mailto:new@example.com \
  --contact mailto:backup@example.com
```

### Migrate from certbot

```bash
# 1. Preview
akamu-cli import certbot --list

# 2. Import (run as root to read certbot's live/ and accounts/ directories)
sudo akamu-cli import certbot \
  --server https://acme-v02.api.letsencrypt.org/directory \
  --account-key /etc/akamu/acct.pem \
  --cert-dir /etc/akamu/certs \
  --dns-hook /etc/akamu/hooks/dns-update.sh

# 3. Renew each certificate with its generated config
akamu-cli renew --renewal-config /etc/akamu/certs/example.com.pem.renewal.toml
```

## External Account Binding

Some CAs require EAB credentials before accepting a new account. Two methods are available: manual key/ID or GSSAPI (Kerberos) authentication.

### Manual EAB (kid + HMAC key)

Obtain a KID and HMAC key from your CA's operator, then pass them to `account register` or `issue`:

```bash
akamu-cli account register \
  --server https://acme.example.com/acme/directory \
  --account-key ~/.akamu/account.pem \
  --agree-tos \
  --eab-kid my-eab-key-id \
  --eab-key dGhpcyBpcyBhIHRlc3Qga2V5 \
  --eab-alg HS256
```

The `--eab-key` value must be the raw HMAC key encoded as base64url without padding. Do not wrap it in additional base64 encoding.

### GSSAPI-authenticated EAB

When the CA uses Kerberos to authenticate EAB requests (via `/acme/eab`), supply a keytab instead:

```bash
akamu-cli account register \
  --server https://acme.example.com/acme/directory \
  --account-key ~/.akamu/account.pem \
  --agree-tos \
  --gssapi-keytab /etc/akamu/client.keytab
```

The CLI derives the target service name `HTTP@<hostname>` from the server URL and calls `GET /acme/eab` with an `Authorization: Negotiate` token. The authenticated Kerberos principal is logged. `--gssapi-keytab` and `--eab-kid` / `--eab-key` are mutually exclusive.

If the server has `external_account_required = true` and you omit all EAB flags, registration fails with `urn:ietf:params:acme:error:externalAccountRequired`.

## Key type selection

| Use case | Recommended type | Notes |
|---|---|---|
| Default / broadest compatibility | `ec:P-256` | Widely supported, fast, small signatures |
| Stronger classical security | `ec:P-384` or `rsa:3072` | Use when policy requires |
| Post-quantum account key | `ml-dsa-65` | Larger signatures; check server support |
| Post-quantum certificate key | `ml-dsa-44` | Smallest PQ key; suitable for most cases |
| Legacy RSA-only environments | `rsa:2048` or `rsa:4096` | Avoid unless forced by policy |

ML-DSA keys require an Akāmu server linked against OpenSSL 3.5 or later, which provides native ML-DSA support via the standard EVP interface. Vanilla Let's Encrypt does not support ML-DSA.

## Logging

Set the `RUST_LOG` environment variable to control log output:

```bash
RUST_LOG=info   akamu-cli issue ...    # normal progress messages
RUST_LOG=debug  akamu-cli issue ...    # HTTP request/response details
RUST_LOG=trace  akamu-cli issue ...    # full JWS content and all internal steps
```

The default level is `warn`, which prints only errors and warnings.

## Error messages and troubleshooting

**`ACME error urn:ietf:params:acme:error:badNonce`**

The server rejected the nonce. The library retries automatically once. If this appears in CLI output, both attempts failed. Retry the command.

**`ACME error urn:ietf:params:acme:error:incorrectResponse`**

The server could not validate the challenge. For http-01, verify that port 80 is reachable and that no firewall or reverse proxy is blocking `.well-known/acme-challenge/`. For tls-alpn-01, verify port 443 is reachable with no TLS terminator in front.

**`ACME error urn:ietf:params:acme:error:externalAccountRequired`**

The server requires EAB credentials. Pass `--eab-kid` and `--eab-key`.

**`ACME error urn:ietf:params:acme:error:accountDoesNotExist`**

No account is registered for the given key. Run `account register` first.

**`invalid reason code 7; valid values: 0–6, 8–10`**

Reason code 7 (`removeFromCRL`) is not valid for revocation requests. Choose a different code or omit `--reason`.

**`Failed to bind port 80: Permission denied`**

The http-01 solver needs to listen on port 80. Either run with `sudo`, grant `CAP_NET_BIND_SERVICE` to the binary, or use an iptables redirect from port 80 to a high port and pass `--http-port <high-port>`.

**`Error: No such file: account.pem.account-url`**

The sidecar file is missing. Run `account register` first, or restore the sidecar from a backup.

**`Unsupported algorithm: ML-DSA-65`**

The server does not support the requested key type. Use a classical key type such as `ec:P-256`, or connect to an Akāmu server linked against OpenSSL 3.5 or later (which provides native ML-DSA support).

**`dns hook '...' add exited with status 1: ...`**

The DNS hook script returned a non-zero exit code. Check the hook's stderr output (included in the error message) and verify that the script has the correct permissions and that the DNS update API is reachable.

**`no certbot accounts found; check --certbot-dir and --server`**

The importer found no accounts under `<certbot-dir>/accounts/`. Verify the `--certbot-dir` path and that the directory is readable. If multiple accounts are present but no `--server` flag was given, run with `--list` first to identify the account URL, then pass `--server`.
