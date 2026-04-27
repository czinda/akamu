# akamu-cli

Command-line ACME client for the Akamu project.  Supports classical and
post-quantum (ML-DSA) account keys.

## Installation

Build from source inside the Akamu workspace:

```sh
cargo build -p akamu-cli --release
```

The binary is written to `target/release/akamu-cli`.

Before building, make sure the workspace root `Cargo.toml` contains the PQC
OpenSSL patch (see the note at the end of this file).

## Commands

### `account register`

Register a new ACME account.  If the account key file does not exist, a new key
is generated and saved.  The resulting account URL is stored in a sidecar file
next to the key (see "Sidecar files" below).

```
akamu-cli account register [OPTIONS] --account-key <FILE>

Options:
  --server <URL>          ACME directory URL
                          [default: https://acme-v02.api.letsencrypt.org/directory]
  --account-key <FILE>    PEM file for the account key (generated if absent)
  --key-type <TYPE>       Key type for a newly generated key [default: ec:P-256]
  --contact <URI>         Contact URI, e.g. "mailto:admin@example.com"
                          (may be repeated)
  --agree-tos             Agree to the server's terms of service
  --eab-kid <KID>         External Account Binding key ID
  --eab-key <KEY>         EAB HMAC key, base64url-encoded (no padding)
  --eab-alg <ALG>         EAB HMAC algorithm: HS256 | HS384 | HS512
                          [default: HS256]
```

`--eab-kid` and `--eab-key` must be provided together or not at all.

### `account deregister`

Deactivate an existing ACME account (RFC 8555 §7.3.7).  Reads the account URL
from the sidecar file and sends a deactivation request.  Removes the sidecar
file on success.

```
akamu-cli account deregister [OPTIONS] --account-key <FILE>

Options:
  --server <URL>          ACME directory URL
                          [default: https://acme-v02.api.letsencrypt.org/directory]
  --account-key <FILE>    PEM file for the account key
```

### `issue`

Obtain a certificate for one or more domains.  If the account key file does not
exist, a new key is generated and a new account is registered automatically
(inline registration supports EAB flags).  If the sidecar file already exists,
the stored account URL is reused.

After a successful issuance, a renewal configuration TOML file is written to
`<out>.renewal.toml` alongside the certificate chain (see "Renewal sidecar"
below).

```
akamu-cli issue [OPTIONS] --account-key <FILE> --out <FILE>

Options:
  --server <URL>              ACME directory URL
                              [default: https://acme-v02.api.letsencrypt.org/directory]
  --domain <DOMAIN>, -d       Domain name (may be repeated; first domain → CN)
  --account-key <FILE>        PEM file for the account key (generated if absent)
  --key-type <TYPE>           Account key type for a newly generated key
                              [default: ec:P-256]
  --cert-key-type <TYPE>      Key type for the certificate signing key
                              [default: ec:P-256]
  --challenge <TYPE>          Challenge type [default: http-01]
                              Supported: http-01, dns-01, dns-persist-01,
                                         tls-alpn-01, onion-csr-01
  --dns-hook <CMD>            Hook script for dns-01 / dns-persist-01 automation
                              (see "DNS hook interface" below)
  --http-port <PORT>          Port to serve http-01 challenges on [default: 80]
  --tls-port <PORT>           Port to serve tls-alpn-01 challenges on [default: 443]
  --onion-key <FILE>          Ed25519 onion service key PEM (required for onion-csr-01)
  --poll-timeout <SECS>       Seconds to wait for challenge validation [default: 120]
  --cert-key <FILE>           Reuse an existing certificate private key PEM
  --out <FILE>                Write the PEM certificate chain to this file
  --eab-kid <KID>             External Account Binding key ID
  --eab-key <KEY>             EAB HMAC key, base64url-encoded (no padding)
  --eab-alg <ALG>             EAB HMAC algorithm: HS256 | HS384 | HS512
                              [default: HS256]
```

Accepted `--key-type` and `--cert-key-type` values:
`ec:P-256`, `ec:P-384`, `ec:P-521`, `rsa:2048`, `rsa:3072`, `rsa:4096`,
`ed25519`, `ed448`, `ml-dsa-44`, `ml-dsa-65`, `ml-dsa-87`.

`http-01` and `tls-alpn-01` cannot validate wildcard domains; use `dns-01` or
`dns-persist-01` for `*.example.com`.

### `renew`

ARI-aware renewal (RFC 9773).  When `--cert` or `--renewal-config` is provided
and `--force` is not set, the command checks the ARI renewal window and skips
issuance if the window has not yet opened.

```
akamu-cli renew [OPTIONS]

Options:
  --renewal-config <FILE>     Load all settings from a .renewal.toml file
                              (written by `issue` or `import certbot`);
                              explicit flags override values from the file
  --server <URL>              ACME directory URL
  --domain <DOMAIN>, -d       Domain name (may be repeated)
  --account-key <FILE>        PEM file for the account key
  --key-type <TYPE>           Account key type [default: ec:P-256]
  --cert-key-type <TYPE>      Certificate key type [default: ec:P-256]
  --challenge <TYPE>          Challenge type [default: http-01]
  --dns-hook <CMD>            Hook script for dns-01 / dns-persist-01 automation
  --http-port <PORT>          [default: 80]
  --tls-port <PORT>           [default: 443]
  --onion-key <FILE>          Ed25519 onion service key PEM
  --poll-timeout <SECS>       [default: 120]
  --cert <FILE>               Existing certificate PEM for ARI window check
  --force                     Renew unconditionally, ignoring the ARI window
  --out <FILE>                Output path for the renewed PEM bundle
  --eab-kid <KID>             EAB key ID
  --eab-key <KEY>             EAB HMAC key (base64url)
  --eab-alg <ALG>             [default: HS256]
```

When `--renewal-config FILE` is given, all parameters are loaded from the TOML
file.  The command then checks ARI against the certificate path stored in the
config before proceeding.  After a successful renewal the `.renewal.toml` sidecar
is rewritten to reflect any updated paths.

### `revoke`

Revoke an issued certificate (RFC 8555 §7.6).

```
akamu-cli revoke [OPTIONS] --account-key <FILE> --cert <FILE>

Options:
  --server <URL>          ACME directory URL
  --account-key <FILE>    PEM file for the account key
  --cert <FILE>           PEM file containing the certificate to revoke
  --reason <N>            CRL reason code: 0–6 or 8–10 (omit for unspecified)
  --cert-key <FILE>       Certificate's own private key for self-revocation
```

### `import certbot`

Import accounts and certificates from an existing certbot installation.

```
akamu-cli import certbot [OPTIONS]

Options:
  --certbot-dir <DIR>         Certbot configuration directory
                              [default: /etc/letsencrypt]
  --account-key <FILE>        Output path for the imported account key PEM
                              (required unless --list)
  --server <URL>              Import only the account for this CA URL
  --domain <DOMAIN>, -d       Limit certificate import to these domains
                              (may be repeated; default: all)
  --cert-dir <DIR>            Directory to write imported certificate files
  --dns-challenge <TYPE>      Challenge type for DNS-based certbot configs
                              [default: dns-01]
  --dns-hook <CMD>            Hook script to store in generated renewal configs
  --dry-run                   Show actions without writing files
  --list                      List discovered accounts and certificates, then exit
```

The importer:

1. Reads `<certbot-dir>/accounts/<ca-hostname>/<account-id>/private_key.json`
   and converts the certbot JWK to a PEM file at `--account-key`.
2. Writes the account URL to `<account-key>.account-url` (the account URL
   sidecar).
3. For each renewal in `<certbot-dir>/renewal/*.conf`, copies
   `live/<domain>/fullchain.pem` and `live/<domain>/privkey.pem` into
   `--cert-dir` and writes a `<cert>.renewal.toml` sidecar.

Certbot's authenticator is mapped to an akamu challenge type:

| Certbot authenticator | akamu challenge type |
|---|---|
| `standalone`, `webroot`, `nginx`, `apache` | `http-01` |
| Any `dns-*` plugin | value of `--dns-challenge` |
| `manual` with `preferred_challenges = dns` | value of `--dns-challenge` |
| `tls-sni-01` | `tls-alpn-01` (with a deprecation notice) |

Wildcard domains (`*.example.com`) are handled automatically; certbot stores
them as `_wildcard.example.com/` in `live/`, and the importer encodes the `*`
form in the generated renewal configuration file.

Reading certbot's directories usually requires root access.  Use `--dry-run` to
preview the import first.

## Sidecar files

### Account URL sidecar

After a successful `account register` or inline registration inside `issue` or
`import certbot`, the account URL is written to a file named
`<account-key>.account-url` in the same directory as the account key.  For
example, if `--account-key` is `/etc/akamu/acme.pem`, the sidecar is
`/etc/akamu/acme.pem.account-url`.

`account deregister` reads this file to find the account URL and removes it
after deactivation.  `issue` and `renew` read it to skip re-registration when
the file already exists.

### Renewal sidecar

After every successful `issue`, a TOML file named `<out>.renewal.toml` is
written alongside the certificate chain.  It captures all parameters needed to
renew the certificate:

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
dns_hook        = "/etc/akamu/hooks/dns-update.sh"

[[domains]]
type  = "dns"
value = "example.com"

[[domains]]
type  = "dns"
value = "*.example.com"
```

Fields that have defaults (`account_key_type`, `cert_key_type`, `challenge_type`,
`http_port`, `tls_port`, `poll_timeout`, `eab_alg`) are optional in the TOML
file; missing fields are filled with sensible defaults on load.

Pass the file to `renew` for zero-configuration renewal:

```sh
akamu-cli renew --renewal-config /etc/ssl/example.com/fullchain.pem.renewal.toml
```

## DNS hook interface

When `--dns-hook <CMD>` is combined with `--challenge dns-01` or
`--challenge dns-persist-01`, the CLI calls `<CMD>` to add and remove TXT
records instead of waiting for manual input.

The hook is invoked as:

```
<CMD> add
<CMD> remove
```

Values are passed only through environment variables (never as command-line
arguments, which would be visible via `/proc/<pid>/cmdline`):

| Variable | Value |
|---|---|
| `AKAMU_DOMAIN` | DNS name being validated (wildcard prefix stripped) |
| `AKAMU_TOKEN` | ACME challenge token |
| `AKAMU_TXT` | TXT record value (`base64url(SHA-256(key_auth))`) |
| `AKAMU_KEY_AUTH` | Full key authorization string |

Exit code 0 → success.  Non-zero → `ClientError` (stderr is captured and shown).

For `dns-01`, the hook is called with `add` before challenge validation and with
`remove` after it completes.  For `dns-persist-01`, only `add` is called on
success (the TXT record is long-lived; it is removed only on validation failure).

## Example session

```sh
# 1. Register an account with Let's Encrypt.
akamu-cli account register \
  --account-key /etc/akamu/acme.pem \
  --key-type ec:P-256 \
  --contact mailto:admin@example.com \
  --agree-tos

# 2a. Issue a certificate via http-01 (port 80; requires root or CAP_NET_BIND_SERVICE).
akamu-cli issue \
  --account-key /etc/akamu/acme.pem \
  --domain example.com \
  --domain www.example.com \
  --out /etc/ssl/example.com/fullchain.pem

# 2b. Issue a wildcard certificate via dns-01 with a hook script.
akamu-cli issue \
  --account-key /etc/akamu/acme.pem \
  --domain "*.example.com" \
  --challenge dns-01 \
  --dns-hook /etc/akamu/hooks/dns-update.sh \
  --out /etc/ssl/example.com/wildcard.pem

# 3. Renew using the generated renewal config (suitable for cron).
akamu-cli renew \
  --renewal-config /etc/ssl/example.com/fullchain.pem.renewal.toml

# 4. Import from certbot and renew the first certificate.
sudo akamu-cli import certbot \
  --account-key /etc/akamu/acme.pem \
  --cert-dir /etc/akamu/certs \
  --dns-hook /etc/akamu/hooks/dns-update.sh

akamu-cli renew \
  --renewal-config /etc/akamu/certs/example.com.pem.renewal.toml

# 5. Deactivate the account when no longer needed.
akamu-cli account deregister \
  --account-key /etc/akamu/acme.pem
```

To use EAB during registration:

```sh
akamu-cli account register \
  --account-key /etc/akamu/acme.pem \
  --agree-tos \
  --eab-kid kid-from-ca \
  --eab-key base64url-hmac-key-from-ca
```

## Logging

Set the `RUST_LOG` environment variable to control log output.  The default
filter enables `INFO`-level messages from `akamu_client`.

```sh
RUST_LOG=debug akamu-cli issue ...
```

## Dependency note — PQC support

ML-DSA and other post-quantum primitives are provided via `native-ossl`, which
is published on crates.io.  No git fork or `[patch.crates-io]` block is
required in any workspace that depends on this crate.

## License

GPL-3.0-or-later
