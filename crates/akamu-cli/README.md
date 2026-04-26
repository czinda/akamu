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
next to the key (see "Sidecar file" below).

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

Only `http-01` challenge validation is built-in.  The challenge responder binds
on `0.0.0.0` at the port specified by `--http-port`; port 80 must be reachable
from the CA's validators or forwarded by an upstream proxy.

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
  --challenge <TYPE>          Challenge type (only http-01 is built-in)
                              [default: http-01]
  --http-port <PORT>          Port to serve http-01 challenges on [default: 80]
  --out <FILE>                Write the PEM certificate chain to this file
  --eab-kid <KID>             External Account Binding key ID
  --eab-key <KEY>             EAB HMAC key, base64url-encoded (no padding)
  --eab-alg <ALG>             EAB HMAC algorithm: HS256 | HS384 | HS512
                              [default: HS256]
```

Accepted `--key-type` and `--cert-key-type` values:
`ec:P-256`, `ec:P-384`, `ec:P-521`, `rsa:2048`, `rsa:3072`, `rsa:4096`,
`ed25519`, `ed448`, `ml-dsa-44`, `ml-dsa-65`, `ml-dsa-87`.

### `revoke`

Not yet implemented.  The command reads the certificate and account key files
but exits immediately with a notice.  Full revocation will be added once
`AcmeClient::revoke_certificate()` is available in `akamu-client`.

```
akamu-cli revoke [OPTIONS] --account-key <FILE> --cert <FILE>

Options:
  --server <URL>          ACME directory URL
  --account-key <FILE>    PEM file for the account key
  --cert <FILE>           PEM file containing the certificate to revoke
```

## Sidecar file

After a successful `account register` or inline registration inside `issue`,
the account URL is written to a file named `<account-key>.account-url` in the
same directory as the account key.  For example, if `--account-key` is
`/etc/akamu/acme.pem`, the sidecar is `/etc/akamu/acme.pem.account-url`.

`account deregister` reads this file to find the account URL and removes it
after deactivation.  `issue` reads it to skip re-registration when the file
already exists.

## Example session

```sh
# 1. Register an account with Let's Encrypt.
akamu-cli account register \
  --account-key /etc/akamu/acme.pem \
  --key-type ec:P-256 \
  --contact mailto:admin@example.com \
  --agree-tos

# Output: Generated new ec:P-256 key → /etc/akamu/acme.pem
# Output: Registered: https://acme-v02.api.letsencrypt.org/acme/acct/12345

# 2. Issue a certificate (http-01 on port 80; requires root or CAP_NET_BIND_SERVICE).
akamu-cli issue \
  --account-key /etc/akamu/acme.pem \
  --domain example.com \
  --domain www.example.com \
  --out /etc/akamu/chain.pem

# Output: Certificate written to /etc/akamu/chain.pem

# 3. Deactivate the account when no longer needed.
akamu-cli account deregister \
  --account-key /etc/akamu/acme.pem

# Output: Deactivated: https://acme-v02.api.letsencrypt.org/acme/acct/12345
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
