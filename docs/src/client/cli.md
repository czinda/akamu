# akamu-cli — Command Reference

`akamu-cli` is a command-line ACME client that wraps `akamu-client`. It covers the most common operations: registering an account, issuing a certificate, and deregistering an account.

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

## Global flags

Every subcommand accepts:

| Flag | Description |
|---|---|
| `--server URL` | ACME directory URL (required) |
| `--account-key FILE` | Path to the PEM account key file (required) |

## Subcommands

### account register

Register a new ACME account and save the account URL to a sidecar file.

```
akamu-cli account register --server URL --account-key FILE [OPTIONS]
```

| Flag | Required | Description |
|---|---|---|
| `--server URL` | yes | ACME directory URL |
| `--account-key FILE` | yes | Path to the account key PEM file. If the file does not exist, a new key is generated and saved. |
| `--key-type TYPE` | no | Key type to generate when the key file does not exist. Default: `ec:P-256`. |
| `--contact URI` | no | Contact URI (e.g. `mailto:admin@example.com`). Repeatable. |
| `--agree-tos` | no | Agree to the server's Terms of Service. |
| `--eab-kid KID` | no | External Account Binding key ID. |
| `--eab-key KEY_B64U` | no | EAB HMAC key encoded as base64url (no padding). |
| `--eab-alg ALG` | no | EAB HMAC algorithm. One of `HS256`, `HS384`, `HS512`. Default: `HS256`. |

After registration the account URL is written to `<account-key>.account-url` (see [Sidecar file](#sidecar-file)).

### account deregister

Deactivate an existing account.

```
akamu-cli account deregister --server URL --account-key FILE
```

The account URL is read from `<account-key>.account-url`. After deactivation the sidecar file is removed.

### issue

Obtain a certificate for one or more domains.

```
akamu-cli issue --server URL --account-key FILE -d DOMAIN [OPTIONS]
```

| Flag | Required | Description |
|---|---|---|
| `--server URL` | yes | ACME directory URL |
| `--account-key FILE` | yes | Account key PEM file |
| `-d DOMAIN` | yes (repeatable) | Domain to include. Use once per domain. The first `-d` value becomes the CN. |
| `--out FILE` | yes | Output path for the PEM bundle (leaf + chain). |
| `--key-type TYPE` | no | Account key type when generating a new key. Default: `ec:P-256`. |
| `--cert-key-type TYPE` | no | Certificate (end-entity) key type. Default: `ec:P-256`. |
| `--challenge TYPE` | no | Challenge type. Currently only `http-01` is supported. Default: `http-01`. |
| `--http-port PORT` | no | Port for the built-in http-01 solver. Default: `80`. |
| `--eab-kid KID` | no | EAB key ID (used if account has not been registered yet). |
| `--eab-key KEY_B64U` | no | EAB HMAC key (base64url). |

If the account URL sidecar file does not exist, `issue` registers a new account before placing the order.

### revoke (stub)

```
akamu-cli revoke --server URL --account-key FILE --cert FILE
```

> **Note:** Certificate revocation is not yet implemented. This subcommand is a placeholder. As a workaround, use certbot or acme.sh with the same ACME server directory URL to perform revocation.

## Sidecar file

When you register an account, `akamu-cli` writes the account URL to a file named `<account-key>.account-url` in the same directory as the account key. For example, if your account key is `~/.akamu/account.pem`, the sidecar is `~/.akamu/account.pem.account-url`.

The `issue` and `deregister` subcommands read this file to find the account URL without contacting the server. This avoids creating a duplicate account on repeated invocations.

If the sidecar is missing and you run `issue`, the CLI registers a new account first. If the sidecar is missing and you run `deregister`, the command fails with an error.

Keep the key file and sidecar file together and back them up. If you lose the account key, you cannot deactivate or otherwise manage the account.

## Example session

### 1. Register an account

```bash
akamu-cli account register \
  --server https://acme.example.com/acme/directory \
  --account-key ~/.akamu/account.pem \
  --key-type ec:P-256 \
  --contact mailto:admin@example.com \
  --agree-tos
```

Output:
```
Generated account key ec:P-256 at /home/user/.akamu/account.pem
Registered account: https://acme.example.com/acme/account/1234
Saved account URL to /home/user/.akamu/account.pem.account-url
```

### 2. Issue a certificate

```bash
akamu-cli issue \
  --server https://acme.example.com/acme/directory \
  --account-key ~/.akamu/account.pem \
  -d example.com \
  -d www.example.com \
  --out /etc/ssl/example.com/fullchain.pem \
  --cert-key-type ec:P-256
```

Port 80 must be reachable for http-01 validation. The CLI starts a temporary HTTP server during challenge validation and shuts it down afterwards.

### 3. Deregister the account

```bash
akamu-cli account deregister \
  --server https://acme.example.com/acme/directory \
  --account-key ~/.akamu/account.pem
```

## External Account Binding

Some CAs require EAB credentials before accepting a new account. Obtain a KID and HMAC key from your CA's operator, then pass them to `account register` or `issue`:

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

If the server has `external_account_required = true` and you omit the EAB flags, registration fails with `urn:ietf:params:acme:error:externalAccountRequired`.

## Key type selection

| Use case | Recommended type | Notes |
|---|---|---|
| Default / broadest compatibility | `ec:P-256` | Widely supported, fast, small signatures |
| Stronger classical security | `ec:P-384` or `rsa:3072` | Use when policy requires |
| Post-quantum account key | `ml-dsa-65` | Larger signatures; check server support |
| Post-quantum certificate key | `ml-dsa-44` | Smallest PQ key; suitable for most cases |
| Legacy RSA-only environments | `rsa:2048` or `rsa:4096` | Avoid unless forced by policy |

ML-DSA keys require that the Akāmu server is built with the PQC OpenSSL fork. Vanilla Let's Encrypt does not support ML-DSA.

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

The server rejected the nonce. This can happen if the server was restarted between requests. Retry the command; the CLI fetches a fresh nonce at startup.

**`ACME error urn:ietf:params:acme:error:incorrectResponse`**

The server could not validate the http-01 challenge. Verify that port 80 is reachable from the server's IP address and that no firewall or reverse proxy is intercepting `.well-known/acme-challenge/` requests.

**`ACME error urn:ietf:params:acme:error:externalAccountRequired`**

The server requires EAB credentials. Pass `--eab-kid` and `--eab-key`.

**`Failed to bind port 80: Permission denied`**

The http-01 solver needs to listen on port 80. Either run with `sudo`, grant `CAP_NET_BIND_SERVICE` to the binary, or use an iptables redirect from port 80 to a high port and pass `--http-port <high-port>`.

**`Error: No such file: account.pem.account-url`**

The sidecar file is missing. Run `account register` first, or restore the sidecar from a backup.

**`Unsupported algorithm: ML-DSA-65`**

The server does not support the requested key type. Use a classical key type such as `ec:P-256`, or connect to an Akāmu server built with the PQC OpenSSL fork.
