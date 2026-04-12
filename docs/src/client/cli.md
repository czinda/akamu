# akamu-cli — Command Reference

`akamu-cli` is a command-line ACME client that wraps `akamu-client`. It covers the full ACME lifecycle: account management, certificate issuance with multiple challenge types, ARI-aware renewal, and revocation.

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
| `--eab-kid KID` | no | External Account Binding key ID. |
| `--eab-key KEY_B64U` | no | EAB HMAC key encoded as base64url (no padding). |
| `--eab-alg ALG` | no | EAB HMAC algorithm: `HS256`, `HS384`, or `HS512`. Default: `HS256`. |

After registration the account URL is written to `<account-key>.account-url` (see [Sidecar file](#sidecar-file)).

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
| `--http-port PORT` | no | Port for the built-in http-01 solver. Default: `80`. |
| `--tls-port PORT` | no | Port for the built-in tls-alpn-01 solver. Default: `443`. |
| `--onion-key FILE` | required for `onion-csr-01` | Ed25519 hidden-service private key PEM file. |
| `--poll-timeout SECS` | no | Maximum seconds to wait for order/challenge validation. Default: `120`. |
| `--eab-kid KID` | no | EAB key ID (used if no account exists yet). |
| `--eab-key KEY_B64U` | no | EAB HMAC key (base64url). |

If the account URL sidecar file does not exist, `issue` registers a new account first.

The `http-01` and `tls-alpn-01` challenge types cannot validate wildcard identifiers (RFC 8555 §8.3, RFC 8737 §3). Use `dns-01` or `dns-persist-01` for `*.example.com`.

The certificate private key is generated and saved to `<out>.key.pem` unless `--cert-key` is provided.

### renew

Check the ARI renewal window (RFC 9773) for an existing certificate, then issue a replacement if renewal is suggested or `--force` is given.

```
akamu-cli renew --server URL --account-key FILE -d DOMAIN --out FILE [OPTIONS]
```

| Flag | Required | Description |
|---|---|---|
| `--server URL` | yes | ACME directory URL |
| `--account-key FILE` | yes | Account key PEM file |
| `-d DOMAIN` | yes (repeatable) | Domains for the new certificate |
| `--out FILE` | yes | Output path for the new PEM bundle |
| `--cert FILE` | no | Existing certificate PEM to check against ARI. Without this flag, no ARI check is performed. |
| `--force` | no | Renew unconditionally, skipping the ARI window check. |
| `--challenge TYPE` | no | Same values as `issue`. Default: `http-01`. |
| `--http-port PORT` | no | Default: `80`. |
| `--tls-port PORT` | no | Default: `443`. |
| `--onion-key FILE` | no | Required for `onion-csr-01`. |
| `--poll-timeout SECS` | no | Default: `120`. |
| `--key-type TYPE` | no | Account key type. Default: `ec:P-256`. |
| `--cert-key-type TYPE` | no | Certificate key type. Default: `ec:P-256`. |
| `--eab-kid KID` | no | EAB key ID. |
| `--eab-key KEY_B64U` | no | EAB HMAC key (base64url). |

Behavior when `--cert` is given and `--force` is not:

- If the current time is before the ARI window start, the command exits without issuing and prints a message.
- If the current time is within (or past) the window, issuance proceeds.
- If the server does not support ARI or returns an error, issuance proceeds with a warning.

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

## Sidecar file

When you register an account, `akamu-cli` writes the account URL to a file named `<account-key>.account-url` in the same directory as the account key. For example, if your account key is `~/.akamu/account.pem`, the sidecar is `~/.akamu/account.pem.account-url`.

The `issue`, `renew`, `deregister`, `account show`, `account update`, and `account key-change` subcommands read this file to find the account URL without re-registering.

If the sidecar is missing and you run `issue`, the CLI registers a new account first. If the sidecar is missing and you run `deregister`, the command fails with an error.

Keep the key file and sidecar file together and back them up. If you lose the account key, you cannot deactivate or otherwise manage the account.

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

### Issue with dns-01 (wildcard)

dns-01 is interactive: the CLI prints the TXT record to add and waits for you to press Enter.

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

### ARI-aware renewal

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

The server does not support the requested key type. Use a classical key type such as `ec:P-256`, or connect to an Akāmu server built with the PQC OpenSSL fork.
