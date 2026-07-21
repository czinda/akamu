# Migration Guide

This page documents breaking or significant configuration changes between
Akamu releases.  Each section describes what changed, why, and how to update
your `config.toml`.

---

## CLI subcommands: `serve`, `init`, `version`

The `akamu` binary now uses subcommands:

- **`akamu serve -c config.toml`** -- start the ACME server (previously `akamu config.toml`)
- **`akamu init`** -- generate a quickstart configuration file
- **`akamu version`** -- print version and build information

**Backward compatibility is preserved:** running `akamu` without a subcommand
still defaults to `serve` behaviour, and `akamu /path/to/config.toml` is
automatically rewritten to `akamu serve -c /path/to/config.toml` when the
argument looks like a file path.

### Before

```bash
akamu /etc/akamu/config.toml
RUST_LOG=debug akamu /etc/akamu/config.toml
```

### After (canonical form)

```bash
akamu serve -c /etc/akamu/config.toml
RUST_LOG=debug akamu serve -c /etc/akamu/config.toml
```

### Quickstart workflow

```bash
akamu init --system -u https://acme.example.com:9443
systemctl enable --now akamu
```

Update any custom systemd units or wrapper scripts to use the new
`akamu serve -c` form.  The shipped `akamu.service` unit already uses
the canonical invocation.

---

## Global `[mtc]` moved to per-CA `[ca.mtc]`

The top-level `[mtc]` section is **deprecated**.  MTC transparency log
configuration now lives inside each `[[ca]]` entry so that multi-CA
deployments can use independent logs with separate signing keys, hash
algorithms, and cosigner sets.

The global `[mtc]` section still works as a fallback: when a CA has no
`[ca.mtc]`, the server uses the global section for backward compatibility.
A deprecation warning is logged at startup when the global section is present.

### Before

```toml
[ca]
key_file  = "/etc/akamu/ca.key"
cert_file = "/etc/akamu/ca.crt"

[mtc]
enabled   = true
log_path  = "/var/lib/akamu/mtc.log"
hash_alg  = "sha256"

[mtc.signing_key]
key_file  = "/var/lib/akamu/mtc-signing.key"
```

### After

```toml
[[ca]]
id        = "default"
is_default = true
key_file  = "/etc/akamu/ca.key"
cert_file = "/etc/akamu/ca.crt"

[ca.mtc]
enabled   = true
log_path  = "/var/lib/akamu/mtc.log"
hash_alg  = "sha256"

[ca.mtc.signing_key]
key_file  = "/var/lib/akamu/mtc-signing.key"
```

With the `[[ca]]` array-of-tables syntax, each CA gets its own `[ca.mtc]`
subsection.  Remove the top-level `[mtc]` once all CAs carry their own.

---

## Admin API shares the ACME listener

The admin API no longer runs on a dedicated listener.  Admin endpoints
(`/admin/*`) are served on the same address as the ACME protocol endpoints.
The old `[admin]` fields `listen_addr`, `cert_file`, `key_file`, and
`ca_certs` have been removed.

Operator mTLS authentication is now configured through `[tls.client_auth]`
(see [TLS Configuration](tls.md)).  If you previously ran a separate admin
listener with its own TLS certificate, remove those fields and configure
server-wide TLS instead.

### Before

```toml
[admin]
listen_addr = "127.0.0.1:9443"
cert_file   = "/etc/akamu/admin-tls.pem"
key_file    = "/etc/akamu/admin-tls-key.pem"
ca_certs    = ["/etc/akamu/operator-ca.pem"]
```

### After

```toml
[tls]
enabled   = true
cert_file = "/etc/akamu/server.pem"
key_file  = "/etc/akamu/server-key.pem"

[tls.client_auth]
ca_files  = ["/etc/akamu/operator-ca.pem"]

[admin]
# No listen_addr, cert_file, key_file, or ca_certs here.
# Admin endpoints are served on the main listener.
```

If GSSAPI is the sole authentication method and no client certificates are
needed, the `[tls.client_auth]` section can be omitted entirely.

---

## `ca_certs` renamed to `ca_files` in `[tls.client_auth]`

The field that specifies trusted CA certificate PEM files for client
authentication was renamed from `ca_certs` to `ca_files`.  This applies to
the `[tls.client_auth]` section (which replaced the old per-admin-listener
`ca_certs` field described above).

### Before

```toml
[tls.client_auth]
ca_certs = ["/etc/akamu/operator-ca.pem"]
```

### After

```toml
[tls.client_auth]
ca_files = ["/etc/akamu/operator-ca.pem"]
```

---

## `challenge_solver` accepts all ACME challenge types

The `[delegation_upstream]` section's `challenge_solver` field now accepts
three values: `"dns-01"`, `"http-01"`, and `"tls-alpn-01"`.  Previously only
`"dns-01"` was supported.

When using `"dns-01"`, a `challenge_deploy_script` is still required.  The
`"http-01"` and `"tls-alpn-01"` solvers do not require deploy scripts.

### Before

```toml
[delegation_upstream]
directory_url    = "https://acme.upstream.example/acme/directory"
account_key_file = "/etc/akamu/upstream-account.key"
challenge_solver = "dns-01"
challenge_deploy_script  = "/usr/local/bin/deploy-dns-txt.sh"
challenge_cleanup_script = "/usr/local/bin/cleanup-dns-txt.sh"
```

### After (unchanged for dns-01)

```toml
[delegation_upstream]
directory_url    = "https://acme.upstream.example/acme/directory"
account_key_file = "/etc/akamu/upstream-account.key"
challenge_solver = "dns-01"
challenge_deploy_script  = "/usr/local/bin/deploy-dns-txt.sh"
challenge_cleanup_script = "/usr/local/bin/cleanup-dns-txt.sh"
```

### After (new http-01 option)

```toml
[delegation_upstream]
directory_url    = "https://acme.upstream.example/acme/directory"
account_key_file = "/etc/akamu/upstream-account.key"
challenge_solver = "http-01"
```

### After (new tls-alpn-01 option)

```toml
[delegation_upstream]
directory_url    = "https://acme.upstream.example/acme/directory"
account_key_file = "/etc/akamu/upstream-account.key"
challenge_solver = "tls-alpn-01"
```

---

## Proxy-forwarded client certificate authentication

A new `[admin.proxy_auth]` section enables operator mTLS authentication when
Akamu runs behind a TLS-terminating reverse proxy (Nginx, Apache, Envoy).
The proxy forwards the verified client certificate in an HTTP header and
Akamu reads it from there instead of performing the TLS handshake itself.

This is an addition, not a replacement.  Direct mTLS via `[tls.client_auth]`
continues to work for deployments where the TLS handshake reaches Akamu
directly.

### Configuration

```toml
[admin.proxy_auth]
trusted_proxies = ["127.0.0.1/32", "::1/128"]
header_format   = "x-ssl-client-cert"
```

| Field | Default | Description |
|-------|---------|-------------|
| `trusted_proxies` | (required) | CIDR ranges or `"local addresses"` for proxy IPs allowed to inject the header. |
| `header_format` | `"x-ssl-client-cert"` | Header convention: `"x-ssl-client-cert"` (Nginx), `"ssl-client-cert"` (Apache), or `"xfcc"` (Envoy). |

Only requests from a trusted proxy IP have the forwarded certificate header
read.  Requests from other IPs ignore the header, preventing spoofing.

### Nginx example

```nginx
location /admin/ {
    proxy_pass http://127.0.0.1:8080;
    proxy_set_header X-SSL-Client-Cert $ssl_client_escaped_cert;
}
```

```toml
[admin.proxy_auth]
trusted_proxies = ["127.0.0.1/32"]
header_format   = "x-ssl-client-cert"
```

See [TLS Configuration -- Proxy-forwarded client certificates](tls.md) for
the full setup walkthrough.
