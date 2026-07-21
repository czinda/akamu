# First Run

This chapter walks through the minimal steps to get `Akāmu` running and reachable by ACME clients.

## 1. Create directories

```
sudo mkdir -p /etc/akamu /var/lib/akamu
sudo chown akamu:akamu /etc/akamu /var/lib/akamu
sudo chmod 0750 /etc/akamu /var/lib/akamu
```

## 2. Write a minimal configuration file

Copy the example configuration and adjust it:

```
sudo cp config.toml.example /etc/akamu/config.toml
sudo chmod 0640 /etc/akamu/config.toml
```

At a minimum you need:

```toml
listen_addr = "0.0.0.0:8080"
base_url    = "https://acme.example.com"

[database]
url = "sqlite:///var/lib/akamu/akamu.db"

[ca]
key_file  = "/etc/akamu/ca.key.pem"
cert_file = "/etc/akamu/ca.cert.pem"

[mtc]
log_path = "/var/lib/akamu/mtc.log"
enabled  = false
```

Replace `acme.example.com` with the actual hostname your ACME clients will use.

> **Note:** `listen_addr` is the address the server binds to. `base_url` is the public-facing URL that appears in all ACME responses, including the directory and certificate URLs. They do not have to match — for example you might bind on `0.0.0.0:8080` and have a reverse proxy forward HTTPS traffic from port 443 to that address.

## 3. Start the server

```
akamu serve -c /etc/akamu/config.toml
```

On first run, because neither `ca.key.pem` nor `ca.cert.pem` exist, the server generates a new EC P-256 CA key and a 10-year self-signed CA certificate and writes them to the configured paths. You will see log output like:

```
INFO akamu: loading config from '/etc/akamu/config.toml'
INFO akamu: opening database '/var/lib/akamu/akamu.db'
INFO akamu: loading CA from '/etc/akamu/ca.key.pem'
INFO akamu::ca::init: Generating new CA key (ec:P-256) — writing to /etc/akamu/ca.key.pem and /etc/akamu/ca.cert.pem
INFO akamu::ca::init: Generated CA certificate (ec:P-256, 10 years)
INFO akamu: ACME server listening on 0.0.0.0:8080 (base_url=https://acme.example.com)
```

## 4. Verify the server is running

```
curl -s https://acme.example.com/acme/directory | python3 -m json.tool
```

Expected output:

```json
{
    "keyChange": "https://acme.example.com/acme/key-change",
    "meta": {},
    "newAccount": "https://acme.example.com/acme/new-account",
    "newNonce": "https://acme.example.com/acme/new-nonce",
    "newOrder": "https://acme.example.com/acme/new-order",
    "revokeCert": "https://acme.example.com/acme/revoke-cert"
}
```

## 5. Install the CA certificate in your trust store (optional)

ACME clients will reject certificates issued by an unknown CA unless you install the CA certificate in your system's trust store or tell the client to trust it explicitly.

Copy the CA certificate:

```
sudo cp /etc/akamu/ca.cert.pem /usr/local/share/ca-certificates/akamu-ca.crt
sudo update-ca-certificates          # Debian/Ubuntu
# or
sudo update-ca-trust                 # Fedora/RHEL
```

## 6. Enable admin access (optional)

The admin API lets you manage operators, certificates, EAB keys, and audit logs through [`akamuctl`](../user/akamuctl.md). It requires TLS with client certificate authentication on the server listener.

Add the following sections to `/etc/akamu/config.toml` and update `listen_addr` and `base_url` for HTTPS:

```toml
listen_addr = "0.0.0.0:8443"
base_url    = "https://acme.example.com:8443"

# ... existing [database], [ca], [mtc] sections ...

[tls]
enabled     = true
cert_file   = "/etc/akamu/server.crt"
key_file    = "/etc/akamu/server.key"
server_name = "acme.example.com"

[tls.client_auth]
ca_files = ["/etc/akamu/ca.cert.pem"]
required = false

[admin]
bootstrap_operator_cert_file = "/etc/akamu/admin-bootstrap.pem"
bootstrap_operator_key_file  = "/etc/akamu/admin-bootstrap-key.pem"
```

Setting `required = false` in `[tls.client_auth]` lets ACME clients connect without a client certificate while still allowing operator authentication via mTLS.

On the next start, because the TLS and bootstrap files do not exist yet, Akamu auto-generates a server TLS certificate and a bootstrap operator certificate (both signed by the CA), and registers the bootstrap operator with the `administrator` role.

Log in with the bootstrap certificate:

```bash
akamuctl --server-url https://acme.example.com:8443 \
         --ca-cert /etc/akamu/ca.cert.pem \
         --cert    /etc/akamu/admin-bootstrap.pem \
         --key     /etc/akamu/admin-bootstrap-key.pem \
    login
```

The session token is cached in `~/.config/akamu/session.json` and reused automatically for subsequent commands.

Verify admin access:

```bash
akamuctl stats       # server counters and version
akamuctl ca list     # configured certificate authorities
```

For the full endpoint reference, see [Admin API and Operator Management](../user/admin-api.md). For all CLI commands, see [akamuctl](../user/akamuctl.md). See [TLS Configuration](../user/tls.md) for advanced TLS setups including proxy-forwarded client certificates.

## Logging

The server uses the `tracing` crate. Control log verbosity with the `RUST_LOG` environment variable:

```
RUST_LOG=debug akamu serve -c /etc/akamu/config.toml
```

Useful levels: `error`, `warn`, `info` (default), `debug`, `trace`.

## Reverse proxy configuration (nginx)

The server speaks plain HTTP internally. An nginx TLS termination configuration:

```nginx
server {
    listen 443 ssl;
    server_name acme.example.com;

    ssl_certificate     /etc/nginx/ssl/acme.example.com.crt;
    ssl_certificate_key /etc/nginx/ssl/acme.example.com.key;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

## Running behind a reverse proxy (Unix socket)

Instead of binding a TCP port, Akāmu can listen on a Unix domain socket. This avoids exposing a TCP port and simplifies firewall rules when the reverse proxy runs on the same host.

Set `listen_addr` to a `unix:` path (TLS must be absent or disabled — the proxy terminates TLS):

```toml
listen_addr = "unix:/run/akamu/akamu.sock"
base_url    = "https://acme.example.com"
# No [tls] section — TLS is terminated at the proxy
```

The `AKAMU_LISTEN` environment variable overrides `listen_addr` without touching the config file:

```
AKAMU_LISTEN=unix:/run/akamu/akamu.sock akamu serve -c /etc/akamu/config.toml
```

### nginx

```nginx
server {
    listen 443 ssl;
    server_name acme.example.com;

    ssl_certificate     /etc/nginx/ssl/acme.example.com.crt;
    ssl_certificate_key /etc/nginx/ssl/acme.example.com.key;

    location / {
        proxy_pass http://unix:/run/akamu/akamu.sock;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

### Apache

```apache
ProxyPass        / unix:/run/akamu/akamu.sock|http://localhost/
ProxyPassReverse / unix:/run/akamu/akamu.sock|http://localhost/
```

### Trusted proxies and X-Remote-User

If you use `server.trusted_proxies` for admin auth via `X-Remote-User`, all connections arriving over a Unix socket are treated as locally trusted (no CIDR check). The header is still required — any connection without it receives a 401.

### systemd socket activation

The provided unit files support socket activation, which lets systemd pre-bind the socket before the service starts:

```
systemctl enable --now akamu.socket akamu.service
```

The socket is created at `/run/akamu/akamu.sock` (mode `0660`). The reverse proxy process must be in group `akamu` to connect. When using socket activation, `listen_addr` in the config file is ignored — the pre-bound socket is passed via `LISTEN_FDS`.

Stale socket files are removed automatically on config-based startup. Under socket activation, systemd owns the socket file and no cleanup is needed.
