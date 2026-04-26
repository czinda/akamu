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
akamu /etc/akamu/config.toml
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

## Logging

The server uses the `tracing` crate. Control log verbosity with the `RUST_LOG` environment variable:

```
RUST_LOG=debug akamu /etc/akamu/config.toml
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
