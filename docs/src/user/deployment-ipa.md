# FreeIPA Co-deployment

This guide covers running akamu on the same host as a FreeIPA server, proxied
behind IPA's Apache httpd at the `/acme` path prefix. IPA manages TLS
termination and DNS; akamu focuses on ACME certificate issuance and operator
authentication via Kerberos.

The complete configuration files and Ansible automation described here live in
[`contrib/demo/ipa/`](https://github.com/akamu-dev/akamu/tree/main/contrib/demo/ipa/).

## Topology

```
Client (certbot / acme.sh)
    │  HTTPS  /acme/acme/directory
    ▼
IPA Apache httpd (TLS termination)
    │  mod_proxy  /acme/ → unix socket
    ▼
akamu (Unix domain socket /run/akamu/akamu.sock)
    │  GSS_USE_PROXY=yes
    ▼
gssproxy daemon (reads /var/lib/ipa/gssproxy/http.keytab)
    │  S4U2Self / S4U2Proxy
    ▼
IPA KDC / IPA LDAP (optional profile fetch)
```

akamu never touches the HTTP keytab directly. gssproxy mediates all Kerberos
operations and enforces that only the `akamu` OS user can obtain the HTTP
service credential.

## Prerequisites

- FreeIPA server installed and running on the target host.
- The `HTTP/<fqdn>@REALM` service principal registered in IPA (created
  automatically when IPA is installed on the host).
- `gssproxy` installed (part of the standard IPA server package set on
  Fedora/RHEL).
- `akamu` installed from the
  [abbra/synta COPR](https://copr.fedorainfracloud.org/coprs/abbra/synta/):

  ```bash
  dnf copr enable abbra/synta
  dnf install akamu
  ```

## Step 1 — gssproxy service entry

Create `/etc/gssproxy/20-akamu.conf` (from
[`contrib/demo/ipa/akamu-gssproxy.conf`](https://github.com/akamu-dev/akamu/tree/main/contrib/demo/ipa/akamu-gssproxy.conf)):

```ini
[service/akamu]
  mechs = krb5
  cred_store = keytab:/var/lib/ipa/gssproxy/http.keytab
  cred_store = client_keytab:/var/lib/ipa/gssproxy/http.keytab
  allow_protocol_transition = true
  allow_constrained_delegation = true
  cred_usage = both
  euid = akamu
```

Then restart gssproxy:

```bash
systemctl restart gssproxy
```

`cred_usage = both` is required: akamu acts as both an acceptor (validating
incoming SPNEGO tokens from ACME clients and admin operators) and an initiator
(obtaining service tickets for LDAP profile fetches when
`[profiles.providers.ipa]` is enabled).

## Step 2 — akamu configuration

Create `/etc/akamu/config.toml` (from
[`contrib/demo/ipa/akamu.toml`](https://github.com/akamu-dev/akamu/tree/main/contrib/demo/ipa/akamu.toml),
substituting your FQDN and realm):

```toml
listen_addr = "unix:/run/akamu/akamu.sock"
base_url    = "https://ipa.example.com/acme"

[database]
url = "sqlite:///var/lib/akamu/akamu.db"

[ca]
key_file  = "/etc/akamu/certs/ca.key.pem"
cert_file = "/etc/akamu/certs/ca.cert.pem"
key_type  = "ec:P-256"
hash_alg  = "sha256"

[server]
validate_dnssec = true

[server.gssapi]
gssproxy = true

[admin]
bootstrap_operator_gssapi_principal = "admin@EXAMPLE.COM"

[admin.gssapi]
gssproxy = true
```

`gssproxy = true` tells akamu to set `GSS_USE_PROXY=yes` at startup and acquire
its acceptor credential via gssproxy rather than reading the keytab directly.
`service_name` defaults to `"HTTP"` and does not need to be set explicitly.

`bootstrap_operator_gssapi_principal` seeds the first akamu Administrator from
the IPA `admin` principal on first run (when the operators table is empty).
Remove this line after the initial operator account has been created.

## Step 3 — Apache proxy

Create `/etc/httpd/conf.d/ipa-acme-proxy.conf` (from
[`contrib/demo/ipa/ipa-acme-proxy.conf`](https://github.com/akamu-dev/akamu/tree/main/contrib/demo/ipa/ipa-acme-proxy.conf)):

```apache
ProxyPass        /acme/  unix:/run/akamu/akamu.sock|http://localhost/  nocanon
ProxyPassReverse /acme/  http://localhost/
ProxyPassReverseCookiePath / /acme/
ProxyPreserveHost On
RedirectMatch permanent ^/acme$ /acme/

<Location "/acme/">
    AuthType None
    Require all granted
    SSLOptions +StdEnvVars +ExportCertData +StrictRequire
    SSLVerifyClient none
    RequestHeader set X-Forwarded-Proto "https"
    Header always set    X-Content-Type-Options "nosniff"
    Header always append X-Frame-Options "DENY"
    Header always append Content-Security-Policy "frame-ancestors 'none'"
</Location>

RewriteCond %{SERVER_PORT} !^443$
RewriteRule ^/acme/(.*)  https://%{HTTP_HOST}/acme/$1 [L,R=307,NC]
```

## Step 4 — socket permissions

The akamu Unix socket lives in `/run/akamu/` (mode `0710`, owned by
`akamu:akamu`). Apache must be in the `akamu` group to connect:

```bash
usermod -aG akamu apache
systemctl reload httpd
```

## Step 5 — start akamu

```bash
systemctl enable --now akamu
```

Verify startup in the journal:

```bash
journalctl -u akamu -n 50
```

Expected lines on a healthy start:

```
INFO gssproxy mode enabled: GSS_USE_PROXY=yes
INFO initializing GSSAPI credential for service 'HTTP'
INFO acquiring GSSAPI credential via gssproxy
INFO akamu listening on unix:/run/akamu/akamu.sock
```

The ACME directory is now available at:

```
https://ipa.example.com/acme/acme/directory
```

## Bootstrapping the first admin

On first run, akamu registers `admin@EXAMPLE.COM` (or whichever principal you
set in `bootstrap_operator_gssapi_principal`) as an Administrator. Confirm the
account was created:

```bash
kinit admin
akamuctl --url https://ipa.example.com/acme --gssapi operators list
```

After the initial operator is confirmed, remove `bootstrap_operator_gssapi_principal`
from `config.toml` and restart akamu so the boot-strap path is no longer active.

## Optional — IPAThinCA certificate profiles

To expose FreeIPA CA certificate profiles via ACME, add a
`[profiles.providers.ipa]` section. The HTTP service principal needs read access
to `o=ipaca`; on Fedora/RHEL IPA this subtree is readable by any IPA-enrolled
principal. See the commented block in `contrib/demo/ipa/akamu.toml` for the
full LDAP connection configuration.

The `ipa_permissions.yml` Ansible playbook in `contrib/demo/ipa/ansible/`
creates an explicit `Akamu IPA CA Read` IPA privilege and assigns it to the
HTTP service principal for auditability.

## Automated deployment with Ansible

The `contrib/demo/ipa/ansible/` directory contains a complete Ansible setup
that installs FreeIPA, deploys akamu on every node, and grants IPA privileges
in one command:

```bash
cd contrib/demo/ipa/ansible
cp inventory.ini.example inventory.ini
# Edit inventory.ini: set hostnames, ipa_domain, ipa_realm, passwords
ansible-playbook -i inventory.ini site.yml
```

See [`contrib/demo/ipa/ansible/README.md`](https://github.com/akamu-dev/akamu/tree/main/contrib/demo/ipa/ansible/README.md)
for the full reference, including standalone (non-replica) node setup with
S4U2Proxy constrained delegation.

## Troubleshooting

| Symptom | Check |
|---|---|
| akamu not starting | `journalctl -u akamu` — often a config parse error or missing DB directory (`/var/lib/akamu/`) |
| `502 Bad Gateway` from Apache | `ls -la /run/akamu/` — the socket must be group-accessible; run `usermod -aG akamu apache && systemctl reload httpd` |
| `GSS_USE_PROXY` not appearing in logs | Confirm `gssproxy = true` is set in `[server.gssapi]` or `[admin.gssapi]` |
| gssproxy errors | `journalctl -u gssproxy` — verify `/etc/gssproxy/20-akamu.conf` has `euid = akamu` and the keytab path is correct |
| `401 Unauthorized` on ACME requests | The client's Kerberos ticket may have expired; run `kinit` and retry |
| Admin operator login fails | Confirm `akamuctl --url ... --gssapi` is used and the operator is in the akamu database: `akamuctl operators list` |
| Certificate issuance fails with profile errors | Enable `[profiles.providers.ipa]` and run `ipa_permissions.yml` to grant CA LDAP read access |
