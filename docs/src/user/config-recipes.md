# Common Configuration Patterns

This page provides complete, ready-to-use configuration files for common
deployment scenarios. Each recipe is a self-contained `config.toml` that you
can copy, adjust the paths and hostnames, and start using immediately.

For the authoritative description of every key, see the
[Configuration Reference](configuration.md).

---

## Minimal ACME Server

The simplest possible configuration: SQLite storage, an auto-generated CA key
pair, and http-01 challenge validation. Suitable for development, testing, or
small internal deployments.

The CA key and certificate are generated on first run if the files do not exist.

```toml
# minimal.toml -- smallest viable ACME server.
#
# Start with:   akamu minimal.toml
# Directory at: https://acme.example.com/acme/directory

# Bind on all interfaces, port 8080.  Put a TLS-terminating reverse proxy
# in front for production use, or enable [tls] below.
listen_addr = "0.0.0.0:8080"

# Public URL that ACME clients use to reach this server.
# Must match the URL exposed by your reverse proxy or DNS.
base_url = "https://acme.example.com"

# ── Database ─────────────────────────────────────────────────────────────────
[database]
# SQLite file database -- created automatically on first run.
url = "sqlite:///var/lib/akamu/acme.db"

# ── Certificate Authority ────────────────────────────────────────────────────
[ca]
# Auto-generated on first run if both files are absent.
key_file  = "/etc/akamu/ca.key.pem"
cert_file = "/etc/akamu/ca.cert.pem"

# ECDSA P-256 is the default; shown here for clarity.
key_type = "ec:P-256"

# 90-day end-entity certificates (the ACME ecosystem default).
validity_days = 90

# CA certificate lasts 10 years.
ca_validity_years = 10

# Subject fields for the auto-generated CA certificate.
common_name  = "My ACME CA"
organization = "My Organization"

# ── Server ───────────────────────────────────────────────────────────────────
[server]
# No EAB required -- any client can register an account and request certs.
external_account_required = false

# Orders and authorizations expire after 24 hours.
order_expiry_secs = 86400
authz_expiry_secs = 86400
```

---

## Internal PKI with Kerberos EAB

Enterprise deployment using GSSAPI/SPNEGO authentication for account
registration. Accounts are bound to Kerberos principals via External Account
Binding, and certificate profiles restrict which identifiers each account
may request.

This configuration is typical for FreeIPA or Active Directory environments
where every ACME client already holds a Kerberos TGT.

```toml
# kerberos-eab.toml -- Kerberos-authenticated internal PKI.
#
# Clients authenticate with:
#   1. kinit (obtain TGT)
#   2. GET /acme/eab with Negotiate auth -> receive (kid, hmac_key)
#   3. POST /acme/new-account with externalAccountBinding

listen_addr = "0.0.0.0:8443"
base_url    = "https://acme.internal.example.com"

[database]
url = "sqlite:///var/lib/akamu/acme.db"

[ca]
key_file  = "/etc/akamu/ca.key.pem"
cert_file = "/etc/akamu/ca.cert.pem"
key_type  = "ec:P-256"
hash_alg  = "sha256"

validity_days     = 90
ca_validity_years = 10
common_name       = "Internal PKI CA"
organization      = "Example Corp"

# CRL and OCSP endpoints using the built-in handlers.
crl_url  = "https://acme.internal.example.com/ca/crl"
ocsp_url = "https://acme.internal.example.com/ca/ocsp"

[server]
# Every new account must present EAB credentials.
external_account_required = true

# Deterministic EAB derivation from Kerberos principals via HKDF.
# Generate with: openssl rand -base64 32 | tr '+/' '-_' | tr -d '='
eab_master_secret = "REPLACE_WITH_YOUR_BASE64URL_SECRET_AT_LEAST_32_BYTES"

# CAA checking for internal domains.
caa_identities = ["acme.internal.example.com"]

# DNSSEC validation -- set to false if your internal DNS is unsigned.
validate_dnssec = false

# ── Standalone GSSAPI authentication ─────────────────────────────────────────
# Akamu handles Authorization: Negotiate directly (no reverse proxy needed
# for Kerberos).  Clients must have a service ticket for
# HTTP/acme.internal.example.com@EXAMPLE.COM.
[server.gssapi]
keytab_file  = "/etc/akamu/http.keytab"
service_name = "HTTP"

# ── TLS (akamu terminates TLS itself) ────────────────────────────────────────
[tls]
enabled   = true
cert_file = "/etc/akamu/server.pem"
key_file  = "/etc/akamu/server-key.pem"

# ── Certificate profiles ─────────────────────────────────────────────────────
[profiles]
refresh_interval_secs = 3600

[profiles.providers.local]
type = "builtin"

# Standard TLS server certificate -- restricted to *.internal.example.com.
[profiles.providers.local.profiles.internal-tls]
description        = "Internal TLS server certificate"
validity_days      = 90
key_usage          = ["digital_signature", "key_encipherment"]
eku                = ["server_auth"]
allowed_key_types  = ["ec:P-256", "ec:P-384", "rsa:2048", "rsa:4096"]
allowed_identifiers = ["dns:.*\\.internal\\.example\\.com$"]
identifier_match    = "all"

# Client authentication certificate with Kerberos principal SAN.
# The account's Kerberos principal (from EAB) is injected as a
# KRB5PrincipalName OtherName SAN.
[profiles.providers.local.profiles.kerberos-client]
description         = "Kerberos client authentication certificate"
validity_days       = 30
key_usage           = ["digital_signature"]
eku                 = ["client_auth"]
inject_account_kpn  = true
require_account_grant = true
```

---

## Reverse Proxy Deployment

Akamu behind Nginx with a Unix domain socket, proxy-forwarded mTLS for the
admin API, and Kerberos authentication delegated to the proxy for ACME EAB.

This is the recommended production layout when you already have Nginx (or
another reverse proxy) handling TLS termination and Kerberos/SPNEGO.

```toml
# reverse-proxy.toml -- behind Nginx with Unix socket.
#
# Nginx handles:
#   - TLS termination
#   - Kerberos/SPNEGO authentication (via mod_auth_gssapi or similar)
#   - Client certificate verification for admin operators
#
# Nginx forwards:
#   - X-Remote-User header (authenticated Kerberos principal)
#   - X-SSL-Client-Cert header (URL-encoded client cert PEM)

# Listen on a Unix domain socket -- only the reverse proxy connects here.
# TLS is not used on this socket (terminated by Nginx).
listen_addr = "unix:/run/akamu/akamu.sock"

# The URL that clients see (via Nginx).
base_url = "https://acme.example.com"

[database]
url = "sqlite:///var/lib/akamu/acme.db"

[ca]
key_file  = "/etc/akamu/ca.key.pem"
cert_file = "/etc/akamu/ca.cert.pem"
key_type  = "ec:P-256"
hash_alg  = "sha256"

validity_days     = 90
ca_validity_years = 10
common_name       = "Example ACME CA"
organization      = "Example Org"

crl_url  = "https://acme.example.com/ca/crl"
ocsp_url = "https://acme.example.com/ca/ocsp"

[server]
# EAB via Kerberos -- the proxy authenticates and forwards X-Remote-User.
external_account_required = true
eab_master_secret = "REPLACE_WITH_YOUR_BASE64URL_SECRET_AT_LEAST_32_BYTES"

# Trust Nginx to supply X-Remote-User.
# "local addresses" matches all IPs on local interfaces (the proxy is on
# the same host as Akamu, connected via the Unix socket).
trusted_proxies = ["local addresses"]

# ── Note: [tls] is intentionally absent ──────────────────────────────────────
# Unix domain sockets and [tls] are mutually exclusive.  TLS is handled by
# Nginx.  Do NOT add a [tls] section here.

# ── Admin API ────────────────────────────────────────────────────────────────
# Nginx verifies admin operator client certificates and forwards them in the
# X-SSL-Client-Cert header.
[admin]
session_ttl_secs = 3600

# Proxy-forwarded client certificate authentication.
[admin.proxy_auth]
trusted_proxies = ["local addresses"]
header_format   = "x-ssl-client-cert"

# Auto-generate a bootstrap admin operator on first run.
# bootstrap_operator_cert_file = "/etc/akamu/admin-bootstrap.pem"
# bootstrap_operator_key_file  = "/etc/akamu/admin-bootstrap-key.pem"

# ── Profiles ─────────────────────────────────────────────────────────────────
[profiles]
refresh_interval_secs = 3600

[profiles.providers.local]
type = "builtin"

[profiles.providers.local.profiles.tlsserver]
description   = "Standard TLS server certificate"
validity_days = 90
key_usage     = ["digital_signature", "key_encipherment"]
eku           = ["server_auth"]
```

**Companion Nginx configuration:**

```nginx
server {
    listen 443 ssl;
    server_name acme.example.com;

    ssl_certificate     /etc/nginx/ssl/acme.example.com.pem;
    ssl_certificate_key /etc/nginx/ssl/acme.example.com-key.pem;

    # Client certificate verification for admin operators (optional).
    ssl_client_certificate /etc/nginx/ssl/operator-ca.pem;
    ssl_verify_client      optional;

    # ACME endpoints (no auth required by the proxy).
    location /acme/ {
        proxy_pass http://unix:/run/akamu/akamu.sock;
    }

    # CRL and OCSP (public, no auth).
    location /ca/ {
        proxy_pass http://unix:/run/akamu/akamu.sock;
    }

    # Admin API -- forward client cert for mTLS operator auth.
    location /admin/ {
        proxy_pass http://unix:/run/akamu/akamu.sock;
        proxy_set_header X-SSL-Client-Cert $ssl_client_escaped_cert;
    }

    # EAB endpoint -- proxy handles SPNEGO, forwards principal.
    location = /acme/eab {
        auth_gss              on;
        auth_gss_keytab       /etc/nginx/http.keytab;
        proxy_pass http://unix:/run/akamu/akamu.sock;
        proxy_set_header X-Remote-User $remote_user;
    }
}
```

---

## Multi-CA Setup

Two separate CA instances (RSA and ECDSA), each reachable at its own ACME
directory URL, with certificate profiles restricted to specific CAs.

```toml
# multi-ca.toml -- RSA + EC CAs with per-CA profiles.
#
# Directories:
#   https://acme.example.com/acme/rsa/directory   (RSA, default)
#   https://acme.example.com/acme/ec/directory    (EC)
#   https://acme.example.com/acme/directory       (alias for default = RSA)
#
# Per-CA CRL/OCSP:
#   /ca/rsa/crl   /ca/rsa/ocsp
#   /ca/ec/crl    /ca/ec/ocsp

listen_addr = "0.0.0.0:8080"
base_url    = "https://acme.example.com"

[database]
url = "sqlite:///var/lib/akamu/acme.db"

# ── RSA CA (default) ─────────────────────────────────────────────────────────
[[ca]]
id         = "rsa"
is_default = true

key_file  = "/etc/akamu/certs/rsa-ca.key.pem"
cert_file = "/etc/akamu/certs/rsa-ca.cert.pem"
key_type  = "rsa:4096"
hash_alg  = "sha256"

validity_days     = 90
ca_validity_years = 10
common_name       = "Example RSA CA"
organization      = "Example Org"

crl_url              = "https://acme.example.com/ca/rsa/crl"
ocsp_url             = "https://acme.example.com/ca/rsa/ocsp"
crl_next_update_secs = 86400

# Per-CA CAA identities (override server-level caa_identities for this CA).
caa_identities = ["rsa.acme.example.com", "acme.example.com"]

# ── EC CA ────────────────────────────────────────────────────────────────────
[[ca]]
id = "ec"

key_file  = "/etc/akamu/certs/ec-ca.key.pem"
cert_file = "/etc/akamu/certs/ec-ca.cert.pem"
key_type  = "ec:P-384"
hash_alg  = "sha384"

validity_days     = 90
ca_validity_years = 10
common_name       = "Example EC CA"
organization      = "Example Org"

crl_url              = "https://acme.example.com/ca/ec/crl"
ocsp_url             = "https://acme.example.com/ca/ec/ocsp"
crl_next_update_secs = 86400

caa_identities = ["ec.acme.example.com", "acme.example.com"]

# ── Server ───────────────────────────────────────────────────────────────────
[server]
terms_of_service_url = "https://acme.example.com/tos.html"
website_url          = "https://acme.example.com"

# Fallback CAA identities (used when a CA's caa_identities is empty).
caa_identities = ["acme.example.com"]

# "server" = one account works with all CAs (the default).
# "ca"     = accounts are isolated per CA.
account_scope = "server"

# ── Certificate profiles ─────────────────────────────────────────────────────
[profiles]
refresh_interval_secs = 3600

[profiles.providers.local]
type = "builtin"

# Available via both CAs (no ca_ids restriction).
[profiles.providers.local.profiles.tlsserver]
description   = "Standard TLS server certificate"
validity_days = 90
key_usage     = ["digital_signature", "key_encipherment"]
eku           = ["server_auth"]

# Restricted to the EC CA only.
[profiles.providers.local.profiles.ec-only]
description   = "EC-only TLS certificate (modern clients)"
validity_days = 90
key_usage     = ["digital_signature"]
eku           = ["server_auth"]
ca_ids        = ["ec"]
allowed_key_types = ["ec:P-256", "ec:P-384"]

# Restricted to the RSA CA only.
[profiles.providers.local.profiles.rsa-compat]
description   = "RSA certificate for legacy compatibility"
validity_days = 90
key_usage     = ["digital_signature", "key_encipherment"]
eku           = ["server_auth"]
ca_ids        = ["rsa"]
allowed_key_types = ["rsa:2048", "rsa:4096"]

# ── TLS (for admin mTLS) ─────────────────────────────────────────────────────
[tls]
enabled   = true
cert_file = "/etc/akamu/server.pem"
key_file  = "/etc/akamu/server-key.pem"

[tls.client_auth]
ca_files = ["/etc/akamu/operator-ca.pem"]
required = false

# ── Admin API ────────────────────────────────────────────────────────────────
[admin]
# Bootstrap an Administrator operator on first run.
# bootstrap_operator_cert_file = "/etc/akamu/admin-bootstrap.pem"
# bootstrap_operator_key_file  = "/etc/akamu/admin-bootstrap-key.pem"
```

---

## Delegated Certificates (RFC 9115)

A CDN delegation scenario: a domain owner (Identity Owner / IdO) runs Akamu
to authorize a CDN provider (Name Delegation Consumer / NDC) to obtain
certificates for the owner's domains. Akamu drives the upstream ACME CA
(e.g. Let's Encrypt) using dns-01 challenges.

```toml
# delegation.toml -- RFC 9115 delegated certificates for CDN.
#
# Workflow:
#   1. Admin creates a delegation via POST /admin/delegations
#   2. NDC discovers the delegation from its account's "delegations" URL
#   3. NDC submits new-order with "delegation": "<delegation-url>"
#   4. Order starts in "ready" (no challenge for the NDC)
#   5. Akamu drives the upstream CA (Let's Encrypt) with dns-01
#   6. NDC downloads the certificate

listen_addr = "0.0.0.0:8080"
base_url    = "https://acme.example.com"

[database]
url = "sqlite:///var/lib/akamu/acme.db"

[ca]
key_file  = "/etc/akamu/ca.key.pem"
cert_file = "/etc/akamu/ca.cert.pem"
key_type  = "ec:P-256"
hash_alg  = "sha256"

validity_days     = 90
ca_validity_years = 10
common_name       = "Example Delegation CA"
organization      = "Example Org"

[server]
# Enable the RFC 9115 delegation API surface.
delegation_enabled = true

# Allow unauthenticated GET of delegation order certificates.
# CDN PoPs can fetch certs without ACME credentials.
allow_certificate_get = true

# ── Upstream CA (IdO-client leg) ─────────────────────────────────────────────
# Akamu acts as an ACME client toward the upstream CA to prove domain control
# via dns-01 and retrieve the certificate.
[delegation_upstream]
# Upstream CA directory (e.g. Let's Encrypt production).
directory_url = "https://acme-v02.api.letsencrypt.org/directory"

# ACME account key for the upstream CA.
# Auto-generated as EC P-256 on first run if absent.
account_key_file = "/etc/akamu/upstream-acme.key.pem"

# Contact for the upstream ACME account registration.
contacts = ["mailto:acme-admin@example.com"]

# dns-01 is the only solver supported for delegation upstream flows.
challenge_solver = "dns-01"

# Script to publish the _acme-challenge TXT record.
# Receives CERTBOT_DOMAIN and CERTBOT_VALIDATION as environment variables.
# Exit 0 = record published successfully.
challenge_deploy_script = "/etc/akamu/dns-deploy.sh"

# Optional: remove the TXT record after upstream validation succeeds.
challenge_cleanup_script = "/etc/akamu/dns-cleanup.sh"

# How often to poll the upstream CA for order status (seconds).
poll_interval_secs = 10

# ── TLS (admin access requires mTLS) ────────────────────────────────────────
[tls]
enabled   = true
cert_file = "/etc/akamu/server.pem"
key_file  = "/etc/akamu/server-key.pem"

[tls.client_auth]
ca_files = ["/etc/akamu/operator-ca.pem"]
required = false

# ── Admin API (required to create delegation objects) ────────────────────────
[admin]
# bootstrap_operator_cert_file = "/etc/akamu/admin-bootstrap.pem"
# bootstrap_operator_key_file  = "/etc/akamu/admin-bootstrap-key.pem"
```

**DNS deploy script example** (`/etc/akamu/dns-deploy.sh`):

```bash
#!/bin/bash
# Publish the dns-01 TXT record using your DNS provider's API.
# Environment:
#   CERTBOT_DOMAIN     -- e.g. _acme-challenge.cdn.example.com
#   CERTBOT_VALIDATION -- the TXT record value
set -euo pipefail

# Example: use nsupdate for BIND / RFC 2136 dynamic DNS.
nsupdate -k /etc/akamu/dns-update.key <<EOF
server ns1.example.com
update add ${CERTBOT_DOMAIN}. 60 IN TXT "${CERTBOT_VALIDATION}"
send
EOF
```

---

## Production Hardened

A full production configuration with PostgreSQL, TLS with mTLS for admin
access, JSONL audit logging, and security-oriented defaults.

```toml
# production.toml -- hardened production deployment.
#
# Checklist:
#   [ ] PostgreSQL with TLS (sslmode=verify-full)
#   [ ] Akamu terminates TLS with a proper certificate
#   [ ] mTLS required for admin operators
#   [ ] JSONL audit log with external logrotate
#   [ ] EAB required for all accounts
#   [ ] DNSSEC validation enabled
#   [ ] CA/B Forum 200-day validity cap enforced

listen_addr = "0.0.0.0:8443"
base_url    = "https://acme.example.com"

# ── Database (PostgreSQL with TLS) ───────────────────────────────────────────
[database]
url             = "postgres://akamu:REPLACE_DB_PASSWORD@db.example.com/akamu?sslmode=verify-full"
max_connections = 20
require_tls     = true

# ── Certificate Authority ────────────────────────────────────────────────────
[ca]
key_file  = "/etc/akamu/ca.key.pem"
cert_file = "/etc/akamu/ca.cert.pem"
key_type  = "ec:P-384"
hash_alg  = "sha384"

validity_days     = 90
ca_validity_years = 10
common_name       = "Example Production CA"
organization      = "Example Corp"

# Enforce the CA/B Forum BR maximum 200-day validity cap at issuance time.
enforce_validity_cap = true

# CRL and OCSP via the built-in endpoints.
crl_url              = "https://acme.example.com/ca/crl"
ocsp_url             = "https://acme.example.com/ca/ocsp"
crl_next_update_secs = 86400

# Require the CA private key to be encrypted on disk (FCS_STG_EXT.1).
require_encrypted_key = true
key_password_file     = "/etc/akamu/ca-key-passphrase"

# ── Server ───────────────────────────────────────────────────────────────────
[server]
terms_of_service_url = "https://acme.example.com/tos.html"
website_url          = "https://acme.example.com"

# CAA checking.
caa_identities = ["acme.example.com"]

# Require External Account Binding for all new accounts.
external_account_required = true
eab_master_secret = "REPLACE_WITH_YOUR_BASE64URL_SECRET_AT_LEAST_32_BYTES"

# DNSSEC validation (required by CA/B Forum BR since 2026-03-15).
validate_dnssec = true

# DNS-over-TLS to Cloudflare for dns-01 and CAA lookups.
dns_resolver_addr   = "1.1.1.1:853"
dns_dot_server_name = "cloudflare-dns.com"

# JSONL audit log (for non-journald environments or archival).
audit_log_file = "/var/log/akamu/audit.jsonl"

# ARI renewal information.
ari_retry_after_secs = 21600
ari_explanation_url  = "https://acme.example.com/docs/renewal-policy"

# Tighter body size limit.
max_body_bytes = 65536

# ── TLS (Akamu terminates TLS) ───────────────────────────────────────────────
[tls]
enabled    = true
cert_file  = "/etc/akamu/server.pem"
key_file   = "/etc/akamu/server-key.pem"
protocols  = ["TLSv1.2", "TLSv1.3"]

# mTLS client certificate authentication for admin operators.
[tls.client_auth]
required          = false
ca_files          = ["/etc/akamu/operator-ca.pem"]
profile           = "rfc5280"
max_chain_depth   = 4
minimum_rsa_modulus = 2048

# ── Admin API ────────────────────────────────────────────────────────────────
[admin]
session_ttl_secs      = 1800
session_lock_secs     = 600
max_failed_auth       = 5
lockout_duration_secs = 1800
auth_rate_limit       = 20

# Audit overflow policy.
audit_max_events      = 1000000
audit_overflow        = "drop_oldest"
audit_alarm_threshold = 10
audit_alarm_action    = "syslog"

# Bootstrap admin operator (generated on first run).
bootstrap_operator_cert_file = "/etc/akamu/admin-bootstrap.pem"
bootstrap_operator_key_file  = "/etc/akamu/admin-bootstrap-key.pem"

# ── Certificate profiles ─────────────────────────────────────────────────────
[profiles]
refresh_interval_secs = 3600

[profiles.providers.local]
type = "builtin"

[profiles.providers.local.profiles.tlsserver]
description         = "Production TLS server certificate"
validity_days       = 90
key_usage           = ["digital_signature", "key_encipherment"]
eku                 = ["server_auth"]
allowed_key_types   = ["ec:P-256", "ec:P-384", "rsa:2048", "rsa:4096"]

[profiles.providers.local.profiles.short-lived]
description         = "Short-lived TLS certificate (7 days)"
validity_days       = 7
key_usage           = ["digital_signature"]
eku                 = ["server_auth"]
allowed_key_types   = ["ec:P-256", "ec:P-384"]
```
