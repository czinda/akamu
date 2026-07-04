# Admin API Authentication Methods

Every request to the admin API (`/admin/*`) must be authenticated.
Four authentication methods are available, each suited to different
deployment environments.  This page helps you choose the right one and
links to detailed configuration for each.

## Which method should I use?

```
Is Akamu behind a TLS-terminating reverse proxy?
 |
 +-- Yes
 |    |
 |    +-- Do operators already have Kerberos credentials (AD / FreeIPA)?
 |    |    |
 |    |    +-- Yes --> GSSAPI/Kerberos
 |    |    +-- No  --> Proxy-forwarded client certificates
 |    |
 +-- No (Akamu terminates TLS directly)
      |
      +-- Do operators already have Kerberos credentials?
           |
           +-- Yes --> GSSAPI/Kerberos (standalone mode)
           +-- No  --> Direct mTLS client certificates
```

**Recommendations by scenario:**

| Scenario | Recommended method |
|----------|--------------------|
| Single-host lab or development | Direct mTLS -- simplest setup, bootstrap operator auto-generated |
| Production behind Nginx / Envoy / Apache | Proxy-forwarded client certificates |
| Enterprise with Active Directory or FreeIPA | GSSAPI/Kerberos |
| Mixed environment (some operators have certs, some have Kerberos) | GSSAPI + mTLS (both can be active simultaneously) |

After the initial authentication, all methods issue a **session token**
that the client reuses for subsequent requests.  The token is returned in
`POST /admin/session` and passed as `Authorization: Bearer <token>`.

---

## Method comparison

| | Direct mTLS | Proxy-forwarded cert | GSSAPI/Kerberos | Session token |
|---|---|---|---|---|
| **Security level** | High (mutual TLS) | High (proxy verifies cert) | High (Kerberos tickets) | Medium (bearer token) |
| **Requires TLS?** | Yes (native) | Yes (at the proxy) | No (but strongly recommended) | N/A (secondary credential) |
| **Requires external infra?** | No (Akamu CA can sign operator certs) | Reverse proxy | KDC (AD, FreeIPA, MIT KDC) | No (issued by prior login) |
| **Config complexity** | Low | Medium | Medium-High | None (automatic) |
| **Config section** | `[tls.client_auth]` | `[admin.proxy_auth]` | `[admin.gssapi]` | `[admin] session_ttl_secs` |
| **Audit event method** | `"cert"` | `"cert-proxy"` | `"gssapi"` | `"token"` |

At least one of `[tls.client_auth]`, `[admin.proxy_auth]`, or
`[admin.gssapi]` must be configured.  The server exits at startup if none
is set.

---

## 1. Direct mTLS (client certificates)

The operator presents a TLS client certificate during the handshake.
Akamu computes the SHA-256 fingerprint of the leaf certificate and matches
it against the `operators` table.

This is the simplest path: on first start Akamu auto-generates a bootstrap
operator certificate and registers it as an administrator.

**Quick-start config:**

```toml
[tls]
enabled   = true
cert_file = "/etc/akamu/server.crt"
key_file  = "/etc/akamu/server.key"

[tls.client_auth]
ca_files = ["/etc/akamu/operator-ca.pem"]
required = false   # allow GSSAPI-only clients without a cert

[admin]
bootstrap_operator_cert_file = "/etc/akamu/admin-bootstrap.pem"
bootstrap_operator_key_file  = "/etc/akamu/admin-bootstrap-key.pem"
```

After first boot, authenticate with the bootstrap certificate and add
permanent operators:

```bash
akamuctl --cert /etc/akamu/admin-bootstrap.pem \
         --key  /etc/akamu/admin-bootstrap-key.pem \
    operator add --name alice --role administrator \
                 --cert-file /etc/akamu/alice-client.pem
```

**Detailed docs:** [TLS Configuration -- Mode 4 (Mutual TLS)](tls.md#mode-4--mutual-tls-mtls),
[Configuration Reference -- `[tls.client_auth]`](configuration.md#tlsclient_auth),
[Admin API -- Operator management workflow](admin-api.md#operator-management-workflow)

---

## 2. Proxy-forwarded client certificates

When Akamu runs behind a TLS-terminating reverse proxy, the proxy verifies
the client certificate and forwards it in an HTTP header.  Akamu extracts
the certificate from the header, computes the fingerprint, and issues a
session token -- identical to the direct mTLS path.

Three header conventions are supported (Nginx, Apache, Envoy).

**Quick-start config:**

```toml
[admin]
session_ttl_secs = 3600

[admin.proxy_auth]
trusted_proxies = ["127.0.0.1/32"]
header_format   = "x-ssl-client-cert"   # or "ssl-client-cert" or "xfcc"
```

The certificate header is only read when the TCP peer address matches a
`trusted_proxies` entry.  Requests from untrusted IPs that include the
header silently ignore it.

**Detailed docs:** [TLS Configuration -- Proxy-forwarded client certificates](tls.md#proxy-forwarded-client-certificates-for-admin-mtls),
[Configuration Reference -- `[admin.proxy_auth]`](configuration.md#adminproxy_auth)

---

## 3. GSSAPI/Kerberos

The operator sends an `Authorization: Negotiate <SPNEGO-token>` header.
Akamu validates the token against a Kerberos keytab (or via gssproxy),
extracts the principal, and looks it up in the `operators` table.

Two credential sources are available: a keytab file read directly by Akamu,
or the gssproxy daemon (no direct keytab access needed).

**Quick-start config (keytab):**

```toml
[admin]
session_ttl_secs = 3600
bootstrap_operator_gssapi_principal = "admin@EXAMPLE.COM"

[admin.gssapi]
keytab_file  = "/etc/akamu/http.keytab"
service_name = "HTTP"
```

**Quick-start config (gssproxy):**

```toml
[admin]
session_ttl_secs = 3600
bootstrap_operator_gssapi_principal = "admin@EXAMPLE.COM"

[admin.gssapi]
gssproxy     = true
service_name = "HTTP"
```

When `bootstrap_operator_gssapi_principal` is set and the operators table
is empty, the principal is registered as an administrator at startup so
the first `akamuctl login --gssapi` succeeds without manual setup.

**Detailed docs:** [EAB and Kerberos Authentication](eab-kerberos.md),
[FreeIPA Co-deployment](deployment-ipa.md),
[Configuration Reference -- `[admin.gssapi]`](configuration.md#admingssapi)

---

## 4. Session tokens (bearer)

Session tokens are not a standalone login method.  After a successful
mTLS, proxy-forwarded cert, or GSSAPI login via `POST /admin/session`,
the server returns a session token.  The client passes it as
`Authorization: Bearer <token>` on subsequent requests.

Tokens expire after `session_ttl_secs` seconds of inactivity (default
1 hour).  After `session_lock_secs` seconds of inactivity (default
15 minutes), the session enters a locked state and requires
re-authentication.

The session store holds at most 1,000 active sessions.  Token comparisons
use constant-time equality to prevent timing side-channels.

**Relevant config keys:**

```toml
[admin]
session_ttl_secs  = 3600    # total session lifetime (1 hour)
session_lock_secs = 900     # lock after 15 minutes idle
```

**Detailed docs:** [Admin API -- Bearer session token](admin-api.md#bearer-session-token),
[Configuration Reference -- `[admin]`](configuration.md#admin)
