# EAB and Kerberos Authentication

akamu can require callers to prove their Kerberos identity before issuing
External Account Binding (EAB) credentials. Two authentication modes are
supported: a reverse proxy that sets a header after completing SPNEGO, and
standalone GSSAPI where akamu validates Negotiate tokens directly.

## Authentication modes

### Proxy header mode

In this mode a trusted reverse proxy (Apache, Nginx, HAProxy, etc.) terminates
the SPNEGO / Kerberos exchange and sets an `X-Remote-User` header on every
forwarded request. akamu accepts this header as the authenticated principal only
when the request arrives from an IP address listed in `trusted_proxies`.

Requests from any other IP — including unauthenticated clients — never have the
header honoured.

### Standalone GSSAPI mode

In this mode akamu handles `Authorization: Negotiate` tokens directly using MIT
Kerberos. At startup the server reads a keytab file and acquires an acceptor
credential for the configured HTTP service principal. Each incoming token is
validated with `gss_accept_sec_context`.

When the token is absent, akamu returns `401 Unauthorized` with a
`WWW-Authenticate: Negotiate` challenge. When the token is invalid or expired,
akamu returns `403 Forbidden`.

Only one mode should be active at a time. Enabling `trusted_proxies` and
`[server.gssapi]` simultaneously is supported but unusual: proxy headers take
precedence for requests from trusted IPs; standalone GSSAPI handles the rest.

## Deployment prerequisites

Both modes require a working Kerberos environment:

- A Kerberos realm (for example, managed by FreeIPA or Active Directory).
- A service principal of the form `HTTP/<hostname>@REALM` registered in the KDC.
- For standalone GSSAPI: a keytab containing a key for that principal, readable
  only by the akamu process.
- For proxy mode: a reverse proxy configured to perform SPNEGO and set
  `X-Remote-User`.

## Configuration

### Proxy mode

```toml
[server]
trusted_proxies = ["192.168.1.10/32"]
```

- `trusted_proxies` lists the IP addresses (CIDR notation) of your reverse proxy.
- Keep this list as narrow as possible. Any host in the list can claim any
  principal name by forging the `X-Remote-User` header.
- IPv4-mapped IPv6 addresses (`::ffff:a.b.c.d`) are automatically normalised to
  plain IPv4 for matching purposes.

No additional configuration is needed on the akamu side. The reverse proxy must
be configured separately to perform Kerberos/SPNEGO authentication and forward
the authenticated username in `X-Remote-User`.

Example Apache configuration (mod_auth_gssapi):

```apache
<Location /acme/eab>
    AuthType GSSAPI
    AuthName "Kerberos"
    GssapiCredStore keytab:/etc/httpd/http.keytab
    Require valid-user
    RequestHeader set X-Remote-User %{REMOTE_USER}e
</Location>
```

### Standalone GSSAPI mode

```toml
[server.gssapi]
keytab_file  = "/etc/akamu/http.keytab"
service_name = "HTTP"
```

- `keytab_file` — path to the HTTP service keytab. The akamu process must be
  able to read this file; no other user should have access to it.
- `service_name` — host-based service name. MIT Kerberos appends
  `@<local-hostname>` automatically when no realm is given. Use
  `"HTTP@akamu.example.com"` to be explicit about the hostname.

Generate and install the keytab for an IPA-managed host:

```bash
ipa-getkeytab -s ipa.example.com \
    -p HTTP/akamu.example.com@EXAMPLE.COM \
    -k /etc/akamu/http.keytab
chmod 600 /etc/akamu/http.keytab
chown akamu: /etc/akamu/http.keytab
```

Verify the keytab:

```bash
klist -kt /etc/akamu/http.keytab
```

## The `GET /acme/eab` endpoint

The `GET /acme/eab` endpoint is the entry point for EAB credential issuance.
It requires a valid authenticated identity through one of the two modes above.

### Current behaviour

The endpoint currently echoes the authenticated principal name back to the caller:

```
GET /acme/eab
Authorization: Negotiate <base64-token>
```

Response:

```json
{ "principal": "user@EXAMPLE.COM" }
```

This confirms that authentication succeeded and identifies the Kerberos
principal that will be associated with an EAB key.

### Planned: EAB HMAC key derivation

EAB HMAC key derivation is not yet implemented. In a future release the endpoint
will return an EAB key identifier and HMAC secret derived from:

- A per-deployment master secret (configured separately).
- The authenticated principal name.
- An HKDF expansion (RFC 5869) binding both inputs.

The derived EAB key will be accepted in `newAccount` requests that include an
`externalAccountBinding` field (RFC 8555 §7.3.4). This allows site
administrators to control who may register ACME accounts by granting or revoking
Kerberos principals access to the ACME server.

## Security notes

- The keytab grants the ability to accept Kerberos service tickets for the HTTP
  principal. Treat it with the same care as a private key.
- File permissions: `600`, owned by the akamu service account.
- Do not share the same keytab between akamu and other services.
- The `trusted_proxies` list must be kept tightly scoped to the actual IP
  addresses of your reverse proxy. A broadly scoped list (for example,
  `0.0.0.0/0`) allows any network client to assert any principal name.
- Kerberos tickets have a finite lifetime (typically 10 hours). Clients must
  obtain fresh tickets before they expire; akamu returns `403` for expired tokens.
