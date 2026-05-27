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

Additional behaviors of this mode:

- **Token size limit.** Negotiate tokens larger than 128 KiB are rejected with
  `400 Bad Request`. Legitimate Kerberos service tickets are always smaller than
  this limit.
- **Case-insensitive scheme matching.** The `"Negotiate "` prefix in the
  `Authorization` header is matched case-insensitively per RFC 7235 §2.1.
- **TLS channel bindings.** When akamu terminates TLS itself, the
  `tls-server-end-point` channel binding (RFC 5929 §4) is computed from the
  server certificate and passed to `gss_accept_sec_context`. This binds the
  Kerberos exchange to the TLS channel, preventing token relay attacks. When the
  server certificate uses ML-DSA (pure or composite) or Ed448 — algorithms for
  which RFC 5929 defines no canonical hash — channel bindings are disabled
  automatically.
- **Replay detection.** After a successful `gss_accept_sec_context` call, akamu
  checks whether `GSS_C_REPLAY_FLAG` is set. When the flag is absent (common
  when clients connect over TLS, because TLS already provides replay
  protection), a `debug`-level log entry is emitted and the authentication
  proceeds normally. This behaviour is intentional: browsers and TLS-first
  clients typically do not negotiate Kerberos-level replay protection.
- **No authentication mechanism configured.** When neither `trusted_proxies`
  nor `[server.gssapi]` is set, requests to authenticated endpoints return
  `404 Not Found` rather than `403 Forbidden`.
- **GSSAPI without TLS.** Running standalone GSSAPI without TLS is permitted
  but emits a `warn`-level log at startup, because SPNEGO tokens are not
  protected against interception or relay attacks without TLS.

Only one mode may be active at a time. Enabling `trusted_proxies` and
`[server.gssapi]` simultaneously is a configuration error: the server exits at
startup with an error message if both are set.

## Deployment prerequisites

Both modes require a working Kerberos environment:

- A Kerberos realm (for example, managed by FreeIPA or Active Directory).
- A service principal of the form `HTTP/<hostname>@REALM` registered in the KDC.
- For standalone GSSAPI: either a keytab file readable only by the akamu
  process, or a gssproxy daemon entry that supplies the credential (no direct
  keytab access needed — see [FreeIPA deployment](deployment-ipa.md)).
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

Two credential sources are supported: a keytab file read directly by akamu, or
the gssproxy daemon (no direct file access needed).

**Keytab mode** — akamu reads the keytab at startup:

```toml
[server.gssapi]
keytab_file = "/etc/akamu/http.keytab"
```

Generate and install the keytab for an IPA-managed host:

```bash
ipa-getkeytab -s ipa.example.com \
    -p HTTP/akamu.example.com@EXAMPLE.COM \
    -k /etc/akamu/http.keytab
chmod 600 /etc/akamu/http.keytab
chown akamu: /etc/akamu/http.keytab
```

**gssproxy mode** — gssproxy supplies the credential; no keytab path is needed:

```toml
[server.gssapi]
gssproxy = true
```

Set `GSS_USE_PROXY=yes` is handled automatically; akamu sets it before the
first GSSAPI call when `gssproxy = true`. Install the gssproxy service entry
first — see [FreeIPA deployment](deployment-ipa.md) for a complete example.

**Common option** — `service_name` selects the Kerberos service component.
MIT Kerberos appends `@<local-hostname>` automatically when no realm is given.
The default is `"HTTP"`; use `"HTTP@akamu.example.com"` to be explicit:

```toml
[server.gssapi]
keytab_file  = "/etc/akamu/http.keytab"
service_name = "HTTP@akamu.example.com"   # explicit hostname
```

`keytab_file` and `gssproxy` are mutually exclusive — the server exits at
startup if both are set.

## The `GET /acme/eab` endpoint

The `GET /acme/eab` endpoint is the entry point for EAB credential issuance.
It requires a valid authenticated identity through one of the two modes above.

### Behaviour with `eab_master_secret` configured (full mode)

When `[server].eab_master_secret` is set, the endpoint derives a deterministic
EAB key identifier and HMAC secret from the master secret and the authenticated
principal using HKDF-SHA-256 (RFC 5869):

```
kid      = base64url( HKDF-SHA256(IKM=master_secret, info="akamu-eab-v1-kid:<principal>", L=16) )
hmac_key = base64url( HKDF-SHA256(IKM=master_secret, info="akamu-eab-v1-key:<principal>", L=32) )
```

Request:

```
GET /acme/eab
Authorization: Negotiate <base64-token>
```

Response (`200 OK`):

```json
{
  "principal": "host/client.example.com@EXAMPLE.COM",
  "kid":       "…22-char base64url…",
  "hmac_key":  "…43-char base64url…",
  "alg":       "HS256"
}
```

The same `(master_secret, principal)` pair always produces the same `kid` and
`hmac_key`. Credentials are stored in the `eab_keys` table on first request and
returned unchanged on subsequent requests by the same principal.

Once the `kid` has been consumed by an account registration (`newAccount` with a
valid `externalAccountBinding`), re-fetching returns `409 Conflict`. Contact
your CA administrator to reset the credential if you need to re-register.

### Behaviour without `eab_master_secret` (stub / backward-compatible mode)

When `eab_master_secret` is absent, the endpoint confirms authentication
succeeded but returns only the principal name:

```json
{ "principal": "host/client.example.com@EXAMPLE.COM" }
```

This mode is useful for testing authentication configuration before enabling EAB
enforcement.

### Configuring `eab_master_secret`

Generate a random 32-byte secret and encode it as base64url:

```bash
openssl rand -base64 32 | tr '+/' '-_' | tr -d '='
```

Add the result to your configuration:

```toml
[server]
external_account_required = true
eab_master_secret         = "<base64url output from above>"
```

The decoded secret must be at least 32 bytes; the server exits at startup if it
is shorter. Treat the master secret with the same care as a private key — anyone
who holds it can derive valid EAB credentials for any principal.

### Client-side usage with `akamu-cli`

The `akamu-cli` and `akamu-client` library support calling this endpoint using a
Kerberos keytab. The CLI `--gssapi-keytab` flag (shared by `account register`
and `issue`) authenticates to the endpoint, logs the returned principal, and
automatically uses the returned `kid` and `hmac_key` to construct the
`externalAccountBinding` field in `newAccount` (RFC 8555 §7.3.4). No manual
copy-paste of EAB credentials is required.

The library exposes `fetch_eab_via_gssapi(eab_url, keytab_file)`, which derives
the target service name `HTTP@<hostname>` from the URL automatically and returns
a `GssapiEabResult` containing `principal`, `kid`, `hmac_key`, and `alg`.

### Using EAB credentials with other ACME clients

Any standard ACME client that supports External Account Binding can use
credentials from `GET /acme/eab`. The pattern is to fetch the credentials in a
pre-registration script and then pass them to the ACME client's EAB flags.

**Step 1 — fetch credentials with `curl` and a Kerberos ticket**

```bash
# Obtain a Kerberos ticket first (if not already cached)
kinit host/client.example.com@EXAMPLE.COM -k -t /etc/client.keytab

# curl handles SPNEGO automatically with --negotiate
RESPONSE=$(curl -s --negotiate -u : \
    https://akamu.example.com/acme/eab)

KID=$(echo "$RESPONSE"      | python3 -c "import sys,json; print(json.load(sys.stdin)['kid'])")
HMAC_KEY=$(echo "$RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin)['hmac_key'])")
```

**Step 2 — pass the credentials to your ACME client**

Certbot:

```bash
certbot register \
    --server https://akamu.example.com/acme/directory \
    --eab-kid     "$KID" \
    --eab-hmac-key "$HMAC_KEY"
```

acme.sh:

```bash
export EAB_KID="$KID"
export EAB_HMAC_KEY="$HMAC_KEY"
acme.sh --register-account \
    --server https://akamu.example.com/acme/directory \
    --eab
```

Lego:

```bash
lego --server https://akamu.example.com/acme/directory \
     --eab \
     --kid      "$KID" \
     --hmac     "$HMAC_KEY" \
     --email    "ops@example.com" \
     run --domains client.example.com ...
```

The `kid` and `hmac_key` values are valid until the first successful
`newAccount` call that consumes them. After registration succeeds the account
key is the ongoing credential; the EAB pair is not needed again. If registration
fails before `newAccount` completes, re-running the script returns the same
`kid` and `hmac_key` (derivation is deterministic), so it is safe to retry.

If `GET /acme/eab` returns `409 Conflict`, the credentials have already been
consumed by a prior registration. Contact your CA administrator to reset them.

## Security notes

- In keytab mode the keytab grants the ability to accept Kerberos service
  tickets for the HTTP principal. Treat it with the same care as a private key:
  permissions `600`, owned by the akamu service account, never shared with
  other services.
- In gssproxy mode the keytab is held by the gssproxy daemon; verify that the
  gssproxy service entry restricts access by `euid = akamu` so that no other
  process on the host can obtain the HTTP service credential.
- The `trusted_proxies` list must be kept tightly scoped to the actual IP
  addresses of your reverse proxy. A broadly scoped list (for example,
  `0.0.0.0/0`) allows any network client to assert any principal name.
- Kerberos tickets have a finite lifetime (typically 10 hours). Clients must
  obtain fresh tickets before they expire; akamu returns `403` for expired tokens.
