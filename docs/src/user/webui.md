# Web UI

Akamu includes a browser-based management interface built with
[PatternFly](https://www.patternfly.org/) and React. It is served at `/ui/`
on the same listener as the ACME and admin APIs and communicates with the
admin API at `/admin/*` directly -- no separate backend or proxy is required.

The web UI is optional. When the `[server.webui]` configuration section is
absent, the `/ui/` routes are not registered and the server operates purely
as an API endpoint.

## Building the frontend

The frontend source lives in the `webui/` directory of the repository. It
requires Node.js (v18+) and npm.

```bash
cd webui
npm ci
npm run build
```

The build output is written to `webui/dist/`. Point the `static_dir`
configuration key to this directory (as an absolute path) to serve it:

```toml
[server.webui]
static_dir = "/path/to/akamu/webui/dist"
```

See [Configuration Reference -- `[server.webui]`](configuration.md#serverwebui)
for full details on the `static_dir` field and its validation rules.

## Authentication

The login page at `/ui/login` offers two authentication methods:

### Kerberos (GSSAPI/SPNEGO)

The "Kerberos" tab sends a `POST /admin/session` request. If the Akamu
server is configured with `[server.gssapi]`, the browser's built-in SPNEGO
support negotiates a Kerberos service ticket automatically. The browser must
be configured for SPNEGO (for example, with the `network.negotiate-auth.trusted-uris`
preference in Firefox).

### EAB key

The "EAB Key" tab accepts a key ID (`kid`) and an HMAC key (base64url-encoded).
The browser computes an HMAC-SHA256 signature client-side and sends it to
`POST /admin/session/eab`. This method does not require Kerberos
infrastructure and works in any browser.

EAB login credentials can be created through the admin API or `akamuctl`.
Each EAB key is linked to an operator; the operator's role determines what
the logged-in user can see and do.

On successful authentication the server returns a session token. The token
is stored in `sessionStorage` and sent as a `Bearer` token on subsequent
admin API calls. Sessions expire after the configured `session_ttl_secs`
(default 1 hour); the UI auto-logs out when the token expires.

## Pages and role-based visibility

Navigation items are shown or hidden based on the operator's role. The four
roles form a hierarchy described in [Operator Roles](operator-roles.md).

| Page | Minimum role | Description |
|------|-------------|-------------|
| Dashboard | any | Certificate, account, EAB key, and server summary statistics |
| Certificates | any | List, search, and inspect issued certificates |
| Orders | any | List and inspect ACME orders |
| Accounts | any | List and inspect ACME accounts |
| Audit Log | `auditor` or `administrator` | Search and browse audit events |
| EAB Keys | `ca_ra` | List, create, and inspect External Account Binding keys |
| Delegations | `ca_ra` | List, create, edit, and inspect RFC 9115 delegations |
| Profiles | `ca_ra` | List and inspect certificate profiles; `administrator` can edit |
| CAs | `ca_operations` | List and inspect configured Certificate Authorities |
| Cross-Certs | `ca_operations`, `auditor`, or `administrator` | List and inspect cross-signed certificates |
| Operators | `administrator` | List, create, edit, and inspect operators |
| Server Config | `administrator` | View the running server configuration |

## Development workflow

For local development the frontend can be run with the Vite dev server,
which proxies `/admin` and `/acme` requests to a running Akamu instance:

```bash
cd webui
npm run dev
```

The dev server listens on `http://localhost:9000/ui/` by default. Set the
`AKAMU_SERVER_URL` environment variable to point at a non-default Akamu
address (the default is `https://localhost:443`).

The `contrib/seedgen/dev.sh` script automates the full dev workflow:

1. Generates a test database with realistic PKI data using `akamu-seedgen`.
2. Starts Akamu against the generated database.
3. Starts the Vite dev server with the proxy pointing at the running
   Akamu instance.

```bash
# Generate test data and start everything
cargo run -p akamu-seedgen -- --output /tmp/devdata.sqlite3
./contrib/seedgen/dev.sh /tmp/devdata
```

The seedgen run prints EAB credentials for a seeded `administrator` operator
at the end of its output. Paste those into the EAB tab on the login page.
See [Test Data Generation](../developer/seedgen.md) for full details.

## Security headers

All responses under `/ui/*` include the following security headers:

| Header | Value |
|--------|-------|
| `Content-Security-Policy` | `default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'` |
| `X-Content-Type-Options` | `nosniff` |
| `X-Frame-Options` | `DENY` |
| `Referrer-Policy` | `strict-origin-when-cross-origin` |

These headers are added by server-side middleware and cannot be overridden
by the static files themselves.
