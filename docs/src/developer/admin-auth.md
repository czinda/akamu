# Admin Authentication

This chapter documents the internal implementation of the admin operator
authentication middleware, with emphasis on the proxy-forwarded client
certificate flow.

## Module layout

```
src/admin/auth.rs       OperatorContext extractor, session management,
                        proxy cert extraction, GSSAPI path
src/config/admin.rs     AdminProxyAuthConfig, ProxyHeaderFormat enum
src/trusted_proxy.rs    TrustedProxies / TrustedProxy newtype and CIDR matching
src/state.rs            AdminAuthMethod enum (Cert, CertProxy, Gssapi, Eab)
```

## Authentication paths overview

The `OperatorContext` axum extractor (`src/admin/auth.rs:398`) is the central
authentication gate for every `/admin/*` route.  It tries four credential
sources in order:

| Priority | Credential | `AdminAuthMethod` | Description |
|---|---|---|---|
| 1 | `Authorization: Bearer <token>` | (inherited from session) | In-memory session token lookup |
| 2a | `PeerClientCert` extension | `Cert` | Direct mTLS client certificate from TLS handshake |
| 2b | Proxy-forwarded header | `CertProxy` | Certificate forwarded by a trusted reverse proxy |
| 3 | `Authorization: Negotiate <token>` | `Gssapi` | GSSAPI/SPNEGO Kerberos token |

Path 2a and 2b are mutually exclusive: if the TLS handshake provided a client
certificate (`PeerClientCert` is present), the proxy header is never consulted.
The proxy header path is only attempted when `PeerClientCert` is absent **and**
`[admin.proxy_auth]` is configured.

## Proxy-forwarded certificate authentication

### Why it exists

When Akamu runs behind a TLS-terminating reverse proxy (Nginx, Apache httpd,
Envoy), the proxy performs the TLS handshake with the client.  The proxy can
verify the client certificate against a CA trust store and forward the verified
certificate to Akamu in an HTTP header.  Akamu then extracts the certificate
from the header and authenticates the operator by matching its SHA-256
fingerprint against the `operators` table -- the same lookup used for direct
mTLS.

### Configuration

Defined in `AdminProxyAuthConfig` (`src/config/admin.rs:208`):

```toml
[admin.proxy_auth]
trusted_proxies = ["127.0.0.1/32", "::1/128"]
header_format   = "x-ssl-client-cert"   # or "ssl-client-cert" or "xfcc"
```

Two fields:

- **`trusted_proxies`** -- a `TrustedProxies` newtype (`src/trusted_proxy.rs:40`).
  A list of CIDR ranges and/or the special literal `"local addresses"`.
  Must be non-empty; validated in `AdminConfig::validate` (`src/config/admin.rs:187`).

- **`header_format`** -- a `ProxyHeaderFormat` enum (`src/config/admin.rs:222`).
  Defaults to `XSslClientCert`.  Determines both the HTTP header name to read
  and how to interpret its value.

### Supported header formats

The `ProxyHeaderFormat` enum maps each variant to an HTTP header name
(`src/config/admin.rs:234`):

| Variant | Config value | HTTP header | Typical proxy | Value encoding |
|---|---|---|---|---|
| `XSslClientCert` | `"x-ssl-client-cert"` | `X-SSL-Client-Cert` | Nginx | URL-encoded PEM |
| `SslClientCert` | `"ssl-client-cert"` | `SSL_CLIENT_CERT` | Apache httpd | URL-encoded PEM |
| `Xfcc` | `"xfcc"` | `X-Forwarded-Client-Cert` | Envoy | XFCC key-value format |

### Header parsing flow

The entry point is `extract_proxy_cert` (`src/admin/auth.rs:267`).  The
function signature:

```rust
fn extract_proxy_cert(
    parts: &Parts,
    proxy_cfg: &AdminProxyAuthConfig,
) -> Result<Option<Vec<u8>>, Response>
```

Returns `Ok(Some(der_bytes))` on success, `Ok(None)` when no certificate is
available (peer untrusted or header absent), and `Err(Response)` with a 400
status when the header is present but malformed.

Step by step:

1. **Read `ConnectInfo`.**  Extract the TCP peer address from request extensions
   (`src/admin/auth.rs:271`).  If `ConnectInfo` is absent (should not happen in
   normal operation), return `Ok(None)` with a warning log.

2. **Trusted-proxy check.**  Call `proxy_cfg.trusted_proxies.contains(&peer_addr.ip())`
   (`src/admin/auth.rs:282`).  If the peer IP does not match any entry, return
   `Ok(None)` silently -- the request is not from a trusted proxy, so the header
   is ignored even if present.

3. **Read the header.**  Look up the header name determined by
   `proxy_cfg.header_format.header_name()` (`src/admin/auth.rs:289`).  If
   absent, return `Ok(None)`.

4. **Validate UTF-8 and size.**  Convert the header value to a `&str`
   (`src/admin/auth.rs:293`).  Reject with 400 if not valid UTF-8.
   Reject with 400 if the header exceeds `MAX_PROXY_CERT_HEADER_LEN`
   (64 KiB, `src/admin/auth.rs:260`).

5. **Format-specific extraction.**  For the XFCC format, call `parse_xfcc_cert`
   to extract the `Cert=` value from the structured header
   (`src/admin/auth.rs:308`).  For the other two formats, the entire header
   value is the URL-encoded PEM.

6. **URL-decode.**  Apply `percent_encoding::percent_decode_str` to the PEM
   value (`src/admin/auth.rs:317`).  Reject with 400 if the decoded bytes are
   not valid UTF-8.

7. **PEM-to-DER.**  Call `synta_certificate::pem_to_der` on the decoded PEM
   text and take the first block (`src/admin/auth.rs:326`).  Reject with 400 if
   no PEM block is found.

8. **Return the DER bytes.**  The caller (`OperatorContext::from_request_parts`)
   proceeds with the standard fingerprint-based operator lookup.

### XFCC parsing

The Envoy `X-Forwarded-Client-Cert` header uses a structured format:

```
By=spiffe://foo;Hash=abc123;Cert="<URL-encoded PEM>";Subject="CN=test"
```

Multiple proxy hops are separated by commas.  The parser
(`parse_xfcc_cert`, `src/admin/auth.rs:212`) takes the **last** element
(nearest proxy) and searches for a `Cert=` key-value pair within it.  Values
may be double-quoted.  The key match is case-insensitive.

Splitting respects double-quoted values: commas and semicolons inside quotes
are not treated as delimiters (`split_respecting_quotes`,
`src/admin/auth.rs:241`).

### Certificate validation

The proxy-forwarded certificate is **not** re-validated against a CA trust
store by Akamu.  The TLS-terminating proxy is responsible for verifying the
certificate chain.  Akamu trusts the proxy's verdict, conditioned on:

1. The TCP peer IP matching a `trusted_proxies` entry.
2. The PEM decoding successfully to a DER-encoded certificate.

The extracted DER bytes are then SHA-256 fingerprinted and looked up in the
`operators` table, exactly like a direct mTLS certificate would be
(`src/admin/auth.rs:544`).

### The trusted-proxy check

The `TrustedProxies` type (`src/trusted_proxy.rs:40`) wraps a
`Vec<TrustedProxy>` where each entry is either:

- **`Cidr(IpNet)`** -- a CIDR range parsed by the `ipnet` crate.
- **`LocalAddresses`** -- the special literal `"local addresses"`.

The `contains` method (`src/trusted_proxy.rs:55`) checks the request's peer IP
against each entry:

- For `Cidr`, it calls `IpNet::contains`.
- For `LocalAddresses`, it checks `ip.is_loopback()` first (fast path), then
  falls back to a cached `getifaddrs(2)` enumeration of all local interface
  addresses (`local_addrs_cache`, `src/trusted_proxy.rs:79`).

IPv4-mapped IPv6 addresses (`::ffff:a.b.c.d`) are normalized to plain IPv4
before matching (`normalize_ip`, `src/trusted_proxy.rs:69`), so a `127.0.0.1/32`
CIDR entry matches both `127.0.0.1` and `::ffff:127.0.0.1`.

The local-address cache has a 30-second TTL and uses a `RwLock` for concurrent
access.  On non-Unix platforms, only loopback addresses are recognized.

### Integration with the admin auth middleware

The proxy cert path integrates at two points in `OperatorContext::from_request_parts`
(`src/admin/auth.rs:398`):

**Rate limiting** (`src/admin/auth.rs:441`).  The `has_proxy_cert_header`
helper (`src/admin/auth.rs:341`) performs a cheap check (trusted-proxy match +
header presence, no parsing) to determine whether this request is a credential
presentation.  If so, it counts toward the per-IP rolling 5-minute rate limit
(`[admin].auth_rate_limit`, default 20).

**Certificate extraction** (`src/admin/auth.rs:524`).  After the Bearer token
path fails, the extractor checks for a direct mTLS cert first
(`PeerClientCert`).  Only when that is absent does it attempt
`extract_proxy_cert`.  On success, the `AdminAuthMethod` is set to `CertProxy`
(rather than `Cert`) so audit logs distinguish the two paths.

After extraction, the flow merges with direct mTLS: SHA-256 fingerprint the
DER, look up `operators.cert_fingerprint`, check lockout, create a session
token, record an audit event.  The `method` field in the audit detail is
`"cert-proxy"` for proxy-forwarded certs and `"cert"` for direct mTLS
(`src/state.rs:858`).

### Security considerations

- **Header injection.**  The proxy-forwarded header is only read when the TCP
  peer IP matches a `trusted_proxies` entry.  If an untrusted client sends the
  header directly, it is ignored.  Operators must ensure their proxy strips or
  overwrites the header on incoming requests.

- **No chain validation.**  Akamu does not re-validate the certificate chain
  from the proxy header.  The proxy is trusted to have performed full chain
  validation.  This is standard practice (Nginx `ssl_verify_client on`,
  Apache `SSLVerifyClient require`, Envoy `require_client_certificate: true`).

- **Size limit.**  Headers larger than 64 KiB are rejected to prevent
  memory exhaustion from oversized certificates.

- **`PeerClientCert` takes priority.**  When Akamu is configured for direct
  mTLS client auth *and* proxy auth simultaneously, a direct TLS client
  certificate always wins.  This prevents a scenario where a client bypasses
  TLS client auth by injecting a proxy header.
