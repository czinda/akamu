# Challenges

A challenge is the mechanism by which `Akāmu` verifies that an ACME client controls the identifier (domain name or IP address) in an authorization. The server supports four challenge types: **http-01**, **dns-01**, **tls-alpn-01**, and **dns-persist-01**.

For each identifier in an order, the server creates one challenge of each supported type. The client chooses which challenge type to complete.

`dns-persist-01` is an opt-in type that requires explicit server configuration. When it is not configured, clients see the standard three types and are not affected. See [dns-persist-01 Challenge](dns-persist-01.md) for the full description of that type.

## Key authorization

Before responding to any challenge, compute the **key authorization** string:

```
key_authorization = token + "." + base64url(SHA-256(JWK-thumbprint-of-account-key))
```

Where:
- `token` is the challenge token provided by the server in the authorization object.
- The SHA-256 is computed over the JWK thumbprint string (itself a base64url-encoded SHA-256 of the canonical JSON of the account public key).
- `base64url` uses the URL-safe alphabet without padding characters.

In practice, ACME client libraries compute this for you.

`dns-persist-01` does not use this formula. Instead of a token, the client receives an `issuer-domain-names` array, and the server matches the account URI directly against the TXT record. See [dns-persist-01 Challenge](dns-persist-01.md) for details.

## Responding to a challenge

To signal that the client has provisioned the challenge response, POST to the challenge URL with an empty JSON object payload:

```json
{}
```

The server immediately marks the challenge as `processing` and spawns a background task to validate it. The response returns the current challenge status:

```json
{
  "type": "http-01",
  "url": "https://acme.example.com/acme/chall/<authz-id>/http-01",
  "status": "processing",
  "token": "<token>"
}
```

Poll the authorization URL (POST-as-GET) to check when validation completes.

## Challenge status transitions

```
pending → processing → valid
                     → invalid
```

A challenge that is already `processing` or `valid` is returned as-is if the client POSTs to it again.

---

## http-01

The server makes an HTTP/1.1 GET request to:

```
http://<domain>/.well-known/acme-challenge/<token>
```

on port 80. The response body (trimmed of whitespace) must equal the key authorization string.

### Provisioning

Create a file at the path `/.well-known/acme-challenge/<token>` on the web server for the domain being validated. The file content must be exactly the key authorization string.

**Example:**

If the token is `abc123` and the key authorization is `abc123.XYZ...`:

```
File path:    /.well-known/acme-challenge/abc123
File content: abc123.XYZ...
```

For Apache or nginx, ensure that requests to `/.well-known/acme-challenge/` are served from the document root without authentication and without redirects.

### Constraints

- Port 80 must be reachable from the ACME server.
- The response body must be less than 8 KiB.
- Redirects are not followed; the initial response must be 200 OK.
- IPv6 addresses are supported as `ip` type identifiers; the URL literal uses bracket notation (e.g., `http://[2001:db8::1]/.well-known/acme-challenge/<token>`).
- Wildcard identifiers (`*.example.com`) cannot be validated with http-01.

---

## dns-01

The server queries the DNS TXT record at:

```
_acme-challenge.<domain>
```

At least one TXT record value must equal:

```
base64url(SHA-256(key_authorization))
```

For example, if `SHA-256(key_authorization)` produces the bytes `\xde\xad...`, the expected TXT value is the base64url encoding of those 32 bytes.

### Provisioning

Add a DNS TXT record:

```
Name:    _acme-challenge.example.com
Type:    TXT
TTL:     60
Content: <base64url-SHA256-of-key-authorization>
```

**Concrete example:**

1. Token: `mytoken`
2. JWK thumbprint: `mythumbprint`
3. Key authorization: `mytoken.mythumbprint`
4. SHA-256 of key auth (hex): `e3b0c4...` (varies; compute for your actual values)
5. base64url of SHA-256: `47DEQp...` (varies)
6. TXT record value: `47DEQp...`

Use `openssl dgst -sha256 -binary <<< "mytoken.mythumbprint" | base64 -w0 | tr '+/' '-_' | tr -d '='` to compute it manually.

### Wildcard domains

For a wildcard identifier `*.example.com`, the leading `*.` is stripped before constructing the DNS query. The TXT record must be placed at `_acme-challenge.example.com`, not `_acme-challenge.*.example.com`.

### DNS propagation

The server uses the system default DNS resolver (or the address configured via `server.dns_resolver_addr`). If the TXT record has not propagated by the time the server queries, validation will fail. Use a short TTL (60 seconds or less) to speed up propagation.

---

## tls-alpn-01

The server opens a TLS connection to port 443 of the domain being validated, advertising the ALPN protocol `acme-tls/1`. The applicant's TLS server must respond with a certificate that:

1. Contains the domain as a dNSName in the SubjectAlternativeName extension.
2. Contains the `id-pe-acmeIdentifier` extension (OID `1.3.6.1.5.5.7.1.31`) marked **critical**, with a value of `OCTET STRING { SHA-256(key_authorization) }`.

### Provisioning

Set up a TLS virtual host that listens on port 443, responds only to ALPN negotiation for `acme-tls/1`, and presents a specially crafted certificate. Most ACME clients handle this automatically.

The certificate must:
- Be self-signed (the server does not verify the trust chain for this challenge type; it only checks the extensions).
- Have `id-pe-acmeIdentifier` as a **critical** extension.
- Have the SHA-256 hash of the key authorization (32 raw bytes) wrapped in an `OCTET STRING` as the extension value.

### TLS version support

The validator accepts both TLS 1.2 and TLS 1.3 connections.

### Constraints

- Port 443 must be reachable from the ACME server.
- Wildcard identifiers are not supported by tls-alpn-01.
- IP address identifiers (`ip` type) are supported; the server connects to the IP address directly.

---

## Challenge failure

If validation fails, the challenge transitions to `invalid` and an error is recorded:

```json
{
  "type": "http-01",
  "status": "invalid",
  "token": "<token>",
  "error": {
    "type": "urn:ietf:params:acme:error:connection",
    "detail": "connection error during challenge: TCP connect to example.com:80: connection refused"
  }
}
```

Common error types:

| Error type | Meaning |
|---|---|
| `connection` | Could not connect to the applicant server |
| `dns` | DNS TXT lookup failed or name not found |
| `incorrectResponse` | Server responded but the content did not match |
| `tls` | TLS handshake failed or extension verification failed |

A failed authorization invalidates the parent order. Create a new order to try again.
