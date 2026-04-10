# dns-persist-01 Challenge

`dns-persist-01` is a DNS-based challenge type that differs from the standard `dns-01` in one important way: the TXT record is **persistent**. It does not change from one certificate renewal to the next. Once an operator provisions the record, it remains valid for every subsequent renewal by the same ACME account — no per-renewal DNS changes are required.

The challenge type is defined by the Let's Encrypt specification published at <https://letsencrypt.org/2026/02/18/dns-persist-01>.

It is available only for `dns` type identifiers. IP address identifiers and the `http-01` / `tls-alpn-01` challenge types are not affected.

---

## How it works

When `dns-persist-01` is offered, the client does not receive a `token` field in the challenge object. Instead, it receives an `issuer-domain-names` array:

```json
{
  "type": "dns-persist-01",
  "url": "https://acme.example.com/acme/chall/<authz-id>/dns-persist-01",
  "status": "pending",
  "issuer-domain-names": ["acme.example.com"]
}
```

The ACME client must ensure that a TXT record exists at `_validation-persist.<domain>` before signalling the challenge. The server then queries that name and evaluates each TXT record value against a set of rules.

### TXT record format

```
_validation-persist.<domain>. IN TXT "<issuer-domain>; accounturi=<account-uri>[; policy=wildcard][; persistUntil=<ISO8601Z>]"
```

Fields are separated by semicolons. Field order is not significant except that the issuer domain must appear first.

| Field | Required | Description |
|-------|----------|-------------|
| `<issuer-domain>` | Yes | First token (before the first `;`). Must match the CA's configured issuer domain, case-insensitively, with any trailing dot stripped. |
| `accounturi=<uri>` | Yes | Full ACME account URI, e.g. `https://acme.example.com/acme/account/42`. Must match the requesting account exactly. |
| `policy=wildcard` | Only for wildcard orders | Must be present when the identifier starts with `*.`. |
| `persistUntil=<timestamp>` | No | If present, must be a UTC timestamp in the format `YYYY-MM-DDTHH:MM:SSZ`. The server rejects records whose timestamp is in the past. |

**Concrete example** for the account `https://acme.example.com/acme/account/42` validating `example.com` through a CA whose issuer domain is `acme.example.com`:

```
_validation-persist.example.com. 300 IN TXT "acme.example.com; accounturi=https://acme.example.com/acme/account/42"
```

For a wildcard certificate (`*.example.com`), add the `policy=wildcard` field:

```
_validation-persist.example.com. 300 IN TXT "acme.example.com; accounturi=https://acme.example.com/acme/account/42; policy=wildcard"
```

A single TXT record can cover both wildcard and non-wildcard orders if both fields are present. Non-wildcard orders do not require `policy=wildcard` and will match a record that contains it.

### What the server checks

The server performs a TXT lookup at `_validation-persist.<base-domain>` (the `*.` prefix is stripped for wildcard orders). It evaluates each TXT record in the response and accepts the challenge as soon as one record satisfies all of the following:

1. The first `;`-delimited token equals the CA's issuer domain (case-insensitive; trailing dot stripped).
2. `accounturi=<uri>` matches the requesting account's full URI.
3. For wildcard orders, `policy=wildcard` is present.
4. If `persistUntil=<timestamp>` is present, the timestamp is at or after the current time.

Unknown key-value tokens are silently ignored, allowing forward-compatible extensions to the TXT record format.

### Key authorization

Unlike other challenge types, `dns-persist-01` does not use a `token · thumbprint` key authorization. The server stores the account URI in the `key_auth` database column instead. During validation the account URI is matched directly against the `accounturi=` field in the TXT record.

---

## Enabling dns-persist-01

This challenge type is **opt-in**. It is offered to ACME clients only when `server.dns_persist_issuer_domain` is set in `config.toml`.

When the field is absent, `dns-persist-01` is not included in the list of challenges created for each authorization. Clients that enumerate challenge types and reject unexpected ones (strict-enum clients) are therefore not affected: they see exactly the same three challenge types (`http-01`, `dns-01`, `tls-alpn-01`) as before.

---

## Configuration reference

Both fields belong to the `[server]` section of `config.toml`.

### `dns_persist_issuer_domain`

**Optional. Default: absent (dns-persist-01 disabled).**

The issuer domain that the CA places in the `issuer-domain-names` field of `dns-persist-01` challenge objects and matches against the first token of TXT records.

When set, `dns-persist-01` is offered alongside the standard challenge types for all `dns` identifiers.

When absent, the server derives the issuer domain from the host part of `base_url` for purposes of TXT record validation, but does not offer the challenge type at all. In practice this means the field must be explicitly set to enable the challenge.

```toml
[server]
dns_persist_issuer_domain = "acme.example.com"
```

Use the same value in your DNS TXT records as the first semicolon-delimited token:

```
_validation-persist.example.com. 300 IN TXT "acme.example.com; accounturi=..."
```

### `dns_resolver_addr`

**Optional. Default: absent (system resolver).**

DNS resolver override for challenge validation. When set, both `dns-01` and `dns-persist-01` validators send queries to this address instead of the system default resolver.

Format: `"<ip>:<port>"`.

```toml
[server]
dns_resolver_addr = "127.0.0.1:5353"
```

This is useful in two scenarios:

- **Split-horizon DNS**: the ACME server runs inside a network where the internal resolver does not serve the public zone. Point `dns_resolver_addr` at a resolver that can see the external TXT records.
- **Testing**: aim the resolver at a local stub server so that integration tests do not depend on public DNS infrastructure.

The `http-01` and `tls-alpn-01` validators are not affected by this field.

---

## Wildcard certificates

To validate a wildcard identifier such as `*.example.com`, the TXT record must include `policy=wildcard`:

```
_validation-persist.example.com. 300 IN TXT "acme.example.com; accounturi=https://acme.example.com/acme/account/42; policy=wildcard"
```

Note that the query name is `_validation-persist.example.com`, not `_validation-persist.*.example.com`. The server always strips the `*.` prefix before constructing the DNS query name.

A record that contains `policy=wildcard` also satisfies non-wildcard orders for the same domain. You may use a single TXT record for both if your deployment issues both `example.com` and `*.example.com` certificates.

---

## `persistUntil` expiry

The optional `persistUntil` field lets an operator set an explicit expiry date on the TXT record's authorization grant, independently of the DNS TTL. This is useful for auditing or for limiting how long a given account is permitted to renew a certificate without re-provisioning the record.

Format: `YYYY-MM-DDTHH:MM:SSZ` (ISO 8601 UTC, with a literal `Z` suffix). Lowercase `z` is also accepted.

```
persistUntil=2027-12-31T23:59:59Z
```

When the server evaluates a record and finds a `persistUntil` field:

- If the timestamp is **at or after** the current time, the field is treated as valid and evaluation continues.
- If the timestamp is **before** the current time, the record is rejected, even if all other fields match.
- If the timestamp cannot be parsed, the record is rejected.

Records without a `persistUntil` field never expire due to this mechanism. Their lifetime is determined solely by DNS TTL and whether the DNS operator removes or changes them.

---

## Complete `[server]` example

```toml
[server]
terms_of_service_url   = "https://acme.example.com/tos.html"
website_url            = "https://acme.example.com"
caa_identities         = ["acme.example.com"]
order_expiry_secs      = 86400
authz_expiry_secs      = 86400

# Enable dns-persist-01 by setting the issuer domain.
# This value must match the first token in the TXT record at
# _validation-persist.<domain>.
dns_persist_issuer_domain = "acme.example.com"

# Optional: override the DNS resolver used for dns-01 and dns-persist-01.
# Useful for split-horizon deployments or testing.
dns_resolver_addr = "10.0.0.53:53"
```

---

## Limitations and known gaps

- **No ACME client library support yet.** As of instant-acme 0.4.3, the `dns-persist-01` challenge type is not implemented. Clients that use this library will not select the challenge automatically. A custom client, a patched version of the library, or direct ACME HTTP calls are required until upstream support is added.

- **No revocation check during TXT lookup.** The server does not consult a CRL or OCSP responder when evaluating the account URI in the TXT record. If an account is deactivated in the Akāmu database, the TXT record itself is not invalidated at the DNS layer; an operator must remove the TXT record manually.

- **One issuer domain per server instance.** The `dns_persist_issuer_domain` field accepts a single string. Deployments with multiple issuer identities or a CA hierarchy with distinct issuing domains are not supported by this field; use `dns-01` in those cases.

- **Resolver override is global.** The `dns_resolver_addr` field applies to all DNS-based challenge validation. It is not possible to use different resolvers for `dns-01` and `dns-persist-01`.
