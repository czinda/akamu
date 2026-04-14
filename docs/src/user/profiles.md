# Certificate Profiles

Certificate profiles let `Akāmu` issue certificates with different extension sets, validity periods, and key usage policies depending on the use case. Without profiles every order gets the same default profile: `digitalSignature` KeyUsage, `serverAuth` EKU, and the validity and URL settings from `[ca]`. With profiles configured, clients can request a named policy at order time and the server enforces it at issuance.

Profiles implement [draft-aaron-acme-profiles-01](https://www.ietf.org/archive/id/draft-aaron-acme-profiles-01.html).

---

## How it works

1. At startup `Akāmu` loads profile definitions from one or more *providers* (see below) and caches them in memory.
2. The directory endpoint advertises the available profiles in `meta.profiles`.
3. A client includes `"profile": "<name>"` in its `newOrder` request.
4. At finalize time the server resolves the profile's `CertificateParameters` and issues the certificate with those extension values; `Akāmu`'s own CA always signs.
5. A background task refreshes the cache every `refresh_interval_secs` seconds (default: 3600).

If no profile is requested, or no providers are configured, the server falls back to CA defaults unchanged.

---

## Configuration overview

```toml
[profiles]
refresh_interval_secs = 3600   # how often to reload from providers (default)

# ── Provider 1: inline TOML definitions ─────────────────────────────────────
[profiles.providers.local]
type = "builtin"

[profiles.providers.local.profiles.tlsserver]
description   = "Standard TLS server certificate"
validity_days = 90
key_usage     = ["digital_signature", "key_encipherment"]
eku           = ["server_auth"]

[profiles.providers.local.profiles.clientauth]
description   = "Client authentication certificate"
validity_days = 365
key_usage     = ["digital_signature"]
eku           = ["client_auth"]

# ── Provider 2: Dogtag PKI profile files ────────────────────────────────────
[profiles.providers.dogtag_prod]
type        = "dogtag"
profile_dir = "/etc/pki/pki-tomcat/ca/profiles/ca"
profiles    = ["caServerCert", "caIPAserviceCert"]   # empty = all

# ── Provider 3: FreeIPA/IPAThinCA via GSSAPI LDAP ───────────────────────────
[profiles.providers.ipa_prod]
type     = "ipa"
profiles = ["caIPAserviceCert", "IECUserRoles"]

[profiles.providers.ipa_prod.ldap]
uri         = "ldap://ipa.example.com:7389"
base_dn     = "o=ipaca"
gssapi      = true
keytab_file = "/etc/akamu/akamu.keytab"
principal   = "akamu/akamu.example.com@EXAMPLE.COM"
```

---

## Provider types

### `builtin` — inline TOML

Define profiles directly in `config.toml`. No external system required.

```toml
[profiles.providers.local]
type = "builtin"

[profiles.providers.local.profiles.<profile-id>]
description   = "Human-readable description shown in meta.profiles"
validity_days = 90          # optional; inherits from [ca].validity_days
hash_alg      = "sha256"    # optional; inherits from [ca].hash_alg
key_usage     = ["digital_signature"]   # see table below
eku           = ["server_auth"]         # see table below
crl_url       = "http://crl.example.com/ca.crl"   # optional
ocsp_url      = "http://ocsp.example.com"          # optional
allowed_key_types = ["ec:P-256", "rsa:2048"]       # optional; empty = any

[[profiles.providers.local.profiles.<profile-id>.certificate_policies]]
oid     = "2.23.140.1.2.1"                         # DV certificate
cps_uri = "https://example.com/cps"               # optional
```

**`key_usage` names**

| Name | KeyUsage bit |
|------|-------------|
| `digital_signature` | `digitalSignature` (bit 0) |
| `non_repudiation` / `content_commitment` | `nonRepudiation` (bit 1) |
| `key_encipherment` | `keyEncipherment` (bit 2) |
| `data_encipherment` | `dataEncipherment` (bit 3) |
| `key_agreement` | `keyAgreement` (bit 4) |
| `key_cert_sign` | `keyCertSign` (bit 5) |
| `crl_sign` | `cRLSign` (bit 6) |
| `encipher_only` | `encipherOnly` (bit 7) |
| `decipher_only` | `decipherOnly` (bit 8) |

**`eku` names and dotted-decimal OIDs**

| Name | OID |
|------|-----|
| `server_auth` | 1.3.6.1.5.5.7.3.1 |
| `client_auth` | 1.3.6.1.5.5.7.3.2 |
| `code_signing` | 1.3.6.1.5.5.7.3.3 |
| `email_protection` | 1.3.6.1.5.5.7.3.4 |
| `time_stamping` | 1.3.6.1.5.5.7.3.8 |
| `ocsp_signing` | 1.3.6.1.5.5.7.3.9 |
| `1.2.3.4.5.6` | raw dotted-decimal OID string |

**`crl_url` / `ocsp_url` three-state semantics**

| Value | Effect |
|-------|--------|
| Absent (key not set) | Inherit from `[ca].crl_url` / `[ca].ocsp_url` |
| `""` (empty string) | Suppress the extension — no CDP / AIA in the certificate |
| `"https://…"` | Override with the given URL |

---

### `dogtag` — Dogtag PKI profile files

Load profiles from a Dogtag PKI `.cfg` file directory. Each file is named `<profile-id>.cfg` and uses the Dogtag Java-properties format.

```toml
[profiles.providers.dogtag_prod]
type        = "dogtag"
profile_dir = "/etc/pki/pki-tomcat/ca/profiles/ca"
profiles    = ["caServerCert", "caIPAserviceCert"]
# profiles = []   # empty = load all .cfg files in the directory
```

| Key | Required | Description |
|-----|----------|-------------|
| `profile_dir` | Conditional | Path to directory of `.cfg` files |
| `ldap` | Conditional | LDAP connection; see below — **not yet implemented** |
| `profiles` | No | Allowlist of profile IDs; empty = all |

At least one of `profile_dir` or `ldap` must be set. If both are set, `profile_dir` is tried first; LDAP loading is not yet implemented and returns an error.

**Supported Dogtag policy classes**

| Class | Fields extracted |
|-------|-----------------|
| `validityDefaultImpl` | `params.range` + `params.rangeUnit` → validity days |
| `keyUsageExtDefaultImpl` | 9 `params.keyUsage*` booleans → KeyUsage bitmask |
| `extendedKeyUsageExtDefaultImpl` | `params.exKeyUsageOIDs` comma-separated OIDs → EKU list |
| `authInfoAccessExtDefaultImpl` | OCSP URL via method `1.3.6.1.5.5.7.48.1` → `ocsp_url` |
| `crlDistributionPointsExtDefaultImpl` | `params.crlDistPointsPointName_0` → `crl_url` |

Unrecognised policy class IDs are silently skipped.

> **Not yet implemented:** `certificatePoliciesExtDefaultImpl` — CertificatePolicies extension translation from Dogtag profiles is planned but not yet coded.

---

### `ipa` — FreeIPA / IPAThinCA

Load profiles from a FreeIPA or IPAThinCA instance. Profile `.cfg` files use the same Dogtag format. The standard location for IPA-embedded Dogtag is `/etc/pki/pki-tomcat/ca/profiles/ca` on the IPA server, and LDAP profiles are stored at `ou=certificateProfiles,ou=ca,o=ipaca` on port 7389.

```toml
[profiles.providers.ipa_prod]
type        = "ipa"
profile_dir = "/etc/pki/pki-tomcat/ca/profiles/ca"   # filesystem fallback
profiles    = ["caIPAserviceCert"]

# LDAP (not yet implemented — use profile_dir for now)
[profiles.providers.ipa_prod.ldap]
uri         = "ldap://ipa.example.com:7389"
base_dn     = "o=ipaca"
gssapi      = true
keytab_file = "/etc/akamu/akamu.keytab"
principal   = "akamu/akamu.example.com@EXAMPLE.COM"
```

**LDAP authentication options**

| Key | Description |
|-----|-------------|
| `gssapi = true` | Use SASL GSSAPI (Kerberos). Required for IPA. |
| `keytab_file` | Path to a Kerberos keytab for the service principal. When set together with `principal`, a TGT is obtained from the keytab before connecting. |
| `principal` | Kerberos principal, e.g. `akamu/host@REALM`. |
| `bind_dn` | Simple bind DN (for non-IPA Dogtag). Not compatible with `gssapi`. |
| `bind_password_file` | Path to a file containing the simple bind password. |
| `tls_ca_cert_file` | Path to a PEM CA certificate for verifying the LDAP server's TLS certificate. |
| `starttls` | If `true`, issue a StartTLS command after connecting on the plain port. |

> **Not yet implemented:** LDAP loading for both `dogtag` and `ipa` providers requires the `ldap3` crate (with SASL/GSSAPI support, linked against `libsasl2` and `libgssapi_krb5`). Until this is implemented, configure `profile_dir` as a filesystem fallback. Calling the LDAP path currently returns an error.

---

## Refresh behaviour

`Akāmu` loads all providers once at startup and caches the results. A background tokio task wakes every `refresh_interval_secs` seconds and re-loads all providers, atomically replacing the cache. Certificates being issued concurrently always see a consistent snapshot.

If a refresh fails (e.g., a `.cfg` file is temporarily unreadable), the previous cache is kept and a warning is logged. The server never stops serving because of a failed refresh.

The refresh task exits automatically when the server shuts down (it holds a weak reference to the registry).

```toml
[profiles]
refresh_interval_secs = 1800   # refresh every 30 minutes instead of 1 hour
```

---

## Precedence when multiple providers list the same profile

If two providers both export a profile with the same ID, the first provider listed in `config.toml` wins. The second is silently ignored. This is determined by `HashMap` iteration order over `[profiles.providers]`, which is non-deterministic in TOML. To avoid ambiguity, give each profile a unique ID across providers, or use a single canonical provider.

---

## Requesting a profile from an ACME client

Include `"profile"` in the `newOrder` payload:

```json
{
  "identifiers": [{ "type": "dns", "value": "example.com" }],
  "profile": "tlsserver"
}
```

The server:
1. Records the profile name on the order.
2. Validates the profile name at finalize time (rejects with `invalidProfile` if no longer loaded).
3. Issues the certificate using the profile's `CertificateParameters`.

The profile name is echoed back in every order response:

```json
{
  "status": "valid",
  "profile": "tlsserver",
  "certificate": "https://acme.example.com/acme/cert/…"
}
```

---

## Legacy `[server.profiles]`

Prior to the `[profiles]` subsystem, profile names were declared as a flat string map under `[server]`:

```toml
[server.profiles]
"tls-server-auth" = "https://acme.example.com/docs/profiles/tls-server-auth"
```

This still works for **advertising** profile names in the directory (the `meta.profiles` field). However, the map is a pure label registry — no actual certificate parameters are loaded from it, and any profile name is accepted at order time (no enforcement of key usage or EKU). Use the new `[profiles]` section for real per-profile issuance policy.

When `[profiles]` providers are configured, `meta.profiles` is populated from the registry; `[server.profiles]` is ignored.
