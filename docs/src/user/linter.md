# Pre-Issuance Linter

`Akāmu` lints every certificate immediately after signing it and before recording it in the database. The linter re-parses the DER, verifies the CA signature, and checks that the certificate conforms to a policy profile. If any check fails the issuance is rejected and the client receives an error — the certificate is never stored.

---

## Built-in profiles

Two profiles are always available; no configuration is required to use them.

| Name | Base standard | Intended use |
|------|--------------|--------------|
| `"webpki"` | CA/B Forum Baseline Requirements | Public TLS server certificates |
| `"rfc5280"` | RFC 5280 | Internal PKI, client auth, non-browser use cases |

**What each profile enforces**

| Check | `webpki` | `rfc5280` |
|-------|----------|-----------|
| SAN present | Required | Optional |
| SAN criticality | Critical when subject empty; non-critical otherwise | Not enforced |
| Name Constraints on EE | Must be absent | Optional |
| `cA=FALSE` on EE cert | Enforced | Not enforced |
| AKI present | Always | Always |
| Algorithm allowlists | Classical + ML-DSA + composite | Same |
| RSA modulus | ≥ 2048 bits | ≥ 2048 bits |

> **EKU** is never checked by the linter. Certificate profiles already define
> the EKU; enforcing a specific EKU in the linter would conflict with profiles
> that use non-`serverAuth` extended key usages.

> **CA certificates** (cross-signed by `Akāmu`) always use RFC 5280 linting
> regardless of the configured base, because the WebPKI profile rejects
> `cA=TRUE` in the EE position.

---

## Defining custom profiles

Add a `[linter]` section to `config.toml`. User-defined profiles start from a built-in base and override individual fields.

```toml
[linter]

[linter.profiles.internal-pki]
base                   = "rfc5280"      # "webpki" (default) or "rfc5280"
san                    = "optional"     # "required" | "optional" | "absent"
name_constraints       = "optional"     # "required" | "optional" | "absent"
algorithms             = "webpki_pq"   # "webpki" | "webpki_pq" | "pq_only"
minimum_rsa_bits       = 2048          # u32; default: 2048
```

### Field reference

| Field | Default | Description |
|-------|---------|-------------|
| `base` | `"webpki"` | Base policy: `"webpki"` (CA/B Forum BR) or `"rfc5280"`. All other fields start from the base's defaults and override only the ones you set. |
| `san` | base default | Subject Alternative Name presence: `"required"` (SAN must be present), `"optional"` (SAN may or may not be present), `"absent"` (SAN must not be present). |
| `name_constraints` | base default | Name Constraints extension presence: same three values. `"absent"` is the `webpki` default; `"optional"` is the `rfc5280` default. |
| `algorithms` | `"webpki_pq"` | Permitted key and signature algorithm sets. See [algorithm tiers](#algorithm-tiers) below. |
| `minimum_rsa_bits` | `2048` | Minimum RSA public key modulus size in bits. Values smaller than 2048 are accepted in config but are strongly discouraged. |

### Algorithm tiers

| Value | Permitted key types | Permitted signature algorithms |
|-------|---------------------|-------------------------------|
| `"webpki"` | RSA, EC (P-256/P-384/P-521), Ed25519, Ed448 | SHA-256/384/512-RSA, RSA-PSS, ECDSA-SHA256/384/512, Ed25519, Ed448 |
| `"webpki_pq"` *(default)* | All of the above + ML-DSA-44/65/87, ML-KEM-512/768/1024, and 18 composite ML-DSA variants | All of the above + ML-DSA-44/65/87 + 18 composite ML-DSA variants |
| `"pq_only"` | ML-DSA-44/65/87, ML-KEM-512/768/1024 | ML-DSA-44/65/87 |

---

## Assigning profiles

### Per certificate profile

Add a `linter` field to any builtin certificate profile:

```toml
[profiles.providers.local.profiles.internal-server]
description = "Internal server certificate"
linter      = "internal-pki"   # name from [linter.profiles.*], or "webpki" / "rfc5280"
```

### Per CA (default)

Set a CA-level default that applies when a certificate profile does not specify a linter:

```toml
[ca]
default_linter = "internal-pki"
```

### Resolution order

At issuance time the linter profile is resolved as follows:

1. The certificate profile's `linter` field, if set.
2. The issuing CA's `default_linter`, if set.
3. The built-in `"webpki"` profile.

---

## Examples

### SAN-only certificates (empty subject DN)

Certificates with no subject DN fields and a SAN-only identity are fully supported without any linter customisation. `Akāmu` automatically marks the SAN extension as critical when the subject is empty, satisfying RFC 5280 §4.1.2.6, so the default `"webpki"` linter passes without any override.

```toml
[profiles.providers.local.profiles.device-cert]
description = "IoT device — SAN only, no subject DN"
key_usage   = ["digital_signature"]
eku         = ["client_auth"]
# No linter override needed; empty-subject criticality is handled automatically.
```

### RFC 5280 for internal PKI

An internal CA that issues certificates to services on a private network, with no requirement to follow CA/B Forum rules.

```toml
[linter.profiles.internal]
base             = "rfc5280"
san              = "optional"
name_constraints = "optional"

[ca]
default_linter = "internal"
```

### Post-quantum only

Enforce that all certificates use post-quantum keys and signatures.

```toml
[linter.profiles.pq-strict]
base       = "webpki"
algorithms = "pq_only"

[profiles.providers.local.profiles.pq-tls]
description     = "PQ-only TLS server certificate"
cert_key_type   = "ml-dsa-65"
linter          = "pq-strict"
```

### Relaxed modulus floor

An organisation still operating 1024-bit RSA legacy devices (not recommended).

```toml
[linter.profiles.legacy-rsa]
base             = "rfc5280"
minimum_rsa_bits = 1024
```

---

## Hardcoded checks

The following checks are always enforced regardless of the linter profile, because they come from `synta_x509_verification` logic that has no override point:

- X.509 version 3
- Serial number: ≤ 20 octets, positive integer
- `signatureAlgorithm` outer field matches TBS field
- Validity window: `notBefore ≤ now ≤ notAfter`
- EC keys: named curve form only (no explicit parameters)
- ML-DSA keys: parameter field absent
- AKI extension: always required
- CA signature over the EE certificate: always re-verified
