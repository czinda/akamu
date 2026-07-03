# Cross-Signing

Cross-signing lets one CA issue a certificate for another CA's public key, creating
an alternative trust chain. This is useful when:

- **Migrating between CAs** — a new CA can be cross-signed by the old one so that
  relying parties that only trust the old root can still validate certificates issued
  by the new CA.
- **Bridging to external PKI** — an Akamu CA can cross-sign an external CA (or
  vice versa) to establish mutual trust without replacing either root.
- **Multi-algorithm deployments** — an RSA CA can cross-sign an EC CA (or the
  reverse) so that clients supporting only one algorithm can validate certificates
  from either.

The resulting cross-certificate has `BasicConstraints: cA=TRUE, pathLen=0`, meaning
the subject CA may sign end-entity certificates but cannot create further subordinate
CAs. Key usage is restricted to `keyCertSign` and `cRLSign`.

## Prerequisites

- A running Akamu server with the `[admin]` section configured.
- An authenticated operator session with the `administrator` or `ca_operations`
  role. See [akamuctl — Admin CLI](akamuctl.md) for authentication methods.

## Listing available CAs

Before cross-signing, identify the CAs configured on your server:

```bash
akamuctl ca list
```

Example output:

```
ID       DEFAULT  KEY TYPE    HASH
rsa      yes      rsa:4096    sha256
ec       no       ec:P-256    sha256
```

The **issuer** is the CA that will sign the cross-certificate. The **subject** is
the CA whose public key will be signed.

## Cross-signing another CA on the same server

When both CAs are configured on the same Akamu instance, use `--subject-ca-id`:

```bash
akamuctl ca cross-sign rsa --subject-ca-id ec --validity-years 5
```

This makes the RSA CA (issuer) sign a certificate for the EC CA (subject). The
resulting cross-certificate is valid for 5 years.

Example JSON output (`-o json`):

```json
{
  "id": "a1b2c3d4-5678-9abc-def0-1234567890ab",
  "created_at": "2026-07-03T12:00:00Z"
}
```

The returned `id` is the UUID of the stored cross-certificate. Use it with the
`cross-cert` subcommands to inspect or download the certificate.

To cross-sign in the other direction (EC signs RSA):

```bash
akamuctl ca cross-sign ec --subject-ca-id rsa --validity-years 5
```

## Cross-signing an external CA

When the subject CA is not configured on this server, provide its certificate as
a PEM file using `--subject-cert`:

```bash
akamuctl ca cross-sign rsa \
    --subject-cert /path/to/partner-ca.pem \
    --validity-years 3
```

The PEM file must contain a CA certificate (`BasicConstraints: cA=TRUE`). The
server rejects end-entity certificates.

## Listing cross-certificates

List all cross-certificates stored on the server:

```bash
akamuctl cross-cert list
```

Filter by issuer or subject CA:

```bash
# All cross-certificates issued by the RSA CA
akamuctl cross-cert list --issuer-ca rsa

# All cross-certificates where the EC CA is the subject
akamuctl cross-cert list --subject-ca ec
```

Pagination is available via `--limit` and `--offset` (defaults: 100 and 0).

## Inspecting a cross-certificate

Show the full metadata for a cross-certificate by its UUID:

```bash
akamuctl cross-cert show a1b2c3d4-5678-9abc-def0-1234567890ab
```

This returns the issuer CA ID, subject CA ID (or `null` for external subjects),
serial number, validity window, creation timestamp, and the full PEM.

## Downloading a cross-certificate

Save the cross-certificate PEM to a file:

```bash
akamuctl cross-cert download a1b2c3d4-5678-9abc-def0-1234567890ab \
    -o cross-cert.pem
```

Without `-o`, the PEM is printed to stdout.

## Public discovery endpoint

Relying parties can discover cross-certificates without authentication via:

```
GET /ca/{ca_id}/cross-certs
```

This returns all cross-certificates where the specified CA is the **subject** (i.e.,
certificates that provide an alternative trust path to this CA). The response
includes the PEM for each cross-certificate.

Example:

```bash
curl https://acme.example.com/ca/ec/cross-certs
```

```json
{
  "cross_certs": [
    {
      "id": "a1b2c3d4-…",
      "issuer_ca_id": "rsa",
      "subject_dn": "CN=Akamu EC CA",
      "serial_number": "0a1b2c3d",
      "not_before": "2026-07-03T12:00:00Z",
      "not_after": "2031-07-03T12:00:00Z",
      "cross_cert_pem": "-----BEGIN CERTIFICATE-----\n…\n-----END CERTIFICATE-----\n",
      "created": "2026-07-03T12:00:00Z"
    }
  ]
}
```

ACME clients can use this endpoint to build complete certificate chains when the
subscriber's trust store does not include the issuing CA's root but does include
the cross-signing CA's root.

## Verifying a cross-certificate

After downloading, verify the cross-certificate chains back to the issuer CA:

```bash
# Download the issuer CA certificate
akamuctl ca cert rsa -o rsa-ca.pem

# Verify the cross-certificate
openssl verify -CAfile rsa-ca.pem cross-cert.pem
```

Expected output:

```
cross-cert.pem: OK
```

To inspect the cross-certificate's extensions:

```bash
openssl x509 -in cross-cert.pem -text -noout
```

Look for:

- `X509v3 Basic Constraints: critical` with `CA:TRUE, pathlen:0`
- `X509v3 Key Usage: critical` with `Certificate Sign, CRL Sign`
- `X509v3 Authority Key Identifier` matching the issuer CA's Subject Key Identifier
- `X509v3 Subject Key Identifier` matching the subject CA's public key

## Complete walkthrough

This example sets up bidirectional cross-signing between an RSA and EC CA, then
verifies both chains.

```bash
# 1. Authenticate
akamuctl login

# 2. List CAs to confirm both are configured
akamuctl ca list

# 3. RSA signs EC (EC certificates can be verified via the RSA root)
akamuctl ca cross-sign rsa --subject-ca-id ec --validity-years 5

# 4. EC signs RSA (RSA certificates can be verified via the EC root)
akamuctl ca cross-sign ec --subject-ca-id rsa --validity-years 5

# 5. List all cross-certificates
akamuctl cross-cert list

# 6. Download and verify the RSA→EC cross-certificate
akamuctl cross-cert list --issuer-ca rsa -o json | \
    jq -r '.cross_certs[0].id'
# Use the UUID from the output:
akamuctl cross-cert download <uuid> -o rsa-signs-ec.pem
akamuctl ca cert rsa -o rsa-ca.pem
openssl verify -CAfile rsa-ca.pem rsa-signs-ec.pem

# 7. Download and verify the EC→RSA cross-certificate
akamuctl cross-cert list --issuer-ca ec -o json | \
    jq -r '.cross_certs[0].id'
akamuctl cross-cert download <uuid> -o ec-signs-rsa.pem
akamuctl ca cert ec -o ec-ca.pem
openssl verify -CAfile ec-ca.pem ec-signs-rsa.pem
```

## Cross-certificate properties

| Property | Value |
|----------|-------|
| Basic Constraints | `cA=TRUE, pathLen=0` (critical) |
| Key Usage | `keyCertSign \| cRLSign` (critical) |
| Subject Key Identifier | From the subject CA's public key |
| Authority Key Identifier | From the issuer CA's public key |
| Validity computation | `validity_years` Julian years (365.25 days) from issuance time |
| Backdate | None (operator-initiated, not time-sensitive) |
| Maximum validity | 50 years |
| Minimum validity | 1 year |
