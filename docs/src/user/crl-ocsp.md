# CRL and OCSP

`Akāmu` supports both Certificate Revocation List (CRL) and Online Certificate Status Protocol (OCSP) as optional mechanisms to communicate revocation status. Neither is served directly by the server; instead, the server embeds URLs in issued certificates that point to external services you operate.

## CRL Distribution Points

When `crl_url` is set in `[ca]`, every issued end-entity certificate contains a `CRLDistributionPoints` extension pointing to that URL:

```toml
[ca]
crl_url = "http://acme.example.com/crl/ca.crl"
```

Clients that check CRL status fetch the file at this URL and verify the certificate's serial number against the revocation list. Akāmu does not generate or publish the CRL file automatically. You are responsible for producing it and hosting it at the configured URL.

### What a CRL contains

When you generate a CRL from Akāmu's data, it will be a v2 CRL conforming to RFC 5280. It contains one entry for each revoked certificate, carrying the hex-encoded serial number, the revocation timestamp, and the reason code (if one was provided at revocation time).

### CRL reason codes

The reason codes that can be recorded at revocation time (see [Certificates](certificates.md)) are also recorded in the CRL:

| Code | CRL reason string |
|---|---|
| 0 | Unspecified |
| 1 | Key Compromise |
| 2 | CA Compromise |
| 3 | Affiliation Changed |
| 4 | Superseded |
| 5 | Cessation of Operation |
| 6 | Certificate Hold |
| 8 | Remove From CRL |
| 9 | Privilege Withdrawn |
| 10 | AA Compromise |

## OCSP

When `ocsp_url` is set in `[ca]`, every issued end-entity certificate contains an `AuthorityInfoAccess` extension with an OCSP responder URI:

```toml
[ca]
ocsp_url = "http://ocsp.example.com"
```

OCSP clients query this URL to determine the status of a specific certificate. Akāmu does not implement an OCSP responder. You must operate one separately (for example, using the `openssl ocsp` command or a dedicated OCSP responder service).

## Practical deployment

### Minimal CRL deployment

For a private CA deployment that only needs CRL-based revocation status:

1. Set `crl_url` to a URL you control, for example `http://acme.internal/crl/ca.crl`.
2. Periodically query the Akāmu database for revoked certificates and generate a signed CRL using the CA key. Akāmu exposes the necessary data — serial numbers, revocation timestamps, and reason codes — in the `certificates` table.
3. Publish the resulting CRL file at the configured URL.

For the internal data format used to build CRLs, see [Certificate Authority — CRL generation](../developer/ca.md#crl-generation-srccarevokers) in the Developer Guide.

### OCSP deployment

For deployments requiring OCSP:

1. Set `ocsp_url` to an OCSP responder you operate.
2. The OCSP responder needs access to the CA's private key (or a delegated OCSP signing key) and the list of issued and revoked certificates. This information lives in the Akāmu database.

### Checking revocation status from the database

To verify whether a specific certificate is currently marked as revoked in Akāmu's database, query the `certificates` table by serial number. The serial number is printed in hex by most certificate inspection tools (for example, `openssl x509 -serial -noout -in cert.pem`):

```sql
SELECT serial_number, status, revoked_at, revocation_reason
FROM certificates
WHERE serial_number = '<hex-serial>';
```

A `status` value of `revoked` indicates the certificate has been revoked. `revoked_at` is a Unix timestamp of when revocation occurred, and `revocation_reason` is the numeric CRL reason code (or NULL if no reason was specified).
