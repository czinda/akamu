# CRL and OCSP

`Akāmu` supports both Certificate Revocation List (CRL) and Online Certificate Status Protocol (OCSP) as optional mechanisms to communicate revocation status. Neither is served directly by the server; instead, the server embeds URLs in issued certificates that point to external services.

## CRL Distribution Points

When `crl_url` is set in `[ca]`, every issued end-entity certificate contains a `CRLDistributionPoints` extension pointing to that URL:

```toml
[ca]
crl_url = "http://acme.example.com/crl/ca.crl"
```

Clients that check CRL status will fetch the file at this URL and verify the serial number of the certificate against the revocation list.

### Generating a CRL

The CRL generation capability is implemented in `src/ca/revoke.rs` via the `build_crl` function. The server does not automatically generate or publish CRL files; you must write tooling around the CA key and the revoked certificate records in the database to produce and serve the CRL.

A v2 CRL is generated using:
- The CA's private key for signing.
- The CA's subject name as the issuer.
- The current timestamp as `thisUpdate`.
- A configurable `nextUpdate` offset.
- A CRL Number extension containing the current Unix timestamp as a monotonically increasing integer.
- One revoked certificate entry per revoked certificate, each with the serial number, revocation time, and optional reason code.

### CRL reason codes

The same reason codes used for revocation (see [Certificates](certificates.md)) are recorded in the CRL:

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

OCSP clients query this URL to determine the status of a specific certificate. The server does not implement an OCSP responder; you must operate one separately.

## Checking revocation status

You can check whether a certificate stored in the database is revoked by querying the `certificates` table directly:

```sql
SELECT id, serial_number, status, revoked_at, revocation_reason
FROM certificates
WHERE serial_number = '<hex-serial>';
```

A `status` of `'revoked'` indicates the certificate has been revoked, along with the Unix timestamp of revocation and the reason code.

## Practical deployment

For a minimal private CA deployment that only needs revocation status for internal clients:

1. Set `crl_url` to a URL you control, for example `http://acme.internal/crl/ca.crl`.
2. Periodically query the database for revoked certificates and build a CRL with the `build_crl` function.
3. Publish the CRL at the URL.

For larger deployments requiring OCSP:

1. Set `ocsp_url` to an OCSP responder you operate (e.g., OpenSSL's `ocsp` command or a dedicated OCSP responder service).
2. The OCSP responder must have access to the CA's private key (or a delegated OCSP signing key) and the list of revoked certificates from the database.
