# CRL and OCSP

`Akāmu` supports both Certificate Revocation List (CRL) and Online Certificate Status Protocol (OCSP) to communicate revocation status to relying parties. Both protocols are served directly by Akāmu at built-in endpoints.

## CRL — `GET /ca/crl`

Akāmu generates and serves a signed v2 CRL (RFC 5280) at:

```
GET /ca/crl
```

The CRL is built on each request from the current revocation database. No caching or pre-generation is required for typical issuance volumes. The response uses `Content-Type: application/pkix-crl`.

### Configuring the CRL URL

Set `crl_url` in `[ca]` to the public URL of the `/ca/crl` endpoint. This URL is embedded in every issued end-entity certificate in the `CRLDistributionPoints` extension:

```toml
[ca]
crl_url = "http://acme.example.com/ca/crl"
```

Clients that check CRL status fetch this URL and verify the certificate's serial number against the revocation list.

### CRL validity window

The `nextUpdate` field in the CRL is set to the current time plus `crl_next_update_secs` (default: 86400 seconds, i.e. one day):

```toml
[ca]
crl_next_update_secs = 86400   # one day (default)
```

Adjust this value to match how frequently clients are expected to re-fetch the CRL.

### What a CRL contains

Each CRL entry carries the certificate's serial number, the revocation timestamp, and the reason code (if one was provided at revocation time). The CRL also includes a `cRLNumber` extension (RFC 5280 §5.2.3) derived from the current Unix timestamp.

### CRL reason codes

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

### Verifying the CRL manually

```bash
curl http://acme.example.com/ca/crl | openssl crl -inform DER -text -noout
```

## OCSP — `GET /ca/ocsp/{request}` and `POST /ca/ocsp`

Akāmu includes a built-in OCSP responder (RFC 6960) at:

```
POST /ca/ocsp                 # body: DER OCSPRequest, Content-Type: application/ocsp-request
GET  /ca/ocsp/{request}       # {request}: base64url-encoded DER OCSPRequest (RFC 6960 §A.1)
```

Both endpoints return a signed `OCSPResponse` with `Content-Type: application/ocsp-response`. No authentication is required — OCSP is a public protocol.

### Configuring the OCSP URL

Set `ocsp_url` in `[ca]` to the public base URL of the OCSP endpoint. This URL is embedded in every issued end-entity certificate in the `AuthorityInfoAccess` extension:

```toml
[ca]
ocsp_url = "http://acme.example.com/ca/ocsp"
```

Clients sending GET requests append the base64url-encoded request to this URL. Clients sending POST requests target the URL directly.

### OCSP response behaviour

For each serial number in an OCSPRequest:

| DB state | OCSP CertStatus |
|---|---|
| Certificate not found | `unknown` (2) |
| Certificate found, `status = "revoked"` | `revoked` (1) |
| Certificate found, any other status | `good` (0) |

The response is signed with the CA key. The responder identity is set to `byName` using the CA's subject DER.

The `nextUpdate` field in each `SingleResponse` is fixed at 24 hours after the response is produced.

### Verifying OCSP manually

```bash
openssl ocsp -issuer ca.pem -cert issued.pem -url http://acme.example.com/ca/ocsp -text
```

## Checking revocation status from the database

To verify whether a specific certificate is currently marked as revoked in Akāmu's database, query the `certificates` table by serial number. The serial number is printed in hex by most certificate inspection tools (for example, `openssl x509 -serial -noout -in cert.pem`):

```sql
SELECT serial_number, status, revoked_at, revocation_reason
FROM certificates
WHERE serial_number = '<hex-serial>';
```

A `status` value of `revoked` indicates the certificate has been revoked. `revoked_at` is a Unix timestamp of when revocation occurred, and `revocation_reason` is the numeric CRL reason code (or NULL if no reason was specified).
