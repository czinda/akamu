# Public API Reference

This page is a consolidated reference for every public (non-admin) HTTP endpoint
served by Akāmu. Public endpoints do not require operator authentication —
they are accessed by ACME clients, relying parties, and peer nodes.

> **Multi-CA routing.** Most ACME and MTC endpoints are registered at both
> `/acme/{path}` and `/acme/{ca_id}/{path}`. The first form resolves to the
> default CA; the second addresses a specific CA by its configured `id`.
> The tables below use the notation `/acme[/{ca_id}]/{path}`.
>
> CRL/OCSP routes use `/ca[/{ca_id}]/{path}` with the same convention.

---

## ACME Core (RFC 8555)

All ACME endpoints (except nonces and certificate download via GET) require
JWS-authenticated POST requests per RFC 8555 §6.2. For supported JWS
algorithms, EAB wire format, and challenge type details, see
[ACME Protocol Reference](../client/protocol.md).

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/acme[/{ca_id}]/directory` | ACME directory object |
| `HEAD` | `/acme[/{ca_id}]/new-nonce` | Get a fresh replay nonce |
| `GET` | `/acme[/{ca_id}]/new-nonce` | Get a fresh replay nonce (alternative) |
| `POST` | `/acme[/{ca_id}]/new-account` | Create or find an account |
| `POST` | `/acme[/{ca_id}]/account/{id}` | Update or deactivate an account |
| `POST` | `/acme[/{ca_id}]/new-order` | Create a certificate order |
| `POST` | `/acme[/{ca_id}]/order/{id}` | Get order status |
| `POST` | `/acme[/{ca_id}]/order/{id}/finalize` | Submit CSR to finalize order |
| `POST` | `/acme[/{ca_id}]/new-authz` | Pre-authorization (RFC 8555 §7.4.1) |
| `POST` | `/acme[/{ca_id}]/authz/{id}` | Get authorization status |
| `POST` | `/acme[/{ca_id}]/chall/{authz_id}/{type}` | Respond to a challenge |
| `GET`, `POST` | `/acme[/{ca_id}]/cert/{id}` | Download issued certificate |
| `POST` | `/acme[/{ca_id}]/revoke-cert` | Revoke a certificate |
| `POST` | `/acme[/{ca_id}]/key-change` | Account key rollover |

### STAR (RFC 8739)

| Method | Path | Description |
|--------|------|-------------|
| `GET`, `POST` | `/acme[/{ca_id}]/cert/star/{order_id}` | Download current STAR rolling certificate |

STAR orders are created through `new-order` with the `auto-renewal` object.
The directory's `meta.auto-renewal` field advertises `min-lifetime`,
`max-duration`, and `allow-certificate-get` capabilities.

### Renewal Info — ARI (RFC 9773)

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/acme[/{ca_id}]/renewal-info/{cert_id}` | Get renewal information for a certificate |

The `cert_id` is the base64url-encoded SHA-256 hash of the certificate's DER
encoding. The response includes a suggested renewal window.

### Delegated Issuance (RFC 9115)

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/acme[/{ca_id}]/delegations/{account_id}` | List delegations for an account |
| `POST` | `/acme[/{ca_id}]/delegation/{id}` | Get delegation details |

---

## MTC Transparency Log

All MTC endpoints return `404 Not Found` when MTC logging is disabled for the
resolved CA. These are read-only, unauthenticated endpoints.

For configuration and operational details, see
[Merkle Tree Certificate Log](mtc.md).

### Tree state

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/acme[/{ca_id}]/mtc/tree-size` | Current tree size |
| `GET` | `/acme[/{ca_id}]/mtc/root` | Tree size and root hash |

**`GET /acme[/{ca_id}]/mtc/tree-size`** — Response:
```json
{ "treeSize": 42 }
```

**`GET /acme[/{ca_id}]/mtc/root`** — Response:
```json
{ "treeSize": 42, "rootHash": "a1b2c3..." }
```

### Inclusion proof

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/acme[/{ca_id}]/mtc/inclusion-proof/{cert_id}` | Merkle inclusion proof for a certificate |

**Response:**
```json
{
  "leafIndex": 7,
  "treeSize": 42,
  "proof": [
    { "hash": "a1b2..." },
    { "hash": "c3d4..." }
  ]
}
```

### Certificate retrieval

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/acme[/{ca_id}]/mtc/cert/{cert_id}/standalone` | Standalone MTC certificate (DER) |
| `GET` | `/acme[/{ca_id}]/mtc/cert/{cert_id}/landmark` | Landmark-relative MTC certificate (DER) |

Both return `Content-Type: application/pkix-cert` with an `X-MTC-Version` header.
The landmark endpoint returns `503 Service Unavailable` with a `Retry-After`
header when the landmark certificate is not yet available.

### Landmarks

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/acme[/{ca_id}]/mtc/landmarks` | List all landmarks (JSON) |
| `GET` | `/acme[/{ca_id}]/mtc/landmark-list` | Landmark list (text/plain, spec §3.4 format) |
| `GET` | `/acme[/{ca_id}]/mtc/landmarks/{seq}/cert` | Download landmark certificate by sequence number (DER) |

**`GET /acme[/{ca_id}]/mtc/landmarks`** — Response:
```json
[
  { "sequenceNo": 1, "treeSize": 100, "createdAt": 1700000000 },
  { "sequenceNo": 2, "treeSize": 200, "createdAt": 1700086400 }
]
```

**`GET /acme[/{ca_id}]/mtc/landmark-list`** — `text/plain` response in
spec §3.4 format:
```
{last_seq_no} {count}
{tree_size_newest}
...
{tree_size_oldest}
0
```

### Consistency and subtree proofs

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/acme[/{ca_id}]/mtc/consistency-proof?from={old}&to={new}` | Consistency proof between two tree sizes |
| `GET` | `/acme[/{ca_id}]/mtc/subtree-root?start={start}&end={end}` | Subtree root hash for range `[start, end)` |

**`GET /acme[/{ca_id}]/mtc/consistency-proof`** — Response:
```json
{
  "fromSize": 10,
  "toSize": 42,
  "fromRoot": "a1b2...",
  "toRoot": "c3d4..."
}
```

**`GET /acme[/{ca_id}]/mtc/subtree-root`** — The `start` parameter must be
aligned to `BIT_CEIL(end - start)` per §4.3.1. Response:
```json
{
  "start": 0,
  "end": 16,
  "rootHash": "a1b2..."
}
```

### Revoked ranges

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/acme[/{ca_id}]/mtc/revoked-ranges` | Revoked log entry index ranges (§5.6) |

**Response:** JSON array of `[start, end]` pairs:
```json
[[5, 8], [20, 22]]
```

### C2SP tlog-tiles API

These endpoints implement the
[C2SP tlog-tiles](https://c2sp.org/tlog-tiles) specification.

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/acme[/{ca_id}]/mtc/checkpoint` | Signed checkpoint (text/plain, signed-note format) |
| `GET` | `/acme[/{ca_id}]/mtc/cosignature` | Cosigner checkpoint (text/plain, signed-note format) |
| `GET` | `/acme[/{ca_id}]/mtc/discovery` | Issuer and cosigner metadata (JSON, CosignersStore-compatible) |
| `GET` | `/acme[/{ca_id}]/mtc/tile/{*path}` | Hash tile data (application/octet-stream) |

The checkpoint and cosignature endpoints return `text/plain` in C2SP signed-note
format. The origin line uses the OID-based format
`oid/1.3.6.1.4.1.{trust_anchor_id}.0.{log_number}`. Both require
`mtc.trust_anchor_id` to be configured; they return `503` otherwise.

Full tiles are served with `Cache-Control: public, max-age=86400`; partial tiles
use `Cache-Control: no-store`. Entry bundles (`tile/entries/…`) are not served
(returns `501 Not Implemented`).

---

## EAB Identity

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/acme/eab` | Derive EAB credentials for the authenticated principal |

This endpoint has no per-CA variant. Authentication is via Kerberos (SPNEGO
`Authorization: Negotiate` header or `X-Remote-User` from a trusted reverse
proxy). Returns deterministic EAB credentials derived via HKDF-SHA-256 from the
configured `eab_master_secret` and the authenticated principal.

For details, see [EAB and Kerberos Authentication](eab-kerberos.md).

---

## CRL and OCSP

These endpoints are unauthenticated and serve revocation information to relying
parties. For operational details, see [CRL and OCSP](crl-ocsp.md).

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/ca[/{ca_id}]/crl` | Download CRL (`application/pkix-crl`) |
| `POST` | `/ca[/{ca_id}]/ocsp` | OCSP request (`application/ocsp-request` → `application/ocsp-response`) |
| `GET` | `/ca[/{ca_id}]/ocsp/{request}` | OCSP request via GET (base64url-encoded) |
| `GET` | `/ca[/{ca_id}]/cross-certs` | Download cross-certificates (PEM bundle) |

---

## Email Webhook (RFC 8823)

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/acme/email-webhook` | Email-reply-00 challenge webhook |

HMAC-authenticated (not JWS). Request body is capped at 64 KiB. Used by the
`email-reply-00` challenge type to receive validation confirmations from an
email gateway.

---

## Gossip Sync

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/gossip/sync` | Inter-node gossip replication |

CMS SignedData-authenticated (ECDSA P-256 with pinned peer certificate). Used
for multi-node cluster replication. For setup details, see
[Cluster Setup and Gossip](../admin/cluster.md).
