# Merkle Tree Certificate Log

`Akāmu` integrates with a Merkle Tree Certificate (MTC) transparency log using the `synta-mtc` library. When enabled, each issued end-entity certificate is appended as a leaf to a disk-backed, append-only log.

For a complete list of all MTC public endpoints and their request/response schemas, see [Public API Reference](public-api.md#mtc-transparency-log).

## What is an MTC log?

A Merkle Tree Certificate log is a tamper-evident, append-only data structure. Each leaf encodes an issued certificate in a way that allows efficient proofs of inclusion and consistency that third parties can verify independently.

This is analogous in concept to Certificate Transparency (CT) logs (RFC 6962) but uses a different data structure and encoding based on the `synta-mtc` specification.

## Configuration

```toml
[mtc]
log_path = "/var/lib/akamu/mtc.log"
enabled  = true
```

When `enabled = true`:

- On startup, the server opens the existing log file at `log_path`, or creates a new one if the file does not exist.
- After each successful certificate issuance, the certificate is appended to the log. The append happens in a background task so it does not delay the issuance response.
- The resulting leaf index is stored in the `certificates` database table. If the append fails, a warning is logged but the certificate issuance response is not affected; the log index will be NULL for that certificate.

When `enabled = false` (the default):
- The log file is never written.
- The `log_path` must still be specified but is not used.

## Issuing MTC certificates directly from a profile

When `[mtc]` is enabled and `[mtc.signing_key]` is configured, a `builtin` certificate profile can be set to issue a Merkle Tree Certificate `StandaloneCertificate` instead of a standard X.509 PEM chain. Set `issue_as = "mtc"` on the profile:

```toml
[mtc]
log_path = "/var/lib/akamu/mtc.log"
enabled  = true

[mtc.signing_key]
key_file = "/var/lib/akamu/mtc-signing.key"
key_type = "ec:P-256"

[profiles.providers.local]
type = "builtin"

[profiles.providers.local.profiles.mtc-tls]
description = "MTC TLS certificate"
validity_days = 90
key_usage   = ["digital_signature"]
eku         = ["server_auth"]
issue_as    = "mtc"
```

When a client finalizes an order with this profile, the finalize handler:

1. Issues the X.509 `TBSCertificate` as usual.
2. Appends the certificate to the MTC log synchronously (not in a background task, because the leaf index is needed immediately for the standalone certificate).
3. Builds a `StandaloneCertificate` embedding the `TBSCertificate`, a Merkle inclusion proof, and a signature from the MTC signing key.
4. Stores the DER-encoded `StandaloneCertificate` and returns the certificate URL to the client.

The certificate download endpoint (`GET /acme/cert/{id}`) detects MTC certificates and serves them as raw DER with `Content-Type: application/pkix-cert`.

If `[mtc]` is not enabled or `[mtc.signing_key]` is absent when a profile with `issue_as = "mtc"` is finalized, the server returns `invalidProfile`.

See [Certificate Profiles — MTC certificate issuance](profiles.md#mtc-certificate-issuance-issue_as--mtc) for the full configuration reference.

### Checkpoint signing

To enable periodic checkpoint production, add a `[mtc.signing_key]` section. The signing key **must** be distinct from the X.509 CA key (§5.5 of the MTC draft).

```toml
[mtc]
log_path                 = "/var/lib/akamu/mtc.log"
enabled                  = true
checkpoint_interval_secs = 3600    # default: 3600 (1 hour)
landmark_interval_secs   = 86400   # default: 86400 (1 day)
max_active_landmarks     = 100     # default: 100
hash_alg                 = "sha256"  # leaf hash algorithm: sha256 | sha384 | sha512 | sha3-256 | sha3-384 | sha3-512
log_number               = 1        # serial encoding: (log_number << 48) | entry_index
# tree_minimum_index     = 0        # §5.2.3 log pruning; absent = no pruning
# trust_anchor_id        = "1.3.6.1.4.1.44363.47.10.1"  # CA self-cosigner OID (§5.4)

[mtc.signing_key]
key_file = "/var/lib/akamu/mtc-signing.key"   # auto-generated if absent
key_type = "ec:P-256"                          # same values as [ca].key_type
hash_alg = "sha256"                            # sha256 | sha384 | sha512
```

Supported `key_type` values are the same set accepted for the CA key: `ec:P-256`, `ec:P-384`, `ec:P-521`, `rsa:2048`–`rsa:4096`, `ed25519`, `ed448`, `ml-dsa-44`, `ml-dsa-65`, `ml-dsa-87`. Per §5.4.2 of the draft, only ECDSA P-256/P-384, Ed25519, and ML-DSA are listed as valid cosigner signature algorithms; prefer EC or EdDSA for the MTC signing key.

When `[mtc.signing_key]` is present:

- At startup the server reads the PEM file at `key_file`, or auto-generates a new key of `key_type` and writes it there.
- A background task fires every `checkpoint_interval_secs` seconds. If the log has grown since the last checkpoint, it computes the Merkle root, constructs a signed checkpoint, and stores it in the database.
- Checkpoints are idempotent: if the tree size has not grown the task is a no-op.

When `[mtc.signing_key]` is absent, checkpoint production is disabled.

### External cosigners

After each checkpoint, Akāmu can POST the checkpoint to external cosigner servers and embed their signatures in each `StandaloneCertificate`.

```toml
[[mtc.cosigners]]
url                  = "https://cosigner.example.com/sign"
cosigner_id_cert_pem = "/etc/akamu/cosigner1.pem"  # optional; path to cosigner X.509 cert PEM
trust_anchor_id      = "1.3.6.1.4.1.44363.47.10.1" # optional; expected TrustAnchorID OID
```

Multiple `[[mtc.cosigners]]` entries are supported. For each entry:

- Akāmu POSTs the DER-encoded checkpoint with `Content-Type: application/octet-stream`.
- The cosigner returns a DER-encoded signature with HTTP 200.
- Each request has a 30-second per-cosigner timeout.
- Failures are logged and skipped — partial success is acceptable; the standalone certificate is still built with whatever signatures arrive.

When `cosigner_id_cert_pem` is set, the PEM file is loaded at startup and added to the TLS trust store for that cosigner's HTTPS connection, in addition to the system root CAs. The certificate's public key is also used for cryptographic verification of received `SubtreeSignature` values. This allows cosigners whose TLS certificate chains to an operator-provisioned CA to be used without installing that CA system-wide.

When `trust_anchor_id` is set, the `SubtreeSignature.cosigner` value in each response is compared against this value. Per draft-ietf-plants-merkle-tree-certs-05 §4.1, `CosignerID` is `TrustAnchorID ::= RELATIVE-OID`; a mismatch causes the signature to be rejected.

> **Security constraint:** Setting `trust_anchor_id` without also setting `cosigner_id_cert_pem` is a hard startup error. OID-only verification provides no cryptographic assurance — anyone who knows the OID could forge a cosignature. Both fields must be set together to enable verified cosignature acceptance. When neither field is set, cosignatures are accepted without any verification and a warning is logged at startup.

## Querying the log index

To find which MTC log slot a certificate occupies, query the database:

```sql
SELECT id, serial_number, mtc_log_index
FROM certificates
WHERE mtc_log_index IS NOT NULL
ORDER BY mtc_log_index;
```

A NULL index means the certificate was either issued before MTC logging was enabled, or the log append failed at issuance time.

## HTTP API

The following read-only endpoints expose the log state. All return 404 when MTC is disabled (`enabled = false`).

### `GET /acme/mtc/tree-size`

Returns the current number of leaves in the log.

```json
{ "treeSize": 42 }
```

### `GET /acme/mtc/root`

Returns the current tree size and the Merkle root hash as a lowercase hex string.

```json
{ "treeSize": 42, "rootHash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" }
```

### `GET /acme/mtc/inclusion-proof/{cert_id}`

Returns a Merkle inclusion proof for the certificate identified by `cert_id` (the internal UUID stored in the `certificates` table). Returns 404 if the certificate does not exist or has no log index.

```json
{
  "leafIndex": 7,
  "treeSize": 42,
  "proof": [
    { "hash": "a1b2c3..." },
    { "hash": "d4e5f6..." }
  ]
}
```

Each element of `proof` is an object with a single `"hash"` field containing the sibling hash as a lowercase hex string. The proof is ordered from the leaf up to the root. The sibling position (left or right) is determined algorithmically from the leaf index and tree size, following the RFC 9162 §2.1 Merkle audit proof construction; it is not encoded in the response.

### `GET /acme/mtc/cert/{cert_id}/standalone`

Returns the DER-encoded standalone certificate (§6.1 of the MTC draft) for the given certificate, with `Content-Type: application/octet-stream`.

The standalone certificate embeds the certificate's TBS data, a Merkle inclusion proof, and a signature from the MTC signing key. Relying parties can verify the certificate's presence in the log without querying the CA.

Returns 404 when:
- MTC is disabled
- The certificate does not exist
- The certificate has no MTC log index (the log append failed at issuance)
- A checkpoint covering the certificate has not yet been produced (the standalone certificate is built during the next checkpoint cycle)

### `GET /acme/mtc/landmark-list`

Returns the landmark list in the spec §3.4 text/plain format. This is the format consumed by `LandmarkDistributor` clients and spec-compliant relying parties.

```
<last_seq_no> <count>
<tree_size for newest landmark>
<tree_size for second-newest landmark>
...
<prev_tree_size>
```

`Content-Type` is `text/plain; charset=utf-8`. Returns an empty body (not 404) when there are no landmarks yet.

### `GET /acme/mtc/cert/{cert_id}/landmark`

Returns the DER-encoded `LandmarkCertificate` for the smallest landmark whose `tree_size` covers the certificate's log index, with `Content-Type: application/pkix-cert`.

Returns 503 with `Retry-After` when:
- A covering landmark exists but its certificate has not been built yet.
- No landmark covers this certificate's log index yet.

Returns 404 when MTC is disabled or the certificate does not exist.

### `GET /acme/mtc/landmarks`

Returns a JSON array of all allocated landmarks, ordered by sequence number ascending (akamu-specific format; use `landmark-list` for spec-compliant clients).

```json
[
  { "sequenceNo": 0, "treeSize": 100, "createdAt": 1700000000 },
  { "sequenceNo": 1, "treeSize": 250, "createdAt": 1700086400 }
]
```

Returns 404 when MTC is disabled.

### `GET /acme/mtc/landmarks/{seq}/cert`

Returns the DER-encoded landmark certificate (§6.3.1 of the MTC draft) for the landmark with sequence number `seq`, with `Content-Type: application/octet-stream`.

Returns 404 when:
- MTC is disabled
- No landmark with that sequence number exists
- The landmark certificate has not yet been built

### `GET /acme/mtc/consistency-proof?from={old_size}&to={new_size}`

Returns the Merkle roots at two tree sizes so a monitor can verify that the tree at `to` extends the tree at `from`.

```json
{
  "fromSize": 10,
  "toSize": 42,
  "fromRoot": "a1b2c3...",
  "toRoot": "d4e5f6..."
}
```

Both `from` and `to` must be positive integers with `from < to` and `to <= current tree size`. Returns 400 for invalid parameters.

### `GET /acme/mtc/subtree-root?start={start}&end={end}`

Returns the Merkle root hash for the subtree `[start, end)`. The subtree must satisfy the alignment constraint from draft-05 §4.3.1 (`start` is a multiple of `BIT_CEIL(end - start)`).

```json
{
  "start": 0,
  "end": 256,
  "rootHash": "e3b0c442..."
}
```

### `GET /acme/mtc/revoked-ranges`

Returns a JSON array of `[start, end]` pairs representing revoked log entry index ranges (draft-05 §7.5). Relying parties use these to reject standalone certificates whose serial number falls within a revoked range.

```json
[[10, 15], [100, 120]]
```

Returns 404 when MTC is disabled.

## C2SP tlog-tiles API

When `[mtc.signing_key]` is configured, three additional endpoints implement the [C2SP tlog-tiles](https://c2sp.org/tlog-tiles) and [C2SP signed-note](https://c2sp.org/signed-note) specifications, enabling compatibility with transparency-log clients that speak the tlog-tiles protocol.

All three endpoints return 404 when MTC is disabled. `GET /acme/mtc/checkpoint` and `GET /acme/mtc/cosignature` additionally require a signing key to be configured; without one they return 503.

### `GET /acme/mtc/checkpoint`

Returns the current tree as a C2SP signed-note checkpoint signed by the MTC signing key acting as the primary log operator.

- Ed25519 key: signature type 0x01.
- ECDSA key: signature type 0x02.

Response `Content-Type` is `text/plain; charset=utf-8`. The note body format is:

```
<log origin>
<tree_size>
<base64(root_hash)>

— <key_name> <base64(key_id || signature)>
```

### `GET /acme/mtc/tile/{*path}`

Serves a C2SP hash tile. The path component encodes `{level}/{tile_index_path}[.p/{width}]`:

- `level` is 0 for leaf-hash tiles, or L > 0 for Merkle subtree roots (covering 256^L leaves each).
- `tile_index_path` is the C2SP multi-level decimal encoding (e.g. `000`, `x001/234`).
- The optional `.p/{width}` suffix requests a partial tile with fewer than 256 entries.

Response `Content-Type` is `application/octet-stream`; each hash entry is 32, 48, or 64 bytes depending on the `[mtc].hash_alg` configured for the log (SHA-256/SHA3-256, SHA-384/SHA3-384, or SHA-512/SHA3-512 respectively).

Returns 404 when the tile is entirely beyond the current log size. Returns 501 for `tile/entries/...` paths because Akāmu stores only leaf hashes, not raw entry data.

### `GET /acme/mtc/cosignature`

Returns a C2SP cosignature note for the current checkpoint, produced by the MTC signing key acting as a cosigner. The current POSIX timestamp is embedded in the signature blob.

- Ed25519 key: cosignature type 0x04 (`cosignature/v1` signed-note format).
- ML-DSA-44 key: cosignature type 0x06 (`subtree/v1` binary cosigned message).
- ECDSA key: uses the operator format (type 0x02) because no dedicated ECDSA cosignature type is defined by C2SP.

Response `Content-Type` is `text/plain; charset=utf-8`.

## Landmark management

A *landmark* is a frozen snapshot of the tree size at a point in time. Relying parties use landmarks to anchor inclusion proofs across the log's lifetime without tracking every checkpoint.

When `[mtc.signing_key]` is configured, a background task fires every `landmark_interval_secs` seconds (default: 86400 = 1 day). If the tree has grown since the last landmark, a new landmark is built and stored in the database. Rows beyond `max_active_landmarks` (default: 100) are pruned automatically, removing the oldest landmarks by sequence number.

## Log integrity

The log is append-only by design. Once a leaf is appended it cannot be removed or modified without corrupting the file. A single Akāmu process is the exclusive writer. At startup, Akāmu acquires an exclusive advisory lock on `<log_path>.lock`; if another process already holds the lock the server exits immediately with a clear error rather than proceeding to corrupt the log.

For details on the internal log format, appending algorithm, checkpoint production, and concurrency model, see [MTC Implementation](../developer/mtc.md) in the Developer Guide.

## See also

- [MTC Cosigner Daemon](cosigner.md) — external cosigner binary for independent checkpoint signing
- [Certificate Downloads and Formats](certificates.md) — MTC standalone certificate download endpoints
- [Certificate Profiles](profiles.md) — `issue_as = "mtc"` profile configuration for MTC issuance
- [akamu-client — MtcClient](../client/client-library.md#mtcclient) — Rust client library for querying and verifying MTC logs
- [akamu-cli — MTC subcommands](../client/cli.md#mtc-subcommands) — command-line tools for MTC log queries and certificate verification
