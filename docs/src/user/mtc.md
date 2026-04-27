# Merkle Tree Certificate Log

`Akāmu` integrates with a Merkle Tree Certificate (MTC) transparency log using the `synta-mtc` library. When enabled, each issued end-entity certificate is appended as a leaf to a disk-backed, append-only log.

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

### Checkpoint signing

To enable periodic checkpoint production, add a `[mtc.signing_key]` section. The signing key **must** be distinct from the X.509 CA key (§5.5 of the MTC draft).

```toml
[mtc]
log_path                 = "/var/lib/akamu/mtc.log"
enabled                  = true
checkpoint_interval_secs = 3600    # default: 3600 (1 hour)
landmark_interval_secs   = 86400   # default: 86400 (1 day)
max_active_landmarks     = 100     # default: 100

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
```

Multiple `[[mtc.cosigners]]` entries are supported. For each entry:

- Akāmu POSTs the DER-encoded checkpoint with `Content-Type: application/octet-stream`.
- The cosigner returns a DER-encoded signature with HTTP 200.
- Each request has a 30-second per-cosigner timeout.
- Failures are logged and skipped — partial success is acceptable; the standalone certificate is still built with whatever signatures arrive.

When `cosigner_id_cert_pem` is set, the PEM file is loaded at checkpoint time and added to the TLS trust store for that cosigner's connection, in addition to the system root CAs. This allows cosigners whose TLS certificate chains to an operator-provisioned CA to be used without installing that CA system-wide.

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

Three read-only endpoints expose the log state. All return 404 when MTC is disabled (`enabled = false`).

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
    { "left": true,  "hash": "a1b2c3..." },
    { "left": false, "hash": "d4e5f6..." }
  ]
}
```

Each element of `proof` is an object with two fields: `"left"` (a boolean indicating whether the sibling is to the left of the current node) and `"hash"` (the sibling hash as a lowercase hex string). The proof is ordered from the leaf up to the root.

### `GET /acme/mtc/cert/{cert_id}/standalone`

Returns the DER-encoded standalone certificate (§6.1 of the MTC draft) for the given certificate, with `Content-Type: application/octet-stream`.

The standalone certificate embeds the certificate's TBS data, a Merkle inclusion proof, and a signature from the MTC signing key. Relying parties can verify the certificate's presence in the log without querying the CA.

Returns 404 when:
- MTC is disabled
- The certificate does not exist
- The certificate has no MTC log index (the log append failed at issuance)
- A checkpoint covering the certificate has not yet been produced (the standalone certificate is built during the next checkpoint cycle)

### `GET /acme/mtc/landmarks`

Returns a JSON array of all allocated landmarks, ordered by sequence number ascending.

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

## Landmark management

A *landmark* is a frozen snapshot of the tree size at a point in time. Relying parties use landmarks to anchor inclusion proofs across the log's lifetime without tracking every checkpoint.

When `[mtc.signing_key]` is configured, a background task fires every `landmark_interval_secs` seconds (default: 86400 = 1 day). If the tree has grown since the last landmark, a new landmark is built and stored in the database. Rows beyond `max_active_landmarks` (default: 100) are pruned automatically, removing the oldest landmarks by sequence number.

## Log integrity

The log is append-only by design. Once a leaf is appended it cannot be removed or modified without corrupting the file. A single Akāmu process is the exclusive writer; multiple processes accessing the same log file concurrently are not supported.

For details on the internal log format, appending algorithm, checkpoint production, and concurrency model, see [MTC Implementation](../developer/mtc.md) in the Developer Guide.
