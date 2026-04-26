# Merkle Tree Certificate Log

`Akāmu` integrates with a Merkle Tree Certificate (MTC) transparency log using the `synta-mtc` library. When enabled, each issued end-entity certificate is appended as a leaf to a disk-backed append-only log.

## What is an MTC log?

A Merkle Tree Certificate log is a tamper-evident, append-only data structure. Each leaf is the SHA-256 hash (with Merkle domain separation) of the DER-encoded `TBSCertificateLogEntry` derived from the issued certificate's `TBSCertificate`. The log supports efficient proofs of inclusion and consistency that third parties can verify.

This is analogous in concept to Certificate Transparency (CT) logs (RFC 6962) but uses a different data structure and encoding based on the `synta-mtc` specification.

## Configuration

```toml
[mtc]
log_path = "/var/lib/akamu/mtc.log"
enabled  = true
```

When `enabled = true`:

- On startup, the server opens the existing log file at `log_path`, or creates a new one if the file does not exist.  A brand-new log is immediately seeded with a `null_entry` at index 0 (required by §5.3 of the MTC draft so that no real certificate ever receives log index 0 as its serial number).
- After each successful certificate issuance, the certificate is appended to the log asynchronously in a background task.
- The resulting leaf index (≥ 1) is stored in the `certificates` database table (`mtc_log_index` column).

When `enabled = false` (the default):
- The log file is never written.
- The `log_path` must still be specified but is not used.

## Log format

The log file is a binary file managed by `synta_mtc::storage::DiskBackedLog`. Entries are written as fixed-size SHA-256 hashes (32 bytes each) in leaf-order. The hash function includes Merkle tree domain separation to prevent second-preimage attacks.

The file is created by `DiskBackedLog::create` and opened by `DiskBackedLog::open`. The server uses a "try create first, fall back to open" strategy to eliminate time-of-check-to-time-of-use races.

## Appending certificates

Appending a certificate involves:

1. Parsing the DER-encoded certificate to extract the `TBSCertificate`.
2. Converting the `TBSCertificate` to a `TBSCertificateLogEntry` using `synta_mtc::integration::tbs_certificate_to_log_entry`.
3. DER-encoding the log entry.
4. Computing `hash_leaf(SHA-256, entry_der)` — the Merkle leaf hash with domain separation prefix `\x00`.
5. Appending the 32-byte hash to the log file under a `tokio::sync::Mutex` guard.

Steps 1–4 run in a `tokio::task::spawn_blocking` thread to avoid blocking the async executor with CPU-bound encoding work. Step 5 takes the mutex and writes.

If the append fails, a warning is logged but the certificate issuance response is not affected. The `mtc_log_index` column remains `NULL` in the database for that certificate.

## Checking the log index

Query the database to find the MTC log index for a certificate:

```sql
SELECT id, serial_number, mtc_log_index
FROM certificates
WHERE mtc_log_index IS NOT NULL
ORDER BY mtc_log_index;
```

A `NULL` index means the certificate was either issued before MTC logging was enabled, or the log append failed.

## HTTP API

Three read-only endpoints expose the log state.  All return 404 when MTC is disabled (`enabled = false`).

### `GET /acme/mtc/tree-size`

Returns the current number of leaves (including the null_entry at index 0).

```json
{ "treeSize": 42 }
```

### `GET /acme/mtc/root`

Returns the current tree size and the SHA-256 Merkle root as a lowercase hex string.

```json
{ "treeSize": 42, "rootHash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" }
```

### `GET /acme/mtc/inclusion-proof/{cert_id}`

Returns a Merkle inclusion proof for the certificate identified by `cert_id` (the internal UUID stored in the `certificates` table).  Returns 404 if the certificate does not exist or has no log index.

```json
{
  "leafIndex": 7,
  "treeSize": 42,
  "proof": [
    "a1b2c3...",
    "d4e5f6..."
  ]
}
```

`proof` is the ordered list of sibling hashes from the leaf up to the root, each encoded as a lowercase hex string.  The position of each sibling (left or right) can be derived from the bits of `leafIndex`.

## Concurrency

The `DiskBackedLog` is not thread-safe internally. The server wraps it in a `tokio::sync::Mutex<DiskBackedLog>` (the `SharedLog` type alias in `src/mtc/log.rs`). All leaf appends and reads acquire this mutex, serializing concurrent operations at the async level.

Multiple processes accessing the same log file concurrently are not supported. A single `Akāmu` process is the exclusive writer.

## Log integrity

The log is append-only by design. Once a leaf is appended it cannot be removed or modified without corrupting the file. The Merkle root can be computed from the log at any time using `compute_root`:

- For a log with zero leaves the root is undefined.
- For a log with one or more leaves the root is the SHA-256 Merkle root of all leaf hashes.

> **Scope note:** Akāmu implements the issuance-log portion of the MTC draft (draft-ietf-plants-merkle-tree-certs).  The following CA operations are intentionally out of scope for now: checkpoint signing and cosignature gathering (§6.2), MTC proof certificate construction with `id-alg-mtcProof` (§6.1), and landmark management (§6.3.1).  The log currently functions as an internal audit trail that satisfies the append-only and null-entry-at-index-zero invariants required by the draft; the HTTP API above exposes the tree state for external verification.
