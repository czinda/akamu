# MTC Implementation

This chapter describes the internal design of the Merkle Tree Certificate (MTC) log integration: how certificates are appended, how checkpoints are produced, and the concurrency model.

## Log storage

The log file is a binary file managed by `synta_mtc::storage::DiskBackedLog`. Entries are written as fixed-size SHA-256 hashes (32 bytes each) in leaf-order. The hash function includes Merkle tree domain separation (a `\x00` prefix byte) to prevent second-preimage attacks.

The file is created by `DiskBackedLog::create` and opened by `DiskBackedLog::open`. The server uses a "try create first, fall back to open" strategy to eliminate time-of-check-to-time-of-use races at startup (`src/mtc/log.rs::open_or_create`).

A brand-new log is immediately seeded with a `null_entry` at index 0 (required by §5.3 of the MTC draft so that no real certificate ever receives log index 0 as its serial number).

## Appending a certificate

Appending a certificate leaf involves:

1. Parsing the DER-encoded certificate to extract the `TBSCertificate`.
2. Converting the `TBSCertificate` to a `TBSCertificateLogEntry` using `synta_mtc::integration::tbs_certificate_to_log_entry`.
3. DER-encoding the log entry.
4. Computing `hash_leaf(SHA-256, entry_der)` — the Merkle leaf hash with the `\x00` domain separation prefix.
5. Appending the 32-byte hash to the log file under a `tokio::sync::Mutex` guard.

Steps 1–4 run in a `tokio::task::spawn_blocking` thread to avoid blocking the async executor with CPU-bound encoding work. Step 5 takes the mutex and writes.

If the append fails, a warning is logged but the certificate issuance response is not affected. The `mtc_log_index` column remains `NULL` in the database for that certificate.

## Concurrency model

`DiskBackedLog` is not thread-safe internally. The server wraps it in a `tokio::sync::Mutex<DiskBackedLog>` (the `SharedLog` type alias in `src/mtc/log.rs`). All leaf appends and reads acquire this mutex, serializing concurrent operations at the async level.

Multiple processes accessing the same log file concurrently are not supported. A single Akāmu process is the exclusive writer.

## Checkpoint production

The checkpoint background task (`src/mtc/checkpoint.rs`) fires every `checkpoint_interval_secs` seconds. If the log has grown since the last checkpoint:

1. It acquires the `SharedLog` mutex and reads the current tree size and computes the Merkle root via `compute_root`.
2. It constructs a `Checkpoint` structure (per §6.2 of the MTC draft).
3. It DER-encodes the `Checkpoint` and signs it with the MTC signing key.
4. It inserts a row into the `mtc_checkpoints` database table.
5. It triggers the cosignature gathering step (see below).
6. It triggers the standalone certificate build step.

Checkpoints are idempotent: if the tree size has not grown the task is a no-op.

After each new checkpoint is stored, rows beyond the `checkpoint_retention_count` limit are pruned from `mtc_checkpoints`. Associated cosignature rows in `mtc_cosignatures` are deleted via the `ON DELETE CASCADE` foreign-key constraint.

## Cosignature gathering

After each checkpoint is produced, `src/mtc/cosign.rs` contacts all configured external cosigners in parallel. For each cosigner:

- An HTTPS POST is made with `Content-Type: application/octet-stream` carrying the DER-encoded `Checkpoint`.
- The cosigner is expected to return a DER-encoded `SubtreeSignature` with HTTP 200.
- Each request uses a 30-second timeout.
- Failures are logged and skipped; partial success is acceptable.

Each `SubtreeSignature` is stored in the `mtc_cosignatures` table, keyed by checkpoint sequence number and cosigner URL.

When `cosigner_id_cert_pem` is configured for a cosigner, the PEM file is loaded at checkpoint time and added to the rustls trust store for that HTTPS connection.

## Standalone certificate construction

There are two code paths that produce a `StandaloneCertificate`:

**Checkpoint-driven (background)**: After cosignatures are gathered, `src/mtc/standalone.rs` builds a `StandaloneCertificate` (§6.1) for every certificate covered by the new checkpoint that does not already have one. This is the path for ordinary X.509 certificates issued with `[mtc]` enabled — logging is asynchronous and the standalone certificate is built during the next checkpoint cycle.

**Profile-driven (synchronous)**: When a `builtin` profile has `issue_as = "mtc"`, the finalize handler (`src/routes/finalize.rs`) builds the `StandaloneCertificate` synchronously during the request itself, before the database transaction:

1. The X.509 `TBSCertificate` is issued as normal.
2. The certificate is appended to the MTC log (synchronously, not via a background task) to obtain the leaf index immediately.
3. `crate::mtc::standalone::build_standalone_der` constructs the `StandaloneCertificate` DER.
4. The DER is stored in the `certificates.der` column; `certificates.pem` stores a PEM-armored wrapper with the `STANDALONE MTC CERTIFICATE` marker so the download handler can detect the format.
5. `certificates.mtc_log_index` is set to the leaf index (not `NULL`), so the regular checkpoint-driven path skips this certificate.

The download handler (`src/routes/certificate.rs::cert_pem_response`) detects MTC certificates by the PEM marker prefix and returns the raw DER with `Content-Type: application/pkix-cert` instead of the PEM bundle.

In both paths the standalone certificate embeds:
- The `TBSCertificate` from the issued certificate.
- A Merkle inclusion proof (computed from the leaf hashes under the `SharedLog` mutex).
- A signature from the MTC signing key.
- Any gathered `SubtreeSignature` entries from external cosigners (empty slice for profile-driven issuance, which does not wait for cosigners).

## Landmark construction

The landmark background task (`src/mtc/landmark.rs`) fires every `landmark_interval_secs` seconds. If the tree has grown since the last landmark:

1. A new row is inserted into the `mtc_landmarks` table with the current tree size and a monotonically increasing `sequence_no`.
2. A representative certificate (any leaf with `mtc_log_index < tree_size`) is selected.
3. All leaf hashes up to `tree_size` are read from the log under the mutex.
4. A `LandmarkCertificate` is built using `LandmarkCertificateBuilder`: it embeds the representative `TBSCertificate`, the leaf's log index, all leaf hashes (for internal inclusion proof generation), the `LandmarkID` (log identity + frozen tree size), and a signature from the MTC signing key.
5. The DER-encoded certificate is stored in the `cert_der` column of the landmark row.

After each new landmark is built, rows beyond `max_active_landmarks` are pruned by sequence number.

## Root computation

The Merkle root is computed from all leaf hashes using the RFC 6962 / synta-mtc binary tree algorithm:

- For a log with zero leaves the root is undefined.
- For a log with one or more leaves the root is the SHA-256 Merkle root of all leaf hashes.

The computation is performed under the `SharedLog` mutex and is exposed to handlers by `src/mtc/log.rs::proof_and_tree_size` and `tree_size`.

## C2SP tlog-tiles module (`src/mtc/tlog.rs`)

`src/mtc/tlog.rs` implements the C2SP tlog-tiles, signed-note, and tlog-cosignature specifications on top of the existing `DiskBackedLog` storage.

### Signed-note key IDs

Key IDs are 4-byte prefixes derived from `SHA-256` of a type-specific input:

| Key type | Role | C2SP type byte | Key ID formula |
|---|---|---|---|
| Ed25519 | Log operator | 0x01 | `SHA-256(name \| LF \| 0x01 \| 32-byte pubkey)[:4]` |
| ECDSA | Log operator or cosigner | 0x02 | `SHA-256(SPKI_DER)[:4]` |
| Ed25519 | Cosigner | 0x04 | `SHA-256(name \| LF \| 0x04 \| 32-byte pubkey)[:4]` |
| ML-DSA-44 | Cosigner | 0x06 | `SHA-256(name \| LF \| 0x06 \| 1312-byte pubkey)[:4]` |

ML-DSA-44 as a primary log operator key and Ed448/RSA keys are rejected — they have no assigned C2SP signed-note type byte.

### Hash tiles

Level-0 tiles are leaf hashes read directly from the `DiskBackedLog` via the `read_hash_range` wrapper in `src/mtc/log.rs`. Level-L tiles are computed by applying `MTH` (RFC 9162 §2) recursively over 256 level-(L-1) entries. Partial tiles (`.p/{width}` suffix in the URL) return fewer than 256 entries when the log ends mid-tile.

### HTTP route wiring

The three tlog-tiles endpoints are registered in `src/routes/mod.rs` and dispatched to handlers in `src/routes/mtc.rs`:

| Endpoint | Handler |
|---|---|
| `GET /acme/mtc/tlog/checkpoint` | `mtc::get_tlog_checkpoint` |
| `GET /acme/mtc/tlog/tile/{*path}` | `mtc::get_tlog_tile` |
| `GET /acme/mtc/tlog/cosignature` | `mtc::get_tlog_cosignature` |

The log origin string used in checkpoint notes is `{base_url}/acme/mtc/tlog`.
