# MTC Implementation

This chapter describes the internal design of the Merkle Tree Certificate (MTC) log integration: how certificates are appended, how checkpoints are produced, and the concurrency model.

## Log storage

The log file is a binary file managed by `synta_mtc::storage::DiskBackedLog`. Entries are written as fixed-size leaf hashes in leaf-order; the hash size (32, 48, or 64 bytes) is determined by `[mtc].hash_alg` and is stored in the log file's header at creation time. The hash function includes Merkle tree domain separation (a `\x00` prefix byte) to prevent second-preimage attacks.

The file is created by `DiskBackedLog::create` and opened by `DiskBackedLog::open`. The server uses a "try create first, fall back to open" strategy to eliminate time-of-check-to-time-of-use races at startup (`src/mtc/log.rs::open_or_create`).

A brand-new log is immediately seeded with a `null_entry` at index 0 (required by §5.3 of the MTC draft so that no real certificate ever receives log index 0 as its serial number).

### Root-hash cache

`DiskBackedLog` is wrapped in a `CachedLog` struct (`src/mtc/log.rs`) which adds an in-memory `(tree_size, root_hash)` cache. Because `compute_root` is an O(N) disk read, the cache avoids repeated traversals when the tree has not grown since the last checkpoint or HTTP read. Cache coherence rules:

- Warmed by `compute_root()` and `tree_size_and_root()`.
- Invalidated by `append_leaf()` (any write to the log).

## Appending a certificate

Appending a certificate leaf involves:

1. Parsing the DER-encoded certificate to extract the `TBSCertificate`.
2. Building a `TBSCertificateLogEntry` manually from the parsed TBS fields, substituting the **LogID issuer DN** for the original CA issuer DN. The LogID issuer DN is pre-computed at startup by `build_logid_issuer_dn_der` (in `src/mtc/standalone.rs`) and passed to `append_cert_to_log` as the `logid_issuer_dn_der` parameter. This substitution ensures the Merkle leaf hash matches what a verifier computes from the standalone certificate's TBS (which has the LogID as its issuer, not the CA DN).
3. Wrapping the entry as a `MerkleTreeCertEntry::TbsCertEntry` and computing the Merkle leaf hash via `hash_log_entry(algorithm, &entry)`. This function TLS wire-encodes the entry (per spec §4.2) and then hashes it with the `\x00` domain separation prefix.
4. Appending the fixed-size leaf hash (32, 48, or 64 bytes depending on `[mtc].hash_alg`) to the log file under a `tokio::sync::Mutex` guard.

Steps 1–3 run in a `tokio::task::spawn_blocking` thread to avoid blocking the async executor with CPU-bound encoding work. Step 4 takes the mutex and writes.

If the append fails, a warning is logged but the certificate issuance response is not affected. The `mtc_log_index` column remains `NULL` in the database for that certificate.

## Concurrency model

`DiskBackedLog` is not thread-safe internally. The server wraps it in a `CachedLog` struct, which is then placed behind a `tokio::sync::Mutex` (the `SharedLog` type alias in `src/mtc/log.rs` is `Arc<Mutex<CachedLog>>`). All leaf appends and reads acquire this mutex, serializing concurrent operations at the async level.

Multiple processes accessing the same log file concurrently are not supported. The server enforces single-process exclusive access via an advisory `flock(LOCK_EX|LOCK_NB)` on a sidecar lock file at `{log_path}.lock` (`src/mtc/log.rs::acquire_log_lock`). The lock file handle is stored in `MtcState::_log_lock` for the lifetime of the process; the kernel releases the lock automatically on exit or drop. A second process attempting to open the same log will receive an immediate error rather than blocking.

## Checkpoint production

The checkpoint background task (`src/mtc/checkpoint.rs`) fires every `checkpoint_interval_secs` seconds. If the log has grown since the last checkpoint, `produce_checkpoint` runs the following phases:

**Phase 1 (blocking thread):**

1. Acquires the `SharedLog` mutex via `blocking_lock()` and reads the current tree size and computes the Merkle root via `compute_root` (which also warms the root cache).
2. Generates Merkle inclusion proofs for all certificates that are newly covered by the checkpoint.
3. Builds and DER-encodes a `Checkpoint` structure (per §6.2 of the MTC draft).
4. Signs the `Checkpoint` DER with the MTC signing key.

**Async phase:**

5. Inserts a row into the `mtc_checkpoints` database table.
6. Contacts all configured external cosigners in parallel to gather `SubtreeSignature` responses.

**Phase 2 (blocking thread):**

7. Builds `StandaloneCertificate` DER blobs for each newly covered certificate (with cosignatures embedded) and persists them to the `certificates.mtc_standalone_der` database column.

Checkpoints are idempotent: if the tree size has not grown the task is a no-op.

After each new checkpoint is stored, rows beyond the `checkpoint_retention_count` limit are pruned from `mtc_checkpoints`. Associated cosignature rows in `mtc_cosignatures` are deleted via the `ON DELETE CASCADE` foreign-key constraint.

## Cosignature gathering

After each checkpoint is produced, `src/mtc/cosign.rs` contacts all configured external cosigners in parallel. For each cosigner:

- An HTTPS POST is made with `Content-Type: application/octet-stream` carrying the DER-encoded `Checkpoint`.
- The cosigner is expected to return a DER-encoded `SubtreeSignature` with HTTP 200.
- Each request uses a 30-second timeout.
- Failures are logged and skipped; partial success is acceptable.

The `CosignerClient` struct (one per `[[mtc.cosigners]]` entry) is built once at server startup. This surfaces misconfigured cosigners at startup rather than silently at checkpoint time, and preserves the HTTP connection pool across checkpoint intervals.

When `cosigner_id_cert_pem` is set for a cosigner, an `AkamuCosignerVerifier` is built at startup and stored inside the `CosignerClient`. At checkpoint time, the received `SubtreeSignature` is verified before being stored:

- **OID identity check**: When `trust_anchor_id` is also configured, the `SubtreeSignature.cosigner` field (a `TrustAnchorID ::= OBJECT IDENTIFIER` per draft-04 §4.1) is compared against the expected OID. A mismatch causes the signature to be rejected.
- **Cryptographic check**: The public key is extracted from the `cosigner_id_cert_pem` PEM and used for signature verification. Verification uses `synta_mtc::cosignature::validate_cosignature_quorum_with_crypto`, which builds the TLS-framed `CosignedMessage` (per §5.4.1 of the MTC draft) internally from the checkpoint and signature fields, then delegates the actual signature check to `OpensslSignatureVerifier`.

Setting `trust_anchor_id` without `cosigner_id_cert_pem` is a hard startup error: OID-only verification provides no cryptographic assurance. When neither field is set, cosignatures are accepted without verification and a warning is logged.

Each `SubtreeSignature` is stored in the `mtc_cosignatures` table, keyed by checkpoint sequence number and cosigner URL.

## Standalone certificate construction

There are two code paths that produce a `StandaloneCertificate`:

**Checkpoint-driven (background)**: After cosignatures are gathered, `produce_checkpoint` in `src/mtc/checkpoint.rs` builds a `StandaloneCertificate` (§6.1) for every certificate covered by the new checkpoint that does not already have one. The DER is stored in `certificates.mtc_standalone_der`. This is the path for ordinary X.509 certificates issued with `[mtc]` enabled — logging is asynchronous and the standalone certificate is built during the next checkpoint cycle.

**Profile-driven (synchronous)**: When a `builtin` profile has `issue_as = "mtc"`, the finalize handler (`src/routes/finalize.rs`) builds the `StandaloneCertificate` synchronously during the request itself, before the database transaction:

1. The X.509 `TBSCertificate` is issued as normal.
2. The certificate is appended to the MTC log (synchronously, not via a background task) to obtain the leaf index immediately.
3. `crate::mtc::standalone::build_standalone_der` constructs the `StandaloneCertificate` DER.
4. The DER is stored in the `certificates.mtc_standalone_der` column; `certificates.pem` stores a PEM-armored wrapper with the `STANDALONE MTC CERTIFICATE` marker so the download handler can detect the format.
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
- For a log with one or more leaves the root is the Merkle root of all leaf hashes, computed using the configured `[mtc].hash_alg` algorithm.

The computation is performed under the `SharedLog` mutex and is exposed to handlers by `src/mtc/log.rs::proof_and_tree_size`, `tree_size_and_root`, and `tree_size`. The `tree_size_and_root` function reads both values under the same lock guard so that `treeSize` and `rootHash` in HTTP responses are always consistent; it also leverages the `CachedLog` root cache to avoid repeated O(N) traversals.

## HTTP endpoints

The following read-only endpoints are served under `/acme/mtc/` and return 404 when MTC is disabled:

| Endpoint | Handler |
|---|---|
| `GET /acme/mtc/tree-size` | `mtc::get_tree_size` |
| `GET /acme/mtc/root` | `mtc::get_root` |
| `GET /acme/mtc/inclusion-proof/{cert_id}` | `mtc::get_inclusion_proof` |
| `GET /acme/mtc/cert/{cert_id}/standalone` | `mtc::get_standalone` |
| `GET /acme/mtc/landmarks` | `mtc::get_landmarks` |
| `GET /acme/mtc/landmarks/{seq}/cert` | `mtc::get_landmark_cert` |
| `GET /acme/mtc/tlog/checkpoint` | `mtc::get_tlog_checkpoint` |
| `GET /acme/mtc/tlog/tile/{*path}` | `mtc::get_tlog_tile` |
| `GET /acme/mtc/tlog/cosignature` | `mtc::get_tlog_cosignature` |
| `GET /acme/mtc/consistency-proof` | `mtc::get_consistency_proof` |
| `GET /acme/mtc/subtree-root` | `mtc::get_subtree_root` |
| `GET /acme/mtc/revoked-ranges` | `mtc::get_revoked_ranges` |

## C2SP tlog-tiles module (`src/mtc/tlog.rs`)

`src/mtc/tlog.rs` implements the C2SP tlog-tiles, signed-note, and tlog-cosignature specifications on top of the existing `DiskBackedLog` storage.

### Signed-note key IDs

Key IDs are 4-byte prefixes derived from `SHA-256` of a type-specific input:

| Key type | Role | C2SP type byte | Key ID formula |
|---|---|---|---|
| Ed25519 | Log operator | 0x01 | `SHA-256(name \| LF \| 0x01 \| 32-byte pubkey)[:4]` |
| ECDSA | Log operator or cosigner | 0x02 | `SHA-256(SPKI_DER)[:4]` |
| Ed25519 | Cosigner | 0x04 | `SHA-256(name \| LF \| 0x04 \| 32-byte pubkey)[:4]` |
| (RFC 6962 CT) | CT log | 0x05 | per c2sp.org/static-ct-api — not produced by Akāmu |
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
