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

## Landmark system

### What landmarks are

A *landmark* is a frozen snapshot of the MTC log's tree size at a point in time, defined in section 6.3.1 of `draft-ietf-plants-merkle-tree-certs`. Relying parties use landmarks to anchor inclusion proofs across the log's lifetime without tracking every checkpoint. While checkpoints are produced frequently (default: every hour) and are pruned aggressively, landmarks are produced less often (default: every day) and retained in larger numbers (default: 100), providing stable reference points for verifiers.

Each landmark carries a `LandmarkCertificate` -- a DER-encoded structure that embeds:

- A `TBSCertificate` from a representative leaf in the log.
- The leaf's log index.
- A Merkle inclusion proof against the full set of leaves at the landmark's frozen tree size.
- A `LandmarkID` identifying the log (hash algorithm + SPKI) and the frozen tree size.
- A signature from the MTC signing key.

This is self-contained: a verifier can check that the representative certificate was present in the log at the stated tree size without contacting the CA.

### Database schema (`mtc_landmarks`)

The `mtc_landmarks` table stores landmark metadata and the built certificate DER. The initial schema is defined in `migrations/{sqlite,postgres,mariadb}/0005_mtc_landmarks.sql`; the `ca_id` column was added by `migrations/sqlite/0030_mtc_per_ca.sql`, `migrations/mariadb/0031_mtc_per_ca.sql`, and `migrations/postgres/0032_mtc_per_ca.sql` to support per-CA transparency logs.

Current schema (after per-CA migration):

| Column | Type | Description |
|--------|------|-------------|
| `id` | `INTEGER PRIMARY KEY` / `BIGSERIAL` | Auto-incrementing row ID. |
| `ca_id` | `TEXT NOT NULL` | CA identifier; defaults to `'default'` for legacy rows. |
| `sequence_no` | `INTEGER` / `BIGINT` | Monotonically increasing per-CA sequence number (0, 1, 2, ...). |
| `tree_size` | `INTEGER` / `BIGINT` | The log tree size frozen by this landmark. |
| `cert_der` | `BLOB` / `BYTEA` | DER-encoded `LandmarkCertificate`; `NULL` until built. |
| `created` | `INTEGER` / `BIGINT` | Unix timestamp of allocation. |

Uniqueness constraints: `UNIQUE(ca_id, sequence_no)` and `UNIQUE(ca_id, tree_size)` -- a given CA cannot have two landmarks for the same tree size or sequence number.

The Rust row type is `LandmarkRow` (`src/db/schema.rs:110`).

### Code layout

| File | Role |
|------|------|
| `src/mtc/landmark.rs` | Background task and `LandmarkCertificate` construction logic. |
| `src/db/landmarks.rs` | CRUD functions for the `mtc_landmarks` table. |
| `src/routes/mtc.rs:147` | `get_landmark_for_cert` -- serves the first landmark covering a cert's log index. |
| `src/routes/mtc.rs:199` | `get_landmarks` -- lists all landmarks as JSON. |
| `src/routes/mtc.rs:222` | `get_landmark_cert` -- serves the DER-encoded `LandmarkCertificate` by sequence number. |

### Database access layer (`src/db/landmarks.rs`)

The module exposes seven functions:

| Function | Description |
|----------|-------------|
| `get_latest(db, ca_id)` | Returns the most recent landmark for a CA (highest `sequence_no`). Used as the fast-path skip check before allocation. |
| `list(db, ca_id)` | Returns all landmarks ordered by `sequence_no` ascending. Omits `cert_der` (returns `NULL`) to avoid loading large blobs for metadata-only queries. |
| `get_by_seq(db, ca_id, seq)` | Fetches a single landmark by sequence number, including `cert_der`. |
| `get_covering(db, ca_id, log_index)` | Returns the first landmark whose `tree_size > log_index` (smallest covering landmark). Used by the `GET /acme/mtc/cert/{id}/landmark` endpoint. |
| `insert(db, ca_id, tree_size, created)` | Allocates a new landmark. The `sequence_no` is computed atomically as `COALESCE(MAX(sequence_no), -1) + 1` inside the INSERT. A `WHERE NOT EXISTS` guard makes the insert idempotent on `(ca_id, tree_size)`. Returns `true` if a row was inserted. |
| `set_cert_der(db, id, cert_der)` | Updates the `cert_der` column after the `LandmarkCertificate` is built. |
| `prune_oldest(db, ca_id, keep_count)` | Deletes all but the most recent `keep_count` landmarks for a CA. |
| `count(db, ca_id)` | Returns the number of active landmarks for a CA. |

### Landmark lifecycle

**1. Scheduling.** `spawn_landmark_task` (`src/mtc/landmark.rs:256`) starts a tokio task that ticks every 60 seconds. On each tick it iterates over all configured CAs and checks whether `landmark_interval_secs` has elapsed since the last allocation for that CA (tracked via `MtcState::last_landmark`, an `AtomicI64` in `src/state.rs:731`). The default interval is 86400 seconds (1 day).

**2. Guard checks.** `maybe_allocate_landmark` (`src/mtc/landmark.rs:46`) runs three guards before proceeding:

- The log must be non-empty (`tree_size > 0`).
- The latest landmark's `tree_size` must be less than the current tree size (the log must have grown).
- A representative certificate must exist in the database with `mtc_log_index < tree_size`. Without a representative cert, the landmark row would be inserted with `cert_der = NULL` and would never be completed because there is no retry path.

**3. Row insertion.** A write transaction allocates the next `sequence_no` and inserts the row with `cert_der = NULL`. The `WHERE NOT EXISTS` guard prevents duplicates if another writer races on the same `tree_size`.

**4. Certificate construction.** The `LandmarkCertificate` is built in a `tokio::task::spawn_blocking` thread (`src/mtc/landmark.rs:111`) because it involves disk I/O (reading all leaf hashes) and CPU-bound crypto (signing). The steps are:

1. Extract the MTC signing key's SPKI DER.
2. Read all leaf hashes from the log under the `SharedLog` mutex, trimming to the landmark's frozen `tree_size`.
3. Parse the representative certificate's DER and extract its `TBSCertificate`.
4. DER-encode the `TBSCertificate` and sign it with the MTC signing key.
5. Build a `LogID` (hash algorithm OID + SPKI) and a `LandmarkID` (LogID + frozen tree size).
6. Assemble the `LandmarkCertificate` via `LandmarkCertificateBuilder` with the TBS, leaf index, tree leaves, hash algorithm, landmark ID, signature algorithm, and signature.
7. DER-encode the result.

**5. Persistence.** The DER bytes are written to the `cert_der` column via `db::landmarks::set_cert_der`.

**6. Pruning.** After each successful allocation, `prune_oldest` deletes landmarks beyond the `max_active_landmarks` limit (default: 100), removing the oldest by `sequence_no`. This keeps the table bounded.

**Memory note:** Step 4.2 loads every leaf hash into memory (32 bytes each for SHA-256). For a log with 10 million leaves this is approximately 320 MB. Operators should plan memory capacity accordingly, or reduce `landmark_interval_secs` to produce more frequent but smaller snapshots.

### Landmark HTTP endpoints

Three endpoints expose landmarks to clients (see also [HTTP endpoints](#http-endpoints) above for the full MTC endpoint table):

- `GET /acme/mtc/landmarks` -- returns a JSON array of `{sequenceNo, treeSize, createdAt}` objects for all active landmarks.
- `GET /acme/mtc/landmarks/{seq}/cert` -- returns the DER-encoded `LandmarkCertificate` for a given sequence number. Returns 503 with `Retry-After` if the certificate has not been built yet.
- `GET /acme/mtc/cert/{cert_id}/landmark` -- returns the DER of the first landmark whose `tree_size` covers the certificate's log index. Returns 503 if no covering landmark exists yet or its certificate is not built.

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

## MTC validator and test vector tooling

The `akamu-mtc-validator` workspace crate (`crates/akamu-mtc-validator/`) is a
standalone tool for verifying that Akāmu's MTC leaf hashing, Merkle tree construction,
and proof generation are byte-for-byte compatible with the reference Go implementation
of draft-ietf-plants-merkle-tree-certs-04.

### Test vector corpus

`contrib/test-vectors/mtc/mtc.json` is a 2036-entry plants-04 test vector corpus
(version `plants-04`). Its schema mirrors the Go demo tool's `config.go`: each
entry in `Entries` may be a null entry or a TBS-certificate entry with key usage,
extended key usage, SANs, BasicConstraints, and subtree/checkpoint bindings.

Pre-generated Go reference artifacts live under `contrib/test-vectors/mtc/reference/`:

| Path | Contents |
|------|---------|
| `ca_cert.pem` | CA certificate used by the Go demo tool |
| `cert_*.pem` | Individual standalone certificates from the Go demo |
| `tile/0/000`–`007.p/244` | Level-0 leaf hash tiles (256 × 32-byte hashes per full tile) |
| `tile/1/000.p/7` | Level-1 interior hash tile |
| `tile/entries/000`–`007.p/244` | TLS-encoded entry tiles |
| `checkpoint` | Go signed-note checkpoint: origin, tree size, base64 root, signature |

To regenerate these artifacts after a spec update, run:

```bash
contrib/test-vectors/mtc/regen.sh
```

This script clones the `ietf-plants-wg/merkle-tree-certs` repo at `HEAD`, builds
the Go demo tool, runs it against `mtc.json`, and overwrites the files under
`reference/`.

### Two-layer validation model

The validator distinguishes two validation layers:

**Layer B — internal consistency** (always available, no Go reference needed):

| Check | What it verifies |
|-------|-----------------|
| B1: tree_size | Expanded entry count matches expected total |
| B2: leaf_hash_length | Every leaf hash is exactly 32 bytes (SHA-256) |
| B3: null_entry_hashes | Null entries hash to `hash_leaf(SHA-256, 0x00000000)` |
| B4: root_computation | Merkle root computation completes without error |
| B5: subtree_alignment | For every cert, `start % next_power_of_two(size) == 0` per §4.3.1 |
| B6: subtree_in_bounds | Every subtree end ≤ tree size |
| B7: leaf_in_subtree | Every cert's leaf index falls within its subtree `[start, end)` |
| B8: inclusion_proofs | Every inclusion proof verifies against its subtree root |
| B9: subtrees_for_interval | Checkpoint-resolved subtrees satisfy `SubtreesForInterval` alignment |
| B10: root_all_leaves | Two independent root computations produce identical results |

**Layer A — byte-for-byte comparison** (requires `contrib/test-vectors/mtc/reference/`):

| Check | What it verifies |
|-------|-----------------|
| A1: reference_tile_read | All level-0 tile files are readable and correctly sized |
| A2: leaf_hash_count | Rust implementation produces same count as Go |
| A3: leaf_hash_values | Every leaf hash matches the Go reference byte-for-byte |
| A4: root_match | Merkle root matches the root in the Go signed-note checkpoint |

### CLI usage

```bash
# Run all 14 checks (B1–B10 + A1–A4) with bundled test vectors
cargo run -p akamu-mtc-validator -- check

# Run Layer B checks only (offline, no reference directory needed)
cargo run -p akamu-mtc-validator -- check \
  --vectors contrib/test-vectors/mtc/mtc.json

# Run Layer B + A with explicit reference directory
cargo run -p akamu-mtc-validator -- check \
  --vectors contrib/test-vectors/mtc/mtc.json \
  --reference contrib/test-vectors/mtc/reference

# Generate artifacts to an output directory for inspection
cargo run -p akamu-mtc-validator -- generate \
  --vectors contrib/test-vectors/mtc/mtc.json \
  --outdir /tmp/generated

# Run only Layer A comparison (generated vs reference)
cargo run -p akamu-mtc-validator -- validate \
  --vectors contrib/test-vectors/mtc/mtc.json \
  --reference contrib/test-vectors/mtc/reference
```

Adding `--fail-fast` to `check` causes the binary to exit with a non-zero code
when any check fails, which is useful in CI pipelines.

### Cargo integration test

`crates/akamu-mtc-validator/tests/mtc_vectors_compat.rs` runs the Layer B suite
as a standard `cargo test` target. It requires no external tools or network access:

```bash
cargo test -p akamu-mtc-validator
```

### Key correctness decisions captured in code

Three encoding details were discovered and fixed during Layer A comparison against
the Go reference (commit `1de25893c`):

1. **Issuer DN carries the TrustAnchorID, not the LogID.** The issuer DN in each
   `TBSCertificateLogEntry` encodes the CA's `TrustAnchorID` (e.g. `"32473.1"`)
   rather than the full `LogID` (e.g. `"32473.1.0.1"`). `LogID` additionally
   encodes the log number arc and is used for the log's own identity, not the
   per-entry issuer substitution.

2. **Subject commonName uses PrintableString, not UTF8String.** Go's `crypto/x509`
   emits `PrintableString` (tag `0x13`) for printable-charset subject CN values.
   `NameBuilder::common_name()` in `synta-certificate` always produces
   `UTF8String` (tag `0x0c`). `generate.rs` replicates Go's behaviour by choosing
   `PrintableStringRef` when the value is in the PrintableString character set and
   falling back to `Utf8StringRef` otherwise, matching Go's output byte-for-byte.

3. **BasicConstraints is marked `critical: true` when `cA=true`.** RFC 5280
   §4.2.1.9 states the BasicConstraints extension SHOULD be marked critical when
   `cA=true`. Go follows this recommendation; Akāmu's `encode_basic_constraints`
   helper does not set the critical flag unconditionally, so `generate.rs` sets
   it explicitly when `is_ca` is true.
