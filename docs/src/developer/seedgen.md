# Test Data Generation (akamu-seedgen)

`akamu-seedgen` is a standalone binary that populates a SQLite database with
realistic PKI test data. It runs an in-process Akāmu server, drives the full
ACME protocol to issue real certificates, then applies direct database
mutations to produce the complete range of PKI lifecycle states — revoked,
expired, near-expiry, STAR, delegation, ARI replacement chains — that would
accumulate naturally over months in a production deployment.

The output is a SQLite database and a ready-to-run `akamu.toml` config that
can be dropped into a dev or test Akāmu instance with no further setup.

## Quick start

```bash
# Build the tool
cargo build -p akamu-seedgen

# Run with built-in defaults (~200 certs, 2 CAs, < 30 s)
cargo run -p akamu-seedgen -- --output /tmp/mytest.sqlite3

# Run with a specific scale spec
cargo run -p akamu-seedgen -- \
    --spec contrib/seedgen/small.toml \
    --output /tmp/small.sqlite3

# Launch a dev akamu + webui dev server against the result
./contrib/seedgen/dev.sh /tmp/small
```

Browse to `http://localhost:9000/ui/` once the dev server starts.

The run prints EAB credentials for the seeded administrator at the end:

```
Web UI login (EAB tab at /ui/login):
  Key ID (kid):         seedgen-admin
  HMAC key (base64url): <key>
```

Paste those two values into the **EAB** tab on the login page to authenticate.

## Command-line reference

```
akamu-seedgen [OPTIONS]

Options:
  -s, --spec <FILE>        Population spec (TOML). Omit to use built-in defaults.
  -o, --output <FILE>      Output SQLite file [default: test-data.sqlite3]
      --seed <N>           Override the RNG seed from the spec
  -v, --verbose            Print per-cert issuance progress
      --output-format      text|json  [default: text]
  -h, --help
```

The output file and an artifacts directory (named after the output file with
its extension stripped) are both produced. For `--output foo.sqlite3` the
layout is:

```
foo/                   ← artifacts directory
  akamu.toml           ← ready-to-run Akāmu config
  ca-<id>/
    ca.key             ← CA private key (mode 0640)
    ca.crt             ← CA certificate (mode 0644)
foo.sqlite3            ← database
```

## Spec file format

A spec file is a TOML document describing the desired population. All
sections are optional; omitting a section uses built-in defaults.

### `[global]`

```toml
[global]
seed   = 42                   # RNG seed — same seed + same spec = identical output
output = "test-data.sqlite3"  # default output path (overridden by --output)
```

`seed` controls the CSPRNG used for key generation, domain names, and
revocation reason selection. The same seed with the same spec always produces
the same database.

### `[[ca]]`

At least one CA is required. Exactly one must have `is_default = true`.

```toml
[[ca]]
id               = "ec-p256"    # URL prefix: /acme/ec-p256/directory
is_default       = true
key_type         = "ec:P-256"   # ec:P-{256,384,521}, rsa:{2048,3072,4096},
                                 # ed25519, ed448, ml-dsa-{44,65,87}
hash_alg         = "sha256"     # sha256 | sha384 | sha512
validity_days    = 90           # default end-entity cert validity
common_name      = "EC P-256 Test CA"
organization     = "Akamu Test PKI"
ca_validity_years = 10
```

### `[[cross_sign]]`

Each entry makes the issuer CA sign the subject CA's public key, producing a
cross-certificate stored in the database.

```toml
[[cross_sign]]
issuer         = "ec-p256"
subject        = "rsa-2048"
validity_years = 5
```

Both `issuer` and `subject` must reference `[[ca]]` IDs defined in the same
spec. Self-sign (`issuer == subject`) is rejected.

### `[[profile]]`

Profiles are added to the in-process server and emitted in the generated
`akamu.toml` so they are available when the instance is restarted.

```toml
[[profile]]
id                = "tls-server"
description       = "Standard TLS server certificate"
eku               = ["server_auth"]
key_usage         = ["digital_signature"]
validity_days     = 90
allowed_key_types = []     # empty = any key type accepted
ca_ids            = []     # empty = all CAs
```

`allowed_key_types` restricts the leaf certificate key algorithm. This is
independent of the CA key type: an `rsa:2048` CA can issue a certificate for
an `ec:P-256` subscriber key.

### `[[scenario]]`

A scenario drives one batch of ACME accounts and certificates under a single
CA + profile combination.

```toml
[[scenario]]
name         = "ec-tls"
ca_id        = "ec-p256"
profile_id   = "tls-server"
num_accounts = 25

[scenario.certs]
valid          = 300    # left in status=valid
revoked        = 75     # revoked; reasons spread across RFC 5280 codes 0,1,3,4,5
expired        = 60     # backdated 1–2 years into the past
near_expiry    = 25     # not_after within 3–30 days from now
ari_chains     = 8      # replacement chains; each chain = 3 certs (A→B→C)
star_active    = 8      # STAR orders, active
star_canceled  = 4      # STAR orders, canceled
delegation     = 2      # processing-state delegation orders (no cert issued)
pending_orders = 3      # stale pending orders, never finalized
invalid_orders = 3      # orders set to status=invalid

[scenario.certs.key_types]
# Relative weights for leaf certificate key selection.
"ec:P-256" = 5
"ec:P-384" = 2
"rsa:2048" = 2
"ed25519"  = 1

[scenario.accounts]
deactivated = 2    # this many accounts are deactivated after cert issuance
```

All cert counts are independent; they do not need to sum to any particular
total. Each count causes that many issuance flows or DB mutations.

## Pre-built specs

Ready-made specs for six scale points live in `contrib/seedgen/`:

| Spec | CAs | ~Certs | ~Accounts | Est. runtime |
|------|-----|--------|-----------|--------------|
| `tiny.toml` | 1 (ec:P-256) | 100 | 10 | < 30 s |
| `small.toml` | 2 (ec:P-256, rsa:2048) | 1 000 | 50 | 2–5 min |
| `small-pqc.toml` | 2 (ec:P-256, ml-dsa-44) | 1 000 | 50 | 2–5 min |
| `medium.toml` | 4 (ec:P-256/384, rsa:2048/4096) | 10 000 | 100 | 10–20 min |
| `medium-pqc.toml` | 4 (ec:P-256, rsa:2048, ml-dsa-44/65) | 10 000 | 100 | 10–20 min |
| `large.toml` | 8 (all classical) | 25 000 | 1 000 | 45–90 min |
| `xlarge.toml` | 16 (classical + PQC + hash variants) | 50 000 | 10 000 | 3–6 h |
| `xxlarge.toml` | 32 (all xlarge + long/short-lived variants) | 50 000 | 10 000 | 6–12 h |

The `*-pqc` specs pair classical and post-quantum CAs with cross-signs in both
directions, exercising hybrid trust chain building in the web UI.

## Output layout

After a successful run the artifacts directory is structured so that `akamu
serve` can be started directly from it:

```
<stem>/
  akamu.toml           ready-to-run config (HTTP, port 8080)
  ca-<id>/
    ca.key             PEM private key, mode 0640
    ca.crt             PEM certificate
  akamu.log            written by dev.sh (not by seedgen itself)
<stem>.sqlite3         database file
```

`akamu.toml` references the database with an absolute path so the server can
be started from any working directory. CA key and certificate paths are also
absolute.

The generated config also includes:

```toml
[admin]

[server]
http_validation_allow_private_ips = true
http_validation_port = 5002
```

The empty `[admin]` section enables the admin session store with all-default
settings; without it the EAB web UI login cannot create sessions. The
`[server]` settings allow new ACME orders to be issued against the seeded
instance without additional config edits.

## Dev workflow

`contrib/seedgen/dev.sh` starts both Akāmu and the Vite dev server in a
single command:

```bash
./contrib/seedgen/dev.sh <artifacts-dir>
```

or equivalently from `webui/`:

```bash
npm run dev:seed -- <artifacts-dir>
```

The script:

1. Validates that `<artifacts-dir>/akamu.toml` exists.
2. Locates the `akamu` binary (`target/debug/akamu`, `target/release/akamu`,
   or builds it if absent; override with `$AKAMU_BIN`).
3. Parses the `listen_addr` port from `akamu.toml`.
4. Starts `akamu serve -c akamu.toml` from inside the artifacts directory so the
   relative database path resolves correctly.
5. Polls `GET /acme/directory` until Akāmu accepts connections (timeout: 30 s;
   exits early with the log if the process crashes).
6. Sets `AKAMU_SERVER_URL=http://localhost:<port>` and starts the Vite dev
   server at `http://localhost:9000/ui/`.
7. On Ctrl-C or Vite exit, terminates the Akāmu process.

Akāmu stdout/stderr is written to `<artifacts-dir>/akamu.log`.

**Environment variables:**

| Variable | Default | Purpose |
|----------|---------|---------|
| `AKAMU_BIN` | auto-detected | Path to the `akamu` binary |
| `AKAMU_LOG` | `warn` | `RUST_LOG` filter for the Akāmu process |
| `VITE_PORT` | `9000` | Port for the Vite dev server |

The Vite proxy in `vite.config.ts` forwards `/admin` and `/acme` paths to
`AKAMU_SERVER_URL`, so the browser sees a single origin with no CORS issues.

## Admin credentials

Every run inserts one administrator operator (`seedgen-admin`) and one linked
EAB key into the database, then prints them at the end of the summary:

```
Web UI login (EAB tab at /ui/login):
  Key ID (kid):         seedgen-admin
  HMAC key (base64url): <43-char base64url string>
```

The HMAC key is derived from the seeded RNG, so the same `seed` value in the
spec always produces the same key.  Paste `kid` and the HMAC key directly into
the EAB tab on the login page; the UI computes the HMAC-SHA256 signature
client-side.

The operator has role `administrator` and full access to every admin API
endpoint.  It is intended for local development only — never import a seeded
database into a production instance.

## Internal architecture

`akamu-seedgen` is a workspace crate at `crates/akamu-seedgen/`. Its modules
map directly to implementation steps:

| Module | Responsibility |
|--------|----------------|
| `spec.rs` | Deserialises and validates the TOML spec |
| `server.rs` | Starts the in-process Akāmu server; persists CA key/cert files |
| `challenge.rs` | HTTP-01 challenge responder (axum on port 0, `RwLock<HashMap>`) |
| `acme.rs` | Thin wrappers over `akamu-client`: register account, issue cert |
| `names.rs` | Seeded deterministic fake domain/org/contact names (`ChaCha8Rng`) |
| `setup.rs` | Registers profiles, issues cross-certs, creates the seeded admin operator + EAB key |
| `scenarios.rs` | Per-scenario issuance loop; produces `Vec<(IssuedCert, TargetState)>` |
| `postprocess.rs` | Direct `sqlx` mutations for non-ACME states; WAL checkpoint |
| `config_writer.rs` | Renders and writes `akamu.toml` |
| `summary.rs` | Tallies counts; prints text or JSON summary |
| `main.rs` | Clap CLI; orchestrates all modules |

### Reproducibility

The `ChaCha8Rng` is seeded from `global.seed` at startup and threaded through
`names.rs`, `scenarios.rs`, and `setup.rs`. All random choices (domain names,
key type selection, revocation reasons, admin HMAC key) consume from this
single RNG in deterministic order, so the same seed with the same spec always
produces the same database and the same admin credentials.

The output database is opened directly as a file-backed SQLite pool at startup.
All writes go straight to `<output>.sqlite3`; no in-memory copy is made.
`postprocess::run()` finishes with `PRAGMA wal_checkpoint(TRUNCATE)` to merge
any pending WAL frames into the main file before the process exits.

### In-process server lifecycle

`server::start()` mirrors the pattern in `benches/acme_bench.rs`:

1. Build one `CaConfig` per spec `[[ca]]` entry, pointing key/cert files to
   `<artifacts-dir>/ca-<id>/`.
2. Call `ca::init::load_or_generate()` for each CA — generates key + self-signed
   cert on first run, loads existing files on subsequent runs.
3. Assemble `AppState` with all CAs, the output SQLite pool, and MTC disabled.
4. Bind a random TCP port; start `axum::serve` in a background task.
5. Signal readiness via `tokio::sync::oneshot` before entering the accept loop.

### Post-processing

After all ACME issuance completes, `postprocess::run()` applies state mutations
directly to the database:

| State | Mechanism |
|-------|-----------|
| `revoked` | `db::certs::revoke()` — sets `status`, `revoked_at`, `revocation_reason` |
| `expired` | `UPDATE certificates SET not_before, not_after` to 1–2 years ago |
| `near_expiry` | `UPDATE certificates SET not_after` to 3–30 days from now |
| `ARI chain` | `db::certs::mark_replaced()` + `UPDATE orders SET replaces` |
| `invalid_orders` | `UPDATE orders SET status='invalid', expires` to the past |

Finally, `PRAGMA wal_checkpoint(TRUNCATE)` is run so the database file is
self-contained when the process exits.

### Extending the tool

To add a new target state (e.g. `on_hold` revocation):

1. Add the variant to `TargetState` in `scenarios.rs`.
2. Assign the new state in `scenarios::run_scenario()` for the appropriate cert count.
3. Add a matching arm in `postprocess::run()` that performs the database mutation.
4. Add a counter to `PostprocessStats` and include it in `summary::Summary`.
