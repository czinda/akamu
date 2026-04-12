# Installation

## Prerequisites

- Rust toolchain 1.75 or later (install via [rustup](https://rustup.rs))
- OpenSSL development headers (required by `synta-certificate`'s cryptography backend)
- The `synta` family of crates, which are path dependencies and must be checked out alongside this repository

### Fedora / RHEL

```
sudo dnf install openssl-devel
```

### Debian / Ubuntu

```
sudo apt install libssl-dev
```

## Checking out the source

`Akāmu` depends on three path-based crates from the `synta` workspace. Both repositories must be present on the local filesystem:

```
git clone <akamu-repo> akamu
git clone <synta-repo> synta
```

The `Cargo.toml` in `Akāmu` contains:

```toml
synta            = { path = "/home/abokovoy/src/upstream/synta" }
synta-certificate = { path = "/home/abokovoy/src/upstream/synta/synta-certificate" }
synta-x509-verification = { path = "/home/abokovoy/src/upstream/synta/synta-x509-verification" }
synta-mtc        = { path = "/home/abokovoy/src/upstream/synta/synta-mtc" }
```

Adjust the paths to match where you cloned `synta` before building.

## Building from source

The repository is a Cargo workspace with four members: the `akamu` server binary, `akamu-jose`, `akamu-client`, and `akamu-cli`.

```
cd akamu
cargo build --release
```

This compiles all four workspace members. The binaries are placed at:
- `target/release/akamu` — the ACME server
- `target/release/akamu-cli` — the command-line client

To build only the server:

```
cargo build --bin akamu --release
```

To build only the CLI:

```
cargo build --bin akamu-cli --release
```

> **Note:** The first build downloads and compiles all dependencies including bundled SQLite and the OpenSSL fork used by `synta-certificate`. It can take several minutes on a first run.

## Verifying the build

```
./target/release/akamu --help
```

The binary accepts a single optional argument: the path to the configuration file (defaults to `config.toml` in the current directory).

## Installing the binary

Copy the binary to a location in `$PATH`:

```
sudo install -m 0755 target/release/akamu /usr/local/bin/akamu
```

## systemd service (optional)

Create `/etc/systemd/system/akamu.service`:

```ini
[Unit]
Description=ACME Certificate Server
After=network.target

[Service]
Type=simple
User=akamu
Group=akamu
ExecStart=/usr/local/bin/akamu /etc/akamu/config.toml
Restart=on-failure
RestartSec=5s

# Logging
StandardOutput=journal
StandardError=journal

# Security hardening
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=/var/lib/akamu /etc/akamu

[Install]
WantedBy=multi-user.target
```

Then enable and start:

```
sudo systemctl daemon-reload
sudo systemctl enable --now akamu
```

## Running tests

```
cargo test
```

`cargo test` runs tests across all workspace members: the server, `akamu-jose`, and `akamu-client`. To limit the run to a specific crate:

```
cargo test -p akamu          # server tests only
cargo test -p akamu-jose     # JWK/JWS primitive tests
cargo test -p akamu-client   # ACME client library tests
```

All tests are self-contained and do not require external services. Some integration tests start local HTTP or TLS servers on ephemeral ports.
