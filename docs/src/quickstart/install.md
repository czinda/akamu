# Installation

## Prerequisites

- Rust toolchain 1.75 or later (install via [rustup](https://rustup.rs))
- OpenSSL development headers and runtime library (required by `synta-certificate`'s cryptography backend and by `rustls-native-ossl`, the TLS crypto provider)

### OpenSSL version requirements

| Component | Minimum OpenSSL | Reason |
|---|---|---|
| Build (all binaries) | 3.0.7 | `native-ossl-sys` build script enforces this floor |
| **Server** (`akamu`) runtime | **3.5** | The server generates ML-KEM-768 keys at startup for CRDT node identity; ML-KEM is available only in OpenSSL 3.5+ |
| **CLI** (`akamu-cli`) with classical keys | 3.0.7 | EC, RSA, and EdDSA key types work with any OpenSSL 3.0.7+ |
| **CLI** with post-quantum keys | **3.5** | ML-DSA-44/65/87 account or certificate keys require OpenSSL 3.5+ |
| Composite ML-DSA signatures | **3.5** | CA key types such as `composite-mldsa65-ecdsa-p384-sha512` require OpenSSL 3.5+ |
| Composite mTLS client cert verification | **3.5** | Verifying composite ML-DSA `CertificateVerify` messages requires OpenSSL 3.5+ NID support |

Check your installed OpenSSL version:

```
openssl version
```

The output should show `OpenSSL 3.5.0` or later for full server functionality.

> **Tip:** On systems where the default `openssl` package is older than 3.5, you can build against a locally installed OpenSSL by setting `NATIVE_OSSL_OPENSSL_SOURCES` to the build directory (must contain `include/` and `libcrypto.a`). See the `native-ossl-sys` build script for details.

### Fedora / RHEL

```
sudo dnf install openssl-devel
```

Fedora 42+ and RHEL 10+ ship OpenSSL 3.5. On older releases, install OpenSSL 3.5 from source or use a module stream that provides it.

### Debian / Ubuntu

```
sudo apt install libssl-dev
```

Ubuntu 25.04+ ships OpenSSL 3.5. On older releases (e.g. Ubuntu 24.04 with OpenSSL 3.0), the CLI works with classical key types but the server will fail at startup. Install OpenSSL 3.5 from source or from a PPA to run the server.

## Checking out the source

```
git clone <akamu-repo> akamu
```

All `synta` dependencies are fetched automatically from [crates.io](https://crates.io) — no manual checkout required.

## Building from source

The repository is a Cargo workspace with seven members: the `akamu` server binary, `akamu-jose`, `akamu-client`, `akamu-cli`, `akamuctl`, `akamu-cosigner`, and `akamu-ldap` (the OpenLDAP C-binding library, used by the server when reading profiles from LDAP).

```
cd akamu
cargo build --release
```

This compiles all seven workspace members. The binaries are placed at:
- `target/release/akamu` — the ACME server
- `target/release/akamu-cli` — the command-line client
- `target/release/akamuctl` — the admin CLI
- `target/release/akamu-cosigner` — the MTC cosigner daemon

To build only the server:

```
cargo build --bin akamu --release
```

To build only the CLI:

```
cargo build --bin akamu-cli --release
```

> **Note:** The first build downloads and compiles all dependencies including bundled SQLite. It can take several minutes on a first run.

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
