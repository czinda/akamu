# ── Stage 1: Build ────────────────────────────────────────────────────────────
FROM quay.io/hummingbird/rust:latest-builder

# Build-time system dependencies:
#   git           – cargo uses the git CLI to fetch the openssl git source
#                   declared in [patch.crates-io]
#   clang         – required by bindgen (openssl-sys, synta FFI)
#   openssl-devel – headers for the PQC-capable OpenSSL fork
#   sqlite-devel  – headers for libsqlite3 (rusqlite links dynamically)
RUN dnf install -y \
        git \
        clang \
        openssl-devel \
        sqlite-devel \
    && dnf clean all

# Copy the akamu workspace into the builder.
WORKDIR /build/akamu
COPY . .

# Build the release binary.
# CARGO_NET_GIT_FETCH_WITH_CLI=true avoids libgit2 auth issues when fetching
# the openssl git source declared in [patch.crates-io].
RUN CARGO_NET_GIT_FETCH_WITH_CLI=true \
    cargo build --release

RUN sed -i -e 's,/etc/akamu,/app/conf,g;s,/var/lib/akamu,/app/data,g' config.toml.example
# ── Stage 2: Runtime ──────────────────────────────────────────────────────────
# FROM quay.io/hummingbird/core-runtime:latest-openssl

LABEL org.opencontainers.image.title="Akamu ACME Server" \
      org.opencontainers.image.description="Full-featured ACME (RFC 8555) server with PQC support" \
      org.opencontainers.image.licenses="GPL-3.0-or-later"

# Runtime system dependencies:
#   openssl-libs  – libssl / libcrypto (PQC-capable OpenSSL 3.x on Fedora 41+)
#   sqlite-libs   – libsqlite3 (rusqlite links dynamically; no bundled build)
#   ca-certificates – trusted root CAs for outbound http-01 validation requests

# Runtime directory layout:
#   /opt/akamu/conf  – config.toml, CA key+cert PEM, optional TLS key+cert
#   /opt/akamu/data  – SQLite database, MTC transparency log
RUN mkdir -p /app/conf /app/data

COPY  /build/akamu/target/release/akamu /app/akamu

# Provide the annotated example config so operators can bootstrap from it.
COPY config.toml.example /app/conf/config.toml.example

COPY contrib/containers/entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh
RUN rm -rf /build
# Declare volumes so container runtimes (podman, docker, kubernetes) track them.
# Mount the host paths (or named volumes) over these to persist state:
#
#   podman run -v akamu-data:/app/data -v akamu-config:/app/conf ...
#
VOLUME ["/app/data", "/app/conf"]

# Default ACME server port (matches listen_addr = "0.0.0.0:8080" in config).
# If you change listen_addr in config.toml, update EXPOSE accordingly.
EXPOSE 8080

ENTRYPOINT ["/app/entrypoint.sh"]
# The entrypoint passes this as the config path argument to akamu.
CMD ["/app/conf/config.toml"]
