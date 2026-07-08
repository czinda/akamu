# ── Stage 1: Build ────────────────────────────────────────────────────────────
FROM quay.io/hummingbird/rust:latest-builder AS builder

RUN dnf install -y \
        git \
        clang \
        openssl-devel \
        sqlite-devel \
        openldap-devel \
        krb5-devel \
        cyrus-sasl-devel \
        p11-kit-devel \
    && dnf clean all

WORKDIR /build/akamu
COPY . .

RUN CARGO_NET_GIT_FETCH_WITH_CLI=true \
    cargo build --release

RUN sed -i -e 's,/etc/akamu,/app/conf,g;s,/var/lib/akamu,/app/data,g' config.toml.example

# Collect runtime shared libraries by known glob.
RUN mkdir -p /runtime-libs && \
    cp -L /usr/lib64/libsqlite3.so*     /runtime-libs/ && \
    cp -L /usr/lib64/libldap.so*        /runtime-libs/ && \
    cp -L /usr/lib64/liblber.so*        /runtime-libs/ && \
    cp -L /usr/lib64/libsasl2.so*       /runtime-libs/ && \
    cp -L /usr/lib64/libgssapi_krb5.so* /runtime-libs/ && \
    cp -L /usr/lib64/libkrb5.so*        /runtime-libs/ && \
    cp -L /usr/lib64/libk5crypto.so*    /runtime-libs/ && \
    cp -L /usr/lib64/libcom_err.so*     /runtime-libs/ && \
    cp -L /usr/lib64/libkrb5support.so* /runtime-libs/ && \
    cp -L /usr/lib64/libkeyutils.so*    /runtime-libs/ && \
    cp -L /usr/lib64/libresolv.so*      /runtime-libs/ && \
    cp -L /usr/lib64/libevent*.so*      /runtime-libs/ && \
    cp -L /usr/lib64/libcrypt.so*       /runtime-libs/ && \
    cp -L /usr/lib64/libp11-kit.so*     /runtime-libs/ 2>/dev/null || true && \
    cp -L /usr/lib64/p11-kit-client.so  /runtime-libs/ 2>/dev/null || true && \
    cp -L /usr/lib64/libffi.so*         /runtime-libs/ 2>/dev/null || true

# Build passwd/group with the akamu user for the runtime stage.
RUN cp /etc/passwd /runtime-libs/passwd && \
    echo 'akamu:x:1001:1001:akamu:/app:/sbin/nologin' >> /runtime-libs/passwd && \
    cp /etc/group /runtime-libs/group && \
    echo 'akamu:x:1001:' >> /runtime-libs/group

# ── Stage 2: Hardened Runtime ─────────────────────────────────────────────────
# core-runtime ships USER 65532 — switch to root for setup, then drop to 1001.
FROM quay.io/hummingbird/core-runtime:latest-openssl

LABEL org.opencontainers.image.title="Akamu ACME Server" \
      org.opencontainers.image.description="Hardened ACME (RFC 8555) CA with PQC support" \
      org.opencontainers.image.licenses="GPL-3.0-or-later" \
      org.opencontainers.image.source="https://github.com/akamu-dev/akamu"

USER root

# Runtime shared libraries (sqlite, ldap, krb5, sasl).
COPY --from=builder /runtime-libs/*.so* /usr/lib64/

# User database with akamu entry.
COPY --from=builder /runtime-libs/passwd /etc/passwd
COPY --from=builder /runtime-libs/group /etc/group

# Remove SUID/SGID bits from all binaries.
RUN find / -xdev -perm /6000 -type f -exec chmod a-s {} + 2>/dev/null || true

# Runtime directories and PKCS#11 config for Kryoptic HSM access.
RUN mkdir -p /app/conf /app/data /etc/pkcs11/modules /var/run/kryoptic && \
    chown -R 1001:1001 /app /var/run/kryoptic && \
    echo 'remote: unix:path=/var/run/kryoptic/pkcs11.sock' > /etc/pkcs11/modules/kryoptic.module

COPY --from=builder --chown=1001:1001 /build/akamu/target/release/akamu /app/akamu
COPY --from=builder --chown=1001:1001 /build/akamu/config.toml.example /app/conf/config.toml.example
COPY --chown=1001:1001 contrib/containers/entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

# Drop to non-root for runtime.
USER 1001
WORKDIR /app

VOLUME ["/app/data", "/app/conf"]
EXPOSE 8080

ENTRYPOINT ["/app/entrypoint.sh"]
CMD ["serve", "-c", "/app/conf/config.toml"]
