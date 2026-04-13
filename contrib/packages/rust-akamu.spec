# Spec for the akamu ACME server workspace.
#
# Source tarball:
#   git archive --format=tar.gz --prefix=akamu-%%{version}/ HEAD \
#       -o akamu-%%{version}.tar.gz
#
# Vendor tarball (full — required because of [patch.crates-io] for the
# openssl pqc-prs fork and several crates not yet in Fedora):
#
#   To include optional PostgreSQL and MariaDB sqlx drivers in the vendor
#   tarball, resolve the lockfile with all features before vendoring:
#     cargo check --features backend-sqlite,backend-postgres,backend-mariadb
#   Then vendor as usual:
#     cargo vendor --versioned-dirs /tmp/v/
#     tar czf akamu-%%{version}-vendor.tar.gz \
#         --exclude='*.profraw' \
#         -C /tmp/v --transform 's|^\./|vendor/|' --transform 's|^\.|vendor|' .
#
# Crates in the vendor tarball absent from Fedora or at incompatible versions:
#   openssl / openssl-sys  — pqc-prs git fork for ML-DSA/ML-KEM/PQC support
#   axum-server 0.8        — Fedora ships 0.7.3 (incompatible API)
#   hickory-resolver 0.24  — Fedora ships 0.25 (incompatible API)
#   toml 0.8               — Fedora ships 1.1 (incompatible API)
#   sqlx-postgres + deps   — needed when %%{with backend_postgres} (not in Fedora)
#   sqlx-mysql + deps      — needed when %%{with backend_mariadb}  (not in Fedora)
#
# PREREQUISITE: install synta* into the mock chroot before rebuilding:
#   mock --install rust-synta-devel rust-synta-certificate-devel \
#                  rust-synta-x509-verification-devel rust-synta-mtc-devel

%bcond check 1
# Optional database backends (in addition to the always-on SQLite default).
# Enable with: rpmbuild --with backend_postgres  or  --with backend_mariadb
%bcond backend_postgres 0
%bcond backend_mariadb  0

%global crate akamu

# The akamu workspace root has both src/lib.rs and src/main.rs.
# The library is internal; only the binary is packaged.
%global cargo_install_lib 0

# Feature list passed to cargo: sqlite is always on; postgres/mariadb are opt-in.
%global _akamu_features backend-sqlite
%if %{with backend_postgres}
%global _akamu_features %{_akamu_features},backend-postgres
%endif
%if %{with backend_mariadb}
%global _akamu_features %{_akamu_features},backend-mariadb
%endif

Name:           rust-akamu
Version:        0.1.0
Release:        1%{?dist}
Summary:        ACME server with post-quantum certificate support

License:        GPL-3.0-or-later
URL:            https://codeberg.org/abbra/akamu
# git archive --format=tar.gz --prefix=akamu-%%{version}/ HEAD \
#     -o akamu-%%{version}.tar.gz
Source0:        akamu-%{version}.tar.gz
# Full vendor tarball — see the generation instructions at the top of this spec.
# Contains all Cargo dependencies, including the openssl pqc-prs fork and
# several crates not yet available in Fedora.
Source1:        akamu-%{version}-vendor.tar.gz
# Minimal systemd service unit for the akamu ACME server
Source2:        akamu.service
# Example configuration file; installed as %%{_sysconfdir}/akamu/config.toml.example
Source3:        config.toml.example

ExclusiveArch:  %{rust_arches}

BuildRequires:  cargo-rpm-macros >= 26
# System libraries
BuildRequires:  pkgconfig(openssl)
BuildRequires:  openssl-devel
BuildRequires:  pkgconfig(sqlite3)
BuildRequires:  sqlite-devel
# Optional backend: PostgreSQL (libpq)
%if %{with backend_postgres}
BuildRequires:  pkgconfig(libpq)
BuildRequires:  libpq-devel
%endif
# Optional backend: MariaDB / MySQL (Connector/C)
%if %{with backend_mariadb}
BuildRequires:  pkgconfig(libmariadb)
BuildRequires:  mariadb-connector-c-devel
%endif
# The openssl-sys build script generates FFI bindings via bindgen, which
# requires libclang.  Rebuild this package whenever openssl-devel changes.
BuildRequires:  clang-devel
# synta* crates are packaged in Fedora; install them into the mock chroot first:
#   mock --install rust-synta-devel rust-synta-certificate-devel \
#                  rust-synta-x509-verification-devel rust-synta-mtc-devel
BuildRequires:  rust-synta-devel
BuildRequires:  rust-synta-certificate-devel
BuildRequires:  rust-synta-x509-verification-devel
BuildRequires:  rust-synta-mtc-devel
# Systemd scriptlet support
BuildRequires:  systemd-rpm-macros
%{?systemd_requires}

%global _description %{expand:
akamu is an ACME (RFC 8555) certificate authority server that supports
post-quantum cryptography via an ML-DSA/PQC-capable OpenSSL fork.  It
implements the full ACME protocol including http-01, dns-01, and tls-alpn-01
challenge types, and supports Merkle Tree Certificates (MTC) for
compressed certificate delivery.
}

%description %{_description}


# ── Main package: server binary ────────────────────────────────────────────────
%package -n %{crate}
Summary:        %{summary}
License:        GPL-3.0-or-later
# Bundled crate licenses are listed in LICENSE.dependencies (cargo-generated).
# The vendor manifest in cargo-vendor.txt lists every vendored crate and its
# SPDX identifier.
%{?systemd_requires}

%description -n %{crate} %{_description}

%files -n %{crate}
%license LICENSE
%license LICENSE.dependencies
%license cargo-vendor.txt
%{_bindir}/akamu
%{_unitdir}/akamu.service
%dir %{_sysconfdir}/akamu
%config(noreplace) %{_sysconfdir}/akamu/config.toml.example


# ── Subpackage: CLI client binary ──────────────────────────────────────────────
%package -n akamu-client
Summary:        ACME client CLI with ML-DSA account key support
License:        GPL-3.0-or-later

%description -n akamu-client
akamu-client is a command-line ACME client that supports ML-DSA (Dilithium)
account keys in addition to the standard RSA and ECDSA key types.  It can
register accounts, obtain and renew certificates, handle http-01, dns-01,
tls-alpn-01, and onion-csr-01 challenges, and supports ARI-aware renewal
(RFC 9773).

%files -n akamu-client
%license LICENSE
%license LICENSE.dependencies
%{_bindir}/akamu-cli


# ── Prep ───────────────────────────────────────────────────────────────────────
%prep
# Unpack the source tarball; -a1 unpacks Source1 (vendor/) inside the build dir.
%autosetup -n %{crate}-%{version} -p1 -a1

# Set up the cargo build environment using the full vendor tree.
# %cargo_prep -v vendor configures .cargo/config.toml to redirect all
# crates-io lookups (and the [patch.crates-io] git source) to vendor/.
%cargo_prep -v vendor

# %cargo_prep -v already wrote the crates-io → vendored-sources redirect.
# We also need to redirect the [patch.crates-io] git source for the
# openssl pqc-prs fork so cargo resolves it from vendor/ instead of fetching
# from git (which is unavailable in the offline mock environment).
cat >> .cargo/config.toml << 'EOF'

[source."git+https://github.com/abbra/rust-openssl.git?branch=pqc-prs"]
git = "https://github.com/abbra/rust-openssl.git"
branch = "pqc-prs"
replace-with = "vendored-sources"
EOF


# ── Generate BuildRequires ─────────────────────────────────────────────────────
%generate_buildrequires
%cargo_generate_buildrequires


# ── Build ──────────────────────────────────────────────────────────────────────
%build
# Build the entire workspace: the server binary (akamu) and the CLI (akamu-cli).
# Pass the feature list explicitly; --no-default-features keeps the set minimal
# (only what %{_akamu_features} requests, always at least backend-sqlite).
%cargo_build -- --workspace --no-default-features --features %{_akamu_features}
# Generate the bundled-dependency license summary required by Fedora policy.
%{cargo_license_summary}
%{cargo_license} > LICENSE.dependencies
%{cargo_vendor_manifest}


# ── Install ────────────────────────────────────────────────────────────────────
%install
# Install the server binary (akamu) from the workspace root crate.
%cargo_install

# Install the CLI binary (akamu-cli) from the crates/akamu-cli workspace member.
(
  cd crates/akamu-cli
  %cargo_install
)

# Systemd service unit
install -Dpm 0644 %{SOURCE2} %{buildroot}%{_unitdir}/akamu.service

# Example configuration file
install -Dpm 0644 %{SOURCE3} %{buildroot}%{_sysconfdir}/akamu/config.toml.example


# ── Check ──────────────────────────────────────────────────────────────────────
%if %{with check}
%check
# Documentation tests require external infrastructure (live ACME endpoints,
# DNS resolver, TLS server) not available inside the mock build environment.
%cargo_test -- --lib --bins --tests --no-default-features --features %{_akamu_features}
%endif


# ── Systemd scriptlets ─────────────────────────────────────────────────────────
%pre -n %{crate}
%systemd_pre akamu.service

%post -n %{crate}
%systemd_post akamu.service

%preun -n %{crate}
%systemd_preun akamu.service

%postun -n %{crate}
%systemd_postun_with_restart akamu.service


%changelog
%autochangelog
