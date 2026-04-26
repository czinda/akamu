# Fedora packager context — akamu workspace

## Source URL

The project is not yet published to crates.io.  Ask the user for the forge
release URL before writing any `rust2rpm.toml`.  The expected form is:

```
https://<forge>/<org>/akamu/archive/v{version}.tar.gz
```

## License

SPDX identifier: `GPL-3.0-or-later`

License file is at the workspace root: `LICENSE`

Set in every `rust2rpm.toml`:
```toml
[package]
license = "GPL-3.0-or-later"
```

Do not use `license-files` — specify the SPDX identifier directly.

## Workspace structure

This is a single-crate workspace.  The one publishable crate is `akamu`
(defined at the workspace root).  There is no publish-order file — only one
spec needs to be created and validated.

## Packaging file location

All packaging files live under `contrib/packages/` in the repository root:

- `contrib/packages/rust2rpm.toml` — rust2rpm configuration
- `contrib/packages/rust-akamu.spec` — generated RPM spec

Run `rust2rpm` from the `contrib/packages/` directory, pointing it at the
workspace root `Cargo.toml`:

```bash
cd contrib/packages
rust2rpm --target fedora ../../
```

The `license_files` path in `rust2rpm.toml` must be relative to
`contrib/packages/`, so the workspace-root `LICENSE` is at `../../LICENSE`.

## Build dependencies

The crate links against OpenSSL and SQLite.  Add to `rust2rpm.toml`:

```toml
[requires]
build = ["openssl-devel", "sqlite-devel"]
comments = [
    "Rebuild this package whenever openssl-devel is updated in Fedora.",
    "The project uses an OpenSSL fork (pqc-prs) for ML-DSA/PQ support;",
    "verify compatibility when the system OpenSSL major version changes.",
]
```

The `openssl-sys` crate uses a patched fork via `[patch.crates-io]` in
`Cargo.toml`.  This means the crate **cannot be built from crates.io sources**
until the patch is upstreamed.  Source downloads must use the forge tarball
and the fork must be vendored or the patch applied in `%prep`.  Raise this
with the user before proceeding.

## Notes

- The binary is named `akamu`; set `install_bin = true` and `install_lib = false`.
- `sqlx` links dynamically against the system `sqlite-devel` via the `backend-sqlite` feature (no bundled SQLite).
- The `synta*` path-dependencies are external and not part of this package;
  they must be packaged separately and installed into the mock chroot first.
