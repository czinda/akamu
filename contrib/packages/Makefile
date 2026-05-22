# Makefile — helpers for preparing Fedora package sources and building SRPMs.
#
# Quick start:
#   make sources   # create all source files (tarball + vendor; requires network)
#   make spec      # validate rust2rpm.toml and generate akamu.spec
#   make srpm      # build an SRPM in the current directory (no ~/rpmbuild needed)
#   make mock      # rebuild SRPM in a clean mock chroot
#
# Override GIT_REF to build from a tag:
#   make sources GIT_REF=v0.1.0
#
# Requires: git, cargo, rust2rpm, rpmbuild, rpmlint
# For 'mock': mock package + your user in the 'mock' group
#   sudo usermod -aG mock $$USER   (then log out and back in)
# For 'copr-build': copr-cli configured with your API token
#
# rust2rpm is used to validate rust2rpm.toml (which is the canonical record of
# all package metadata and build requirements) before each spec/SRPM build.
# Full spec generation via rust2rpm is not possible for workspace crates that
# are not published on crates.io — rust2rpm requires a .crate archive and
# rejects workspace Cargo.toml files.  The spec template (akamu.spec.in) is
# therefore maintained alongside rust2rpm.toml; both must be kept in sync.

# Enable pipefail so that a failed 'git archive | gzip' pipe is not silently
# swallowed (gzip always exits 0, which would make Make think the tarball
# target succeeded and leave an empty .tar.gz behind).
SHELL       := /bin/bash
.SHELLFLAGS := -eu -o pipefail -c

# Delete the target file when a recipe exits with a non-zero status.
.DELETE_ON_ERROR:

# ──────────────────────────────────────────────────────────────────────────────
# Variables
# ──────────────────────────────────────────────────────────────────────────────

SPEC_IN  := akamu.spec.in
SPEC_OUT := akamu.spec

# Absolute path to the git repository root (two levels above this Makefile).
REPOROOT := $(abspath $(dir $(abspath $(lastword $(MAKEFILE_LIST))))/../..)

# Derive NAME and VERSION from the canonical sources (Cargo.toml / rust2rpm.toml)
# rather than from the spec template so that they stay correct even if the
# spec.in header is out of date.
NAME    := akamu
VERSION := $(shell python3 -c \
    "import tomllib; print(tomllib.load(open('$(REPOROOT)/Cargo.toml','rb'))['package']['version'])" \
    2>/dev/null)

# Resolved synta version from Cargo.lock (the lock file pins the exact version
# selected by the resolver, unlike Cargo.toml which only has a requirement).
# Used to locate the vendored synta directory that carries the asn1/ schemas.
SYNTA_VERSION := $(shell awk '/^\[\[package\]\]/{p=0} /^name = "synta"$$/{p=1} p && /^version =/{gsub(/[" ]/, "", $$3); print $$3; exit}' "$(REPOROOT)/Cargo.lock")
$(if $(SYNTA_VERSION),,$(error SYNTA_VERSION: could not extract synta version from $(REPOROOT)/Cargo.lock))

TARBALL              := $(NAME)-$(VERSION).tar.gz
VENDOR_TARBALL       := $(NAME)-$(VERSION)-vendor.tar.gz
WEBUI_DIST_TARBALL   := $(NAME)-$(VERSION)-webui-dist.tar.gz

# Absolute path to the crate dependency checker script.
CHECKDEPS := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))check-crate-deps.sh

ALL_SOURCES := $(TARBALL) $(VENDOR_TARBALL) $(WEBUI_DIST_TARBALL)

# Git ref used for the tarball and snapshot release identifiers.
# Defaults to HEAD so snapshots reflect the current branch tip.
# Override to a release tag for stable builds:
#   make sources GIT_REF=v0.1.0
GIT_REF ?= HEAD

# Snapshot release identifiers derived from GIT_REF.
# SNAPDATE   — commit date+time of GIT_REF in YYYYMMDDhhmm format.
#              The time component ensures multiple builds on the same day sort
#              correctly when the Release field is used for EVR comparison.
# SNAPCOMMIT — abbreviated commit hash of GIT_REF (7 hex digits).
# RELEASE    — full RPM Release value (without %{?dist}),
#              e.g. 1.202604101215.gitabc1234
SNAPDATE   := $(shell git -C "$(REPOROOT)" log -1 --format=%cd --date=format:%Y%m%d%H%M $(GIT_REF) 2>/dev/null)
SNAPCOMMIT := $(shell git -C "$(REPOROOT)" rev-parse --short $(GIT_REF) 2>/dev/null)
RELEASE    := 1.$(SNAPDATE).git$(SNAPCOMMIT)

# Mock chroot configuration for 'make mock'.
# Override on the command line:  make mock MOCK_CONFIG=fedora-42-x86_64
MOCK_CONFIG ?= fedora-rawhide-x86_64

# ──────────────────────────────────────────────────────────────────────────────

.PHONY: all sources tarball vendor webui-dist spec srpm mock lint check-deps clean help copr-build

all: sources

help:
	@echo "Targets:"
	@echo "  sources       prepare all source files (tarball + vendor + webui-vendor)"
	@echo "  tarball       create $(TARBALL) from GIT_REF=$(GIT_REF)"
	@echo "  vendor        create $(VENDOR_TARBALL)  [needs network]"
	@echo "  webui-dist    create $(WEBUI_DIST_TARBALL)  [needs npm + rollup locally]"
	@echo "  spec          validate rust2rpm.toml and generate $(SPEC_OUT)"
	@echo "  srpm          build SRPM (Release: $(RELEASE)%{?dist})"
	@echo "  mock          rebuild SRPM in mock chroot (MOCK_CONFIG=$(MOCK_CONFIG))"
	@echo "  lint          run rpmlint on the generated $(SPEC_OUT)"
	@echo "  check-deps    check which Cargo.lock crates are available as system packages"
	@echo "  copr-build    submit SRPM to COPR  (COPR=project required)"
	@echo "                example: make copr-build COPR=@mygroup/akamu"
	@echo "  clean         remove generated source files and the generated spec"
	@echo ""
	@echo "Snapshot: GIT_REF=$(GIT_REF)  date=$(SNAPDATE)  commit=$(SNAPCOMMIT)"
	@echo ""
	@echo "Note: rust2rpm validates rust2rpm.toml before every spec/SRPM build but"
	@echo "  cannot generate the spec for this workspace (akamu is not on crates.io;"
	@echo "  rust2rpm rejects workspace Cargo.toml files).  $(SPEC_IN) is the"
	@echo "  spec template; rust2rpm.toml is the canonical metadata record.  Keep"
	@echo "  both in sync when adding subpackages, BuildRequires, or scriptlets."

# ══════════════════════════════════════════════════════════════════════════════
# SOURCE PREPARATION
# ══════════════════════════════════════════════════════════════════════════════

sources: tarball vendor webui-dist

# ── tarball ───────────────────────────────────────────────────────────────────

tarball: $(TARBALL)

$(TARBALL):
	@echo "==> Creating $@ from $(GIT_REF)"
	git -C "$(REPOROOT)" archive \
	    --prefix=$(NAME)-$(VERSION)/ \
	    $(GIT_REF) \
	| gzip -9 > $@

# ── vendor ────────────────────────────────────────────────────────────────────
#
# The vendor tarball must include all optional backend crates (postgres, mariadb)
# so that the spec can be built with --with backend_postgres / --with backend_mariadb
# without network access.  We resolve the lock file with all three backends first,
# then vendor with --versioned-dirs so each crate directory carries its version
# (e.g. vendor/axum-0.8.8/ rather than vendor/axum/).
#
# The [patch.crates-io] override in Cargo.toml redirects openssl and openssl-sys
# to the PQC-capable rust-openssl fork (pqc-prs branch); cargo vendor follows
# this patch and includes the fork in vendor/ automatically.

vendor: $(VENDOR_TARBALL)

$(VENDOR_TARBALL):
	@echo "==> Creating $@ — resolving all backends and vendoring (includes PQC rust-openssl fork)"
	@# Resolve the lock file with all optional backends enabled.
	@# This ensures postgres/mariadb driver crates are present in Cargo.lock
	@# and will be included in the vendor directory.
	cd "$(REPOROOT)" && cargo check --quiet \
	    --features backend-sqlite,backend-postgres,backend-mariadb 2>/dev/null || true
	@# Vendor with versioned directory names into the repo root vendor/.
	@# cargo vendor outputs the [source.*] redirect stanzas that %prep appends
	@# to .cargo/config.toml; we discard that output here because the spec
	@# handles the git-source redirect (for the PQC openssl fork) directly.
	cd "$(REPOROOT)" && cargo vendor --versioned-dirs vendor >/dev/null
	@# Remove .profraw coverage artefacts that may be present in vendored crate
	@# sources (e.g. synta built from a dirty checkout that had a coverage/ dir).
	@# We must delete the files AND scrub their entries from each crate's
	@# .cargo-checksum.json; cargo verifies all listed files during the build
	@# and fails with "No such file or directory" if any are missing.
	@find "$(REPOROOT)/vendor" -name '*.profraw' -delete
	@find "$(REPOROOT)/vendor" -name '.cargo-checksum.json' \
	    -exec python3 -c "import json,sys;[open(p,'w').write(json.dumps(dict(d,files={k:v for k,v in d['files'].items() if not k.endswith('.profraw')}),separators=(',',':'))) for p in sys.argv[1:] for d in [json.load(open(p))]]" {} +
	@# synta crates are local path dependencies; cargo vendor skips them.
	@# Vendor them manually from the sibling synta repo so the RPM build's
	@# vendor directory is fully self-contained without network access.
	@echo "==> Vendoring synta crates from $(REPOROOT)/../synta"
	python3 "$(CURDIR)/vendor-local-crates.py" \
	    "$(REPOROOT)" \
	    "$(REPOROOT)/../synta" \
	    "$(REPOROOT)/vendor"
	@# synta-codegen's build script looks for ASN.1 schemas at ../asn1 relative
	@# to its CARGO_MANIFEST_DIR.  In the vendor layout that resolves to
	@# vendor/asn1/; copy from vendor/synta-{ver}/asn1/ (vendored above).
	cp -a "$(REPOROOT)/vendor/synta-$(SYNTA_VERSION)/asn1" "$(REPOROOT)/vendor/asn1"
	@# Archive vendor/ and Cargo.lock (pinned versions for reproducible builds).
	tar -czf "$(CURDIR)/$@" \
	    -C "$(REPOROOT)" vendor/ Cargo.lock
	rm -rf "$(REPOROOT)/vendor"
	@echo "==> $@ ready"

# ── webui-dist ────────────────────────────────────────────────────────────────
#
# Build the management web UI static assets on the developer machine and pack
# the resulting webui/dist/ directory into a tarball.  The COPR/mock build
# environment unpacks this pre-built tarball instead of running npm/rollup,
# which is not available for aarch64 in the npm registry.
#
# Re-run this target whenever webui source files change.  Requires npm and a
# rollup-capable Node.js environment (e.g. x86_64 Fedora workstation).

webui-dist: $(WEBUI_DIST_TARBALL)

$(WEBUI_DIST_TARBALL):
	@echo "==> Building webui (npm install + vite build) and packing dist/"
	cd "$(REPOROOT)/webui" && npm install --prefer-offline
	cd "$(REPOROOT)/webui" && npm run build
	tar -czf "$(CURDIR)/$@" \
	    -C "$(REPOROOT)/webui" dist/
	@echo "==> $@ ready (pre-built; unpack in RPM %%build instead of running npm)"

# ══════════════════════════════════════════════════════════════════════════════
# SPEC / SRPM / MOCK / LINT
# ══════════════════════════════════════════════════════════════════════════════

# ── spec ──────────────────────────────────────────────────────────────────────
#
# Validate rust2rpm.toml (the canonical metadata record), then generate the
# RPM spec by substituting snapshot release globals into the spec template.
#
# rust2rpm validates that all keys in rust2rpm.toml are recognised and that
# their values have the correct types.  This catches drift between the TOML
# config and the spec template before the SRPM is assembled.
#
# Full spec generation via rust2rpm is not possible for this workspace:
#   - rust2rpm requires a .crate archive as input.
#   - It explicitly rejects workspace Cargo.toml files.
#   - akamu is not published on crates.io, so --offline fetch fails too.
# The spec template ($(SPEC_IN)) is therefore maintained alongside
# rust2rpm.toml.  Both files must be kept in sync.
#
# Service units live in contrib/systemd/ as plain files; sysusers.d and
# tmpfiles.d sources use the .conf.in convention and are staged as .conf
# files in _sourcedir so rpmbuild can locate Source2–Source9.

spec:
	@echo "==> Validating rust2rpm.toml"
	rust2rpm --validate-only -C "$(CURDIR)/rust2rpm.toml"
	@echo "==> Generating $(SPEC_OUT) from $(SPEC_IN)"
	sed \
	    -e "s/^%global snapdate[[:space:]].*/%global snapdate    $(SNAPDATE)/" \
	    -e "s/^%global snapcommit[[:space:]].*/%global snapcommit  $(SNAPCOMMIT)/" \
	    "$(SPEC_IN)" > "$(SPEC_OUT)"

# ── srpm ──────────────────────────────────────────────────────────────────────

srpm: sources spec
	@echo "==> Building SRPM ($(NAME)-$(VERSION)-$(RELEASE))"
	cp "$(REPOROOT)/contrib/systemd/akamu.service" .
	cp "$(REPOROOT)/contrib/systemd/akamu-cosigner.service" .
	cp "$(REPOROOT)/contrib/systemd/akamu.socket" .
	cp "$(REPOROOT)/contrib/systemd/akamu-cosigner.socket" .
	cp "$(REPOROOT)/contrib/systemd/akamu-sysusers.conf.in"          akamu-sysusers.conf
	cp "$(REPOROOT)/contrib/systemd/akamu-cosigner-sysusers.conf.in" akamu-cosigner-sysusers.conf
	cp "$(REPOROOT)/contrib/systemd/akamu-tmpfiles.conf.in"          akamu-tmpfiles.conf
	cp "$(REPOROOT)/contrib/systemd/akamu-cosigner-tmpfiles.conf.in" akamu-cosigner-tmpfiles.conf
	rpmbuild -bs \
	    --define "_sourcedir $(CURDIR)" \
	    --define "_specdir   $(CURDIR)" \
	    --define "_srcrpmdir $(CURDIR)" \
	    "$(SPEC_OUT)"
	rm -f "$(SPEC_OUT)" \
	      akamu.service akamu-cosigner.service \
	      akamu.socket akamu-cosigner.socket \
	      akamu-sysusers.conf akamu-cosigner-sysusers.conf \
	      akamu-tmpfiles.conf akamu-cosigner-tmpfiles.conf
	@echo "==> To skip the webui build: rpmbuild -bs --without webui ..."

# ── mock ──────────────────────────────────────────────────────────────────────

mock: srpm
	$(eval SRPM := $(shell ls -1t "$(CURDIR)"/$(NAME)-$(VERSION)-*.src.rpm 2>/dev/null | head -1))
	@if [ -z "$(SRPM)" ]; then \
	    echo "ERROR: no SRPM found in $(CURDIR) for $(NAME)-$(VERSION)"; \
	    exit 1; \
	fi
	@echo "==> Rebuilding $(SRPM) in mock ($(MOCK_CONFIG))"
	mock -r "$(MOCK_CONFIG)" --rebuild "$(SRPM)"

# ── lint ──────────────────────────────────────────────────────────────────────
#
# Run rpmlint on the generated spec (not the .spec.in template, which contains
# unresolved substitution placeholders that rpmlint would flag as errors).

lint: spec
	rpmlint "$(SPEC_OUT)"
	rm -f "$(SPEC_OUT)"

# ══════════════════════════════════════════════════════════════════════════════
# DEPENDENCY CHECKING
# ══════════════════════════════════════════════════════════════════════════════

# Advisory check — reports which Cargo.lock crates are available as system RPMs
# and which must be satisfied by the vendor tarball.  Exit code 1 (some missing)
# is suppressed because missing crates are expected (they are vendored); only
# unexpected errors (exit code 2+) propagate.

check-deps:
	@rc=0; bash "$(CHECKDEPS)" "$(REPOROOT)/Cargo.lock" || rc=$$?; \
	exit $$((rc > 1 ? rc : 0))

# ══════════════════════════════════════════════════════════════════════════════
# COPR SUBMISSION
# ══════════════════════════════════════════════════════════════════════════════
#
# Submit the latest SRPM to a COPR project.
#
# Usage:
#   make copr-build COPR=@mygroup/akamu
#   make copr-build COPR=myuser/akamu-staging COPR_OPTS="--chroot fedora-42-x86_64 --wait"
#
# COPR      — required: the COPR project (e.g. @mygroup/akamu)
# COPR_OPTS — optional: extra flags passed directly to copr-chain-build.sh

COPR      ?=
COPR_OPTS ?=

copr-build:
	@test -n "$(COPR)" || \
	    { echo "ERROR: set COPR=<project>  e.g. make copr-build COPR=@mygroup/akamu" >&2; exit 1; }
	bash "$(dir $(abspath $(lastword $(MAKEFILE_LIST))))copr-chain-build.sh" \
	    --srpm-dir "$(CURDIR)" \
	    $(COPR_OPTS) \
	    "$(COPR)"

# ══════════════════════════════════════════════════════════════════════════════
# CLEAN
# ══════════════════════════════════════════════════════════════════════════════

clean:
	rm -f $(ALL_SOURCES) "$(SPEC_OUT)"
	rm -rf "$(REPOROOT)/vendor"
