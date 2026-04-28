# Makefile — helpers for preparing Fedora package sources and building SRPMs.
#
# Quick start:
#   make sources   # create all source files (tarball + vendor; requires network)
#   make srpm      # build an SRPM in the current directory (no ~/rpmbuild needed)
#   make mock      # rebuild SRPM in a clean mock chroot
#
# Override GIT_REF to build from a tag:
#   make sources GIT_REF=v0.1.0
#
# Requires: git, cargo, rpmbuild, rpmlint
# For 'mock': mock package + your user in the 'mock' group
#   sudo usermod -aG mock $$USER   (then log out and back in)
# For 'copr-build': copr-cli configured with your API token

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

SPEC     := akamu.spec.in
SPEC_TMP := akamu.spec

NAME    := $(shell awk '/^Name:/{print $$2; exit}' $(SPEC))
VERSION := $(shell awk '/^Version:/{print $$2; exit}' $(SPEC))

# Resolved synta version from Cargo.lock (the lock file pins the exact version
# selected by the resolver, unlike Cargo.toml which only has a requirement).
# Used to locate the vendored synta directory that carries the asn1/ schemas.
SYNTA_VERSION := $(shell awk '/^\[\[package\]\]/{p=0} /^name = "synta"$$/{p=1} p && /^version =/{gsub(/[" ]/, "", $$3); print $$3; exit}' "$(REPOROOT)/Cargo.lock")

# Absolute path to the git repository root (two levels above this Makefile).
REPOROOT := $(abspath $(dir $(abspath $(lastword $(MAKEFILE_LIST))))/../..)

TARBALL        := $(NAME)-$(VERSION).tar.gz
VENDOR_TARBALL := $(NAME)-$(VERSION)-vendor.tar.gz

# Absolute path to the crate dependency checker script.
CHECKDEPS := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))check-crate-deps.sh

ALL_SOURCES := $(TARBALL) $(VENDOR_TARBALL)

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

.PHONY: all sources tarball vendor srpm mock lint validate-spec check-deps clean help copr-build

all: sources

help:
	@echo "Targets:"
	@echo "  sources       prepare all source files (tarball + vendor)"
	@echo "  tarball       create $(TARBALL) from GIT_REF=$(GIT_REF)"
	@echo "  vendor        create $(VENDOR_TARBALL)  [needs network]"
	@echo "  srpm          build SRPM (Release: $(RELEASE)%{?dist})"
	@echo "  mock          rebuild SRPM in mock chroot (MOCK_CONFIG=$(MOCK_CONFIG))"
	@echo "  lint          run rpmlint on $(SPEC)"
	@echo "  validate-spec validate rust2rpm.toml against the rust2rpm schema"
	@echo "  check-deps    check which Cargo.lock crates are available as system packages"
	@echo "  copr-build    submit SRPM to COPR  (COPR=project required)"
	@echo "                example: make copr-build COPR=@mygroup/akamu"
	@echo "  clean         remove generated source files and the temporary spec"
	@echo ""
	@echo "Snapshot: GIT_REF=$(GIT_REF)  date=$(SNAPDATE)  commit=$(SNAPCOMMIT)"
	@echo ""
	@echo "Note: rust-akamu.spec.in is maintained manually."
	@echo "  rust2rpm cannot generate it automatically because akamu is a Cargo"
	@echo "  workspace not published on crates.io (cargo package fails on path"
	@echo "  dependencies, and rust2rpm rejects workspace Cargo.toml files)."
	@echo "  Use 'make validate-spec' to check rust2rpm.toml for schema errors."

# ══════════════════════════════════════════════════════════════════════════════
# SOURCE PREPARATION
# ══════════════════════════════════════════════════════════════════════════════

sources: tarball vendor

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
	@# synta-codegen's build script resolves ASN.1 schemas via ../asn1 relative to
	@# each crate's CARGO_MANIFEST_DIR.  In the vendored layout that path resolves
	@# to vendor/asn1/, but the schemas live inside vendor/synta-0.1.6/asn1/.
	@# Copy them to the expected sibling location so the build script finds them.
	cp -a "$(REPOROOT)/vendor/synta-$(SYNTA_VERSION)/asn1" "$(REPOROOT)/vendor/asn1"
	@# Archive vendor/ and Cargo.lock (pinned versions for reproducible builds).
	tar -czf "$(CURDIR)/$@" \
	    -C "$(REPOROOT)" vendor/ Cargo.lock
	rm -rf "$(REPOROOT)/vendor"
	@echo "==> $@ ready"

# ══════════════════════════════════════════════════════════════════════════════
# SRPM / MOCK / LINT
# ══════════════════════════════════════════════════════════════════════════════

# ── srpm ──────────────────────────────────────────────────────────────────────
#
# Substitute the snapshot release globals into a temporary .spec file and
# build the SRPM into the current directory (no ~/rpmbuild tree needed).

srpm: sources
	@echo "==> Building SRPM (rust-$(NAME)-$(VERSION)-$(RELEASE))"
	sed \
	    -e "s/^%global snapdate[[:space:]].*/%global snapdate    $(SNAPDATE)/" \
	    -e "s/^%global snapcommit[[:space:]].*/%global snapcommit  $(SNAPCOMMIT)/" \
	    "$(SPEC)" > "$(SPEC_TMP)"
	@# Service units now live in contrib/systemd/; copy them into _sourcedir
	@# so rpmbuild can locate Source2 and Source4 in the offline build.
	cp "$(REPOROOT)/contrib/systemd/akamu.service" .
	cp "$(REPOROOT)/contrib/systemd/akamu-cosigner.service" .
	rpmbuild -bs \
	    --define "_sourcedir $(CURDIR)" \
	    --define "_specdir   $(CURDIR)" \
	    --define "_srcrpmdir $(CURDIR)" \
	    "$(SPEC_TMP)"
	rm -f "$(SPEC_TMP)" akamu.service akamu-cosigner.service

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

lint:
	rpmlint "$(SPEC)"

# ── validate-spec ─────────────────────────────────────────────────────────────
#
# Validate rust2rpm.toml against the rust2rpm JSON schema.
#
# Full spec regeneration via rust2rpm is not possible for this project:
#   - akamu is a Cargo workspace; rust2rpm rejects workspace Cargo.toml files.
#   - akamu is not published on crates.io; --offline fetch fails.
#   - cargo package fails on workspace path dependencies (no explicit versions).
# rust2rpm.toml is kept as a machine-validated record of the package metadata
# and build requirements.  The spec itself (akamu.spec.in) is maintained
# manually, bootstrapped from the rust2rpm-generated template.

validate-spec:
	rust2rpm --validate-only -C "$(CURDIR)/rust2rpm.toml"
	@echo "rust2rpm.toml is valid."

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
	rm -f $(ALL_SOURCES) "$(SPEC_TMP)"
	rm -rf "$(REPOROOT)/vendor"
