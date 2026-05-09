#!/usr/bin/env python3
"""
Vendor local-path Cargo crates into a vendor/ directory.

Usage: vendor-local-crates.py <repo-root> <synta-repo-root> <vendor-dir>

For each synta-related crate found in Cargo.lock but absent from vendor/,
copies the crate source into vendor/<name>-<ver>/ with a valid
.cargo-checksum.json.  Workspace member subdirectories of the root crate are
excluded (they appear as separate packages with their own vendor entries).
"""
import hashlib
import json
import re
import shutil
import sys
from pathlib import Path

CRATES = [
    "synta",
    "synta-certificate",
    "synta-codegen",
    "synta-derive",
    "synta-mtc",
    "synta-x509-verification",
]

SKIP_PARTS = {".git", "target"}


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def read_versions(lock: Path) -> dict[str, str]:
    versions: dict[str, str] = {}
    for block in re.split(r"\[\[package\]\]", lock.read_text()):
        m_name = re.search(r'^name\s*=\s*"([^"]+)"', block, re.MULTILINE)
        m_ver = re.search(r'^version\s*=\s*"([^"]+)"', block, re.MULTILINE)
        if m_name and m_ver:
            versions[m_name.group(1)] = m_ver.group(1)
    return versions


def workspace_member_dirs(synta_root: Path) -> set[str]:
    text = (synta_root / "Cargo.toml").read_text()
    m = re.search(r'\[workspace\][^\[]*?members\s*=\s*\[([^\]]+)\]', text, re.DOTALL)
    if not m:
        return set()
    return {s.strip().strip('"') for s in m.group(1).split(",") if s.strip().strip('"') != "."}


def crate_dir(synta_root: Path, name: str) -> Path:
    if name == "synta":
        return synta_root
    d = synta_root / name
    if (d / "Cargo.toml").exists():
        return d
    raise FileNotFoundError(f"no Cargo.toml for {name} under {synta_root}")


def vendor_crate(src: Path, dst: Path, exclude_top: set[str]) -> None:
    files: dict[str, str] = {}
    for item in src.rglob("*"):
        parts = item.relative_to(src).parts
        if any(p in SKIP_PARTS or p.startswith(".") for p in parts):
            continue
        if parts[0] in exclude_top:
            continue
        if not item.is_file():
            continue
        rel = str(item.relative_to(src))
        dest = dst / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(item, dest)
        files[rel] = sha256_file(item)
    (dst / ".cargo-checksum.json").write_text(
        json.dumps({"files": files, "package": None}, separators=(",", ":"))
    )
    print(f"    {dst.name}: vendored {len(files)} files")


def main() -> None:
    if len(sys.argv) != 4:
        sys.exit(__doc__)
    repo_root = Path(sys.argv[1])
    synta_root = Path(sys.argv[2])
    vendor_dir = Path(sys.argv[3])

    versions = read_versions(repo_root / "Cargo.lock")
    ws_members = workspace_member_dirs(synta_root)

    for name in CRATES:
        ver = versions.get(name)
        if not ver:
            print(f"  {name}: not in Cargo.lock, skipping")
            continue
        dst = vendor_dir / f"{name}-{ver}"
        if dst.exists():
            continue
        src = crate_dir(synta_root, name)
        exclude = ws_members if name == "synta" else set()
        print(f"  vendoring {name}-{ver} from {src}")
        vendor_crate(src, dst, exclude)


if __name__ == "__main__":
    main()
