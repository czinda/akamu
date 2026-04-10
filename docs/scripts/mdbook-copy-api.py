#!/usr/bin/env python3
"""
mdBook renderer: copy target/doc into the book output as api/.

Configured in docs/book.toml:

    [output.copy-api]
    command = "python3 ../../scripts/mdbook-copy-api.py"

Protocol
--------
mdBook sends a JSON object to stdin:
    {"root": "/abs/path/to/docs", "book": {...}, "config": {...},
     "destination": "/abs/path/to/docs/book/copy-api", "renderer": "copy-api", ...}

The renderer consumes stdin, performs its work, and exits 0 on success.
No stdout output is required.

mdBook runs the renderer with CWD set to the renderer output subdirectory
(docs/book/copy-api/), so all path resolution uses the JSON "root" and
"destination" fields rather than the CWD.  The HTML renderer runs first
and cleans docs/book/ before this renderer is called, so the copy always
lands in a fresh output tree.
"""

import json
import os
import shutil
import sys

data = json.load(sys.stdin)

# data["root"] is the absolute path to the book root (docs/).
# The workspace root is one level up; target/doc lives there.
book_root = data["root"]
workspace_root = os.path.dirname(book_root)
src = os.path.join(workspace_root, "target", "doc")

# With multiple renderers mdBook places each renderer's output in its own
# named subdirectory: build-dir/html/ for HTML, build-dir/copy-api/ for us.
# api/ must live inside the HTML output so links resolve correctly.
build_dir = data.get("config", {}).get("build", {}).get("build-dir", "book")
dst = os.path.join(book_root, build_dir, "html", "api")

if not os.path.isdir(src):
    print(
        f"mdbook-copy-api: skipped — {src} not found "
        "(run: cargo doc --workspace --no-deps)",
        file=sys.stderr,
    )
    sys.exit(0)

if os.path.exists(dst):
    shutil.rmtree(dst)
shutil.copytree(src, dst)
print(f"mdbook-copy-api: rustdoc → {dst}/", file=sys.stderr)
