#!/usr/bin/env python3
"""
generate_manifest.py — regenerate docs/manifest.json

Scans the docs/ directory for HTML files, groups them by folder (each folder
becomes a print section), and writes manifest.json.

Run whenever a new doc is added:
    python docs/generate_manifest.py

Or via make:
    make docs-manifest
"""

import json
import re
from pathlib import Path

DOCS_ROOT = Path(__file__).parent

# Files and folders to skip
EXCLUDE_FILES = {"index.html", "print.html"}
EXCLUDE_FOLDERS = {
    "screenshots",
    "Universität Hamburg_files",
    "api",       # placeholder folders — add back when they have docs
    "runbooks",
    "decisions",
    "database",
}


def extract_title(path: Path) -> str:
    """Pull <title> or first <h1> text from an HTML file."""
    try:
        text = path.read_text(errors="replace")
        m = re.search(r"<title[^>]*>([^<]+)</title>", text, re.I)
        if m:
            return m.group(1).strip()
        m = re.search(r"<h1[^>]*>([^<]+)</h1>", text, re.I)
        if m:
            return re.sub(r"<[^>]+>", "", m.group(1)).strip()
    except OSError:
        pass
    return path.stem.replace("_", " ").replace("-", " ")


def main() -> None:
    sections: dict[str, list[dict]] = {}

    for path in sorted(DOCS_ROOT.glob("**/*.html")):
        rel = path.relative_to(DOCS_ROOT)
        parts = rel.parts

        # Skip root-level files and excluded names
        if len(parts) == 1:
            continue
        folder = parts[0]
        if folder in EXCLUDE_FOLDERS:
            continue
        if rel.name in EXCLUDE_FILES:
            continue

        sections.setdefault(folder, []).append(
            {"file": str(rel).replace("\\", "/"), "title": extract_title(path)}
        )

    manifest = {
        "sections": [
            {"name": folder.upper(), "folder": folder, "docs": docs}
            for folder, docs in sorted(sections.items())
        ]
    }

    out = DOCS_ROOT / "manifest.json"
    out.write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n")

    total = sum(len(s["docs"]) for s in manifest["sections"])
    print(
        f"manifest.json updated — {total} docs across "
        f"{len(manifest['sections'])} sections: "
        + ", ".join(s["folder"] for s in manifest["sections"])
    )


if __name__ == "__main__":
    main()
