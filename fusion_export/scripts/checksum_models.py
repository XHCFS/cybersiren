#!/usr/bin/env python3
"""
Print SHA-256 checksums for the model joblib files.

Use before/after a model swap to verify integrity:
  python scripts/checksum_models.py
  python scripts/checksum_models.py --verify checksums.txt
"""
from __future__ import annotations

import argparse
import hashlib
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MODEL_FILES = [
    "models/url_char_lr.joblib",
    "models/hgb_operational.joblib",
]


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--models-dir", type=Path, default=ROOT / "models")
    ap.add_argument("--verify", type=Path, default=None,
                    help="Compare against a saved checksums file (one 'sha256  path' per line)")
    args = ap.parse_args()

    current: dict[str, str] = {}
    for rel in MODEL_FILES:
        p = args.models_dir / Path(rel).name
        if not p.exists():
            print(f"MISSING  {p}", file=sys.stderr)
            continue
        digest = sha256(p)
        current[str(p.name)] = digest
        print(f"{digest}  {p}")

    if args.verify:
        expected: dict[str, str] = {}
        for line in args.verify.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(None, 1)
            if len(parts) == 2:
                digest, path = parts
                expected[Path(path).name] = digest

        ok = True
        for name, digest in current.items():
            exp = expected.get(name)
            if exp is None:
                print(f"NOT IN BASELINE  {name}")
            elif exp != digest:
                print(f"MISMATCH  {name}")
                print(f"  expected: {exp}")
                print(f"  got:      {digest}")
                ok = False
            else:
                print(f"OK  {name}")
        return 0 if ok else 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
