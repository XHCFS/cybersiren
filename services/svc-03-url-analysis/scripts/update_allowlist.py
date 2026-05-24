#!/usr/bin/env python3
"""
Generate the Cisco Umbrella top-N apex-domain allowlist.

Usage:
    python3 scripts/update_allowlist.py \
        --input /path/to/top-1m.csv \
        --output services/svc-03-url-analysis/internal/url/data/top10k_domains.txt \
        --n 10000

The Cisco Umbrella top-1M CSV format is: rank,domain
Download from: https://s3-us-west-1.amazonaws.com/umbrella-static/top-1m.csv.zip
"""

import argparse
import sys

try:
    import tldextract
except ImportError:
    print("error: tldextract is required — pip install tldextract", file=sys.stderr)
    sys.exit(1)


def main():
    parser = argparse.ArgumentParser(description="Generate apex-domain allowlist from Cisco Umbrella top-1M CSV.")
    parser.add_argument("--input", required=True, help="Path to Cisco Umbrella top-1m.csv")
    parser.add_argument("--output", required=True, help="Output path for the allowlist text file")
    parser.add_argument("--n", type=int, default=10000, help="Number of entries to emit (default: 10000)")
    args = parser.parse_args()

    seen: set[str] = set()
    results: list[str] = []

    with open(args.input, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            parts = line.split(",", 1)
            domain = parts[1] if len(parts) == 2 else parts[0]
            ext = tldextract.extract(domain.strip())
            if not ext.domain or not ext.suffix:
                continue
            apex = f"{ext.domain}.{ext.suffix}"
            if apex in seen:
                continue
            seen.add(apex)
            results.append(apex)
            if len(results) >= args.n:
                break

    with open(args.output, "w", encoding="utf-8") as f:
        f.write("\n".join(results) + "\n")

    print(f"wrote {len(results)} entries to {args.output}")


if __name__ == "__main__":
    main()
