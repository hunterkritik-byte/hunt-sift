#!/usr/bin/env python3
"""Build a compact, redacted digest from a Hunt Sift findings/report JSON file.

Offline-only utility: reads one local JSON file and writes JSON to stdout.
"""
from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path


def load(path: Path) -> list[dict]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, dict):
        data = data.get("findings", [])
    if not isinstance(data, list):
        raise ValueError("Input must be a findings list or an object containing 'findings'.")
    return [row for row in data if isinstance(row, dict)]


def main() -> int:
    parser = argparse.ArgumentParser(description="Summarize a local Hunt Sift findings file.")
    parser.add_argument("input", type=Path)
    args = parser.parse_args()

    rows = load(args.input)
    severity = Counter(str(r.get("severity", "unknown")) for r in rows)
    category = Counter(str(r.get("category", "unknown")) for r in rows)

    digest = {
        "input": str(args.input),
        "finding_count": len(rows),
        "severity": dict(sorted(severity.items())),
        "categories": dict(sorted(category.items())),
        "notes": [
            "Digest is derived only from the supplied local JSON.",
            "Evidence and finding messages are intentionally omitted to reduce sensitive-data exposure.",
            "Counts are triage metadata, not exploitability or severity validation.",
        ],
    }
    print(json.dumps(digest, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
