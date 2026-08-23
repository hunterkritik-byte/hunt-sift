"""Hunt Sift CLI: an offline security-research workbench."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .core.render import render_leads
from .core.workspace import index_directory, search_records, write_index
from .parsers import burp_xml, har, http_export, nmap_xml, s3_policy, static_files


def local_path(value: str) -> Path:
    path = Path(value).expanduser().resolve()
    if not path.exists():
        raise argparse.ArgumentTypeError(f"Local input does not exist: {path}")
    return path


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="hunt-sift",
        description="Offline security workbench for researcher-supplied artifacts. No scanning, replay, execution, or network access.",
    )
    parser.add_argument("--json", action="store_true", help="Print structured JSON where supported.")
    commands = parser.add_subparsers(dest="command", required=True)
    for name, help_text in (
        ("nmap", "Analyze a previously exported Nmap XML file."),
        ("burp", "Analyze a previously exported Burp Suite XML file."),
        ("har", "Analyze a previously saved HTTP Archive (HAR) file."),
        ("http", "Analyze a previously saved raw HTTP response."),
        ("s3", "Analyze a previously exported S3-style bucket policy JSON file."),
        ("static", "Review local source with non-executing pattern checks."),
    ):
        command = commands.add_parser(name, help=help_text)
        command.add_argument("--input", required=True, type=local_path)
        if name == "http":
            command.add_argument("--url", help="Optional original URL used only as a local label; it is never requested.")

    inventory = commands.add_parser("inventory", help="Build a local project index with SHA-256 fingerprints.")
    inventory.add_argument("--input", required=True, type=local_path)
    inventory.add_argument("--output", help="Optional JSON index path.")

    search = commands.add_parser("search", help="Search a previously generated local inventory JSON file.")
    search.add_argument("--input", required=True, type=local_path)
    search.add_argument("--query", required=True)

    commands.add_parser("boundaries", help="Print the tool's safety and authorization boundaries.")
    return parser


def _inventory_rows(path: Path) -> list[dict[str, object]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, list):
        raise ValueError("Inventory JSON must contain a list")
    return data


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "inventory":
            records = index_directory(args.input)
            if args.output:
                write_index(records, args.output)
            payload = [record.__dict__ for record in records]
            print(json.dumps(payload, indent=2) if args.json else f"Indexed {len(records)} local artifacts.")
            return 0
        if args.command == "search":
            rows = _inventory_rows(args.input)
            needle = args.query.casefold()
            rows = [row for row in rows if needle in str(row.get("path", "")).casefold() or needle in str(row.get("kind", "")).casefold()]
            print(json.dumps(rows, indent=2) if args.json else "\n".join(f"{row.get('kind','other'):12} {row.get('path','')}" for row in rows) or "No matching artifacts.")
            return 0

        analyzers = {"nmap": nmap_xml.analyze, "burp": burp_xml.analyze, "har": har.analyze, "static": static_files.analyze, "s3": s3_policy.analyze}
        if args.command == "http":
            leads = http_export.analyze(args.input, args.url)
        elif args.command in analyzers:
            leads = analyzers[args.command](args.input)
        else:
            print("Hunt Sift only reads researcher-supplied local artifacts. It does not scan, discover targets, replay requests, execute files, generate payloads, store credentials, or contact networks. Confirm authorization separately before testing.")
            return 0
    except (ValueError, OSError, json.JSONDecodeError) as error:
        print(f"Input error: {error}")
        return 2
    print(render_leads(leads, args.json))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
