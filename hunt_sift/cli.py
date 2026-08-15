"""Hunt Sift CLI. All commands read named local artifacts only; none send network traffic."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .analyzers import Lead, analyze_http_export, analyze_nmap_xml, analyze_static_path


def local_path(value: str) -> Path:
    path = Path(value).expanduser().resolve()
    if not path.exists():
        raise argparse.ArgumentTypeError(f"Local input does not exist: {path}")
    return path


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="hunt-sift",
        description="Offline-only review of local Nmap XML, HTTP exports, and static files. No scanning, network, or execution features.",
    )
    parser.add_argument("--json", action="store_true", help="Print structured JSON rather than readable text.")
    commands = parser.add_subparsers(dest="command", required=True)

    nmap = commands.add_parser("nmap", help="Analyze a previously exported local Nmap XML file.")
    nmap.add_argument("--input", required=True, type=local_path, help="Path to a local Nmap XML export.")

    http = commands.add_parser("http", help="Analyze a previously saved raw HTTP response file.")
    http.add_argument("--input", required=True, type=local_path, help="Path to a local response export.")
    http.add_argument("--url", help="Optional original URL used only to label the local report; it is never requested.")

    static = commands.add_parser("static", help="Review a selected local file or directory with non-executing pattern checks.")
    static.add_argument("--input", required=True, type=local_path, help="Path to a local file or directory.")

    commands.add_parser("boundaries", help="Print the tool's safety and authorization boundaries.")
    return parser


def print_leads(leads: list[Lead], as_json: bool) -> None:
    if as_json:
        print(json.dumps([lead.to_dict() for lead in leads], indent=2))
        return
    if not leads:
        print("No review leads were generated from this local artifact. This is not a security conclusion.")
        return
    for number, lead in enumerate(leads, start=1):
        print(f"[{number}] {lead.severity.upper()} / {lead.category}")
        print(f"  {lead.message}")
        print(f"  evidence: {lead.evidence}")
        print(f"  next step: {lead.guidance}\n")


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "nmap":
            leads = analyze_nmap_xml(args.input)
        elif args.command == "http":
            leads = analyze_http_export(args.input, args.url)
        elif args.command == "static":
            leads = analyze_static_path(args.input)
        else:
            print(
                "Hunt Sift accepts only researcher-supplied local artifacts. It does not scan, discover targets, replay requests, execute files, generate payloads, store credentials, or contact networks. Confirm authorization separately before any testing."
            )
            return 0
    except ValueError as error:
        print(f"Input error: {error}")
        return 2
    print_leads(leads, args.json)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
