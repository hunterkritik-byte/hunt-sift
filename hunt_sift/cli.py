"""Hunt Sift CLI. Every command reads a named local artifact and never contacts targets."""

from __future__ import annotations

import argparse
from pathlib import Path

from .core.render import render_leads
from .parsers import burp_xml, har, http_export, nmap_xml, s3_policy, static_files


def local_path(value: str) -> Path:
    """Validate that a user named an existing local file or directory."""
    path = Path(value).expanduser().resolve()
    if not path.exists():
        raise argparse.ArgumentTypeError(f"Local input does not exist: {path}")
    return path


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="hunt-sift",
        description="Offline-only review of local Nmap XML, Burp XML, HAR, HTTP exports, S3 policy JSON, and static files. No scanning, network, or execution features.",
    )
    parser.add_argument("--json", action="store_true", help="Print structured JSON rather than readable text.")
    commands = parser.add_subparsers(dest="command", required=True)
    for name, help_text in (
        ("nmap", "Analyze a previously exported local Nmap XML file."),
        ("burp", "Analyze a previously exported local Burp Suite XML file."),
        ("har", "Analyze a previously saved HTTP Archive (HAR) file."),
        ("http", "Analyze a previously saved raw HTTP response file."),
        ("s3", "Analyze a previously exported S3-style bucket policy JSON file."),
        ("static", "Review a selected local file or directory with non-executing pattern checks."),
    ):
        command = commands.add_parser(name, help=help_text)
        command.add_argument("--input", required=True, type=local_path, help="Path to a local artifact.")
        if name == "http":
            command.add_argument("--url", help="Optional original URL used only as a redacted local label; it is never requested.")
    commands.add_parser("boundaries", help="Print the tool's safety and authorization boundaries.")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        analyzers = {
            "nmap": nmap_xml.analyze,
            "burp": burp_xml.analyze,
            "har": har.analyze,
            "static": static_files.analyze,
            "s3": s3_policy.analyze,
        }
        if args.command == "http":
            leads = http_export.analyze(args.input, args.url)
        elif args.command in analyzers:
            leads = analyzers[args.command](args.input)
        else:
            print("Hunt Sift accepts only researcher-supplied local artifacts. It does not scan, discover targets, replay requests, execute files, generate payloads, store credentials, or contact networks. Confirm authorization separately before any testing.")
            return 0
    except ValueError as error:
        print(f"Input error: {error}")
        return 2
    print(render_leads(leads, args.json))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
