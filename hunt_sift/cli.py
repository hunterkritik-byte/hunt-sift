"""Hunt Sift CLI: an offline security-research workbench."""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
from .core.models import Lead
from .core.render import render_leads
from .core.reporting import write_json, write_sarif
from .core.html_report import write_html
from .core.risk_engine import prioritize, triage_summary
from .core.request_review import analyze_request, safe_test_templates
from .core.source_review import analyze_source
from .core.workspace import index_directory, write_index
from .core.io import read_text
from .core.jwt_review import analyze_jwt
from .core.graphql_review import analyze_graphql
from .core.openapi_review import analyze_openapi
from .core.secrets_review import analyze_secrets
from .core.response_diff import compare_responses
from .core.endpoint_map import endpoint_dicts
from .core.parameter_miner import mine_parameters
from .parsers import burp_xml, har, http_export, nmap_xml, s3_policy, static_files

MAX_FINDINGS = 10_000
MAX_FINDING_FIELD_BYTES = 20_000


def local_path(value: str) -> Path:
    raw = Path(value).expanduser()
    if raw.is_symlink():
        raise argparse.ArgumentTypeError(f"Refusing to follow symbolic link: {raw}")
    path = raw.resolve()
    if not path.exists():
        raise argparse.ArgumentTypeError(f"Local input does not exist: {path}")
    return path


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="hunt-sift", description="Offline security workbench for researcher-supplied artifacts. No scanning, replay, execution, or network access.")
    parser.add_argument("--json", action="store_true", help="Print structured JSON where supported.")
    commands = parser.add_subparsers(dest="command", required=True)
    for name, help_text in (("nmap","Analyze a previously exported Nmap XML file."),("burp","Analyze a previously exported Burp Suite XML file."),("har","Analyze a previously saved HTTP Archive (HAR) file."),("http","Analyze a previously saved raw HTTP response."),("request","Analyze a previously saved raw HTTP request."),("s3","Analyze a previously exported S3-style bucket policy JSON file."),("static","Review local source with non-executing pattern checks."),("source","Analyze source or JavaScript with non-executing security rules."),("jwt","Decode and review a locally supplied JWT without verifying or transmitting it."),("graphql","Review a saved GraphQL request/query for security configuration cues."),("openapi","Review a saved OpenAPI/Swagger JSON specification."),("secrets","Scan local text for secret-like patterns with mandatory redaction.")):
        command = commands.add_parser(name, help=help_text)
        command.add_argument("--input", required=True, type=local_path)
        if name == "http":
            command.add_argument("--url", help="Optional original URL used only as a local label; it is never requested.")
    templates = commands.add_parser("test-templates", help="Generate inert manual-review templates from a saved HTTP request.")
    templates.add_argument("--input", required=True, type=local_path)
    inventory = commands.add_parser("inventory", help="Build a local project index with SHA-256 fingerprints.")
    inventory.add_argument("--input", required=True, type=local_path); inventory.add_argument("--output")
    search = commands.add_parser("search", help="Search a local inventory JSON file.")
    search.add_argument("--input", required=True, type=local_path); search.add_argument("--query", required=True)
    report = commands.add_parser("report", help="Convert saved findings into JSON, SARIF, or HTML.")
    report.add_argument("--input", required=True, type=local_path); report.add_argument("--output", required=True); report.add_argument("--format", choices=("json","sarif","html"), default="json")
    triage = commands.add_parser("triage", help="Prioritize a saved finding list using deterministic local scoring.")
    triage.add_argument("--input", required=True, type=local_path)
    diff = commands.add_parser("diff", help="Compare two saved HTTP responses without sending requests.")
    diff.add_argument("--before", required=True, type=local_path); diff.add_argument("--after", required=True, type=local_path)
    endpoints = commands.add_parser("endpoints", help="Build a deduplicated endpoint map from a local artifact.")
    endpoints.add_argument("--input", required=True, type=local_path)
    params = commands.add_parser("params", help="Mine and classify parameter names from a local artifact.")
    params.add_argument("--input", required=True, type=local_path)
    commands.add_parser("boundaries", help="Print the tool's safety and authorization boundaries.")
    return parser


def _field(value: object, name: str) -> str:
    text = str(value)
    if len(text.encode("utf-8")) > MAX_FINDING_FIELD_BYTES:
        raise ValueError(f"Finding field '{name}' exceeds the {MAX_FINDING_FIELD_BYTES:,}-byte limit")
    return text


def load_leads(path: Path) -> list[Lead]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(payload, dict) and isinstance(payload.get("findings"), list):
        payload = payload["findings"]
    if not isinstance(payload, list):
        raise ValueError("Finding JSON must contain a list or a report object with a findings list")
    if len(payload) > MAX_FINDINGS:
        raise ValueError(f"Finding JSON contains {len(payload):,} entries; limit is {MAX_FINDINGS:,}")
    leads = []
    required = ("source", "category", "severity", "message", "evidence", "guidance")
    for row in payload:
        if not isinstance(row, dict):
            continue
        if not all(k in row for k in required):
            raise ValueError("Each finding must contain source, category, severity, message, evidence, and guidance")
        leads.append(Lead(*(_field(row[k], k) for k in required)))
    return leads


def lead_key(lead: Lead) -> str:
    material = "\x1f".join((lead.category, lead.severity, lead.message, lead.evidence, lead.guidance))
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def deduplicate(leads: list[Lead]) -> list[Lead]:
    """Remove exact duplicate review leads deterministically while preserving order."""
    seen: set[str] = set()
    result: list[Lead] = []
    for lead in leads:
        key = lead_key(lead)
        if key not in seen:
            seen.add(key)
            result.append(lead)
    return result


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "inventory":
            records = index_directory(args.input); write_index(records, args.output) if args.output else None
            print(json.dumps([r.__dict__ for r in records], indent=2) if args.json else f"Indexed {len(records)} local artifacts."); return 0
        if args.command == "search":
            data = json.loads(args.input.read_text(encoding="utf-8")); needle = args.query.casefold()
            rows = [r for r in data if needle in str(r.get("path", "")).casefold() or needle in str(r.get("kind", "")).casefold()]
            print(json.dumps(rows, indent=2) if args.json else "\n".join(f"{r.get('kind','other'):12} {r.get('path','')}" for r in rows) or "No matching artifacts."); return 0
        if args.command == "report":
            leads = deduplicate(load_leads(args.input))
            if args.format == "sarif": write_sarif(args.output, leads)
            elif args.format == "html": write_html(args.output, leads)
            else: write_json(args.output, leads)
            print(f"Wrote {args.format} report with {len(leads)} local review leads to {args.output}."); return 0
        if args.command == "triage":
            leads = deduplicate(load_leads(args.input)); rows = prioritize(leads); summary = triage_summary(leads)
            payload = {"summary": summary, "findings": rows}
            print(json.dumps(payload, indent=2) if args.json else "\n".join(f"P{r['priority']}  {r['lead']['category']}: {r['lead']['message']}" for r in rows) or "No findings to triage."); return 0
        if args.command == "diff":
            print(render_leads(compare_responses(read_text(args.before), read_text(args.after)), args.json)); return 0
        if args.command == "endpoints":
            payload = endpoint_dicts(read_text(args.input), str(args.input)); print(json.dumps(payload, indent=2) if args.json else "\n".join(f"{r['method']:6} {r['path']}  params={','.join(r['parameters'])}" for r in payload) or "No endpoints found."); return 0
        if args.command == "params":
            payload = mine_parameters(read_text(args.input)); print(json.dumps(payload, indent=2) if args.json else "\n".join(f"{k}: {', '.join(v)}" for k,v in payload["classes"].items() if v) or "No classified parameters found."); return 0
        if args.command == "request": leads = analyze_request(read_text(args.input))
        elif args.command == "source": leads = analyze_source(read_text(args.input), str(args.input))
        elif args.command == "jwt": leads = analyze_jwt(read_text(args.input))
        elif args.command == "graphql": leads = analyze_graphql(read_text(args.input))
        elif args.command == "openapi": leads = analyze_openapi(read_text(args.input))
        elif args.command == "secrets": leads = analyze_secrets(read_text(args.input), str(args.input))
        elif args.command == "test-templates":
            payload = safe_test_templates(read_text(args.input)); print(json.dumps(payload, indent=2) if args.json else "\n".join(f"{i['class']}: {i['template']}" for i in payload) or "No manual-review templates generated."); return 0
        else:
            analyzers = {"nmap": nmap_xml.analyze, "burp": burp_xml.analyze, "har": har.analyze, "static": static_files.analyze, "s3": s3_policy.analyze}
            if args.command == "http": leads = http_export.analyze(args.input, args.url)
            elif args.command in analyzers: leads = analyzers[args.command](args.input)
            else: print("Hunt Sift reads researcher-supplied local artifacts only. It does not scan, replay requests, execute files, generate exploit payloads, store credentials, or contact networks."); return 0
    except (ValueError, OSError, json.JSONDecodeError) as error:
        print(f"Input error: {error}"); return 2
    print(render_leads(leads, args.json)); return 0


if __name__ == "__main__": raise SystemExit(main())
