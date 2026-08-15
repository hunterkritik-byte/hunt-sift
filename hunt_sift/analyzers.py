"""Purely local parsers for researcher-supplied artifacts.

This module intentionally contains no networking, subprocess invocation, payload generation, or target discovery.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable


@dataclass(frozen=True)
class Lead:
    """A review prompt derived from an imported artifact, not a vulnerability claim."""

    source: str
    category: str
    severity: str
    message: str
    evidence: str
    guidance: str

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


def read_text(path: Path, limit: int = 2_000_000) -> str:
    """Read a user-supplied local text file with a size cap."""
    if not path.is_file():
        raise ValueError(f"Input must be a local file: {path}")
    if path.stat().st_size > limit:
        raise ValueError(f"Refusing to read {path}: it exceeds the {limit:,}-byte local analysis limit.")
    return path.read_text(encoding="utf-8", errors="replace")


def analyze_nmap_xml(path: Path) -> list[Lead]:
    """Analyze imported Nmap XML; it does not start Nmap or contact a host."""
    text = read_text(path)
    try:
        root = ET.fromstring(text)
    except ET.ParseError as exc:
        raise ValueError(f"Invalid Nmap XML: {exc}") from exc

    leads: list[Lead] = []
    legacy_services = {"telnet", "ftp", "rsh", "rlogin", "rexec"}
    for host in root.findall("host"):
        address = host.find("address")
        host_label = address.get("addr", "unknown-host") if address is not None else "unknown-host"
        for port in host.findall("./ports/port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            service = port.find("service")
            port_id = port.get("portid", "?")
            protocol = port.get("protocol", "tcp")
            service_name = (service.get("name", "unknown") if service is not None else "unknown").lower()
            product = service.get("product", "") if service is not None else ""
            version = service.get("version", "") if service is not None else ""
            evidence = f"{host_label} {protocol}/{port_id} reports service '{service_name}'"

            if service_name in legacy_services:
                leads.append(
                    Lead(
                        "nmap-xml",
                        "legacy-service-review",
                        "review",
                        f"Imported scan lists an open {service_name} service.",
                        evidence,
                        "Confirm scope and ownership, then review whether this service is expected, access-controlled, and still required. Do not infer a vulnerability from service presence alone.",
                    )
                )
            if service_name == "http":
                leads.append(
                    Lead(
                        "nmap-xml",
                        "transport-review",
                        "review",
                        "Imported scan lists HTTP. Compare the service inventory and transport policy with the authorized program requirements.",
                        evidence,
                        "Review redirect behavior and any HTTPS companion service only within confirmed scope; Hunt Sift does not make network requests.",
                    )
                )
            if product or version:
                fingerprint = " ".join(part for part in (product, version) if part)
                leads.append(
                    Lead(
                        "nmap-xml",
                        "service-inventory",
                        "informational",
                        "Imported scan contains service-version metadata.",
                        f"{evidence}; fingerprint: {fingerprint}",
                        "Treat version output as an inventory clue. Validate it against an authorized asset inventory before making any security conclusion.",
                    )
                )
    return leads


def parse_http_headers(text: str) -> tuple[str, dict[str, list[str]]]:
    """Parse the final HTTP response header block from a user-exported raw response."""
    blocks = re.split(r"\r?\n\r?\n(?=HTTP/)", text)
    header_block = next((block for block in reversed(blocks) if block.startswith("HTTP/")), text)
    lines = header_block.replace("\r\n", "\n").split("\n")
    status = lines[0].strip() if lines else "HTTP response"
    headers: dict[str, list[str]] = {}
    for line in lines[1:]:
        if not line or ":" not in line:
            continue
        name, value = line.split(":", 1)
        headers.setdefault(name.strip().lower(), []).append(value.strip())
    return status, headers


def analyze_http_export(path: Path, url: str | None = None) -> list[Lead]:
    """Review a saved response file without replaying or modifying any request."""
    status, headers = parse_http_headers(read_text(path))
    target = url or path.name
    leads: list[Lead] = []
    evidence_base = f"{target} / {status}"

    for name, message, guidance in (
        ("content-security-policy", "No Content-Security-Policy header was found in this exported response.", "Assess the page context and existing browser controls; header absence alone does not prove exploitability."),
        ("x-content-type-options", "No X-Content-Type-Options header was found in this exported response.", "Check whether user-controlled or ambiguous content types are actually served before assigning impact."),
        ("referrer-policy", "No Referrer-Policy header was found in this exported response.", "Review only if the page includes sensitive URL parameters or outbound navigation that could expose them."),
    ):
        if name not in headers:
            leads.append(Lead("http-export", "response-hardening-review", "review", message, evidence_base, guidance))

    if url and url.lower().startswith("https://") and "strict-transport-security" not in headers:
        leads.append(
            Lead(
                "http-export",
                "transport-hardening-review",
                "review",
                "HTTPS URL provided, but no Strict-Transport-Security header is present in the saved response.",
                evidence_base,
                "Check program policy and deployment context. HSTS absence is not automatically a reportable issue.",
            )
        )
    for cookie in headers.get("set-cookie", []):
        lowered = cookie.lower()
        missing = [flag for flag in ("secure", "httponly", "samesite") if flag not in lowered]
        if missing:
            leads.append(
                Lead(
                    "http-export",
                    "cookie-attribute-review",
                    "review",
                    f"A saved Set-Cookie value lacks: {', '.join(missing)}.",
                    f"{evidence_base}; Set-Cookie: {cookie[:160]}",
                    "Confirm cookie purpose, transport requirements, and program impact standards without using other users' data.",
                )
            )
    if "access-control-allow-origin" in headers and "*" in headers["access-control-allow-origin"]:
        leads.append(
            Lead(
                "http-export",
                "cors-policy-review",
                "review",
                "The exported response uses Access-Control-Allow-Origin: *.",
                evidence_base,
                "Review whether a sensitive unauthenticated response is readable cross-origin. Wildcard CORS alone does not establish impact.",
            )
        )
    for exposed in ("server", "x-powered-by"):
        if exposed in headers:
            leads.append(
                Lead(
                    "http-export",
                    "technology-metadata",
                    "informational",
                    f"The response exposes the {exposed} header.",
                    f"{evidence_base}; {exposed}: {headers[exposed][0]}",
                    "Treat this as inventory metadata unless it directly contributes to a validated security impact.",
                )
            )
    return leads


STATIC_RULES = (
    (re.compile(r"\beval\s*\("), "dynamic-code-review", "Found eval( in a static file.", "Review data flow and whether untrusted input can reach it; this pattern alone is not a vulnerability."),
    (re.compile(r"\.innerHTML\s*="), "dom-sink-review", "Found an innerHTML assignment in a static file.", "Review the source value and sanitization path; do not assume XSS without an untrusted input path."),
    (re.compile(r"\bdebug\s*=\s*true\b", re.IGNORECASE), "debug-setting-review", "Found a debug=true setting in a static file.", "Check the deployment configuration and whether debug output reveals sensitive application details."),
    (re.compile(r"\bTODO\b|\bFIXME\b"), "implementation-note", "Found a TODO or FIXME marker.", "Use it as a code-review navigation cue, not a security finding."),
    (re.compile(r"http://[^\s'\"<>]+", re.IGNORECASE), "mixed-content-review", "Found an HTTP URL in a static file.", "Check the actual runtime context before concluding there is a mixed-content or transport issue."),
)


def iter_local_text_files(path: Path) -> Iterable[Path]:
    """Yield small, ordinary text files under a user-selected local path."""
    if path.is_file():
        yield path
        return
    if not path.is_dir():
        raise ValueError(f"Input must be a local file or directory: {path}")
    for candidate in path.rglob("*"):
        if candidate.is_file() and candidate.stat().st_size <= 2_000_000:
            yield candidate


def analyze_static_path(path: Path) -> list[Lead]:
    """Inspect selected local source text; no code from the path is executed."""
    leads: list[Lead] = []
    skip_suffixes = {".png", ".jpg", ".jpeg", ".gif", ".ico", ".pdf", ".zip", ".woff", ".woff2"}
    for file_path in iter_local_text_files(path):
        if file_path.suffix.lower() in skip_suffixes:
            continue
        text = read_text(file_path)
        for pattern, category, message, guidance in STATIC_RULES:
            match = pattern.search(text)
            if not match:
                continue
            line_number = text[: match.start()].count("\n") + 1
            snippet = text.splitlines()[line_number - 1].strip()[:180]
            leads.append(
                Lead(
                    "static-file",
                    category,
                    "review" if category != "implementation-note" else "informational",
                    message,
                    f"{file_path}:{line_number}: {snippet}",
                    guidance,
                )
            )
    return leads
