"""Non-executing review of selected local source files."""

from __future__ import annotations

import re
from pathlib import Path

from ..core.io import iter_local_text_files, read_text
from ..core.models import Lead
from ..core.redaction import appears_placeholder, redact

STATIC_RULES = (
    (re.compile(r"\beval\s*\("), "dynamic-code-review", "Found eval( in a static file.", "Review data flow and whether untrusted input can reach it; this pattern alone is not a vulnerability."),
    (re.compile(r"\.innerHTML\s*="), "dom-sink-review", "Found an innerHTML assignment in a static file.", "Review the source value and sanitization path; do not assume XSS without an untrusted input path."),
    (re.compile(r"\bdebug\s*=\s*true\b", re.IGNORECASE), "debug-setting-review", "Found a debug=true setting in a static file.", "Check the deployment configuration and whether debug output reveals sensitive application details."),
    (re.compile(r"\bTODO\b|\bFIXME\b"), "implementation-note", "Found a TODO or FIXME marker.", "Use it as a code-review navigation cue, not a security finding."),
    (re.compile(r"http://[^\s'\"<>]+", re.IGNORECASE), "mixed-content-review", "Found an HTTP URL in a static file.", "Check the actual runtime context before concluding there is a mixed-content or transport issue."),
    (re.compile(r"access-control-allow-origin[\"']?\s*[:=]\s*[\"']?\*", re.IGNORECASE), "cors-policy-review", "Found a wildcard Access-Control-Allow-Origin configuration string.", "Confirm the served response, sensitivity of the resource, and authorization before making any cross-origin security claim."),
    (re.compile(r"(?is)\bcors\s*\(\s*\{(?=[^}]{0,300}\borigin\s*:\s*true)(?=[^}]{0,300}\bcredentials\s*:\s*true)[^}]{0,300}\}"), "cors-policy-review", "Found a CORS middleware configuration that appears to allow reflected origins with credentials.", "Review the exact framework behavior and protected response context. A source pattern alone does not establish cross-origin impact."),
)

NAMED_CREDENTIAL = re.compile(
    r"(?ix)\b(?P<name>api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|secret(?:[_-]?key)?|private[_-]?key)\b\s*[:=]\s*[\"'](?P<value>[^\"'\r\n]{12,})[\"']"
)
TOKEN_SHAPED_CREDENTIAL = re.compile(
    r"\b(?P<value>(?:AIza[0-9A-Za-z_-]{20,}|AKIA[0-9A-Z]{16}|ghp_[0-9A-Za-z]{20,}|github_pat_[0-9A-Za-z_]{20,}|xox[baprs]-[0-9A-Za-z-]{16,}))\b"
)


def line_and_excerpt(text: str, index: int) -> tuple[int, str]:
    """Find a local line number without returning the full line contents."""
    return text[:index].count("\n") + 1, ""


def credential_leads(file_path: Path, text: str) -> list[Lead]:
    """Find only likely local credential material and redact it before rendering evidence."""
    leads: list[Lead] = []
    candidates = list(NAMED_CREDENTIAL.finditer(text)) + list(TOKEN_SHAPED_CREDENTIAL.finditer(text))
    matches: list[re.Match[str]] = []
    seen_spans: set[tuple[int, int]] = set()
    for candidate in candidates:
        value_span = candidate.span("value")
        if value_span not in seen_spans:
            matches.append(candidate)
            seen_spans.add(value_span)
    for match in matches[:3]:
        value = match.group("value")
        if appears_placeholder(value):
            continue
        line_number, _ = line_and_excerpt(text, match.start())
        name = match.groupdict().get("name") or "token-shaped value"
        leads.append(
            Lead(
                "static-file",
                "potential-credential-exposure",
                "review",
                f"Found a potential credential-shaped value associated with '{name}'.",
                f"{file_path}:{line_number}: value={redact(value)}",
                "Treat this as a local triage signal only. Confirm whether it is real, revoke through the owner's approved process if needed, and never publish the full value.",
            )
        )
    return leads


def analyze(path: Path) -> list[Lead]:
    """Analyze static text patterns without executing source code."""
    leads: list[Lead] = []
    for file_path in iter_local_text_files(path):
        text = read_text(file_path)
        for pattern, category, message, guidance in STATIC_RULES:
            match = pattern.search(text)
            if not match:
                continue
            line_number = text[: match.start()].count("\n") + 1
            snippet = text.splitlines()[line_number - 1].strip()[:180]
            leads.append(Lead("static-file", category, "review" if category != "implementation-note" else "informational", message, f"{file_path}:{line_number}: {snippet}", guidance))
        leads.extend(credential_leads(file_path, text))
    return leads
