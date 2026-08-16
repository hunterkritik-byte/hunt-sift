"""Non-executing review of selected local source files."""

from __future__ import annotations

import re
from pathlib import Path

from ..core.io import iter_local_text_files, read_text
from ..core.models import Lead
from ..core.redaction import appears_placeholder, redact

STATIC_RULES = (
    (re.compile(r"\beval\s*\("), "dynamic-code-review", "Found eval( in a static file.", "Review data flow and whether untrusted input can reach it; this pattern alone is not a vulnerability."),
    (re.compile(r"\.innerHTML\s*="), "dom-sink-review", "Found an innerHTML assignment in a static file.", "Review the source value and sanitization path; do not assume XSS without an untrusted input chain."),
    (re.compile(r"\bdebug\s*=\s*true\b", re.IGNORECASE), "debug-setting-review", "Found a debug=true setting in a static file.", "Check the deployment configuration and whether debug output reveals sensitive data."),
    (re.compile(r"\bTODO\b|\bFIXME\b"), "implementation-note", "Found a TODO or FIXME marker.", "Use it as a code-review navigation cue, not a security finding."),
    (re.compile(r"http://[^\s'\"<>]+", re.IGNORECASE), "mixed-content-review", "Found an HTTP URL in a static file.", "Check the actual runtime context before concluding there is a mixed-content or downgrade risk."),
    (re.compile(r"access-control-allow-origin[\"']?\s*[:=]\s*[\"']?\*", re.IGNORECASE), "cors-policy-review", "Found a wildcard Access-Control-Allow-Origin configuration string.", "Confirm the server context and whether wildcard CORS is intentional."),
    (re.compile(r"(?is)\bcors\s*\(\s*\{(?=[^}]{0,300}\borigin\s*:\s*true)(?=[^}]{0,300}\bcredentials\s*:\s*true)[^}]{0,300}\}"), "cors-policy-review", "Found a CORS middleware configuration that allows credentials with origin:true.", "Verify this is not an unsafe CORS + credentials combination."),
    (re.compile(r"(?i)\bjwt\.decode\s*\("), "jwt-validation-review", "Found a JWT decode call in a static file.", "Review whether this call is used only for non-security UI data or whether a verification step follows."),
    (re.compile(r"(?i)\b(?:ignoreexpiration|verifyexpiration)\s*[:=]\s*(?:true|false)"), "jwt-claim-validation-review", "Found an explicit JWT expiration-validation configuration.", "Review the lifetime and context; disabling expiration validation is a high-risk pattern."),
    (re.compile(r"(?is)\b(?:jwt\.)?(?:sign|encode)\s*\([^;]{0,500}\b(?:algorithm|alg)\s*[:=]\s*[\"']none[\"']"), "jwt-algorithm-review", "Found a JWT creation configuration using algorithm 'none'.", "Confirm whether this is test-only or production code; using 'none' algorithm is a critical risk."),
)

# Combine all static rules into a single mega-pattern for one-pass scanning
_COMBINED_PATTERN = re.compile(
    "|".join(f"(?P<g{i}>{pattern.pattern})" for i, (pattern, _, _, _) in enumerate(STATIC_RULES)),
    re.IGNORECASE | re.MULTILINE
)

NAMED_CREDENTIAL = re.compile(
    r"(?ix)\b(?P<name>api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|jwt[_-]?secret|secret(?:[_-]?key)?|private[_-]?key)\b\s*[:=]\s*[\"'](?P<value>[^\"'\r\n]{12,})[\"']"
)
TOKEN_SHAPED_CREDENTIAL = re.compile(
    r"\b(?P<value>(?:AIza[0-9A-Za-z_-]{20,}|AKIA[0-9A-Z]{16}|ghp_[0-9A-Za-z]{20,}|github_pat_[0-9A-Za-z_]{20,}|xox[baprs]-[0-9A-Za-z-]{16,}))\b"
)

CREDENTIAL_PATTERNS = (NAMED_CREDENTIAL, TOKEN_SHAPED_CREDENTIAL)


def line_and_excerpt(text: str, index: int) -> tuple[int, str]:
    """Find a local line number without returning the full line contents."""
    return text[:index].count("\n") + 1, ""


def safe_excerpt(line: str) -> str:
    """Redact potential credentials before a generic static-rule excerpt is rendered."""
    # Use a list to avoid O(n²) string concatenation
    chars = list(line)
    # Track ranges to redact (in reverse order to maintain indices)
    redactions = []
    for pattern in CREDENTIAL_PATTERNS:
        for match in pattern.finditer(line):
            value = match.group("value")
            redactions.append((match.start("value"), match.end("value"), redact(value)))
    
    # Sort by start position in reverse to apply from end to beginning
    redactions.sort(reverse=True, key=lambda x: x[0])
    for start, end, replacement in redactions:
        chars = chars[:start] + list(replacement) + chars[end:]
    
    result = "".join(chars)[:180]
    return result


def credential_leads(file_path: Path, text: str) -> list[Lead]:
    """Find only likely local credential material and redact it before rendering evidence.
    
    Limits results to first 3 findings and uses deduplication by span.
    """
    leads: list[Lead] = []
    # Combine both patterns into a single pass
    candidates = NAMED_CREDENTIAL.finditer(text)
    matches: list[re.Match[str]] = []
    seen_spans: set[tuple[int, int]] = set()
    
    # Early exit: stop after finding 3 unique credentials
    for candidate in candidates:
        if len(matches) >= 3:
            break
        value_span = candidate.span("value")
        if value_span not in seen_spans:
            matches.append(candidate)
            seen_spans.add(value_span)
    
    # Only search token patterns if we haven't found 3 yet
    if len(matches) < 3:
        for candidate in TOKEN_SHAPED_CREDENTIAL.finditer(text):
            if len(matches) >= 3:
                break
            value_span = candidate.span("value")
            if value_span not in seen_spans:
                matches.append(candidate)
                seen_spans.add(value_span)
    
    for match in matches:
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
    """Analyze static text patterns without executing source code.
    
    Optimized to use combined regex pattern for single-pass scanning of all rules.
    """
    leads: list[Lead] = []
    lines_cache: dict[str, list[str]] = {}  # Cache splitlines per file
    
    for file_path in iter_local_text_files(path):
        text = read_text(file_path)
        lines_cache[str(file_path)] = text.splitlines()
        
        # Single combined pass over the text for all static rules
        for match in _COMBINED_PATTERN.finditer(text):
            # Find which group matched
            for i, (pattern, category, message, guidance) in enumerate(STATIC_RULES):
                if match.group(f"g{i}"):
                    line_number = text[: match.start()].count("\n") + 1
                    lines = lines_cache[str(file_path)]
                    snippet = safe_excerpt(lines[line_number - 1].strip()) if line_number <= len(lines) else ""
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
                    break
        
        leads.extend(credential_leads(file_path, text))
    
    return leads
