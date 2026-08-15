"""Non-executing review of selected local source files."""

from __future__ import annotations

import re
from pathlib import Path

from ..core.io import iter_local_text_files, read_text
from ..core.models import Lead

STATIC_RULES = (
    (re.compile(r"\beval\s*\("), "dynamic-code-review", "Found eval( in a static file.", "Review data flow and whether untrusted input can reach it; this pattern alone is not a vulnerability."),
    (re.compile(r"\.innerHTML\s*="), "dom-sink-review", "Found an innerHTML assignment in a static file.", "Review the source value and sanitization path; do not assume XSS without an untrusted input path."),
    (re.compile(r"\bdebug\s*=\s*true\b", re.IGNORECASE), "debug-setting-review", "Found a debug=true setting in a static file.", "Check the deployment configuration and whether debug output reveals sensitive application details."),
    (re.compile(r"\bTODO\b|\bFIXME\b"), "implementation-note", "Found a TODO or FIXME marker.", "Use it as a code-review navigation cue, not a security finding."),
    (re.compile(r"http://[^\s'\"<>]+", re.IGNORECASE), "mixed-content-review", "Found an HTTP URL in a static file.", "Check the actual runtime context before concluding there is a mixed-content or transport issue."),
)


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
    return leads
