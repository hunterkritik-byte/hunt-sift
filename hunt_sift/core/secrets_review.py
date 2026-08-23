"""Conservative local secret-pattern review with mandatory redaction."""
from __future__ import annotations
import re
from .models import Lead

_PATTERNS = (
    ("private-key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"), "high"),
    ("github-token-like", re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b"), "high"),
    ("aws-access-key-like", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "high"),
    ("generic-secret-assignment", re.compile(r"(?i)\b(?:api[_-]?key|secret|password|token)\s*[:=]\s*[\"'][^\"']{8,}[\"']"), "review"),
)


def analyze_secrets(text: str, source: str = "source") -> list[Lead]:
    leads: list[Lead] = []
    for name, pattern, severity in _PATTERNS:
        matches = list(pattern.finditer(text))
        if matches:
            leads.append(Lead(source, "secret-review", severity, f"Potential {name} material detected in local content.", f"{len(matches)} match(es); matched values redacted", "Treat matches as potential secrets until verified. Rotate confirmed exposed credentials and avoid placing secret values in reports."))
    return leads
