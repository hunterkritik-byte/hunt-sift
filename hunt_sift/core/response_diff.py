"""Offline comparison of two saved HTTP responses.

The diff is designed for authorized A/B testing from artifacts already on disk.
It never sends requests and never generates exploit payloads.
"""
from __future__ import annotations

import re
from .models import Lead

_SECRET_HEADER = re.compile(r"^(authorization|cookie|set-cookie|x-api-key)$", re.I)
_SENSITIVE = re.compile(r"(token|secret|password|email|phone|ssn|credit.?card|api.?key)", re.I)


def _parse(text: str) -> tuple[str, dict[str, list[str]], str]:
    normalized = text.replace("\r\n", "\n")
    head, _, body = normalized.partition("\n\n")
    lines = head.splitlines()
    status = lines[0].strip() if lines else ""
    headers: dict[str, list[str]] = {}
    for line in lines[1:]:
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        headers.setdefault(key.strip().lower(), []).append(value.strip())
    return status, headers, body


def compare_responses(before: str, after: str) -> list[Lead]:
    status_a, headers_a, body_a = _parse(before)
    status_b, headers_b, body_b = _parse(after)
    leads: list[Lead] = []
    if status_a != status_b:
        leads.append(Lead("response-diff", "status-change", "review", "The saved responses have different status lines.", "status values redacted", "Determine whether the difference represents an authorization, validation, or error-handling boundary."))
    for name in sorted(set(headers_a) | set(headers_b)):
        if _SECRET_HEADER.search(name):
            continue
        if headers_a.get(name) != headers_b.get(name):
            leads.append(Lead("response-diff", "header-change", "review", f"Header behavior changed for {name}.", f"{name}: <values redacted>", "Review whether the change affects authentication, caching, CORS, content handling, or security policy."))
    if body_a != body_b:
        sensitive_delta = bool(_SENSITIVE.search(body_a) != _SENSITIVE.search(body_b))
        category = "sensitive-body-delta" if sensitive_delta else "body-delta"
        leads.append(Lead("response-diff", category, "review", "The saved response bodies differ.", f"body lengths: {len(body_a)} -> {len(body_b)} bytes", "Compare only authorized test identities and redact account or secret data before sharing evidence."))
    return leads
