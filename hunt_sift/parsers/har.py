"""Parser for local HTTP Archive (HAR) files. Imported entries are not replayed."""

from __future__ import annotations

import json
from pathlib import Path

from ..core.http_review import label_url, review_headers
from ..core.io import read_text
from ..core.models import Lead


def response_headers(entry: dict[str, object]) -> dict[str, list[str]]:
    """Convert HAR response header objects to a local name/value mapping."""
    response = entry.get("response", {})
    if not isinstance(response, dict):
        return {}
    headers = response.get("headers", [])
    result: dict[str, list[str]] = {}
    if not isinstance(headers, list):
        return result
    for header in headers:
        if not isinstance(header, dict) or "name" not in header:
            continue
        result.setdefault(str(header["name"]), []).append(str(header.get("value", "")))
    return result


def analyze(path: Path) -> list[Lead]:
    """Review saved HAR response headers without sending requests or contacting referenced URLs."""
    try:
        payload = json.loads(read_text(path))
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid HAR JSON: {exc}") from exc
    if not isinstance(payload, dict) or not isinstance(payload.get("log"), dict):
        raise ValueError("Invalid HAR: expected a top-level log object.")
    entries = payload["log"].get("entries", [])
    if not isinstance(entries, list):
        raise ValueError("Invalid HAR: expected log.entries to be a list.")

    leads: list[Lead] = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        request = entry.get("request", {})
        response = entry.get("response", {})
        url = label_url(str(request.get("url", "har-entry"))) if isinstance(request, dict) else "har-entry"
        status_value = response.get("status", "response unavailable") if isinstance(response, dict) else "response unavailable"
        leads.extend(review_headers("har", url, f"HTTP {status_value}", response_headers(entry)))
    return leads
