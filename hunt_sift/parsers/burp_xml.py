"""Parser for local Burp Suite XML exports. No Burp integration or traffic replay occurs."""

from __future__ import annotations

import base64
import xml.etree.ElementTree as ET
from pathlib import Path

from ..core.http_review import label_url, parse_raw_http_headers, review_headers
from ..core.io import read_text
from ..core.models import Lead


def response_text(element: ET.Element | None) -> str:
    """Decode a Burp response element in memory, with no content execution."""
    if element is None:
        return ""
    raw = "".join(element.itertext())
    if element.get("base64", "false").lower() == "true":
        try:
            return base64.b64decode("".join(raw.split()), validate=True).decode("utf-8", errors="replace")
        except (ValueError, UnicodeDecodeError) as exc:
            raise ValueError("Invalid base64 response in Burp XML export.") from exc
    return raw


def analyze(path: Path) -> list[Lead]:
    """Create cautious response-header review leads from an imported Burp XML file."""
    try:
        root = ET.fromstring(read_text(path))
    except ET.ParseError as exc:
        raise ValueError(f"Invalid Burp Suite XML: {exc}") from exc

    leads: list[Lead] = []
    for item in root.findall(".//item"):
        url = label_url((item.findtext("url") or "burp-item").strip())
        raw_response = response_text(item.find("response"))
        if raw_response:
            status, headers = parse_raw_http_headers(raw_response)
        else:
            status = f"HTTP {item.findtext('status') or 'response unavailable'}"
            headers = {}
        leads.extend(review_headers("burp-xml", url, status, headers))
    return leads
