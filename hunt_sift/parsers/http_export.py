"""Parser for a saved raw HTTP response file."""

from __future__ import annotations

from pathlib import Path

from ..core.http_review import label_url, parse_raw_http_headers, review_headers
from ..core.io import read_text
from ..core.models import Lead


def analyze(path: Path, url: str | None = None) -> list[Lead]:
    """Review a saved response file without connecting to the original URL."""
    status, headers = parse_raw_http_headers(read_text(path))
    return review_headers("http-export", label_url(url) if url else path.name, status, headers)
