"""Compatibility facade for Hunt Sift's modular offline analyzers."""

from __future__ import annotations

from pathlib import Path

from .core.http_review import parse_raw_http_headers
from .core.models import Lead
from .parsers import burp_xml, har, http_export, nmap_xml, s3_policy, static_files


def analyze_nmap_xml(path: Path) -> list[Lead]:
    return nmap_xml.analyze(path)


def analyze_http_export(path: Path, url: str | None = None) -> list[Lead]:
    return http_export.analyze(path, url)


def analyze_burp_xml(path: Path) -> list[Lead]:
    return burp_xml.analyze(path)


def analyze_har(path: Path) -> list[Lead]:
    return har.analyze(path)


def analyze_static_path(path: Path) -> list[Lead]:
    return static_files.analyze(path)


def analyze_s3_policy(path: Path) -> list[Lead]:
    return s3_policy.analyze(path)


def parse_http_headers(text: str) -> tuple[str, dict[str, list[str]]]:
    """Backward-compatible alias for parsing a saved raw HTTP response."""
    return parse_raw_http_headers(text)
