"""Helpers that prevent full potential credential values appearing in Hunt Sift output."""

from __future__ import annotations


def redact(value: str, visible: int = 4) -> str:
    """Return a short recognisable prefix/suffix while withholding the complete value."""
    cleaned = value.strip()
    if len(cleaned) <= visible * 2:
        return "<redacted>"
    return f"{cleaned[:visible]}…{cleaned[-visible:]}"


def appears_placeholder(value: str) -> bool:
    """Avoid review leads for common obvious placeholder values."""
    lowered = value.lower()
    return any(marker in lowered for marker in ("example", "placeholder", "changeme", "your_", "your-", "demo", "replace_me"))
