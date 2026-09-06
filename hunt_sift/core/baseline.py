"""Create a deterministic, local-only baseline for finding counts.

The baseline is intentionally metadata-only: it stores category/severity counts,
not evidence, URLs, credentials, or raw artifacts.
"""
from __future__ import annotations

from collections import Counter
from typing import Iterable


def baseline(leads: Iterable[object]) -> dict[str, object]:
    categories: Counter[str] = Counter()
    severities: Counter[str] = Counter()
    for lead in leads:
        category = str(getattr(lead, "category", "unknown"))
        severity = str(getattr(lead, "severity", "unknown"))
        categories[category] += 1
        severities[severity] += 1
    return {
        "finding_count": sum(categories.values()),
        "categories": dict(sorted(categories.items())),
        "severities": dict(sorted(severities.items())),
    }
