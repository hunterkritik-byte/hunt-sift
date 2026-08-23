"""Offline report helpers for Hunt Sift review leads.

The module deliberately operates on already-produced Lead objects. It does not
perform network access, execute source, or infer exploitability.
"""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import asdict
from pathlib import Path
from typing import Iterable

from .models import Lead


def summarize(leads: Iterable[Lead]) -> dict[str, object]:
    rows = list(leads)
    return {
        "total": len(rows),
        "by_severity": dict(Counter(row.severity for row in rows)),
        "by_category": dict(Counter(row.category for row in rows)),
        "sources": sorted({row.source for row in rows}),
    }


def deduplicate(leads: Iterable[Lead]) -> list[Lead]:
    """Remove exact duplicate leads while preserving first-seen order."""
    seen: set[tuple[str, str, str, str]] = set()
    result: list[Lead] = []
    for lead in leads:
        key = (lead.source, lead.category, lead.severity, lead.message)
        if key not in seen:
            seen.add(key)
            result.append(lead)
    return result


def write_json(path: str | Path, leads: Iterable[Lead]) -> None:
    rows = deduplicate(leads)
    payload = {"summary": summarize(rows), "findings": [asdict(row) for row in rows]}
    Path(path).write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


def to_sarif(leads: Iterable[Lead]) -> dict[str, object]:
    """Return a conservative SARIF 2.1.0 document for local review leads."""
    rows = deduplicate(leads)
    results = []
    rules: dict[str, dict[str, object]] = {}
    for lead in rows:
        rule_id = f"hunt-sift/{lead.category}"
        rules.setdefault(
            rule_id,
            {
                "id": rule_id,
                "name": lead.category,
                "shortDescription": {"text": lead.message[:160]},
                "help": {"text": lead.guidance},
            },
        )
        results.append(
            {
                "ruleId": rule_id,
                "level": "warning" if lead.severity == "review" else "note",
                "message": {"text": lead.message},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": lead.source}}}],
                "properties": {"evidence": lead.evidence, "offline_review_lead": True},
            }
        )
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "Hunt Sift", "rules": list(rules.values())}}, "results": results}],
    }


def write_sarif(path: str | Path, leads: Iterable[Lead]) -> None:
    Path(path).write_text(json.dumps(to_sarif(leads), indent=2), encoding="utf-8")
