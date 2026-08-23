"""Explainable prioritization for offline review leads."""
from __future__ import annotations
from collections import Counter
from .models import Lead

_SEVERITY = {"review": 3, "high": 4, "medium": 3, "low": 1, "informational": 0, "info": 0}


def score_lead(lead: Lead) -> int:
    """Return triage metadata; never infer exploitability."""
    score = _SEVERITY.get(lead.severity.casefold(), 1)
    text = f"{lead.category} {lead.message}".casefold()
    if any(x in text for x in ("credential", "cookie", "secret", "authorization")):
        score += 2
    if any(x in text for x in ("injection", "idor", "bola", "disclosure", "conflict")):
        score += 1
    return min(score, 10)


def prioritize(leads: list[Lead]) -> list[dict[str, object]]:
    rows = [{"lead": lead.to_dict(), "priority": score_lead(lead)} for lead in leads]
    return sorted(rows, key=lambda row: int(row["priority"]), reverse=True)


def triage_summary(leads: list[Lead]) -> dict[str, object]:
    rows = prioritize(leads)
    bands = Counter("high" if r["priority"] >= 7 else "medium" if r["priority"] >= 4 else "low" for r in rows)
    return {"total": len(rows), "priority_bands": dict(bands), "max_priority": max((int(r["priority"]) for r in rows), default=0)}
