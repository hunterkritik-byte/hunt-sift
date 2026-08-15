"""Local command-line presentation helpers."""

from __future__ import annotations

import json

from .models import Lead


def render_leads(leads: list[Lead], as_json: bool) -> str:
    """Render local leads as readable console text or structured JSON."""
    if as_json:
        return json.dumps([lead.to_dict() for lead in leads], indent=2)
    if not leads:
        return "No review leads were generated from this local artifact. This is not a security conclusion."
    rows: list[str] = []
    for number, lead in enumerate(leads, start=1):
        rows.extend(
            (
                f"[{number}] {lead.severity.upper()} / {lead.category}",
                f"  {lead.message}",
                f"  evidence: {lead.evidence}",
                f"  next step: {lead.guidance}",
                "",
            )
        )
    return "\n".join(rows).rstrip()
