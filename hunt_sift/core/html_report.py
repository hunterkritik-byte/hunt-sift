"""Generate a self-contained HTML report from local review leads."""
from __future__ import annotations
import html
from pathlib import Path
from .models import Lead
from .risk_engine import prioritize, triage_summary


def write_html(path: str | Path, leads: list[Lead]) -> None:
    rows = prioritize(leads)
    summary = triage_summary(leads)
    cards = "".join(
        f"<tr><td>{r['priority']}</td><td>{html.escape(r['lead']['severity'])}</td>"
        f"<td>{html.escape(r['lead']['category'])}</td><td>{html.escape(r['lead']['message'])}</td>"
        f"<td><code>{html.escape(r['lead']['evidence'])}</code></td></tr>"
        for r in rows
    )
    document = f'''<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Hunt Sift Offline Report</title><style>
body{{font-family:system-ui,sans-serif;margin:2rem;background:#07111f;color:#e5eef8}}main{{max-width:1200px;margin:auto}}
.card{{display:inline-block;padding:1rem;margin:.3rem;border:1px solid #24415e;border-radius:10px;background:#0c1b2d}}
table{{width:100%;border-collapse:collapse;background:#0c1b2d}}th,td{{padding:.7rem;border-bottom:1px solid #24415e;text-align:left;vertical-align:top}}th{{color:#67e8f9}}code{{white-space:pre-wrap;overflow-wrap:anywhere}}
.note{{color:#9fb3c8}}.badge{{font-weight:700;color:#67e8f9}}
</style></head><body><main><h1>Hunt Sift — Offline Review</h1>
<p class="note">Generated locally. Findings are review leads, not vulnerability assertions. No network activity is performed.</p>
<div class="card"><span class="badge">TOTAL</span><br>{summary['total']}</div>
<div class="card"><span class="badge">MAX PRIORITY</span><br>{summary['max_priority']}</div>
<div class="card"><span class="badge">BANDS</span><br>{html.escape(str(summary['priority_bands']))}</div>
<table><thead><tr><th>Priority</th><th>Severity</th><th>Category</th><th>Finding</th><th>Evidence</th></tr></thead><tbody>{cards}</tbody></table>
</main></body></html>'''
    Path(path).write_text(document, encoding="utf-8")
