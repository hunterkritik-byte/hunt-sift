import tempfile
from pathlib import Path
from hunt_sift.core.html_report import write_html
from hunt_sift.core.models import Lead
from hunt_sift.core.risk_engine import prioritize, score_lead, triage_summary


def lead(message="Authorization cookie disclosure review", severity="review"):
    return Lead("test", "cookie-review", severity, message, "<redacted>", "review locally")


def test_priority_is_deterministic_and_bounded():
    value = score_lead(lead())
    assert value == score_lead(lead())
    assert 0 <= value <= 10


def test_prioritize_orders_highest_first():
    rows = prioritize([lead("ordinary metadata", "low"), lead()])
    assert rows[0]["priority"] >= rows[1]["priority"]


def test_summary_reports_bands():
    summary = triage_summary([lead(), lead("ordinary metadata", "low")])
    assert summary["total"] == 2
    assert summary["max_priority"] > 0


def test_html_report_escapes_evidence():
    item = Lead("test", "review", "review", "<tag>", "secret & value", "guidance")
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "report.html"
        write_html(path, [item])
        content = path.read_text(encoding="utf-8")
        assert "&lt;tag&gt;" in content
        assert "secret &amp; value" in content
