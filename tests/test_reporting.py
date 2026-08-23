import json

from hunt_sift.core.models import Lead
from hunt_sift.core.reporting import deduplicate, summarize, to_sarif


def sample_leads():
    return [
        Lead("a.txt", "idor-review", "review", "Object identifier needs review", "id=<redacted>", "Confirm authorization."),
        Lead("a.txt", "idor-review", "review", "Object identifier needs review", "id=<redacted>", "Confirm authorization."),
        Lead("b.js", "secret-review", "informational", "Secret-shaped value", "value=<redacted>", "Rotate if real."),
    ]


def test_deduplicate_preserves_first_seen_order():
    rows = deduplicate(sample_leads())
    assert [row.source for row in rows] == ["a.txt", "b.js"]


def test_summary_counts_categories_and_sources():
    summary = summarize(sample_leads())
    assert summary["total"] == 3
    assert summary["by_category"]["idor-review"] == 2
    assert summary["sources"] == ["a.txt", "b.js"]


def test_sarif_is_machine_readable_and_marks_review_leads():
    document = to_sarif(sample_leads())
    assert document["version"] == "2.1.0"
    results = document["runs"][0]["results"]
    assert len(results) == 2
    assert results[0]["properties"]["offline_review_lead"] is True
    json.dumps(document)
