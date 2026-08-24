from pathlib import Path

import pytest

from hunt_sift.cli import deduplicate, load_leads
from hunt_sift.core.io import iter_local_text_files, read_text
from hunt_sift.core.models import Lead


def make_lead(message="same"):
    return Lead("test", "review", "review", message, "evidence", "guidance")


def test_deduplicate_preserves_first_seen_order():
    leads = [make_lead("a"), make_lead("a"), make_lead("b")]
    assert [lead.message for lead in deduplicate(leads)] == ["a", "b"]


def test_read_text_rejects_symlink(tmp_path: Path):
    target = tmp_path / "target.txt"
    target.write_text("secret", encoding="utf-8")
    link = tmp_path / "link.txt"
    try:
        link.symlink_to(target)
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation is unavailable on this platform")
    with pytest.raises(ValueError, match="symbolic link"):
        read_text(link)


def test_directory_walk_skips_symlink(tmp_path: Path):
    outside = tmp_path / "outside"
    outside.mkdir()
    secret = outside / "secret.txt"
    secret.write_text("secret", encoding="utf-8")
    case = tmp_path / "case"
    case.mkdir()
    link = case / "linked"
    try:
        link.symlink_to(outside, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation is unavailable on this platform")
    assert list(iter_local_text_files(case)) == []


def test_load_leads_rejects_oversized_field(tmp_path: Path):
    payload = [{
        "source": "test", "category": "review", "severity": "low",
        "message": "x" * 20_001, "evidence": "e", "guidance": "g"
    }]
    path = tmp_path / "findings.json"
    import json
    path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError, match="exceeds"):
        load_leads(path)


def test_load_leads_rejects_too_many_findings(tmp_path: Path):
    row = {
        "source": "test", "category": "review", "severity": "low",
        "message": "m", "evidence": "e", "guidance": "g"
    }
    import json
    path = tmp_path / "findings.json"
    path.write_text(json.dumps([row] * 10_001), encoding="utf-8")
    with pytest.raises(ValueError, match="limit"):
        load_leads(path)
