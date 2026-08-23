import json
import tempfile
import unittest
from pathlib import Path

from hunt_sift.core.workspace import index_directory, search_records, write_index


class WorkspaceTests(unittest.TestCase):
    def test_index_skips_generated_directories_and_hashes_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "response.har").write_text("demo", encoding="utf-8")
            (root / ".git").mkdir()
            (root / ".git" / "ignored.txt").write_text("ignored", encoding="utf-8")
            records = index_directory(root)
            self.assertEqual([record.path for record in records], ["response.har"])
            self.assertEqual(records[0].kind, "har")
            self.assertEqual(len(records[0].sha256), 64)

    def test_search_matches_path_and_kind(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "capture.har").write_text("demo", encoding="utf-8")
            (root / "notes.txt").write_text("demo", encoding="utf-8")
            records = index_directory(root)
            self.assertEqual(len(search_records(records, "har")), 1)
            self.assertEqual(len(search_records(records, "notes")), 1)

    def test_index_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "capture.json").write_text("{}", encoding="utf-8")
            records = index_directory(root)
            output = root / "inventory.json"
            write_index(records, output)
            data = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(data[0]["kind"], "json")


if __name__ == "__main__":
    unittest.main()
