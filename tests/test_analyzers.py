"""Tests that keep Hunt Sift local-only and interpret artifacts as review leads."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from hunt_sift.analyzers import analyze_http_export, analyze_nmap_xml, analyze_static_path


class AnalyzerTests(unittest.TestCase):
    def test_imported_nmap_xml_produces_review_leads(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            sample = Path(tempdir) / "scan.xml"
            sample.write_text(
                """<?xml version='1.0'?><nmaprun><host><address addr='192.0.2.10'/><ports><port protocol='tcp' portid='23'><state state='open'/><service name='telnet' product='Demo' version='1.0'/></port></ports></host></nmaprun>""",
                encoding="utf-8",
            )
            leads = analyze_nmap_xml(sample)
            self.assertTrue(any(lead.category == "legacy-service-review" for lead in leads))
            self.assertTrue(all(lead.source == "nmap-xml" for lead in leads))

    def test_saved_http_export_is_not_replayed(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            response = Path(tempdir) / "response.txt"
            response.write_text("HTTP/1.1 200 OK\nServer: Demo\nAccess-Control-Allow-Origin: *\nSet-Cookie: session=demo\n\nbody", encoding="utf-8")
            leads = analyze_http_export(response, "https://app.example.test")
            categories = {lead.category for lead in leads}
            self.assertIn("cors-policy-review", categories)
            self.assertIn("cookie-attribute-review", categories)

    def test_static_review_never_executes_source(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            source = Path(tempdir) / "app.js"
            source.write_text("const template = location.hash; target.innerHTML = template; // TODO review\n", encoding="utf-8")
            leads = analyze_static_path(source)
            categories = {lead.category for lead in leads}
            self.assertIn("dom-sink-review", categories)
            self.assertIn("implementation-note", categories)


if __name__ == "__main__":
    unittest.main()
