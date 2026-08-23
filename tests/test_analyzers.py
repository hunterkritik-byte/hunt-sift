"""Tests that keep Hunt Sift local-only and interpret artifacts as review leads."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from hunt_sift.analyzers import analyze_burp_xml, analyze_har, analyze_http_export, analyze_nmap_xml, analyze_s3_policy, analyze_static_path


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

    def test_burp_xml_import_redacts_url_query_and_reviews_response(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            export = Path(tempdir) / "burp.xml"
            export.write_text(
                """<items><item><url>https://app.example.test/account?private=redacted</url><response><![CDATA[HTTP/1.1 200 OK\nServer: Demo\nAccess-Control-Allow-Origin: *\n\nbody]]></response></item></items>""",
                encoding="utf-8",
            )
            leads = analyze_burp_xml(export)
            self.assertTrue(any(lead.source == "burp-xml" for lead in leads))
            self.assertIn("cors-policy-review", {lead.category for lead in leads})
            self.assertTrue(all("private=redacted" not in lead.evidence for lead in leads))

    def test_har_import_reviews_saved_headers_without_a_request(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            export = Path(tempdir) / "capture.har"
            export.write_text(
                """{"log":{"entries":[{"request":{"url":"https://api.example.test/v1/profile?account=masked"},"response":{"status":500,"headers":[{"name":"Server","value":"Demo"},{"name":"Set-Cookie","value":"session=demo"},{"name":"Access-Control-Allow-Origin","value":"*"},{"name":"Access-Control-Allow-Credentials","value":"true"}]}}]}}""",
                encoding="utf-8",
            )
            leads = analyze_har(export)
            categories = {lead.category for lead in leads}
            self.assertIn("server-error-review", categories)
            self.assertIn("cookie-attribute-review", categories)
            self.assertIn("cors-credentials-policy-review", categories)
            self.assertTrue(all("account=masked" not in lead.evidence for lead in leads))

    def test_conflicting_security_headers_are_reviewed_and_redacted(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            response = Path(tempdir) / "response.txt"
            response.write_text(
                "HTTP/1.1 200 OK\nContent-Security-Policy: default-src 'self'\nContent-Security-Policy: default-src *\n\nbody",
                encoding="utf-8",
            )
            leads = analyze_http_export(response, "https://app.example.test")
            matches = [lead for lead in leads if lead.category == "conflicting-security-header-review"]
            self.assertEqual(len(matches), 1)
            self.assertIn("content-security-policy", matches[0].message)
            self.assertNotIn("default-src", matches[0].evidence)
            self.assertIn("2 distinct values redacted", matches[0].evidence)

    def test_static_review_never_executes_source(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            source = Path(tempdir) / "app.js"
            source.write_text("const template = location.hash; target.innerHTML = template; // TODO review\n", encoding="utf-8")
            leads = analyze_static_path(source)
            categories = {lead.category for lead in leads}
            self.assertIn("dom-sink-review", categories)
            self.assertIn("implementation-note", categories)

    def test_static_cors_and_potential_credential_rules_redact_the_value(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            source = Path(tempdir) / "config.js"
            possible_key = "AIzaSyDUMMYKEYWITHMORETHAN20CHARS"
            source.write_text(
                f"const headers = {{ 'Access-Control-Allow-Origin': '*' }}; const api_key = '{possible_key}';\n",
                encoding="utf-8",
            )
            leads = analyze_static_path(source)
            categories = {lead.category for lead in leads}
            self.assertIn("cors-policy-review", categories)
            credential = next(lead for lead in leads if lead.category == "potential-credential-exposure")
            self.assertNotIn(possible_key, credential.evidence)
            self.assertIn("AIza…", credential.evidence)

    def test_static_jwt_rules_are_review_leads_only(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            source = Path(tempdir) / "auth.js"
            source.write_text(
                "const parsed = jwt.decode(token); const settings = { ignoreExpiration: true }; const jwt_secret = 'local-signed-value-only';\n",
                encoding="utf-8",
            )
            leads = analyze_static_path(source)
            categories = {lead.category for lead in leads}
            self.assertIn("jwt-validation-review", categories)
            self.assertIn("jwt-claim-validation-review", categories)
            credential = next(lead for lead in leads if lead.category == "potential-credential-exposure")
            self.assertNotIn("local-signed-value-only", credential.evidence)
            self.assertTrue(all("local-signed-value-only" not in lead.evidence for lead in leads))

    def test_s3_policy_review_never_contacts_cloud(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            policy = Path(tempdir) / "policy.json"
            policy.write_text(
                """{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":["s3:GetObject","s3:PutObject"],"Resource":"arn:aws:s3:::example-bucket/*"}]}""",
                encoding="utf-8",
            )
            leads = analyze_s3_policy(policy)
            categories = {lead.category for lead in leads}
            self.assertIn("s3-public-read-policy-review", categories)
            self.assertIn("s3-public-write-policy-review", categories)


if __name__ == "__main__":
    unittest.main()
