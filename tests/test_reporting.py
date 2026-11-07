from __future__ import annotations

import json
import unittest

from lauda_recon.models import Confidence, Evidence, Finding, RunReport, Severity
from lauda_recon.reporting import redact, report_to_json, report_to_text


class ReportingTests(unittest.TestCase):
    def test_redacts_sensitive_fields_and_known_token_patterns(self) -> None:
        result = redact(
            {
                "api_key": "should-not-appear",
                "note": "Found AKIA1234567890ABCDEF in a public file",
                "nested": {"password": "still-not-visible"},
            }
        )
        self.assertEqual(result["api_key"], "[REDACTED]")
        self.assertEqual(result["nested"]["password"], "[REDACTED]")
        self.assertNotIn("AKIA1234567890ABCDEF", result["note"])

    def test_text_and_json_reports_retain_safe_evidence(self) -> None:
        report = RunReport(domain="example.com")
        report.add_finding(
            Finding(
                category="Live hosts",
                title="Active web service",
                asset="https://api.example.com",
                severity=Severity.LOW,
                confidence=Confidence.VERIFIED,
                verification="HTTP 200; title API",
                evidence=[Evidence(source="httpx", detail="token=will-be-redacted")],
            )
        )
        payload = json.loads(report_to_json(report))
        self.assertEqual(payload["findings"][0]["evidence"][0]["detail"], "[REDACTED]")
        self.assertEqual(payload["summary"]["findings"], 1)
        self.assertIn("https://api.example.com", report_to_text(report))
        self.assertIn("Summary: 0 asset(s), 0 live service(s), 1 finding(s).", report_to_text(report))
        self.assertNotIn("will-be-redacted", report_to_text(report))


if __name__ == "__main__":
    unittest.main()
