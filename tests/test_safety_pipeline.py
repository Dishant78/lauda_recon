from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from lauda_recon.config import ConfigError, ScanConfig, load_config, merge
from lauda_recon.mutations import generate_mutations
from lauda_recon.orchestrator import _tool_failure_note
from lauda_recon.parsing import parse_trufflehog_jsonl
from lauda_recon.scope import Scope
from lauda_recon.verify import validate_exposure_structure, verify_takeover_signature


class SafetyPipelineTests(unittest.TestCase):
    def test_scope_exclusion_overrides_root_suffix(self) -> None:
        scope = Scope.build("example.com", exclusions=("auth.example.com", "*.private.example.com"))
        self.assertTrue(scope.allows("api.example.com"))
        self.assertFalse(scope.allows("auth.example.com"))
        self.assertFalse(scope.allows("db.private.example.com"))

    def test_mutations_stay_in_scope_and_are_bounded(self) -> None:
        scope = Scope.build("example.com")
        mutations = generate_mutations(["api.example.com", "outside.invalid"], scope, maximum=20)
        self.assertLessEqual(len(mutations), 20)
        self.assertTrue(mutations)
        self.assertTrue(all(scope.allows(host) for host in mutations))
        self.assertNotIn("outside.invalid", mutations)

    def test_configuration_refuses_secret_validation_and_unknown_tools(self) -> None:
        with self.assertRaises(ConfigError):
            ScanConfig(domain="example.com", authorized=True, enabled_tools=("unknown",)).validate()
        with self.assertRaises(ConfigError):
            ScanConfig(domain="example.com", authorized=True, github_repositories=("https://token@github.com/acme/repo.git",)).validate()
        config = merge(ScanConfig(), domain="example.com", authorized=True, github_repositories=("https://github.com/acme/repo.git",))
        self.assertEqual(config.validate().github_repositories, ("https://github.com/acme/repo.git",))

    def test_json_configuration_drives_ports_tools_and_exclusions(self) -> None:
        raw = {
            "network": {"ports": [443, 8443], "rate_limit_per_second": 2},
            "scope": {"exclude": ["auth.example.com"]},
            "tools": {"subfinder": {"enabled": True}, "httpx": {"enabled": True}},
            "finding_policy": {"verify_secret_credentials": False},
        }
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temporary:
            path = Path(temporary) / "config.json"
            path.write_text(json.dumps(raw), encoding="utf-8")
            config = merge(load_config(path), domain="example.com", authorized=True).validate()
        self.assertEqual(config.ports, (443, 8443))
        self.assertEqual(config.rate_limit_per_second, 2)
        self.assertEqual(config.enabled_tools, ("subfinder", "httpx"))
        self.assertEqual(config.exclude_scope, ("auth.example.com",))

    def test_trufflehog_parser_never_returns_raw_value_or_source_metadata(self) -> None:
        raw_secret = "ghp_abcdefghijklmnopqrstuvwxyz123456"
        record = {
            "DetectorName": "GitHub",
            "Raw": raw_secret,
            "SourceMetadata": {"snippet": "token=" + raw_secret},
        }
        result = list(parse_trufflehog_jsonl([json.dumps(record)]))[0]
        self.assertNotIn(raw_secret, json.dumps(result))
        self.assertTrue(result["source"].startswith("source-sha256:"))

    def test_structural_file_and_takeover_checks_need_multiple_signals(self) -> None:
        response = {
            "url": "https://api.example.com/.env",
            "status_code": 200,
            "structural_markers": ["db_host=", "app_key="],
        }
        exposure = validate_exposure_structure(response["url"], response)
        self.assertIsNotNone(exposure)
        takeover = verify_takeover_signature(
            "gone.example.com",
            ["project.s3.amazonaws.com"],
            {"provider_signatures": ["s3_missing_bucket"]},
        )
        self.assertIsNotNone(takeover)
        self.assertEqual(takeover["confidence"], "needs_manual_review")

    def test_tool_diagnostics_are_not_copied_into_reports(self) -> None:
        secret_like_diagnostic = "token=should-never-enter-a-report"
        note = _tool_failure_note("subfinder", {"return_code": 1, "stderr": secret_like_diagnostic})
        self.assertNotIn(secret_like_diagnostic, note)
        self.assertIn("diagnostic output suppressed", note)


if __name__ == "__main__":
    unittest.main()
