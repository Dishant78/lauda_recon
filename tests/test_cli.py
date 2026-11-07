from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from lauda_recon.cli import main


class CliTests(unittest.TestCase):
    def test_dry_run_writes_both_safe_report_formats(self) -> None:
        # Some sandboxed Windows runners expose a read-only system temp
        # directory, while the project working directory remains writable.
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temporary:
            directory = Path(temporary)
            text_path = directory / "report.txt"
            json_path = directory / "report.json"
            exit_code = main(
                [
                    "-d",
                    "example.com",
                    "--authorized",
                    "--dry-run",
                    "--no-colour",
                    "-o",
                    str(text_path),
                    "-oJ",
                    str(json_path),
                ]
            )
            self.assertEqual(exit_code, 0)
            self.assertIn("LAUDA RECON REPORT", text_path.read_text(encoding="utf-8"))
            payload = json.loads(json_path.read_text(encoding="utf-8"))
            self.assertEqual(payload["domain"], "example.com")
            self.assertTrue(any("Dry run" in note for note in payload["notes"]))

    def test_authorization_acknowledgement_is_required_for_a_scan(self) -> None:
        with self.assertRaises(SystemExit) as caught:
            main(["-d", "example.com", "--dry-run", "--no-colour"])
        self.assertEqual(caught.exception.code, 2)

    def test_config_values_are_preserved_when_the_cli_flag_is_omitted(self) -> None:
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temporary:
            directory = Path(temporary)
            config_path = directory / "config.json"
            report_path = directory / "report.json"
            config_path.write_text('{"active": true, "enabled_tools": []}', encoding="utf-8")
            exit_code = main(
                [
                    "-d", "example.com", "--authorized", "--config", str(config_path),
                    "--dry-run", "--no-colour", "-oJ", str(report_path),
                ]
            )
            self.assertEqual(exit_code, 0)
            payload = json.loads(report_path.read_text(encoding="utf-8"))
            self.assertIn("Active verification would be enabled.", payload["notes"])


if __name__ == "__main__":
    unittest.main()
