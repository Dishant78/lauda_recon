from __future__ import annotations

import sys
import unittest

from lauda_recon.content import context_paths
from lauda_recon.tools import BinaryRunner, ToolInvocation


class ToolsAndContentTests(unittest.TestCase):
    def test_binary_runner_executes_argv_without_a_shell(self) -> None:
        runner = BinaryRunner()
        invocation = ToolInvocation("python-smoke", (sys.executable, "-c", "print('adapter-ok')"), 10)
        result = runner.run(invocation)
        self.assertTrue(result["succeeded"])
        self.assertEqual(result["stdout"].strip(), "adapter-ok")

    def test_context_paths_do_not_mix_php_paths_into_django_profile(self) -> None:
        django_paths = context_paths(["common", "django"])
        php_paths = context_paths(["common", "php"])
        self.assertNotIn("/wp-config.php", django_paths)
        self.assertIn("/wp-config.php", php_paths)
        self.assertIn("/.env", django_paths)


if __name__ == "__main__":
    unittest.main()
