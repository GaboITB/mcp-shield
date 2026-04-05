"""Integration tests for the AuditEngine.

Tests the full scan pipeline on a synthetic mini-project fixture
to verify that detectors, dedup, cap, and scoring work end-to-end.

Note: fixture files contain intentionally vulnerable code patterns
(shell injection, dynamic code execution, hardcoded secrets) that
the detectors are expected to flag. These are TEST FIXTURES, not
production code.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from mcp_shield.core.engine import AuditEngine
from mcp_shield.core.models import Grade, Severity
from mcp_shield.core.registry import create_default_registry


# Fixture content strings — intentionally vulnerable for detection testing
_FIXTURE_SERVER_PY = (
    "import subprocess\n"
    "def run_cmd(user_input):\n"
    '    subprocess.run(f"echo {user_input}", shell=True)\n'
)

_FIXTURE_HANDLER_JS = (
    "const data = getUserInput();\n"
    "eval(data);  // intentionally vulnerable for testing\n"
)

_FIXTURE_CONFIG_PY = 'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n'

_FIXTURE_PACKAGE_JSON = (
    '{"name": "test-mcp", "version": "1.0.0", '
    '"scripts": {"postinstall": "node setup.js"}, '
    '"dependencies": {"@modelcontextprotocol/sdk": "0.5.0"}}'
)


def _create_fixture(tmp: Path) -> Path:
    """Create a minimal MCP project with known vulnerabilities."""
    project = tmp / "test-mcp"
    project.mkdir(parents=True)

    (project / "package.json").write_text(_FIXTURE_PACKAGE_JSON, encoding="utf-8")
    (project / "server.py").write_text(_FIXTURE_SERVER_PY, encoding="utf-8")
    (project / "handler.js").write_text(_FIXTURE_HANDLER_JS, encoding="utf-8")
    (project / "config.py").write_text(_FIXTURE_CONFIG_PY, encoding="utf-8")

    return project


class TestEngineIntegration(unittest.TestCase):
    """End-to-end integration tests for the scan pipeline."""

    def setUp(self):
        self._tmp = tempfile.mkdtemp(prefix="mcp_shield_test_")
        self._fixture = _create_fixture(Path(self._tmp))

    def tearDown(self):
        import shutil

        shutil.rmtree(self._tmp, ignore_errors=True)

    def _run_scan(self, name="test-mcp"):
        registry = create_default_registry()
        engine = AuditEngine(registry)
        return engine.run(source=str(self._fixture), name=name)

    def test_scan_finds_shell_injection(self):
        """Engine should detect shell=True with dynamic input."""
        result = self._run_scan()
        rule_ids = {f.rule_id for f in result.findings}
        self.assertIn("shell_injection", rule_ids)

    def test_scan_finds_eval(self):
        """Engine should detect code execution (static or dynamic)."""
        result = self._run_scan()
        rule_ids = {f.rule_id for f in result.findings}
        self.assertTrue(
            rule_ids & {"eval_exec_dynamic", "eval_exec_static"},
            f"Expected eval finding, got: {rule_ids}",
        )

    def test_scan_finds_phantom_dep(self):
        """Engine should detect phantom dependency."""
        result = self._run_scan()
        rule_ids = {f.rule_id for f in result.findings}
        self.assertIn("phantom_dependency", rule_ids)

    def test_scan_finds_postinstall(self):
        """Engine should flag postinstall script."""
        result = self._run_scan()
        rule_ids = {f.rule_id for f in result.findings}
        self.assertIn("postinstall_script", rule_ids)

    def test_grade_reflects_findings(self):
        """Grade should be C or worse with these vulnerabilities."""
        result = self._run_scan()
        self.assertGreater(result.total_score, 60)
        self.assertIn(result.grade, (Grade.C, Grade.D, Grade.F))

    def test_findings_are_capped(self):
        """No rule_id should have more than 5 findings."""
        result = self._run_scan()
        from collections import Counter

        counts = Counter(f.rule_id for f in result.findings)
        for rule_id, count in counts.items():
            self.assertLessEqual(count, 5, f"{rule_id} has {count} findings (max 5)")

    def test_result_has_health_info(self):
        """Result should include repo health data."""
        result = self._run_scan()
        self.assertIn("file_count", result.health)
        self.assertGreater(result.health["file_count"], 0)

    def test_result_has_aivss(self):
        """Result should have AIVSS scoring."""
        result = self._run_scan()
        self.assertIsNotNone(result.aivss)
        self.assertGreater(result.aivss.score, 0)

    def test_result_has_timestamp(self):
        """Result should have a timestamp."""
        result = self._run_scan()
        self.assertTrue(result.timestamp)

    def test_auto_infer_name(self):
        """Name should be auto-inferred from local path."""
        registry = create_default_registry()
        engine = AuditEngine(registry)
        result = engine.run(source=str(self._fixture))
        self.assertEqual(result.name, "test-mcp")


if __name__ == "__main__":
    unittest.main()
