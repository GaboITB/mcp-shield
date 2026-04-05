"""Tests for output formatters (terminal, JSON, SARIF, HTML)."""

from __future__ import annotations

import json
import unittest

from mcp_shield.core.models import AuditResult, Finding, Severity, Surface


def _make_result(n_findings: int = 3) -> AuditResult:
    """Create a test AuditResult with N findings."""
    findings = []
    severities = [
        Severity.CRITICAL,
        Severity.HIGH,
        Severity.MEDIUM,
        Severity.LOW,
        Severity.INFO,
    ]
    for i in range(n_findings):
        findings.append(
            Finding(
                rule_id=f"test_rule_{i}",
                severity=severities[i % len(severities)],
                surface=Surface.SOURCE_CODE,
                title=f"Test finding {i}",
                evidence=f"evidence line {i}",
                location=f"src/file_{i}.py:10",
                detail=f"Detail for finding {i}",
            )
        )
    return AuditResult(
        name="test-mcp",
        source="https://github.com/test/test-mcp",
        findings=findings,
        timestamp="2026-04-05T10:00:00",
    )


class TestTerminalFormatter(unittest.TestCase):
    """Tests for terminal output formatter."""

    def test_format_summary_returns_string(self):
        from mcp_shield.formatters.terminal import format_summary

        result = _make_result()
        output = format_summary(result)
        self.assertIsInstance(output, str)
        self.assertIn("test-mcp", output)

    def test_format_summary_empty_result(self):
        from mcp_shield.formatters.terminal import format_summary

        result = _make_result(0)
        output = format_summary(result)
        self.assertIn("A+", output)

    def test_format_findings_contains_severities(self):
        from mcp_shield.formatters.terminal import format_findings

        result = _make_result(5)
        output = format_findings(result)
        self.assertIn("CRITICAL", output)
        self.assertIn("HIGH", output)

    def test_format_findings_empty(self):
        from mcp_shield.formatters.terminal import format_findings

        result = _make_result(0)
        output = format_findings(result)
        self.assertIsInstance(output, str)

    def test_format_full_report_markdown(self):
        from mcp_shield.formatters.terminal import format_full_report

        result = _make_result()
        output = format_full_report(result)
        self.assertIn("#", output)  # Markdown headers
        self.assertIn("test-mcp", output)

    def test_format_verdict(self):
        from mcp_shield.formatters.terminal import format_verdict

        result = _make_result(1)  # CRITICAL only
        output = format_verdict(result)
        self.assertIsInstance(output, str)


class TestJsonFormatter(unittest.TestCase):
    """Tests for JSON output formatter."""

    def test_to_json_valid(self):
        from mcp_shield.formatters.json import to_json

        result = _make_result()
        output = to_json(result)
        data = json.loads(output)
        self.assertEqual(data["name"], "test-mcp")

    def test_to_json_has_metadata(self):
        from mcp_shield.formatters.json import to_json

        result = _make_result()
        output = to_json(result)
        data = json.loads(output)
        self.assertIn("mcp_shield_version", data)
        self.assertIn("$schema", data)
        self.assertIn("generated_at", data)

    def test_to_json_computed_properties(self):
        from mcp_shield.formatters.json import to_json

        result = _make_result(3)
        data = json.loads(to_json(result))
        self.assertIn("total_score", data)
        self.assertIn("grade", data)
        self.assertIn("critical_count", data)
        self.assertIn("high_count", data)
        self.assertIn("deny_rules", data)

    def test_to_json_empty_findings(self):
        from mcp_shield.formatters.json import to_json

        result = _make_result(0)
        data = json.loads(to_json(result))
        self.assertEqual(data["grade"], "A+")
        self.assertEqual(data["total_score"], 0)

    def test_to_json_file(self):
        import tempfile
        from pathlib import Path

        from mcp_shield.formatters.json import to_json_file

        result = _make_result()
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "test.json"
            to_json_file(result, path)
            self.assertTrue(path.exists())
            data = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(data["name"], "test-mcp")


class TestSarifFormatter(unittest.TestCase):
    """Tests for SARIF output formatter."""

    def test_sarif_valid_json(self):
        from mcp_shield.formatters.sarif import format_sarif

        result = _make_result()
        output = format_sarif(result)
        data = json.loads(output)
        self.assertIn("$schema", data)
        self.assertEqual(data["version"], "2.1.0")

    def test_sarif_has_runs(self):
        from mcp_shield.formatters.sarif import format_sarif

        result = _make_result()
        data = json.loads(format_sarif(result))
        self.assertEqual(len(data["runs"]), 1)
        run = data["runs"][0]
        self.assertIn("tool", run)
        self.assertIn("results", run)

    def test_sarif_results_match_findings(self):
        from mcp_shield.formatters.sarif import format_sarif

        result = _make_result(5)
        data = json.loads(format_sarif(result))
        sarif_results = data["runs"][0]["results"]
        self.assertEqual(len(sarif_results), 5)

    def test_sarif_severity_mapping(self):
        from mcp_shield.formatters.sarif import format_sarif

        result = _make_result(2)  # CRITICAL + HIGH
        data = json.loads(format_sarif(result))
        levels = [r["level"] for r in data["runs"][0]["results"]]
        self.assertTrue(all(level == "error" for level in levels))

    def test_sarif_empty_findings(self):
        from mcp_shield.formatters.sarif import format_sarif

        result = _make_result(0)
        data = json.loads(format_sarif(result))
        self.assertEqual(len(data["runs"][0]["results"]), 0)


class TestHtmlFormatter(unittest.TestCase):
    """Tests for HTML report formatter."""

    def test_html_is_valid_html(self):
        from mcp_shield.formatters.html import format_html_report

        result = _make_result()
        output = format_html_report(result)
        self.assertIn("<!DOCTYPE html>", output)
        self.assertIn("</html>", output)

    def test_html_contains_mcp_name(self):
        from mcp_shield.formatters.html import format_html_report

        result = _make_result()
        output = format_html_report(result)
        self.assertIn("test-mcp", output)

    def test_html_contains_findings(self):
        from mcp_shield.formatters.html import format_html_report

        result = _make_result(3)
        output = format_html_report(result)
        self.assertIn("CRITICAL", output)

    def test_html_standalone(self):
        """HTML report should not reference external CSS/JS."""
        from mcp_shield.formatters.html import format_html_report

        result = _make_result()
        output = format_html_report(result)
        self.assertNotIn('link rel="stylesheet"', output)
        self.assertNotIn("src=", output.replace("source", ""))  # Crude but effective


class TestCliUtils(unittest.TestCase):
    """Tests for CLI utility functions."""

    def test_sanitize_filename_basic(self):
        from mcp_shield.cli._parser import sanitize_filename

        self.assertEqual(sanitize_filename("my-mcp-server"), "my-mcp-server")

    def test_sanitize_filename_traversal(self):
        from mcp_shield.cli._parser import sanitize_filename

        result = sanitize_filename("../../etc/passwd")
        self.assertNotIn("..", result)
        self.assertNotIn("/", result)

    def test_sanitize_filename_special_chars(self):
        from mcp_shield.cli._parser import sanitize_filename

        result = sanitize_filename("server<>|name")
        self.assertNotIn("<", result)
        self.assertNotIn(">", result)

    def test_sanitize_filename_empty(self):
        from mcp_shield.cli._parser import sanitize_filename

        self.assertEqual(sanitize_filename(""), "unknown")

    def test_sanitize_filename_max_length(self):
        from mcp_shield.cli._parser import sanitize_filename

        result = sanitize_filename("a" * 200)
        self.assertLessEqual(len(result), 100)

    def test_exit_code_clean(self):
        from mcp_shield.cli._utils import exit_code_from_result

        result = _make_result(0)
        self.assertEqual(exit_code_from_result(result), 0)

    def test_exit_code_critical(self):
        from mcp_shield.cli._utils import exit_code_from_result

        result = _make_result(1)  # CRITICAL
        self.assertEqual(exit_code_from_result(result), 2)

    def test_exit_code_fail_on(self):
        from mcp_shield.cli._utils import exit_code_from_result

        result = _make_result(3)  # CRITICAL, HIGH, MEDIUM
        self.assertEqual(exit_code_from_result(result, fail_on="medium"), 2)

    def test_exit_code_fail_on_no_match(self):
        from mcp_shield.cli._utils import exit_code_from_result

        # Only INFO finding
        result = AuditResult(
            name="test",
            source="test",
            findings=[
                Finding(
                    rule_id="info_only",
                    severity=Severity.INFO,
                    surface=Surface.SOURCE_CODE,
                    title="Info",
                    evidence="info",
                    location="test.py:1",
                )
            ],
        )
        self.assertEqual(exit_code_from_result(result, fail_on="high"), 0)

    def test_audit_result_from_dict_roundtrip(self):
        from mcp_shield.cli._utils import audit_result_from_dict
        from mcp_shield.formatters.json import to_json

        original = _make_result(3)
        json_str = to_json(original)
        data = json.loads(json_str)
        restored = audit_result_from_dict(data)
        self.assertEqual(restored.name, original.name)
        self.assertEqual(len(restored.findings), len(original.findings))
        self.assertEqual(restored.findings[0].rule_id, original.findings[0].rule_id)

    def test_build_parser_commands(self):
        from mcp_shield.cli._parser import build_parser

        parser = build_parser()
        # Verify parser was built without errors
        args = parser.parse_args(["scan", "https://github.com/test/repo"])
        self.assertEqual(args.subcommand, "scan")
        self.assertEqual(args.source, "https://github.com/test/repo")

    def test_build_parser_scan_flags(self):
        from mcp_shield.cli._parser import build_parser

        parser = build_parser()
        args = parser.parse_args(
            [
                "scan",
                "test",
                "--full",
                "--no-open",
                "--no-ignore",
                "--suppress",
                "tls_disabled",
                "--fail-on",
                "high",
            ]
        )
        self.assertTrue(args.full)
        self.assertTrue(args.no_open)
        self.assertTrue(args.no_ignore)
        self.assertEqual(args.suppress, "tls_disabled")
        self.assertEqual(args.fail_on, "high")


if __name__ == "__main__":
    unittest.main()
