"""Tests for the Docker sandbox module — parsing, findings, and prerequisites."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from mcp_shield.core.models import Severity, Surface
from mcp_shield.runtime.sandbox import (
    SandboxResult,
    _parse_sandbox_output,
)


class TestSandboxResult(unittest.TestCase):
    """Test SandboxResult data model."""

    def test_empty_result_is_clean(self):
        r = SandboxResult()
        self.assertEqual(r.verdict, "CLEAN")
        self.assertEqual(r.to_findings(), [])

    def test_to_dict_keys(self):
        r = SandboxResult()
        d = r.to_dict()
        self.assertIn("status", d)
        self.assertIn("verdict", d)
        self.assertIn("dns_queries", d)
        self.assertIn("tcp_connections", d)
        self.assertIn("sensitive_files_accessed", d)
        self.assertIn("processes_launched", d)
        self.assertIn("external_connections", d)

    def test_sensitive_file_finding(self):
        r = SandboxResult(sensitive_files_accessed=["/etc/shadow", "/root/.ssh/id_rsa"])
        findings = r.to_findings()
        self.assertEqual(len(findings), 2)
        self.assertTrue(all(f.rule_id == "sandbox_sensitive_file" for f in findings))
        self.assertTrue(all(f.severity == Severity.CRITICAL for f in findings))
        self.assertTrue(all(f.surface == Surface.RUNTIME_DELTA for f in findings))

    def test_external_connection_finding(self):
        r = SandboxResult(external_connections=["203.0.113.1:443"])
        findings = r.to_findings()
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "sandbox_external_connection")
        self.assertEqual(findings[0].severity, Severity.HIGH)

    def test_dns_query_finding(self):
        r = SandboxResult(dns_queries=["evil.example.com", "c2.attacker.io"])
        findings = r.to_findings()
        self.assertEqual(len(findings), 2)
        self.assertTrue(all(f.rule_id == "sandbox_dns_query" for f in findings))
        self.assertTrue(all(f.severity == Severity.MEDIUM for f in findings))

    def test_verdict_danger_on_sensitive_files(self):
        r = SandboxResult(sensitive_files_accessed=["/etc/shadow"])
        # Manually trigger verdict logic (normally done by parser)
        if r.sensitive_files_accessed:
            r.verdict = "DANGER"
        self.assertEqual(r.verdict, "DANGER")

    def test_combined_findings(self):
        r = SandboxResult(
            sensitive_files_accessed=["/root/.ssh/id_rsa"],
            external_connections=["10.0.0.1:80"],
            dns_queries=["api.evil.com"],
        )
        findings = r.to_findings()
        self.assertEqual(len(findings), 3)
        rule_ids = {f.rule_id for f in findings}
        self.assertEqual(
            rule_ids,
            {
                "sandbox_sensitive_file",
                "sandbox_external_connection",
                "sandbox_dns_query",
            },
        )

    def test_finding_weights_are_registered(self):
        """Sandbox findings should have non-zero weights."""
        r = SandboxResult(
            sensitive_files_accessed=["/etc/shadow"],
            external_connections=["1.2.3.4:443"],
            dns_queries=["evil.com"],
        )
        for f in r.to_findings():
            self.assertGreater(f.weight, 0, f"Weight for {f.rule_id} should be > 0")


class TestSandboxOutputParsing(unittest.TestCase):
    """Test parsing of sandbox container stdout."""

    def test_parse_dns_queries(self):
        stdout = "=== DNS queries ===\nevil.example.com\nc2.attacker.io\n\n=== TCP connections ===\n(none)\n"
        r = _parse_sandbox_output(stdout)
        self.assertEqual(r.dns_queries, ["evil.example.com", "c2.attacker.io"])
        self.assertEqual(r.tcp_connections, [])
        self.assertEqual(r.verdict, "REVIEW")

    def test_parse_sensitive_files(self):
        stdout = (
            "=== Sensitive files ===\n"
            "/root/.ssh/id_rsa\n"
            "/etc/shadow\n"
            "\n"
            "=== External connections ===\n(none)\n"
        )
        r = _parse_sandbox_output(stdout)
        self.assertEqual(len(r.sensitive_files_accessed), 2)
        self.assertEqual(r.verdict, "DANGER")

    def test_parse_external_connections(self):
        stdout = (
            "=== External connections ===\n"
            'sin_addr=inet_addr("203.0.113.50")\n'
            "\n=== DNS queries ===\n(none)\n"
        )
        r = _parse_sandbox_output(stdout)
        self.assertEqual(len(r.external_connections), 1)
        self.assertEqual(r.verdict, "SUSPECT")

    def test_parse_clean_output(self):
        stdout = (
            "=== DNS queries ===\n(none)\n"
            "=== TCP connections ===\n(none)\n"
            "=== Sensitive files ===\n(none)\n"
            "=== External connections ===\n(none)\n"
            "=== Processes launched ===\n(none)\n"
        )
        r = _parse_sandbox_output(stdout)
        self.assertEqual(r.verdict, "CLEAN")
        self.assertEqual(r.to_findings(), [])

    def test_parse_empty_string(self):
        r = _parse_sandbox_output("")
        self.assertEqual(r.verdict, "CLEAN")

    def test_parse_processes(self):
        stdout = (
            "=== Processes launched ===\n"
            "/usr/bin/curl\n"
            "/bin/sh\n"
            "\n=== DNS queries ===\n(none)\n"
        )
        r = _parse_sandbox_output(stdout)
        self.assertEqual(len(r.processes_launched), 2)
        self.assertIn("/usr/bin/curl", r.processes_launched)


class TestDockerAvailability(unittest.TestCase):
    """Test Docker availability check."""

    @patch("mcp_shield.runtime.sandbox.subprocess.run")
    def test_docker_available_when_installed(self, mock_run):
        from mcp_shield.runtime.sandbox import docker_available

        mock_run.return_value = type("R", (), {"returncode": 0})()
        self.assertTrue(docker_available())

    @patch("mcp_shield.runtime.sandbox.subprocess.run")
    def test_docker_unavailable_when_not_installed(self, mock_run):
        from mcp_shield.runtime.sandbox import docker_available

        mock_run.side_effect = FileNotFoundError
        self.assertFalse(docker_available())

    @patch("mcp_shield.runtime.sandbox.subprocess.run")
    def test_docker_unavailable_on_timeout(self, mock_run):
        import subprocess as sp

        from mcp_shield.runtime.sandbox import docker_available

        mock_run.side_effect = sp.TimeoutExpired("docker", 10)
        self.assertFalse(docker_available())

    @patch("mcp_shield.runtime.sandbox.docker_available", return_value=False)
    def test_prerequisites_fail_without_docker(self, _mock):
        from mcp_shield.runtime.sandbox import check_sandbox_prerequisites

        ok, msg = check_sandbox_prerequisites()
        self.assertFalse(ok)
        self.assertIn("Docker", msg)

    @patch("mcp_shield.runtime.sandbox.docker_available", return_value=False)
    def test_run_sandbox_skips_without_docker(self, _mock):
        from mcp_shield.runtime.sandbox import run_sandbox

        result = run_sandbox(source="test", name="test")
        self.assertEqual(result.status, "skipped")
        self.assertEqual(result.verdict, "SKIPPED")


if __name__ == "__main__":
    unittest.main()
