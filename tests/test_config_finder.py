"""Tests for MCP config auto-detection and HTML formatter."""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from mcp_shield.core.config_finder import (
    MCPServerConfig,
    _parse_mcp_servers,
    find_mcp_configs,
)
from mcp_shield.core.models import AuditResult, Finding, Severity, Surface
from mcp_shield.formatters.html import format_html_report


class TestParseMCPServers(unittest.TestCase):
    """Test parsing MCP server definitions from config dicts."""

    def test_parse_standard_format(self):
        data = {
            "mcpServers": {
                "my-mcp": {
                    "command": "node",
                    "args": ["server.js"],
                    "env": {"API_KEY": "test"},
                }
            }
        }
        servers = _parse_mcp_servers(data, "/path/config.json", "Claude Desktop")
        self.assertEqual(len(servers), 1)
        self.assertEqual(servers[0].name, "my-mcp")
        self.assertEqual(servers[0].command, "node")
        self.assertEqual(servers[0].args, ["server.js"])
        self.assertEqual(servers[0].client, "Claude Desktop")

    def test_parse_multiple_servers(self):
        data = {
            "mcpServers": {
                "mcp-a": {"command": "node", "args": ["a.js"]},
                "mcp-b": {"command": "python", "args": ["-m", "mcp_b"]},
            }
        }
        servers = _parse_mcp_servers(data, "config.json", "Cursor")
        self.assertEqual(len(servers), 2)
        names = {s.name for s in servers}
        self.assertEqual(names, {"mcp-a", "mcp-b"})

    def test_skip_invalid_config(self):
        data = {"mcpServers": {"bad": "not a dict"}}
        servers = _parse_mcp_servers(data, "config.json", "Test")
        self.assertEqual(len(servers), 0)

    def test_skip_no_command(self):
        data = {"mcpServers": {"empty": {"args": ["test"]}}}
        servers = _parse_mcp_servers(data, "config.json", "Test")
        self.assertEqual(len(servers), 0)

    def test_no_mcp_servers_key(self):
        data = {"other": "stuff"}
        servers = _parse_mcp_servers(data, "config.json", "Test")
        self.assertEqual(len(servers), 0)

    def test_env_var_reference(self):
        data = {
            "mcpServers": {
                "mcp": {
                    "command": "node",
                    "args": [],
                    "env": {"TOKEN": "${MCP_TEST_TOKEN}"},
                }
            }
        }
        with patch.dict("os.environ", {"MCP_TEST_TOKEN": "resolved_value"}):
            servers = _parse_mcp_servers(data, "config.json", "Test")
            self.assertEqual(servers[0].env["TOKEN"], "resolved_value")

    def test_redacted_in_to_dict(self):
        config = MCPServerConfig(
            name="test",
            command="node",
            env={"SECRET": "real_value"},
        )
        d = config.to_dict()
        self.assertEqual(d["env"]["SECRET"], "***")


class TestFindMCPConfigs(unittest.TestCase):
    """Test the auto-detection with mocked config files."""

    def test_find_config_from_temp_file(self):
        """Create a temp config and verify parsing."""
        config = {
            "mcpServers": {
                "test-mcp": {"command": "node", "args": ["test.js"]},
            }
        }
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(config, f)
            f.flush()
            servers = _parse_mcp_servers(config, f.name, "Test")

        self.assertEqual(len(servers), 1)
        self.assertEqual(servers[0].name, "test-mcp")
        Path(f.name).unlink(missing_ok=True)


class TestHTMLFormatter(unittest.TestCase):
    """Test HTML report generation."""

    def test_empty_result_produces_html(self):
        result = AuditResult(name="test-mcp", source="test")
        html = format_html_report(result)
        self.assertIn("<!DOCTYPE html>", html)
        self.assertIn("test-mcp", html)
        self.assertIn("MCP Shield", html)
        self.assertIn("A+", html)  # Empty = A+

    def test_findings_in_html(self):
        result = AuditResult(
            name="vuln-mcp",
            source="test",
            findings=[
                Finding(
                    rule_id="shell_injection",
                    severity=Severity.CRITICAL,
                    surface=Surface.SOURCE_CODE,
                    title="Shell injection detected",
                    evidence="child_process with dynamic input",
                    location="src/index.js:42",
                    detail="This is dangerous",
                ),
                Finding(
                    rule_id="secrets_hardcoded",
                    severity=Severity.HIGH,
                    surface=Surface.SOURCE_CODE,
                    title="Hardcoded API key",
                    evidence="api_key = sk-...",
                    location="config.js:3",
                ),
            ],
        )
        html = format_html_report(result)
        self.assertIn("CRITICAL", html)
        self.assertIn("Shell injection", html)
        self.assertIn("Hardcoded API key", html)
        self.assertIn("shell_injection", html)
        self.assertIn("Grade", html)
        self.assertIn("<style>", html)

    def test_html_escapes_xss(self):
        """Ensure HTML special chars in findings are escaped."""
        result = AuditResult(
            name="<script>alert(1)</script>",
            source="test",
            findings=[
                Finding(
                    rule_id="test",
                    severity=Severity.LOW,
                    surface=Surface.SOURCE_CODE,
                    title='<img src=x onerror="alert(1)">',
                    evidence="<script>evil</script>",
                    location="test",
                ),
            ],
        )
        html = format_html_report(result)
        self.assertNotIn("<script>alert", html)
        self.assertIn("&lt;script&gt;", html)

    def test_html_is_single_file(self):
        """No external CSS/JS references."""
        result = AuditResult(name="test", source="test")
        html = format_html_report(result)
        self.assertNotIn("stylesheet", html.lower().replace("<style>", ""))
        self.assertNotIn("<script src=", html)
        self.assertIn("<style>", html)

    def test_grade_colors(self):
        # F grade
        result = AuditResult(
            name="bad",
            source="test",
            findings=[
                Finding(
                    rule_id="shell_injection",
                    severity=Severity.CRITICAL,
                    surface=Surface.SOURCE_CODE,
                    title="test",
                    evidence="test",
                    location="test",
                )
            ]
            * 10,
        )
        html = format_html_report(result)
        self.assertIn("#dc2626", html)  # Red for F grade


if __name__ == "__main__":
    unittest.main()
