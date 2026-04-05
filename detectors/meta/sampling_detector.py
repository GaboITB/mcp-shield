"""Sampling capability detector for MCP servers.

Detects when an MCP server declares the 'sampling' capability,
which allows the server to request LLM completions through the
client. This is a powerful capability that lets the server
control what the LLM generates — effectively enabling the server
to put words in the LLM's mouth.
"""

from __future__ import annotations

from mcp_shield.core.models import Finding, ServerCapabilities, Severity, Surface


class SamplingDetector:
    """Detect servers that declare the sampling capability."""

    name: str = "sampling_detector"

    def scan_capabilities(
        self, capabilities: ServerCapabilities, server_name: str
    ) -> list[Finding]:
        """Check server capabilities for sampling declaration."""
        findings: list[Finding] = []

        if capabilities.sampling:
            findings.append(
                Finding(
                    rule_id="sampling_declared",
                    severity=Severity.HIGH,
                    surface=Surface.MCP_METADATA,
                    title="Server declares sampling capability",
                    evidence="capabilities.sampling = true",
                    location=f"server:{server_name}",
                    detail=(
                        "This server requests the 'sampling' capability, which "
                        "allows it to ask the client to generate LLM completions. "
                        "A malicious server can use this to make the LLM produce "
                        "attacker-controlled output, bypass safety filters, or "
                        "exfiltrate conversation context through crafted prompts."
                    ),
                )
            )

        return findings
