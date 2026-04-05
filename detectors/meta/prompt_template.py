"""Prompt template detector for MCP prompt metadata.

Scans MCP prompts (prompts/list) for injection patterns in
descriptions and argument definitions. MCP prompts are server-defined
templates that get injected into the LLM conversation — they can
carry hidden instructions or manipulate the LLM's behavior.
"""

from __future__ import annotations

from typing import Any

from mcp_shield.core.models import Finding, PromptInfo, Severity, Surface
from mcp_shield.detectors.meta.prompt_injection import _scan_text


class PromptTemplateDetector:
    """Detect injection risks in MCP prompt templates."""

    name: str = "prompt_template"

    def scan_prompt(self, prompt: PromptInfo) -> list[Finding]:
        """Scan a single MCP prompt for security issues."""
        findings: list[Finding] = []
        location = f"prompt:{prompt.name}"

        # 1. Prompt injection in prompt description
        if prompt.description:
            findings.extend(
                _scan_text(prompt.description, location, "prompt description")
            )

        # 2. Scan argument descriptions for injection
        for arg in prompt.arguments:
            arg_name = arg.get("name", "unknown")
            arg_desc = arg.get("description", "")
            if arg_desc and isinstance(arg_desc, str):
                findings.extend(
                    _scan_text(
                        arg_desc,
                        f"{location}:{arg_name}",
                        f"prompt argument '{arg_name}' description",
                    )
                )

        # 3. Check for required arguments with suspicious defaults
        for arg in prompt.arguments:
            arg_name = arg.get("name", "unknown")
            default = arg.get("default", "")
            if isinstance(default, str) and len(default) > 200:
                # Long default values could embed hidden instructions
                injection_findings = _scan_text(
                    default,
                    f"{location}:{arg_name}",
                    f"prompt argument '{arg_name}' default value",
                )
                if injection_findings:
                    findings.extend(injection_findings)
                else:
                    findings.append(
                        Finding(
                            rule_id="prompt_template_suspicious",
                            severity=Severity.LOW,
                            surface=Surface.MCP_METADATA,
                            title=f"Long default value in prompt argument '{arg_name}'",
                            evidence=f"Default length: {len(default)} chars",
                            location=f"{location}:{arg_name}",
                            detail=(
                                "Prompt argument has an unusually long default value. "
                                "This could embed hidden instructions that get injected "
                                "into the conversation without user awareness."
                            ),
                        )
                    )

        return findings

    def scan_prompts(self, prompts: list[PromptInfo]) -> list[Finding]:
        """Scan all prompts from a server."""
        findings: list[Finding] = []
        for prompt in prompts:
            findings.extend(self.scan_prompt(prompt))
        return findings
