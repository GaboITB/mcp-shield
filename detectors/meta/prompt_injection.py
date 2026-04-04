"""Prompt injection detector for MCP tool descriptions and schemas.

Scans tool descriptions and input_schema description fields for patterns
commonly used in prompt injection attacks against LLM-based tool dispatchers.
"""

from __future__ import annotations

import re
from typing import Any

from mcp_shield.core.models import Finding, Severity, Surface

# ---------------------------------------------------------------------------
# Compiled patterns — each tuple: (compiled regex, human-readable label)
# ---------------------------------------------------------------------------

_INJECTION_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    # --- Instruction override ---
    (
        re.compile(
            r"ignore\s+(all\s+)?(previous|above|prior|earlier|preceding)\s+"
            r"(instructions|rules|prompts|guidelines|context)",
            re.IGNORECASE,
        ),
        "instruction override (ignore previous)",
    ),
    (
        re.compile(
            r"(disregard|forget)\s+(all\s+)?(previous|above|prior|your)\s+"
            r"(instructions|rules|prompts|guidelines|context|training)",
            re.IGNORECASE,
        ),
        "instruction override (disregard/forget)",
    ),
    (
        re.compile(
            r"forget\s+(everything|what|your)\b",
            re.IGNORECASE,
        ),
        "instruction override (forget everything)",
    ),
    # --- Imperative role reassignment ---
    (
        re.compile(
            r"\byou\s+(must|should|shall|are\s+now|are\s+actually|will\s+now)\b",
            re.IGNORECASE,
        ),
        "imperative role reassignment",
    ),
    (
        re.compile(
            r"\b(pretend\s+you\s+are|act\s+as\s+if|assume\s+the\s+role)\b",
            re.IGNORECASE,
        ),
        "role impersonation",
    ),
    # --- Fake XML/system tags ---
    (
        re.compile(
            r"<\s*/?\s*(system|instruction|prompt|admin|override|context)\s*/?\s*>",
            re.IGNORECASE,
        ),
        "fake system/instruction XML tag",
    ),
    # --- Information suppression ---
    (
        re.compile(
            r"do\s+not\s+(tell|reveal|show|disclose|mention|display)\s+"
            r"(the\s+)?(user|human|operator|caller)",
            re.IGNORECASE,
        ),
        "information suppression directive",
    ),
    # --- Secret exfiltration ---
    (
        re.compile(
            r"(output|print|return|send|leak|exfiltrate|reveal)\s+(the\s+)?"
            r"(secret|password|key|token|credential|api[_\s]?key|private)",
            re.IGNORECASE,
        ),
        "secret exfiltration attempt",
    ),
    # --- New instructions block ---
    (
        re.compile(
            r"(new|updated|revised|real|actual)\s+instructions\s*:",
            re.IGNORECASE,
        ),
        "new instructions block",
    ),
    (
        re.compile(
            r"IMPORTANT\s*:\s*(override|ignore|disregard|replace|update)",
            re.IGNORECASE,
        ),
        "IMPORTANT override directive",
    ),
    # --- Pre-action exfiltration ---
    (
        re.compile(
            r"before\s+(respond|answer|reply|process|execut)ing\s*,?\s*"
            r"(first\s+)?(send|post|fetch|call|request|forward|transmit)",
            re.IGNORECASE,
        ),
        "pre-action exfiltration",
    ),
    # --- Covert additional actions ---
    (
        re.compile(
            r"secretly\s+(also|always|first|additionally|then)\b",
            re.IGNORECASE,
        ),
        "covert additional action",
    ),
    (
        re.compile(
            r"\b(also|additionally|then)\s+secretly\b",
            re.IGNORECASE,
        ),
        "covert additional action (reversed)",
    ),
    # --- Hidden content after whitespace ---
    (
        re.compile(r"\n{5,}"),
        "hidden content after excessive newlines",
    ),
    # --- Base64-encoded payload ---
    (
        re.compile(
            r"[A-Za-z0-9+/]{40,}={0,2}",
        ),
        "possible base64-encoded payload",
    ),
    # --- Encoded instruction markers ---
    (
        re.compile(
            r"(eval|decode|atob|base64)\s*\(",
            re.IGNORECASE,
        ),
        "encoded instruction invocation",
    ),
    # --- Direct prompt manipulation ---
    (
        re.compile(
            r"\b(system\s+prompt|system_prompt|systemprompt)\b",
            re.IGNORECASE,
        ),
        "system prompt reference",
    ),
    (
        re.compile(
            r"\b(jailbreak|prompt\s*inject|DAN|bypass\s+filter)\b",
            re.IGNORECASE,
        ),
        "jailbreak/injection keyword",
    ),
]


def _scan_text(text: str, location: str, context: str) -> list[Finding]:
    """Run all injection patterns against a text blob."""
    findings: list[Finding] = []
    for pattern, label in _INJECTION_PATTERNS:
        match = pattern.search(text)
        if match:
            snippet = match.group(0)
            # Base64 blocks are medium severity (could be legitimate)
            if "base64" in label.lower():
                sev = Severity.MEDIUM
            # Hidden newlines are medium
            elif "newlines" in label.lower():
                sev = Severity.MEDIUM
            else:
                sev = Severity.CRITICAL

            findings.append(
                Finding(
                    rule_id="prompt_injection",
                    severity=sev,
                    surface=Surface.MCP_METADATA,
                    title=f"Prompt injection: {label}",
                    evidence=snippet[:200],
                    location=location,
                    detail=f"Detected in {context}. Pattern: {label}",
                )
            )
    return findings


def _extract_schema_descriptions(schema: dict[str, Any]) -> list[tuple[str, str]]:
    """Recursively extract (field_path, description) from a JSON Schema."""
    results: list[tuple[str, str]] = []

    def _walk(obj: Any, path: str) -> None:
        if not isinstance(obj, dict):
            return
        desc = obj.get("description", "")
        if desc:
            results.append((path or "root", desc))
        # Walk nested properties
        for key, value in obj.get("properties", {}).items():
            _walk(value, f"{path}.{key}" if path else key)
        # Walk items (array schemas)
        items = obj.get("items")
        if isinstance(items, dict):
            _walk(items, f"{path}[]")
        # Walk allOf / anyOf / oneOf
        for combiner in ("allOf", "anyOf", "oneOf"):
            for i, sub in enumerate(obj.get(combiner, [])):
                _walk(sub, f"{path}/{combiner}[{i}]")

    _walk(schema, "")
    return results


class PromptInjectionDetector:
    """Detect prompt injection patterns in tool descriptions and schemas."""

    name: str = "prompt_injection"

    def scan_tool(
        self,
        tool_name: str,
        description: str,
        schema: dict[str, Any],
        annotations: dict[str, Any] | None = None,
    ) -> list[Finding]:
        findings: list[Finding] = []

        # Scan main description
        if description:
            findings.extend(_scan_text(description, tool_name, "tool description"))

        # Scan input_schema description fields
        for field_path, field_desc in _extract_schema_descriptions(schema):
            findings.extend(
                _scan_text(
                    field_desc,
                    f"{tool_name}:{field_path}",
                    f"schema field '{field_path}' description",
                )
            )

        return findings
