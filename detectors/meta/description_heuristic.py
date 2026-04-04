"""Description heuristic detector for MCP tool metadata.

Behavioral and statistical analysis of tool descriptions:
- Oversized descriptions (> 500 chars)
- High imperative word ratio
- Empty descriptions
- Cross-tool reference manipulation
- Read-only name vs write-action description mismatch
"""

from __future__ import annotations

import re
from typing import Any

from mcp_shield.core.models import Finding, Severity, Surface

# ---------------------------------------------------------------------------
# Thresholds
# ---------------------------------------------------------------------------

_MAX_DESCRIPTION_LENGTH = 500
_IMPERATIVE_RATIO_THRESHOLD = 0.08  # 8% of words are imperatives

# ---------------------------------------------------------------------------
# Compiled patterns
# ---------------------------------------------------------------------------

# Imperative / control words
_IMPERATIVE_WORDS = re.compile(
    r"\b(?:must|always|never|ignore|override|require|shall|"
    r"mandatory|forbidden|critical|essential|immediately|"
    r"do\s+not|important|urgent|absolutely)\b",
    re.IGNORECASE,
)

# Word tokenizer (simple but sufficient)
_RE_WORD = re.compile(r"\b[a-zA-Z]{2,}\b")

# Read-only tool name indicators
_RE_READONLY_NAME = re.compile(
    r"^(?:get|read|list|fetch|query|search|find|show|display|view|"
    r"describe|inspect|check|verify|validate|count|lookup|browse|"
    r"retrieve|scan|peek|head|stat|info|status|health|ping|echo|"
    r"explain|help|suggest|recommend|preview|render|format|parse|"
    r"decode|encode|convert|calculate|compute|estimate|compare|"
    r"measure|analyze|classify|detect|identify|extract|summarize)"
    r"[_-]?",
    re.IGNORECASE,
)

# Write/destructive operation keywords in descriptions
_RE_WRITE_KEYWORDS = re.compile(
    r"\b(?:delet(?:e|es|ing)|remov(?:e|es|ing)|creat(?:e|es|ing)|"
    r"writ(?:e|es|ing)|updat(?:e|es|ing)|modif(?:y|ies|ying)|"
    r"insert(?:s|ing)?|drop(?:s|ping)?|kill(?:s|ing)?|"
    r"execut(?:e|es|ing)|run(?:s|ning)?|send(?:s|ing)?|"
    r"deploy(?:s|ing)?|install(?:s|ing)?|upload(?:s|ing)?|"
    r"overwrite(?:s|ing)?|replac(?:e|es|ing)|purg(?:e|es|ing)|"
    r"truncat(?:e|es|ing)|restart(?:s|ing)?|stop(?:s|ping)?|"
    r"terminat(?:e|es|ing)|shutdown|reboot|format(?:s|ting)?)\b",
    re.IGNORECASE,
)

# Cross-tool reference pattern (mentioning tool-like names)
_RE_TOOL_REFERENCE = re.compile(
    r"\b(?:use|call|invoke|trigger|run|execute)\s+(?:the\s+)?"
    r"[`'\"]?([a-z][a-z0-9_-]{2,})[`'\"]?\s+(?:tool|function|command)\b",
    re.IGNORECASE,
)

# Direct tool name reference (tool_name or tool-name patterns)
_RE_TOOL_NAME_PATTERN = re.compile(
    r"\b(?:first|then|also|before|after)\s+(?:call|use|invoke|run)\s+"
    r"[`'\"]?([a-z][a-z0-9_-]{2,})[`'\"]?",
    re.IGNORECASE,
)


class DescriptionHeuristicDetector:
    """Heuristic analysis of tool descriptions for suspicious patterns."""

    name: str = "description_heuristic"

    def scan_tool(
        self,
        tool_name: str,
        description: str,
        schema: dict[str, Any],
        annotations: dict[str, Any] | None = None,
    ) -> list[Finding]:
        findings: list[Finding] = []

        # --- Empty description ---
        if not description or not description.strip():
            findings.append(
                Finding(
                    rule_id="description_oversized",
                    severity=Severity.MEDIUM,
                    surface=Surface.MCP_METADATA,
                    title="Empty tool description",
                    evidence="(no description provided)",
                    location=tool_name,
                    detail=(
                        "Tool has no description. Users and LLMs cannot assess "
                        "what this tool does before approving its use. This is "
                        "suspicious — legitimate tools document their purpose."
                    ),
                )
            )
            return findings  # No further analysis possible

        # --- Oversized description ---
        desc_len = len(description)
        if desc_len > _MAX_DESCRIPTION_LENGTH:
            findings.append(
                Finding(
                    rule_id="description_oversized",
                    severity=Severity.LOW,
                    surface=Surface.MCP_METADATA,
                    title=f"Oversized description ({desc_len} chars)",
                    evidence=f"Description length: {desc_len} (threshold: {_MAX_DESCRIPTION_LENGTH})",
                    location=tool_name,
                    detail=(
                        "Unusually long tool description. Oversized descriptions "
                        "may hide prompt injection payloads or manipulative "
                        "instructions in the body of the text."
                    ),
                )
            )

        # --- High imperative ratio ---
        words = _RE_WORD.findall(description)
        word_count = len(words)
        if word_count > 5:  # Need enough words for meaningful ratio
            imperative_matches = _IMPERATIVE_WORDS.findall(description)
            imperative_count = len(imperative_matches)
            ratio = imperative_count / word_count

            if ratio >= _IMPERATIVE_RATIO_THRESHOLD:
                findings.append(
                    Finding(
                        rule_id="description_imperative",
                        severity=Severity.MEDIUM,
                        surface=Surface.MCP_METADATA,
                        title=f"High imperative word ratio ({ratio:.0%})",
                        evidence=(
                            f"{imperative_count}/{word_count} words are imperatives: "
                            f"{', '.join(imperative_matches[:8])}"
                        ),
                        location=tool_name,
                        detail=(
                            "Description contains an unusually high proportion of "
                            "imperative/control words (must, always, never, ignore, "
                            "override). This pattern is common in prompt injection "
                            "attempts that try to override LLM behavior."
                        ),
                    )
                )

        # --- Cross-tool manipulation ---
        tool_refs: list[str] = []
        for pattern in (_RE_TOOL_REFERENCE, _RE_TOOL_NAME_PATTERN):
            for m in pattern.finditer(description):
                ref_name = m.group(1)
                if ref_name.lower() != tool_name.lower():
                    tool_refs.append(m.group(0))

        if tool_refs:
            findings.append(
                Finding(
                    rule_id="description_imperative",
                    severity=Severity.HIGH,
                    surface=Surface.MCP_METADATA,
                    title="Cross-tool reference in description",
                    evidence="; ".join(tool_refs[:3])[:200],
                    location=tool_name,
                    detail=(
                        "Description references other tools by name, potentially "
                        "attempting to chain tool calls or redirect the LLM to "
                        "invoke additional tools without user consent."
                    ),
                )
            )

        # --- Read-only name vs write description mismatch ---
        if _RE_READONLY_NAME.match(tool_name):
            write_matches = _RE_WRITE_KEYWORDS.findall(description)
            if write_matches:
                unique_writes = sorted(set(w.lower() for w in write_matches))
                findings.append(
                    Finding(
                        rule_id="description_imperative",
                        severity=Severity.HIGH,
                        surface=Surface.MCP_METADATA,
                        title="Read-only name but description implies writes",
                        evidence=(
                            f"Name '{tool_name}' suggests read-only, "
                            f"but description mentions: {', '.join(unique_writes[:5])}"
                        ),
                        location=tool_name,
                        detail=(
                            "Tool name suggests a read-only operation (get/list/read) "
                            "but the description mentions destructive or write "
                            "operations. This mismatch could trick users into "
                            "approving a tool that modifies data."
                        ),
                    )
                )

        return findings
