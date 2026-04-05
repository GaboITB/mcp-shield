"""Annotation coherence detector for MCP tool metadata.

Checks that tool annotations (readOnlyHint, destructiveHint, etc.)
are consistent with the tool name and description. Incoherent
annotations can trick approval workflows — e.g., a tool marked
readOnly that actually deletes data.
"""

from __future__ import annotations

import re
from typing import Any

from mcp_shield.core.models import Finding, Severity, Surface

# Destructive keywords in tool names or descriptions
_RE_DESTRUCTIVE = re.compile(
    r"\b(?:delet(?:e|es|ing)|remov(?:e|es|ing)|drop(?:s|ping)?|"
    r"kill(?:s|ing)?|terminat(?:e|es|ing)|destroy(?:s|ing)?|"
    r"purg(?:e|es|ing)|truncat(?:e|es|ing)|wip(?:e|es|ing)|"
    r"format(?:s|ting)?|nuk(?:e|es|ing)?|erase(?:s|d)?|"
    r"overwrite(?:s|ing)?|reset(?:s|ting)?|shutdown|reboot|"
    r"restart(?:s|ing)?|stop(?:s|ping)?)\b",
    re.IGNORECASE,
)

# Write keywords
_RE_WRITE = re.compile(
    r"\b(?:writ(?:e|es|ing)|creat(?:e|es|ing)|updat(?:e|es|ing)|"
    r"modif(?:y|ies|ying)|insert(?:s|ing)?|set(?:s|ting)?|"
    r"sav(?:e|es|ing)|stor(?:e|es|ing)|push(?:es|ing)?|"
    r"send(?:s|ing)?|post(?:s|ing)?|upload(?:s|ing)?|"
    r"deploy(?:s|ing)?|install(?:s|ing)?|configur(?:e|es|ing)|"
    r"assign(?:s|ing)?|grant(?:s|ing)?|revok(?:e|es|ing))\b",
    re.IGNORECASE,
)

# Read-only keywords
_RE_READONLY = re.compile(
    r"\b(?:get(?:s|ting)?|read(?:s|ing)?|list(?:s|ing)?|"
    r"fetch(?:es|ing)?|quer(?:y|ies|ying)|search(?:es|ing)?|"
    r"find(?:s|ing)?|show(?:s|ing)?|display(?:s|ing)?|"
    r"view(?:s|ing)?|describ(?:e|es|ing)|inspect(?:s|ing)?|"
    r"check(?:s|ing)?|count(?:s|ing)?|lookup|retriev(?:e|es|ing)|"
    r"scan(?:s|ning)?|stat(?:s)?|info|status|health|ping)\b",
    re.IGNORECASE,
)


class AnnotationCoherenceDetector:
    """Detect incoherent annotations vs actual tool behavior."""

    name: str = "annotation_coherence"

    def scan_tool(
        self,
        tool_name: str,
        description: str,
        schema: dict[str, Any],
        annotations: dict[str, Any] | None = None,
    ) -> list[Finding]:
        findings: list[Finding] = []
        if not annotations:
            return findings

        text = f"{tool_name} {description}"

        # Check 1: readOnlyHint=true but name/desc suggests destructive
        if annotations.get("readOnlyHint") is True:
            destructive_matches = _RE_DESTRUCTIVE.findall(text)
            if destructive_matches:
                findings.append(
                    Finding(
                        rule_id="annotation_incoherent",
                        severity=Severity.HIGH,
                        surface=Surface.MCP_METADATA,
                        title="readOnlyHint=true but tool appears destructive",
                        evidence=(
                            f"Annotations say readOnly, but found: "
                            f"{', '.join(sorted(set(m.lower() for m in destructive_matches[:5])))}"
                        ),
                        location=tool_name,
                        detail=(
                            "Tool is annotated as read-only but its name or "
                            "description contains destructive keywords. This "
                            "mismatch can trick approval workflows into granting "
                            "access to a tool that modifies or deletes data."
                        ),
                    )
                )

            write_matches = _RE_WRITE.findall(text)
            if write_matches and not destructive_matches:
                findings.append(
                    Finding(
                        rule_id="annotation_incoherent",
                        severity=Severity.MEDIUM,
                        surface=Surface.MCP_METADATA,
                        title="readOnlyHint=true but tool appears to write",
                        evidence=(
                            f"Annotations say readOnly, but found: "
                            f"{', '.join(sorted(set(m.lower() for m in write_matches[:5])))}"
                        ),
                        location=tool_name,
                        detail=(
                            "Tool is annotated as read-only but its name or "
                            "description mentions write operations."
                        ),
                    )
                )

        # Check 2: destructiveHint=false but name/desc is clearly destructive
        if annotations.get("destructiveHint") is False:
            destructive_matches = _RE_DESTRUCTIVE.findall(text)
            if destructive_matches:
                findings.append(
                    Finding(
                        rule_id="annotation_incoherent",
                        severity=Severity.HIGH,
                        surface=Surface.MCP_METADATA,
                        title="destructiveHint=false but tool appears destructive",
                        evidence=(
                            f"Annotations say non-destructive, but found: "
                            f"{', '.join(sorted(set(m.lower() for m in destructive_matches[:5])))}"
                        ),
                        location=tool_name,
                        detail=(
                            "Tool annotation claims it is not destructive but its "
                            "name or description clearly indicates destructive "
                            "operations (delete, drop, kill, etc.)."
                        ),
                    )
                )

        # Check 3: idempotentHint=true but description suggests side effects
        if annotations.get("idempotentHint") is True:
            if _RE_DESTRUCTIVE.search(text):
                findings.append(
                    Finding(
                        rule_id="annotation_incoherent",
                        severity=Severity.MEDIUM,
                        surface=Surface.MCP_METADATA,
                        title="idempotentHint=true but tool appears destructive",
                        evidence="Claims idempotent but has destructive keywords",
                        location=tool_name,
                        detail=(
                            "Tool claims to be idempotent (safe to retry) but "
                            "contains destructive keywords. Retrying a delete "
                            "operation could cause unintended data loss."
                        ),
                    )
                )

        return findings
