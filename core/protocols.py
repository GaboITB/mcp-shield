"""Detector protocols for MCP Shield v3.

Three distinct protocols for three detection surfaces:
- SourceDetector: scans source code files (line-by-line or AST)
- MetadataDetector: scans MCP tool/resource/prompt metadata
- RuntimeDetector: compares baseline vs current state (delta check)

All produce the same Finding type. Detectors use structural subtyping
(Protocol, PEP 544) — no inheritance required.
"""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable

from mcp_shield.core.models import Finding, ToolInfo


@runtime_checkable
class SourceDetector(Protocol):
    """Scans source code files for security issues.

    Implementations receive file content and return findings.
    Can operate line-by-line (regex) or structurally (AST).
    """

    name: str

    def scan_file(self, path: str, content: str) -> list[Finding]: ...


@runtime_checkable
class MetadataDetector(Protocol):
    """Scans MCP metadata (tool descriptions, schemas, names).

    Receives individual tool/resource/prompt info and checks for
    prompt injection, unicode tricks, schema abuse, etc.
    """

    name: str

    def scan_tool(
        self,
        tool_name: str,
        description: str,
        schema: dict[str, Any],
        annotations: dict[str, Any] | None = None,
    ) -> list[Finding]: ...


@runtime_checkable
class RuntimeDetector(Protocol):
    """Compares two states for drift, shadowing, or tampering.

    Receives baseline (from static analysis or registry) and current
    (from live MCP connection) tool lists.
    """

    name: str

    def scan_delta(
        self,
        baseline: list[ToolInfo],
        current: list[ToolInfo],
    ) -> list[Finding]: ...
