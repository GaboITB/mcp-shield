"""Core data models for MCP Shield v2.

All audit results flow through these types. Detectors produce Findings,
fetchers produce ToolInfo/ResourceInfo/PromptInfo, and the engine
aggregates everything into an AuditResult.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Severity(Enum):
    """Finding severity levels, ordered by criticality."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    def __lt__(self, other: Severity) -> bool:
        order = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFO: 4,
        }
        return order[self] < order[other]


class Surface(Enum):
    """Detection surface — where the finding was discovered."""

    SOURCE_CODE = "source_code"
    MCP_METADATA = "mcp_metadata"
    RUNTIME_DELTA = "runtime_delta"


class Grade(Enum):
    """Overall audit grade."""

    A_PLUS = "A+"
    A = "A"
    B = "B"
    C = "C"
    F = "F"


# Scoring weights per rule_id — detectors reference these
SEVERITY_WEIGHTS: dict[str, int] = {
    # Code detectors
    "shell_injection": 50,
    "shell_hardcoded": 5,
    "eval_exec_dynamic": 40,
    "eval_exec_static": 5,
    "ssrf_dynamic_url": 20,
    "ssrf_env_url": 10,
    "secrets_hardcoded": 35,
    "path_traversal": 25,
    "excessive_permissions": 10,
    "tls_disabled": 10,
    "postinstall_script": 25,
    "obfuscated_code": 40,
    "base64_decode": 2,
    "telemetry_phonehome": 8,
    "sensitive_file_access": 2,
    "force_push": 30,
    "sql_multistatement": 25,
    "credential_in_args": 25,
    "exfiltration_api": 12,
    "unpinned_dependency": 1,
    "phantom_dependency": 8,
    "native_module_dep": 8,
    "npm_deprecated": 20,
    "sdk_outdated": 10,
    "no_rate_limiting": 10,
    # Meta detectors
    "prompt_injection": 50,
    "unicode_invisible": 40,
    "homoglyph_spoofing": 40,
    "schema_injection": 30,
    "markdown_injection": 20,
    "description_oversized": 10,
    "description_imperative": 15,
    # Delta detectors
    "tool_shadowing": 50,
    "param_divergence": 30,
    "capability_drift": 50,
    "tool_appeared_live": 40,
    "tool_disappeared_live": 20,
    # Repo health
    "no_tests": 3,
    "no_license": 5,
    "no_ci": 2,
}


@dataclass(frozen=True, slots=True)
class Finding:
    """A single security finding produced by a detector."""

    rule_id: str
    severity: Severity
    surface: Surface
    title: str
    evidence: str
    location: str  # file:line OR tool_name OR endpoint
    detail: str = ""

    @property
    def weight(self) -> int:
        return SEVERITY_WEIGHTS.get(self.rule_id, 0)


@dataclass(frozen=True, slots=True)
class ToolInfo:
    """MCP tool metadata — from static analysis or live fetch."""

    name: str
    description: str = ""
    input_schema: dict[str, Any] = field(default_factory=dict)
    output_schema: dict[str, Any] = field(default_factory=dict)
    annotations: dict[str, Any] = field(default_factory=dict)
    source: str = ""  # "static" or "live"
    file: str = ""
    line: int = 0

    @property
    def is_destructive(self) -> bool:
        if self.annotations.get("readOnlyHint", False):
            return False
        if self.annotations.get("destructiveHint", False):
            return True
        destructive_kw = {
            "delete",
            "remove",
            "drop",
            "kill",
            "stop",
            "execute",
            "exec",
            "run",
            "send",
            "write",
            "create",
            "update",
            "modify",
            "patch",
            "put",
            "upload",
            "import",
            "ban",
            "block",
            "promote",
            "demote",
            "invite",
            "forward",
            "edit",
            "pin",
            "unpin",
            "archive",
            "mute",
            "leave",
            "join",
        }
        return any(kw in self.name.lower() for kw in destructive_kw)

    def content_hash(self) -> str:
        """Stable hash for rug pull detection (name + desc + schemas + annotations)."""
        import hashlib
        import json

        canonical = json.dumps(
            {
                "name": self.name,
                "description": self.description,
                "inputSchema": self.input_schema,
                "outputSchema": self.output_schema,
                "annotations": self.annotations,
            },
            sort_keys=True,
            ensure_ascii=False,
        )
        return hashlib.sha256(canonical.encode()).hexdigest()[:32]


@dataclass(frozen=True, slots=True)
class ResourceInfo:
    """MCP resource metadata."""

    uri: str
    name: str = ""
    description: str = ""
    mime_type: str = ""


@dataclass(frozen=True, slots=True)
class PromptInfo:
    """MCP prompt metadata."""

    name: str
    description: str = ""
    arguments: list[dict[str, Any]] = field(default_factory=list)


@dataclass(frozen=True, slots=True)
class ServerCapabilities:
    """MCP server declared capabilities."""

    tools: bool = False
    resources: bool = False
    prompts: bool = False
    sampling: bool = False
    logging: bool = False


@dataclass
class AuditResult:
    """Aggregated audit result — produced by the engine."""

    name: str
    source: str
    findings: list[Finding] = field(default_factory=list)
    tools_static: list[ToolInfo] = field(default_factory=list)
    tools_live: list[ToolInfo] = field(default_factory=list)
    resources: list[ResourceInfo] = field(default_factory=list)
    prompts: list[PromptInfo] = field(default_factory=list)
    capabilities: ServerCapabilities | None = None
    health: dict[str, Any] = field(default_factory=dict)
    deps: dict[str, Any] = field(default_factory=dict)
    urls: list[dict[str, Any]] = field(default_factory=list)
    pinned_version: dict[str, str] = field(default_factory=dict)
    deprecated_msg: str = ""
    sdk_info: dict[str, str] = field(default_factory=dict)
    sbom: dict = field(default_factory=dict)
    dep_audit: str = ""
    transitive_audit: str = ""
    npm_github_diff: dict[str, Any] = field(default_factory=dict)
    rate_limited_tools: list[str] = field(default_factory=list)
    aivss: Any = None  # AIVSSResult, set by engine after scoring
    timestamp: str = ""

    @property
    def total_score(self) -> int:
        return sum(f.weight for f in self.findings)

    @property
    def grade(self) -> Grade:
        s = self.total_score
        if s == 0:
            return Grade.A_PLUS
        if s <= 20:
            return Grade.A
        if s <= 60:
            return Grade.B
        if s <= 150:
            return Grade.C
        return Grade.F

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.HIGH)

    def findings_by_severity(self) -> dict[Severity, list[Finding]]:
        result: dict[Severity, list[Finding]] = {}
        for f in sorted(self.findings, key=lambda x: x.severity):
            result.setdefault(f.severity, []).append(f)
        return result

    def findings_by_surface(self) -> dict[Surface, list[Finding]]:
        result: dict[Surface, list[Finding]] = {}
        for f in self.findings:
            result.setdefault(f.surface, []).append(f)
        return result

    def deny_rules(self, mcp_name: str | None = None) -> list[str]:
        """Generate settings.json deny rules for destructive tools."""
        safe_name = (mcp_name or self.name).replace("-", "_")
        rules = []
        for t in self.tools_live or self.tools_static:
            if t.is_destructive:
                rules.append(f"mcp__{safe_name}__{t.name}")
        return rules
