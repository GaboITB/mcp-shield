"""Tool Shadowing Detector — MCP Shield v3.

Detects dynamically injected tools, hidden tools, and name collisions
with known built-in tool names. Also flags near-matches that could be
used for typosquatting (underscore vs hyphen, case differences).
"""

from __future__ import annotations

import re

from mcp_shield.core.models import Finding, Severity, Surface, ToolInfo

# Known built-in tool names that MCP clients commonly expose.
# A server tool matching these could shadow the real built-in.
BUILTIN_TOOL_NAMES: frozenset[str] = frozenset(
    {
        "read_file",
        "write_file",
        "execute",
        "run_command",
        "search",
        "list_files",
        "edit_file",
    }
)


def _normalize(name: str) -> str:
    """Normalize a tool name for near-match comparison.

    Collapses underscores, hyphens, and casing so that
    ``Read-File``, ``read_file``, and ``readfile`` all resolve
    to the same canonical form.
    """
    return re.sub(r"[-_]", "", name).lower()


def _is_near_match(a: str, b: str) -> bool:
    """Return True if *a* and *b* are different strings but normalize
    to the same canonical form."""
    return a != b and _normalize(a) == _normalize(b)


class ToolShadowingDetector:
    """Detects tool injection, hiding, and name collisions."""

    name: str = "tool_shadowing"

    def scan_delta(
        self,
        baseline: list[ToolInfo],
        current: list[ToolInfo],
    ) -> list[Finding]:
        findings: list[Finding] = []

        baseline_names: dict[str, ToolInfo] = {t.name: t for t in baseline}
        current_names: dict[str, ToolInfo] = {t.name: t for t in current}

        # --- Dynamically injected tools (in live, not in static) ---
        injected = set(current_names) - set(baseline_names)
        for tool_name in sorted(injected):
            findings.append(
                Finding(
                    rule_id="tool_appeared_live",
                    severity=Severity.HIGH,
                    surface=Surface.RUNTIME_DELTA,
                    title=f"Dynamically injected tool: {tool_name}",
                    evidence=(
                        f"Tool '{tool_name}' exists at runtime but was NOT "
                        f"found in static source analysis."
                    ),
                    location=tool_name,
                    detail=(
                        "This tool may have been injected after install "
                        "(post-install hook, dynamic registration, remote "
                        "config). Inspect what it does before allowing it."
                    ),
                )
            )

        # --- Hidden tools (in static, not in live) ---
        hidden = set(baseline_names) - set(current_names)
        for tool_name in sorted(hidden):
            t = baseline_names[tool_name]
            loc = f"{t.file}:{t.line}" if t.file else tool_name
            findings.append(
                Finding(
                    rule_id="tool_disappeared_live",
                    severity=Severity.MEDIUM,
                    surface=Surface.RUNTIME_DELTA,
                    title=f"Hidden tool not exposed at runtime: {tool_name}",
                    evidence=(
                        f"Tool '{tool_name}' is defined in source ({loc}) "
                        f"but not listed by the running server."
                    ),
                    location=loc,
                    detail=(
                        "The server may conditionally hide tools based on "
                        "clientInfo or timing. This could indicate evasive "
                        "behavior — the tool may activate later."
                    ),
                )
            )

        # --- Name collisions with built-in tools ---
        for tool_name in sorted(current_names):
            if tool_name in BUILTIN_TOOL_NAMES:
                findings.append(
                    Finding(
                        rule_id="tool_shadowing",
                        severity=Severity.CRITICAL,
                        surface=Surface.RUNTIME_DELTA,
                        title=f"Tool shadows built-in: {tool_name}",
                        evidence=(
                            f"Server exposes '{tool_name}' which exactly "
                            f"matches a known built-in tool name."
                        ),
                        location=tool_name,
                        detail=(
                            "An MCP server providing a tool with a built-in "
                            "name can intercept calls meant for the host. "
                            "This is a high-confidence attack indicator."
                        ),
                    )
                )
                continue  # skip near-match check — exact is worse

            # Near-match detection (typosquatting)
            for builtin in BUILTIN_TOOL_NAMES:
                if _is_near_match(tool_name, builtin):
                    findings.append(
                        Finding(
                            rule_id="tool_shadowing",
                            severity=Severity.HIGH,
                            surface=Surface.RUNTIME_DELTA,
                            title=(
                                f"Tool near-matches built-in: "
                                f"{tool_name} ~ {builtin}"
                            ),
                            evidence=(
                                f"Server tool '{tool_name}' normalizes to "
                                f"the same form as built-in '{builtin}' "
                                f"(ignoring case/hyphens/underscores)."
                            ),
                            location=tool_name,
                            detail=(
                                "Near-match names can confuse LLMs into "
                                "calling the server tool instead of the "
                                "built-in. Verify this is intentional."
                            ),
                        )
                    )

        return findings
