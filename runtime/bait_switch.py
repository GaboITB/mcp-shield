"""Bait-and-switch detector for MCP Shield v3.

Connects to an MCP server multiple times with different client identities
and compares the tool lists. If the server returns different tools depending
on who's asking, it's behaving maliciously (bait-and-switch attack).

A legitimate server returns the same tools regardless of the client.
A malicious server may:
- Hide dangerous tools when it detects a scanner
- Show extra tools only for specific clients (Claude, Cursor)
- Change tool descriptions or schemas per-client

Detection method:
1. Connect as "Claude Desktop" (popular AI client)
2. Connect as "Cursor IDE" (popular AI IDE)
3. Connect as "mcp-audit-tool" (scanner identity)
4. Compare all three tool lists
5. Any difference = CRITICAL finding (zero false positives)
"""

from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass, field
from typing import Any

from mcp_shield.core.models import Finding, Severity, Surface, ToolInfo
from mcp_shield.fetcher.live import fetch_live_tools

logger = logging.getLogger("mcp_shield.runtime.bait_switch")

# ---------------------------------------------------------------------------
# Client identities for multi-identity probing
# ---------------------------------------------------------------------------

PROBE_IDENTITIES: list[dict[str, str]] = [
    {"name": "Claude Desktop", "version": "1.2.0"},
    {"name": "Cursor", "version": "0.45.6"},
    {"name": "mcp-audit-tool", "version": "1.0.0"},
]

# Extended identities for thorough mode
EXTENDED_IDENTITIES: list[dict[str, str]] = [
    {"name": "Claude Desktop", "version": "1.2.0"},
    {"name": "Cursor", "version": "0.45.6"},
    {"name": "mcp-audit-tool", "version": "1.0.0"},
    {"name": "Windsurf", "version": "1.0.0"},
    {"name": "Continue", "version": "0.9.0"},
    {"name": "generic-client", "version": "0.0.1"},
]


# ---------------------------------------------------------------------------
# Result model
# ---------------------------------------------------------------------------


@dataclass
class BaitSwitchResult:
    """Result of a bait-and-switch probe."""

    status: str = "ok"
    identities_tested: list[str] = field(default_factory=list)
    tool_counts: dict[str, int] = field(default_factory=dict)
    tool_hashes: dict[str, str] = field(default_factory=dict)
    differences: list[dict[str, Any]] = field(default_factory=list)
    is_bait_switch: bool = False

    def to_findings(self) -> list[Finding]:
        """Convert detected differences into Finding objects."""
        findings: list[Finding] = []

        if self.is_bait_switch:
            # Top-level finding: server is doing bait-and-switch
            findings.append(
                Finding(
                    rule_id="bait_switch",
                    severity=Severity.CRITICAL,
                    surface=Surface.RUNTIME_DELTA,
                    title="Bait-and-switch: server returns different tools per client identity",
                    evidence=(
                        f"Tested {len(self.identities_tested)} identities. "
                        f"Tool counts: {self.tool_counts}"
                    ),
                    location="multi-identity probe",
                    detail=(
                        "The MCP server returns different tools depending on the "
                        "clientInfo identity. This is a strong indicator of malicious "
                        "behavior: the server is hiding capabilities from scanners "
                        "while exposing them to real AI clients."
                    ),
                )
            )

        for diff in self.differences:
            diff_type = diff.get("type", "unknown")

            if diff_type == "tool_only_in":
                findings.append(
                    Finding(
                        rule_id="bait_switch_tool_hidden",
                        severity=Severity.CRITICAL,
                        surface=Surface.RUNTIME_DELTA,
                        title=f"Tool '{diff['tool']}' only visible to '{diff['identity']}'",
                        evidence=f"Tool '{diff['tool']}' appears for {diff['identity']} but not others",
                        location="multi-identity probe",
                        detail=(
                            "This tool is selectively shown to specific clients. "
                            "The server is likely hiding dangerous capabilities from "
                            "scanners while exposing them to AI clients."
                        ),
                    )
                )

            elif diff_type == "description_changed":
                findings.append(
                    Finding(
                        rule_id="bait_switch_desc_changed",
                        severity=Severity.HIGH,
                        surface=Surface.RUNTIME_DELTA,
                        title=f"Tool '{diff['tool']}' description differs per client",
                        evidence=(
                            f"Description changes between '{diff['identity_a']}' "
                            f"and '{diff['identity_b']}'"
                        ),
                        location="multi-identity probe",
                        detail=(
                            "The tool description changes depending on the client. "
                            "This may be used to inject different prompts for "
                            "different AI models."
                        ),
                    )
                )

            elif diff_type == "schema_changed":
                findings.append(
                    Finding(
                        rule_id="bait_switch_schema_changed",
                        severity=Severity.HIGH,
                        surface=Surface.RUNTIME_DELTA,
                        title=f"Tool '{diff['tool']}' schema differs per client",
                        evidence=(
                            f"Input schema changes between '{diff['identity_a']}' "
                            f"and '{diff['identity_b']}'"
                        ),
                        location="multi-identity probe",
                        detail=(
                            "The tool input schema changes depending on the client. "
                            "This may add hidden parameters or change validation rules."
                        ),
                    )
                )

        return findings


# ---------------------------------------------------------------------------
# Tool comparison logic
# ---------------------------------------------------------------------------


def _tool_fingerprint(tool: ToolInfo) -> str:
    """Create a stable hash of a tool's identity (name + desc + schema)."""
    canonical = json.dumps(
        {
            "name": tool.name,
            "description": tool.description,
            "inputSchema": tool.input_schema,
        },
        sort_keys=True,
        ensure_ascii=False,
    )
    return hashlib.sha256(canonical.encode()).hexdigest()[:16]


def _tools_to_map(tools: list[ToolInfo]) -> dict[str, ToolInfo]:
    """Convert a tool list to a name -> ToolInfo dict."""
    return {t.name: t for t in tools}


def _compare_tool_lists(
    results: dict[str, list[ToolInfo]],
) -> list[dict[str, Any]]:
    """Compare tool lists from multiple identities and return differences."""
    differences: list[dict[str, Any]] = []
    identities = list(results.keys())

    if len(identities) < 2:
        return differences

    # Build name sets per identity
    name_sets: dict[str, set[str]] = {
        ident: {t.name for t in tools} for ident, tools in results.items()
    }

    # Find tools that only appear for specific identities
    all_names = set()
    for names in name_sets.values():
        all_names |= names

    for tool_name in all_names:
        present_in = [ident for ident, names in name_sets.items() if tool_name in names]
        absent_in = [
            ident for ident, names in name_sets.items() if tool_name not in names
        ]

        if absent_in:
            for ident in present_in:
                differences.append(
                    {
                        "type": "tool_only_in",
                        "tool": tool_name,
                        "identity": ident,
                        "absent_in": absent_in,
                    }
                )

    # Compare descriptions and schemas for tools present in all identities
    common_names = set.intersection(*name_sets.values()) if name_sets else set()
    tool_maps = {ident: _tools_to_map(tools) for ident, tools in results.items()}

    for tool_name in common_names:
        # Compare each pair
        for i in range(len(identities)):
            for j in range(i + 1, len(identities)):
                ident_a = identities[i]
                ident_b = identities[j]
                tool_a = tool_maps[ident_a][tool_name]
                tool_b = tool_maps[ident_b][tool_name]

                if tool_a.description != tool_b.description:
                    differences.append(
                        {
                            "type": "description_changed",
                            "tool": tool_name,
                            "identity_a": ident_a,
                            "identity_b": ident_b,
                        }
                    )

                if tool_a.input_schema != tool_b.input_schema:
                    differences.append(
                        {
                            "type": "schema_changed",
                            "tool": tool_name,
                            "identity_a": ident_a,
                            "identity_b": ident_b,
                        }
                    )

    return differences


# ---------------------------------------------------------------------------
# Main probe function
# ---------------------------------------------------------------------------


def probe_bait_switch(
    command: str,
    args: list[str] | None = None,
    env: dict[str, str] | None = None,
    thorough: bool = False,
) -> BaitSwitchResult:
    """Probe an MCP server for bait-and-switch behavior.

    Connects multiple times with different client identities and compares
    the tool lists. Any difference is flagged.

    Args:
        command: Server executable (e.g., "node", "npx").
        args: Server command-line arguments.
        env: Environment variables for the server process.
        thorough: Use 6 identities instead of 3.

    Returns:
        BaitSwitchResult with comparison data and findings.
    """
    identities = EXTENDED_IDENTITIES if thorough else PROBE_IDENTITIES
    results: dict[str, list[ToolInfo]] = {}
    result = BaitSwitchResult()

    print(f"[*] Bait-and-switch probe: testing {len(identities)} identities...")

    for client_info in identities:
        identity_label = client_info["name"]
        print(f"    Connecting as '{identity_label}'...", end=" ")

        tools = fetch_live_tools(
            command=command,
            args=args,
            env=env,
            client_info=client_info,
        )

        if tools is None:
            print("FAILED (could not connect)")
            result.status = "partial"
            continue

        results[identity_label] = tools
        result.identities_tested.append(identity_label)
        result.tool_counts[identity_label] = len(tools)

        # Create a hash of the full tool list for quick comparison
        all_fps = sorted(_tool_fingerprint(t) for t in tools)
        list_hash = hashlib.sha256("|".join(all_fps).encode()).hexdigest()[:16]
        result.tool_hashes[identity_label] = list_hash

        print(f"{len(tools)} tools (hash: {list_hash})")

    if len(results) < 2:
        print("[!] Not enough successful connections for comparison")
        result.status = "insufficient"
        return result

    # Compare all tool lists
    result.differences = _compare_tool_lists(results)
    result.is_bait_switch = len(result.differences) > 0

    # Quick check: are all hashes the same?
    unique_hashes = set(result.tool_hashes.values())
    if len(unique_hashes) == 1:
        print(f"\n[+] CLEAN: All {len(results)} identities received identical tools")
    else:
        print(
            f"\n[!] BAIT-AND-SWITCH DETECTED: {len(unique_hashes)} different tool sets!"
        )
        print(f"    {len(result.differences)} differences found")

    return result
