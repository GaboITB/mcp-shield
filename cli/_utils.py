"""Shared utilities for CLI commands."""

from __future__ import annotations

import json
from pathlib import Path

_SEVERITY_RANK = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}


def exit_code_from_result(result: "AuditResult", fail_on: str | None = None) -> int:
    """Determine exit code from audit result.

    Args:
        fail_on: If set, exit 2 if any finding at this severity or higher.
                 Otherwise, default behavior (exit 2 for critical/high).
    """
    from mcp_shield.core.models import Severity

    if fail_on:
        threshold = _SEVERITY_RANK.get(fail_on, 1)
        for f in result.findings:
            if _SEVERITY_RANK.get(f.severity.value, 4) <= threshold:
                return 2
        return 0

    for f in result.findings:
        if f.severity in (Severity.CRITICAL, Severity.HIGH):
            return 2
    if result.findings:
        return 1
    return 0


def find_mcp_command(name: str) -> tuple[str, list[str], dict[str, str]] | None:
    """Try to find the MCP server command from installed configs.

    Searches Claude Desktop, Cursor, Windsurf, etc. for a matching
    MCP server name and returns (command, args, env) if found.
    """
    from mcp_shield.core.config_finder import find_mcp_configs

    servers = find_mcp_configs()
    # Try exact name match first, then partial
    for server in servers:
        if server.name.lower() == name.lower():
            return server.command, server.args, server.env
    for server in servers:
        if name.lower() in server.name.lower():
            return server.command, server.args, server.env
    return None


def find_mcp_command_from_repo(
    repo_path: Path,
) -> tuple[str, list[str], dict[str, str]] | None:
    """Try to infer the MCP server command from the cloned repo.

    Checks (in order):
    1. mcp.json -- standard MCP config with command/args
    2. package.json#bin -- npm executable entry point
    3. package.json#main -- Node.js main entry
    4. src/server.py or server.py -- Python server
    """
    # 1. mcp.json
    mcp_json = repo_path / "mcp.json"
    if mcp_json.is_file():
        try:
            data = json.loads(mcp_json.read_text(encoding="utf-8"))
            servers = data.get("mcpServers", {})
            for _name, cfg in servers.items():
                cmd = cfg.get("command", "")
                args = cfg.get("args", [])
                env = cfg.get("env", {})
                if cmd:
                    return cmd, args, env
        except (json.JSONDecodeError, OSError):
            pass

    # 2-3. package.json
    pkg_json = repo_path / "package.json"
    if pkg_json.is_file():
        try:
            data = json.loads(pkg_json.read_text(encoding="utf-8"))
            # bin entry
            pkg_bin = data.get("bin", {})
            if isinstance(pkg_bin, str):
                entry = pkg_bin
            elif isinstance(pkg_bin, dict) and pkg_bin:
                entry = next(iter(pkg_bin.values()))
            else:
                entry = None
            if entry and (repo_path / entry).is_file():
                return "node", [str(repo_path / entry)], {}
            # main entry
            main = data.get("main", "")
            if main and (repo_path / main).is_file():
                return "node", [str(repo_path / main)], {}
        except (json.JSONDecodeError, OSError):
            pass

    # 4. Python server patterns
    for candidate in ["src/server.py", "server.py", "src/main.py", "main.py"]:
        py_file = repo_path / candidate
        if py_file.is_file():
            return "python3", [str(py_file)], {}

    return None


def load_mcp_settings() -> dict | None:
    """Load MCP settings from known Claude config paths."""
    settings_path = None
    for candidate in [
        Path.home() / ".claude.json",
        Path.home() / ".claude" / "settings.json",
        Path.home() / "AppData" / "Roaming" / "Claude" / "claude_desktop_config.json",
    ]:
        if candidate.exists():
            settings_path = candidate
            break

    if not settings_path:
        print("[!] Cannot locate Claude settings to determine MCP command.")
        return None

    try:
        return json.loads(settings_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"[!] Cannot read settings: {exc}")
        return None


def audit_result_from_dict(data: dict) -> "AuditResult":
    """Reconstruct an AuditResult from a JSON dict.

    This handles the reverse of JSON serialization, rebuilding
    dataclass instances from plain dicts.
    """
    from mcp_shield.core.models import (
        AuditResult,
        Finding,
        PromptInfo,
        ResourceInfo,
        Severity,
        Surface,
        ToolInfo,
    )

    findings = []
    for fd in data.get("findings", []):
        findings.append(
            Finding(
                rule_id=fd["rule_id"],
                severity=Severity(fd["severity"]),
                surface=Surface(fd["surface"]),
                title=fd["title"],
                evidence=fd["evidence"],
                location=fd["location"],
                detail=fd.get("detail", ""),
            )
        )

    tools_static = []
    for td in data.get("tools_static", []):
        tools_static.append(
            ToolInfo(
                name=td["name"],
                description=td.get("description", ""),
                input_schema=td.get("input_schema", {}),
                output_schema=td.get("output_schema", {}),
                annotations=td.get("annotations", {}),
                source=td.get("source", ""),
                file=td.get("file", ""),
                line=td.get("line", 0),
            )
        )

    tools_live = []
    for td in data.get("tools_live", []):
        tools_live.append(
            ToolInfo(
                name=td["name"],
                description=td.get("description", ""),
                input_schema=td.get("input_schema", {}),
                output_schema=td.get("output_schema", {}),
                annotations=td.get("annotations", {}),
                source=td.get("source", ""),
                file=td.get("file", ""),
                line=td.get("line", 0),
            )
        )

    resources = []
    for rd in data.get("resources", []):
        resources.append(
            ResourceInfo(
                uri=rd["uri"],
                name=rd.get("name", ""),
                description=rd.get("description", ""),
                mime_type=rd.get("mime_type", ""),
            )
        )

    prompts = []
    for pd in data.get("prompts", []):
        prompts.append(
            PromptInfo(
                name=pd["name"],
                description=pd.get("description", ""),
                arguments=pd.get("arguments", []),
            )
        )

    return AuditResult(
        name=data.get("name", "unknown"),
        source=data.get("source", ""),
        findings=findings,
        tools_static=tools_static,
        tools_live=tools_live,
        resources=resources,
        prompts=prompts,
        health=data.get("health", {}),
        deps=data.get("deps", {}),
        urls=data.get("urls", []),
        pinned_version=data.get("pinned_version", {}),
        deprecated_msg=data.get("deprecated_msg", ""),
        sdk_info=data.get("sdk_info", {}),
        sbom=data.get("sbom", {}),
        dep_audit=data.get("dep_audit", ""),
        transitive_audit=data.get("transitive_audit", ""),
        timestamp=data.get("timestamp", ""),
    )
