"""Auto-detect MCP server configurations from known client config files.

Searches for configuration files from popular MCP clients:
- Claude Desktop (claude_desktop_config.json)
- Cursor (.cursor/mcp.json)
- Windsurf (~/.windsurf/mcp.json)
- Cline (~/.cline/mcp_settings.json)
- Continue (~/.continue/config.json)
- Claude Code (.claude.json, .claude/settings.json)

Supports Windows, macOS, and Linux paths.
"""

from __future__ import annotations

import json
import os
import platform
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class MCPServerConfig:
    """A single MCP server configuration extracted from a client config."""

    name: str
    command: str
    args: list[str] = field(default_factory=list)
    env: dict[str, str] = field(default_factory=dict)
    source_file: str = ""
    client: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "command": self.command,
            "args": self.args,
            "env": {k: "***" for k in self.env},  # Redact env values
            "source_file": self.source_file,
            "client": self.client,
        }


def _get_config_paths() -> list[tuple[str, Path]]:
    """Get all known MCP config file paths for the current platform."""
    system = platform.system()
    home = Path.home()
    paths: list[tuple[str, Path]] = []

    # Claude Desktop
    if system == "Windows":
        appdata = os.environ.get("APPDATA", "")
        if appdata:
            paths.append(
                (
                    "Claude Desktop",
                    Path(appdata) / "Claude" / "claude_desktop_config.json",
                )
            )
    elif system == "Darwin":
        paths.append(
            (
                "Claude Desktop",
                home
                / "Library"
                / "Application Support"
                / "Claude"
                / "claude_desktop_config.json",
            )
        )
    else:  # Linux
        xdg = os.environ.get("XDG_CONFIG_HOME", str(home / ".config"))
        paths.append(
            (
                "Claude Desktop",
                Path(xdg) / "claude" / "claude_desktop_config.json",
            )
        )

    # Claude Code
    paths.append(("Claude Code", home / ".claude.json"))
    paths.append(("Claude Code", home / ".claude" / "settings.json"))

    # Cursor
    if system == "Windows":
        appdata = os.environ.get("APPDATA", "")
        if appdata:
            paths.append(("Cursor", Path(appdata) / "Cursor" / "mcp.json"))
    paths.append(("Cursor", home / ".cursor" / "mcp.json"))

    # Windsurf
    paths.append(("Windsurf", home / ".windsurf" / "mcp.json"))
    if system == "Windows":
        appdata = os.environ.get("APPDATA", "")
        if appdata:
            paths.append(("Windsurf", Path(appdata) / "Windsurf" / "mcp.json"))

    # Cline
    paths.append(("Cline", home / ".cline" / "mcp_settings.json"))

    # Continue
    paths.append(("Continue", home / ".continue" / "config.json"))

    # VSCode settings (MCP configs can be in settings.json)
    if system == "Windows":
        appdata = os.environ.get("APPDATA", "")
        if appdata:
            paths.append(("VS Code", Path(appdata) / "Code" / "User" / "settings.json"))
    elif system == "Darwin":
        paths.append(
            (
                "VS Code",
                home
                / "Library"
                / "Application Support"
                / "Code"
                / "User"
                / "settings.json",
            )
        )
    else:
        paths.append(("VS Code", home / ".config" / "Code" / "User" / "settings.json"))

    return paths


def _parse_mcp_servers(
    data: dict[str, Any],
    source_file: str,
    client: str,
) -> list[MCPServerConfig]:
    """Extract MCP server definitions from a parsed config dict."""
    servers: list[MCPServerConfig] = []

    # Standard format: {"mcpServers": {"name": {"command": ..., "args": [...]}}}
    mcp_servers = data.get("mcpServers", {})
    if not isinstance(mcp_servers, dict):
        return servers

    for name, config in mcp_servers.items():
        if not isinstance(config, dict):
            continue

        command = config.get("command", "")
        if not command:
            continue

        args = config.get("args", [])
        if not isinstance(args, list):
            args = [str(args)]

        env = config.get("env", {})
        if not isinstance(env, dict):
            env = {}

        # Resolve environment variable references
        resolved_env: dict[str, str] = {}
        for k, v in env.items():
            if isinstance(v, str) and v.startswith("${") and v.endswith("}"):
                env_var = v[2:-1]
                resolved_env[k] = os.environ.get(env_var, v)
            else:
                resolved_env[k] = str(v)

        servers.append(
            MCPServerConfig(
                name=name,
                command=command,
                args=[str(a) for a in args],
                env=resolved_env,
                source_file=source_file,
                client=client,
            )
        )

    return servers


def find_mcp_configs() -> list[MCPServerConfig]:
    """Auto-detect all MCP server configurations on the system.

    Returns a list of MCPServerConfig objects found across all
    supported MCP client config files.
    """
    all_servers: list[MCPServerConfig] = []
    checked: list[str] = []
    found: list[str] = []

    for client, config_path in _get_config_paths():
        if not config_path.exists():
            continue

        checked.append(str(config_path))

        try:
            raw = config_path.read_text(encoding="utf-8")
            data = json.loads(raw)
        except (json.JSONDecodeError, OSError):
            continue

        servers = _parse_mcp_servers(data, str(config_path), client)
        if servers:
            found.append(f"{client}: {config_path} ({len(servers)} servers)")
            all_servers.extend(servers)

    return all_servers


def find_and_report() -> tuple[list[MCPServerConfig], str]:
    """Find configs and return a human-readable summary."""
    servers = find_mcp_configs()

    lines = [f"Found {len(servers)} MCP server(s) across system configs:"]
    seen_clients: dict[str, list[str]] = {}
    for s in servers:
        seen_clients.setdefault(s.client, []).append(s.name)

    for client, names in seen_clients.items():
        lines.append(f"  {client}: {', '.join(names)}")

    if not servers:
        lines = ["No MCP server configurations found on this system."]

    return servers, "\n".join(lines)
