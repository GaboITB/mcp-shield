"""Approval store for MCP Shield v2.

Persists MCP approval decisions in a JSON file at
~/.config/mcp-shield/approvals.json. Each entry records the
tool hashes at approval time so we can detect rug pulls later.
"""

from __future__ import annotations

import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

from mcp_shield.core.models import AuditResult, ToolInfo

if sys.platform == "win32":
    _DEFAULT_DIR = Path.home() / ".config" / "mcp-shield"
else:
    _DEFAULT_DIR = Path.home() / ".config" / "mcp-shield"


class ApprovalStore:
    """JSON-backed store for MCP server approvals."""

    def __init__(self, path: Path | None = None) -> None:
        self._path = path or (_DEFAULT_DIR / "approvals.json")
        self._data: dict[str, Any] = {}
        self._load()

    def _load(self) -> None:
        """Load approvals from disk."""
        if self._path.exists():
            try:
                self._data = json.loads(self._path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                self._data = {}
        else:
            self._data = {}

    def _save(self) -> None:
        """Persist approvals to disk."""
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._path.write_text(
            json.dumps(self._data, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )

    def approve(self, name: str, result: AuditResult) -> None:
        """Register an MCP server as approved.

        Args:
            name: MCP server name (key in settings.json).
            result: The audit result at approval time.
        """
        tools = result.tools_live or result.tools_static
        tool_hashes = {t.name: t.content_hash() for t in tools}

        self._data[name] = {
            "mcp_name": name,
            "tool_hashes": tool_hashes,
            "approved_at": datetime.now().isoformat(),
            "version": result.pinned_version.get("version", "unknown"),
            "source": result.source,
            "grade": result.grade.value,
            "total_score": result.total_score,
            "deny_rules": result.deny_rules(name),
            "tool_count": len(tools),
        }
        self._save()

    def check(self, name: str, current_tools: list[ToolInfo]) -> list[str]:
        """Compare current tools against approved hashes.

        Args:
            name: MCP server name.
            current_tools: Current tool list (e.g., from live fetch).

        Returns:
            List of alert messages. Empty list means no changes detected.
        """
        if name not in self._data:
            return [f"MCP '{name}' has never been approved."]

        entry = self._data[name]
        approved_hashes: dict[str, str] = entry.get("tool_hashes", {})
        alerts: list[str] = []

        current_names = {t.name for t in current_tools}
        approved_names = set(approved_hashes.keys())

        # New tools since approval
        for added in sorted(current_names - approved_names):
            alerts.append(f"NEW TOOL: '{added}' appeared since approval.")

        # Removed tools since approval
        for removed in sorted(approved_names - current_names):
            alerts.append(f"REMOVED TOOL: '{removed}' disappeared since approval.")

        # Changed tools
        for tool in current_tools:
            if tool.name in approved_hashes:
                current_hash = tool.content_hash()
                if current_hash != approved_hashes[tool.name]:
                    alerts.append(
                        f"MODIFIED TOOL: '{tool.name}' hash changed "
                        f"({approved_hashes[tool.name][:12]}... -> {current_hash[:12]}...)."
                    )

        return alerts

    def list_approved(self) -> list[dict[str, Any]]:
        """List all approved MCP servers.

        Returns:
            List of approval entries.
        """
        return [
            {
                "name": key,
                "approved_at": val.get("approved_at", ""),
                "grade": val.get("grade", "?"),
                "tool_count": val.get("tool_count", 0),
                "source": val.get("source", ""),
            }
            for key, val in self._data.items()
        ]

    def revoke(self, name: str) -> bool:
        """Revoke approval for an MCP server.

        Args:
            name: MCP server name to revoke.

        Returns:
            True if the entry existed and was removed.
        """
        if name in self._data:
            del self._data[name]
            self._save()
            return True
        return False

    def get(self, name: str) -> dict[str, Any] | None:
        """Get approval entry for a specific MCP server."""
        return self._data.get(name)
