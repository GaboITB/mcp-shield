"""Approval workflow for MCP Shield v3.

Interactive workflow to review audit findings, apply deny rules
to Claude settings.json, and register approved MCPs.
"""

from __future__ import annotations

import json
import shutil
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

from mcp_shield.approval.store import ApprovalStore
from mcp_shield.core.models import AuditResult, ToolInfo
from mcp_shield.formatters.terminal import format_findings, format_summary


def _find_settings_path() -> Path | None:
    """Locate Claude Code settings.json."""
    candidates = []
    if sys.platform == "win32":
        appdata = Path.home() / "AppData" / "Roaming"
        candidates = [
            appdata / "Claude" / "claude_desktop_config.json",
            Path.home() / ".claude" / "settings.json",
            Path.home() / ".claude.json",
        ]
    else:
        candidates = [
            Path.home() / ".config" / "claude" / "claude_desktop_config.json",
            Path.home() / ".claude" / "settings.json",
            Path.home() / ".claude.json",
        ]
    for p in candidates:
        if p.exists():
            return p
    return None


def _backup_settings(path: Path) -> Path:
    """Create a timestamped backup of settings.json."""
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup = path.with_suffix(f".{ts}.bak")
    shutil.copy2(path, backup)
    return backup


def _apply_deny_rules(settings_path: Path, deny_rules: list[str]) -> bool:
    """Add deny rules to Claude settings.json.

    Args:
        settings_path: Path to settings.json.
        deny_rules: List of tool patterns to deny.

    Returns:
        True if rules were applied successfully.
    """
    if not deny_rules:
        return True

    try:
        content = settings_path.read_text(encoding="utf-8")
        settings = json.loads(content)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"[!] Cannot read settings: {exc}")
        return False

    # Navigate to the deny list, creating it if needed
    if "permissions" not in settings:
        settings["permissions"] = {}
    if "deny" not in settings["permissions"]:
        settings["permissions"]["deny"] = []

    existing = set(settings["permissions"]["deny"])
    added = []
    for rule in deny_rules:
        if rule not in existing:
            settings["permissions"]["deny"].append(rule)
            added.append(rule)

    if added:
        settings_path.write_text(
            json.dumps(settings, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        print(f"[+] Added {len(added)} deny rule(s) to {settings_path}")
    else:
        print("[*] All deny rules already present.")

    return True


def approve_mcp(
    result: AuditResult,
    store: ApprovalStore,
    settings_path: Path | None = None,
    auto_yes: bool = False,
) -> bool:
    """Interactive approval workflow.

    Args:
        result: The audit result to review.
        store: Approval store instance.
        settings_path: Path to settings.json (auto-detected if None).
        auto_yes: Skip confirmation prompt.

    Returns:
        True if the MCP was approved.
    """
    # Show summary
    print()
    print(format_summary(result))
    print()

    # Show findings if any
    if result.findings:
        print(format_findings(result))
        print()

    # Show deny rules
    deny = result.deny_rules()
    if deny:
        print(f"[*] {len(deny)} destructive tool(s) will be denied:")
        for rule in deny:
            print(f"    - {rule}")
        print()

    # Confirmation
    if not auto_yes:
        try:
            answer = input(
                f"Approve '{result.name}' (grade {result.grade.value})? [y/N] "
            )
        except (EOFError, KeyboardInterrupt):
            print("\n[!] Aborted.")
            return False

        if answer.strip().lower() not in ("y", "yes"):
            print("[!] Not approved.")
            return False

    # Apply deny rules to settings.json
    if deny:
        resolved_path = settings_path or _find_settings_path()
        if resolved_path and resolved_path.exists():
            backup = _backup_settings(resolved_path)
            print(f"[+] Settings backup: {backup}")
            if not _apply_deny_rules(resolved_path, deny):
                return False
        elif resolved_path:
            print(
                f"[!] Settings file not found at {resolved_path}, skipping deny rules."
            )
        else:
            print("[!] Could not locate settings.json, skipping deny rules.")

    # Register in store
    store.approve(result.name, result)
    print(f"[+] '{result.name}' approved and registered.")
    return True


def check_approved(
    store: ApprovalStore,
    tools: list[ToolInfo],
    name: str,
) -> list[str]:
    """Compare current tools against approved hashes.

    Args:
        store: Approval store instance.
        tools: Current tool list (e.g., from live fetch).
        name: MCP server name.

    Returns:
        List of alert messages (empty = no changes).
    """
    return store.check(name, tools)
