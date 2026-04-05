"""Live and approval check command implementations."""

from __future__ import annotations

import argparse

from mcp_shield.cli._utils import load_mcp_settings


def cmd_live(args: argparse.Namespace) -> int:
    """Execute the live subcommand."""
    from mcp_shield.approval.store import ApprovalStore

    store = ApprovalStore()

    # --all: check every approved MCP
    if args.all:
        return cmd_live_all(store)

    if not args.mcp_name:
        print("[!] Please specify an MCP name or use --all.")
        return 1

    return check_single_live(args.mcp_name, store)


def cmd_live_all(store: "ApprovalStore") -> int:
    """Check all approved MCPs against their current live state."""
    entries = store.list_approved()
    if not entries:
        print("[!] No approved MCPs found. Run 'scan' and 'approve' first.")
        return 0

    settings = load_mcp_settings()
    if settings is None:
        return 1

    mcp_servers = settings.get("mcpServers", {})
    total_alerts = 0
    checked = 0

    for entry in entries:
        name = entry["name"]
        mcp_config = mcp_servers.get(name)
        if not mcp_config:
            print(f"[~] '{name}' -- not found in settings, skipping.")
            continue

        command = mcp_config.get("command", "")
        mcp_args = mcp_config.get("args", [])
        env = mcp_config.get("env")
        if not command:
            print(f"[~] '{name}' -- no command defined, skipping.")
            continue

        from mcp_shield.approval.workflow import check_approved
        from mcp_shield.fetcher.live import fetch_live_tools

        print(f"[*] Checking '{name}'...")
        live_tools = fetch_live_tools(command, mcp_args, env)
        if live_tools is None:
            print(f"[!] '{name}' -- could not connect.")
            total_alerts += 1
            continue

        checked += 1
        alerts = check_approved(store, live_tools, name)
        if alerts:
            print(f"[!] '{name}' -- {len(alerts)} change(s):")
            for alert in alerts:
                print(f"    - {alert}")
            total_alerts += len(alerts)
        else:
            print(f"[+] '{name}' -- OK")

    print()
    print(
        f"[*] Checked {checked}/{len(entries)} approved MCPs, {total_alerts} alert(s)."
    )
    return 2 if total_alerts > 0 else 0


def check_single_live(mcp_name: str, store: "ApprovalStore") -> int:
    """Check a single MCP against its approval record."""
    from mcp_shield.approval.workflow import check_approved
    from mcp_shield.fetcher.live import fetch_live_tools

    entry = store.get(mcp_name)
    if not entry:
        print(f"[!] '{mcp_name}' has no approval record. Run 'scan' first.")
        return 1

    settings = load_mcp_settings()
    if settings is None:
        return 1

    mcp_config = settings.get("mcpServers", {}).get(mcp_name)
    if not mcp_config:
        print(f"[!] MCP '{mcp_name}' not found in settings.")
        return 1

    command = mcp_config.get("command", "")
    mcp_args = mcp_config.get("args", [])
    env = mcp_config.get("env")

    if not command:
        print(f"[!] No command defined for MCP '{mcp_name}'")
        return 1

    print(f"[*] Fetching live tools from '{mcp_name}'...")
    live_tools = fetch_live_tools(command, mcp_args, env)

    if live_tools is None:
        print("[!] Could not connect to MCP server.")
        return 2

    print(f"[*] Got {len(live_tools)} live tools.")

    alerts = check_approved(store, live_tools, mcp_name)

    if alerts:
        print()
        print(f"[!] {len(alerts)} change(s) detected since approval:")
        for alert in alerts:
            print(f"    - {alert}")
        return 2
    else:
        print("[+] No changes detected. Tools match approved state.")
        return 0
