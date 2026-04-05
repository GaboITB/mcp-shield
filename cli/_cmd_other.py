"""Standalone commands: sandbox, bait-switch, detect, approve, report."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from mcp_shield.cli._utils import audit_result_from_dict


def cmd_sandbox(args: argparse.Namespace) -> int:
    """Execute the standalone sandbox subcommand."""
    from mcp_shield.runtime.sandbox import check_sandbox_prerequisites, run_sandbox

    ok, msg = check_sandbox_prerequisites()
    if not ok:
        print(f"[!] {msg}", file=sys.stderr)
        return 1

    result = run_sandbox(
        source=args.source,
        name=args.name,
        mcp_type=args.type,
        duration=args.duration,
        network=args.network,
    )

    if result.status == "error":
        print(f"[!] Sandbox error: {result.verdict}", file=sys.stderr)
        return 2

    print(f"\n[+] Verdict: {result.verdict}")
    findings = result.to_findings()
    if findings:
        print(f"[!] {len(findings)} runtime findings:")
        for f in findings:
            print(f"    {f.severity.value.upper():8s} {f.title}: {f.evidence}")
    else:
        print("[+] No suspicious runtime behavior detected")

    return 0 if result.verdict == "CLEAN" else 1


def cmd_bait_switch(args: argparse.Namespace) -> int:
    """Execute the bait-switch subcommand."""
    from mcp_shield.runtime.bait_switch import probe_bait_switch

    result = probe_bait_switch(
        command=args.command,
        args=args.server_args or None,
        thorough=args.thorough,
    )

    findings = result.to_findings()
    if findings:
        print(f"\n[!] BAIT-AND-SWITCH DETECTED -- {len(findings)} findings:")
        for f in findings:
            print(f"    {f.severity.value.upper():8s} {f.title}")
            print(f"             {f.evidence}")
        return 2
    elif result.status == "insufficient":
        print("\n[!] Could not complete probe -- insufficient connections")
        return 1
    else:
        print("\n[+] No bait-and-switch behavior detected")
        return 0


def cmd_detect(args: argparse.Namespace) -> int:
    """Auto-detect MCP configs on this system."""
    from mcp_shield.core.config_finder import find_and_report

    servers, summary = find_and_report()
    print(summary)

    if servers:
        print()
        for s in servers:
            print(f"  [{s.client}] {s.name}")
            print(f"    Command: {s.command} {' '.join(s.args)}")
            print(f"    Config:  {s.source_file}")
            print()

    return 0


def cmd_approve(args: argparse.Namespace) -> int:
    """Execute the approve subcommand."""
    from mcp_shield.approval.store import ApprovalStore
    from mcp_shield.approval.workflow import approve_mcp

    store = ApprovalStore()

    # Load audit result
    if args.audit_file:
        if not args.audit_file.exists():
            print(f"[!] Audit file not found: {args.audit_file}")
            return 1
        try:
            data = json.loads(args.audit_file.read_text(encoding="utf-8"))
            result = audit_result_from_dict(data)
        except Exception as exc:
            print(f"[!] Failed to load audit file: {exc}")
            return 1
    else:
        # Check if we have a cached result
        from mcp_shield.core.paths import get_cache_dir

        cache_dir = get_cache_dir()
        cache_file = cache_dir / f"{args.mcp_name}.json"
        if cache_file.exists():
            try:
                data = json.loads(cache_file.read_text(encoding="utf-8"))
                result = audit_result_from_dict(data)
            except Exception:
                print(
                    f"[!] No valid audit result for '{args.mcp_name}'. Run 'scan' first."
                )
                return 1
        else:
            print(
                f"[!] No audit result for '{args.mcp_name}'. Run 'scan' first, or use --audit-file."
            )
            return 1

    settings_path = getattr(args, "settings", None)
    approved = approve_mcp(
        result=result,
        store=store,
        settings_path=settings_path,
        auto_yes=args.yes,
    )

    return 0 if approved else 1


def cmd_report(args: argparse.Namespace) -> int:
    """Execute the report subcommand."""
    from mcp_shield.approval.store import ApprovalStore

    store = ApprovalStore()
    entries = store.list_approved()

    if args.name:
        entries = [e for e in entries if e["name"] == args.name]

    if not entries:
        msg = "No approval records found"
        if args.name:
            msg += f" for '{args.name}'"
        print(msg + ".")
        return 0

    if args.format == "json":
        print(json.dumps(entries, indent=2, ensure_ascii=False))
    else:
        print(f"{'Name':<25} {'Grade':<8} {'Tools':<8} {'Approved':<22} Source")
        print("-" * 90)
        for e in entries:
            print(
                f"{e['name']:<25} {e['grade']:<8} {e['tool_count']:<8} "
                f"{e['approved_at'][:19]:<22} {e['source'][:40]}"
            )

    return 0
